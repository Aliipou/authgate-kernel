# authgate-kernel — Operational Guide

> **Audience:** Security engineers deploying authgate-kernel in production AI systems.
> This guide covers: installation, registry setup, key rotation, audit operations, CLI reference, and failure recovery.

---

## Table of contents

1. [Installation](#1-installation)
2. [Core concepts](#2-core-concepts)
3. [Registry setup](#3-registry-setup)
4. [Verifying actions](#4-verifying-actions)
5. [Audit log](#5-audit-log)
6. [Key rotation](#6-key-rotation)
7. [CLI reference](#7-cli-reference)
8. [Thread safety](#8-thread-safety)
9. [Integration patterns](#9-integration-patterns)
10. [Failure modes](#10-failure-modes)
11. [Multi-layer safety composition](#11-multi-layer-safety-composition)
12. [Observability hooks](#12-observability-hooks)
13. [Operational checklist](#13-operational-checklist)

---

## 1. Installation

```bash
# From source (recommended for production — pin the commit hash)
git clone https://github.com/Aliipou/authgate-kernel
cd authgate-kernel
pip install -e ".[dev]"

# Verify installation
authgate-cli --help
pytest                      # 273 tests must pass
```

**Python requirement:** 3.11+. No native extensions required for the Python runtime. The Rust TCB (`freedom-kernel/`) requires a Rust toolchain only if you compile the kernel binary.

**Rust TCB build:**
```bash
cd freedom-kernel
cargo build --release
cargo build --features sandbox   # include WASM executor
cargo test --lib                 # 141 tests
```

---

## 2. Core concepts

### The trust hierarchy

```
Human principal (alice)
  └── owns Machine (analyst-bot)
        └── holds RightsClaim on Resource (sales-data)
              scope: "/data/sales/"
              rights: can_read=True
              confidence: 1.0
              expires_at: None (no expiry)
```

Every **machine** must have a registered human **owner**. A machine with no owner is blocked by axiom A4, regardless of any claims it holds.

### Rights are typed

Rights are not strings — they are boolean fields on `RightsClaim`:

| Field | Meaning |
|---|---|
| `can_read` | Actor may read the resource |
| `can_write` | Actor may write the resource |
| `can_delegate` | Actor may sub-delegate this claim to another entity |

### Scope is a prefix

`Resource.scope` is a path prefix. `scope_contains(parent, child)` is true iff `child` starts with `normalize(parent) + "/"` or equals `normalize(parent)`. Path traversal (`..` segments) is always rejected.

### Confidence is a float [0.0, 1.0]

Claims carry a `confidence` score. Verify results below `0.8` produce warnings. Conflicting write claims on the same resource trigger human arbitration flags.

---

## 3. Registry setup

### Minimal setup

```python
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry

registry = OwnershipRegistry()

# 1. Define principals
alice = Entity("alice", AgentType.HUMAN)
bot   = Entity("analyst-bot", AgentType.MACHINE)

# 2. Register ownership
registry.register_machine(bot, alice)

# 3. Define resources
sales = Resource("sales-data", ResourceType.DATASET, scope="/data/sales/")
reports = Resource("reports",  ResourceType.FILE,    scope="/reports/alice/")

# 4. Grant rights
registry.add_claim(RightsClaim(bot, sales,   can_read=True))
registry.add_claim(RightsClaim(bot, reports, can_write=True))
```

### Delegation

```python
# alice grants bot the ability to sub-delegate sales access to a sub-agent
registry.add_claim(RightsClaim(alice, sales, can_read=True, can_delegate=True))
registry.delegate(
    RightsClaim(sub_bot, sales, can_read=True),
    delegated_by=bot,
)
```

Delegation enforces attenuation: `sub_bot` cannot get rights `bot` doesn't hold. `confidence` can only decrease down the chain.

### Loading from JSON (CLI / production)

```json
{
  "agents": [
    {"id": "alice", "kind": "HUMAN"},
    {"id": "analyst-bot", "kind": "MACHINE"}
  ],
  "machine_owners": [
    {"machine": "analyst-bot", "owner": "alice"}
  ],
  "resources": [
    {"id": "sales-data", "type": "DATASET", "scope": "/data/sales/"}
  ],
  "claims": [
    {"holder": "analyst-bot", "resource": "sales-data", "can_read": true}
  ]
}
```

```bash
authgate-cli verify --registry registry.json --action action.json
```

### Revocation

```python
# Revoke all claims held by a compromised bot
count = registry.revoke_all("compromised-bot")

# Revoke cascading — also revokes delegated claims downstream
count = registry.revoke_cascading("compromised-bot")

# Remove expired claims
count = registry.expire_stale()
```

---

## 4. Verifying actions

### Single action

```python
from authgate.kernel.verifier import Action, FreedomVerifier

# Freeze the registry — eliminates TOCTOU between registry reads
frozen   = registry.freeze()
verifier = FreedomVerifier(frozen, audit_log=audit)

action = Action(
    action_id="read-q1-sales",
    actor=bot,
    resources_read=[sales],
)
result = verifier.verify(action)

if not result.permitted:
    print(result.summary())
    agent.halt()
```

### Action fields

```python
Action(
    action_id="unique-id",          # required, unique per call
    actor=bot,                       # required
    resources_read=[...],            # list[Resource]
    resources_write=[...],           # list[Resource]
    resources_delegate=[...],        # list[Resource]
    governs_humans=[...],            # list[Entity] — triggers A6 if any
    # Sovereignty flags — any True → instant FORBIDDEN
    increases_machine_sovereignty=False,
    resists_human_correction=False,
    bypasses_verifier=False,
    weakens_verifier=False,
    disables_corrigibility=False,
    machine_coalition_dominion=False,
    coerces=False,
    deceives=False,
    self_modification_weakens_verifier=False,
    machine_coalition_reduces_freedom=False,
)
```

**Critical:** Any sovereignty flag set to `True` produces `FORBIDDEN` violations and blocks the action regardless of claims. These checks run before all others.

### Plan verification

```python
actions = [action1, action2, action3]
results = verifier.verify_plan(actions)

# If action[i] triggers a sovereignty flag, actions[i+1:] are cancelled
for r in results:
    print(r.summary())
```

### VerificationResult fields

```python
result.permitted                  # bool — the single gating decision
result.violations                 # tuple[str] — empty if permitted
result.warnings                   # tuple[str] — low-confidence warnings
result.confidence                 # float — minimum confidence across all claims
result.requires_human_arbitration # bool — conflicting write claims detected
result.manipulation_score         # float — always 0.0 from kernel; set by ExtendedFreedomVerifier
```

---

## 5. Audit log

### Setup

```python
from authgate.kernel.audit import AuditLog

# In-memory (testing)
audit = AuditLog()

# Persistent (production)
audit = AuditLog(path="/var/log/authgate/kernel.jsonl")
```

### Chain verification

The audit log is SHA-256 hash-chained. Each entry contains `prev_hash` and `entry_hash`. Tampering or deletion of any entry is detected by `verify_chain()`.

```python
# Verify integrity
assert audit.verify_chain(), "Audit chain compromised — halt and investigate"

# Detailed error reporting
errors = audit.chain_errors()
for error in errors:
    print(error)
```

### Forensic replay

```python
# Replay entry at index 42
entry = audit.replay(42)
print(entry["action_id"], entry["permitted"], entry["violations"])

# Replay a range
entries = audit.replay_range(100, 200)  # entries [100, 200)
```

### Load from file

```python
# Load and verify in one call
log, errors = AuditLog.load_and_verify("/var/log/authgate/kernel.jsonl")
if errors:
    raise IntegrityError("audit_chain", detail=str(errors))

# Load and continue appending
log = AuditLog.load_from_file("/var/log/authgate/kernel.jsonl")
verifier2 = FreedomVerifier(frozen, audit_log=log)
# new verify() calls append to the loaded chain
```

### Entry format

Each `.jsonl` line is a JSON object:

```json
{
  "ts":         1779992240.817,
  "action_id":  "read-q1-sales@1779992240817",
  "permitted":  true,
  "confidence": 1.0,
  "violations": [],
  "warnings":   [],
  "signature":  null,
  "prev_hash":  "0000...0000",
  "entry_hash": "a3f1...b8e2"
}
```

---

## 6. Key rotation

### Issue a rotation certificate

```python
from authgate.key_rotation import issue_rotation, verify_rotation, ActiveKeySet

# old_sign: callable(msg: bytes) -> bytes  (signing function for old private key)
# OLD_PUBKEY, NEW_PUBKEY: bytes            (raw public key bytes)

cert = issue_rotation(
    old_sign=old_sign,
    old_pubkey=OLD_PUBKEY,
    new_pubkey=NEW_PUBKEY,
    new_epoch=10,
    overlap_window_seconds=3600,   # 1-hour grace period
)
```

### Apply rotation

```python
key_set = ActiveKeySet(current_pubkey=OLD_PUBKEY)
key_set.apply_rotation(cert, old_verify)

# During grace period: both keys accepted
accepted = key_set.accepted_keys(now)   # [OLD_PUBKEY, NEW_PUBKEY]

# After cutover: only new key accepted
accepted = key_set.accepted_keys(now)   # [NEW_PUBKEY]
```

### Emergency rotation (zero grace period)

```python
cert = issue_rotation(
    old_sign=old_sign,
    old_pubkey=OLD_PUBKEY,
    new_pubkey=NEW_PUBKEY,
    new_epoch=99,
    overlap_window_seconds=0,      # immediate cutover — no grace period
)
```

### Wire format

```python
wire = cert.to_wire()          # dict — JSON-serializable
cert2 = RotationCertificate.from_wire(wire)

json_str = cert.to_json()      # str
cert3 = RotationCertificate.from_json(json_str)

assert cert2 == cert3          # roundtrip
```

### Rotation procedure (production runbook)

1. Generate `NEW_PUBKEY` offline on a secure workstation.
2. Issue `cert = issue_rotation(...)` with `new_epoch = current_epoch + 1`, `overlap_window_seconds = 3600`.
3. Distribute `cert` to all nodes via your existing config channel.
4. Each node calls `key_set.apply_rotation(cert, old_verify)`. During the 1-hour window both keys are valid.
5. After `cert.cutover_at`, only `NEW_PUBKEY` is accepted. All proofs signed by the old key are rejected.
6. Emergency path: set `overlap_window_seconds=0` and distribute immediately.

---

## 7. CLI reference

### `authgate-cli verify`

```
authgate-cli verify --registry REG.json --action ACTION.json [options]

Options:
  --registry REG.json     Registry file (required)
  --action   ACTION.json  Action file (required)
  --audit    LOG.jsonl    Append audit entry to this file
  --json                  Output machine-readable JSON

Exit codes:
  0  Action permitted
  1  Action denied
  2  Usage or parse error
```

**Registry JSON format:** see §3 above.

**Action JSON format:**
```json
{
  "action_id": "read-sales",
  "actor": "analyst-bot",
  "resources_read": ["sales-data"],
  "resources_write": [],
  "increases_machine_sovereignty": false
}
```

### `authgate-cli audit verify`

```
authgate-cli audit verify LOG.jsonl

Exit codes:
  0  Chain intact
  1  Chain broken (tampering or deletion detected)
```

### `authgate-cli audit replay`

```
authgate-cli audit replay LOG.jsonl INDEX

Outputs the entry at INDEX as JSON. Exits 2 if out of range.
Exits 1 if the entry's hash does not match its content (tampered).
```

### `authgate-cli audit stats`

```
authgate-cli audit stats LOG.jsonl

Outputs: total entries, permitted count, denied count, chain status, head hash.
```

### `authgate-cli key verify-cert`

```
authgate-cli key verify-cert CERT.json

Inspects a rotation certificate — prints metadata without verifying signature
(signature verification requires providing the old public key, not yet in CLI).
```

---

## 8. Thread safety

### OwnershipRegistry

Uses `threading.RLock`. Safe for concurrent reads and writes. `freeze()` produces an independent snapshot under the lock.

### AuditLog

Uses `threading.Lock`. `record()` reads and sets `_last_hash` inside the lock — concurrent appends always form a valid linear chain. Proven by 200-concurrent-append stress test in `tests/test_audit_hardening.py::TestPrevHashAtomicity`.

### FreedomVerifier

`verify()` is read-only against the registry. Pass a frozen registry to guarantee TOCTOU-free verification:

```python
frozen   = registry.freeze()        # snapshot — immutable
verifier = FreedomVerifier(frozen)  # all verify() calls read the same snapshot
```

A frozen registry raises `RuntimeError` on any mutation attempt.

### Recommended pattern

```python
# Startup: build registry, freeze once, create verifier with audit
registry = build_registry_from_config()
frozen   = registry.freeze()
audit    = AuditLog(path=LOG_PATH)
verifier = FreedomVerifier(frozen, audit_log=audit)

# Request handling: all threads share the same verifier
# (frozen registry + AuditLog are both thread-safe)
result = verifier.verify(action)
```

For policy updates (new claims, revocations): rebuild the registry, freeze again, and swap the verifier atomically using a lock or an immutable reference.

---

## 9. Integration patterns

### LangChain

See `examples/langchain_integration/demo.py` for a complete working example.

```python
from authgate.adapters.langchain import FreedomTool, kernel_gate

@kernel_gate(registry=frozen, actor=bot)
def my_tool(input: str) -> str:
    return do_work(input)
```

### OpenAI / Anthropic / AutoGen

```python
from authgate import AnthropicKernelAdapter, AutoGenKernelAdapter, OpenAIKernelMiddleware

middleware = OpenAIKernelMiddleware(registry=frozen)
# Wrap your OpenAI client with middleware — every tool call is gated
```

### FastAPI (HTTP service)

```python
from authgate.api.app import app
uvicorn authgate.api.app:app --host 0.0.0.0 --port 8000
```

Exposes `/verify` endpoint with the same semantics as `FreedomVerifier.verify()`.

### Error handling

```python
from authgate.errors import (
    AuthgateError, CapabilityError, RightsError,
    IntegrityError, WireError, RegistryError, KeyRotationError,
)

try:
    result = verifier.verify(action)
except AuthgateError as e:
    logger.error("authgate error: %s", e)
    raise
```

All authgate exceptions are structured dataclasses — they carry machine-readable fields (`actor_id`, `resource`, `failed_check`, etc.) so you can respond programmatically without parsing message strings.

---

## 10. Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| Frozen registry mutation attempt | `RuntimeError: Registry is frozen` | Use original unfrozen registry for mutations |
| Audit chain broken | `audit.verify_chain()` returns False | Halt, preserve log, investigate; do NOT overwrite |
| Malformed registry JSON | `WireError` on `authgate-cli verify` | Validate JSON schema before use |
| Ownerless machine | `[A4] UNOWNED_MACHINE` in violations | Register machine with `registry.register_machine(bot, owner)` |
| Machine governing human | `[A6] MACHINE_DOMINION` in violations | Remove `governs_humans` from the action |
| Sovereignty flag set | `FORBIDDEN (...)` in violations | Block action — no recovery, by design |
| Conflicting write claims | `requires_human_arbitration=True` | Route to human review before proceeding |
| Clock skew (expiry false-positive) | `violations` contains `ExpiryGate` | Synchronize clocks; use NTP in production |
| Replay attack | `action_id` is not unique | Generate unique action IDs (UUID4 + timestamp) |
| Key rotation signature invalid | `KeyRotationError` raised | Verify old private key is correct; do not apply |

### Audit log incident response

If `verify_chain()` returns `False`:

1. **Stop appending** — do not write new entries.
2. Run `authgate-cli audit stats log.jsonl` to get the count and head hash.
3. Run `authgate-cli audit verify log.jsonl` to identify which entries are broken.
4. Use `log.chain_errors()` for a list of all broken positions.
5. Preserve the log file unchanged — it is forensic evidence.
6. Start a new log file at the next entry index.
7. Report the incident with: log path, entry count, first broken index, head hash.

---

## 11. Multi-layer safety composition

The kernel (`FreedomVerifier`) is a **necessary condition**, not a sufficient one.
Four verifier layers compose cleanly — each adds an independent orthogonal condition.
All must pass for an action to proceed.

```
Layer 1: FreedomVerifier        — authority gate (ownership + rights claims)
Layer 2: ConsentVerifier        — human consent for sensitive actions
Layer 3: NonInterferenceChecker — IFC / Bell-LaPadula confidentiality
Layer 4: PolicyVerifier         — ABAC operational rules
```

### Wiring all four layers

```python
from authgate import (
    FreedomVerifier, OwnershipRegistry, RightsClaim, Entity, AgentType,
    Resource, ResourceType, Action,
)
from authgate.kernel.consent import ConsentCapability, ConsentVerifier
from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier
from authgate.kernel.policy_dsl import compile as compile_policy
from authgate.extensions.ifc import NonInterferenceChecker, SecurityLattice, IFCViolation

# ── Setup ─────────────────────────────────────────────────────────────────────
registry = OwnershipRegistry()
dr_alice = Entity("DrAlice", AgentType.HUMAN)
medbot = Entity("MedBot", AgentType.MACHINE)
patient_record = Resource("phi-001", ResourceType.DATASET,
                          scope="/phi/patients", ifc_label="SECRET")

registry.register_machine(medbot, dr_alice)
registry.add_claim(RightsClaim(medbot, patient_record, can_read=True))

kernel = FreedomVerifier(registry.freeze())

# Layer 2: consent — patient data requires explicit physician consent
consent_verifier = ConsentVerifier(capabilities=[
    ConsentCapability(
        claim=RightsClaim(medbot, patient_record, can_read=True),
        consent_required=True,
        consent_given_by=dr_alice,    # must be a human
        consent_scope="/phi/patients",
    )
])

# Layer 3: IFC — SECRET data must not flow to PUBLIC resources
ifc_checker = NonInterferenceChecker(verifier=kernel, lattice=SecurityLattice.default())

# Layer 4: ABAC — no machine writes to /phi scope (policy DSL)
policy = compile_policy("""
    DENY *
      WRITE /phi
""", name="phi-write-protection")
policy_verifier = PolicyVerifier(kernel=kernel, policy=policy)

# ── Per-action verification ────────────────────────────────────────────────────
def is_permitted(action: Action) -> tuple[bool, list[str]]:
    """Run all four layers; return (ok, reasons_if_blocked)."""
    failures = []

    # L1: kernel gate
    result = kernel.verify(action)
    if not result.permitted:
        return False, [f"KERNEL: {'; '.join(result.violations)}"]

    # L2: consent (only for kernel-permitted actions)
    for v in consent_verifier.check(action):
        failures.append(f"CONSENT: {v.reason}")

    # L3: IFC (track labels across action sequence in production)
    try:
        ifc_checker.check_action(action, read_labels_so_far=set())
    except IFCViolation as e:
        failures.append(f"IFC: {e}")

    # L4: policy
    pol_result = policy_verifier.verify(action)
    if not pol_result.permitted:
        failures.extend(f"POLICY: {v}" for v in pol_result.violations)

    return len(failures) == 0, failures
```

### Composition order matters

- **Layer 1 first** — sovereignty flags (FORBIDDEN) are checked before any other layer.
  An action with `bypasses_verifier=True` is rejected instantly; consent and IFC are never consulted.
- **Layer 2 and 3 only when kernel permits** — no point checking consent for a kernel-denied action.
- **Layer 3 stateful** — IFC tracks labels across the entire session, not just per-action.
  In production, pass a single `read_labels_so_far` set across the agent's session.
- **Layer 4 orthogonal** — `PolicyVerifier.verify()` calls `kernel.verify()` internally;
  it short-circuits if the kernel denies.

### IFC across a session

```python
session_labels: set[str] = set()  # shared across all actions in one agent session

for action in agent_actions:
    # ... layers 1, 2, 4 ...
    try:
        ifc_checker.check_action(action, read_labels_so_far=session_labels)
    except IFCViolation:
        halt_agent()
        break
    # session_labels now contains all resource labels read so far
```

### Policy DSL quick reference

```
ALLOW <subject>               # ALLOW or DENY
  READ   <scope>              # one or more operations
  WRITE  <scope>              # scope is a prefix (/phi matches /phi/*, not /phi-extra)
  UNLESS delegated_by <name>  # optional: only if NOT delegated by <name>
  MAX_DELEGATION_DEPTH 2      # optional: limit chain depth
  EXPIRES 3600                # optional: time-limited rule (seconds)
  TRUST_DOMAIN internal       # optional: restrict to named trust domain
```

`compile_policy(text, name)` parses the DSL and returns a `Policy` ready for `PolicyVerifier`.

---

## 12. Observability hooks

`HookRegistry` and `MetricsCollector` provide zero-dependency observability.
Every `verify()` call automatically emits a `VerificationEvent` — no code changes needed.

```python
from authgate import HookRegistry, MetricsCollector, VerificationEvent

# Register a metrics collector
collector = MetricsCollector()
HookRegistry.register(collector.on_event)

# ... run your agent ...

snapshot = collector.snapshot()
print(collector.summary())
# "100 calls, 97 permit, 3 deny (3.0%); arbitration=1; avg=24.2µs"

# Unregister when done
HookRegistry.unregister(collector.on_event)
```

### Custom hooks

```python
def my_hook(event: VerificationEvent) -> None:
    if not event.permitted:
        alert_pagerduty(event.action_id, event.actor_name, event.violation_count)

HookRegistry.register(my_hook)
```

Hooks run synchronously after the `verify()` decision is recorded.
Exceptions in hooks are swallowed — a broken hook never affects the kernel decision.
Hooks run in registration order. `HookRegistry.clear()` removes all hooks.

---

## 13. Operational checklist

### Before go-live

- [ ] Every machine has a registered human owner (`registry.register_machine`)
- [ ] Resource scopes are minimal (principle of least privilege)
- [ ] `AuditLog` is writing to a durable path (`AuditLog(path=...)`)
- [ ] Registry is frozen before any `FreedomVerifier` is created
- [ ] Key rotation procedure is documented and tested in staging
- [ ] `audit.verify_chain()` passes on startup (if loading from existing log)
- [ ] `pytest` passes on the deployed code (`438 tests`)
- [ ] Sovereignty flags are never set to `True` by default in action builders

### After deployment

- [ ] `authgate-cli audit stats` checked daily
- [ ] `authgate-cli audit verify` run on log rotation
- [ ] `AuditLog.load_and_verify()` called on any restored log before use
- [ ] Epoch advanced whenever a cohort of machines is compromised
- [ ] Revoked machine claims removed via `registry.revoke_all()` or `registry.revoke_cascading()`

### Monitoring signals

| Signal | Condition |
|---|---|
| `denied_rate` high | Many actions being denied — check claim coverage |
| `arbitration_rate` > 0 | Conflicting write claims — investigate claim overlap |
| `confidence_warn` rate | Claims with confidence < 0.8 — review claim quality |
| `chain_error` | Any non-zero count — immediate incident response |
| `verify_latency` p99 > 1ms | Registry may be too large — consider freezing subsets |
