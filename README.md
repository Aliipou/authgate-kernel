# authgate-kernel

**Capability verification between a decision and IO.**

Given a sealed action and a capability-proof chain, the gate answers one
structural question: does this actor hold a valid, non-expired, cryptographically
signed capability for this resource and these rights, in a chain traceable to a
trust root? Same inputs → same `Permit` / `Deny`. No LLM calls, no scores, no
network I/O inside the verify path.

Not a better Cedar/OPA/Zanzibar. Not a product pitch for “AI safety.” See
[`STATUS.md`](STATUS.md) for what was killed and what remains open, and
[`ASSUMPTIONS.md`](ASSUMPTIONS.md) for what is proved vs axiomatized.

**Pipeline (when composed with a legitimacy layer):** identity → legitimacy
(DENY-only) → **this kernel (authority)** → PEP execute + audit. Legitimacy may
only refuse; it cannot grant. The optional normative lineage of the Theory of
Freedom is documented under [`PHILOSOPHY/`](PHILOSOPHY/) / `nazariye-azadi` and is
**not** the industrial claim — see [`FREEDOM_THEORY_POSITION.md`](FREEDOM_THEORY_POSITION.md).

[![CI](https://github.com/Aliipou/authgate-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Aliipou/authgate-kernel/actions)
[![Rust](https://img.shields.io/badge/kernel-Rust-orange.svg)](authgate-kernel/)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-orange.svg)](LICENSE)

**External review:** [`REVIEW_PACKET.md`](REVIEW_PACKET.md) ·
[`CHATGPT_REVIEW_BRIEF.md`](CHATGPT_REVIEW_BRIEF.md) · wire format under [`spec/`](spec/)

---

## The problem

Any decision-maker can reach IO without proving authority. Today that is often an
LLM agent; the gap does not depend on which planner sits on top.

## What this is

```
[Any decision-maker]  →  CallGate (verify authority proof)  →  [Any IO target]
                              ↓ if denied
                         audit log entry, action does not execute
```

### Contract (the integration surface)

- [`spec/canonical_action.schema.json`](spec/canonical_action.schema.json)
- [`spec/gate_result.schema.json`](spec/gate_result.schema.json)
- [`spec/audit_entry.schema.json`](spec/audit_entry.schema.json)

Framework adapters (LangChain, OpenAI, Anthropic, AutoGen, CrewAI, LangGraph,
DSPy, MCP) under `src/authgate/adapters/` are conveniences. The wire format is
the product boundary.

---

## What it does NOT do

| Not this | Why |
|---|---|
| Alignment / ethics / intent | Values and NL intent are out of scope; this is typed authority |
| Side-channel defense | Timing / covert channels excluded by design |
| Python-equivalent security | `src/authgate/` is a compatibility runtime — **not** the TCB |
| Replacing Cedar / OPA / ReBAC | Authorization-as-policy is absorbed by incumbents (`WHY_NOT_OPA.md`) |

The Python layer mirrors TCB *shape* for tests and prototyping. It is bypassable
(e.g. a tool calling `subprocess`). Only `authgate-kernel/src/tcb/` carries the
stated security guarantees. Gaps: [`formal/INCOMPLETENESS.md`](formal/INCOMPLETENESS.md).

---

## Numbers that matter (re-run before citing)

| Metric | Value (2026-08-20 local) |
|---|---|
| Security-enforcing Rust path | `engine.rs` + `dag.rs` + `call_gate.rs` (see `authgate-kernel/src/tcb/`) |
| Rust `cargo test --lib` | **293** passed |
| Kani | Bounded model checking — not unbounded proof (`ASSUMPTIONS.md`) |
| Lean 4 | Partial; crypto boundary is **axiomatized** (`sig_euf_cma`) |
| TLA+ AuthGateV3 | **TLC completed, no error** on bounded model (`Len(audit_log)≤1`, safety-only) — `formal/tlc_run.log`, `formal/COVERAGE.md` |

Python integration suite size fluctuates with optional extras; do not treat README
badges as a substitute for a fresh `pytest` / `cargo test` run.

> **Windows note:** building the Rust crate under a non-ASCII filesystem path can
> break `gcc` linking. Use an ASCII junction and `CARGO_TARGET_DIR` (e.g.
> `D:\ag-target`).

## Theory → Engineering coverage (optional lineage)

On `nazariye-azadi` / [`PHILOSOPHY/`](PHILOSOPHY/), axioms map to modules. Trust
levels matter: only TCB rows below are in the trusted core.

| Axiom | Module | Trust level | What it guarantees |
|---|---|---|---|
| **A3** — consent must be recorded, not assumed | `authgate-kernel/src/tcb/consent.rs` | **TCB** — in the trusted core | When the adapter sets `requires_consent`, no `Permit` is possible without a consent record that ed25519-verifies under its claimed grantor key, is unexpired and unrevoked, and covers the actor, resource, and rights. Folded into the binding hash (tamper-evident). The kernel does **not** verify the grantor is the resource's rightful owner — that is the policy layer's job (L2). |
| **A4/A5** — no action may coerce or deceive | `authgate-kernel/src/semantic_gate.rs` | **NOT TCB** — advisory heuristic | A typed `SemanticGate` interface + `CoercionAnalyzer` (exit-blocking, HHI concentration, deception markers). Returns a `SemanticVerdict`; it **never structurally denies** — it is an input to a policy decision. |
| **A7** — MahdaviCompass (move toward the final order) | `authgate-kernel/src/compass/` | **NOT TCB** — advisory scorer | `C(a) = w₁·RVD + w₂·VOI + w₃·CD` as a **post-hoc scorer that annotates, never denies**. Any deny threshold is operator policy, not theory (`flagged_below`). |

Each ships with adversarial coverage: `consent_redteam.rs` (18), `semantic_gate_redteam.rs`
(15), and `compass/redteam.rs` (14) — including honest tests for known heuristic
evasions (e.g. unicode homoglyphs) and a test asserting the Compass never denies.

---

## Architecture

```
Human Principal  (trust root)
        │  signs CapabilityProof chains
        │  sets min_epoch to revoke cohorts
        ▼
CanonicalAction  (sealed by adapter)
   actor_id, resource_hash, required_rights,
   capability_proofs[], revocation_proofs[],
   nonce, timestamp, min_epoch,
   binding_hash = SHA-256(all fields above)
        │
        ▼
┌──────────────── CallGate ─────────────────────────────┐
│  [L1] verify binding_hash             (AT-1)          │
│  [L2] for each cap where subject == actor:            │
│       resource_hash match?            (AT-6.1)        │
│       expiry >= now?                  (AT-3.6)        │
│       epoch >= min_epoch?             (AT-3.2)        │
│       validate_chain():                               │
│         depth ≤ 16                   (AT-2.7)        │
│         each node epoch >= min_epoch  (AT-3.1)        │
│         ed25519 valid                 (AT-2.3/4)      │
│         SHA-256(pubkey)==subject_id   (AT-5.1)        │
│         rights ⊆ parent.rights       (AT-2.6)        │
│       rights sufficiency                              │
│  [L3] root-signed revocations        (AT-3.3/4)      │
└───────────────────────────────────────────────────────┘
        │
   Decision::Permit  or  Decision::Deny { reason }
        │
        ▼
  AuditLog  (SHA-256 hash-chained, tamper-evident, thread-safe)
```

**Security-enforcing critical path:** `tcb/engine.rs` + `tcb/dag.rs` +
`tcb/call_gate.rs`. `#![forbid(unsafe_code)]` on TCB files. `engine::verify` is
`pub(crate)` — bypassing `CallGate` is a compile-time type error where that
boundary is enforced.

**Identity binding:** `subject_id = SHA-256(issuer_pubkey)`. Every delegation node must satisfy this. An attacker who knows a parent proof hash but not the parent private key cannot forge a child.

**Revocation:** Set `min_epoch` in each action. All proofs with `epoch < min_epoch` are rejected. No revocation list required — advancing the epoch invalidates an entire compromised cohort in O(1).

---

## Repository layout

```
freedom-kernel/src/
  tcb/               ← TRUSTED COMPUTING BASE — all security guarantees live here
    call_gate.rs       CallGate — only public TCB entry point
    engine.rs          pub(crate) verify(action, root_key, now) → Decision
    dag.rs             delegation chain traversal + attenuation + resource propagation
    types.rs           CanonicalAction, CapabilityProof, RevocationProof, Rights
    tests.rs           73 tests — one per security invariant path
    hardening_tests.rs 31 adversarial tests (resource redirection, crypto, proptest)
  sequence.rs        SequenceContext — policy helper (NOT in TCB)
  sandbox.rs         SandboxedExecutor — WASM capability-gated tool runner

formal/
  authgate_v3.tla / AuthGateV3.tla   TLA+ model (TLC: see COVERAGE.md)
  MC_AuthGateV3.tla|.cfg             Bounded TLC instance
  tlc_run.log                        Latest green TLC log (bounded)
  kani/                              Kani harnesses (bounded)
  lean4/                             Lean 4 modules (partial; crypto axiomatized)
  COVERAGE.md                        What is and is not discharged
  INCOMPLETENESS.md                  Explicit gaps

attack_harness/
  wire_attacks.py        27 wire boundary tests (WA-1 through WA-18)
  differential_tests.py  20 differential tests (Python model boundary semantics)
  mutation_attacks.py    20 mutation tests
  simulation/            231-scenario adversarial simulation engine

src/authgate/        Python compatibility runtime (NOT TCB)
  kernel/            FreedomVerifier, OwnershipRegistry, AuditLog, Action
    distributed_kernel.py   Merkle state, threshold revocations, partition policy
    recursive_governance.py  Delegation depth bounds, anti-feudal, revocation propagation
    constitutional_economy.py  Oligarchy detection, sovereignty erosion, lock-in
    exit_guarantees.py      Exit rights, identity portability, revocation reachability
    federation.py           Cross-kernel federation, constitutional consensus
    multi_agent_coordinator.py  Coalition detection, dependency graph analysis
    sandbox_executor.py     Capability-gated tool execution (Python layer)
    consent.py              ConsentCapability — revocable, contextual, non-delegable
    inalienable.py          InnalienableRights — structural rights that cannot be waived
    sovereign_identity.py   Commitment-based selective disclosure (ZK-compatible)
    persuasion.py           PersuasionBoundaryChecker — structural manipulation detection
    anti_capture.py         AntiCaptureChecker — scope drift, credential access
    coercion.py             CoercionAnalyzer — formal coercion boundary detection
    override_detector.py    OverrideDetector — lock-in pattern detection
    sovereignty_metrics.py  HHI-based dependency, reversibility index, agency score
    tool_abi.py             Typed tool ABI — ToolSchema, ToolParam, ToolABIRegistry
    audit.py                AuditLog — SHA-256 hash-chain + Ed25519 signed export
  key_rotation.py    RotationCertificate, ActiveKeySet, key rotation protocol
  errors.py          Typed exception hierarchy (AuthgateError → …)
  cli.py             authgate-cli — verify / audit / key subcommands
  adapters/          Framework adapters (LangChain, OpenAI, Anthropic, AutoGen, DSPy)
  extensions/        Heuristic layers (IFC, manipulation scorer) — not TCB

examples/
  langchain_integration/demo.py   End-to-end integration demo (Phase D2)
```

---

## Quick start

### Rust (TCB — use this for production)

```rust
use authgate_kernel::tcb::{
    call_gate::CallGate,
    types::{CanonicalAction, Decision, RIGHT_READ},
};

let gate = CallGate::new(root_verifying_key);
let mut action = build_canonical_action(/* ... */);
action.binding_hash = action.compute_hash();

match gate.execute(&action, unix_now()) {
    Decision::Permit => execute_action(),
    Decision::Deny { reason } => reject(reason),
}
```

### Python (non-TCB compatibility runtime)

```python
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog

# Build registry once
registry = OwnershipRegistry()
human = Entity("alice", AgentType.HUMAN)
bot   = Entity("analyst-bot", AgentType.MACHINE)
data  = Resource("sales-data", ResourceType.DATASET, scope="/data/sales/")

registry.register_machine(bot, human)
registry.add_claim(RightsClaim(bot, data, can_read=True))

# Freeze registry before verifying (eliminates TOCTOU)
frozen   = registry.freeze()
audit    = AuditLog(path="/var/log/authgate.jsonl")
verifier = FreedomVerifier(frozen, audit_log=audit)

result = verifier.verify(Action("read-sales", actor=bot, resources_read=[data]))
print(result.summary())
# [PERMITTED] read-sales (confidence=1.00, manipulation=0.00)

# Verify audit chain integrity
assert audit.verify_chain()
```

### CLI

```bash
pip install -e .

# Verify an action against a registry file
authgate-cli verify --registry registry.json --action action.json --audit log.jsonl

# Verify audit log chain integrity
authgate-cli audit verify /var/log/authgate.jsonl

# Replay entry 42
authgate-cli audit replay /var/log/authgate.jsonl 42

# Audit statistics
authgate-cli audit stats /var/log/authgate.jsonl
```

### WASM sandbox (feature-gated)

```bash
cargo build --features sandbox
```

`SandboxedExecutor` wraps `CallGate` — permitted actions run inside a WASM instance whose host function imports are limited to the rights bitmask. An action permitted by the gate but requesting an unlisted host function fails at WASM instantiation time, not at runtime.

---

## Running tests

```bash
# Rust TCB
cd freedom-kernel
cargo test --lib
cargo test --features sandbox

# Kani model checking
cargo kani --harness prop_attenuation_two_node
cargo kani --harness prop_epoch_check
cargo kani --harness proof_forged_revocation_ignored

# Lean 4
cd formal/lean4 && lake build

# Python integration (273 tests)
pip install -e ".[dev]"
pytest

# Python attack harness
python attack_harness/wire_attacks.py
python attack_harness/differential_tests.py
python attack_harness/mutation_attacks.py

# Integration demo
python examples/langchain_integration/demo.py
```

---

## Security invariants (TCB)

Nine invariants enforced on every `verify()` call, in strict order:

| # | Name | Claim |
|---|---|---|
| I1 | CanonicalBinding | `action.binding_hash == SHA-256(all other fields)` |
| I2 | IdentityBinding | `cap.subject_id == action.actor_id` |
| I3 | ExpiryGate | `cap.expiry >= now` |
| I4 | EpochSafety | `cap.epoch >= action.min_epoch` (leaf + all chain nodes) |
| I5 | ResourceBinding | `cap.resource_hash == action.resource_hash` |
| I6 | Attenuation | `child.rights ⊆ parent.rights` at every delegation step |
| I7 | ChainEpoch | Every intermediate chain node satisfies EpochSafety |
| I8 | ChainComplete | Every `Delegated` cap in a Permit has a valid parent in the bundle |
| I9 | RevocationSafety | Only root-signed revocations affect decisions |

**Minimal generating set:** {I2, I3, I4, I5, I6, I7, I8} — I1 and I9 are implied by structural integrity.

---

## Branch layout

| Branch | Role | Merge rule |
|---|---|---|
| `main` | Production — the only branch that deploys | CI green + all attack classes closed |
| `spec-core` | Formal spec — TLA+, Lean 4, threat model | TLC-verified or Lean-discharged |
| `tcb-core` | Rust kernel — `call_gate.rs`, `engine.rs`, `dag.rs` | CI + attack regression clean |
| `adversarial-lab` | Attack harness — black-box probes | Never merges to main directly |
| `integration` | Python runtime, adapters, CLI | TCB contract satisfied |

Merge path: `adversarial-lab → spec-core → tcb-core → main` and `integration → main`.

---

## Engineering Gaps

The gap between `Permit/Deny` and actual constrained execution:

| Gap | Status | What closes it |
|---|---|---|
| **WASM sandbox** (`cargo build --features sandbox`) | Blocked: Windows SDK kernel32.lib missing | Install Windows SDK 10.0.22621 or build on Linux |
| **OS-level confinement** (seccomp-bpf) | Not implemented | Wrap tool subprocess with seccomp filter |
| **End-to-end integration test** | **Done** (`tests/test_integration_e2e.py`) | 18 assertions: tool call → gate → audit chain |
| **TLC model checker** | Java not installed | `java -jar tla2tools.jar -tool MC_AuthGateV3` |
| **CLI** | Exists; not packaged | `pip install authgate-kernel` |

The WASM sandbox is the most important. When it exists, the enforcement chain becomes:
```
Agent → CallGate → Capability-bound WASM instance → restricted host imports → actual IO
```
A tool that imports `write_byte` but was only granted `RIGHT_READ` fails at WASM instantiation — a missing symbol, not a runtime check.

## Explicit limitations

| # | Limitation |
|---|---|
| L1 | Semantic content not checked — natural language intent is not gated |
| L2 | Malicious trust root is out of scope |
| L3 | Side channels not addressed (timing, covert, steganography) |
| L4 | Python runtime is not formally checked |
| L5 | Extensions (IFC, manipulation scorer) are heuristic, not TCB |
| L6 | Distributed consistency: `distributed_kernel.py` covers the Python layer; Rust distributed consensus is future work |
| L7 | No implementation-level refinement proof from TLA+ to Rust |
| L8 | Clock integrity is caller-supplied — compromised clock not detected |

---

## Contributing

Before opening a PR on `src/tcb/`, answer:

> *Can this feature exist entirely outside `src/tcb/`?*

If yes, it doesn't belong in the TCB. TCB changes require a written invariant justification in `spec-core`, a Kani or Lean proof, and a regression test in `adversarial-lab`. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`BRANCHES.md`](BRANCHES.md).

---

## License

**Source-available** under the [PolyForm Noncommercial License 1.0.0](LICENSE) — see also [`NOTICE`](NOTICE).

| Use | Status |
|---|---|
| Evaluation | ✅ Allowed |
| Research | ✅ Allowed |
| Educational | ✅ Allowed |
| Internal non-commercial testing | ✅ Allowed |
| Redistribution (non-commercial) | ✅ Allowed, with attribution |
| Production deployment | ⛔ Requires commercial license |
| Commercial use / SaaS / resale | ⛔ Requires commercial license |
| Patent rights | Reserved |

A **commercial license is available separately.** For production or commercial use,
contact **Ali Pourrahim — Alipourrahim.ap@gmail.com**.
