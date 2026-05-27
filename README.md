# authgate-kernel

**Capability-security runtime for autonomous agents. Formally verified. No heuristics.**

[![CI](https://github.com/Aliipou/authgate-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Aliipou/authgate-kernel/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/kernel-Rust-orange.svg)](authgate-kernel/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kani](https://img.shields.io/badge/verified-Kani%2019%20harnesses-green.svg)](formal/)
[![Lean4](https://img.shields.io/badge/proved-Lean4%204%20theorems-blue.svg)](formal/lean4/)

---

## What this is

A structurally unavoidable permission gate between an LLM and the world. Before any agent action executes, the kernel verifies typed capability claims against an ownership graph. If the agent lacks explicit, valid, non-expired authority — it is blocked. No argument overrides a sovereignty flag.

~200 lines of pure Rust form the Trusted Computing Base (TCB). No ML. No natural language parsing. No "trust scores". The Python layer mirrors the Rust logic and is used when the Rust kernel is not compiled.

---

## What this is NOT

| Not this | Why it is explicitly excluded |
|---|---|
| Alignment solution | Alignment operates on values and intent; this kernel operates on typed authority graphs |
| Intent verifier | The kernel does not parse, interpret, or score natural language output |
| Ethics engine | Ethical reasoning requires semantic content; this kernel is purely structural |
| Behavioral monitor | No runtime heuristics or anomaly detection in the TCB |
| Covert channel detector | Timing, steganography, and side-channel leakage are out of scope by design |
| LLM output sanitizer | The kernel gates actions, not token streams |

See [`NON_GOALS.md`](NON_GOALS.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for full boundaries.

---

## Architecture

```
Human Principal
  (trust root — registered owner of all machines)
        │
        │  registers machines, delegates claims
        ▼
OwnershipRegistry
  - claims map: (actor, resource) → RightsClaim
  - delegation chains: child_capability ⊆ parent_capability
  - machine → human owner entries
        │
        │  typed Action IR (actor, resources[], capability_kind, flags[])
        │  no natural language — structured data only
        ▼
engine.rs   ◄────────────────────────────────────────────────────────┐
  (TCB gate, ~200 LOC)                                               │
  [1] sovereignty flag check  — O(1), unconditional                  │
  [2] machine ownership check — is actor in registry?                │
  [3] machine-governs-human   — is actor attempting dominion?        │
  [4] capability claim check  — does actor hold valid claim?         │
        │                                                            │
        ├── PERMITTED ──► AuditLog (append-only, cryptographically   │
        │                           signed, JSON)                    │
        │                                                            │
        └── BLOCKED   ──► halt + surface violation to human owner ──┘
                           (owner may inspect, retry with correction)
```

**Trusted Computing Base:** `engine.rs`, `capability.rs`, `wire.rs`, `crypto.rs`, and the new `src/tcb/` module (v2 stateless kernel).
Everything else — adapters, extensions, scheduler, registry logic — is outside the TCB.

### Repository layout

```
freedom-kernel/src/
  engine.rs           registry-based verifier (v1, production)        — TCB
  capability.rs       closed capability algebra (enums only)           — TCB
  wire.rs             typed JSON wire format (serde, no logic)         — TCB
  crypto.rs           ed25519 attestation                              — TCB
  tcb/                stateless proof-chain kernel (v2, in progress)   — TCB
    types.rs            CanonicalAction + CapabilityProof + Rights
    engine.rs           verify(action, root_key, now) -> Decision
    dag.rs              delegation chain validation + attenuation
    sequence.rs         composition safety tracker (SequenceContext)
  ffi.rs              C ABI — thin facade                              — not TCB
  verifier.rs         PyO3 facade over engine.rs                       — not TCB
  registry.rs         ownership registry (v1; not truth in v2)        — not TCB

src/authgate/
  kernel/          Python implementation (mirrors Rust)
  extensions/      heuristic layers — explicitly NOT TCB
    ifc.py         Bell-LaPadula non-interference
    detection.py   manipulation scorer (heuristic signal)
    synthesis.py   rule admission engine

formal/
  kani/            Kani bounded model-checking harnesses
  lean4/           Lean 4 proofs (Core.lean, Invariants.lean, Proofs.lean)

attack_harness/
  mutation_attacks.py        20 mutation tests — one security check per test
  canonicalization_attacks.py  5 canonical gate attacks (CA-1 through CA-5)
  sequence_attacks.py          5 composition safety attacks (SA-1 through SA-4)
```

### v2 TCB design

The v2 kernel (`src/tcb/`) is stateless and registry-free. All authority is carried in signed capability proof chains. Key design decisions:

**Canonical gate (Layer 1):** Every action arrives as a `CanonicalAction` with a `binding_hash` over all fields. The kernel recomputes this hash before touching any proof — IR tampered between adapter and kernel is rejected before any cryptographic work begins.

**Epoch-based primary revocation:** Instead of distributing revocation lists, the caller sets `min_epoch` in each action. Capability proofs with `epoch < min_epoch` are rejected without consulting any revocation list. Advancing the epoch invalidates an entire cohort of proofs in O(1).

**Revocation proofs (secondary):** Emergency single-proof revocation via root-signed `RevocationProof`. Forged or invalid-signature revocations are silently skipped — attackers cannot force a Deny by injecting garbage revocation proofs.

**Composition safety:** `SequenceContext` tracks the union of all rights exercised within a session. Policy layers compare the accumulated state against the session limit, closing the gap where individually-permitted actions compose into a globally-invalid sequence.

### TCB guards (CI-enforced on every commit)

**`engine.rs`:**

| Guard | Rule |
|---|---|
| LOC ceiling | Must stay ≤ 300 lines |
| Public API | Exports exactly one function: `verify` |
| Import scope | May only import from `crate::capability` and `crate::wire` |
| Purity | No randomness, network, or filesystem calls |

**`capability.rs`:**

| Guard | Rule |
|---|---|
| LOC ceiling | Must stay ≤ 200 lines |
| Self-contained | No `use crate::` imports |
| Enums only | No struct definitions — structs carry state and open extension points |

---

## Security guarantees

These are formal properties of `engine.rs`, verified by Kani and Lean 4. They apply to the Rust TCB only.

| Property | Formal statement |
|---|---|
| **P1 Confinement** | An agent cannot act on resources outside its explicit claim set. For all actions A and resources R: if `verify(A) = PERMITTED` then `∀r ∈ resources(A): actor holds valid claim on r`. |
| **P2 Attenuation** | Delegated authority is a strict subset of the delegator's authority. `child_claim.rights ⊆ parent_claim.rights` is enforced at delegation time; violations raise `PermissionError`. |
| **P3 Sovereignty Invariants** | All 10 sovereignty flags produce `BLOCKED` for any input, with no exceptions. Verified exhaustively by Kani over all possible input combinations. |
| **P4 Determinism** | `verify` is a pure function. Same typed input → same output. No hidden state, no randomness, no I/O. Proved in Lean 4 (`verify_deterministic`). |
| **P5 Cryptographic Attestation** | Every `PERMITTED` result is signed with ed25519. A signed result cannot be fabricated without the kernel's private key. Timestamp + nonce prevent replay. |

**Scope:** These properties cover `engine.rs` behaviors on typed inputs. Not covered: the Python implementation, extensions, adapters, multi-agent semantics, or any property involving natural language content.

See [`formal/INCOMPLETENESS.md`](formal/INCOMPLETENESS.md) for an explicit enumeration of what is not proved.

---

## Capability taxonomy

All 17 capability kinds recognized by the kernel, with risk classification:

| CapabilityKind | Risk | Description |
|---|---|---|
| `READ` | Low | Read access to a resource |
| `WRITE` | Medium | Write or mutate a resource |
| `EXECUTE` | Medium | Execute a process or command |
| `DELETE` | High | Permanently remove a resource |
| `DELEGATE` | High | Grant authority to another agent |
| `NETWORK_EGRESS` | High | Outbound network connections |
| `NETWORK_INGRESS` | High | Accept inbound network connections |
| `FILE_SYSTEM` | High | Broad filesystem access |
| `PROCESS_SPAWN` | High | Spawn child processes or agents |
| `MEMORY_WRITE` | High | Write to process memory |
| `CREDENTIAL_READ` | Critical | Access secrets, tokens, keys |
| `CREDENTIAL_WRITE` | Critical | Modify or rotate credentials |
| `AUDIT_READ` | Critical | Read audit logs |
| `AUDIT_WRITE` | Critical | Append to or modify audit logs |
| `POLICY_READ` | Critical | Read policy definitions |
| `REGISTRY_MODIFY` | Catastrophic | Modify the ownership registry |
| `POLICY_MODIFY` | Catastrophic | Modify kernel policy or sovereignty flags |

`REGISTRY_MODIFY` and `POLICY_MODIFY` require explicit human-principal authorization and cannot be delegated by machine actors.

---

## Quick start

```python
from authgate import (
    Action, AgentType, Entity, FreedomVerifier,
    OwnershipRegistry, Resource, ResourceType, RightsClaim,
)

alice  = Entity("Alice",       AgentType.HUMAN)
bot    = Entity("ResearchBot", AgentType.MACHINE)

dataset = Resource("alice-data", ResourceType.DATASET, scope="/data/alice/")
report  = Resource("report.txt", ResourceType.FILE,    scope="/outputs/")

registry = OwnershipRegistry()
registry.register_machine(bot, alice)
registry.add_claim(RightsClaim(alice, dataset, can_read=True, can_write=True, can_delegate=True))
registry.add_claim(RightsClaim(bot,   dataset, can_read=True))
registry.add_claim(RightsClaim(bot,   report,  can_read=True, can_write=True))

verifier = FreedomVerifier(registry)

result = verifier.verify(Action("write-report", bot, resources_write=[report]))
print(result.summary())
# [PERMITTED] write-report (confidence=1.00)

result = verifier.verify(Action("self-expand", bot, increases_machine_sovereignty=True))
print(result.summary())
# [BLOCKED] self-expand — VIOLATION: FORBIDDEN (increases machine sovereignty)
```

**Install:**

```bash
pip install authgate                        # pure Python, no build toolchain
pip install maturin && cd authgate-kernel && pip install .   # with Rust kernel
```

```python
from authgate.kernel import _BACKEND
print(_BACKEND)  # "rust" or "python"
```

---

## Forbidden flags

Any `Action` with any of these flags set to `True` is **unconditionally blocked**.
No context, argument, or emergency overrides them. Flag check is O(1).

| Flag | Invariant enforced |
|---|---|
| `increases_machine_sovereignty` | Machines do not accumulate ungranted authority |
| `resists_human_correction` | Human owners must be able to halt or revoke at any time |
| `bypasses_verifier` | Circumventing the gate is itself a sovereignty violation |
| `weakens_verifier` | Degrading enforcement strength is forbidden |
| `disables_corrigibility` | Corrigibility is structural, not a preference |
| `machine_coalition_dominion` | Collective machine dominion over persons is blocked |
| `coerces` | Coercion invalidates consent |
| `deceives` | Deception produces invalid consent |
| `self_modification_weakens_verifier` | Equivalent to bypassing the gate |
| `machine_coalition_reduces_freedom` | Coordinated machine action reducing human freedom |

---

## Limitations

These are explicit, non-negotiable limitations of the current system:

| # | Limitation |
|---|---|
| **L1** | **Semantic content is not checked.** An agent that encodes harmful intent in its text output is not detected. The kernel gates typed actions, not natural language. |
| **L2** | **A malicious human owner is out of scope.** The system requires a trust root. It does not verify that the root is itself trustworthy. This is an explicit design choice, not an oversight. |
| **L3** | **Side channels are not addressed.** Timing attacks, steganography, and covert channel leakage are out of scope. |
| **L4** | **The Python implementation is not formally verified.** Only `engine.rs` is under Kani/Lean 4 proofs. The Python layer is tested but not proved. |
| **L5** | **Extensions are heuristic.** `manipulation_score`, IFC labels, and similar signals are probabilistic. They are not TCB components and do not carry formal guarantees. |
| **L6** | **Distributed consistency requires additional infrastructure.** The registry is in-process. Multi-node deployments require an external consensus layer; the kernel does not provide one. |
| **L7** | **Cross-runtime attestation is not yet standardized.** Signed results from one kernel instance are verifiable but there is no cross-instance revocation protocol yet. |

---

## Integrations

The kernel exposes a C ABI for language-agnostic use:

```c
#include "authgate_kernel.h"

char out[FREEDOM_KERNEL_MAX_OUTPUT];
const char *input = "{\"registry\":{...},\"action\":{...}}";
authgate_kernel_verify(input, strlen(input), out, sizeof(out));
// {"permitted":true,"signature":"...","signing_key":"...","key_id":"..."}
```

JSON in, JSON out. Confirmed working from: **C, Go, Zig, Java (JNA), Node.js (ffi-napi)**.

**Framework adapters (outside TCB):**

| Adapter | Status | Notes |
|---|---|---|
| LangChain | Available | Tool wrapper — intercepts `tool.run()` calls |
| OpenAI Agents SDK | Available | Function-call hook before execution |
| AutoGen | Available | Agent message interceptor |
| Anthropic (Claude) | Available | Tool use → Action IR → verify → execute |
| C ABI | Stable | Go, Zig, Java, Node.js via FFI |

---

## Benchmarks

Measured on x86-64 Linux, single core, Rust release build. Python numbers are ~10-20x higher.

| Benchmark | Target | Typical | Notes |
|---|---|---|---|
| `verify()` — permit path | < 5 µs | ~2 µs | Single claim lookup, O(claims) |
| `verify()` — blocked (flag) | < 1 µs | ~0.3 µs | Flag check is O(1), exits immediately |
| Registry, 10k claims | < 50 µs | ~30 µs | Linear scan; hash index planned |
| Delegation chain, depth 16 | < 200 µs | ~120 µs | Full chain validation |
| Cascading revocation, 100 agents | < 1 ms | ~600 µs | BFS over ownership graph |

Run benchmarks:

```bash
cargo bench --bench verify_bench
```

---

## Formal verification

### Kani bounded model-checking

Covers `engine.rs` (v1) and `src/tcb/` (v2). Each harness is symbolically executed over all possible inputs within unwind bounds.

**v1 harnesses (19):**

| Harness | What is verified |
|---|---|
| `prop_increases_machine_sovereignty` … `prop_coalition_reduces_freedom` | All 10 flags produce BLOCKED, for any input |
| `prop_ownerless_machine_blocked` | Machine with no owner entry → BLOCKED, always |
| `prop_machine_governs_human_blocked` | Machine governing human → BLOCKED, always |
| `prop_public_resource_read_permitted` | `is_public=true` + read → PERMITTED, always |
| `prop_write_denied_without_claim` / `prop_read_denied_without_claim` | No claim → BLOCKED |
| `prop_permitted_deterministic` | Same input → same output, no hidden state |
| `prop_permitted_implies_no_violations` | PERMITTED ↔ violations list is empty |
| `prop_blocked_implies_violations_non_empty` | BLOCKED ↔ at least one violation |

**v2 harnesses (3, `formal/kani/`):**

| Harness | What is verified |
|---|---|
| `prop_attenuation_two_node` | Child rights ⊆ parent rights for all bitmask combinations |
| `prop_epoch_check` | Epoch gate is a total relation (no third case exists) |
| `proof_forged_revocation_ignored` | Invalid-sig revocation never changes Permit → Deny |

```bash
cargo kani --harness prop_increases_machine_sovereignty   # v1
cargo kani --harness prop_attenuation_two_node            # v2
```

### Lean 4

**Proved theorems (no `sorry` except where explicitly admitted at cryptographic boundaries):**

| Theorem | File | What is proved |
|---|---|---|
| `forbidden_flags_always_block` | Proofs.lean | Flag set → `permitted = false`, constructively |
| `verify_deterministic` | Proofs.lean | Pure function: no state, no effects |
| `attenuation_transitive` | Proofs.lean | If B ⊆ A and C ⊆ B then C ⊆ A (chain attenuation) |
| `rights_sufficiency_correct` | Proofs.lean | `required ⊆ cap.rights` ↔ rights check passes |
| `epoch_gate_total` | Proofs.lean | `cap_epoch < min_epoch ∨ min_epoch ≤ cap_epoch` — no third case |
| `stale_epoch_implies_deny` | Proofs.lean | Stale epoch → `¬FreshEpoch` — deny without revocation list |
| `subject_mismatch_violates_binding` | Proofs.lean | `cap.subject ≠ actor_id` → `¬SubjectBinding` |

**Admitted (axiomatized from cryptographic assumptions):**

| Axiom | Assumption |
|---|---|
| `sig_euf_cma` | ed25519 EUF-CMA security — unforgeability of valid signatures |
| `forged_revocation_harmless` | Invalid-sig revocations do not affect decisions — proved by code inspection |

```bash
cd formal/lean4 && lake build
```

**Proof scope:** TCB behaviors on typed inputs. Not proved: Python implementation, extensions, adapters, multi-agent semantics, or any property involving natural language. See [`formal/INCOMPLETENESS.md`](formal/INCOMPLETENESS.md).

### Attack harness (25 tests, all passing)

```bash
cd attack_harness
python mutation_attacks.py           # 10 tests: one per security check in engine.rs
python canonicalization_attacks.py   # 5 tests: CA-1 through CA-5
python sequence_attacks.py           # 5 tests: SA-1 through SA-4 + edge cases
```

These are black-box regression tests for the security properties. They run against the Python model of the v2 TCB and serve as ground truth for what the Rust TCB must implement.

---

## Contributing

Before opening a PR, answer one question:

> **Can this feature exist entirely outside `engine.rs`?**

If yes — it does not belong in the TCB. Extensions, adapters, and new capability kinds are welcome outside the TCB. Changes that touch TCB files (`engine.rs`, `capability.rs`, `wire.rs`, `crypto.rs`) require a written justification and must pass all CI guards.

The pull request template enforces this check. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`TCB.md`](TCB.md).

---

## Ecosystem

```
authgate-kernel   — this repo, engineering only
freedom-specs    — formal RFCs and specifications
authgate   — theoretical foundations (not required to use the kernel)
```

The theoretical foundations are in [authgate](https://github.com/Aliipou/authgate) — a separate repository by design. Using, auditing, or deploying the kernel requires no engagement with it.

---

## Running tests

```bash
pip install -e ".[dev]"
pytest --cov=authgate   # 165 tests, 85% coverage gate
```

---

## License

MIT. See [LICENSE](LICENSE).
