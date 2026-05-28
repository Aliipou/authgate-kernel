# authgate-kernel

**Capability-security runtime for autonomous agents. Mechanically checked core invariants. No heuristics inside the TCB.**

[![CI](https://github.com/Aliipou/authgate-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Aliipou/authgate-kernel/actions)
[![Rust](https://img.shields.io/badge/kernel-Rust-orange.svg)](freedom-kernel/)
[![Kani](https://img.shields.io/badge/Kani-19%20harnesses-green.svg)](formal/)
[![Lean4](https://img.shields.io/badge/Lean4-7%20theorems-blue.svg)](formal/lean4/)
[![Tests](https://img.shields.io/badge/TCB%20tests-78%20passing-brightgreen.svg)](freedom-kernel/src/tcb/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What this does

Every agent action passes through a capability gate before execution. The gate answers one question in pure Rust, with no global state:

> Does this actor hold a valid, non-expired, cryptographically signed capability for this resource and these rights, issued by a chain traceable to the trust root?

If yes: `Decision::Permit`. If no: `Decision::Deny { reason }`. No exceptions. No overrides. No probability scores.

The kernel is stateless. Authority lives in signed `CapabilityProof` chains passed with each request — no registry lookup, no network call, no side effects. The same action with the same proofs always produces the same decision.

**Trusted Computing Base surface area:** `src/tcb/` — 5 files, ~510 LOC, `#![forbid(unsafe_code)]` everywhere. That is the entire kernel. Everything else is untrusted.

---

## What this does NOT do

| Not this | Why |
|---|---|
| Alignment | Alignment is about values and intent. This kernel is about typed authority. |
| Intent verification | The kernel does not parse, score, or interpret natural language. |
| Ethics enforcement | Ethical reasoning requires semantic content. The kernel is purely structural. |
| Side-channel defense | Timing attacks, steganography, covert channels — out of scope by design. |
| Distributed consensus | The kernel is in-process. Multi-node deployments require an external consensus layer. |
| Behavioral monitoring | No heuristics or anomaly detection inside the TCB. |
| Python-equivalent security | The Python layer is a non-TCB compatibility runtime — not formally checked. |

See [`NON_GOALS.md`](NON_GOALS.md) and [`formal/INCOMPLETENESS.md`](formal/INCOMPLETENESS.md) for the full enumeration.

---

## Architecture

```
Human Principal  (trust root)
        │
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
│  The only public entry point into the TCB.            │
│  engine::verify is pub(crate) — bypassing CallGate    │
│  is a compile-time type error. (AT-7.5 closed)        │
│                                                       │
│  [L1] verify binding_hash ─────────────── AT-1        │
│  [L2] for each cap where subject == actor:            │
│       resource_hash match? ──────────── AT-6.1        │
│       expiry >= now? ────────────────── AT-3.6        │
│       epoch >= min_epoch? ──────────── AT-3.2        │
│       validate_chain():                               │
│         depth ≤ 16 ─────────────────── AT-2.7        │
│         each node epoch >= min_epoch ── AT-3.1        │
│         ed25519 valid ──────────────── AT-2.3/4       │
│         SHA-256(pubkey)==subject_id ─── AT-5.1        │
│         rights ⊆ parent.rights ──────── AT-2.6        │
│       rights sufficiency                              │
│  [L3] root-signed revocations ─────────── AT-3.3/4   │
└───────────────────────────────────────────────────────┘
        │
   Decision::Permit  or  Decision::Deny { reason }
```

**Identity model:** `subject_id = SHA-256(issuer_pubkey)`. Every delegation node in a chain must satisfy this binding. An attacker who knows a parent proof hash but does not hold the parent's private key cannot forge a child delegation (AT-5.1).

**Epoch-based revocation:** The caller sets `min_epoch` in each action. All capability proofs with `epoch < min_epoch` are rejected — no revocation list required. Advancing the epoch invalidates an entire compromised cohort in O(1).

---

## Repository layout

```
freedom-kernel/src/
  tcb/               ← THE TRUSTED COMPUTING BASE (all security guarantees live here)
    call_gate.rs       CallGate — only public entry point; verify() is pub(crate)
    engine.rs          pub(crate) verify(action, root_key, now) → Decision
    dag.rs             delegation chain traversal + attenuation enforcement
    sequence.rs        SequenceContext — session-scoped rights accumulation
    types.rs           CanonicalAction, CapabilityProof, RevocationProof, Rights
    tests.rs           56 targeted tests (one mutation → one deny path each)

  engine.rs          v1 registry-based verifier (used by Python adapter)
  capability.rs      closed capability taxonomy (enums only, no logic)
  wire.rs            typed JSON wire format (serde, no logic)
  crypto.rs          ed25519 kernel signing key (audit log attestation)
  ffi.rs             C ABI — thin facade, not TCB
  verifier.rs        PyO3 adapter — not TCB

formal/
  authgate_v3.tla    TLA+ state machine (9 invariants, PermitSoundness theorem)
  MC_AuthGateV3.tla  TLC-runnable model (finite actor/resource/epoch sets)
  MC_AuthGateV3.cfg  TLC configuration
  kani/              Kani bounded model-checking harnesses (19 harnesses)
  lean4/             Lean 4 proofs (7 theorems, 2 admitted crypto axioms)
  COVERAGE.md        What is and is not formally verified
  INCOMPLETENESS.md  Explicit enumeration of gaps

attack_harness/
  mutation_attacks.py          20 mutation tests — one security check per test
  canonicalization_attacks.py  5 canonical gate attacks
  sequence_attacks.py          5 composition attacks
  attack_tree_coverage.py      21 tests across AT-1 through AT-7
  simulation/                  231-scenario adversarial simulation engine

src/authgate/        Python compatibility runtime (NOT TCB, NOT formally checked)
  kernel/            Python mirror of v1 registry verifier
  extensions/        Heuristic layers (IFC, manipulation scorer) — explicitly NOT TCB
```

---

## Branch architecture — Dual Reality

This project maintains three independent truths that must stay consistent but never contaminate each other. Merging without proof produces self-justifying security.

| Branch | Truth | What lives here | Merge rule |
|---|---|---|---|
| `main` | Ground truth | The only branch that deploys | CI green + zero CBCT-2 violations |
| `spec-core` | Mathematical truth | TLA+ spec, Lean4 proofs, THREAT_MODEL | TLC-verified or Lean-discharged |
| `tcb-core` | Execution truth | Rust TCB (≤600 LOC gate), CallGate | CI green + attack regression clean |
| `adversarial-lab` | Adversarial truth | Attack harness, simulation engine | Never merges to main directly |
| `integration` | Execution truth | Python adapters, MCP gate, LangGraph | TCB contract satisfied |

### Merge rules — no cross-contamination without proof

```
ALLOWED:
  adversarial-lab → spec-core     (new attack class → formal threat model)
  spec-core       → tcb-core      (proven invariant → Rust implementation)
  tcb-core        → main          (CI green + regression clean)
  integration     → main          (TCB contract satisfied)

FORBIDDEN:
  adversarial-lab → main          (attack finding ≠ production change)
  adversarial-lab → tcb-core      (no proof → no code change)
  spec-core       → adversarial-lab (backflow breaks independence)
```

### Branch guides

**`main`** — Ground truth. The only branch that deploys. No research-grade code ever merges here without passing through formal + CI gates.

**`spec-core`** — Mathematical truth. `formal/authgate_v3.tla` and `formal/MC_AuthGateV3.tla` live here. Work here is never compiled or deployed. Correctness is established by TLC model checking and Lean 4 theorem discharge. To add an invariant: define it in `authgate_v3.tla`, add it to `THREAT_MODEL.md`, write a TLC configuration entry.

**`tcb-core`** — Execution truth. The Rust kernel: `call_gate.rs`, `engine.rs`, `dag.rs`, `types.rs`, `sequence.rs`. Hard rules: total LOC ≤ 600, no IO, no network, no panics, no unsafe, `engine::verify` stays `pub(crate)`. Every public function maps to at least one invariant in spec-core.

**`adversarial-lab`** — Adversarial truth. Probes the kernel from the outside: craft a structurally invalid action, run it through the Python oracle, verify it is denied. A violation = kernel returned Permit for invalid input. Runs independently of spec-core (CBCT-3: no circular self-validation). Findings flow to spec-core; never directly to tcb-core.

**`integration`** — Execution truth (adapter layer). Python compatibility runtime, MCP gate, LangGraph adapter. The Python runtime must match tcb-core behavior on all inputs. Divergence = integration test failure, not a kernel change.

See [`BRANCHES.md`](BRANCHES.md) for the Cross-Branch Consistency Theorem (CBCT) and full merge rules.

---

## Test coverage

### TCB Rust tests (78 total, all passing)

| File | Tests | Coverage category |
|---|---|---|
| `engine.rs` (inline) | 5 | Basic permit/deny sanity checks |
| `dag.rs` (inline) | 7 | Chain validation: root, delegation, attenuation, AT-5.1, AT-3.1 |
| `sequence.rs` (inline) | 2 | Accumulation, limit detection |
| `tests.rs` (integration) | 56 | One test per security invariant path |
| `call_gate.rs` (inline) | 22 | All deny paths + consistency + AT-7.5 |

Every security check in `engine.rs` and `dag.rs` has:
1. A test that triggers it (deny path fires)
2. A test that does NOT trigger it on a valid input (happy path is not over-guarded)
3. A boundary test (expiry == now, epoch == min_epoch, etc.)

Named tests map to attack tree nodes (e.g. `deny_intermediate_node_stale_epoch_enforced` → AT-3.1, `deny_delegation_impersonation_blocked` → AT-5.1).

### Python adversarial harness (231 scenarios, 0 violations)

```
Mutation attacks:          20 tests — one field mutation per test
Canonicalization attacks:   5 tests — Layer 1 binding hash variants
Sequence attacks:           5 tests — SequenceContext composition
Attack tree coverage:      21 tests — all 7 AT classes
Simulation (composition): 231 scenarios — depth-2 mutation pairs
```

Run:
```bash
python attack_harness/mutation_attacks.py
python attack_harness/canonicalization_attacks.py
python attack_harness/sequence_attacks.py
python attack_harness/attack_tree_coverage.py
```

### Formal verification coverage

| Method | Coverage | Status |
|---|---|---|
| Kani (bounded model checking) | 19 harnesses on engine.rs and tcb/kani/ | All proved |
| Lean 4 | 7 theorems (forbidden flags, attenuation, epoch gate, subject mismatch, etc.) | 2 crypto axioms admitted |
| TLA+ (TLC) | 9 invariants + PermitSoundness theorem, MCConstraint ≤3 log entries | PENDING TLC run |

What is NOT covered: Python compatibility runtime, extensions (IFC, manipulation scorer), adapter layer semantics, distributed consistency, side channels.

---

## Security invariants (TCB)

Nine invariants are enforced on every `verify()` call, in order:

| # | Name | Claim |
|---|---|---|
| I1 | CanonicalBinding | `action.binding_hash == SHA-256(all other fields)` |
| I2 | IdentityBinding | `cap.subject_id == action.actor_id` for every actor cap |
| I3 | ExpiryGate | `cap.expiry >= now` |
| I4 | EpochSafety | `cap.epoch >= action.min_epoch` (leaf and every chain node) |
| I5 | ResourceBinding | `cap.resource_hash == action.resource_hash` |
| I6 | Attenuation | `child.rights ⊆ parent.rights` at every delegation step |
| I7 | ChainEpoch | Every intermediate chain node satisfies EpochSafety |
| I8 | ChainComplete | Every `Delegated` cap in a Permit has a valid parent in the bundle |
| I9 | RevocationSafety | Only root-signed revocations affect decisions |

**Invariant lattice:** I7 ⟹ I1 (chain epoch implies epoch safety). I8 is a prerequisite for I2 and I6 (cannot check attenuation without a complete chain). I4/I5/I9 are mutually independent. Minimal generating set: {I2, I3, I4, I5, I6, I7, I8}.

**AT-7.5 (shadow execution):** Closed. `engine::verify` is `pub(crate)`. External code that tries to call it directly is rejected by the Rust compiler. `CallGate::execute()` is the only public path into the kernel.

---

## Security guarantees (precise scope)

These properties hold for the Rust TCB (`src/tcb/`) on typed inputs. They do not extend to the Python runtime, adapter layer, or any property involving natural language.

| Property | Formal statement |
|---|---|
| **PermitSoundness** | Every `Decision::Permit` is produced only when a cap passes all 9 invariants |
| **DenySoundness** | Every `Decision::Deny` reports the first invariant that failed |
| **Attenuation** | `child.rights ⊆ parent.rights` at every delegation step — proven by Kani |
| **EpochTotal** | `cap.epoch < min_epoch ∨ cap.epoch ≥ min_epoch` — no third case — proven by Lean 4 |
| **Determinism** | Same action + same root key + same `now` → same decision, always |
| **NoBypass** | Calling `verify()` without going through `CallGate` is a compile-time error |

**What "mechanically checked" means here:** Kani exhaustively explores all `verify()` paths within unwind bounds. Lean 4 proves algebraic properties of the invariant structure. TLC checks the TLA+ state machine for finite model instances. None of these constitute a full implementation-level correctness proof (that requires refinement proofs from TLA+ to Rust — an open gap documented in `formal/INCOMPLETENESS.md`).

---

## Quick start

```rust
use authgate_kernel::tcb::{
    call_gate::CallGate,
    types::{CanonicalAction, Decision, RIGHT_READ},
};

// Build the gate once with your trust anchor key.
let gate = CallGate::new(root_verifying_key);

// Seal an action (adapter's responsibility).
let mut action = build_canonical_action(/* ... */);
action.binding_hash = action.compute_hash();

// Gate the action.
match gate.execute(&action, unix_now()) {
    Decision::Permit => execute_action(),
    Decision::Deny { reason } => reject(reason),
}
```

Python (non-TCB compatibility runtime):

```python
from authgate import FreedomVerifier, Action, OwnershipRegistry

registry = OwnershipRegistry()
# ... register actors, add claims ...

verifier = FreedomVerifier(registry)
result = verifier.verify(Action("write-report", bot, resources_write=[report]))
print(result.summary())
# [PERMITTED] write-report
```

**Note:** The Python `FreedomVerifier` is a compatibility runtime — not the Rust TCB. It is tested but not formally checked. Use the Rust `CallGate` for security-sensitive deployments.

---

## Running tests

```bash
# Rust TCB tests (78 tests)
cd freedom-kernel && cargo test --lib

# Kani model checking (per harness)
cargo kani --harness prop_attenuation_two_node
cargo kani --harness prop_epoch_check
cargo kani --harness proof_forged_revocation_ignored

# Lean 4 proofs
cd formal/lean4 && lake build

# Python attack harness
python attack_harness/mutation_attacks.py
python attack_harness/canonicalization_attacks.py
python attack_harness/sequence_attacks.py
python attack_harness/attack_tree_coverage.py

# Python oracle / integration tests
pip install -e ".[dev]"
pytest --cov=authgate
```

---

## Limitations (explicit, non-negotiable)

| # | Limitation |
|---|---|
| L1 | **Semantic content not checked.** The kernel gates typed actions, not LLM outputs. An agent encoding harmful intent in natural language is not blocked here. |
| L2 | **Malicious trust root is out of scope.** The system requires a trust anchor. It does not verify the root is itself trustworthy. |
| L3 | **Side channels not addressed.** Timing attacks, steganography, covert channels — out of scope by design. |
| L4 | **Python runtime is not formally checked.** Only the Rust TCB is under Kani/Lean 4. |
| L5 | **Extensions are heuristic.** IFC labels, manipulation scores — probabilistic, not proved, not TCB. |
| L6 | **Distributed consistency requires external infrastructure.** The kernel is in-process. Multi-node requires a separate consensus layer. |
| L7 | **No implementation-level refinement proof.** TLA+ spec and Rust implementation are aligned by design and testing, not by mechanized refinement proof. |
| L8 | **Clock integrity is caller-supplied.** A compromised clock is not detected by the kernel. |

---

## Contributing

Before opening a PR, answer one question:

> Can this feature exist entirely outside `src/tcb/`?

If yes — it does not belong in the TCB. TCB changes require a written justification, a corresponding spec-core invariant, and must pass all CI guards. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`BRANCHES.md`](BRANCHES.md).

The dependency order for new features is:
```
1. Define invariant in spec-core (TLA+ or THREAT_MODEL)
2. Verify formally (TLC or Lean proof)
3. Implement in tcb-core (Rust)
4. Close in adversarial-lab (attack scenario denied)
5. Mirror in integration (Python oracle updated)
6. Merge to main (all CI green)
```

Skipping steps 1–2 is tech debt. Skipping step 4 is an unclosed CBCT-2 gap.

---

## Ecosystem

| Repo | Purpose |
|---|---|
| `authgate-kernel` | This repo — engineering and implementation |
| `authgate-specs` | Formal RFCs and specifications |
| `freedom-theory` | Theoretical foundations (not required to use the kernel) |

---

## License

MIT. See [`LICENSE`](LICENSE).
