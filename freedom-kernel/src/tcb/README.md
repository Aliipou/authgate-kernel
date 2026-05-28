# TCB — Trusted Computing Base

The `tcb/` module is the entire security kernel. Everything outside it is untrusted.

## Public API

```rust
// The only way to call the kernel from outside this crate:
let gate = CallGate::new(root_key);
let decision = gate.execute(&action, now);
```

`engine::verify` is `pub(crate)`. Calling it from outside the crate is a compile-time error (AT-7.5 structural closure).

## Module map

| File | Role | LOC budget |
|---|---|---|
| `call_gate.rs` | Public entry point; wraps `engine::verify` | ≤ 50 |
| `engine.rs` | `pub(crate) verify()` — 3-layer decision logic | ≤ 120 |
| `dag.rs` | Delegation chain traversal and validation | ≤ 120 |
| `sequence.rs` | Session-scoped rights accumulation | ≤ 100 |
| `types.rs` | Data types: zero logic, zero IO | ≤ 120 |
| `tests.rs` | Integration test suite (56+ tests) | — |

## Invariant mapping

Every security check in `engine.rs` maps to a formal invariant in `formal/authgate_v3.tla`:

| Code check | TLA+ invariant | Attack class closed |
|---|---|---|
| `action.verify_binding()` | `I1 (CanonicalBinding)` | AT-1 (IR tampering) |
| `cap.subject_id == action.actor_id` | `I2 (IdentityBinding)` | AT-2.1, AT-5.2 |
| `cap.resource_hash == action.resource_hash` | `I5 (ResourceBinding)` | AT-6.1, AT-2.2 |
| `cap.expiry >= now` | `I3 (ExpiryGate)` | AT-3.6 |
| `cap.epoch >= action.min_epoch` | `I4 (EpochSafety)` — leaf | AT-3.2 |
| `validate_chain(cap, ...)` | `I6 (Attenuation)`, `I7 (ChainEpoch)` | AT-2.3–2.7, AT-3.1, AT-5.1 |
| `(cap.rights & required) == required` | rights sufficiency (implied by I2+I6) | AT-2.6 |
| revocation proof check | `I4 (RevocationSafety)` | AT-3.3, AT-3.4 |
| CallGate structural closure | — | AT-7.5 (shadow execution) |

## Identity model

`subject_id = SHA-256(issuer_pubkey)`

Every node in a delegation chain must satisfy this binding (AT-5.1). It is enforced in `dag::validate_chain` by computing `SHA-256(current.issuer_pubkey)` and comparing it to `parent.subject_id`.

## Decision layers

```
engine::verify()
  [L1] action.verify_binding()           ← AT-1: any IR tamper caught here
  [L2] for each cap where subject == actor:
       resource_hash match?              ← AT-6.1
       expiry >= now?                   ← AT-3.6
       epoch >= min_epoch?              ← AT-3.2
       validate_chain(cap, bundle):
           depth ≤ 16                   ← AT-2.7
           each node epoch >= min_epoch ← AT-3.1
           ed25519 signature valid      ← AT-2.3, AT-2.4
           parent found in bundle       ← AT-2.5
           SHA-256(pubkey) == subject   ← AT-5.1
           rights ⊆ parent.rights       ← AT-2.6 (attenuation)
       rights sufficiency               ← rights gap
  [L3] revocation proofs (root-signed only) ← AT-3.3, AT-3.4
```

## Test suite

`tests.rs` contains 56 tests organized by category:

- **happy_***: valid inputs that should Permit
- **deny_***: one mutation that triggers exactly one deny path
- **edge_***: boundary values (expiry == now, epoch == min_epoch, etc.)
- **chain_***: delegation chain scenarios (depth limit, missing parent)
- **compose_***: SequenceContext composition tests
- **AT-N.M_***: named test for a specific attack tree node

`call_gate.rs` adds 22 tests that verify the same logic through the public API, plus a consistency test confirming gate output matches `engine::verify` directly.

## Hard rules (never break these)

- No `unsafe` anywhere in this module (`#![forbid(unsafe_code)]` in every file)
- No IO, no network, no global state, no panics
- `engine::verify` stays `pub(crate)` — never `pub`
- Total TCB LOC ≤ 600 (enforced by `TCB_CONSTRAINTS.md`)
