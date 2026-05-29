# TCB Constraints — authgate-kernel tcb-core branch

These constraints are CI-enforced hard gates. A PR to `main` from `tcb-core`
must pass all of them. Failing any constraint = block.

## C1: TCB LOC limit

```
freedom-kernel/src/tcb/engine.rs  ≤ 120 LOC
freedom-kernel/src/tcb/dag.rs     ≤ 120 LOC
freedom-kernel/src/tcb/types.rs   ≤ 220 LOC
freedom-kernel/src/tcb/sequence.rs ≤ 120 LOC
TOTAL TCB (4 files)               ≤ 600 LOC
```

Rationale: small TCB is auditable TCB. Every LOC added must be justified
against a specific invariant in `spec-core/formal/authgate_v3.tla`.

Current LOC (2026-05-28):

```
engine.rs:  ~115 LOC
dag.rs:     ~100 LOC
types.rs:   ~200 LOC
sequence.rs: ~83 LOC
TOTAL:      ~498 LOC  (within budget)
```

## C2: No IO, no network, no panics in TCB

The four TCB files must contain:
- No `std::io`, `std::net`, `std::fs` imports
- No `unwrap()`, `expect()`, `panic!()` calls (use `?` or explicit `Err`)
- No `unsafe` (enforced by `#![forbid(unsafe_code)]`)

## C3: Invariant alignment

Every security check in `engine.rs` and `dag.rs` must correspond to a stated
invariant in `spec-core/formal/authgate_v3.tla`. Mapping:

| Code check | TLA+ invariant |
|---|---|
| `action.verify_binding()` | binding_valid (canonical gate) |
| `cap.epoch < action.min_epoch` | I1 EpochSafety (leaf) |
| `current.epoch < min_epoch` in dag | I7 ChainEpoch |
| `SHA-256(issuer_pubkey) == parent.subject_id` | I2 IdentityBinding |
| `(child.rights & !parent.rights) != 0` | I3 Attenuation |
| `cap.proof_hash == rev.target_proof_hash` | I4 RevocationSafety |
| `cap.resource_hash != action.resource_hash` | I6 ResourceBinding |

## C4: CI must pass

- `cargo test --lib tcb` — all Rust TCB tests
- `cargo test --lib` — full Rust test suite
- Python: `attack_tree_coverage.py` — zero FAIL lines

## C5: AT-7.5 call gate (pending)

Before `tcb-core` can ship a v3 release, the adapter boundary must enforce
that no code path executes agent actions without calling `verify()`.

Design: add a `CallGate` wrapper type that is the only public entry point.
Adapters receive a `CallGate` handle; raw `verify()` is not exported.

Status: design pending, not yet implemented.
