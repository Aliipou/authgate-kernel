# TCB — Trusted Computing Base

Branch: `tcb-core` | Track: Execution Truth

## What Is Here

The authgate-kernel Trusted Computing Base: the minimal set of Rust code that
all security guarantees depend on. Every line here is part of the attack surface.
Less code = smaller attack surface = easier audit.

```
engine.rs    ≤ 120 LOC   verify() entry point, main decision loop
dag.rs       ≤ 120 LOC   validate_chain() — BFS proof-chain verification
types.rs     ≤ 220 LOC   CanonicalAction, CapabilityProof, Decision IR
sequence.rs  ≤ 120 LOC   SequenceContext — accumulated rights across a session
─────────────────────────
TOTAL        ≤ 600 LOC   hard CI gate
```

## Files

| File | Invariants enforced | Key functions |
|---|---|---|
| `engine.rs` | I1, I3, I4, I6 (leaf checks) | `verify()`, `check_cap()` |
| `dag.rs` | I2, I3, I7 (chain checks) | `validate_chain()` |
| `types.rs` | binding_valid (canonical gate) | `CanonicalAction::verify_binding()` |
| `sequence.rs` | I5 CompositionMono | `SequenceContext::accumulate()` |
| `tests.rs` | All (56 tests) | integration + unit coverage |

## Invariant Mapping

Every security check traces to a TLA+ invariant in `spec-core/formal/authgate_v3.tla`:

| Code check | TLA+ invariant | Attack class closed |
|---|---|---|
| `action.verify_binding()` | binding_valid | AT-7 post-seal tamper |
| `cap.epoch < action.min_epoch` | I1 EpochSafety | AT-3 leaf epoch |
| `current.epoch < min_epoch` in dag | I7 ChainEpoch | AT-3.1 intermediate epoch |
| `SHA-256(issuer_pubkey) == parent.subject_id` | I2 IdentityBinding | AT-5.1 delegation impersonation |
| `(child.rights & !parent.rights) != 0` | I3 Attenuation | AT-2 attenuation violation |
| `cap.proof_hash == rev.target_proof_hash` | I4 RevocationSafety | AT-3 revocation |
| `cap.resource_hash != action.resource_hash` | I6 ResourceBinding | AT-6 cross-resource |

## Rules (enforced by TCB_CONSTRAINTS.md)

- No `std::io`, `std::net`, `std::fs`
- No `unwrap()`, `expect()`, `panic!()` — use `?` or explicit `Err`
- No `unsafe` (`#![forbid(unsafe_code)]` in lib.rs)
- Every new check needs a corresponding TLA+ invariant in spec-core

## Running Tests

```bash
cd freedom-kernel
cargo test --lib tcb -- --nocapture   # TCB unit tests (56)
cargo test --lib                       # full suite
```

## Identity Model

`subject_id = SHA-256(pubkey)` — established in AT-5.1 fix (commit bf23248).

All delegation chain construction must use `subject_id_of(sk)` in tests:
```rust
fn subject_id_of(sk: &SigningKey) -> [u8; 32] {
    Sha256::digest(sk.verifying_key().to_bytes()).into()
}
```

## Open Gap: AT-7.5 Call Gate (v3 release gate)

The kernel cannot prevent adapters that bypass `verify()` entirely.

Design: a `CallGate` wrapper will be the only exported entry point.
Raw `verify()` will be private. Adapters receive a `CallGate` handle.

Status: design pending. This is a hard gate before v3 ships to production.
