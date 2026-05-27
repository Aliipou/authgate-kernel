# TCB Code Mapping — Attack → Implementation

Branch: `adversarial-lab` | Companion to: `ATTACK_MATRIX.md`

This document maps each attack class to the **specific function and logical
check** in the Rust TCB that closes it. Use this when auditing the kernel or
verifying that a code change preserves coverage.

---

## Anatomy of a verify() call

```
engine::verify(action, root_key, now)
  │
  ├─ [L1] action.verify_binding()                    ← closes AT-1 (all sub-attacks)
  │          SHA-256 over all fields, constant-time compare
  │
  ├─ [L2] for each cap in action.capability_proofs:
  │   │
  │   ├─ cap.subject_id == action.actor_id?          ← closes AT-2.1, AT-5.2
  │   ├─ cap.resource_hash == action.resource_hash?  ← closes AT-6.1, AT-2.2
  │   ├─ cap.expiry >= now?                          ← closes AT-3.6
  │   ├─ cap.epoch >= action.min_epoch?              ← closes AT-3.2 (leaf)
  │   ├─ required_rights ⊆ cap.rights?              ← closes AT-2.6 (leaf check)
  │   └─ validate_chain(cap, proofs, root_key, min_epoch)
  │           │
  │           ├─ depth ≤ MAX_CHAIN_DEPTH             ← closes AT-2.7
  │           ├─ current.epoch >= min_epoch          ← closes AT-3.1 (chain nodes)
  │           ├─ current.sig_valid                   ← closes AT-2.3, AT-2.4
  │           ├─ HasParent(current, bundle)          ← closes AT-2.5
  │           ├─ SHA-256(current.issuer_pubkey)      ← closes AT-5.1
  │           │    == parent.subject_id
  │           └─ current.rights ⊆ parent.rights     ← closes AT-2.6 (chain)
  │
  ├─ [L3] revocation check                          ← closes AT-3.3, AT-3.4
  │         cap.proof_hash in revoked_set?
  │         revocation.sig valid against root_key?
  │
  └─ Decision::Permit | Decision::Deny(reason)
```

---

## Mapping Table

| Attack | Check | File | Function | Error message |
|---|---|---|---|---|
| AT-1.* | binding_hash mismatch | types.rs | `verify_binding()` | "binding hash mismatch" |
| AT-2.1 | subject_id ≠ actor_id | engine.rs | `check_cap()` | "cap subject does not match actor" |
| AT-2.2 | resource_hash mismatch | engine.rs | `check_cap()` | "cap resource does not match action resource" |
| AT-2.3 | root sig invalid | dag.rs | `validate_chain()` | "root signature invalid" |
| AT-2.4 | intermediate sig invalid | dag.rs | `validate_chain()` | "intermediate signature invalid" |
| AT-2.5 | parent not in bundle | dag.rs | `validate_chain()` | "parent proof not found in bundle" |
| AT-2.6 | rights escalation | dag.rs | `validate_chain()` | "capability rights exceed parent" |
| AT-2.7 | depth limit | dag.rs | `validate_chain()` | "delegation chain exceeds maximum depth" |
| AT-2.8 | empty bundle | engine.rs | `verify()` | "no capability proofs provided" |
| AT-3.1 | intermediate epoch stale | dag.rs | `validate_chain()` | "delegation chain node epoch predates minimum required epoch" |
| AT-3.2 | leaf epoch stale | engine.rs | `check_cap()` | "capability epoch below minimum" |
| AT-3.3 | revocation hit | engine.rs | `check_revocation()` | "capability has been revoked" |
| AT-3.4 | revocation forgery | engine.rs | `check_revocation()` | "revocation proof signature invalid" |
| AT-3.6 | cap expired | engine.rs | `check_cap()` | "capability has expired" |
| AT-4.1 | rights accumulation | sequence.rs | `accumulate()` | (no error — monotone union) |
| AT-5.1 | issuer binding mismatch | dag.rs | `validate_chain()` | "issuer pubkey does not correspond to parent subject identity" |
| AT-5.2 | zero actor_id | engine.rs | `verify()` | "actor identity is zero" |
| AT-6.1 | cross-resource reuse | engine.rs | `check_cap()` | "cap resource does not match action resource" |
| AT-7.1–7.2 | post-seal tamper | types.rs | `verify_binding()` | "binding hash mismatch" |
| AT-7.5 | shadow execution | **NOT IMPLEMENTED** | CallGate (pending) | n/a |

---

## File-Level Responsibility

### `types.rs` — Canonical Action IR

Closes: AT-1 (all sub-attacks)

Key function: `CanonicalAction::verify_binding()`
- Serializes all fields deterministically
- Computes SHA-256
- Compares with `binding_hash` using `subtle::ConstantTimeEq`
- Returns `Err("binding hash mismatch")` if tampered

LOC budget: ≤ 220

### `engine.rs` — Verify Entry Point

Closes: AT-2.1, AT-2.8, AT-3.2, AT-3.3, AT-3.4, AT-3.6, AT-5.2, AT-6.1

Key function: `verify(action, root_key, now) -> Decision`
- Layer 1: `verify_binding()` — binding gate
- Layer 2: loop over `capability_proofs`
  - `check_cap(cap, action)` — per-cap structural checks
  - `validate_chain(cap, proofs, root_key, action.min_epoch)` — chain walk
  - revocation check
- Returns `Decision::Permit` only if all checks pass

LOC budget: ≤ 120

### `dag.rs` — Delegation Chain Validator

Closes: AT-2.3, AT-2.4, AT-2.5, AT-2.6, AT-2.7, AT-3.1, AT-5.1

Key function: `validate_chain(cap, bundle, root_key, min_epoch) -> Result<(), &str>`
- BFS / iterative walk from leaf to root
- Checks at every node:
  1. `current.epoch >= min_epoch` (I7 — AT-3.1)
  2. `SHA-256(current.issuer_pubkey) == parent.subject_id` (I2 — AT-5.1)
  3. `current.rights ⊆ parent.rights` (I3 — AT-2.6)
  4. `ed25519::verify(signing_message, sig, issuer_pubkey)` (AT-2.3/AT-2.4)
  5. `HasParent(current, bundle)` (AT-2.5)
  6. depth counter vs MAX_CHAIN_DEPTH (AT-2.7)

LOC budget: ≤ 120

### `sequence.rs` — Composition Tracker

Closes: AT-4.1, AT-4.3 (partial — monotonicity only)

Key type: `SequenceContext`
- `accumulated_rights: Rights` — union of all granted rights in session
- `accumulate(new_rights)` — union update, never decreases (I5)
- Session limit enforcement is a caller responsibility (policy layer)

LOC budget: ≤ 120

---

## Pending: `call_gate.rs` — Adapter Boundary (v3)

Target: close AT-7.5

Design:
```rust
pub struct CallGate {
    root_key: VerifyingKey,   // private — not accessible to adapter
}

impl CallGate {
    pub fn execute(&self, action: CanonicalAction, now: u64) -> Decision {
        verify(action, &self.root_key, now)   // only path to verify()
    }
}

// verify() is NOT pub — only CallGate::execute() is exported
fn verify(...) -> Decision { ... }
```

This makes AT-7.5 **structurally impossible**: the adapter receives a `CallGate`
handle and cannot call `verify()` directly, cannot skip the call, and cannot
call it with different arguments than what `execute()` passes.

Status: design complete, implementation pending (v3 release gate).

---

## How to Use This Document

**When adding a new security check to the TCB:**
1. Identify which attack sub-class it closes
2. Add a row to the mapping table
3. Add a simulation scenario to `ATTACK_MATRIX.md`
4. Add a TLA+ invariant to `authgate_v3.tla` if the class has no formal coverage
5. Update `COVERAGE.md` with the new invariant's status

**When auditing an existing check:**
1. Find the attack class in `ATTACK_MATRIX.md`
2. Locate the code row in the mapping table
3. Verify the error message matches what tests assert
4. Verify the TLA+ invariant covers the attack in the MC model
