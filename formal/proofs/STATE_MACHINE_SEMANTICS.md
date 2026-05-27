# State-Machine Semantics for Capability Lifecycle

**Phase:** 5 (6–12 months)
**Status:** Design stub — formal model not yet written.

---

## Goal

Model the full lifecycle of a capability claim as a state machine with
formally specified transitions and invariants.

---

## States

```
PENDING → ACTIVE → EXPIRED
               ↓
           REVOKED
               ↓
          CASCADED_REVOKED
```

| State | Description |
|---|---|
| PENDING | Claim created but not yet `is_valid()` (confidence=0 or pre-activation) |
| ACTIVE | Claim is valid: confidence > 0, not expired, not revoked |
| EXPIRED | Claim has passed `expires_at` timestamp |
| REVOKED | Claim explicitly revoked by `revoke_all()` or `revoke_on_resource()` |
| CASCADED_REVOKED | Claim revoked by `revoke_cascading()` due to delegator revocation |

---

## Transition Invariants

1. ACTIVE → EXPIRED is monotonic (time only moves forward)
2. ACTIVE → REVOKED requires `registry.revoke_*()` call by a privileged actor
3. REVOKED → ACTIVE is forbidden (no resurrection)
4. CASCADED_REVOKED inherits all properties of REVOKED
5. Delegation can only occur from ACTIVE → ACTIVE (delegator must be ACTIVE)

---

## Formal Model Target

Express these states and transitions in TLA+ or Lean 4.
Key property to prove: **no REVOKED or EXPIRED claim can produce a PERMITTED result**.

This closes the gap between `expire_stale()` correctness (currently tested, not proved)
and the formal semantics.

---

## Next Steps

1. Write TLA+ state machine for RightsClaim lifecycle
2. Add `REVOKED` state explicitly to the data model (currently implicit via list removal)
3. Prove REVOKED → never ACTIVE
