# Revocation Correctness Proofs

**Phase:** 5 (6–12 months)
**Status:** Proof targets defined — not yet proved.

---

## Definitions

Let `R` be the registry and `R'` be the registry after `revoke_cascading(a)`.

**Revocation completeness:** For all claims `c` in `R'`, `c.holder ≠ a` and
`delegated_by(c)` does not transitively include `a`.

**Revocation soundness:** No claim is removed from `R'` that was not transitively
delegated by `a`.

---

## Proof Targets

**T1 (Completeness):** After `revoke_cascading(a)`, no agent reachable from `a`
in the delegation graph holds any valid claim.

*Current status:* Enforced by BFS in `registry.py` with `delegated_by` tracking.
Proof requires showing BFS visits all reachable nodes (follows from BFS correctness).

**T2 (Soundness):** `revoke_cascading(a)` does not remove claims held by agents
NOT in the transitive closure of `a`'s delegation subtree.

*Current status:* Enforced by BFS termination condition. Proof is straightforward.

**T3 (Monotonicity):** A claim revoked at time T is not present at any T' > T.

*Current status:* True by construction (claims are removed from the list). Not formally proved.

---

## Gap

The current implementation tracks `delegated_by` as a direct parent reference.
A complete cascading revocation requires computing the full transitive closure of
the delegation DAG, not just direct children. This needs to be verified against the
BFS implementation in `registry.py`.

---

## Next Steps

1. Write a property test (hypothesis) that checks T1 for random delegation graphs
2. Formalize T1 in Lean 4 using the BFS correctness theorem
3. Verify BFS covers all reachable nodes (not just direct children)
