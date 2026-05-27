# Delegation Chain Transitivity Proofs

**Phase:** 5 (6–12 months)
**Status:** Proof targets defined — partially derivable from existing Lean 4 proofs.

---

## Goal

Prove that authority can only flow downward (toward narrower capability sets) through
delegation chains, and that no chain can produce a claim wider than the root grant.

---

## Existing Proofs (from Lean 4)

`attenuation_cannot_escalate` (proved, no sorry):
> Delegated confidence ≤ delegator confidence.

This covers confidence. We need analogous proofs for capability kinds.

---

## Additional Claims to Prove

**C1 (Capability attenuation):** For any chain `(a₀ → a₁ → ... → aₙ)`, the
capability set of `aₙ` is a subset of the capability set of `a₀`.

*Proof approach:* By induction on chain length. Base case: n=1 (direct delegation),
enforced by `delegate()` attenuation check. Inductive step: if `cap(aₙ) ⊆ cap(a₀)`,
then any extension `aₙ → aₙ₊₁` satisfies `cap(aₙ₊₁) ⊆ cap(aₙ) ⊆ cap(a₀)`.

**C2 (Root-bounded authority):** The capability set of any agent in the system is
bounded above by the capability set of its root human principal.

*Proof approach:* Follows from C1 plus the fact that human principals' capabilities
are bounded at registry construction time.

**C3 (DAG property):** Delegation chains are acyclic.

*Proof approach:* Enforced by topological sort in `authority_graph.rs`. Needs to be
formalized — currently tested, not proved.

---

## Next Steps

1. Formalize C1 in Lean 4 (extends existing `attenuation_cannot_escalate`)
2. Use hypothesis (property testing) to detect counterexamples before proving C3
3. Extract DAG invariant from authority_graph.rs for formal treatment
