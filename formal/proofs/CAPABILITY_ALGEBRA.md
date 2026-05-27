# Capability Algebra Proofs — Formal Methods Expansion

**Phase:** 5 (6–12 months)
**Status:** Proof stubs — not yet proved.

---

## Goal

Prove that the delegation relation over capability sets forms a bounded distributive lattice.

---

## Definitions

Let `C` be the set of all capability kinds (17 elements, closed enum).
Let `cap(a)` be the capability set held by agent `a`.

**Delegation partial order:** `a ≤ b` iff `cap(a) ⊆ cap(b)`.

---

## Claims to Prove

**Claim 1 (Transitivity):** If `a` delegates to `b` and `b` delegates to `c`,
then `cap(c) ⊆ cap(b) ⊆ cap(a)`.

*Proof sketch:* By attenuation (enforced at delegation time), each link satisfies
`cap(child) ⊆ cap(parent)`. Transitivity follows by subset composition.

**Claim 2 (Anti-monotonicity of confidence):** For any delegation chain
`(a → b → c)`, `conf(c) ≤ conf(b) ≤ conf(a)`.

*Proof sketch:* Confidence attenuation is enforced at `delegate()` time:
`claim.confidence ≤ best.confidence`. By induction on chain length.

**Claim 3 (No cycles):** The delegation graph is a DAG.

*Proof sketch:* `authority_graph.rs` runs topological sort before committing
any delegation edge. A cycle would be detected and rejected. This is enforced
by construction, not yet proved as a formal invariant.

**Claim 4 (Lattice structure):** The set of possible capability subsets under
delegation forms a bounded distributive lattice with meet = intersection,
join = union (within the delegator's cap set), bottom = ∅, top = root cap.

*Status:* Conjecture — not yet proved. Requires formalizing the attenuation
partial order in Lean 4.

---

## Next Steps

1. Formalize Claim 1 and 2 in Lean 4 (straightforward, follows from code invariants)
2. Prove Claim 3 requires extracting the graph invariant from authority_graph.rs
3. Claim 4 is the research contribution — novel proof target
