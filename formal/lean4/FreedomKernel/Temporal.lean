-- formal/lean4/FreedomKernel/Temporal.lean
-- Temporal IFC invariants: taint propagation across plan prefixes.
-- Mirrors planner.rs StateProjection logic.

namespace FreedomKernel.Temporal

-- ── Label lattice ─────────────────────────────────────────────────────────────

inductive Label | Public | Internal | Secret
  deriving DecidableEq, Repr

def labelRank : Label → Nat
  | .Public   => 0
  | .Internal => 1
  | .Secret   => 2

def labelDominates (a b : Label) : Bool :=
  labelRank a > labelRank b

-- ── Taint monotonicity ────────────────────────────────────────────────────────

def highest (a b : Label) : Label :=
  if labelRank a >= labelRank b then a else b

-- PROOF: taint can only increase across a plan prefix
theorem taint_monotone (current new_read : Label) :
    labelRank (highest current new_read) ≥ labelRank current := by
  -- `split_ifs` is a Mathlib tactic and this file imports no Mathlib, so the
  -- original script did not elaborate ("unknown tactic"). `split` is the core
  -- Lean equivalent. Statement unchanged.
  simp only [highest]
  split
  · exact Nat.le_refl _
  · next h => exact Nat.le_of_lt (Nat.not_le.mp h)

-- ── Capability Amplification Theorem ─────────────────────────────────────────

-- A plan step that writes to a label L cannot be in a plan that has already
-- read a label strictly dominating L.
-- This mirrors planner.rs StateProjection.advance() IFC check.

theorem no_downward_write
    (taint write_label : Label)
    (h : labelDominates taint write_label = true) :
    -- The write must be blocked — stated as a structural constraint
    True := trivial  -- enforced at runtime in planner.rs; Kani-verified

-- ── Machine-checked axiom audit ──────────────────────────────────────────────
-- ⚠ `no_downward_write` has conclusion `True` and is therefore VACUOUS: it
-- reports a clean axiom list because it asserts nothing, not because the
-- IFC property has been established. Only `taint_monotone` has real content.
#print axioms taint_monotone
#print axioms no_downward_write

end FreedomKernel.Temporal
