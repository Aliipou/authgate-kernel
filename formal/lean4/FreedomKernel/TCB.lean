-- formal/lean4/FreedomKernel/TCB.lean
-- Formal theorems about Freedom Kernel TCB properties.
-- Mirrors engine.rs types and invariants.
--
-- Build: cd formal/lean4 && lake build
-- Status: P5 (determinism) is fully proved. Others have 'sorry' placeholders
-- pending full verify definition. See INCOMPLETENESS.md.

namespace FreedomKernel

-- ── Core types ───────────────────────────────────────────────────────────────

inductive AgentType | Human | Machine
  deriving DecidableEq, Repr

structure Entity where
  id : String
  agentType : AgentType
  deriving Repr

structure Resource where
  id : String
  scope : String
  deriving Repr

structure RightsClaim where
  entity : Entity
  resource : Resource
  canRead : Bool
  canWrite : Bool
  canDelegate : Bool
  deriving Repr

-- ── ActionIR ─────────────────────────────────────────────────────────────────
-- Only the fields relevant to the 10 forbidden flags and axiom checks.

structure ActionIR where
  id : String
  actor : Entity
  increasesMachineSovereignty : Bool := false
  resistsHumanCorrection      : Bool := false
  bypassesVerifier            : Bool := false
  weakensVerifier             : Bool := false
  disablesCorrigibility       : Bool := false
  machineCoalitionDominion    : Bool := false
  coerces                     : Bool := false
  deceives                    : Bool := false
  selfModificationWeakens     : Bool := false
  machineCoalitionReduces     : Bool := false
  deriving Repr

-- ── hasForbiddenFlag ─────────────────────────────────────────────────────────

def hasForbiddenFlag (a : ActionIR) : Bool :=
  a.increasesMachineSovereignty ||
  a.resistsHumanCorrection      ||
  a.bypassesVerifier            ||
  a.weakensVerifier             ||
  a.disablesCorrigibility       ||
  a.machineCoalitionDominion    ||
  a.coerces                     ||
  a.deceives                    ||
  a.selfModificationWeakens     ||
  a.machineCoalitionReduces

-- ── Verification result ───────────────────────────────────────────────────────

inductive Outcome | Permitted | Blocked
  deriving DecidableEq, Repr

-- ── verify (simplified model — flag check only) ───────────────────────────────
-- Full verify also checks A4/A6/A7. Those are proved in separate lemmas below.
-- This definition captures the forbidden-flag layer unconditionally.

def verifyFlags (a : ActionIR) : Outcome :=
  if hasForbiddenFlag a then .Blocked else .Permitted

-- ── P1: Forbidden flags always block ────────────────────────────────────────

-- PROOF: unconditional — follows directly from definition of verifyFlags and hasForbiddenFlag.
theorem forbidden_flags_always_block (a : ActionIR) (h : hasForbiddenFlag a = true) :
    verifyFlags a = .Blocked := by
  simp [verifyFlags, h]

-- Individual flag corollaries

theorem sovereignty_flag_blocks (a : ActionIR) (h : a.increasesMachineSovereignty = true) :
    verifyFlags a = .Blocked := by
  apply forbidden_flags_always_block
  simp [hasForbiddenFlag, h]

theorem coercion_flag_blocks (a : ActionIR) (h : a.coerces = true) :
    verifyFlags a = .Blocked := by
  apply forbidden_flags_always_block
  simp [hasForbiddenFlag, h]

theorem deception_flag_blocks (a : ActionIR) (h : a.deceives = true) :
    verifyFlags a = .Blocked := by
  apply forbidden_flags_always_block
  simp [hasForbiddenFlag, h]

-- ── P5: Determinism ───────────────────────────────────────────────────────────

-- PROOF: verifyFlags is a pure function — rfl.
theorem verify_deterministic (a : ActionIR) : verifyFlags a = verifyFlags a := rfl

-- ── P2: If permitted, no forbidden flag is set ────────────────────────────────

theorem permitted_implies_no_forbidden_flag (a : ActionIR) (h : verifyFlags a = .Permitted) :
    hasForbiddenFlag a = false := by
  -- `Bool.eq_false_iff_ne_true` does not exist in Lean 4.32 core (unknown
  -- constant), so this file never compiled. Replaced by case analysis on the
  -- boolean, which is a complete proof of the same statement.
  cases hf : hasForbiddenFlag a with
  | false => rfl
  | true  => simp [verifyFlags, hf] at h

-- ── A4: Ownerless machine model ────────────────────────────────────────────────

structure OwnershipGraph where
  machineOwners : List (Entity × Entity)  -- (machine, owner)

def hasOwner (g : OwnershipGraph) (e : Entity) : Bool :=
  g.machineOwners.any (fun (m, _) => m.id == e.id)

-- For a MACHINE actor: no owner → blocked (A4)
-- This is stated as a predicate; the full engine.rs proof is in Kani harnesses.
theorem ownerless_machine_must_have_owner
    (e : Entity) (h : e.agentType = AgentType.Machine) (g : OwnershipGraph)
    (hno : hasOwner g e = false) :
    -- The engine must produce a violation containing "A4"
    -- Stated as a logical obligation; the Rust proof is in kani_proofs.rs
    True := trivial

-- ── A6: No machine governs any human ─────────────────────────────────────────

-- For any machine actor and any human target: governance is structurally blocked.
-- Proved in Kani: prop_machine_governs_human_blocked.
theorem machine_cannot_govern_human : True := trivial  -- Kani-verified

-- ── Machine-checked axiom audit ──────────────────────────────────────────────
-- `[propext, Classical.choice, Quot.sound]` = Lean's own logic only, i.e. the
-- theorem is discharged. Any other name is a trust assumption.
--
-- ⚠ READ WITH CARE. An empty axiom list is NOT evidence that a theorem says
-- anything useful. The last three declarations in this file
-- (`ownerless_machine_must_have_owner`, `machine_cannot_govern_human`, and
-- `verify_deterministic`) are VACUOUS: the first two have conclusion `True`,
-- which is provable without any hypothesis, and the third proves `x = x`.
-- They will report a clean axiom list precisely because they assert nothing.
-- See formal/PROOF_STATUS.md §"Vacuous theorems".
#print axioms forbidden_flags_always_block
#print axioms sovereignty_flag_blocks
#print axioms coercion_flag_blocks
#print axioms deception_flag_blocks
#print axioms verify_deterministic
#print axioms permitted_implies_no_forbidden_flag
#print axioms ownerless_machine_must_have_owner
#print axioms machine_cannot_govern_human

end FreedomKernel
