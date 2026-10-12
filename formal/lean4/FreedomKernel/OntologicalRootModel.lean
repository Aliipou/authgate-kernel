-- formal/lean4/FreedomKernel/OntologicalRootModel.lean
-- Relative consistency of the A0 axioms in OntologicalRoot.lean, by an explicit
-- model. Written deliberately, after `infinite_horizon_undecidable` turned out
-- to be inconsistent and was found only by accident.
--
-- Self-contained like the rest of this package: the types are restated here,
-- identically, rather than imported.
--
-- The four axioms of OntologicalRoot.lean are the fields of `A0Axioms`. The
-- `trivialModel` instantiates them with a concrete interpretation in plain
-- Lean (no axioms of its own), so the set is consistent relative to Lean.
--
-- HONEST SCOPE: the model is trivial -- nobody owns anything, and "owned by
-- God" is true of everyone. That proves the axioms are not contradictory. It
-- also shows how little they constrain: `no_human_owns_human` and
-- `no_machine_owns_human` hold in a model where *no* ownership relation exists,
-- so they are not evidence about any real ownership graph.

namespace FreedomKernel.OntologicalRootModel

inductive AgentType | Human | Machine
  deriving DecidableEq, Repr

structure Entity where
  id : String
  agentType : AgentType
  deriving DecidableEq, Repr

/-- The content of OntologicalRoot.lean's four axioms, as a structure. -/
structure A0Axioms where
  Owns : Entity → Entity → Prop
  OwnedByGod : Entity → Prop
  A0_every_human_owned_by_god :
    ∀ (h : Entity), h.agentType = AgentType.Human → OwnedByGod h
  A0_exclusive :
    ∀ (owner h : Entity), h.agentType = AgentType.Human → OwnedByGod h →
      Owns owner h → False

/-- A concrete model: nothing owns anything; every entity is "owned by God". -/
def trivialModel : A0Axioms where
  Owns := fun _ _ => False
  OwnedByGod := fun _ => True
  A0_every_human_owned_by_god := fun _ _ => trivial
  A0_exclusive := fun _ _ _ _ hown => hown

/-- Consequence the axioms are used for, derived inside the model. -/
theorem model_no_human_owns_human (M : A0Axioms) (h1 h2 : Entity)
    (hh2 : h2.agentType = AgentType.Human) : ¬ M.Owns h1 h2 :=
  fun hown => M.A0_exclusive h1 h2 hh2 (M.A0_every_human_owned_by_god h2 hh2) hown

/-- Consistency witness: the axiom structure is inhabited. -/
theorem a0_consistent : Nonempty A0Axioms := ⟨trivialModel⟩

end FreedomKernel.OntologicalRootModel
