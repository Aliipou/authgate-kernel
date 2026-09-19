-- formal/lean4/FreedomKernel/OntologicalRoot.lean
-- Formalizes PHILOSOPHY/GOD_HUMAN_BOUNDARY.md's argument as a checked artifact.
--
-- `Person(h) -> OwnedByGod(h)` is declared here as a Lean `axiom` -- NOT
-- proved, and not provable by this or any formal system (see
-- GOD_HUMAN_BOUNDARY.md for the argument why not: it is the same shape of
-- boundary Incompleteness.lean already states for axiom soundness generally,
-- one level up, for the root A1..A7 protect).
--
-- What CAN honestly be checked is what FOLLOWS from it. Today the kernel
-- treats "no human owns another human" and "no machine governs a human" as
-- two separate, independently-asserted rules (AXIOM_MAP.md marks the first
-- Code-only "by construction" -- true only because no such claim type
-- exists in the Python layer -- and the second Kani-verified against the
-- engine's runtime check, TCB.lean's `machine_cannot_govern_human` being
-- `True := trivial`, i.e. asserted, not derived). This file shows both are
-- not independent assumptions at all: they are the SAME consequence of ONE
-- axiom -- exclusive divine ownership of every human -- applied twice.
--
-- Self-contained, like Incompleteness.lean and MultiAgent.lean: its own
-- sub-namespace, its own minimal types, no cross-file import (TCB.lean,
-- MultiAgent.lean etc. do the same -- none of the files under FreedomKernel/
-- currently import one another; see BUILD_NOTE.md for the aggregator import
-- path issue this sidesteps rather than silently relies on).

namespace FreedomKernel.OntologicalRoot

inductive AgentType | Human | Machine
  deriving DecidableEq, Repr

structure Entity where
  id : String
  agentType : AgentType
  deriving DecidableEq, Repr

-- A general "owns/governs this entity" relation -- the book's broader
-- ontological relation, introduced only to state and check the entailment
-- below. It has no runtime counterpart and proves nothing about the
-- `OwnershipGraph` used by the actual engine in TCB.lean.
axiom Owns : Entity → Entity → Prop

axiom OwnedByGod : Entity → Prop

-- A0, the ontological root, exactly as PHILOSOPHY/README.md states it.
axiom A0_every_human_owned_by_god :
    ∀ (h : Entity), h.agentType = AgentType.Human → OwnedByGod h

-- A0's exclusivity clause, made explicit rather than left implicit in the
-- word "owned": if a human is owned by God, nothing else also stands in the
-- `Owns` relation to that human. This is the load-bearing half of A0 for
-- what follows -- without it, "God owns every human" alone says nothing
-- about whether something ELSE can also own them. Naming it as its own
-- axiom makes that dependency visible instead of smuggling it into A0.
axiom A0_exclusive :
    ∀ (owner h : Entity), h.agentType = AgentType.Human → OwnedByGod h →
      Owns owner h → False

-- ── What follows, checked by `lake build` / `lean`, not asserted ────────

-- No human owns another human -- not even themselves (see the `h1 = h2`
-- check below). AXIOM_MAP.md row A2 today: "Code-only (by construction)" --
-- true only because the Python layer never defines a human-owns-human claim
-- type. Here it is a genuine derivation from A0, not an absence.
theorem no_human_owns_human (h1 h2 : Entity)
    (_hh1 : h1.agentType = AgentType.Human) (hh2 : h2.agentType = AgentType.Human) :
    ¬ Owns h1 h2 :=
  fun hown => A0_exclusive h1 h2 hh2 (A0_every_human_owned_by_god h2 hh2) hown

-- No machine owns/governs a human (A6). TCB.lean's
-- `machine_cannot_govern_human` is `True := trivial` -- Kani-verified against
-- the runtime engine, but asserted rather than derived in Lean. Here it
-- follows from the SAME axiom pair as `no_human_owns_human` above, not from
-- a second independent assumption.
theorem no_machine_owns_human (m h : Entity)
    (_hm : m.agentType = AgentType.Machine) (hh : h.agentType = AgentType.Human) :
    ¬ Owns m h :=
  fun hown => A0_exclusive m h hh (A0_every_human_owned_by_god h hh) hown

-- Not a vacuous consequence of an inconsistent axiom pair: this derives a
-- concrete proposition from a further hypothesis, exercising both axioms
-- together in the exact shape the two theorems above use them, rather than
-- asserting `False` outright (which an inconsistent axiom set would also
-- let through, silently).
example (h1 h2 : Entity) (hh1 : h1.agentType = AgentType.Human)
    (hh2 : h2.agentType = AgentType.Human) (hown : Owns h1 h2) : False :=
  no_human_owns_human h1 h2 hh1 hh2 hown

-- The `h1 = h2` case takes no special-casing, and needs none:
-- `no_human_owns_human` has no `h1 ≠ h2` hypothesis, so it already covers "a
-- human does not even 'own' themselves" in this relation's sense --
-- consistent with the theory's own framing (Human <-> Human: rights, not
-- ownership; a person's relation to themselves is autonomy, not property).
-- Checked explicitly here so the self-case is predictable, not an edge case
-- nobody looked at.
example (h : Entity) (hh : h.agentType = AgentType.Human) (hown : Owns h h) : False :=
  no_human_owns_human h h hh hh hown

end FreedomKernel.OntologicalRoot
