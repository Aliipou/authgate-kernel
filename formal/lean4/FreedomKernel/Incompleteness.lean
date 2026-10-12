-- formal/lean4/FreedomKernel/Incompleteness.lean
-- Formal statement of what Freedom Kernel cannot prove.
-- This is a strength, not a weakness. seL4 documents the same gap.

namespace FreedomKernel.Incompleteness

-- ── Rice's Theorem (informal) ─────────────────────────────────────────────────

-- By Rice's theorem, no algorithm can decide whether an arbitrary
-- infinite sequence of PERMITTED actions reaches an unsafe state.

-- RESPONSE: verify_plan() operates on a bounded plan prefix of depth n.
-- GUARANTEE: no prefix of length ≤ n violates temporal invariants.
-- GAP: the range (n, ∞) is not covered.

-- REMOVED 2026-10-12: `infinite_horizon_undecidable` was inconsistent.
--
-- It was stated as:
--   not (exists decide : List Unit -> Bool, forall plan, decide plan = true <-> True)
--
-- That is refutable: `fun _ => true` witnesses the existential, so the axiom
-- yields `False` and any module importing it could prove anything.
--
-- The intended content is a Rice-style meta-theoretic result: no total
-- decision procedure settles an arbitrary semantic property of plans over an
-- unbounded horizon. `List Unit -> Bool` cannot model that (the domain carries
-- no information about the plan). Formalising it needs a real model of plans
-- and of the property decided, and is not attempted here.
--
-- This is NOT an assumption the development rests on and must not appear in
-- the preprint's list of unproved assumptions.

-- ── Semantic Intent ───────────────────────────────────────────────────────────

-- The kernel verifies typed predicates, not intent.
-- Action("read-research", bot, resources_read=[paper]) is PERMITTED
-- if bot has delegation — even if "research" is a pretext.
-- The kernel cannot distinguish genuine intent from pretext.

-- Stated as a non-theorem:
-- There is no formal proof that permitted actions are "genuinely safe"
-- in the semantic sense. Safety requires the ownership graph to accurately
-- reflect the human owner's actual intent.

-- ── Axiom Soundness ───────────────────────────────────────────────────────────

-- The kernel enforces A1–A7. Whether A1–A7 are the correct axioms is
-- a philosophical question outside the scope of formal verification.
-- The kernel is sound relative to A1–A7; it cannot verify A1–A7 themselves.

-- ── What IS formally proved ───────────────────────────────────────────────────

-- See TCB.lean for proved theorems:
-- P1: forbidden_flags_always_block   (unconditional, proved by simp)
-- P5: verify_deterministic           (proved by rfl)
-- P2: permitted_implies_no_forbidden_flag
-- Individual flag corollaries (sovereignty, coercion, deception)
-- Temporal taint monotonicity (Temporal.lean)
-- Attenuation cannot escalate (MultiAgent.lean)

end FreedomKernel.Incompleteness
