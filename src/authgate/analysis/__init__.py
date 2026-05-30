"""
authgate.analysis — observation layer, NOT enforcement.

⚠ ARCHITECTURAL NOTICE ⚠

These modules contain HEURISTIC ANALYSIS:
  - constitutional_economy   — oligarchy/sovereignty metrics (heuristic)
  - sovereignty_metrics      — HHI dependency, reversibility (heuristic)
  - recursive_governance     — anti-feudal checks (heuristic)
  - persuasion               — persuasion boundary detection (heuristic)
  - anti_capture             — scope drift, owner mismatch (heuristic)
  - coercion                 — dependency monopoly (heuristic)
  - exit_guarantees          — exit reachability (heuristic)
  - sovereign_identity       — commitment-based identity (research-grade)
  - multi_agent_coordinator  — coalition checker (heuristic)
  - override_detector        — owner lockout (heuristic)

They are NOT in the TCB. The CI guard `TCB v2 purity` forbids any of these
concepts from appearing in `src/tcb/`. The gate
(`authgate.kernel.verifier.FreedomVerifier.verify()`) does not call them.

Per TCB_DISCIPLINE.md Rule 2: no semantic concept enters the TCB.

These modules are kept under `authgate.analysis` for backward compatibility,
but conceptually belong in a separate `freedom-theory` package. The long-term
plan is to extract them into a sibling repository so the authgate identity
stays focused on "capability enforcement, nothing else".

If you are evaluating authgate for deployment: ignore this module. The
authorization decision uses only `authgate.kernel` and `freedom-kernel/src/tcb/`.
"""
