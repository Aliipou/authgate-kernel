# Decisions

Architectural decision records. See CLAUDE.md §7 for the format.

## 2026-06-18 — FDK↔AuthGate boundary: a JSON contract, not shared code

**Context:** FDK (Freedom Decision Kernel) and AuthGate both touch
ownership/consent concepts and risked overlapping. We needed the two to compose
into one product — `Request → Planner → FDK → AuthGate → TCB → Execution` —
without coupling them or duplicating responsibility.

**Decision:** Split responsibility cleanly and connect them through a single
serialisable contract:
- **FDK** answers *"is this action legitimate?"* and emits a `PolicyDecision`
  (`spec/policy_decision.schema.json`): `verdict` ∈ {ALLOW, DENY, DEFER},
  `action_id`, `reasons`, `axiom_trace`, `fail_closed`.
- **AuthGate** answers *"can this actor execute it?"* (capability + scope +
  signature + TCB) and consumes the contract via `authgate.integrations.fdk`.
- The seam (`enforce_legitimacy`) runs the `CallGate` **only** on an explicit
  ALLOW bound to the same `action_id`; everything else (DENY, DEFER,
  `fail_closed`, malformed payload, id mismatch) is fail-closed → no execution.
- `authgate.integrations.fdk` imports **no FDK code.** The contract is the only
  coupling.

**Reason:** A shared schema (not shared code) keeps each side independently
deployable, testable, and replaceable, and removes the production-ambiguity of
two systems both claiming ownership logic. AuthGate stays the single source of
truth for authority; FDK only *interprets* legitimacy. Ambiguity is the enemy in
production — this draws the line where it belongs.

**Trade-offs accepted:** The two repos must keep the `PolicyDecision` schema in
sync by hand (no generated stubs). We deliberately omit a `confidence` field:
FDK is a deterministic, categorical gate, so a probability would re-introduce the
ambiguity we are removing — `DEFER` already means "unsure, ask a human."

**Revisit when:** a second upstream decider needs the seam (generalise
`integrations/`), or the contract needs a breaking change (bump
`policy_decision.schema.json` + both sides).
