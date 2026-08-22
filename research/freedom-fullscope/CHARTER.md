# research/freedom-fullscope — experiment charter

**Branch:** `research/freedom-fullscope`  
**Rule:** Does not merge into `main` / TCB without an explicit product decision.  
**Goal:** Encode Freedom Formal skill A1–A5 as **enforceable solutions** (no GAP),
red-team them, and measure when they catch cases AuthGate authority alone misses.

## Solutions (computable reductions)

| Skill axiom | Machine solution |
|---|---|
| A1 توحید | Deny UltAuth proxies: dominion, human-ownership, sovereignty escalate, ownerless machine |
| A2 معاد | Require `audit_bound`; deny trail wipe; deny `known_audit_deadline` (anti End Game) |
| A3 نبوت | Seal `constitution_digest`; deny rival formal systems; deny compulsory guide |
| A4 عدل | `Resp(actor)` — deny liability shift + loss socialization |
| A5 امامت | Deny exit / return-to-freedom lock; require guide channel when Is/Ought gap (opt-in) |

## Code

- `src/authgate/research/freedom_formal/` — evaluator, pipeline, scenario catalog  
- `tests/research/` — unit + red-team  

## Report

See [DIFFERENCE_REPORT.md](DIFFERENCE_REPORT.md).

## Composition (locked 2026-08-21)

- **Not** merged into AuthGate TCB.
- Seam: `authgate.integrations.legitimacy` (FDK name = compat shim).
- Decision-os lattice meet: legitimacy DENY-only → then CallGate.
- Branches: `main` without legitimacy required; `with-legitimacy` wires the meet;
  this research branch develops the Freedom Formal engine.
