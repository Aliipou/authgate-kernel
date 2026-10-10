# Feature Freeze — 2026

> "I would add almost no new features starting today. The biggest risk is no longer
> a lack of capability. The biggest risk is the project drifting from solving one
> specific problem to trying to solve every problem in the world."
> — Architect review, 2026-05-30

This is a binding policy, not a suggestion. From 2026-05-30 forward, the project
is in feature freeze through end of 2026.

---

## What FEATURE FREEZE means

Three categories of change exist:

### ✅ ALLOWED (always)

- **Bug fixes** in any existing code path
- **Security patches** for any reported vulnerability
- **External review responses** — closing findings from D8 reviews
- **Documentation improvements** (clarity, examples, typos)
- **Test additions** for already-existing functionality (no new functionality)
- **CI / tooling improvements** (faster builds, better gates)
- **Performance optimization** within existing API surface
- **Removal** of unused code (Rule 1 of TCB_DISCIPLINE.md)

### ⚠ ALLOWED (with explicit justification + maintainer sign-off)

- **Adapter updates** to track upstream framework changes (LangChain, MCP, etc.)
- **Refactoring** that reduces TCB LOC or complexity
- **Test infrastructure** (fuzzer improvements, new harness types)
- **API stability fixes** — only if breaking external usage

### ❌ FORBIDDEN

- **New right kinds** in the capability bitmask
- **New attack classes** — until existing AT-* are externally reviewed
- **New AuthoritySource implementations** (MarketOracle, Reputation, etc.)
- **Distributed / federated features** — Phase 4 territory, premature
- **ML / heuristic features** anywhere in the codebase
- **New trust roots / multi-issuer support**
- **Workflow engines, planners, orchestrators**
- **New formal proof targets** — unless they verify existing invariants
- **"Just one more layer" / "small addition"** — these compound

A PR proposing anything in the FORBIDDEN list is closed without review,
referencing this document.

---

## Why the freeze

Before the freeze:
- 1155 tests
- 6 git branches
- 38/53 deployment readiness (DEPLOYMENT_READINESS.md)
- **Zero external production users (F1 = 0/5)**
- **Zero external security reviews (D8 = NO)**

Adding more features does not move F1 or D8. Only humans do — by adopting and reviewing.
Every hour spent on a new feature is an hour not spent finding the first adopter.

The project has graduated from "is the concept sound?" to "does anyone use this?"
The bottleneck has shifted. The work must shift with it.

---

## What gets worked on during the freeze

The 2026 work is **outside the codebase**:

| Quarter | Goal |
|---------|------|
| Q3 2026 | External adversarial review request (D8) sent to ≥3 security engineers |
| Q4 2026 | First external review completed; findings triaged and closed |
| Q4 2026 | First adopter conversation started (F1) — even internal use at one company |
| Q1 2027 | First deployment in shadow mode |
| Q2 2027 | First deployment promoted to primary gate |

Code work that supports the above (closing review findings, writing
deployment recipes) is the ONLY in-scope code work during the freeze.

---

## Freeze reactivation conditions

The feature freeze ends when ALL three are true:

1. ✅ One external adversarial review completed with findings closed
2. ✅ One real deployment in production (even internal) for ≥30 days
3. ✅ At least one postmortem from real operational experience

Until all three: no new features. Period.

When the freeze ends, the next features are chosen by what the adopter needed
that didn't exist — not by what the team imagined would be useful.

---

## How to enforce the freeze

The freeze is enforced by three mechanisms:

1. **This document** — referenced in every PR template
2. **CI guards** — `.github/workflows/ci.yml` blocks TCB growth above ceiling
3. **PR template** — every PR must answer: "Does this add a feature? If yes, cite the freeze exception."

Adding a checkbox to `.github/PULL_REQUEST_TEMPLATE.md` (if it exists) is the
operational hook. The freeze is not voluntary — it is structural.

---

## The cultural cost of NOT freezing

The list of security projects killed by feature creep is long:

- Crypto libraries that started minimal and bloated into "platforms"
- Authorization frameworks that absorbed every adjacent concern
- Sandbox systems that grew interpreters, then interpreters of interpreters
- "AI safety" projects that became philosophy departments

The pattern is identical. Survivors said NO to interesting ideas.

> "When in doubt, delete the code. If the project survives the deletion,
> the code didn't belong." — TCB_DISCIPLINE.md

---

## Acknowledgment

This freeze is hard because the project has momentum. Each task in the
backlog feels reasonable. Each refactor looks small. Each adapter feels useful.

The discipline is not "this idea is bad." The discipline is **"this idea is
not relevant to the current bottleneck."** The bottleneck is adoption and
external validation, not engineering.

Engineering is the easy part. Saying no is the hard part.

---

*Reviewed: 2026-05-30. Next review: 2027-01-01.*
*Maintainer sign-off required to modify this file.*
