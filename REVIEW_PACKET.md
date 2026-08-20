# REVIEW_PACKET — AuthGate / decision-os-min / FDK

**Audience:** external reviewers (formal methods, capability security, AuthZEN).  
**Date:** 2026-08-20  
**Honesty rule:** cite `ASSUMPTIONS.md`; do not upgrade axioms to proofs in replies.

---

## 0. Read first (30 minutes)

| # | Doc | Why |
|---|---|---|
| 1 | `ASSUMPTIONS.md` | What is proved vs axiomatized |
| 2 | `contracts-spec/conformance/PROFILE.md` + `CLAIM.md` | The measurable claim |
| 3 | `FREEDOM_THEORY_POSITION.md` | Normative layer demoted |
| 4 | `MCP_STANDARDIZATION.md` | Why MCP, not a new RFC |
| 5 | `REVIEW_REQUEST_2026-08-10.md` (workspace root) | What was falsified and kept |

## 1. What to attack

Please try to break these claims specifically:

1. **Non-amplification under composition.** Can an untrusted evaluator cause an
   unauthorized effect (grant, tool rewrite, payload authorship, mint-before-veto)?
2. **AE-4 / AE-5.** Can a macaroon-lite delegation amplify tools or outlive its parent?
3. **AE-10.** Can a composed DENY be logged without the vetoing reason / tool?
4. **Ed25519 axiom fidelity.** Does the axiom statement match what the runtime
   actually calls? (Chlipala)
5. **Generality.** Is the result only true inside our own scenarios? (Heljanko)
6. **TCB boundary.** Does `INCOMPLETENESS.md` understate what callers will assume? (Jung)

Runnable suites:

```text
cd decision-os-min && python -m pytest -q
cd contracts-spec && python -m conformance.suite
```

## 2. Current measured status (2026-08-20)

- `decision-os-min`: **172 tests** green (incl. red-team regressions).
- Conformance profile: **10 PASS / 0 FAIL / 0 N/A** on the reference driver.
- Open deliberate gaps: evaluator timeout, BaseException handling, sequential
  pipeline vs composer divergence (`test_break7a/7c/8/8b`).
- Ed25519: **unverified runtime** — axiom in ASSUMPTIONS.md.
- TLC for `AuthGateV3`: see `formal/tlc_run.log` / `formal/COVERAGE.md`.

## 3. Architecture in one diagram

```text
Action
  → co-equal evaluators (authority ∧ legitimacy ∧ …)   lattice meet, DENY absorbs
  → signed decision + one-time action-bound token       only if composed PERMIT
  → PEP (signature + binding + spend) + audit record
  → tool / MCP
```

Delegation (optional path): root `grant()` → macaroon-lite `delegate()` with
tool and time caveats that only narrow.

## 4. Prior art we are *not* reinventing

Cedar, OPA/Rego, Zanzibar/OpenFGA/SpiceDB, Macaroons/Biscuit, MCP OAuth, Miller
*Robust Composition* (2006), Anderson reference monitor, seL4 separation kernel line.

## 5. Asks by reviewer type

| Reviewer | Ask |
|---|---|
| Formal methods | ASSUMPTIONS table; Kani=bounded vs Verus; Squirrel/Tamarin path |
| Capability / CHERI / seL4 | Is the wedge real once Macaroons+MCP are granted? |
| AuthZEN / OIDF | Fit of AE profile as agent-tool annex; no new RFC yet |
| Programming-language security | Iris/RefinedRust readiness; TCB story |

## 6. Contact / repos

- Engineering contact: Ali Pourrahim
- Kernel: `freedom-kernel-work` / `authgate-kernel` (GitHub: Aliipou/authgate-kernel)
- Reference PEP: `decision-os-min`
- Profile: `contracts-spec/conformance`

---

*Negative results welcome. “Archive the claim” is a valid review outcome.*
