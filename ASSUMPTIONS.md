# ASSUMPTIONS — what is proved, what is axiomatized, what is open

**Discipline (Chlipala):** for every security-relevant claim, state exactly one of
*proved* / *explicit assumption* / *no formal counterpart*. Partial coverage is
stated as partial. This file is the single honesty table for AuthGate / FDK /
decision-os-min outreach.

**Updated:** 2026-08-20

---

## 1. Cryptographic boundary

| Claim | Status | Where |
|---|---|---|
| Ed25519 EUF-CMA (signature unforgeability) | **AXIOM** | Lean: `formal/lean4/Proofs.lean` `sig_euf_cma`; runtime uses `cryptography` Ed25519, **not** HACL*/Fiat-verified code |
| Forged revocation evidence is harmless under the axiom | **AXIOM** (reduces to EUF-CMA) | `forged_revocation_harmless` |
| Hash-chain audit tamper detection (SHA-256 collision resistance) | **ASSUMED** (standard hash assumption; not proved here) | `decision_os_min/audit.py`, Rust audit export |
| HMAC-SHA256 integrity of macaroon caveat chains | **ASSUMED** (HMAC unforgeability) | `decision_os_min/attenuation.py` |

### Ed25519 axiom (explicit, per Adam Chlipala feedback)

> **Axiom `sig_euf_cma`.** The signature oracle used by the kernel (`IsValidSig` /
> `cryptography.hazmat…Ed25519`) is treated as EUF-CMA-secure. No theorem in this
> repository discharges that claim. Until a verified implementation from the
> HACL* / Fiat-Crypto family replaces the runtime signer **and** the Lean oracle
> is linked to it, every theorem that mentions signatures is **conditional on this
> axiom**.

Status-table row (do not upgrade without evidence):

| Component | Implementation | Verified? | Role in claims |
|---|---|---|---|
| Decision signing (`decision-os-min`, `decision-kernel-core`) | `cryptography` Ed25519 | **No** | AXIOM |
| AuthGate Rust TCB signatures | project crypto provider | **No** (Kani/Lean treat sig as oracle) | AXIOM |
| Target replacement | HACL* / Fiat Ed25519 | planned | removes axiom |

---

## 2. Authority / composition (decision-os-min + conformance profile)

| Claim | Status | Evidence |
|---|---|---|
| AE-1 Default deny | **TESTED** (conformance PASS) | `contracts-spec/conformance` |
| AE-2 No amplification (constraint inputs) | **TESTED** | same |
| AE-3 Constraint inputs veto-only | **TESTED** + red-team regressions | `test_redteam_composition.py`, round 2 |
| AE-4 Attenuation on delegation | **TESTED** (macaroon-lite) | `attenuation.py`, AE-4 PASS |
| AE-5 Temporal attenuation | **TESTED** | AE-5 PASS |
| AE-6–AE-10 | **TESTED** | 10/10 PASS on one implementation |
| Lattice meet commutative/associative | **TESTED** (Hypothesis) | `test_compose_properties.py` |
| Canonical interned verdicts defeat lying `str` subclasses | **TESTED** | `test_redteam_round2.py` |
| Evaluator timeout / BaseException→DENY | **OPEN** (deliberate `test_break*`) | documented gaps |
| Profile is a multi-party standard | **NOT CLAIMED** | one implementation measured |

---

## 3. Formal specs (authgate-kernel)

| Artifact | Status |
|---|---|
| TLA+ `AuthGateV3` invariants (I1–I8, BigSafety, PermitSoundness) | **TLC VERIFIED** 2026-08-20 on `MC_AuthGateV3` with `Len(audit_log)≤1`, safety-only (no WF); 4227 distinct states, no error — see `formal/tlc_run.log`. Larger bound (`≤3`) is overnight budget. |
| Lean 4 attenuation / scope theorems | Partial: some proved, some `sorry` (see `formal/COVERAGE.md`) |
| Kani harnesses on Rust TCB | Bounded model checking — **not** unbounded proof (Parno distinction) |
| Verus unbounded proofs | **NOT STARTED** |
| Squirrel / Tamarin symbolic proofs of key-reuse in delegation+audit | **NOT STARTED** (Blanchet path: symbolic first) |
| Iris / RefinedRust | **NOT STARTED** (Krebbers estimate: 1–1.5y) |

---

## 4. Normative / theory layer

| Claim | Status |
|---|---|
| A1–A7 are the *correct* liberty axioms | **OUT OF SCOPE** of verification (`INCOMPLETENESS.md`) |
| Ownership/consent ontology discriminates vs Cedar/OPA/purpose baselines | **FALSIFIED** as a unique contribution (see `REVIEW_REQUEST_2026-08-10.md` §4) |
| Theory of Freedom as upstream normative layer vs independent security-capability thesis | **DECIDED** — see `FREEDOM_THEORY_POSITION.md` |

---

## 5. How to cite this table

In any review packet, email, or AuthZEN post: quote the row, not a paraphrase.
"Formally verified" without pointing at this table is a violation of the project’s
own honesty rule.
