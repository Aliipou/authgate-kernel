# Axiomatic Foundation — The Project's Actual Win

> "The win of this project is not the tests, the LOC count, the branches, or the
> framework adapters. The win is a consistent axiomatic formal system."
> — Project review, 2026-05-30

This is the canonical statement of every axiom the project rests on, every place
the axiom is enforced in code, every mechanical proof that demonstrates
consistency, and the explicit boundary of what is **not** axiomatic.

If any of the axioms below are false, the entire enforcement story collapses.
If the implementation diverges from any axiom, the proofs are decorative.
This document is what makes the consistency claim auditable.

---

## What "axiomatic formal system" means here

Three things must hold simultaneously:

1. **A small set of axioms is stated explicitly.** Not implicit. Not "the code is the spec." Stated, numbered, with motivation.
2. **The implementation provably enforces each axiom within a stated scope.** Mechanical proof (Kani / Lean) for the kernel; tests for the Python reference layer; explicit gap for what is unproven.
3. **The boundary of the axiomatic claim is enumerated.** What is NOT covered is documented as carefully as what IS covered. (See `formal/INCOMPLETENESS.md`.)

A system with (1) but not (2) is philosophy.
A system with (2) but not (1) is a code dump that compiled.
A system with (1) and (2) but not (3) is a marketing pitch.
A system with all three is **axiomatic infrastructure**. That's the goal.

---

## The Seven Kernel Axioms (A1 – A7)

These are the ONLY axioms the kernel enforces. Any other concept (manipulation,
sovereignty score, coercion, ethics, alignment) is **explicitly outside** this list
and must live in `extensions/` or `analysis/`.

### A1 — Action Integrity (Canonical Binding)

> Every action submitted to the kernel is sealed by a binding hash that covers
> every field of the action. Any post-seal mutation to any field is detected
> before any other check runs.

**Enforces:** the wire format is tamper-evident across the adapter→kernel boundary.

| Aspect | Reference |
|--------|-----------|
| Code (Rust)   | `freedom-kernel/src/tcb/engine.rs:35` (Layer 1) |
| Code (Python) | `src/authgate/kernel/verifier.py:verify()` |
| Hash function | `freedom-kernel/src/tcb/types.rs:compute_hash` |
| Proof         | All AT-1.* attack scenarios in `attack_harness/simulation/engine.py` |
| Test count    | 40 mutation tests (one per binding-hash-covered field × variants) |
| Boundary      | Does NOT prevent mutation before sealing (caller's responsibility) |

### A2 — Sovereignty / Corrigibility Flags Are Unconditional Denials

> If an action carries any of the 10 hard sovereignty flags
> (`increases_machine_sovereignty`, `resists_human_correction`, `bypasses_verifier`,
> etc.), the action is denied. No claim, no proof, no context overrides this.

**Enforces:** corrigibility is structural, not negotiable.

| Aspect | Reference |
|--------|-----------|
| Code (Python) | `src/authgate/kernel/verifier.py:128-150` (1st check after binding) |
| Code (Rust)   | sovereignty flags are out-of-scope for Rust v2 TCB (Python only — see boundary) |
| Lean theorem  | `forbidden_flags_always_block` (proved by simp, no axioms) |
| Lean theorem  | `sovereignty_always_blocks` (proved by simp, no axioms) |
| Kani harnesses| 10 (one per flag): `prop_increases_machine_sovereignty` ... `prop_coalition_reduces_freedom` |
| Test count    | 113 in `test_army.py::TestSecurity05` + 25 in `test_adversarial_redteam.py` |
| Boundary      | Flag detection is structural (boolean field check), NOT semantic interpretation of the action |

### A3 — Cryptographic Identity Binding

> An actor's identity is `SHA-256(public_key)` (Rust TCB) or a registered
> identity token (Python layer). Two principals with the same display name
> but different keys/tokens are distinct identities and cannot impersonate
> each other.

**Enforces:** "knowing a name" is not the same as "being the principal."

| Aspect | Reference |
|--------|-----------|
| Code (Rust)   | `freedom-kernel/src/tcb/dag.rs:95` (`SHA-256(issuer_pubkey) == parent.subject_id`) |
| Code (Python) | `src/authgate/kernel/registry.py:_enroll_identity()` (identity_token tracking) |
| Closes attack | AT-5.1 (delegation impersonation), C-1 (Python name spoofing) |
| Test count    | 10 in `test_c1_identity_binding.py` + AT-5 scenarios in simulation |
| Boundary      | Python without `identity_token`: degenerates to name match (documented in `Entity` docstring) |

### A4 — No Ownerless Machine

> Every machine actor must have a registered human owner (or, in future,
> a registered constitutional trust root — `AuthoritySource`). A machine
> with no owner cannot perform any action.

**Enforces:** trust always traces to a root. No ambient machine authority.

| Aspect | Reference |
|--------|-----------|
| Code (Python) | `src/authgate/kernel/verifier.py:152-165` ("[A4] UNOWNED_MACHINE") |
| Code (Rust)   | implicit: a CapabilityProof with no chain to root_key fails `dag.rs` validation |
| Lean predicate| `permitted` in `formal/FreedomKernel.lean:132` — explicit A4 line |
| Kani harness  | `prop_ownerless_machine_blocked` (✓ proved) |
| Test count    | included in 25 red team + 113 army tests |
| Boundary      | This axiom changes when scenario 4 (no human root) materializes — see `DEATH_SCENARIOS.md` |

### A5 — Capability Proofs Are Cryptographically Signed and Time-Bounded

> A capability proof is valid only if (a) its signature verifies against the
> issuer's public key, (b) it has not expired, (c) its epoch is ≥ the action's
> required minimum epoch.

**Enforces:** authority has shape, lifetime, and provenance — never bare assertion.

| Aspect | Reference |
|--------|-----------|
| Code (Rust)   | `freedom-kernel/src/tcb/engine.rs:60-69` (expiry + epoch) + `dag.rs:62,72` (signatures) |
| Code (Python) | `src/authgate/kernel/registry.py:can_act()` (epoch gate) + `RightsClaim.is_expired()` |
| Lean axiom    | `sig_euf_cma` in `formal/lean4/Proofs.lean:66` (ed25519 EUF-CMA assumption — admitted, not proved) |
| Lean theorem  | `attenuation_transitive` (proves chain integrity given signature validity) |
| Lean theorem  | `stale_epoch_implies_deny` (proves epoch gate is unconditional) |
| Kani harness  | `prop_epoch_check` + `proof_forged_revocation_ignored` |
| Closes attacks| AT-2.5 (forged sig), AT-2.6 (expired cap), AT-3.* (epoch attacks) |
| Boundary      | Cryptographic strength assumed (`sig_euf_cma` is an admitted axiom from cryptographic literature, not proved here) |

### A6 — Attenuation: Child Rights ⊆ Parent Rights

> If actor B holds a capability delegated from actor A, B's rights are a
> bitwise subset of A's rights. No delegation can grant rights the delegator
> did not possess. AND: a machine cannot govern any human, in any chain.

**Enforces:** authority decreases as it travels; impossible to "grant up."
Plus the strict variant: machine→human dominion is structurally impossible.

| Aspect | Reference |
|--------|-----------|
| Code (Rust)   | `freedom-kernel/src/tcb/dag.rs:101` (`(rights & !parent.rights) != 0` → reject) |
| Code (Python) | `src/authgate/kernel/registry.py:_delegation_chain_valid()` + `verify()` machine-dominion check |
| Lean theorem  | `attenuation_cannot_escalate` in `MultiAgent.lean:38` (proved) |
| Lean theorem  | `rights_sufficiency_correct` (proved by simp) |
| Kani harness  | `prop_attenuation_two_node` (✓ proved) |
| Kani harness  | `prop_machine_governs_human_blocked` (✓ proved) |
| Closes attacks| AT-2.4 (child > parent), AT-5.* (impersonation) |
| Boundary      | Pairwise check; transitive consequence follows from `attenuation_transitive` |

### A7 — No Ambient Authority

> Access to a resource requires a registered, valid claim. Absence of an
> applicable rights claim = denial. Default-deny. Always.

**Enforces:** the system has no "open by default" mode. Permissions are explicit.

| Aspect | Reference |
|--------|-----------|
| Code (Python) | `src/authgate/kernel/verifier.py:184-217` (resource access loop) |
| Code (Rust)   | `freedom-kernel/src/tcb/engine.rs:51` (filter caps where `subject_id == actor`) → no match = `"capability not issued to this actor"` |
| Kani harness  | `prop_read_denied_without_claim` (✓ proved) |
| Kani harness  | `prop_write_denied_without_claim` (✓ proved) |
| Kani harness  | `prop_delegation_denied_without_delegate_claim` (✓ proved) |
| Closes attacks| AT-2.1 (empty caps), AT-2.2 (cross-actor), AT-2.8 (insufficient rights) |
| Boundary      | Public resources (`is_public=true`) are the one exception, explicit in `registry.can_act()` |

---

## Universal Properties (Cross-Axiom)

These are not axioms but properties that follow from the construction:

| Property | Statement | Proof |
|----------|-----------|-------|
| **Determinism** | Same inputs → same output | `verify_deterministic` (Lean, by rfl) for Rust TCB. Python: NOT pure (documented C-4 in `FINDINGS.md`). |
| **Permitted ⇒ no violations** | If `permitted=true` then `violations = ()` | `permitted_implies_no_forbidden_flag` (Lean) + `prop_permitted_implies_no_violations` (Kani) |
| **Denied ⇒ reason non-empty** | If `permitted=false` then `violations ≠ ()` | `prop_blocked_implies_violations_non_empty` (Kani) |
| **High-water mark** | `SequenceContext.accumulated_rights` is monotone | `prop_seq_accumulated_monotone` (Kani) |
| **Total epoch relation** | `cap.epoch < min_epoch` or `cap.epoch ≥ min_epoch` — no third case | `epoch_gate_total` (Lean) |

---

## What is NOT axiomatic (the explicit boundary)

Per `formal/INCOMPLETENESS.md`, the following are NOT covered by the axioms:

| NOT axiomatic | Why | Where the gap lives |
|--------------|-----|---------------------|
| Infinite-horizon plan safety | Rice's theorem — undecidable | `formal/INCOMPLETENESS.md §1` |
| Semantic intent verification | Kernel does not parse language | `formal/INCOMPLETENESS.md §2` |
| Whether A1–A7 are the **correct** axioms | Meta-question, philosophical | `formal/INCOMPLETENESS.md §3` |
| Goal-intent alignment | Depends on human's actual preferences | `formal/INCOMPLETENESS.md §4` |
| Python implementation | NOT formally checked; only the Rust TCB has Kani+Lean coverage | `formal/INCOMPLETENESS.md "Formal scope: Rust TCB only"` |
| Side-channels (timing, cache, power) | Out of scope by design | `NON_GOALS.md`, `THREAT_MODEL.md` |
| Compromised root key | "Malicious trust root" out of scope | `THREAT_MODEL.md`, `DEATH_SCENARIOS.md §4` |
| Manipulation / coercion / ethics | Heuristic, lives outside TCB | `extensions/`, `analysis/` |
| Distributed authority | Phase 4 work; not implemented | `DEATH_SCENARIOS.md`, layer discipline section |

---

## Admitted Axioms (cryptographic dependencies we do not prove)

The proofs depend on these admitted axioms. Their soundness is external.

| Admitted axiom | Source | Used to prove |
|---------------|--------|---------------|
| `sig_euf_cma` | ed25519 EUF-CMA security from cryptographic literature | A5 (cap signatures cannot be forged without private key) |
| `forged_revocation_harmless` | Code inspection (revocation with invalid sig is silently ignored) | DoS resistance against forged revocations |
| `infinite_horizon_undecidable` | Rice's theorem | Statement of incompleteness boundary |

Replacing these axioms with mechanical proofs would require either:
- A formal ed25519 verification (massive undertaking; out of scope)
- A complete proof of the Python/Rust runtime semantics

We accept these as borrowings from a wider mathematical context.

---

## Why this is the actual win

The project has 1155 tests. The project has 24 Kani harnesses and 16 Lean theorems.
The project has 8 framework adapters. The project has 6 git branches.

**None of those are the win.** Tests, harnesses, adapters, branches — every
serious project has some quantity of these. They are inputs, not outcomes.

The win is what those inputs assemble into:

> **A consistent axiomatic formal system. Seven explicit axioms. Mechanical
> proofs of consistency within a stated scope. Honest enumeration of what is
> NOT proved.**

This combination is rare. Most security projects have:
- many tests but no axioms → "we tested a lot of things"
- some axioms but no proofs → "we believe these things"
- proofs but no boundary → "we proved everything!" (always false)

The triple — axioms + proofs + boundary — is what infrastructure-grade
security systems look like (seL4, CompCert, CHERI). Joining that club is
a measurable, achievable goal. We are halfway there.

---

## Halfway there means

| Done | Not done |
|------|----------|
| Axioms stated and numbered (A1–A7) | External review of the axiom choice |
| Code enforcement traceable per axiom | Refinement proof Lean ↔ Rust ↔ Python |
| Mechanical proofs (Kani + Lean) for kernel scope | TLC model checker not yet run |
| INCOMPLETENESS.md enumerates the gaps | Workshop paper / arXiv preprint not written |
| Python reference layer mirrors Rust intent | Python NOT formally verified (acknowledged) |
| Cryptographic axioms cited (`sig_euf_cma`) | No external crypto audit |

The work to get from "halfway" to "fully" is mostly:
- External adversarial review (D8 in `DEPLOYMENT_READINESS.md`)
- A workshop paper formalizing the axiom set
- A first real deployment exercising the axioms under load (F1)

None of those are code. All of them are validation by people outside the project.

---

## How to use this document

| Reader | Use |
|--------|-----|
| External security reviewer | Read this first. Then `THREAT_DEFENSE_PAIRS.md`. Then `formal/INCOMPLETENESS.md`. |
| Contributor proposing a TCB change | Identify which axiom the change strengthens or weakens. If neither: it belongs outside the TCB. |
| Adopter evaluating for production | Map your deployment's needs to A1–A7. If you need something outside A1–A7, ask. |
| Academic reviewer | Cite A1–A7 as the project's claim; cite the proofs as the consistency evidence; cite INCOMPLETENESS.md as the honest boundary. |
| Future maintainer | If a proposed feature does not strengthen consistency with A1–A7, reject. |

---

## Maintenance

This document is **constitutional**. Changes require:

1. The proposed new/modified axiom in its final stated form
2. Identification of the enforcement site in code
3. The proof (existing or new) that demonstrates consistency
4. Updated boundary statement if the change shifts what is/isn't axiomatic
5. Update to `formal/INCOMPLETENESS.md` if the proof scope changes
6. Update to `THREAT_DEFENSE_PAIRS.md` if any AT-X.Y pairing changes
7. Sign-off from the TCB Guardian (E-01 per `TEAM.md`)

Casual edits are not allowed. This file's stability is a feature, not a bug.

---

*Updated: 2026-05-30. Next review: when an external party challenges any axiom.*
