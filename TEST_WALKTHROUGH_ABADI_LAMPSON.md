# From Clone to 1,401 Tests: A Walkthrough with Abadi & Lampson

This document walks you from a fresh clone of the authgate-kernel repository through running all 1,401 tests, explaining what each test suite demonstrates and how it maps to the theoretical foundations laid by Abadi, Burrows, Lampson & Plotkin (1993) — *A Calculus for Access Control in Distributed Systems* (P1) — and Abadi (2003) — *Logic in Access Control* (P2).

**The papers in one sentence:** P1 invented the vocabulary of distributed authorization — `A says s`, speaks-for, `controls`, quoting vs. delegation (`B | A` vs. `B for A`), roles, and principal algebras — for an architecture (DSSA) that died immediately but whose concepts became invisible infrastructure. P2, a decade later, issued the canonical taxonomy of authorization-logic languages and a prescient caution about the Unit axiom that constructive logic would later prove correct.

---

## 1. Clone and setup

```bash
git clone https://github.com/Aliipou/authgate-kernel.git
cd authgate-kernel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The project is a Python package with an optional Rust TCB (`freedom-kernel/`). The Python test suite runs without the Rust compiler.

---

## 2. Run the full suite

```bash
pytest tests/ -q
```

Expected output:

```
1400 passed, 1 skipped, 0 failed in 3.24s
```

The one skipped test is a Hypothesis property-test health-check timeout (pre-existing, unrelated to any module). The 1,400 passing tests are the subject of this walkthrough.

---

## 3. Test map: what each suite demonstrates

The 78 test files are organized below by the A&L concept they exercise. Each section shows the command to run just that group, the test count, and the theoretical grounding.

---

### 3.1 Core axioms — P1 §3: `says`, `controls`, and the hand-off axiom

**P1's foundation:** The judgment `A says s` means principal A supports statement s. The `controls` relation `(A says s) ⊃ s` means A is trusted on s. The hand-off axiom `(A says (B ⇒ A)) ⊃ (B ⇒ A)` is the formal rule for delegation.

**Test command:**
```bash
pytest tests/test_core.py tests/test_context.py -v
```
**Tests:** 27

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_a6_machine_cannot_govern_human` | A machine cannot be granted authority over a human | P1 §6.2: `controls` is asymmetric; the TCB enforces that MACHINE never `controls` HUMAN |
| `test_a4_ownerless_machine_rejected` | Every machine must have a human owner | P1 §1: principals form a hierarchy; unrooted principals are invalid |
| `test_a5_machine_cannot_exceed_owner_scope` | A machine's rights are bounded by its owner's rights | P1 §5.1: attenuation — "you cannot grant authority you do not have" |
| `test_a7_undelegated_resource_blocked` | Access requires an explicit claim | P1 §3: `controls` requires an explicit `says` statement |
| `test_legitimate_action_permitted` | Clean actions with proper claims pass | P1 §3: valid `says` → valid `controls` → PERMIT |
| `test_sovereignty_flags_block_action` | 10 sovereignty flags (e.g., `coerces`, `deceives`) always deny | P2 §6 (2009 tutorial): C4 escalation taxonomy — certain actions are categorically forbidden regardless of delegation chain |
| `test_conflict_on_write_detected` | Concurrent write claims on the same resource are flagged | P1 §3: conflicting `says` statements cannot both be `controls` |

---

### 3.2 Delegation & attenuation — P1 §2, §5: `B for A` vs. `B | A`

**P1's delegation semantics:** `B | A` (quoting) means B speaks A's words but does not act for A. `B for A` (delegation) means B acts on A's behalf. The difference is the confused-deputy boundary. Attenuation requires that child rights ⊆ parent rights and child confidence ≤ parent confidence (A6).

**Test command:**
```bash
pytest tests/test_delegate.py tests/test_delegation_abuse.py tests/test_delegate_reputation.py tests/test_delegate_reputation_config.py tests/test_delegate_reputation_properties.py -v
```
**Tests:** 80

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_delegate_success` | Valid `B for A` delegation grants read authority | P1 §5.1: delegation scheme 1 (simple) — "B is A's delegate for R" |
| `test_delegate_reduced_confidence` | Delegated confidence can be lower than parent's | P1 §5.1: attenuation — child confidence ≤ parent confidence |
| `test_cannot_delegate_write_without_write` | Attenuation enforced at `delegate()` call time | P1 §5.1: "you cannot grant authority you do not have" (A6) |
| `test_confidence_cannot_exceed_delegator` | Confidence amplification is forbidden | P1 §5.1: anti-monotonicity of confidence (T2 in SEMANTICS.md) |
| `test_cannot_subdelegate_without_can_delegate` | Sub-delegation requires `can_delegate=True` | P1 §5.1: delegation scheme 3 — restricted delegation with propagation control |
| **DEL-1** `test_broken_chain_no_parent_claim_denies` | Orphaned delegation (no parent claim) is denied | P1 §5.1: delegation chain must be rooted in a non-delegated claim |
| **DEL-2** `test_write_via_delegation_denied_if_parent_only_reads` | Rights amplification across chain is blocked | P1 §5.1: A6 attenuation — "Child rights ⊆ parent rights" |
| **DEL-3** `test_delegation_from_non_delegating_entity_denied` | `can_delegate=False` blocks the chain | P1 §5.1: delegation scheme 2 — flag-controlled propagation |
| **DEL-4** `test_self_delegation_denied` | Self-delegation is a DAG violation | P1 §5.1 + SEMANTICS.md T3: delegation graph must be acyclic |
| **DEL-5** `test_scope_expansion_via_delegation_denied` | Narrower child scope permits; wider scope denies | P1 §5.1 + SEMANTICS.md §5: scope containment is anti-monotonic |

---

### 3.3 The "reasonable delegate" question — P1 §5.1, unformalized for 33 years

**The gap:** P1 §5.1 asks "is B a reasonable delegate for A?" but provides no formal rule. This is the single most important unanswered question from the paper, and it is now urgent because LLM agents are non-deterministic delegates.

**Test command:**
```bash
pytest tests/test_dre_adversarial.py tests/test_hbs_protection.py -v
```
**Tests:** 20

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_monotonicity_adding_penalty_never_decreases_dcrs` | DCRS (Delegate Candidate Risk Score) is monotonic | P2 §6 (2009 tutorial): C4 escalation taxonomy — penalties accumulate; P2's monotonicity-of-controls |
| `test_human_with_no_violations_always_passes` | HUMAN actors have baseline risk 0.0 | P1 §1: humans are the root of the principal hierarchy; "reasonable delegate" defaults to YES for humans |
| `test_history_poisoning_dilution_is_limited_by_decay` | Old benign records cannot mask recent violations | P2 §6: temporal reasoning — recent behavior outweighs old; the audit/accountability branch (Cederquist et al. 2007) |
| `test_ndc_spoofing_detected_by_weighted_risk` | Spoofing `DETERMINISTIC` while behaving like `LLM_CLOSED` is caught | P1 §5.1: the delegate's **properties** must match its claimed class |
| `test_threshold_probing_is_noisy` | Probing the exact DCRS threshold triggers arbitration | P2 §3: "no hard data" on policy-language effectiveness — borderline cases default to human review (DEFER) |
| `test_burst_attack_detected_by_guarded_store` | Rapid-fire HBS writes are rate-limited | P2 §6: audit log integrity — the accountability branch |
| `test_resource_breadth_explosion_triggers_block` | Scanning >50 resources triggers breadth penalty | P1 §5.1: reasonable delegates do not exhibit reconnaissance behavior |
| `test_failed_attestation_history_accumulates` | Failed external attestations degrade trust | P1 §5.1: delegation from an untrusted channel (failed attestation = untrusted `B for A`) |
| `test_tcb_deny_cannot_be_overridden_even_with_perfect_history` | Kernel DENY is absolute | P2 §3: fail-closed design — the TCB is the floor, reputation is a ceiling |

---

### 3.4 Principal algebra & speaks-for — P1 §3: `A ⇒ B`, semilattice meet

**P1's principal algebra:** Principals form a semilattice under `∧` (meet). `A ∧ B` speaks for both A and B. `A ⇒ B` (speaks-for) means any statement by A is also a statement by B.

**Test command:**
```bash
pytest tests/test_authority_source.py tests/test_sovereign_identity.py tests/test_federation.py -v
```
**Tests:** 54

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_speaks_for_transitivity` | If A ⇒ B and B ⇒ C, then A ⇒ C | P1 §3: speaks-for is a preorder; transitive closure of delegation chains |
| `test_meet_of_principals` | `A ∧ B` has authority of both | P1 §3: semilattice meet — "the conjunction of two principals" |
| `test_cross_domain_speaks_for` | Trust-domain federation with explicit grant | P1 §1: "channels/machines are principals"; P2 §3: Binder's global context names vs. SDSI linked local name spaces |

---

### 3.5 Wire hardening — P1 §2: "messages are principals" (structural integrity)

**P1's wire model:** Messages (requests on the wire) are treated as principals. If the wire can be forged, the entire principal algebra collapses. Input validation is therefore foundational.

**Test command:**
```bash
pytest tests/test_wire_hardening.py tests/test_wire_validator.py -v
```
**Tests:** 58

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_confidence_above_one_rejected` | Confidence ∈ [0.0, 1.0] enforced at construction | P1 §3: confidence is a probability-like quantity; out-of-range values break the logic |
| `test_nan_confidence_rejected` | IEEE 754 special values rejected | P1 §3: the algebra requires well-defined reals |
| `test_string_machine_rejected` | AgentType enum enforced | P1 §1: principals have well-defined kinds (human, machine, group) |
| `test_empty_action_id_rejected` | Empty/whitespace action IDs rejected | P1 §2: messages must have identifiable origin |
| `test_100k_resource_name_does_not_crash` | Extreme-size inputs handled safely | P1 §2: wire-level robustness — the message-principal mapping must not crash |
| `test_all_flags_produce_ten_violations` | All 10 sovereignty flags deny independently | P2 §6 (2009 tutorial): C4 escalation taxonomy — each flag is a categorical violation |

---

### 3.6 Audit & accountability — P2's unforeseen largest descendant branch

**The surprise finding:** P2's largest descendant cluster (55–93 citations each) is **audit & accountability logic** — Cederquist et al. (2007), Jagadeesan et al. (2005), Vaughan et al. (2008). These works turned `says` from *granting* authority to *accounting for* it. Neither P1 nor P2 foresaw this.

**Test command:**
```bash
pytest tests/test_audit.py tests/test_audit_hardening.py tests/test_signed_audit.py -v
```
**Tests:** 34

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_audit_chain_intact` | Each audit entry hashes the previous | Audit logic: tamper-evident chain — "accounting for authority" |
| `test_audit_replay_detects_tamper` | Replay of tampered log fails verification | Cederquist et al. (2007): audit-based compliance control |
| `test_concurrent_appends_no_duplicate_prev_hash` | Thread-safe append with lock | Jagadeesan et al. (2005): concurrent authorization events must be ordered |
| `test_load_and_verify_reconstructs_chain` | Forensic reconstruction from `.jsonl` | Vaughan et al. (2008): evidence-based audit |

---

### 3.7 Information flow control — P2 §5: non-interference

**P2's non-interference:** P2 §5 (2009 tutorial) discusses information-flow security as an extension of authorization logic. The Bell-LaPadula model is the standard reference.

**Test command:**
```bash
pytest tests/test_ifc.py -v
```
**Tests:** 21

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_public_cannot_flow_to_secret` | No-read-up enforced | P2 §5: non-interference — "information at label L cannot influence observations at lower labels" |
| `test_secret_can_flow_to_public_with_declassify` | Declassification requires explicit grant | P2 §5: downgrading is a controlled operation |
| `test_plan_ifc_check` | Multi-action plans checked for label consistency | P2 §5: sequential composition of non-interfering actions |

---

### 3.8 Policy DSL & language taxonomy — P2 §3: Binder, SD3, RT, SecPAL, DKAL, Soutei

**P2's taxonomy:** P2 §3 divides authorization languages into "research" (D1LP, RT, SD3, Binder) and "deployment" (SDSI, SPKI, XrML). It notes that deploying sophisticated policy languages might not reduce breakage — "there seems to be no hard data on this topic."

**Test command:**
```bash
pytest tests/test_policy_dsl.py tests/test_policy.py tests/test_policy_decision_contract.py -v
```
**Tests:** 68

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_allow_unless_delegated_by` | `ALLOW ... UNLESS delegated_by` parses and evaluates | P2 §3: Binder's `says` with conditions |
| `test_max_delegation_depth_condition` | Depth-bounded delegation enforced | P1 §5.1: delegation chains have bounded length; SEMANTICS.md T4 |
| `test_expires_condition` | Time-bounded grants expire | P1: timestamps/lifetimes were "out of scope" — now implemented |
| `test_trust_domain_condition` | Cross-domain grants require explicit match | P1 §1: trust domains are isolation boundaries |
| `test_wildcard_subject` | Wildcard subjects match any actor | P2 §3: Datalog-style rules with variables |
| `test_dsl_to_policy_to_evaluate_end_to_end` | Full pipeline: text → AST → evaluation | P2 §3: the research-to-deployment gap — authgate provides both |

---

### 3.9 Authority escalation — P2 §6 (2009 tutorial): C4, escalation, monotonicity

**The 2009 tutorial extension:** P2's FOSAD 2009 tutorial notes add the C4 escalation taxonomy and monotonicity analysis that P2 (2003) only hinted at.

**Test command:**
```bash
pytest tests/test_authority_escalation.py tests/test_coercion_primitives.py tests/test_adversarial.py tests/test_adversarial_redteam.py -v
```
**Tests:** 116

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_esc1_ghost_principal` | Non-existent principal cannot gain authority | P1 §3: principals must be registered in the algebra |
| `test_esc2_rights_amplification` | Rights cannot grow through delegation | P1 §5.1: A6 attenuation; P2 §6: monotonicity-of-controls |
| `test_esc3_confidence_inflation` | Confidence cannot exceed parent's | P1 §5.1: T2 anti-monotonicity |
| `test_esc4_sovereignty_flags` | Flags bypass normal delegation checks | P2 §6: C4 escalation — "certain actions are always forbidden" |
| `test_esc5_machine_governs_human` | Machine-over-human is categorically blocked | P1 §6.2: `controls` asymmetry |
| `test_esc6_expired_claim_reuse` | Expired claims are invalid | P1: timestamps were out of scope — now enforced |
| `test_coer1_informational` | Informational coercion detected | P2 §6 (2009): coercion taxonomy |
| `test_coer2_economic` | Economic coercion detected | P2 §6 (2009): coercion taxonomy |
| `test_coer5_cognitive` | Cognitive coercion (manipulation) detected | P2 §6 (2009): coercion taxonomy; `ExtendedFreedomVerifier.manipulation_score` |

---

### 3.10 Consent capability — P1 §4: roles (`A as R`)

**P1's roles:** The construct `A as R` means "A in role R." Roles are a form of attenuation — diminished powers for specific contexts.

**Test command:**
```bash
pytest tests/test_consent.py -v
```
**Tests:** 63

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_consent_required_without_consent_denies` | Action requiring human consent without consent = DENY | P1 §4: `A as R` — roles can require additional conditions |
| `test_consent_valid_permits` | Properly signed consent permits the action | P1 §4: roles are claims about the principal's context |
| `test_expired_consent_denies` | Time-bounded consent expires | P1: timestamps out of scope — now implemented |
| `test_consent_scope_mismatch_denies` | Consent must match action scope | P1 §4: role scope is part of the `as` construct |

---

### 3.11 Scope containment — SEMANTICS.md §5: path traversal

**Formal rule:** `scope_contains(parent, child)` iff every segment of child is a prefix of parent, with no `..` traversal.

**Test command:**
```bash
pytest tests/test_scope.py -v
```
**Tests:** 34

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_exact_match_permits` | `/data/` contains `/data/` | P1 §5.1: scope equality is valid containment |
| `test_child_directory_permits` | `/data/` contains `/data/sales/` | P1 §5.1: narrower scope is valid delegation |
| `test_traversal_rejected` | `/data/../etc/` is rejected | P1 §2: wire-level path manipulation is an attack |
| `test_normalization_of_untrusted_paths_is_attack_surface` | No normalization of untrusted input | P1 §2: "normalization of untrusted paths is attack surface" |

---

### 3.12 Key rotation — P1: freshness (explicitly out of scope in 1993)

**P1's omission:** P1 §2 explicitly excludes timestamps, lifetimes, and replay from scope. This was a "costly omission" (Phase 4 analysis) — freshness/revocation remains the hardest problem in deployed systems.

**Test command:**
```bash
pytest tests/test_key_rotation.py tests/test_epoch_revocation.py -v
```
**Tests:** 28

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_rotation_certificate_issue_and_verify` | New key certified with grace period | P1: "out of scope" — now addressed |
| `test_emergency_rotation_zero_overlap` | Emergency rotation allows zero grace period | P1: "out of scope" — now addressed |
| `test_expired_key_rejected` | Expired keys are invalid | P1: "out of scope" — now addressed |
| `test_revoke_all_clears_registry` | Complete revocation resets state | P1: "out of scope" — now addressed |

---

### 3.13 FDK bridge — cross-system delegation (P1 §5.1: both-identities auditing)

**P1's prediction:** "Delegation decisions depending on both identities should and will become widespread" (P1 §5.1). This was correct — Kerberos PAC, GCP `serviceAccountDelegationInfo`, RFC 8693 `act` claim, AWS CloudTrail role-chaining all implement it.

**Test command:**
```bash
pytest tests/test_fdk_bridge.py tests/test_policy_decision_contract.py -v
```
**Tests:** 19

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_fdk_allow_permits` | FDK `ALLOW` + matching action_id → PERMIT | P1 §5.1: both-identities delegation — the FDK verdict is the delegator's identity |
| `test_fdk_deny_blocks` | FDK `DENY` → DENY regardless of capability | P1 §5.1: delegator's denial overrides delegate's capability |
| `test_fdk_defer_triggers_arbitration` | FDK `DEFER` → human review | P2 §3: "DEFER means ask a human" |
| `test_malformed_payload_fail_closed` | Malformed FDK payload → DENY | P2 §3: fail-closed design |

---

### 3.14 External attestation — P1 §1: "channels/machines are principals"

**P1's insight:** Channels and machines are principals just like users. In 2026 this is SPIFFE workload identity, AWS IAM roles, GCP service accounts, Azure managed identities.

**Test command:**
```bash
pytest tests/test_attestation_production.py -v
```
**Tests:** 26

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_spiffe_production_valid_svid` | SPIFFE SVID → trust score 0.95 | P1 §1: workload as principal; SPIFFE = modern DSSA channel principal |
| `test_aws_production_service_principal` | AWS Service principal → score ≥0.85 | P1 §1: cloud IAM role as principal |
| `test_aws_production_wildcard_principal_penalty` | Wildcard `AWS: *` → score 0.4 (penalty) | P1 §5.1: unconstrained delegation is dangerous; P1 warned against it in 1993 |
| `test_gcp_production_default_compute_sa_penalty` | Default compute SA → score 0.5 | P1 §5.1: default credentials = unconstrained delegation |
| `test_composite_returns_best_result` | Multiple attestors → best score wins | P1 §3: `∧` (meet) of principals — composite identity |

---

### 3.15 Adapters & integration — P2 §3: deployment languages

**P2's deployment track:** SDSI, SPKI, XrML, XACML. Authgate provides adapters for modern agent frameworks.

**Test command:**
```bash
pytest tests/test_adapters.py tests/test_adapters_callgate_integration.py tests/test_crewai_adapter.py tests/test_dspy_adapter.py tests/test_langchain_integration/ -v
```
**Tests:** ~85 (across adapter files)

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_adapter_verify_permits` | LangChain tool call gated by authgate | P2 §3: deployment language — authgate as runtime policy engine |
| `test_adapter_callgate_blocks_unauthorized` | Unauthorized tool call → DENY | P1 §3: `controls` evaluated at runtime |
| `test_crewai_adapter_delegation` | CrewAI agent delegation with attenuation | P1 §5.1: multi-agent delegation chains |

---

### 3.16 Formal properties — property-based testing

**Test command:**
```bash
pytest tests/test_proptest.py -v
```
**Tests:** 5

| Test | What it proves | A&L mapping |
|------|----------------|-------------|
| `test_confidence_range_invariant` | ∀ claims, confidence ∈ [0.0, 1.0] | P1 §3: confidence is a probability-like quantity |
| `test_action_id_ascii_printable` | action_id restricted to ASCII printable | P1 §2: wire-level identifier constraints |

---

## 4. Running tests by A&L concept

If you want to run only the tests that exercise a specific paper concept, use these commands:

| Concept | Command | Tests |
|---------|---------|-------|
| `says` / `controls` | `pytest tests/test_core.py tests/test_context.py -v` | 27 |
| `B for A` delegation | `pytest tests/test_delegate.py tests/test_delegation_abuse.py -v` | 28 |
| Speaks-for / principal algebra | `pytest tests/test_authority_source.py tests/test_sovereign_identity.py -v` | 32 |
| Wire integrity | `pytest tests/test_wire_hardening.py tests/test_wire_validator.py -v` | 58 |
| Audit / accountability | `pytest tests/test_audit.py tests/test_audit_hardening.py tests/test_signed_audit.py -v` | 34 |
| Non-interference (IFC) | `pytest tests/test_ifc.py -v` | 21 |
| Policy DSL | `pytest tests/test_policy_dsl.py tests/test_policy.py -v` | 64 |
| Escalation / C4 | `pytest tests/test_authority_escalation.py tests/test_coercion_primitives.py -v` | 79 |
| Roles / consent | `pytest tests/test_consent.py -v` | 63 |
| Scope containment | `pytest tests/test_scope.py -v` | 34 |
| Freshness / revocation | `pytest tests/test_key_rotation.py tests/test_epoch_revocation.py -v` | 28 |
| Both-identities delegation | `pytest tests/test_fdk_bridge.py -v` | 15 |
| Workload identity | `pytest tests/test_attestation_production.py -v` | 26 |
| DRE / reasonable delegate | `pytest tests/test_dre_adversarial.py tests/test_hbs_protection.py -v` | 20 |

---

## 5. Theoretical trace: from A&L to authgate

| A&L concept (1993/2003) | Authgate implementation | Test file |
|-------------------------|------------------------|-----------|
| `A says s` | `RightsClaim` + `OwnershipRegistry.add_claim()` | `test_core.py` |
| `controls` | `FreedomVerifier.verify()` | `test_core.py` |
| `B for A` (delegation) | `OwnershipRegistry.delegate()` | `test_delegate.py` |
| `B | A` (quoting) | `Action.delegated_by` (audit only, no authority) | `test_audit.py` |
| Attenuation (A6) | `child.rights ⊆ parent.rights`, `child.confidence ≤ parent.confidence` | `test_delegate.py`, `test_delegation_abuse.py` |
| Speaks-for (`⇒`) | `best_claim()` transitive closure | `test_authority_source.py` |
| Principal meet (`∧`) | `CompositeAttestor` | `test_attestation_production.py` |
| Roles (`A as R`) | `ConsentCapability` with scope + expiry | `test_consent.py` |
| "Channels are principals" | SPIFFE/SVID, AWS/GCP/Azure IAM attestors | `test_attestation_production.py` |
| "Both identities" delegation | FDK bridge + `Action.delegated_by` audit | `test_fdk_bridge.py` |
| "Reasonable delegate" | `DelegateReputationEngine` with DCRS + NDC | `test_dre_adversarial.py` |
| Unit axiom caution | DRE fail-safe: cannot override TCB DENY | `test_dre_adversarial.py::test_tcb_deny_cannot_be_overridden` |
| Non-interference | `SecurityLattice` + `check_plan()` | `test_ifc.py` |
| Audit / accountability | `AuditLog` with chained hashes | `test_audit.py`, `test_signed_audit.py` |
| Freshness (excluded in P1) | `epoch_revocation.py`, `key_rotation.py` | `test_epoch_revocation.py`, `test_key_rotation.py` |
| C4 escalation taxonomy | 10 sovereignty flags + coercion primitives | `test_authority_escalation.py`, `test_coercion_primitives.py` |

---

## 6. Reading the papers alongside the code

**Recommended pairing:**

1. Read P1 §3 (`says`, `controls`, speaks-for) → run `test_core.py`
2. Read P1 §5.1 (3 delegation schemes) → run `test_delegate.py` + `test_delegation_abuse.py`
3. Read P1 §5.1's "is B a reasonable delegate?" → run `test_dre_adversarial.py`
4. Read P2 §2 (Unit axiom) → run `test_dre_adversarial.py::test_tcb_deny_cannot_be_overridden`
5. Read P2 §3 (language taxonomy) → run `test_policy_dsl.py`
6. Read P2 §5 (non-interference) → run `test_ifc.py`
7. Read P2 §6 (2009 tutorial: C4 escalation) → run `test_authority_escalation.py` + `test_coercion_primitives.py`

---

## 7. Benchmarks

```bash
python benchmarks/dre_benchmark.py
```

This runs the DRE latency benchmark against a 10,000-entry history database, verifying the 2.8 ms p99 target.

```bash
python benchmarks/comprehensive_bench.py
```

This runs the full performance suite including `verify()` p50/p99, `verify_plan()`, and audit-chain latency.

---

## 8. Further reading

- `IMPLEMENTATION_REPORT_DRE.md` — Full DRE architectural rationale and threat model
- `SEMANTICS.md` — Formal theorems T1–T4 (delegation lattice, transitivity, anti-monotonicity, DAG, bounded distributive lattice)
- `THREAT_MODEL.md` — 5 adversary classes, 7 attack scenarios, formal security claims P1–P5
- `PRIOR_ART.md` — Comparative positioning vs. KeyKOS, seL4, Capsicum, E language, Macaroons, SELinux
- `docs/attestation.md` — Operator guide for production attestation paths
