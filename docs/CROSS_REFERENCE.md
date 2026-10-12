# AuthGate Kernel — Cross-Reference Map

> **Purpose:** Trace every claim, theorem, attack, and concept to its code, proof, and test.
> **Last updated:** 2026-08-23
> **Scope:** Axioms, theorems, attacks, defenses, documents, tests, and code files.

---

## Table of Contents

1. [Axioms → Code → Proofs → Tests](#1-axioms--code--proofs--tests)
2. [Theorems → Code → Proofs](#2-theorems--code--proofs)
3. [Attack Classes → Defenses → Tests](#3-attack-classes--defenses--tests)
4. [Document Citation Graph](#4-document-citation-graph)
5. [Test Files → Concepts](#5-test-files--concepts)
6. [Code Files → Invariants](#6-code-files--invariants)
7. [Formal Artifacts → Code Coverage](#7-formal-artifacts--code-coverage)
8. [DRE Feature Cross-Reference](#8-dre-feature-cross-reference)
9. [Quick Lookup Tables](#9-quick-lookup-tables)

---

## 1. Axioms → Code → Proofs → Tests

### A1 — Action Integrity (Canonical Binding)

| Aspect | Reference |
|--------|-----------|
| **Statement** | Every action submitted to the kernel is sealed by a binding hash covering every field. Post-seal mutation is detected before any other check. |
| **Code (Rust)** | `freedom-kernel/src/tcb/engine.rs:35` (Layer 1) |
| **Code (Python)** | `src/authgate/kernel/verifier.py:verify()` |
| **Hash function** | `freedom-kernel/src/tcb/types.rs:compute_hash` |
| **Lean theorem** | `forbidden_flags_always_block` (proved by simp) |
| **Kani harness** | All binding-hash-related properties |
| **Tests** | `attack_harness/simulation/engine.py` AT-1.* (40 scenarios) |
| **Tests** | `tests/test_wire_hardening.py` — mutation tests |

### A2 — Sovereignty / Corrigibility Flags Are Unconditional Denials

| Aspect | Reference |
|--------|-----------|
| **Statement** | Any of 10 hard sovereignty flags → immediate DENY. No claim, proof, or context overrides this. |
| **Code (Python)** | `src/authgate/kernel/verifier.py:128-150` (1st check after binding) |
| **Code (Rust)** | Sovereignty flags out-of-scope for Rust v2 TCB (Python only — see boundary) |
| **Lean theorem** | `forbidden_flags_always_block` (proved by simp, no axioms) |
| **Lean theorem** | `sovereignty_always_blocks` (proved by simp, no axioms) |
| **Kani harness** | 10 (one per flag): `prop_increases_machine_sovereignty` … `prop_coalition_reduces_freedom` |
| **Tests** | `tests/test_army.py::TestSecurity05` (113 tests) |
| **Tests** | `tests/test_adversarial_redteam.py` (25 tests) |
| **Tests** | `tests/test_authority_escalation.py` (22 tests) |
| **Tests** | `tests/test_coercion_primitives.py` (57 tests) |

### A3 — Cryptographic Identity Binding

| Aspect | Reference |
|--------|-----------|
| **Statement** | Actor identity = `SHA-256(public_key)` (Rust) or registered identity token (Python). Same name, different keys = distinct identities. |
| **Code (Rust)** | `freedom-kernel/src/tcb/dag.rs:95` (`SHA-256(issuer_pubkey) == parent.subject_id`) |
| **Code (Python)** | `src/authgate/kernel/registry.py:_enroll_identity()` |
| **Closes attack** | AT-5.1 (delegation impersonation), C-1 (Python name spoofing) |
| **Tests** | `tests/test_c1_identity_binding.py` (10 tests) |
| **Tests** | `attack_harness/simulation/engine.py` AT-5.* scenarios |

### A4 — No Ownerless Machine

| Aspect | Reference |
|--------|-----------|
| **Statement** | Every machine actor must have a registered human owner. Ownerless machine = blocked. |
| **Code (Python)** | `src/authgate/kernel/verifier.py:152-165` ("[A4] UNOWNED_MACHINE") |
| **Code (Rust)** | Implicit: CapabilityProof with no chain to root_key fails `dag.rs` validation |
| **Lean predicate** | `permitted` in `formal/FreedomKernel.lean:132` — explicit A4 line |
| **Kani harness** | `prop_ownerless_machine_blocked` (✓ proved) |
| **Tests** | `tests/test_core.py` — `test_a4_ownerless_machine_rejected` |
| **Tests** | 25 red team + 113 army tests (included) |

### A5 — Capability Proofs Are Cryptographically Signed and Time-Bounded

| Aspect | Reference |
|--------|-----------|
| **Statement** | Valid proof requires: (a) signature verifies against issuer's pubkey, (b) not expired, (c) epoch ≥ action's min_epoch. |
| **Code (Rust)** | `freedom-kernel/src/tcb/engine.rs:60-69` (expiry + epoch) + `dag.rs:62,72` (signatures) |
| **Code (Python)** | `src/authgate/kernel/registry.py:can_act()` (epoch gate) + `RightsClaim.is_expired()` |
| **Lean axiom** | `sig_euf_cma` in `formal/lean4/Proofs.lean:66` (ed25519 EUF-CMA — admitted, not proved) |
| **Lean theorem** | `attenuation_transitive` (chain integrity given signature validity) |
| **Lean theorem** | `stale_epoch_implies_deny` (epoch gate is unconditional) |
| **Kani harness** | `prop_epoch_check` + `proof_forged_revocation_ignored` |
| **Closes attacks** | AT-2.5 (forged sig), AT-2.6 (expired cap), AT-3.* (epoch attacks) |

### A6 — Attenuation: Child Rights ⊆ Parent Rights

| Aspect | Reference |
|--------|-----------|
| **Statement** | If B holds a capability delegated from A, B's rights are a subset of A's. No delegation can grant rights the delegator lacks. Machine cannot govern human. |
| **Code (Rust)** | `freedom-kernel/src/tcb/dag.rs:101` (`(rights & !parent.rights) != 0` → reject) |
| **Code (Python)** | `src/authgate/kernel/registry.py:_delegation_chain_valid()` + `verify()` machine-dominion check |
| **Lean theorem** | `attenuation_cannot_escalate` in `MultiAgent.lean:38` (proved) |
| **Lean theorem** | `rights_sufficiency_correct` (proved by simp) |
| **Kani harness** | `prop_attenuation_two_node` (✓ proved) |
| **Kani harness** | `prop_machine_governs_human_blocked` (✓ proved) |
| **Closes attacks** | AT-2.4 (child > parent), AT-5.* (impersonation) |

### A7 — No Ambient Authority

| Aspect | Reference |
|--------|-----------|
| **Statement** | Access requires a registered, valid claim. Absence = denial. Default-deny. Always. |
| **Code (Python)** | `src/authgate/kernel/verifier.py:184-217` (resource access loop) |
| **Code (Rust)** | `freedom-kernel/src/tcb/engine.rs:51` (filter caps where `subject_id == actor`) → no match = denied |
| **Kani harness** | `prop_read_denied_without_claim` (✓ proved) |
| **Kani harness** | `prop_write_denied_without_claim` (✓ proved) |
| **Kani harness** | `prop_delegation_denied_without_delegate_claim` (✓ proved) |
| **Closes attacks** | AT-2.1 (empty caps), AT-2.2 (cross-actor), AT-2.8 (insufficient rights) |

---

## 2. Theorems → Code → Proofs

### T1 — Transitivity of Delegation

| Aspect | Reference |
|--------|-----------|
| **Statement** | If B derives from A and C derives from B, then C.rights ⊆ A.rights and C.confidence ≤ A.confidence. |
| **Proof** | Subset transitivity + ℝ ≤ transitivity. Written in `SEMANTICS.md §6`. |
| **Code enforcement** | `OwnershipRegistry.delegate()` checks each link; transitivity follows by construction. |
| **Lean** | `attenuation_transitive` (proved) |
| **Tests** | `tests/test_delegate.py` — multi-hop delegation chains |

### T2 — Anti-Monotonicity of Confidence

| Aspect | Reference |
|--------|-----------|
| **Statement** | Confidence never increases through delegation chains. |
| **Proof** | Every link requires `C.confidence ≤ P.confidence`. By induction, for any n-hop chain: Cₙ.confidence ≤ C₀.confidence. |
| **Code enforcement** | `registry.delegate()` enforces at each hop. |
| **Lean** | Implicit in `attenuation_transitive` |
| **Tests** | `tests/test_delegate.py::test_confidence_cannot_exceed_delegator` |
| **Tests** | `tests/test_delegation_abuse.py` |

### T3 — No Cycles (Delegation Graph is a DAG)

| Aspect | Reference |
|--------|-----------|
| **Statement** | The delegation graph contains no cycles. |
| **Proof** | `OwnershipRegistry.delegate()` requires existing claim for delegating party. A cycle would require the terminal holder's claim to precede the root — impossible for the root which has no precursor. Depth bound of 16 provides secondary guarantee. |
| **Code enforcement** | `authority_graph.rs` topological sort at `delegate()` time. `engine.rs` depth check. |
| **Tests** | `tests/test_delegate.py::test_self_delegation_denied` |
| **Tests** | `tests/test_delegation_abuse.py::DEL-4` |

### T4 — Bounded Distributive Lattice

| Aspect | Reference |
|--------|-----------|
| **Statement** | `(Rights × [0,1], ≤)` forms a bounded distributive lattice under meet (∧) and join (∨). |
| **Proof** | Distributive law: `C₁ ∧ (C₂ ∨ C₃) = (C₁ ∧ C₂) ∨ (C₁ ∧ C₃)` — rights equality uses ∩/∪ distributivity; confidence uses min-max distributive identity on [0,1]. |
| **Code enforcement** | `OwnershipRegistry` computes meet at delegation time; `best_claim()` computes join for multiple claims. |
| **Tests** | `tests/test_compose_properties.py` — Hypothesis property-based tests for commutativity/associativity |

---

## 3. Attack Classes → Defenses → Tests

### AT-1: Canonicalization / IR Mismatch

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-1.1 actor_id tampered after seal | DEF-1.1 binding_hash recompute rejects | `engine.rs:35` | `attack_harness/simulation/engine.py` AT-1.* |
| AT-1.2 resource_hash tampered | DEF-1.2 binding_hash includes resource_hash | `engine.rs:35` | 40 mutation tests |
| AT-1.3 required_rights tampered | DEF-1.3 binding_hash includes rights | `engine.rs:35` | 40 mutation tests |
| AT-1.4 nonce tampered | DEF-1.4 binding_hash includes nonce | `engine.rs:35` | `tests/test_wire_hardening.py` |
| AT-1.5 timestamp tampered | DEF-1.5 binding_hash includes timestamp | `engine.rs:35` | `tests/test_wire_hardening.py` |
| AT-1.6 min_epoch lowered | DEF-1.6 binding_hash includes min_epoch | `engine.rs:35` | `tests/test_epoch_revocation.py` |
| AT-1.7 cap_bytes injected | DEF-1.7 binding_hash includes cap_bytes | `engine.rs:35` | `attack_harness/wire_attacks.py` |
| AT-1.8 rev_bytes injected | DEF-1.8 binding_hash includes rev_bytes | `engine.rs:35` | `attack_harness/wire_attacks.py` |

### AT-2: Proof Chain Manipulation

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-2.1 empty capability bundle | DEF-2.1 reject if no caps for actor | `engine.rs:39` | `tests/test_core.py` |
| AT-2.2 cross-actor cap reuse | DEF-2.2 subject_id filter | `engine.rs:51` | `tests/test_core.py::test_a7_undelegated_resource_blocked` |
| AT-2.3 cross-resource cap reuse | DEF-2.3 resource_hash match | `engine.rs:55` | `tests/test_scope.py` |
| AT-2.4 child rights exceed parent | DEF-2.4 attenuation check | `dag.rs:101` | `tests/test_delegate.py`, `tests/test_delegation_abuse.py::DEL-2` |
| AT-2.5 invalid signature | DEF-2.5 ed25519 verify | `dag.rs:62,72` | `tests/test_signed_audit.py` |
| AT-2.6 expired capability | DEF-2.6 expiry check | `engine.rs:60` | `tests/test_epoch_revocation.py` |
| AT-2.7 chain depth exhaustion | DEF-2.7 MAX_CHAIN_DEPTH=16 | `dag.rs:23` | `tests/test_delegate.py::test_max_depth` |
| AT-2.8 insufficient rights | DEF-2.8 rights bitmask check | `engine.rs:79` | `tests/test_core.py`, `tests/test_authority_escalation.py::test_esc2` |

### AT-3: Epoch / Revocation

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-3.1 stale parent epoch | DEF-3.1 every chain node checked | `dag.rs:52` | `tests/test_epoch_revocation.py` |
| AT-3.2 stale leaf epoch | DEF-3.2 cap.epoch < min_epoch check | `engine.rs:68` | `tests/test_epoch_revocation.py` |
| AT-3.3 forged revocation | DEF-3.3 only root-signed revocations | `engine.rs:108` | `tests/test_epoch_revocation.py` |
| AT-3.4 revocation suppression | DEF-3.4 epoch advance is primary | architectural | `tests/test_epoch_revocation.py` |
| AT-3.5 nonce replay | DEF-3.5 nonce in binding_hash | `types.rs:compute_hash` | `tests/test_wire_hardening.py` |
| AT-3.6 expiry past now | DEF-3.6 same as AT-2.6 | `engine.rs:60` | `tests/test_epoch_revocation.py` |

### AT-4: Composition / Sequence

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-4.1 stepwise privilege accumulation | DEF-4.1 SequenceContext tracks rights | `sequence.rs:56` | `tests/test_authority_escalation.py` |
| AT-4.2 read-execute-write exfiltration | DEF-4.2 caller compares accumulated vs limit | `sequence.rs:74` | `tests/test_ifc.py` |
| AT-4.3 multi-actor rights merge | DEF-4.3 policy-layer concern | architectural | `tests/test_policy_dsl.py` |
| AT-4.4 high-water mark regression | DEF-4.4 bitwise OR is monotonic | `sequence.rs:57` | `tests/test_proptest.py` |
| AT-4.5 session boundary confusion | DEF-4.5 one SequenceContext per session | architectural | `tests/test_context.py` |

### AT-5: Identity Binding

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-5.1 delegation impersonation | DEF-5.1 SHA-256(pubkey) == subject_id | `dag.rs:95` | `tests/test_c1_identity_binding.py` |
| AT-5.2 all-zeros actor confusion | DEF-5.2 actor_id is opaque 32 bytes | `types.rs` | `tests/test_wire_hardening.py` |
| AT-5.3 Python name-based impersonation | DEF-5.3 identity_token + registry tracking | `registry.py:_enroll_identity` | `tests/test_c1_identity_binding.py` |
| AT-5.4 multi-identity collision | DEF-5.4 compound key (name, kind, resource) | `registry.py:_claim_key` | `tests/test_wire_hardening.py` |

### AT-6: Crypto Boundary

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-6.1 signature forgery | DEF-6.1 ed25519 EUF-CMA (admitted axiom) | `formal/lean4/` | `tests/test_signed_audit.py` |
| AT-6.2 cross-context proof reuse | DEF-6.2 resource_hash must match | `engine.rs:55` | `tests/test_scope.py` |
| AT-6.3 timing side-channel | DEF-6.3 constant-time comparison | `types.rs:verify_binding` | `tests/test_wire_hardening.py` |
| AT-6.4 weak nonce predictability | DEF-6.4 caller-supplied | DEPLOY | `tests/test_wire_hardening.py` |
| AT-6.5 nonce reuse | DEF-6.5 binding_hash uniqueness from nonce | `types.rs:compute_hash` | `tests/test_wire_hardening.py` |

### AT-7: Integration / Adapter Boundary

| Attack | Defense | Enforcement | Tests |
|--------|---------|-------------|-------|
| AT-7.1 adapter mutates action | DEF-7.1 binding_hash detects mutation | `engine.rs:35` | `tests/test_adapters_callgate_integration.py` |
| AT-7.2 adapter replays action | DEF-7.2 nonce + timestamp + replay cache | DEPLOY | `tests/test_wire_hardening.py` |
| AT-7.3 post-verify mutation | DEF-7.3 binding_hash recompute changes | `engine.rs:35` | `tests/test_wire_hardening.py` |
| AT-7.4 adapter logs proofs | DEF-7.4 adapter is untrusted | architectural | `tests/test_adapters.py` |
| AT-7.5 shadow execution | DEF-7.5 Rust: `pub(crate)`, Python: name-mangled, OS: WASM/seccomp | `call_gate.rs` + `call_gate.py` | `tests/test_adversarial_redteam.py` |

---

## 4. Document Citation Graph

### Primary Documents (most cited)

| Document | Cited by |
|----------|----------|
| `AXIOMATIC_FOUNDATION.md` | `README.md`, `THREAT_MODEL.md`, `THREAT_DEFENSE_PAIRS.md`, `SEMANTICS.md`, `MASTER_PLAN.md`, `CONTRIBUTING.md`, `TCB.md`, `FINDINGS.md` |
| `SEMANTICS.md` | `README.md`, `MASTER_PLAN.md`, `TEST_WALKTHROUGH_ABADI_LAMPSON.md`, `ARCHITECTURE.md`, `CHANGELOG.md` |
| `THREAT_MODEL.md` | `README.md`, `SECURITY.md`, `DEPLOYMENT_READINESS.md`, `THREAT_DEFENSE_PAIRS.md`, `NON_GOALS.md` |
| `ASSUMPTIONS.md` | `AXIOMATIC_FOUNDATION.md`, `SECURITY.md`, `REVIEW_PACKET.md`, `FREEDOM_THEORY_POSITION.md` |
| `POSITIONING.md` | `README.md`, `MASTER_PLAN.md`, `SILICON_VALLEY.md`, `OUTREACH_DRAFTS.md`, `DEATH_SCENARIOS.md` |

### Document Clusters

**Security Cluster:**
```
THREAT_MODEL.md ←→ THREAT_DEFENSE_PAIRS.md
    ↓                   ↓
SECURITY.md ←→ FINDINGS.md ←→ ASSUMPTIONS.md
    ↓
NON_GOALS.md
```

**Formal Verification Cluster:**
```
AXIOMATIC_FOUNDATION.md ←→ SEMANTICS.md ←→ MASTER_PLAN.md
    ↓                           ↓
ASSUMPTIONS.md ←→ formal/INCOMPLETENESS.md
```

**DRE Feature Cluster:**
```
PR_DESCRIPTION_DRE.md ←→ IMPLEMENTATION_REPORT_DRE.md ←→ RELEASE_BRIEF_DRE.md
    ↓                           ↓                           ↓
QUICKSTART.md ←→ TEST_WALKTHROUGH_ABADI_LAMPSON.md ←→ docs/attestation.md
```

**Deployment Cluster:**
```
GUIDE.md ←→ DEPLOYMENT_READINESS.md ←→ DEPLOYMENT.md
    ↓              ↓
INFRA.md ←→ INCIDENT_RESPONSE.md
```

---

## 5. Test Files → Concepts

### Core Kernel Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_core.py` | 27 | `says`, `controls`, hand-off, sovereignty flags | P1 §3, P2 §6 |
| `tests/test_context.py` | ~10 | Execution context, session boundaries | P1 §3 |
| `tests/test_delegate.py` | ~28 | Delegation, attenuation, confidence | P1 §5.1 |
| `tests/test_delegation_abuse.py` | 16 | DEL-1..5, orphaned chains, amplification | P1 §5.1 |
| `tests/test_authority_source.py` | ~32 | Speaks-for, principal algebra, federation | P1 §3 |
| `tests/test_sovereign_identity.py` | ~15 | Identity binding, machine ownership | P1 §1 |
| `tests/test_federation.py` | ~7 | Cross-domain speaks-for | P2 §3 |

### Security & Adversarial Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_authority_escalation.py` | 22 | ESC-1..6, C4 taxonomy | P2 §6 |
| `tests/test_coercion_primitives.py` | 57 | 10 sovereignty flags by coercion type | P2 §6 |
| `tests/test_adversarial.py` | ~25 | General adversarial scenarios | P1 §3, P2 §6 |
| `tests/test_adversarial_redteam.py` | 25 | Red-team scenarios, TCB supremacy | P2 §3 |
| `tests/test_army.py` | 113 | Security army comprehensive tests | P1 §3, P2 §6 |
| `tests/test_c1_identity_binding.py` | 10 | Identity token, impersonation | P1 §1 |

### DRE & Reputation Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_dre_adversarial.py` | 10 | Monotonicity, poisoning, spoofing, TCB supremacy | P1 §5.1, P2 §6 |
| `tests/test_hbs_protection.py` | 10 | Rate limiting, burst, NDC spoofing, breadth | P2 §6 |
| `tests/test_attestation_production.py` | 26 | SPIFFE, AWS, GCP, Azure attestors | P1 §1 |
| `tests/test_delegate_reputation.py` | 438 | NDC matrix, historical penalties, DCRS | P1 §5.1 |
| `tests/test_delegate_reputation_config.py` | ~20 | Config validation, edge cases | — |
| `tests/test_delegate_reputation_properties.py` | ~20 | Property-based DRE tests | P2 §6 |

### Audit & Wire Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_audit.py` | ~20 | Chain integrity, append-only | Cederquist 2007 |
| `tests/test_audit_hardening.py` | ~10 | Concurrent appends, race conditions | Jagadeesan 2005 |
| `tests/test_signed_audit.py` | ~4 | Ed25519 signatures, replay | Vaughan 2008 |
| `tests/test_wire_hardening.py` | 37 | WA-1..18, input validation | P1 §2 |
| `tests/test_wire_validator.py` | 16 | Schema validation, type enforcement | P1 §2 |

### Policy & Scope Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_policy_dsl.py` | 51 | DSL parser, conditions, compilation | P2 §3 |
| `tests/test_policy.py` | ~13 | Policy evaluation, rules | P2 §3 |
| `tests/test_policy_decision_contract.py` | 4 | FDK bridge, JSON contract | P1 §5.1 |
| `tests/test_scope.py` | 34 | Scope containment, path traversal | P1 §2, SEMANTICS §5 |
| `tests/test_ifc.py` | 21 | Bell-LaPadula, non-interference | P2 §5 |
| `tests/test_consent.py` | 63 | Roles, consent, expiry | P1 §4 |

### Infrastructure Tests

| Test File | Tests | Concepts Exercised | A&L Mapping |
|-----------|-------|-------------------|-------------|
| `tests/test_key_rotation.py` | ~15 | Key rotation, certificates, grace period | P1 (out of scope → addressed) |
| `tests/test_epoch_revocation.py` | ~13 | Epoch advance, stale claims, revocation | P1 (out of scope → addressed) |
| `tests/test_hooks.py` | 29 | Observability, metrics, exception isolation | — |
| `tests/test_fdk_bridge.py` | 15 | FDK integration, both-identities delegation | P1 §5.1 |
| `tests/test_adapters.py` | ~20 | Framework adapters | P2 §3 |
| `tests/test_adapters_callgate_integration.py` | ~15 | Adapter + CallGate integration | P1 §3 |
| `tests/test_proptest.py` | 5 | Hypothesis property-based tests | P1 §3 |

---

## 6. Code Files → Invariants

### TCB (Trusted Computing Base)

| File | LOC Ceiling | Invariants Enforced | Formal Coverage |
|------|-------------|---------------------|-----------------|
| `authgate-kernel/src/tcb/engine.rs` | 300 | I1 CanonicalBinding, I2 IdentityBinding, I3 ExpiryGate, I4 EpochSafety, I5 ResourceBinding, I8 ChainComplete, I9 RevocationSafety | Kani: 19 harnesses |
| `authgate-kernel/src/tcb/dag.rs` | 200 | I6 Attenuation, I7 ChainEpoch, signature verification, depth cap | Kani: `prop_attenuation_two_node`, `prop_epoch_check` |
| `authgate-kernel/src/tcb/types.rs` | uncapped | `compute_hash`, `verify_binding` (constant-time) | Inline tests |
| `authgate-kernel/src/tcb/crypto.rs` | uncapped | ed25519 signing/verification, nonce generation | Axiom: `sig_euf_cma` (admitted) |
| `authgate-kernel/src/tcb/wire.rs` | uncapped | Typed deserialization, no logic | Inline tests (11) |
| `authgate-kernel/src/tcb/sequence.rs` | 107 | Accumulated rights monotonicity, session limits | Kani: 5 harnesses |

### Python Reference Layer

| File | Invariants Enforced | Tests |
|------|---------------------|-------|
| `src/authgate/kernel/verifier.py` | A2 sovereignty flags, A4 ownership, A7 default-deny | `test_core.py`, `test_authority_escalation.py` |
| `src/authgate/kernel/registry.py` | A6 attenuation (at delegation time), cycle detection | `test_delegate.py`, `test_delegation_abuse.py` |
| `src/authgate/kernel/entities.py` | Resource scope containment, AgentType enum | `test_scope.py`, `test_wire_hardening.py` |
| `src/authgate/kernel/audit.py` | Append-only hash chain, tamper detection | `test_audit.py`, `test_audit_hardening.py` |
| `src/authgate/kernel/consent.py` | Role-based consent, expiry | `test_consent.py` |
| `src/authgate/kernel/policy_dsl.py` | DSL parsing, compilation | `test_policy_dsl.py` |

### DRE Extension

| File | Invariants Enforced | Tests |
|------|---------------------|-------|
| `src/authgate/extensions/delegate_reputation.py` | DCRS monotonicity, human safety, TCB supremacy | `test_dre_adversarial.py` |
| `src/authgate/extensions/historical_behavior_store.py` | Append-only SQLite, thread safety | `test_hbs_protection.py` |
| `src/authgate/extensions/hbs_protection.py` | Rate limiting, burst detection, NDC spoofing, breadth limits | `test_hbs_protection.py` |
| `src/authgate/extensions/attestation.py` | SPIFFE/SVID, AWS/GCP/Azure IAM verification | `test_attestation_production.py` |

---

## 7. Formal Artifacts → Code Coverage

### TLA+ Specification

| Artifact | Status | Code Coverage |
|----------|--------|---------------|
| `formal/authgate_kernel.tla` | Invariants stated, TLC verified 2026-08-20 (bounded: 4227 states, no error) | `engine.rs` invariants I1–I8 |
| `formal/TLC_SETUP.md` | Setup instructions for Java + tla2tools.jar | — |
| `formal/tlc_run.log` | TLC run output | — |

### Lean 4 Proofs

| Theorem | File | Status | Code Coverage |
|---------|------|--------|---------------|
| `forbidden_flags_always_block` | `formal/lean4/Proofs.lean` | Proved (simp) | `engine.rs` flag check |
| `sovereignty_always_blocks` | `formal/lean4/Proofs.lean` | Proved (simp) | `engine.rs` flag check |
| `attenuation_transitive` | `formal/lean4/Proofs.lean` | Proved | `dag.rs` chain validation |
| `attenuation_cannot_escalate` | `formal/lean4/MultiAgent.lean` | Proved | `dag.rs:101` |
| `stale_epoch_implies_deny` | `formal/lean4/Proofs.lean` | Proved | `engine.rs:68` |
| `rights_sufficiency_correct` | `formal/lean4/Proofs.lean` | Proved (simp) | `engine.rs:79` |
| `verify_deterministic` | `formal/lean4/Proofs.lean` | Proved (rfl) | `engine.rs` pure function |
| `permitted_implies_no_forbidden_flag` | `formal/lean4/Proofs.lean` | Proved | `engine.rs` output invariant |
| `taint_monotone` | `formal/lean4/Proofs.lean` | Proved | `sequence.rs` accumulated rights |
| `sig_euf_cma` | `formal/lean4/Proofs.lean` | **Admitted axiom** | `crypto.rs` ed25519 |

### Kani Harnesses

| Harness | Property | File Tested |
|---------|----------|-------------|
| `prop_attenuation_two_node` | Child rights ⊆ parent rights | `dag.rs` |
| `prop_epoch_check` | Stale epoch → deny | `engine.rs` + `dag.rs` |
| `proof_forged_revocation_ignored` | Forged revocations ignored | `engine.rs` |
| `prop_ownerless_machine_blocked` | No owner → blocked | `engine.rs` |
| `prop_machine_governs_human_blocked` | Machine over human → blocked | `engine.rs` |
| `prop_read_denied_without_claim` | No claim → deny (read) | `engine.rs` |
| `prop_write_denied_without_claim` | No claim → deny (write) | `engine.rs` |
| `prop_delegation_denied_without_delegate_claim` | No delegate claim → deny | `engine.rs` |
| `prop_permitted_implies_no_violations` | PERMITTED ↔ violations empty | `engine.rs` |
| `prop_blocked_implies_violations_non_empty` | BLOCKED ↔ violations non-empty | `engine.rs` |
| `prop_permitted_deterministic` | Same input → same output | `engine.rs` |
| `prop_increases_machine_sovereignty` | Flag blocks (1 of 10) | `engine.rs` |
| ... | ... | ... |
| `prop_seq_accumulated_monotone` | Accumulated rights monotone | `sequence.rs` |
| `prop_seq_exceeds_limit_consistent` | Bitmask semantics | `sequence.rs` |
| `prop_seq_step_count_matches_records` | Bounded counting | `sequence.rs` |
| `prop_seq_empty_never_exceeds` | Vacuous truth | `sequence.rs` |
| `prop_seq_idempotent_rights` | Idempotent under OR | `sequence.rs` |

---

## 8. DRE Feature Cross-Reference

### DRE Modules → Tests → Documentation

| Module | Tests | Docs | Concepts |
|--------|-------|------|----------|
| `delegate_reputation.py` | `test_delegate_reputation.py` (438), `test_dre_adversarial.py` (10) | `IMPLEMENTATION_REPORT_DRE.md` §2, `RELEASE_BRIEF_DRE.md` §4 | DCRS, NDC, chain-depth attenuation |
| `historical_behavior_store.py` | `test_hbs_protection.py` (10) | `IMPLEMENTATION_REPORT_DRE.md` §2, `docs/attestation.md` | SQLite, append-only, covering index |
| `hbs_protection.py` | `test_hbs_protection.py` (10) | `IMPLEMENTATION_REPORT_DRE.md` §5a | Rate limit, burst, spoofing, breadth |
| `attestation.py` | `test_attestation_production.py` (26) | `docs/attestation.md`, `IMPLEMENTATION_REPORT_DRE.md` §4 | SPIFFE, AWS, GCP, Azure |
| `delegate_reputation_config.py` | `test_delegate_reputation_config.py` (~20) | `IMPLEMENTATION_REPORT_DRE.md` §2 | Pydantic config, validation |

### DRE Performance Benchmarks

| Benchmark | Target | Actual | Test File |
|-----------|--------|--------|-----------|
| DRE latency p99 (10k history) | < 5 ms | 2.8 ms | `benchmarks/dre_benchmark.py` |
| DRE latency p50 (10k history) | < 3 ms | 2.49 ms | `benchmarks/dre_benchmark.py` |
| DRE latency p99.9 (10k history) | < 10 ms | 4.71 ms | `benchmarks/dre_benchmark.py` |

### DRE Invariants

| Invariant | Enforcement | Test |
|-----------|-------------|------|
| TCB Supremacy | `DelegateReputationEngine.evaluate()` returns DENY if kernel DENY | `test_dre_adversarial.py::test_tcb_deny_cannot_be_overridden` |
| Monotonicity | Adding penalty never decreases DCRS | `test_dre_adversarial.py::test_monotonicity_adding_penalty_never_decreases_dcrs` |
| Human Safety | HUMAN with no violations always passes (DCRS < 0.5) | `test_dre_adversarial.py::test_human_with_no_violations_always_passes` |
| Time-Decay | Old benign records cannot mask recent violations | `test_dre_adversarial.py::test_history_poisoning_dilution_is_limited_by_decay` |

---

## 9. Quick Lookup Tables

### Invariant Quick Lookup

| Invariant | Code File | Line | Proof | Test |
|-----------|-----------|------|-------|------|
| I1 CanonicalBinding | `engine.rs` | 35 | Kani | `attack_harness/simulation/engine.py` AT-1.* |
| I2 IdentityBinding | `engine.rs` | 51 | Kani | `test_c1_identity_binding.py` |
| I3 ExpiryGate | `engine.rs` | 60 | Kani | `test_epoch_revocation.py` |
| I4 EpochSafety | `engine.rs` | 68 | Kani | `test_epoch_revocation.py` |
| I5 ResourceBinding | `engine.rs` | 55 | Kani | `test_scope.py` |
| I6 Attenuation | `dag.rs` | 101 | Lean: `attenuation_cannot_escalate` | `test_delegate.py` |
| I7 ChainEpoch | `dag.rs` | 52 | Kani | `test_epoch_revocation.py` |
| I8 ChainComplete | `engine.rs` | 79 | Kani | `test_delegate.py` |
| I9 RevocationSafety | `engine.rs` | 108 | Kani | `test_epoch_revocation.py` |

### A&L Concept → Test Command Quick Reference

| Concept | Command | Tests |
|---------|---------|-------|
| `says` / `controls` | `pytest tests/test_core.py tests/test_context.py -v` | 27 |
| `B for A` delegation | `pytest tests/test_delegate.py tests/test_delegation_abuse.py -v` | 44 |
| Speaks-for / principal algebra | `pytest tests/test_authority_source.py tests/test_sovereign_identity.py -v` | 47 |
| Wire integrity | `pytest tests/test_wire_hardening.py tests/test_wire_validator.py -v` | 53 |
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

### File Extension → Purpose

| Extension | Purpose |
|-----------|---------|
| `.rs` | Rust TCB, extensions, adapters |
| `.py` | Python compatibility layer, extensions, tests |
| `.lean` | Lean 4 formal proofs |
| `.tla` | TLA+ specification |
| `.json` | JSON Schema wire contracts |
| `.md` | Documentation, decisions, specifications |
| `.yaml` / `.yml` | CI/CD, K8s manifests |
| `.toml` | Rust/Cargo, Python packaging |

---

*This cross-reference map is a living document. Update when new invariants, theorems, attacks, or test files are added.*
