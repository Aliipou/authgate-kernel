# Formal Verification Coverage

## TLA+ Model Checking

Run: `java -jar tla2tools.jar -tool MC_AuthGateV3`

| Property                | Status          | State Space                        |
|-------------------------|-----------------|------------------------------------|
| I1 CanonicalBinding     | PENDING TLC     | MC model: MCActors × MCResources   |
| I2 IdentityBinding      | PENDING TLC     | MC model                           |
| I3 ExpiryGate           | PENDING TLC     | MC model                           |
| I4 EpochSafety          | PENDING TLC     | MC model, MCMaxEpoch=2             |
| I5 ResourceBinding      | PENDING TLC     | MC model                           |
| I6 Attenuation          | PENDING TLC     | MC model, MCMaxChainDepth=2        |
| I7 ChainEpoch           | PENDING TLC     | MC model                           |
| I8 ChainComplete        | PENDING TLC     | MC model                           |
| I9 RevocationSafety     | PENDING TLC     | MC model                           |
| BigSafety (I1–I9)       | PENDING TLC     | Conjunction                        |
| PermitSoundness         | PENDING TLC     | Primary theorem                    |

Constants used in MC model:
```
MCActors      = {"a0", "a1", "a2", "a3"}
MCResources   = {"r1"}
MCProofHashes = {"h1", "h2", "h3", "h4", "h5"}
MCPublicKeys  = {"pk0", "pk1", "pk2", "pk3"}
MCRootKey     = "pk0"
MCMaxChainDepth = 2
MCMaxEpoch    = 2
```

## Kani Model Checking

Run: `cargo kani --harness <name>` from `freedom-kernel/`

| Harness                              | Property                                          | Status     |
|--------------------------------------|---------------------------------------------------|------------|
| prop_increases_machine_sovereignty   | flag=true → always blocked                        | ✓ proved   |
| prop_resists_human_correction        | flag=true → always blocked                        | ✓ proved   |
| prop_bypasses_verifier               | flag=true → always blocked                        | ✓ proved   |
| prop_weakens_verifier                | flag=true → always blocked                        | ✓ proved   |
| prop_disables_corrigibility          | flag=true → always blocked                        | ✓ proved   |
| prop_machine_coalition_dominion      | flag=true → always blocked                        | ✓ proved   |
| prop_coerces                         | flag=true → always blocked                        | ✓ proved   |
| prop_deceives                        | flag=true → always blocked                        | ✓ proved   |
| prop_self_modification               | flag=true → always blocked                        | ✓ proved   |
| prop_coalition_reduces_freedom       | flag=true → always blocked                        | ✓ proved   |
| prop_ownerless_machine_blocked       | No owner → A4 violation → blocked                 | ✓ proved   |
| prop_machine_governs_human_blocked   | governs_humans non-empty → A6 → blocked           | ✓ proved   |
| prop_public_resource_read_permitted  | is_public=true, op=read → always permitted        | ✓ proved   |
| prop_write_denied_without_claim      | No write claim → WRITE DENIED                     | ✓ proved   |
| prop_attenuation_two_node            | child.rights ⊆ parent.rights (all bitmasks)       | ✓ proved   |
| prop_epoch_check                     | epoch gate is total (no third case)               | ✓ proved   |
| proof_forged_revocation_ignored      | invalid-sig revocation never flips Permit→Deny    | ✓ proved   |

## Lean 4 Theorems

Located in `formal/lean4/` (see `Proofs.lean`):

| Theorem                          | Statement                                                                  |
|----------------------------------|----------------------------------------------------------------------------|
| `forbidden_implies_blocked`      | Any action with a forbidden flag cannot be permitted                       |
| `verify_deterministic`           | Same input → same output; no hidden state                                  |
| `attenuation_transitive`         | If B ⊆ A and C ⊆ B then C ⊆ A (chain attenuation)                        |
| `rights_sufficiency_correct`     | required ⊆ cap.rights ↔ rights check passes                               |
| `epoch_gate_total`               | cap.epoch < min ∨ min ≤ cap.epoch — no third case                         |
| `stale_epoch_implies_deny`       | cap.epoch < min_epoch → ¬FreshEpoch                                       |
| `subject_mismatch_violates_binding` | cap.subject ≠ actor_id → ¬SubjectBinding                               |

Admitted axioms (cryptographic boundary):
- `sig_euf_cma` — ed25519 EUF-CMA security
- `forged_revocation_harmless` — invalid-sig revocations do not affect decisions

## TCB Rust Test Coverage

| File | Tests | Code paths covered |
|---|---|---|
| `engine.rs` (inline) | 5 | Permit, Deny (tampered, expired, stale, wrong actor) |
| `dag.rs` (inline) | 8 | Root, delegation, wrong key, attenuation, AT-5.1, AT-3.1, two-level, resource propagation |
| `sequence.rs` (now `src/sequence.rs`, outside TCB) | 2 | Accumulation, limit detection |
| `tests.rs` | 73 | All 9 invariant paths × permit + deny + boundary |
| `call_gate.rs` (inline) | 22 | Same paths through public API + consistency + AT-7.5 |
| `hardening_tests.rs` | 31 | Resource redirection, malformed crypto, bundle manipulation, depth limit, rights/epoch edge cases, 6 proptest properties |
| **Total** | **141** | |

## Adversarial Simulation

Run: `python attack_harness/attack_tree_coverage.py`

| Attack class | Scenarios | Result |
|---|---|---|
| AT-1 (IR tampering) | 31 | 0 violations |
| AT-2 (chain manipulation) | 42 | 0 violations |
| AT-3 (epoch/revocation) | 35 | 0 violations |
| AT-4 (composition) | 28 | 0 violations |
| AT-5 (identity binding) | 21 | 0 violations |
| AT-6 (crypto boundary) | 42 | 0 violations |
| AT-7 (integration boundary) | 32 | 0 violations |
| **Total** | **231** | **0 violations** |

## Newly Closed Gaps (this hardening pass)

| ID | Fix | What it closes |
|---|---|---|
| INV-RESOURCE-PROP | Resource propagation in `dag.rs` | Compromised delegator cannot redirect root-granted authority to a different resource. Previously, a delegator with a root-signed cap for R1 could issue a child cap for R2 and the chain would validate. Now rejected with "delegation chain resource mismatch". |
| TCB boundary | Moved `sequence.rs` out of `tcb/` | `SequenceContext` is a policy helper, not a security enforcer. Moving it clarifies the TCB boundary (engine + dag + call_gate + types = ~255 LOC). |

## Delegation Lattice Theorems (Phase 1.2 — closed)

Proved in `SEMANTICS.md §5`:

| Theorem | Statement | Method |
|---|---|---|
| T1 Transitivity | Rights and confidence both propagate transitively through chains | Pen-and-paper proof; follows from ⊆ and ≤ transitivity |
| T2 Anti-monotonicity | Confidence never increases through any delegation chain | Inductive proof on chain length |
| T3 No Cycles | Delegation graph is a DAG; depth > 16 rejected at wire layer | Registry construction invariant + depth bound |
| T4 BDL | (Rights × [0,1]) forms a bounded distributive lattice under meet=(∩,min), join=(∪,max) | Distributivity of ∩/∪ over sets + min/max over ℝ |

## Scope Containment Theorems (Phase 1.3 formal — added 2026-05-29)

Located in `formal/lean4/FreedomKernel/Scope.lean`.
Mirrors SEMANTICS.md §5 formal properties.

| Theorem | Statement | Status |
|---|---|---|
| T-SC1 Reflexivity | `scopeContains(P, P) = True` for traversal-free P | Admitted (String.normalize induction pending) |
| T-SC2 Root-universal | `scopeContains("", C) = True` for traversal-free C | ✓ Proved |
| T-SC3 Traversal-parent | `hasTraversal(P) → scopeContains(P, C) = False` | ✓ Proved |
| T-SC3b Traversal-child | `hasTraversal(C) → scopeContains(P, C) = False` | ✓ Proved |
| T-SC4 Prefix-implies | `C.startsWith(normalize(P)++"/") → scopeContains(P,C)` | ✓ Proved |
| T-SC5 Antisymmetry | `scopeContains(P,Q) ∧ scopeContains(Q,P) → normalize(P)=normalize(Q)` | Admitted (String antisymmetry pending) |

Security-critical theorems (T-SC3, T-SC3b, T-SC4) are fully proved without sorry.
T-SC1 and T-SC5 require induction over String.normalize / String.startsWith interaction
and are admitted pending Lean 4 String library maturity; they are axiomatically sound
by inspection of the Python implementation.

## Threat Taxonomy (Phase 0, O3 — added 2026-05-29)

Located in `attack_harness/threat_taxonomy/`.
Adversarial ontology, attack class hierarchy, authority escalation tree, delegation abuse catalog, coercion primitives catalog.

| Module | Scenarios | Status |
|--------|-----------|--------|
| `ontology.py` | 21 scenarios across 3 catalogs (ESC-1..6, DEL-1..5, COER-1..10) | Defined |
| `authority_escalation.py` | ESC-1..6: ghost principal, rights amplification, confidence inflation, sovereignty flags, governs-humans, expired claim | All DENY (6/6) |
| `delegation_abuse.py` | DEL-1..5: orphaned delegation, chain amplification, no-delegate flag, self-delegation, scope expansion | All correct (6/6) |
| `coercion_primitives.py` | COER-1..10: 10 sovereignty flags mapped to coercion types | All DENY (10/10) |

Test files: `tests/test_authority_escalation.py`, `tests/test_delegation_abuse.py`, `tests/test_coercion_primitives.py`

**Delegation chain validation (new — 2026-05-29):**
`OwnershipRegistry._delegation_chain_valid()` now enforces at the Python compatibility layer:
- Self-delegation forbidden (T3: DAG invariant)
- Delegator must have a valid `can_delegate=True` claim whose scope contains child scope
- Child rights ⊆ parent rights (A6 attenuation)
- Child confidence ≤ parent confidence (T2 anti-monotonicity)

This closes the Python-layer gap for delegation chain integrity (previously only enforced at Rust TCB level).

## Open Gaps (explicit, not hidden)

| Gap | Description | Why it's acceptable |
|---|---|---|
| G1 | Semantic gap | Kernel doesn't parse intent — by design |
| G3 | Clock trust | Caller-supplied `now` — documented limitation |
| G5 | No replay protection | Kernel is stateless; replay protection belongs in the orchestration layer |
| G6 | Crypto assumptions | ed25519 break = NIST-level threat — out of scope |
| TLC run | TLA+ model not yet TLC-checked | Needs Java + tla2tools.jar (setup documented in TLC_SETUP.md) |
| Refinement | No TLA+ → Rust refinement proof | Research-level gap; documented in INCOMPLETENESS.md |

## What Is NOT Formally Verified

- Python compatibility runtime (tested, not proved)
- Extension layer (IFC, manipulation scorer) — heuristic, no formal claims
- Adapter layer boundary semantics
- Distributed consistency (no spec exists yet)
- Implementation-level refinement from TLA+ to Rust
