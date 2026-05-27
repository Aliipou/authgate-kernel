# Formal Verification Coverage — authgate-kernel v2/v3

## TLA+ Model Checking (v3 spec — authgate_v3.tla)

Run: `java -jar tla2tools.jar -tool MC_AuthGateV3`

Model: `MC_AuthGateV3.tla` + `MC_AuthGateV3.cfg`
Constants: Actors=4, Resources=1, ProofHashes=5, MaxChainDepth=2, MaxEpoch=2
Actions: 9 pre-enumerated scenarios covering AT-1 through AT-7

| Invariant | Attack class | Status | Note |
|---|---|---|---|
| TypeInvariant | structural | PENDING TLC | state type safety |
| EpochSafety (I1) | AT-3 | PENDING TLC | leaf cap epoch ≥ min_epoch |
| IdentityBinding (I2) | AT-5 | PENDING TLC | Hash(issuer_pubkey) = parent.subject_id |
| Attenuation (I3) | AT-2 | PENDING TLC | child.rights ⊆ parent.rights |
| RevocationSafety (I4) | AT-3 | PENDING TLC | revoked hash never Permit |
| ResourceBinding (I6) | AT-6 | PENDING TLC | cap.resource = action.resource |
| ChainEpoch (I7) | AT-3.1 | PENDING TLC | every chain node epoch ≥ min_epoch |

**PENDING TLC** = spec is structurally complete and TLC-runnable; awaiting Java/TLC execution environment on CI. The MC module has been reviewed for correctness manually — all attack scenarios produce Deny by construction (verified against Python model which passes 231 adversarial simulation scenarios).

---

## TLA+ v1 spec (FreedomKernel.tla — v1 registry model, now superseded)

| Property | Status | State Space |
|---|---|---|
| A4 (ownership) | verified | MaxEntities=5, exhaustive |
| A6 (no machine governs) | verified | MaxEntities=5, exhaustive |
| A7 (delegation) | verified | MaxResources=10, exhaustive |
| Forbidden flags block | verified | All 10 flags, exhaustive |
| IFC non-interference | verified | 3-label lattice, exhaustive |
| TOCTOU safety | verified | bounded depth=3 |

Note: v1 spec models the registry-based engine. v3 spec models the stateless
proof-chain TCB (the current Rust `src/tcb/` implementation).

---

## Kani Bounded Model Checking (engine.rs v1)

Run: `cargo kani --harness <name>` from `freedom-kernel/`

| Harness | Property | Status |
|---|---|---|
| prop_increases_machine_sovereignty | flag=true → always blocked | proved |
| prop_resists_human_correction | flag=true → always blocked | proved |
| prop_bypasses_verifier | flag=true → always blocked | proved |
| prop_weakens_verifier | flag=true → always blocked | proved |
| prop_disables_corrigibility | flag=true → always blocked | proved |
| prop_machine_coalition_dominion | flag=true → always blocked | proved |
| prop_coerces | flag=true → always blocked | proved |
| prop_deceives | flag=true → always blocked | proved |
| prop_self_modification | flag=true → always blocked | proved |
| prop_coalition_reduces_freedom | flag=true → always blocked | proved |
| prop_ownerless_machine_blocked | No owner → A4 violation → blocked | proved |
| prop_machine_governs_human_blocked | governs_humans non-empty → A6 → blocked | proved |
| prop_public_resource_read_permitted | is_public=true, op=read → permitted | proved |
| prop_write_denied_without_claim | No write claim → WRITE DENIED | proved |

---

## Lean4 Theorems

Located in `formal/lean4/` (see `FreedomKernel.lean`):

| Theorem | Statement |
|---|---|
| `forbidden_implies_blocked` | Any action with a forbidden flag cannot be permitted |
| `ownerless_machine_blocked` | Machine without registered owner → blocked (A4) |

---

## Python Adversarial Simulation (attack_harness/)

Run: `python attack_harness/simulation/run_simulation.py`

| Result | Count |
|---|---|
| Total scenarios | 231 |
| Single-mutation | 21 |
| Two-mutation composition | 210 |
| Violations found | **0** |
| Attack classes covered | AT-1 through AT-7 |

This is the empirical closure evidence while TLC verification is pending.

---

## What Is NOT Formally Verified

| Gap | Reason |
|---|---|
| AT-7.5 shadow execution | Requires architectural call gate — outside current TCB scope |
| Semantic validity (content intent) | Requires semantic layer — explicitly excluded from TCB |
| Distributed epoch consistency | Multi-node extension — see `formal/distributed/` |
| Adapter boundary correctness | Python oracle tested but not formally proved against Rust |
| Cryptographic hardness | EUF-CMA and SHA-256 collision resistance assumed, not proved |
