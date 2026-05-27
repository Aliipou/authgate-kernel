# Formal Verification Coverage

## TLA+ Model Checking

Run: `tlc FreedomKernel.tla -config FreedomKernel.cfg -workers auto`

| Property                | Status       | State Space                        |
|-------------------------|--------------|------------------------------------|
| A4 (ownership)          | ✓ verified   | MaxEntities=5, exhaustive          |
| A6 (no machine governs) | ✓ verified   | MaxEntities=5, exhaustive          |
| A7 (delegation)         | ✓ verified   | MaxResources=10, exhaustive        |
| Forbidden flags block   | ✓ verified   | All 10 flags, exhaustive           |
| IFC non-interference    | ✓ verified   | 3-label lattice, exhaustive        |
| TOCTOU safety           | ✓ verified   | bounded depth=3                    |

Constants used (exhaustive within these bounds):
```
MaxEntities  = 5
MaxResources = 10
MaxDepth     = 3
```

## Kani Model Checking

Run: `cargo kani --harness <name>` from `authgate-kernel/`

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

## Lean 4 Theorems

Located in `formal/lean/` (see `FreedomKernel.lean`):

| Theorem                      | Statement                                                         |
|------------------------------|-------------------------------------------------------------------|
| `forbidden_implies_blocked`  | Any action with a forbidden flag cannot be permitted              |
| `ownerless_machine_blocked`  | A machine without a registered owner is always blocked (A4)       |

## What Is NOT Formally Verified

- Manipulation detection scores (probabilistic, not formally proved)
- Confidence weighting (design intent, not invariant)
- Audit log chain integrity (tested, not model-checked)
- Fuzzing coverage (continuous, not exhaustive)
