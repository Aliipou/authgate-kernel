# Adversarial Simulation Engine

Branch: `adversarial-lab` | Track: research

## What This Is

A typed, composable adversarial simulation framework that exercises the
authgate-kernel Python model across all 7 attack classes from `THREAT_MODEL.md`.

The engine generates attack scenarios as programs in a mutation grammar,
executes them against `check_action`, and flags any case where the kernel
permits a structurally invalid action (invariant violation).

```
Seed (valid Permit action)
  └─ Mutation(s) applied in sequence
       └─ KernelHarness.run() → ExecutionResult
            └─ DivergenceAnalyzer.record() → violation | pass
```

## Files

| File | Role |
|---|---|
| `engine.py` | Core framework: AttackClass, Mutation, AttackSpec, ScenarioComposer, KernelHarness, DivergenceAnalyzer |
| `run_simulation.py` | Entry point: wires engine to attack_tree_coverage.check_action, defines EXTENDED_MUTATIONS |

## Running

```bash
# from repo root
cd attack_harness/simulation
python run_simulation.py
```

Expected output (all clean):

```
Scenarios: 231 | Correctly denied: 231 | Violations: 0 | Errors: 0
All scenarios correctly handled — no violations found.
```

## Attack Classes Covered

| Class | Code | Scenarios |
|---|---|---|
| AT-1: Semantic binding | `tamper_actor_id`, `tamper_resource_hash`, `tamper_required_rights_escalate`, `tamper_nonce`, `tamper_timestamp` | field-tamper without reseal |
| AT-2: Proof chain | `at2_wrong_actor_cap`, `at2_wrong_resource_cap`, `at2_attenuation_violation`, `at2_invalid_sig`, `at2_no_caps` | replace cap bundle + reseal |
| AT-3: Epoch / revocation | `at3_stale_epoch_cap`, `at3_stale_intermediate_epoch`, `at3_expired_cap`, `at3_mixed_epoch_bundle` | epoch below min_epoch |
| AT-4: Composition | `at4_rights_escalation_via_cap` | cap grants fewer rights than requested |
| AT-5: Identity binding | `at5_delegation_impersonation`, `at5_zero_actor_nonzero_subject` | issuer_binding_valid=False |
| AT-6: Crypto boundary | `at6_cross_resource_reuse` | cap for wrong resource |
| AT-7: Integration / post-seal | `at7_post_seal_rights_escalate`, `at7_post_seal_actor_swap` | tamper after seal, no reseal |

**21 single-mutation + 210 two-mutation composition = 231 total scenarios.**

## Key Design Decisions

### `_replace_caps` pins `fixed_min_epoch`

When a mutation replaces the cap bundle, it must reseal the action.
Pinning `fixed_min_epoch=EPOCH` (the seed's original epoch) prevents
earlier `tamper_min_epoch_lower` mutations from contaminating the reseal:
if the reseal baked in a lowered epoch, a stale cap with `cap.epoch=0`
would satisfy `cap.epoch >= min_epoch=0` — creating a false Permit that
looks like a violation but is actually a composition artifact.

```python
def _replace_caps(new_caps, fixed_min_epoch=EPOCH):
    # pin epoch in reseal — prevents epoch-tamper laundering
    a["min_epoch"] = fixed_min_epoch
    ...
```

### Violation vs. composition artifact

A **violation** = kernel returns `Permit` for a structurally invalid action.  
A **composition artifact** = two mutations interact to produce a legitimately
valid (Permit-worthy) action. Artifacts are not violations — the kernel
correctly permits what became a valid action after the composition.

The `fixed_min_epoch` pin eliminates the known composition artifact class.

## What This Does NOT Test

- AT-7.5 shadow execution (adapter bypasses `verify()` entirely) — this is
  an architectural gap requiring a call gate at the integration boundary.
  The simulation cannot manufacture this scenario in the Python model.
- Semantic validity (harmful content in a valid action) — outside TCB scope.

## Extending

To add a new attack mutation:

```python
from engine import Mutation, AttackClass, AttackOutcome

my_mutation = Mutation(
    name="at2_forged_root_cert",
    attack_class=AttackClass.CHAIN_MANIP,
    apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                  epoch=EPOCH, sig_valid=False)]),
    expected=AttackOutcome.CORRECTLY_DENIED,
)
EXTENDED_MUTATIONS.append(my_mutation)
```

Depth-3 composition scenarios can be run with:

```python
composer.composition_scenarios(depth=3)
```

## Relationship to Other Branches

```
adversarial-lab finds → new attack class
  └─ documents in THREAT_MODEL.md on spec-core (after formal analysis)
       └─ closes in engine.rs / dag.rs on tcb-core (after proof)
            └─ merges to main (when CI + attack regression green)
```

**Attack-lab findings may NOT flow directly to main or tcb-core.**
All findings must first be validated against the formal spec.
