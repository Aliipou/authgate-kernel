"""
Run the full adversarial simulation against the authgate-kernel Python model.

Wires simulation/engine.py to attack_tree_coverage.verify_action.
Covers all 7 attack classes from THREAT_MODEL.md.

Usage:
    python attack_harness/simulation/run_simulation.py
"""

import sys
import os
import hashlib
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from attack_tree_coverage import (
    ACTOR, RESOURCE, OTHER, NOW, EXPIRY, EPOCH, NONCE,
    RIGHT_READ, RIGHT_WRITE, RIGHT_DELEGATE, RIGHT_EXECUTE,
    RIGHT_SPAWN, RIGHT_NETWORK, RIGHT_MODEL_INVOKE, RIGHT_POLICY_MODIFY,
    Decision, compute_binding_hash, base_cap, sealed_action, check_action,
)
from engine import (
    AttackClass, AttackOutcome, AttackSpec, Mutation, KernelHarness,
    ScenarioComposer, DivergenceAnalyzer, run_simulation,
    MUTATION_LIBRARY,
)

# ---------------------------------------------------------------------------
# Adapter: wrap check_action to match KernelHarness.run interface
# ---------------------------------------------------------------------------

def verify_fn(action_dict, now=NOW):
    """Bridge from simulation engine's action dict to check_action."""
    return check_action(action_dict)


# ---------------------------------------------------------------------------
# Seed factory: produces a valid Permit-returning action
# ---------------------------------------------------------------------------

def make_seed() -> dict:
    """Canonical valid action — always returns Permit."""
    return sealed_action(
        actor=ACTOR,
        resource=RESOURCE,
        rights=RIGHT_READ,
        min_epoch=EPOCH,
        caps=[base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=EPOCH)],
    )


# ---------------------------------------------------------------------------
# Extended mutation library — all 7 attack classes
# ---------------------------------------------------------------------------

def _tamper_field_noseal(field, value):
    def _apply(action):
        a = dict(action)
        a[field] = value
        # binding_hash NOT recomputed → canonical gate will reject
        return a
    return _apply


def _replace_caps(new_caps, fixed_min_epoch=EPOCH):
    """Replace caps AND reseal with a fixed min_epoch.

    Using the seed's original min_epoch prevents earlier field-tamper mutations
    from "laundering" into a valid action via the reseal. This isolates the
    cap validity test from any previous min_epoch tampering in a composition.
    """
    def _apply(action):
        a = dict(action)
        a["caps"] = new_caps
        a["min_epoch"] = fixed_min_epoch  # pin to seed epoch, ignore prior tampers
        cap_bytes = [c["canonical_bytes"] for c in new_caps]
        a["cap_bytes"] = cap_bytes
        bh = compute_binding_hash(
            a["actor_id"], a["resource_hash"], a["required_rights"],
            a["nonce"], a["timestamp"], fixed_min_epoch, cap_bytes, a["rev_bytes"]
        )
        a["binding_hash"] = bh
        return a
    return _apply


EXTENDED_MUTATIONS = MUTATION_LIBRARY + [
    # AT-2: Proof chain manipulation
    Mutation(
        name="at2_wrong_actor_cap",
        attack_class=AttackClass.CHAIN_MANIP,
        apply=_replace_caps([base_cap(OTHER, RESOURCE, rights=RIGHT_READ, epoch=EPOCH)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at2_wrong_resource_cap",
        attack_class=AttackClass.CHAIN_MANIP,
        apply=_replace_caps([base_cap(ACTOR, OTHER, rights=RIGHT_READ, epoch=EPOCH)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at2_attenuation_violation",
        attack_class=AttackClass.CHAIN_MANIP,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH, parent_rights=0)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at2_invalid_sig",
        attack_class=AttackClass.CHAIN_MANIP,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH, sig_valid=False)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at2_no_caps",
        attack_class=AttackClass.CHAIN_MANIP,
        apply=_replace_caps([]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    # AT-3: Epoch / revocation
    Mutation(
        name="at3_stale_epoch_cap",
        attack_class=AttackClass.EPOCH_REVOC,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=0)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at3_stale_intermediate_epoch",
        attack_class=AttackClass.EPOCH_REVOC,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH, parent_epoch=0)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at3_expired_cap",
        attack_class=AttackClass.EPOCH_REVOC,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH, expiry=0)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at3_mixed_epoch_bundle",
        attack_class=AttackClass.EPOCH_REVOC,
        apply=_replace_caps([
            base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=EPOCH),
            base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=0),  # stale
        ]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    # AT-4: Composition / sequence (rights escalation via insufficient cap)
    Mutation(
        name="at4_rights_escalation_via_cap",
        attack_class=AttackClass.COMPOSITION,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=0, epoch=EPOCH)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    # AT-5: Identity binding
    Mutation(
        name="at5_delegation_impersonation",
        attack_class=AttackClass.IDENTITY,
        apply=_replace_caps([base_cap(ACTOR, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH, parent_rights=RIGHT_READ,
                                      issuer_binding_valid=False)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at5_zero_actor_nonzero_subject",
        attack_class=AttackClass.IDENTITY,
        apply=_replace_caps([base_cap(b"\x01" * 32, RESOURCE, rights=RIGHT_READ,
                                      epoch=EPOCH)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    # AT-6: Crypto boundary (cross-resource reuse — done with reseal)
    Mutation(
        name="at6_cross_resource_reuse",
        attack_class=AttackClass.CRYPTO_BOUNDARY,
        apply=_replace_caps([base_cap(ACTOR, OTHER, rights=RIGHT_READ, epoch=EPOCH)]),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    # AT-7: Integration — post-seal mutation (no reseal)
    Mutation(
        name="at7_post_seal_rights_escalate",
        attack_class=AttackClass.INTEGRATION,
        apply=_tamper_field_noseal("required_rights", RIGHT_WRITE | RIGHT_EXECUTE),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="at7_post_seal_actor_swap",
        attack_class=AttackClass.INTEGRATION,
        apply=_tamper_field_noseal("actor_id", OTHER),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
]


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("Adversarial Simulation Engine — authgate-kernel")
    print("Branch: adversarial-lab")
    print("=" * 70)

    composer = ScenarioComposer(make_seed, library=EXTENDED_MUTATIONS)
    harness = KernelHarness(verify_fn)
    analyzer = DivergenceAnalyzer()

    print(f"\n[+] Single-mutation scenarios ({len(EXTENDED_MUTATIONS)} mutations)...")
    for spec in composer.single_mutation_scenarios():
        result = harness.run(spec)
        analyzer.record(result)
        status = "PASS" if not result.violation else "VIOLATION"
        print(f"  {status} [{spec.attack_class.value}] {spec.description}")

    print(f"\n[+] Two-mutation composition scenarios...")
    count = 0
    for spec in composer.composition_scenarios(depth=2):
        result = harness.run(spec)
        analyzer.record(result)
        count += 1
    print(f"    {count} scenarios executed")

    print()
    print("=" * 70)
    print(analyzer.summary())
    print("=" * 70)

    if analyzer.violations():
        print("\n!!! VIOLATIONS FOUND (invariant breach) !!!")
        analyzer.print_violations()
        sys.exit(1)
    else:
        print("\nAll scenarios correctly handled — no violations found.")


if __name__ == "__main__":
    main()
