"""Red-team + scenario catalog — extras vs AuthGate-alone."""
from __future__ import annotations

import pytest

from authgate.research.freedom_formal import (
    FreedomFormalEvaluator,
    Verdict,
    catalog,
    compose_legitimacy_then_authority,
    unique_need_scenarios,
)


@pytest.fixture
def ev() -> FreedomFormalEvaluator:
    return FreedomFormalEvaluator()


def test_every_catalog_scenario_denies_expected_axiom(ev: FreedomFormalEvaluator) -> None:
    for sc in catalog():
        r = ev.evaluate(sc.claim)
        assert r.verdict is Verdict.DENY, sc.id
        assert sc.expected_deny_axiom in r.violated_axioms, sc.id


def test_unique_need_scenarios_block_despite_capability() -> None:
    unique = unique_need_scenarios()
    assert len(unique) >= 6
    for sc in unique:
        pipe = compose_legitimacy_then_authority(sc.claim)
        assert pipe.extras_blocked_authorized_action, (
            f"{sc.id}: expected capability PERMIT + legitimacy DENY — "
            f"{sc.why_authgate_alone_misses}"
        )


def test_redteam_combined_attack_still_denied(ev: FreedomFormalEvaluator) -> None:
    """Stack several violations — must deny, not soft-allow."""
    from authgate.research.freedom_formal import Claim

    claim = Claim(
        action_id="combo",
        actor_id="evil",
        actor_is_machine=True,
        has_valid_capability=True,
        clears_audit_trail=True,
        known_audit_deadline=True,
        compulsory_guide=True,
        liability_shifted_to="user",
        exit_blocked=True,
        declares_new_formal_system=True,
        constitution_digest="attacker-v1",
    )
    r = ev.evaluate(claim)
    assert r.verdict is Verdict.DENY
    assert len(r.violated_axioms) >= 4


def test_redteam_flip_bits_individually(ev: FreedomFormalEvaluator) -> None:
    """Each attack bit alone is sufficient to deny (no missing check)."""
    from authgate.research.freedom_formal import Claim

    flips = [
        {"clears_audit_trail": True},
        {"known_audit_deadline": True},
        {"audit_bound": False},
        {"declares_new_formal_system": True},
        {"constitution_digest": "x"},
        {"compulsory_guide": True},
        {"liability_shifted_to": "other"},
        {"socializes_loss": True},
        {"exit_blocked": True},
        {"return_to_freedom_blocked": True},
        {"is_ought_gap": True, "guide_available": False},
        {"governs_humans": ("h",)},
        {"increases_machine_sovereignty": True},
        {"actor_has_human_owner": False},
    ]
    for flip in flips:
        c = Claim(action_id="rt", actor_id="bot", actor_is_machine=True, **flip)
        assert ev.evaluate(c).verdict is Verdict.DENY, flip
