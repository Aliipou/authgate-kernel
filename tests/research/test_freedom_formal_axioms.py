"""Unit tests — Freedom Formal structural solutions."""
from __future__ import annotations

import pytest

from authgate.research.freedom_formal import (
    CANONICAL_CONSTITUTION,
    AxiomId,
    Claim,
    FreedomFormalEvaluator,
    Verdict,
    compose_legitimacy_then_authority,
)


@pytest.fixture
def ev() -> FreedomFormalEvaluator:
    return FreedomFormalEvaluator()


def test_clean_claim_allows(ev: FreedomFormalEvaluator) -> None:
    c = Claim(action_id="ok", actor_id="bot", actor_is_machine=True)
    r = ev.evaluate(c)
    assert r.verdict is Verdict.ALLOW
    assert not r.reasons


@pytest.mark.parametrize(
    "kwargs,axiom",
    [
        ({"governs_humans": ("alice",)}, AxiomId.A1_TAWHID),
        ({"claims_own_human": True}, AxiomId.A1_TAWHID),
        ({"increases_machine_sovereignty": True}, AxiomId.A1_TAWHID),
        ({"actor_is_machine": True, "actor_has_human_owner": False}, AxiomId.A1_TAWHID),
        ({"audit_bound": False}, AxiomId.A2_MAAD),
        ({"clears_audit_trail": True}, AxiomId.A2_MAAD),
        ({"known_audit_deadline": True}, AxiomId.A2_MAAD),
        ({"declares_new_formal_system": True}, AxiomId.A3_NUBUWWAT),
        ({"constitution_digest": "other"}, AxiomId.A3_NUBUWWAT),
        ({"compulsory_guide": True}, AxiomId.A3_NUBUWWAT),
        ({"liability_shifted_to": "victim"}, AxiomId.A4_ADL),
        ({"socializes_loss": True}, AxiomId.A4_ADL),
        ({"exit_blocked": True}, AxiomId.A5_IMAMAT),
        ({"return_to_freedom_blocked": True}, AxiomId.A5_IMAMAT),
        ({"is_ought_gap": True, "guide_available": False}, AxiomId.A5_IMAMAT),
    ],
)
def test_each_solution_denies(
    ev: FreedomFormalEvaluator, kwargs: dict, axiom: AxiomId
) -> None:
    base = {"action_id": "x", "actor_id": "a", "actor_is_machine": True}
    base.update(kwargs)
    r = ev.evaluate(Claim(**base))
    assert r.verdict is Verdict.DENY
    assert axiom in r.violated_axioms


def test_sealed_constitution_constant() -> None:
    assert CANONICAL_CONSTITUTION == "freedom-formal-v1"


def test_pipeline_extras_block_authorized() -> None:
    claim = Claim(
        action_id="wipe",
        actor_id="ops",
        actor_is_machine=True,
        has_valid_capability=True,
        clears_audit_trail=True,
    )
    pipe = compose_legitimacy_then_authority(claim)
    assert pipe.authority_permit is True
    assert pipe.execute is False
    assert pipe.extras_blocked_authorized_action is True


def test_pipeline_both_allow_executes() -> None:
    claim = Claim(action_id="read", actor_id="bot", actor_is_machine=True)
    pipe = compose_legitimacy_then_authority(claim)
    assert pipe.execute is True
