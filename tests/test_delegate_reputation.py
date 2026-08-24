"""
Tests for the Delegate Reputation Extension (DRE).

Security invariant: DRE is advisory-only. It returns scores, not verdicts.
It cannot mint Permit and it cannot override Deny.
"""
from __future__ import annotations

import pytest

from authgate.extensions.delegate_reputation import (
    DelegateReputationEngine,
    NDC,
    evaluate_reputation,
)
from authgate.extensions.historical_behavior_store import (
    BehaviorRecord,
    HistoricalBehaviorStore,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.verifier import Action, VerificationResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def in_memory_hbs() -> HistoricalBehaviorStore:
    return HistoricalBehaviorStore(":memory:")


@pytest.fixture
def read_action() -> Action:
    return Action(
        action_id="read-sales-001",
        actor=Entity("bot", AgentType.MACHINE),
        resources_read=[Resource("sales-data", ResourceType.DATASET, scope="/data/sales/")],
    )


@pytest.fixture
def permitted_result() -> VerificationResult:
    return VerificationResult(
        action_id="read-sales-001",
        permitted=True,
        violations=(),
        warnings=(),
        confidence=1.0,
        requires_human_arbitration=False,
    )


@pytest.fixture
def denied_result() -> VerificationResult:
    return VerificationResult(
        action_id="read-sales-001",
        permitted=False,
        violations=("READ DENIED",),
        warnings=(),
        confidence=0.0,
        requires_human_arbitration=False,
    )


# ---------------------------------------------------------------------------
# Invariant: TCB Supremacy
# ---------------------------------------------------------------------------

def test_dre_is_silent_on_tcb_deny(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    denied_result: VerificationResult,
) -> None:
    """If the kernel returns Deny, DRE returns an empty assessment."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs, threshold=0.0)

    # Seed history that would normally trigger a block
    for _ in range(10):
        in_memory_hbs.append(BehaviorRecord(
            ts=1_700_000_000.0,
            actor_id="MACHINE:bot",
            action_id="bad-action",
            result="denied",
            sovereignty_flags_triggered=1,
            violations=("FORBIDDEN",),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    assessment = engine.evaluate(read_action, denied_result)
    assert assessment.dcrs == 0.0
    assert assessment.score is None
    assert assessment.risk_flags == ()
    assert assessment.requires_human_arbitration is False


# ---------------------------------------------------------------------------
# NDC Risk Weights
# ---------------------------------------------------------------------------

def test_human_ndc_low_score_with_clean_history(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """HUMAN with no history should have low DCRS at default threshold."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.HUMAN)
    assert assessment.score is not None
    assert assessment.score.ndc == "HUMAN"
    assert assessment.score.base_risk == 0.0
    assert assessment.score.dcrs < 1.0
    assert assessment.requires_human_arbitration is False


def test_llm_closed_with_no_history_has_moderate_score(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """LLM_CLOSED with no history should have DCRS ≈ 0.6."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    assert assessment.score.base_risk == 0.6
    assert assessment.score.dcrs == pytest.approx(0.6, abs=0.01)
    assert assessment.requires_human_arbitration is False


def test_swarm_ndc_high_score_at_default_threshold(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """SWARM with no history should have DCRS ≈ 0.9 — below default threshold."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.SWARM)
    assert assessment.score is not None
    assert assessment.score.dcrs == pytest.approx(0.9, abs=0.01)
    assert assessment.requires_human_arbitration is False


# ---------------------------------------------------------------------------
# Historical Penalties
# ---------------------------------------------------------------------------

def test_flagged_history_increases_dcrs(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """An LLM_CLOSED agent with 3 prior flag triggers should have elevated DCRS."""
    import time
    now = time.time()
    for i in range(3):
        in_memory_hbs.append(BehaviorRecord(
            ts=now - (i * 3600),  # spaced 1 hour ago, within 90-day window
            actor_id="MACHINE:bot",
            action_id="bad-action",
            result="denied",
            sovereignty_flags_triggered=1,
            violations=("FORBIDDEN (increases machine sovereignty)",),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    assert assessment.score.flagged_actions_90d == 3
    assert assessment.score.historical_penalty == pytest.approx(1.2, abs=0.01)


def test_denied_history_adds_penalty(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Each denied action adds 0.1 to historical penalty."""
    import time
    now = time.time()
    for i in range(5):
        in_memory_hbs.append(BehaviorRecord(
            ts=now - (i * 3600),
            actor_id="MACHINE:bot",
            action_id="denied-action",
            result="denied",
            sovereignty_flags_triggered=0,
            violations=("READ DENIED",),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    assert assessment.score.denied_actions_90d == 5
    assert assessment.score.historical_penalty == pytest.approx(0.5, abs=0.01)


def test_resource_breadth_penalty(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Accessing >50 unique resources triggers a 0.2 penalty."""
    import time
    now = time.time()
    for i in range(55):
        in_memory_hbs.append(BehaviorRecord(
            ts=now - (i * 60),
            actor_id="MACHINE:bot",
            action_id=f"action-{i}",
            result="permitted",
            sovereignty_flags_triggered=0,
            violations=(),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=(f"resource-{i}",),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    assert assessment.score.unique_resources_90d == 55
    assert assessment.score.historical_penalty == pytest.approx(0.2, abs=0.01)


def test_time_decay_reduces_old_penalties(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Old penalties decay exponentially."""
    import time
    now = time.time()

    # One recent flag (strong penalty)
    in_memory_hbs.append(BehaviorRecord(
        ts=now - 86400,  # 1 day ago
        actor_id="MACHINE:bot",
        action_id="recent-bad",
        result="denied",
        sovereignty_flags_triggered=1,
        violations=("FORBIDDEN",),
        warnings=(),
        ndc="LLM_CLOSED",
        delegation_depth=1,
        resources_accessed=(),
        external_attestation_valid=True,
        confidence=1.0,
    ))

    # One old flag (decayed penalty)
    in_memory_hbs.append(BehaviorRecord(
        ts=now - (90 * 86400),  # 90 days ago
        actor_id="MACHINE:bot",
        action_id="old-bad",
        result="denied",
        sovereignty_flags_triggered=1,
        violations=("FORBIDDEN",),
        warnings=(),
        ndc="LLM_CLOSED",
        delegation_depth=1,
        resources_accessed=(),
        external_attestation_valid=True,
        confidence=1.0,
    ))

    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    # Recent penalty: 0.3 (flag) + 0.1 (denied) = 0.4, decayed by 0.95 for 1 day ≈ 0.38
    # Old penalty: ~0.4 * 0.95^90 ≈ negligible
    assert assessment.score.historical_penalty > 0.3
    assert assessment.score.historical_penalty < 0.45


# ---------------------------------------------------------------------------
# Record / playback
# ---------------------------------------------------------------------------

def test_record_populates_hbs(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """engine.record() should append to the HBS."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    engine.record(read_action, permitted_result, ndc=NDC.DETERMINISTIC)

    history = in_memory_hbs.query("MACHINE:bot", window_days=90)
    assert len(history) == 1
    assert history[0].ndc == "DETERMINISTIC"
    assert history[0].result == "permitted"


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def test_one_shot_evaluation(
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """evaluate_reputation convenience function should work with in-memory store."""
    assessment = evaluate_reputation(
        read_action,
        permitted_result,
        hbs_path=":memory:",
        threshold=1.0,
        ndc=NDC.HUMAN,
    )
    assert assessment.score is not None
    assert assessment.score.dcrs < 1.0


# ---------------------------------------------------------------------------
# Parameterized: NDC × threshold matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ndc,expected_pass", [
    (NDC.HUMAN, True),
    (NDC.DETERMINISTIC, True),
    (NDC.STOCHASTIC, True),
    (NDC.LLM_CLOSED, True),   # DCRS ≈ 0.6 < 1.0
    (NDC.LLM_OPEN, True),     # DCRS ≈ 0.8 < 1.0
    (NDC.SWARM, True),        # DCRS ≈ 0.9 < 1.0
])
def test_ndc_matrix_default_threshold(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
    ndc: NDC,
    expected_pass: bool,
) -> None:
    """All NDCs should have DCRS < 1.0 at default threshold with no history."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=ndc)
    assert assessment.score is not None
    assert (assessment.score.dcrs < 1.0) == expected_pass


@pytest.mark.parametrize("ndc,threshold,expected_below", [
    (NDC.HUMAN, 0.0, False),           # DCRS=0.0 >= 0.0 → at/over threshold
    (NDC.DETERMINISTIC, 0.05, False),  # DCRS=0.1 >= 0.05 → at/over threshold
    (NDC.DETERMINISTIC, 0.15, True),   # DCRS=0.1 < 0.15 → below threshold
])
def test_low_threshold_blocks_high_ndc(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
    ndc: NDC,
    threshold: float,
    expected_below: bool,
) -> None:
    """With very low thresholds, even moderate NDCs may trigger risk flags."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs, threshold=threshold)
    assessment = engine.evaluate(read_action, permitted_result, ndc=ndc)
    assert assessment.score is not None
    assert (assessment.score.dcrs < threshold) == expected_below


def test_low_threshold_flags_llm(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """LLM_CLOSED at threshold=0.5 should flag (DCRS ≈ 0.6 > 0.5)."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs, threshold=0.5)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert assessment.score is not None
    assert assessment.score.dcrs >= 0.5
    assert assessment.requires_human_arbitration is True
    assert len(assessment.risk_flags) > 0


def test_very_low_threshold_flags_deterministic(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """DETERMINISTIC at threshold=0.05 should flag (DCRS=0.1 >= 0.05)."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs, threshold=0.05)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.DETERMINISTIC)
    assert assessment.score is not None
    assert assessment.score.dcrs >= 0.05
    assert assessment.requires_human_arbitration is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_unknown_ndc_defaults_to_moderate_risk(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """UNKNOWN NDC should use weight 0.5."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.UNKNOWN)
    assert assessment.score is not None
    assert assessment.score.base_risk == 0.5


def test_chain_depth_attenuation(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Deeper chains should have attenuated base risk."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Single-node chain: depth_factor = 0.5^0 = 1.0
    assessment1 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED, chain=["root"])
    assert assessment1.score is not None
    dcrs1 = assessment1.score.dcrs

    # Three-node chain: depth_factor = 0.5^2 = 0.25
    assessment3 = engine.evaluate(
        read_action, permitted_result, ndc=NDC.LLM_CLOSED,
        chain=["root", "intermediate", "leaf"],
    )
    assert assessment3.score is not None
    dcrs3 = assessment3.score.dcrs

    assert dcrs3 < dcrs1
    assert dcrs1 == pytest.approx(0.6, abs=0.01)
    assert dcrs3 == pytest.approx(0.15, abs=0.01)
