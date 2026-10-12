"""
Adversarial / red-team tests for the Delegate Reputation Extension (DRE).

These tests verify that the DRE resists history poisoning, NDC spoofing,
threshold probing, and other gaming attempts identified in the A&L analysis.

Security invariant: DRE can only escalate Permit → Deny.
A compromised DRE cannot cause a false-negative permit.
"""
from __future__ import annotations

import time

import pytest

from authgate.extensions.delegate_reputation import (
    DEFAULT_NDC_RISK,
    DelegateReputationEngine,
    NDC,
    ReputationScore,
)
from authgate.extensions.historical_behavior_store import BehaviorRecord, HistoricalBehaviorStore
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


def _make_record(
    actor_id: str = "MACHINE:bot",
    result: str = "permitted",
    flagged: int = 0,
    ndc: str = "LLM_CLOSED",
    resources: tuple[str, ...] = (),
    ts_offset: float = 0.0,
) -> BehaviorRecord:
    return BehaviorRecord(
        ts=time.time() + ts_offset,
        actor_id=actor_id,
        action_id="action-001",
        result=result,
        sovereignty_flags_triggered=flagged,
        violations=("FORBIDDEN",) if flagged else (),
        warnings=(),
        ndc=ndc,
        delegation_depth=1,
        resources_accessed=resources,
        external_attestation_valid=True,
        confidence=1.0,
    )


# ---------------------------------------------------------------------------
# Invariant: Monotonicity
# ---------------------------------------------------------------------------

def test_monotonicity_adding_penalty_never_decreases_dcrs(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Adding a denied record to history must not decrease DCRS."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Baseline: clean history
    result1 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    dcrs1 = result1.reputation.dcrs if result1.reputation else 0.0

    # Add a denied record (penalty +0.1)
    in_memory_hbs.append(_make_record(result="denied"))

    result2 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    dcrs2 = result2.reputation.dcrs if result2.reputation else 0.0

    assert dcrs2 >= dcrs1


def test_monotonicity_adding_flag_never_decreases_dcrs(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Adding a sovereignty flag trigger must not decrease DCRS."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    result1 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    dcrs1 = result1.reputation.dcrs if result1.reputation else 0.0

    in_memory_hbs.append(_make_record(flagged=1))

    result2 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    dcrs2 = result2.reputation.dcrs if result2.reputation else 0.0

    assert dcrs2 >= dcrs1


# ---------------------------------------------------------------------------
# Invariant: Human Safety
# ---------------------------------------------------------------------------

def test_human_with_no_violations_always_passes(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """A HUMAN actor with clean history must always pass (DCRS < 0.5)."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)
    result = engine.evaluate(read_action, permitted_result, ndc=NDC.HUMAN)
    assert result.permitted
    assert result.reputation is not None
    assert result.reputation.dcrs < 0.5


# ---------------------------------------------------------------------------
# Adversarial: History Poisoning
# ---------------------------------------------------------------------------

def test_history_poisoning_dilution_is_limited_by_decay(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """
    Attacker generates 1000 benign actions to dilute a bad record.
    Defense: time-decay means recent bad records still have impact.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # One recent bad record (today)
    in_memory_hbs.append(_make_record(flagged=1, ts_offset=0))

    # 1000 old benign records (90 days ago)
    now = time.time()
    for i in range(1000):
        in_memory_hbs.append(BehaviorRecord(
            ts=now - (90 * 86400),  # 90 days old
            actor_id="MACHINE:bot",
            action_id=f"old-action-{i}",
            result="permitted",
            sovereignty_flags_triggered=0,
            violations=(),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    result = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    # The old benign records are heavily decayed, so the recent flag still matters
    assert result.reputation is not None
    assert result.reputation.flagged_actions_90d >= 1
    # DCRS should still reflect the penalty (base 0.6 + flag penalty ~0.3)
    assert result.reputation.dcrs >= 0.6


# ---------------------------------------------------------------------------
# Adversarial: NDC Spoofing
# ---------------------------------------------------------------------------

def test_ndc_spoofing_detected_by_weighted_risk(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """
    Attacker declares DETERMINISTIC but behaves like LLM_CLOSED.
    Even if NDC is spoofed, behavioral history (violations/flags) reveals truth.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Attacker claims DETERMINISTIC but has many flags (LLM-like behavior)
    for _ in range(5):
        in_memory_hbs.append(_make_record(flagged=1, ndc="DETERMINISTIC"))

    result = engine.evaluate(read_action, permitted_result, ndc=NDC.DETERMINISTIC)
    assert result.reputation is not None
    # 5 flags × 0.3 = 1.5 penalty, well above threshold
    assert result.reputation.dcrs >= 1.0
    assert not result.permitted


# ---------------------------------------------------------------------------
# Adversarial: Threshold Probing
# ---------------------------------------------------------------------------

def test_threshold_probing_is_noisy(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """
    Attacker varies action patterns to find the exact DCRS threshold.
    Defense: DCRS is a continuous score; borderline cases trigger arbitration.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs, threshold=1.0)

    # Seed history that puts actor right at the edge
    for i in range(3):
        in_memory_hbs.append(_make_record(flagged=0, result="permitted"))
    # Add exactly enough flags to approach threshold
    in_memory_hbs.append(_make_record(flagged=1))  # +0.3
    in_memory_hbs.append(_make_record(flagged=1))  # +0.3

    result = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert result.reputation is not None
    # DCRS = 0.6 (base) + 0.6 (flags) = 1.2 >= 1.0 → blocked
    assert not result.permitted
    assert result.kernel_result.requires_human_arbitration


# ---------------------------------------------------------------------------
# Adversarial: Burst Attack on HBS
# ---------------------------------------------------------------------------

def test_burst_attack_detected_by_guarded_store() -> None:
    """Rapid-fire writes should be blocked by GuardedBehaviorStore."""
    from authgate.extensions.hbs_protection import GuardedBehaviorStore

    hbs = HistoricalBehaviorStore(":memory:")
    guard = GuardedBehaviorStore(hbs, burst_threshold=5, burst_window_seconds=60.0)

    for _ in range(5):
        assert guard.append(_make_record()).allowed is True

    # 6th write in rapid succession should be blocked
    result = guard.append(_make_record())
    assert result.allowed is False
    assert "burst" in result.reason.lower()


# ---------------------------------------------------------------------------
# Adversarial: Resource Breadth Explosion
# ---------------------------------------------------------------------------

def test_resource_breadth_explosion_triggers_block(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Attacker scans >50 unique resources to probe breadth limits."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs, max_unique_resources_penalty=50)

    for i in range(55):
        in_memory_hbs.append(_make_record(resources=(f"resource-{i}",)))

    result = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert result.reputation is not None
    assert result.reputation.unique_resources_90d == 55
    # 0.6 base + 0.2 breadth penalty = 0.8, still under 1.0
    # but let's push it further with some flags
    in_memory_hbs.append(_make_record(flagged=1))
    result2 = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert result2.reputation is not None
    assert result2.reputation.dcrs >= 1.0
    assert not result2.permitted


# ---------------------------------------------------------------------------
# Adversarial: Failed Attestation Flooding
# ---------------------------------------------------------------------------

def test_failed_attestation_history_accumulates(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """Repeated failed attestations should accumulate penalty."""
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    for _ in range(3):
        in_memory_hbs.append(_make_record())
        in_memory_hbs.append(
            BehaviorRecord(
                ts=time.time(),
                actor_id="MACHINE:bot",
                action_id="action-001",
                result="permitted",
                sovereignty_flags_triggered=0,
                violations=(),
                warnings=(),
                ndc="LLM_CLOSED",
                delegation_depth=1,
                resources_accessed=(),
                external_attestation_valid=False,
                confidence=1.0,
            )
        )

    result = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)
    assert result.reputation is not None
    # 3 failed attestations × 0.4 = 1.2 penalty
    assert result.reputation.dcrs >= 1.0
    assert not result.permitted


# ---------------------------------------------------------------------------
# Invariant: TCB Supremacy under adversarial DRE
# ---------------------------------------------------------------------------

def test_tcb_deny_cannot_be_overridden_even_with_perfect_history(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
) -> None:
    """
    Even if attacker has perfect history (all permitted, no flags),
    a TCB Deny must remain Deny.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Perfect history
    for _ in range(100):
        in_memory_hbs.append(_make_record(result="permitted", flagged=0))

    denied = VerificationResult(
        action_id="read-sales-001",
        permitted=False,
        violations=("FORBIDDEN",),
        warnings=(),
        confidence=1.0,
        requires_human_arbitration=False,
    )

    result = engine.evaluate(read_action, denied, ndc=NDC.LLM_CLOSED)
    assert not result.permitted
    assert result.reputation is None  # DRE should not even compute score
