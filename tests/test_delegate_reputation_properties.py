"""
Property-based tests for the Delegate Reputation Extension (DRE).

Uses Hypothesis to verify security invariants that should hold for ALL inputs.
"""
from __future__ import annotations

import time

from hypothesis import given, settings, strategies as st

from authgate.extensions.delegate_reputation import (
    DelegateReputationEngine,
    NDC,
)
from authgate.extensions.historical_behavior_store import (
    BehaviorRecord,
    HistoricalBehaviorStore,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.verifier import Action, VerificationResult


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

ndc_strategy = st.sampled_from(list(NDC))

action_strategy = st.builds(
    Action,
    action_id=st.text(
        min_size=1,
        max_size=32,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    ).map(lambda s: s or "a"),
    actor=st.builds(
        Entity,
        name=st.text(min_size=1, max_size=16).map(lambda s: s or "bot"),
        kind=st.just(AgentType.MACHINE),
    ),
    resources_read=st.lists(
        st.builds(
            Resource,
            name=st.text(min_size=1, max_size=16).map(lambda s: s or "r"),
            rtype=st.just(ResourceType.DATASET),
            scope=st.just("/data/"),
        ),
        min_size=0,
        max_size=3,
    ),
)

permitted_result_strategy = st.builds(
    VerificationResult,
    action_id=st.just("test-action"),
    permitted=st.just(True),
    violations=st.just(()),
    warnings=st.just(()),
    confidence=st.floats(min_value=0.0, max_value=1.0),
    requires_human_arbitration=st.just(False),
)

denied_result_strategy = st.builds(
    VerificationResult,
    action_id=st.just("test-action"),
    permitted=st.just(False),
    violations=st.tuples(st.just("DENIED")),
    warnings=st.just(()),
    confidence=st.just(0.0),
    requires_human_arbitration=st.just(False),
)


# ---------------------------------------------------------------------------
# Invariant 1: TCB Supremacy — DRE never overrides Deny → Permit
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(
    action=action_strategy,
    ndc=ndc_strategy,
    base_result=denied_result_strategy,
)
def test_pbt_tcb_supremacy(
    action: Action,
    ndc: NDC,
    base_result: VerificationResult,
) -> None:
    """For ANY action and ANY NDC, if kernel says Deny, DRE must say Deny."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs, threshold=0.0)  # most aggressive DRE
    result = engine.evaluate(action, base_result, ndc=ndc)
    assert not result.permitted
    assert result.reputation is None  # DRE should not compute score
    engine.close()


# ---------------------------------------------------------------------------
# Invariant 2: Monotonicity — adding bad history never decreases DCRS
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    action=action_strategy,
    ndc=ndc_strategy,
    base_result=permitted_result_strategy,
    bad_records=st.integers(min_value=0, max_value=10),
)
def test_pbt_monotonicity_with_bad_history(
    action: Action,
    ndc: NDC,
    base_result: VerificationResult,
    bad_records: int,
) -> None:
    """Adding flagged/denied records should never decrease the DCRS."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs)

    # Baseline DCRS with clean history
    result_clean = engine.evaluate(action, base_result, ndc=ndc)
    assert result_clean.reputation is not None
    dcrs_clean = result_clean.reputation.dcrs

    # Add bad records
    now = time.time()
    for i in range(bad_records):
        hbs.append(BehaviorRecord(
            ts=now - i,
            actor_id=engine._actor_id(action),
            action_id=f"bad-{i}",
            result="denied",
            sovereignty_flags_triggered=1,
            violations=("FORBIDDEN",),
            warnings=(),
            ndc=ndc.name,
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    result_bad = engine.evaluate(action, base_result, ndc=ndc)
    assert result_bad.reputation is not None
    dcrs_bad = result_bad.reputation.dcrs

    assert dcrs_bad >= dcrs_clean
    engine.close()


# ---------------------------------------------------------------------------
# Invariant 3: Decay Sanity — older identical penalties are less severe
# ---------------------------------------------------------------------------

@settings(max_examples=30, deadline=None)
@given(
    action=action_strategy,
    base_result=permitted_result_strategy,
)
def test_pbt_decay_sanity(
    action: Action,
    base_result: VerificationResult,
) -> None:
    """An old bad record should contribute less than a recent identical one."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs)
    actor_id = engine._actor_id(action)
    now = time.time()

    # One recent flag (1 day ago)
    hbs.append(BehaviorRecord(
        ts=now - 86400,
        actor_id=actor_id,
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
    result_recent = engine.evaluate(action, base_result, ndc=NDC.LLM_CLOSED)
    assert result_recent.reputation is not None
    dcrs_recent = result_recent.reputation.dcrs

    # Clear and add one old flag (60 days ago)
    hbs2 = HistoricalBehaviorStore(":memory:")
    engine2 = DelegateReputationEngine(hbs=hbs2)
    hbs2.append(BehaviorRecord(
        ts=now - (60 * 86400),
        actor_id=actor_id,
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
    result_old = engine2.evaluate(action, base_result, ndc=NDC.LLM_CLOSED)
    assert result_old.reputation is not None
    dcrs_old = result_old.reputation.dcrs

    # Recent should be at least as high as old (decay reduces old penalties)
    assert dcrs_recent >= dcrs_old
    engine.close()
    engine2.close()


# ---------------------------------------------------------------------------
# Invariant 4: Human Safety — HUMAN NDC with clean history passes at threshold >= 0
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    action=action_strategy,
    base_result=permitted_result_strategy,
    threshold=st.floats(min_value=0.01, max_value=2.0),
)
def test_pbt_human_safety(
    action: Action,
    base_result: VerificationResult,
    threshold: float,
) -> None:
    """HUMAN NDC with no bad history should always pass at reasonable thresholds."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs, threshold=threshold)
    result = engine.evaluate(action, base_result, ndc=NDC.HUMAN)
    assert result.permitted
    assert result.reputation is not None
    assert result.reputation.base_risk == 0.0
    assert result.reputation.dcrs < threshold
    engine.close()


# ---------------------------------------------------------------------------
# Invariant 5: Attestation penalty bounded in [0.0, 1.0]
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    action=action_strategy,
    ndc=ndc_strategy,
    base_result=permitted_result_strategy,
)
def test_pbt_attestation_penalty_bounded(
    action: Action,
    ndc: NDC,
    base_result: VerificationResult,
) -> None:
    """Attestation penalty must always be within [0.0, 1.0]."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs)
    result = engine.evaluate(action, base_result, ndc=ndc)
    assert result.reputation is not None
    penalty = result.reputation.attestation_penalty
    assert 0.0 <= penalty <= 1.0
    engine.close()


# ---------------------------------------------------------------------------
# Invariant 6: DCRS non-negativity
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    action=action_strategy,
    ndc=ndc_strategy,
    base_result=permitted_result_strategy,
    bad_records=st.integers(min_value=0, max_value=20),
)
def test_pbt_dcrs_non_negative(
    action: Action,
    ndc: NDC,
    base_result: VerificationResult,
    bad_records: int,
) -> None:
    """DCRS must never be negative, regardless of history."""
    hbs = HistoricalBehaviorStore(":memory:")
    engine = DelegateReputationEngine(hbs=hbs)

    now = time.time()
    for i in range(bad_records):
        hbs.append(BehaviorRecord(
            ts=now - i,
            actor_id=engine._actor_id(action),
            action_id=f"bad-{i}",
            result="denied",
            sovereignty_flags_triggered=1,
            violations=("FORBIDDEN",),
            warnings=(),
            ndc=ndc.name,
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=False,
            confidence=1.0,
        ))

    result = engine.evaluate(action, base_result, ndc=ndc)
    assert result.reputation is not None
    assert result.reputation.dcrs >= 0.0
    engine.close()


# ---------------------------------------------------------------------------
# Invariant 7: Threshold monotonicity — higher threshold → more permissive
# ---------------------------------------------------------------------------

@settings(max_examples=30, deadline=None)
@given(
    action=action_strategy,
    ndc=ndc_strategy,
    base_result=permitted_result_strategy,
    low_threshold=st.floats(min_value=0.0, max_value=0.5),
    high_threshold=st.floats(min_value=1.0, max_value=2.0),
)
def test_pbt_threshold_monotonicity(
    action: Action,
    ndc: NDC,
    base_result: VerificationResult,
    low_threshold: float,
    high_threshold: float,
) -> None:
    """A higher threshold should never be MORE restrictive than a lower one."""
    hbs = HistoricalBehaviorStore(":memory:")

    # Seed some history to make evaluation non-trivial
    now = time.time()
    for i in range(3):
        hbs.append(BehaviorRecord(
            ts=now - i,
            actor_id=f"MACHINE:{action.actor.name}",
            action_id=f"action-{i}",
            result="denied",
            sovereignty_flags_triggered=1,
            violations=("FORBIDDEN",),
            warnings=(),
            ndc=ndc.name,
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    engine_low = DelegateReputationEngine(hbs=hbs, threshold=low_threshold)
    engine_high = DelegateReputationEngine(hbs=hbs, threshold=high_threshold)

    result_low = engine_low.evaluate(action, base_result, ndc=ndc)
    result_high = engine_high.evaluate(action, base_result, ndc=ndc)

    # If strict (low) threshold permits, lenient (high) must also permit
    # (contra-positive: if high blocks, low MAY block or permit)
    if result_low.permitted:
        assert result_high.permitted


    engine_low.close()
    engine_high.close()
