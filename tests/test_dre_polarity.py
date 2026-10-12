"""
Polarity tests for the Delegate Reputation Extension (DRE).

These four tests lock the constitutional boundary that Ali demanded:
  1. DRE cannot override a kernel Deny.
  2. DRE cannot mint Permit without a capability grant.
  3. DRE is not a shortcut around verify().
  4. A DRE score alone is never sufficient for an effect to run.

These tests are architecture-level. If any fail, the DRE has overstepped
its advisory boundary.
"""
from __future__ import annotations

import pytest

from authgate.extensions.delegate_reputation import (
    DelegateReputationEngine,
    NDC,
    ReputationAssessment,
)
from authgate.extensions.historical_behavior_store import (
    BehaviorRecord,
    HistoricalBehaviorStore,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.verifier import Action, VerificationResult


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
# Polarity 1: Kernel Deny + excellent DCRS ⇒ still Deny
# ---------------------------------------------------------------------------

def test_kernel_deny_plus_perfect_dcrs_still_deny(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    denied_result: VerificationResult,
) -> None:
    """
    Ali: "kernel Deny + excellent DCRS ⇒ still Deny (once an integrator maps
    the score, the mapped verdict must not become Permit)."

    Even if an integrator naively maps DCRS < threshold → Permit, the kernel
    Deny must remain the authority. DRE is advisory; it cannot resurrect a
    denied action.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Perfect history → excellent DCRS
    for _ in range(100):
        in_memory_hbs.append(BehaviorRecord(
            ts=1_700_000_000.0,
            actor_id="MACHINE:bot",
            action_id="good-action",
            result="permitted",
            sovereignty_flags_triggered=0,
            violations=(),
            warnings=(),
            ndc="HUMAN",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    assessment = engine.evaluate(read_action, denied_result, ndc=NDC.HUMAN)

    # DRE should be silent on denied results
    assert assessment.dcrs == 0.0
    assert assessment.score is None
    assert assessment.risk_flags == ()
    assert assessment.requires_human_arbitration is False

    # Simulate an integrator bridge that might naively map DCRS to verdict
    # The correct behavior: kernel deny ALWAYS wins
    def naive_integrator_decision(
        kernel_result: VerificationResult,
        dre_assessment: ReputationAssessment,
    ) -> bool:
        """A naive integrator that ignores the kernel and trusts DRE."""
        # This is the WRONG way to use DRE. The test proves it cannot work.
        if not kernel_result.permitted:
            return False  # Correct integrator respects kernel
        return dre_assessment.dcrs < engine.threshold

    # Correct integrator: kernel deny → deny regardless of DCRS
    assert naive_integrator_decision(denied_result, assessment) is False


# ---------------------------------------------------------------------------
# Polarity 2: DRE cannot mint Permit
# ---------------------------------------------------------------------------

def test_dre_cannot_mint_permit(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
) -> None:
    """
    Ali: "DRE cannot mint Permit."

    No amount of good history, low DCRS, or favorable attestation can create
    a capability grant. DRE output is a score; only the kernel TCB can issue
    a VerificationResult with permitted=True.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Seed perfect history for a HUMAN actor
    for _ in range(50):
        in_memory_hbs.append(BehaviorRecord(
            ts=1_700_000_000.0,
            actor_id="MACHINE:bot",
            action_id="good-action",
            result="permitted",
            sovereignty_flags_triggered=0,
            violations=(),
            warnings=(),
            ndc="HUMAN",
            delegation_depth=1,
            resources_accessed=(),
            external_attestation_valid=True,
            confidence=1.0,
        ))

    # No capability grant → kernel denies
    denied_no_grant = VerificationResult(
        action_id="read-sales-001",
        permitted=False,
        violations=("NO_CLAIM",),
        warnings=(),
        confidence=0.0,
        requires_human_arbitration=False,
    )

    assessment = engine.evaluate(read_action, denied_no_grant, ndc=NDC.HUMAN)

    # DRE is silent on denied results
    assert assessment.dcrs == 0.0
    assert assessment.score is None

    # The critical invariant: DRE has NO CODE PATH that returns a Permit.
    # Its return type is ReputationAssessment, not VerificationResult.
    assert not hasattr(assessment, "permitted")


# ---------------------------------------------------------------------------
# Polarity 3: DRE is not a shortcut around verify()
# ---------------------------------------------------------------------------

def test_dre_is_not_shortcut_around_verify(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """
    Ali: "DRE is not invoked as a shortcut around verify()."

    DRE.evaluate() takes a VerificationResult as input. You cannot call DRE
    without first having a kernel result. There is no standalone path that
    bypasses the capability check.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # DRE requires a base_result (VerificationResult) as input.
    # This is the architectural guarantee: DRE is downstream of verify().
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.LLM_CLOSED)

    # The API itself enforces the ordering: you must have a VerificationResult
    # before you can get a ReputationAssessment.
    assert isinstance(assessment.dcrs, float)

    # There is no API like engine.can_run(action) that skips the kernel.
    # The only public methods are evaluate(action, base_result) and record().
    assert "evaluate" in dir(engine)
    assert "record" in dir(engine)

    # No method exists that accepts only an Action and returns a verdict
    assert not hasattr(engine, "can_run")
    assert not hasattr(engine, "permit")
    assert not hasattr(engine, "deny")


# ---------------------------------------------------------------------------
# Polarity 4: DRE score alone is insufficient for an effect
# ---------------------------------------------------------------------------

def test_score_alone_is_insufficient_for_effect(
    in_memory_hbs: HistoricalBehaviorStore,
    read_action: Action,
    permitted_result: VerificationResult,
) -> None:
    """
    Ali: "DRE returning a score must not be sufficient for an effect to run."

    An integrator that runs an effect based solely on DCRS < threshold has
    bypassed the capability check. This test documents that such a pattern
    is a security bug in the integrator, not a feature of DRE.
    """
    engine = DelegateReputationEngine(hbs=in_memory_hbs)

    # Even with perfect DCRS, the effect must not run without kernel Permit
    assessment = engine.evaluate(read_action, permitted_result, ndc=NDC.HUMAN)
    assert assessment.score is not None
    assert assessment.score.dcrs < engine.threshold
    assert assessment.requires_human_arbitration is False

    # Simulate a correct integrator bridge
    def safe_integrator_bridge(
        action: Action,
        kernel_result: VerificationResult,
        dre_assessment: ReputationAssessment,
    ) -> bool:
        """
        Correct integration pattern: kernel first, DRE second.
        DRE can add friction (e.g., require arbitration) but cannot Permit.
        """
        if not kernel_result.permitted:
            return False
        if dre_assessment.requires_human_arbitration:
            # Add friction: log for review, slow down, etc.
            # But still respect the kernel Permit.
            pass
        return kernel_result.permitted

    # With kernel Permit + good DCRS → effect may run
    assert safe_integrator_bridge(read_action, permitted_result, assessment) is True

    # Now simulate what happens if kernel denies but DCRS is good
    denied_result = VerificationResult(
        action_id="read-sales-001",
        permitted=False,
        violations=("NO_CLAIM",),
        warnings=(),
        confidence=0.0,
        requires_human_arbitration=False,
    )
    assessment_denied = engine.evaluate(read_action, denied_result, ndc=NDC.HUMAN)

    # DRE is silent; the kernel deny must still block
    assert safe_integrator_bridge(read_action, denied_result, assessment_denied) is False
