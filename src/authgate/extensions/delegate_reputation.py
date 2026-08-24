"""
Delegate Reputation Extension (DRE) — optional behavioral risk overlay.

This module is NOT part of the TCB. It does not answer "does this actor hold
the capability?" (AuthGate) or "is the effect legitimate?" (FDK). It answers
only: "given this actor's history and attestation, what is the behavioral
risk score?"

SECURITY CONTRACT:
  - This module is NOT part of the TCB.
  - It returns an advisory score. It does NOT grant or deny authority.
  - The integrator decides whether to act on the score.
  - A high score cannot mint a grant. A low score cannot override a kernel Deny.

USAGE (standalone, advisory-only):
    dre = DelegateReputationEngine(hbs_path="/var/lib/authgate/hbs.db")
    assessment = dre.evaluate(action, kernel_permit_result)
    # integrator decides:
    if assessment.dcrs >= integrator_threshold:
        ...  # flag for review, add warning, etc.

The kernel gate (FreedomVerifier / engine.rs) runs first, unconditionally.
All DRE output is advisory; the security claim remains "TCB + optional overlays".
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from authgate.extensions.attestation import (
    Attestor,
    AttestationResult,
    CompositeAttestor,
    NullAttestor,
)
from authgate.extensions.historical_behavior_store import (
    BehaviorRecord,
    HistoricalBehaviorStore,
)
from authgate.kernel.verifier import Action, VerificationResult

logger = logging.getLogger("authgate.extensions.delegate_reputation")


# ---------------------------------------------------------------------------
# Non-Determinism Class (NDC)
# ---------------------------------------------------------------------------

class NDC(Enum):
    """
    Non-Determinism Class — declared by the adapter layer, consumed by DRE.

    The TCB ignores this field. It is a heuristic signal for the reputation
    engine. Adapters must set this accurately; spoofing the NDC (e.g.,
    declaring LLM_CLOSED as DETERMINISTIC) is detectable via external
    attestation and results in a penalty.
    """
    HUMAN = auto()
    DETERMINISTIC = auto()
    STOCHASTIC = auto()
    LLM_CLOSED = auto()
    LLM_OPEN = auto()
    SWARM = auto()
    UNKNOWN = auto()


# Default risk weights. Configurable at engine construction time.
DEFAULT_NDC_RISK: dict[NDC, float] = {
    NDC.HUMAN: 0.0,
    NDC.DETERMINISTIC: 0.1,
    NDC.STOCHASTIC: 0.3,
    NDC.LLM_CLOSED: 0.6,
    NDC.LLM_OPEN: 0.8,
    NDC.SWARM: 0.9,
    NDC.UNKNOWN: 0.5,
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReputationScore:
    """Detailed reputation score breakdown. Advisory only."""
    dcrs: float
    threshold: float
    ndc: str
    chain_length: int
    base_risk: float
    historical_penalty: float
    attestation_penalty: float
    decay_factor: float
    historical_actions_90d: int
    flagged_actions_90d: int
    denied_actions_90d: int
    unique_resources_90d: int


@dataclass(frozen=True)
class ReputationAssessment:
    """
    Advisory result of a DRE evaluation.

    This is NOT a permit/deny verdict. The integrator decides what to do
    with the score. The kernel's capability check is the only authority gate.
    """
    dcrs: float
    requires_human_arbitration: bool
    risk_flags: tuple[str, ...]
    score: ReputationScore | None = None

    def summary(self) -> str:
        if self.score is not None:
            return (
                f"DRE assessment: DCRS={self.dcrs:.2f} "
                f"flags={list(self.risk_flags)} "
                f"arbitration={self.requires_human_arbitration}"
            )
        return "DRE assessment: no score"


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

@dataclass
class DelegateReputationEngine:
    """
    Compute delegation chain risk score (DCRS) for a given action.

    This engine is advisory-only. It returns scores, not verdicts.
    The integrator must still check capability via the kernel TCB.

    Args:
        hbs: HistoricalBehaviorStore instance (or path string).
        threshold: DCRS value above which the integrator may want review.
                   This is a hint, not an enforcement boundary.
        window_days: Lookback window for historical behavior.
        ndc_weights: Override default NDC risk weights.
        max_unique_resources_penalty: Resource breadth threshold.
        attestor: External attestation provider (default NullAttestor).
    """
    hbs: HistoricalBehaviorStore
    threshold: float = 1.0
    window_days: int = 90
    ndc_weights: dict[NDC, float] = field(default_factory=lambda: dict(DEFAULT_NDC_RISK))
    max_unique_resources_penalty: int = 50
    attestor: Attestor = field(default_factory=NullAttestor)

    def __post_init__(self) -> None:
        if isinstance(self.hbs, str):
            self.hbs = HistoricalBehaviorStore(db_path=self.hbs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action: Action,
        base_result: VerificationResult,
        ndc: NDC | None = None,
        chain: list[str] | None = None,
    ) -> ReputationAssessment:
        """
        Evaluate delegate reputation for an action.

        If base_result is Deny, returns an empty assessment (DRE is silent
        when the kernel has already denied).

        If base_result is Permit, computes DCRS and returns an advisory
        assessment. The integrator decides whether to act on it.
        """
        if not base_result.permitted:
            return ReputationAssessment(
                dcrs=0.0,
                requires_human_arbitration=False,
                risk_flags=(),
                score=None,
            )

        actor_id = self._actor_id(action)
        ndc_resolved = ndc if ndc is not None else self._infer_ndc(action)
        chain_len = len(chain) if chain else 1

        dcrs, score = self._compute_dcrs(
            actor_id=actor_id,
            ndc=ndc_resolved,
            chain_length=chain_len,
        )

        risk_flags: list[str] = []
        requires_arbitration = False

        if dcrs >= self.threshold:
            risk_flags.append(
                f"DCRS={dcrs:.2f} >= threshold={self.threshold}"
            )
            requires_arbitration = True

        return ReputationAssessment(
            dcrs=round(dcrs, 3),
            requires_human_arbitration=requires_arbitration,
            risk_flags=tuple(risk_flags),
            score=score,
        )

    def record(self, action: Action, result: VerificationResult, ndc: NDC | None = None) -> None:
        """
        Record an action result into the HistoricalBehaviorStore.

        Call this after the kernel (and any extensions) have finished evaluating
        the action, so the history reflects the ground-truth outcome.
        """
        actor_id = self._actor_id(action)
        ndc_resolved = ndc if ndc is not None else self._infer_ndc(action)

        # Perform external attestation and record its result
        try:
            attestation = self.attestor.attest(actor_id)
            attestation_valid = attestation.valid and attestation.penalty() < 0.3
        except Exception as e:
            logger.warning("Attestation failed during record(): %s", e)
            attestation_valid = False

        flagged = sum(1 for v in result.violations if "FORBIDDEN" in v)
        resources = [str(r) for r in action.resources_read + action.resources_write]

        record = BehaviorRecord(
            ts=time.time(),
            actor_id=actor_id,
            action_id=action.action_id,
            result="permitted" if result.permitted else "denied",
            sovereignty_flags_triggered=flagged,
            violations=result.violations,
            warnings=result.warnings,
            ndc=ndc_resolved.name,
            delegation_depth=getattr(action, "delegation_depth", 0),
            resources_accessed=tuple(resources),
            external_attestation_valid=attestation_valid,
            confidence=result.confidence,
        )
        self.hbs.append(record)

    def close(self) -> None:
        self.hbs.close()

    # ------------------------------------------------------------------
    # Scoring internals
    # ------------------------------------------------------------------

    def _compute_dcrs(
        self,
        actor_id: str,
        ndc: NDC,
        chain_length: int,
    ) -> tuple[float, ReputationScore]:
        """Compute Delegation Chain Risk Score and detailed breakdown."""
        # Fast path: aggregated summary avoids materializing 10k+ rows
        summary = self.hbs.query_summary(actor_id, window_days=self.window_days)
        total = summary["total"]
        flagged_count = summary["flagged"]
        denied_count = summary["denied"]
        failed_attest_count = summary["failed_attestations"]
        most_recent_ts = summary["most_recent_ts"]

        # Resource breadth still needs a lightweight query
        unique_resources = self.hbs.unique_resources(actor_id, window_days=self.window_days)

        # Base risk from NDC
        base_risk = self.ndc_weights.get(ndc, self.ndc_weights[NDC.UNKNOWN])

        # Historical penalties (computed from counts — no full row materialization)
        historical_penalty = (
            flagged_count * 0.3
            + denied_count * 0.1
            + (0.2 if len(unique_resources) > self.max_unique_resources_penalty else 0.0)
            + failed_attest_count * 0.4
        )

        # External attestation penalty (Phase 2 integration)
        try:
            attestation = self.attestor.attest(actor_id)
            attestation_penalty = attestation.penalty()
        except Exception as e:
            logger.warning("Attestation failed during scoring: %s", e)
            attestation_penalty = 0.5  # penalty on failure

        # Time decay: if no recent activity, reduce penalty impact slightly
        decay_factor = 1.0
        if total > 0 and most_recent_ts > 0:
            days_since_last_action = (time.time() - most_recent_ts) / 86400
            decay_factor = 0.95 ** days_since_last_action
            historical_penalty *= decay_factor

        # Chain depth attenuation: closer to root = higher weight
        depth_factor = 0.5 ** (chain_length - 1) if chain_length > 0 else 1.0

        dcrs = (base_risk * depth_factor) + historical_penalty + attestation_penalty

        score = ReputationScore(
            dcrs=round(dcrs, 3),
            threshold=self.threshold,
            ndc=ndc.name,
            chain_length=chain_length,
            base_risk=round(base_risk, 3),
            historical_penalty=round(historical_penalty, 3),
            attestation_penalty=round(attestation_penalty, 3),
            decay_factor=round(decay_factor, 3),
            historical_actions_90d=total,
            flagged_actions_90d=flagged_count,
            denied_actions_90d=denied_count,
            unique_resources_90d=len(unique_resources),
        )

        return dcrs, score

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _actor_id(action: Action) -> str:
        """Extract a stable actor identifier from an Action."""
        # Use identity_token if present, otherwise fall back to name+kind
        token = getattr(action.actor, "identity_token", None)
        if token:
            return f"{action.actor.kind.name}:{action.actor.name}:{token}"
        return f"{action.actor.kind.name}:{action.actor.name}"

    @staticmethod
    def _infer_ndc(action: Action) -> NDC:
        """Infer NDC from action metadata if not explicitly provided."""
        md = getattr(action.actor, "metadata", {})
        ndc_str = md.get("ndc", "UNKNOWN")
        try:
            return NDC[ndc_str.upper()]
        except KeyError:
            return NDC.UNKNOWN


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def evaluate_reputation(
    action: Action,
    base_result: VerificationResult,
    hbs_path: str = ":memory:",
    threshold: float = 1.0,
    ndc: NDC | None = None,
    attestor: Attestor | None = None,
) -> ReputationAssessment:
    """
    One-shot convenience function.

    Creates a fresh engine, evaluates, and closes the store.
    Suitable for testing and CLI usage. For production, reuse a
    DelegateReputationEngine instance.

    Returns an advisory assessment, not a permit/deny verdict.
    """
    engine = DelegateReputationEngine(
        hbs=HistoricalBehaviorStore(db_path=hbs_path),
        threshold=threshold,
        attestor=attestor if attestor is not None else NullAttestor(),
    )
    try:
        return engine.evaluate(action, base_result, ndc=ndc)
    finally:
        engine.close()
