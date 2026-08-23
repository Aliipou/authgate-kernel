"""
Delegate Reputation Extension (DRE) — heuristic extension for the
"reasonable delegate" problem identified by Abadi & Lampson (1993).

SECURITY CONTRACT:
  - This module is NOT part of the TCB.
  - It can only escalate Permit → Deny. It can never de-escalate Deny → Permit.
  - The TCB gate (FreedomVerifier / engine.rs) runs first, unconditionally.
  - All DRE decisions are advisory heuristics; the security claim remains
    "TCB + optional extensions".

USAGE (standalone):
    dre = DelegateReputationEngine(hbs_path="/var/lib/authgate/hbs.db")
    result = dre.evaluate(action, base_result)

USAGE (with ExtendedFreedomVerifier):
    ev = ExtendedFreedomVerifier(registry, ...)
    ev.add_reputation_engine(dre)
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
    """Detailed reputation score breakdown."""
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
    passed: bool


@dataclass(frozen=True)
class DelegateReputationResult:
    """Result of a DRE evaluation."""
    kernel_result: VerificationResult
    reputation: ReputationScore | None = None
    dre_violation: str | None = None

    @property
    def action_id(self) -> str: return self.kernel_result.action_id
    @property
    def permitted(self) -> bool: return self.kernel_result.permitted
    @property
    def violations(self) -> tuple: return self.kernel_result.violations
    @property
    def warnings(self) -> tuple: return self.kernel_result.warnings
    @property
    def confidence(self) -> float: return self.kernel_result.confidence

    def summary(self) -> str:
        base = self.kernel_result.summary()
        if self.reputation is not None:
            base += f" (DRE DCRS={self.reputation.dcrs:.2f})"
        if self.dre_violation:
            base += f" [DRE BLOCKED: {self.dre_violation}]"
        return base


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

@dataclass
class DelegateReputationEngine:
    """
    Compute delegation chain risk score (DCRS) for a given action.

    Args:
        hbs: HistoricalBehaviorStore instance (or path string).
        threshold: DCRS value above which Permit is escalated to Deny.
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
    ) -> DelegateReputationResult:
        """
        Evaluate delegate reputation for an action.

        If base_result is Deny, returns immediately (DRE does not override TCB).
        If base_result is Permit, computes DCRS and escalates if threshold exceeded.
        """
        if not base_result.permitted:
            return DelegateReputationResult(kernel_result=base_result)

        actor_id = self._actor_id(action)
        ndc_resolved = ndc if ndc is not None else self._infer_ndc(action)
        chain_len = len(chain) if chain else 1

        dcrs, score = self._compute_dcrs(
            actor_id=actor_id,
            ndc=ndc_resolved,
            chain_length=chain_len,
        )

        if dcrs >= self.threshold:
            dre_result = VerificationResult(
                action_id=base_result.action_id,
                permitted=False,
                violations=tuple(list(base_result.violations) + [
                    f"[DRE] Delegate reputation threshold exceeded (DCRS={dcrs:.2f})"
                ]),
                warnings=base_result.warnings,
                confidence=base_result.confidence,
                requires_human_arbitration=True,
            )
            return DelegateReputationResult(
                kernel_result=dre_result,
                reputation=score,
                dre_violation=f"DCRS={dcrs:.2f} >= threshold={self.threshold}",
            )

        return DelegateReputationResult(kernel_result=base_result, reputation=score)

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
            passed=dcrs < self.threshold,
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
# Convenience wrapper for ExtendedFreedomVerifier integration
# ---------------------------------------------------------------------------

def evaluate_reputation(
    action: Action,
    base_result: VerificationResult,
    hbs_path: str = ":memory:",
    threshold: float = 1.0,
    ndc: NDC | None = None,
    attestor: Attestor | None = None,
) -> DelegateReputationResult:
    """
    One-shot convenience function.

    Creates a fresh engine, evaluates, and closes the store.
    Suitable for testing and CLI usage. For production, reuse a
    DelegateReputationEngine instance.
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
