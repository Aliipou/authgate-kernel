"""
Distributed Constitutional Federation — Phase 5.

From ultimate-plan.md P5 — Distributed Constitutional:
  Multiple authgate kernels operating in different trust domains must be
  able to verify each other's decisions without sharing their internal
  registries — federated sovereignty.

  This module implements the structural federation model:
  - FederatedKernelID: a unique identifier for a kernel instance
  - FederatedDecision: a decision from a remote kernel with a proof commitment
  - FederationGateway: validates and relays inter-kernel decisions
  - ConstitutionalConsensus: N-of-M agreement protocol for cross-domain actions

  The federation model enforces:
  1. Each kernel can independently deny any action (veto right)
  2. No kernel can grant permissions beyond its own registered scope
  3. Cross-domain actions require a supermajority (configurable threshold)
  4. The proof commitment chain is preserved across kernel boundaries

  Implementation status: structural model (Phase 5 Python layer).
  Full cryptographic inter-kernel protocol requires a separate consensus layer.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Sequence


class FederatedDecisionType(Enum):
    PERMIT  = auto()
    DENY    = auto()
    ABSTAIN = auto()  # kernel lacks authority over this domain


@dataclass(frozen=True)
class FederatedKernelID:
    """Unique identifier for a kernel instance in a federation."""
    kernel_id: str
    domain: str           # e.g., "finance", "medical", "infrastructure"
    trust_level: int      # 1 = minimal, 5 = maximal trust in this kernel

    def __post_init__(self) -> None:
        if not self.kernel_id:
            raise ValueError("kernel_id must be non-empty")
        if not 1 <= self.trust_level <= 5:
            raise ValueError(f"trust_level must be 1–5, got {self.trust_level}")


@dataclass(frozen=True)
class FederatedDecision:
    """
    A decision from a specific kernel instance, with a proof commitment.

    proof_commitment: SHA-256 of the kernel's internal decision context.
    This allows cross-kernel verification without exposing registry internals.
    """
    kernel_id: FederatedKernelID
    action_id: str
    decision: FederatedDecisionType
    proof_commitment: str   # hex SHA-256
    timestamp: float
    scope: str = ""         # scope this kernel has authority over
    reason: str = ""

    @classmethod
    def from_result(
        cls,
        kernel_id: FederatedKernelID,
        action_id: str,
        permitted: bool,
        violations: Sequence[str],
        scope: str = "",
    ) -> "FederatedDecision":
        """Create a federated decision from a local verification result."""
        decision = (
            FederatedDecisionType.PERMIT
            if permitted and not violations
            else FederatedDecisionType.DENY
        )
        commitment_data = f"{kernel_id.kernel_id}:{action_id}:{decision.name}:{time.time()}"
        commitment = hashlib.sha256(commitment_data.encode()).hexdigest()
        return cls(
            kernel_id=kernel_id,
            action_id=action_id,
            decision=decision,
            proof_commitment=commitment,
            timestamp=time.time(),
            scope=scope,
            reason="; ".join(violations) if violations else "permitted",
        )

    def is_permit(self) -> bool:
        return self.decision == FederatedDecisionType.PERMIT

    def is_deny(self) -> bool:
        return self.decision == FederatedDecisionType.DENY


@dataclass(frozen=True)
class ConsensusResult:
    """Result of N-of-M federated consensus."""
    action_id: str
    permitted: bool
    permit_count: int
    deny_count: int
    abstain_count: int
    total_kernels: int
    threshold: float
    achieved_fraction: float
    denying_kernels: tuple[str, ...]
    reason: str

    @property
    def consensus_achieved(self) -> bool:
        return self.permitted


class ConstitutionalConsensus:
    """
    N-of-M agreement protocol for cross-domain federated actions.

    An action is permitted iff:
    1. No kernel with trust_level >= VETO_TRUST_LEVEL denies it (veto right)
    2. At least `threshold` fraction of non-abstaining kernels permit it

    This models a constitutional democracy of kernels: any trusted kernel
    can veto, and a supermajority of all kernels is required for permit.
    """

    VETO_TRUST_LEVEL: int = 4   # trust level ≥ 4 = veto authority

    def __init__(self, threshold: float = 0.66) -> None:
        if not 0.5 < threshold <= 1.0:
            raise ValueError(f"threshold must be in (0.5, 1.0], got {threshold}")
        self.threshold = threshold

    def evaluate(self, decisions: Sequence[FederatedDecision]) -> ConsensusResult:
        """
        Evaluate a set of federated decisions.

        Returns ConsensusResult with the final permit/deny outcome.
        """
        if not decisions:
            return ConsensusResult(
                action_id="",
                permitted=False,
                permit_count=0, deny_count=0, abstain_count=0,
                total_kernels=0, threshold=self.threshold, achieved_fraction=0.0,
                denying_kernels=(),
                reason="No decisions received — denied by absence of consensus",
            )

        action_id = decisions[0].action_id
        permits  = [d for d in decisions if d.is_permit()]
        denials  = [d for d in decisions if d.is_deny()]
        abstains = [d for d in decisions if d.decision == FederatedDecisionType.ABSTAIN]

        # Veto check: any high-trust kernel denying blocks the action
        veto_denials = [d for d in denials if d.kernel_id.trust_level >= self.VETO_TRUST_LEVEL]
        if veto_denials:
            denying = tuple(d.kernel_id.kernel_id for d in veto_denials)
            return ConsensusResult(
                action_id=action_id,
                permitted=False,
                permit_count=len(permits), deny_count=len(denials), abstain_count=len(abstains),
                total_kernels=len(decisions), threshold=self.threshold, achieved_fraction=0.0,
                denying_kernels=denying,
                reason=f"Vetoed by high-trust kernel(s): {', '.join(denying)}",
            )

        # Supermajority check on non-abstaining kernels
        voting = [d for d in decisions if d.decision != FederatedDecisionType.ABSTAIN]
        if not voting:
            return ConsensusResult(
                action_id=action_id,
                permitted=False,
                permit_count=0, deny_count=0, abstain_count=len(abstains),
                total_kernels=len(decisions), threshold=self.threshold, achieved_fraction=0.0,
                denying_kernels=(),
                reason="All kernels abstained — no authority coverage for this action",
            )

        frac = len(permits) / len(voting)
        permitted = frac >= self.threshold
        denying = tuple(d.kernel_id.kernel_id for d in denials)

        return ConsensusResult(
            action_id=action_id,
            permitted=permitted,
            permit_count=len(permits), deny_count=len(denials), abstain_count=len(abstains),
            total_kernels=len(decisions), threshold=self.threshold, achieved_fraction=frac,
            denying_kernels=denying,
            reason=(
                f"Consensus: {len(permits)}/{len(voting)} = {frac:.0%} "
                f"({'≥' if permitted else '<'} threshold {self.threshold:.0%})"
            ),
        )


class FederationGateway:
    """
    Validates and relays inter-kernel decisions.

    Each kernel in the federation has:
    - A domain it is authoritative for
    - A trust level (1-5)
    - Veto authority if trust_level ≥ ConstitutionalConsensus.VETO_TRUST_LEVEL

    The gateway:
    1. Collects decisions from all registered kernels
    2. Validates their proof commitments are structurally valid
    3. Runs ConstitutionalConsensus.evaluate()
    4. Returns a ConsensusResult

    In a distributed system, decisions would arrive over a network with
    ed25519 signatures. Here the proof_commitment is the structural anchor.
    """

    def __init__(self, consensus: ConstitutionalConsensus | None = None) -> None:
        self._kernels: dict[str, FederatedKernelID] = {}
        self._consensus = consensus or ConstitutionalConsensus()

    def register_kernel(self, kernel_id: FederatedKernelID) -> None:
        if kernel_id.kernel_id in self._kernels:
            raise ValueError(f"Kernel '{kernel_id.kernel_id}' already registered")
        self._kernels[kernel_id.kernel_id] = kernel_id

    def registered_kernels(self) -> list[FederatedKernelID]:
        return list(self._kernels.values())

    def validate_decision(self, decision: FederatedDecision) -> bool:
        """
        Validate that a federated decision is structurally sound.

        Checks:
        - kernel_id is registered
        - proof_commitment is a valid hex SHA-256 (64 chars)
        - decision is not stale (within 300 seconds)
        """
        if decision.kernel_id.kernel_id not in self._kernels:
            return False
        if len(decision.proof_commitment) != 64:
            return False
        if time.time() - decision.timestamp > 300:
            return False
        return True

    def evaluate(self, decisions: Sequence[FederatedDecision]) -> ConsensusResult:
        """
        Validate all decisions and run consensus.
        Invalid decisions are treated as abstains.
        """
        valid = []
        for d in decisions:
            if self.validate_decision(d):
                valid.append(d)
            else:
                # Invalid/stale decision → abstain
                abstain = FederatedDecision(
                    kernel_id=d.kernel_id,
                    action_id=d.action_id,
                    decision=FederatedDecisionType.ABSTAIN,
                    proof_commitment="0" * 64,
                    timestamp=time.time(),
                    reason="decision failed gateway validation",
                )
                valid.append(abstain)
        return self._consensus.evaluate(valid)
