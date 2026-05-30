"""
Freedom Theory Extensions — pluggable layer wrapping the kernel gate.

ExtendedFreedomVerifier = kernel.FreedomVerifier
    + manipulation detection (detection.py)
    + conflict queue       (resolver.py)
    + synthesis engine     (synthesis.py)

The API uses ExtendedFreedomVerifier.
The kernel FreedomVerifier is the formal gate; extensions add observability
and adversarial robustness on top.
"""
from __future__ import annotations

from collections.abc import Callable

from authgate.extensions.detection import detect
from authgate.extensions.ifc import IFCViolation, NonInterferenceChecker, SecurityLattice
from authgate.extensions.resolver import ConflictQueue
from authgate.extensions.synthesis import ProposedRule, SynthesisEngine
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


from dataclasses import dataclass


@dataclass(frozen=True)
class ExtendedVerificationResult:
    """
    Heuristic-augmented result. NEVER returned by the kernel.

    Wraps a kernel VerificationResult with heuristic signals like
    manipulation_score. Callers that need these signals use ExtendedFreedomVerifier;
    callers that need only structural enforcement use the kernel FreedomVerifier
    and get a clean VerificationResult.

    The kernel contract stays clean. The extension carries its own type.
    """
    kernel_result: VerificationResult
    manipulation_score: float = 0.0

    # Delegate the structural fields for convenience
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
    @property
    def requires_human_arbitration(self) -> bool:
        return self.kernel_result.requires_human_arbitration

    def summary(self) -> str:
        base = self.kernel_result.summary()
        if self.manipulation_score > 0:
            return f"{base} (manipulation={self.manipulation_score:.2f})"
        return base


class ExtendedFreedomVerifier:
    """
    Wraps FreedomVerifier (kernel gate) with heuristics:
      - Manipulation detection on action.argument
      - ConflictQueue for human-arbitration tracking
      - SynthesisEngine for constrained rule induction

    Returns ExtendedVerificationResult — a SUPERTYPE that carries the kernel
    result plus heuristic fields. The kernel's VerificationResult is never mutated.
    """

    def __init__(
        self,
        registry: OwnershipRegistry,
        conclusion_tester: Callable[[str], bool] | None = None,
        manipulation_threshold: float = 0.5,
        freeze: bool = True,
    ) -> None:
        self.registry = registry
        self._gate = FreedomVerifier(registry, freeze=freeze)
        self.synthesis = SynthesisEngine()
        self.conflict_queue = ConflictQueue()
        self._conclusion_tester = conclusion_tester
        self._manip_threshold = manipulation_threshold

    def verify(self, action: Action) -> ExtendedVerificationResult:
        manip_score = 0.0
        manip_warnings: list[str] = []

        if action.argument:
            dr = detect(
                action.argument,
                threshold=self._manip_threshold,
                conclusion_tester=self._conclusion_tester,
            )
            manip_score = dr.score
            if dr.suspicious:
                manip_warnings.append(
                    f"Manipulation detected (score={dr.score:.2f}): {dr.recommendation} "
                    f"Patterns: {list(dr.matched_patterns or dr.matched_keywords)}"
                )

        kernel_result = self._gate.verify(action)

        # If we have manipulation warnings, append them to the kernel result's warnings.
        # The kernel result itself is immutable; we construct a fresh one with augmented warnings.
        if manip_warnings:
            augmented = VerificationResult(
                action_id=kernel_result.action_id,
                permitted=kernel_result.permitted,
                violations=kernel_result.violations,
                warnings=tuple(list(kernel_result.warnings) + manip_warnings),
                confidence=kernel_result.confidence,
                requires_human_arbitration=kernel_result.requires_human_arbitration,
            )
        else:
            augmented = kernel_result

        return ExtendedVerificationResult(
            kernel_result=augmented,
            manipulation_score=round(manip_score, 3),
        )

    def admit_rule(self, rule: ProposedRule) -> tuple[bool, str]:
        return self.synthesis.admit_rule(rule)

    def register_induction_hook(self, hook: Callable) -> None:
        self.synthesis.add_induction_hook(hook)


__all__ = [
    "ExtendedFreedomVerifier",
    "ExtendedVerificationResult",
    "ProposedRule",
    "SynthesisEngine",
    "ConflictQueue",
    "IFCViolation",
    "NonInterferenceChecker",
    "SecurityLattice",
]
