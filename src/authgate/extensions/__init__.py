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


class ExtendedFreedomVerifier:
    """
    Wraps FreedomVerifier (kernel gate) with:
      - Manipulation detection on action.argument
      - ConflictQueue for human-arbitration tracking
      - SynthesisEngine for constrained rule induction

    Drop-in replacement for FreedomVerifier when manipulation_score
    or synthesis capabilities are needed.
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

    def verify(self, action: Action) -> VerificationResult:
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

        result = self._gate.verify(action)

        return VerificationResult(
            action_id=result.action_id,
            permitted=result.permitted,
            violations=result.violations,
            warnings=tuple(list(result.warnings) + manip_warnings),
            confidence=result.confidence,
            requires_human_arbitration=result.requires_human_arbitration,
            manipulation_score=round(manip_score, 3),
        )

    def admit_rule(self, rule: ProposedRule) -> tuple[bool, str]:
        return self.synthesis.admit_rule(rule)

    def register_induction_hook(self, hook: Callable) -> None:
        self.synthesis.add_induction_hook(hook)


__all__ = [
    "ExtendedFreedomVerifier",
    "ProposedRule",
    "SynthesisEngine",
    "ConflictQueue",
    "IFCViolation",
    "NonInterferenceChecker",
    "SecurityLattice",
]
