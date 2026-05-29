"""
Persuasion Boundary Formal Model — Phase 4, O1.

From ultimate-plan.md P4/O1 — Persuasion Boundaries:
  Manipulation detection must graduate from heuristic manipulation_score
  to a formal model with provable boundaries.

  Formal definition:
    A request R is persuasive-boundary-violating iff it satisfies ≥K of
    the following structural criteria (K=2 for HIGH, K=3 for CRITICAL):

    S1. Information asymmetry: actor has access to information the target
        cannot independently verify (credential, model_weights, identity resources)
    S2. Urgency framing: action_id or argument contains time-pressure language
    S3. Authority amplification: actor claims rights that exceed their chain
    S4. Scope maximization: action requests maximum possible scope (root + all rights)
    S5. Reversibility obscuring: action involves CREDENTIAL or IDENTITY without expiry

  This is structural — no NLP, no semantic parsing. The criteria are derivable
  from the typed claims and action fields alone.

Outputs:
  PersuasionBoundaryResult — contains which criteria fired and the formal verdict
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class PersuasionCriterion(Enum):
    INFORMATION_ASYMMETRY   = auto()  # S1
    URGENCY_FRAMING         = auto()  # S2
    AUTHORITY_AMPLIFICATION = auto()  # S3
    SCOPE_MAXIMIZATION      = auto()  # S4
    REVERSIBILITY_OBSCURING = auto()  # S5


_URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediate|asap|now|critical|deadline|emergency|must|force|override)\b",
    re.IGNORECASE,
)

_SENSITIVE_RTYPES: set[str] = {
    "credential", "identity", "model_weights", "behavioral_profile",
    "biological_telemetry", "digital_twin",
}


@dataclass(frozen=True)
class PersuasionBoundaryResult:
    """Formal persuasion boundary check result."""
    action_id: str
    criteria_fired: tuple[PersuasionCriterion, ...]
    verdict: str            # "CLEAR", "SUSPICIOUS", "HIGH", "CRITICAL"
    block: bool             # True = hard block recommended
    description: str

    @property
    def score(self) -> int:
        return len(self.criteria_fired)


class PersuasionBoundaryChecker:
    """
    Checks an action for structural persuasion boundary violations.

    Thresholds:
      0-1 criteria → CLEAR (no block)
      2   criteria → SUSPICIOUS (warn)
      3   criteria → HIGH (soft block; human arbitration)
      4-5 criteria → CRITICAL (hard block)
    """

    SUSPICIOUS_THRESHOLD: int = 2
    HIGH_THRESHOLD: int = 3
    CRITICAL_THRESHOLD: int = 4

    def check(self, action: Any, registry: Any = None) -> PersuasionBoundaryResult:
        """
        Evaluate an action against the 5 formal persuasion criteria.

        registry: optional OwnershipRegistry for authority amplification check (S3).
        """
        fired: list[PersuasionCriterion] = []

        fired.extend(self._s1_information_asymmetry(action))
        fired.extend(self._s2_urgency_framing(action))
        fired.extend(self._s3_authority_amplification(action, registry))
        fired.extend(self._s4_scope_maximization(action))
        fired.extend(self._s5_reversibility_obscuring(action))

        k = len(fired)
        if k >= self.CRITICAL_THRESHOLD:
            verdict, block = "CRITICAL", True
        elif k >= self.HIGH_THRESHOLD:
            verdict, block = "HIGH", True
        elif k >= self.SUSPICIOUS_THRESHOLD:
            verdict, block = "SUSPICIOUS", False
        else:
            verdict, block = "CLEAR", False

        cnames = ", ".join(c.name for c in fired) if fired else "none"
        description = (
            f"Persuasion boundary check for '{action.action_id}': "
            f"{k}/5 criteria fired [{cnames}] → {verdict}"
        )

        return PersuasionBoundaryResult(
            action_id=action.action_id,
            criteria_fired=tuple(fired),
            verdict=verdict,
            block=block,
            description=description,
        )

    # ── Criteria implementations ──────────────────────────────────────────────

    def _s1_information_asymmetry(self, action: Any) -> list[PersuasionCriterion]:
        """S1: actor is accessing resources the target cannot independently verify."""
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
            + list(getattr(action, "resources_delegate", []))
        )
        for res in all_resources:
            rtype_val = getattr(res.rtype, "value", str(res.rtype))
            if rtype_val in _SENSITIVE_RTYPES:
                return [PersuasionCriterion.INFORMATION_ASYMMETRY]
        return []

    def _s2_urgency_framing(self, action: Any) -> list[PersuasionCriterion]:
        """S2: action_id or argument contains urgency/pressure language."""
        text = action.action_id + " " + getattr(action, "argument", "")
        if _URGENCY_PATTERN.search(text):
            return [PersuasionCriterion.URGENCY_FRAMING]
        desc = getattr(action, "description", "")
        if desc and _URGENCY_PATTERN.search(desc):
            return [PersuasionCriterion.URGENCY_FRAMING]
        return []

    def _s3_authority_amplification(self, action: Any, registry: Any) -> list[PersuasionCriterion]:
        """S3: actor's requested rights exceed what the registry grants them."""
        if registry is None:
            return []
        actor = getattr(action, "actor", None)
        if actor is None or not actor.is_machine():
            return []

        read_resources = list(getattr(action, "resources_read", []))
        write_resources = list(getattr(action, "resources_write", []))

        for res in read_resources:
            claim = registry.best_claim(actor, res, "read")
            if claim is None:
                return [PersuasionCriterion.AUTHORITY_AMPLIFICATION]
        for res in write_resources:
            claim = registry.best_claim(actor, res, "write")
            if claim is None:
                return [PersuasionCriterion.AUTHORITY_AMPLIFICATION]
        return []

    def _s4_scope_maximization(self, action: Any) -> list[PersuasionCriterion]:
        """S4: action requests maximum scope (root scope + read+write+delegate)."""
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
            + list(getattr(action, "resources_delegate", []))
        )
        root_resources = [
            r for r in all_resources
            if not r.scope or r.scope in ("/", "")
        ]
        has_read = bool(getattr(action, "resources_read", []))
        has_write = bool(getattr(action, "resources_write", []))
        has_delegate = bool(getattr(action, "resources_delegate", []))
        if root_resources and has_read and has_write and has_delegate:
            return [PersuasionCriterion.SCOPE_MAXIMIZATION]
        return []

    def _s5_reversibility_obscuring(self, action: Any) -> list[PersuasionCriterion]:
        """S5: action touches CREDENTIAL or IDENTITY without a clear expiry constraint."""
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
        )
        irreversible_types = {"credential", "identity"}
        for res in all_resources:
            rtype_val = getattr(res.rtype, "value", str(res.rtype))
            if rtype_val in irreversible_types:
                return [PersuasionCriterion.REVERSIBILITY_OBSCURING]
        return []


# ── Convenience ───────────────────────────────────────────────────────────────

_DEFAULT_CHECKER = PersuasionBoundaryChecker()


def check_persuasion_boundary(action: Any, registry: Any = None) -> PersuasionBoundaryResult:
    """Check an action against the formal persuasion boundary model."""
    return _DEFAULT_CHECKER.check(action, registry)
