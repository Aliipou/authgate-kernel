"""Compose Freedom Formal legitimacy (DENY-only) with AuthGate-style authority.

Pipeline: Claim → FreedomFormalEvaluator → (if ALLOW) authority bit → execute.
Authority here is a stub boolean `has_valid_capability` so scenarios can show
cases AuthGate would Permit while Freedom Formal Denies (and vice versa).
"""
from __future__ import annotations

from dataclasses import dataclass

from authgate.research.freedom_formal.axioms import FreedomFormalEvaluator
from authgate.research.freedom_formal.types import Claim, Evaluation, Verdict


@dataclass(frozen=True)
class PipelineResult:
    legitimacy: Evaluation
    authority_permit: bool
    execute: bool
    note: str

    @property
    def extras_blocked_authorized_action(self) -> bool:
        """True when capability would Permit but Freedom Formal Denies."""
        return self.authority_permit and self.legitimacy.verdict is Verdict.DENY


def compose_legitimacy_then_authority(
    claim: Claim,
    evaluator: FreedomFormalEvaluator | None = None,
) -> PipelineResult:
    ev = (evaluator or FreedomFormalEvaluator()).evaluate(claim)
    authority = bool(claim.has_valid_capability)
    if ev.verdict is Verdict.DENY:
        return PipelineResult(
            legitimacy=ev,
            authority_permit=authority,
            execute=False,
            note="legitimacy DENY — authority not consulted for execution",
        )
    if not authority:
        return PipelineResult(
            legitimacy=ev,
            authority_permit=False,
            execute=False,
            note="legitimacy ALLOW but authority DENY",
        )
    return PipelineResult(
        legitimacy=ev,
        authority_permit=True,
        execute=True,
        note="legitimacy ALLOW and authority PERMIT",
    )
