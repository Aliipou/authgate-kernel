"""
authgate.integrations.legitimacy — DENY-only legitimacy seam → AuthGate authority.

Decision-os composition (lattice meet): legitimacy never grants. AuthGate alone
decides capability. This module replaces the old FDK product name while keeping
the same JSON contract (`spec/policy_decision.schema.json`).

    Request → Planner → Legitimacy evaluator → PolicyDecision
            → enforce_legitimacy() → CallGate → TCB → Execution

Default evaluator on `with-legitimacy` / research branches: Freedom Formal
(`authgate.research.freedom_formal`). On `main` without legitimacy, skip this
seam and call CallGate directly.

Compat: `authgate.integrations.fdk` re-exports this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from authgate.kernel.call_gate import CallGate, GateResult

_ALLOWED_VERDICTS = frozenset({"ALLOW", "DENY", "DEFER"})


class Verdict(StrEnum):
    """Three-valued legitimacy verdict on the wire contract."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


class PolicyContractError(ValueError):
    """Malformed PolicyDecision — fail-closed (never execute)."""


@dataclass(frozen=True)
class PolicyDecision:
    """Boundary contract. See `spec/policy_decision.schema.json`."""

    verdict: Verdict
    action_id: str
    actor: str = ""
    reasons: tuple[str, ...] = ()
    axiom_trace: tuple[str, ...] = ()
    fail_closed: bool = False

    @property
    def is_allow(self) -> bool:
        return self.verdict is Verdict.ALLOW and not self.fail_closed

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "action_id": self.action_id,
            "actor": self.actor,
            "reasons": list(self.reasons),
            "axiom_trace": list(self.axiom_trace),
            "fail_closed": self.fail_closed,
        }


def parse_policy_decision(payload: Any) -> PolicyDecision:
    """Strictly parse a PolicyDecision JSON object."""
    if not isinstance(payload, dict):
        raise PolicyContractError(
            f"PolicyDecision must be a JSON object, got {type(payload).__name__}"
        )
    verdict = payload.get("verdict")
    if verdict not in _ALLOWED_VERDICTS:
        raise PolicyContractError(f"unknown or missing verdict: {verdict!r}")
    action_id = payload.get("action_id")
    if not isinstance(action_id, str) or not action_id.strip():
        raise PolicyContractError("PolicyDecision.action_id must be a non-empty string")
    return PolicyDecision(
        verdict=Verdict(verdict),
        action_id=action_id,
        actor=str(payload.get("actor", "")),
        reasons=tuple(payload.get("reasons") or ()),
        axiom_trace=tuple(payload.get("axiom_trace") or ()),
        fail_closed=bool(payload.get("fail_closed", False)),
    )


def enforce_legitimacy(
    decision: PolicyDecision | dict[str, Any],
    gate: CallGate,
    action: Any,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> GateResult:
    """Lattice meet: run CallGate only on explicit ALLOW bound to this action."""
    try:
        parsed = (
            decision
            if isinstance(decision, PolicyDecision)
            else parse_policy_decision(decision)
        )
    except PolicyContractError as exc:
        return GateResult(
            permitted=False,
            denied_reason=f"legitimacy contract error: {exc}",
            tool_name=tool_name,
        )

    if not parsed.is_allow:
        why = "; ".join(parsed.reasons) if parsed.reasons else str(parsed.verdict)
        return GateResult(
            permitted=False,
            denied_reason=f"legitimacy gate {parsed.verdict}: {why}",
            tool_name=tool_name,
        )

    expected_id = getattr(action, "action_id", None)
    if expected_id is not None and parsed.action_id != expected_id:
        return GateResult(
            permitted=False,
            denied_reason=(
                f"legitimacy decision action_id {parsed.action_id!r} "
                f"does not match action {expected_id!r}"
            ),
            tool_name=tool_name,
        )

    return gate.execute(action, tool_name, arguments)


def decide_freedom_formal(claim: Any) -> PolicyDecision:
    """Run the Freedom Formal evaluator and emit a PolicyDecision (DENY-only semantics).

    ALLOW here only means "legitimacy did not veto" — AuthGate still must Permit.
    """
    from authgate.research.freedom_formal import (
        FreedomFormalEvaluator,
    )
    from authgate.research.freedom_formal import (
        Verdict as FFVerdict,
    )

    evaluation = FreedomFormalEvaluator().evaluate(claim)
    actor = getattr(claim, "actor_id", "") or ""
    action_id = getattr(claim, "action_id", "") or ""
    if evaluation.verdict is FFVerdict.DENY:
        return PolicyDecision(
            verdict=Verdict.DENY,
            action_id=action_id,
            actor=actor,
            reasons=evaluation.reasons,
            axiom_trace=evaluation.axiom_trace,
            fail_closed=True,
        )
    return PolicyDecision(
        verdict=Verdict.ALLOW,
        action_id=action_id,
        actor=actor,
        reasons=(),
        axiom_trace=evaluation.axiom_trace,
        fail_closed=False,
    )


def enforce_freedom_formal(
    claim: Any,
    gate: CallGate,
    action: Any,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> GateResult:
    """Convenience: Freedom Formal → PolicyDecision → enforce_legitimacy → CallGate."""
    return enforce_legitimacy(
        decide_freedom_formal(claim),
        gate,
        action,
        tool_name,
        arguments,
    )
