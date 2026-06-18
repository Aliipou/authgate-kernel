"""
authgate.integrations.fdk — consume a Freedom Decision Kernel (FDK) verdict.

The two products have ONE responsibility each, and meet at ONE contract:

    FDK      → "Is this action *legitimate*?"   (property-rights / consent)   → emits PolicyDecision
    AuthGate → "Can this actor *execute* it?"   (capability + scope + sig)    → CallGate → TCB

This module is the ~50-line seam between them:

    Request → Planner → FDK → PolicyDecision → enforce_legitimacy() → CallGate → TCB → Execution

Decoupling (deliberate, and the whole point): this module imports **nothing**
from FDK. FDK serialises a PolicyDecision to JSON; AuthGate parses that JSON and,
ONLY on an explicit ALLOW, runs its own gate. Either side can be replaced as long
as the contract (`spec/policy_decision.schema.json`) holds. AuthGate remains the
sole source of truth for ownership/authority; FDK only *interprets* legitimacy.

Fail-closed: anything that is not a well-formed, explicit ALLOW bound to *this*
action — a DENY, a DEFER, `fail_closed=true`, a malformed payload, a missing
verdict, or an action_id that does not match — results in **no execution**. There
is no path from a non-ALLOW verdict to a tool call.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from authgate.kernel.call_gate import CallGate, GateResult

_ALLOWED_VERDICTS = frozenset({"ALLOW", "DENY", "DEFER"})


class Verdict(StrEnum):
    """The three-valued FDK verdict carried by the contract."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


class PolicyContractError(ValueError):
    """An FDK payload that does not conform to the PolicyDecision schema. The
    seam treats it as fail-closed: a contract error denies, never executes."""


@dataclass(frozen=True)
class PolicyDecision:
    """The boundary contract (subset AuthGate relies on). Mirrors what FDK's
    `fdk_runtime.PolicyDecision` emits; see `spec/policy_decision.schema.json`."""

    verdict: Verdict
    action_id: str
    actor: str = ""
    reasons: tuple[str, ...] = ()
    axiom_trace: tuple[str, ...] = ()
    fail_closed: bool = False

    @property
    def is_allow(self) -> bool:
        """True only for an explicit ALLOW that is not itself a fail-closed
        verdict. This is the single bit that may unlock execution."""
        return self.verdict is Verdict.ALLOW and not self.fail_closed


def parse_policy_decision(payload: Any) -> PolicyDecision:
    """Strictly parse an FDK PolicyDecision payload (the decoded JSON object).

    Raises `PolicyContractError` on any malformation; callers map that to a
    fail-closed denial. Unknown extra fields are ignored (forward-compatible),
    but the fields AuthGate trusts are validated strictly.
    """
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
    """The seam. Run the AuthGate `CallGate` for `action`/`tool_name` ONLY when
    `decision` is an explicit FDK ALLOW bound to this action; otherwise deny
    without executing.

    `decision` may be an already-parsed `PolicyDecision` or the raw decoded JSON
    object (a dict) straight off the wire. Any contract violation is fail-closed.
    """
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

    # Bind the verdict to THIS action: a legitimacy decision for action X must
    # never authorise execution of action Y (decision-confusion / replay).
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

    # Legitimate, current, and bound to this action → AuthGate now decides
    # authority/scope/signature and (only then) executes inside the TCB.
    return gate.execute(action, tool_name, arguments)
