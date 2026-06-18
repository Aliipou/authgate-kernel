"""
FDK -> AuthGate boundary tests (authgate.integrations.fdk).

Proves the seam holds the responsibility split and is fail-closed end to end:

    FDK PolicyDecision (legitimacy) -> enforce_legitimacy() -> CallGate (authority) -> tool

The bridge imports no FDK code; these tests feed PolicyDecision payloads (the
JSON contract) through a REAL AuthGate registry/verifier/gate. Covers the golden
happy path plus every non-ALLOW and malformed path — the body must never run
unless legitimacy AND authority both pass.
"""
from __future__ import annotations

import json

import pytest

from authgate.integrations.fdk import (
    PolicyContractError,
    PolicyDecision,
    Verdict,
    enforce_legitimacy,
    parse_policy_decision,
)
from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _build():
    """A real AuthGate setup: bot may READ sales (delegated by owner alice),
    and has no claim at all on config."""
    alice = Entity("alice", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    sales = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
    config = Resource("system-config", ResourceType.FILE, scope="/etc/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, sales, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, sales, can_read=True), delegated_by=alice)

    gate = CallGate(FreedomVerifier(reg, freeze=False, audit_log=AuditLog()))
    ran: list[str] = []

    def read_sales(path: str) -> str:
        ran.append(path)
        return f"DATA:{path}"

    gate.register("read_sales", read_sales)

    authorized = Action("read-sales", actor=bot, resources_read=[sales])
    unauthorized = Action("read-config", actor=bot, resources_read=[config])
    return gate, authorized, unauthorized, ran


def _decision(verdict: str = "ALLOW", action_id: str = "read-sales", **extra) -> dict:
    payload = {"verdict": verdict, "action_id": action_id, "actor": "bot"}
    payload.update(extra)
    return payload


# ── the golden end-to-end flow ────────────────────────────────────────────────

def test_golden_flow_allow_and_authorized_executes():
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(_decision("ALLOW"), gate, authorized, "read_sales",
                                {"path": "/data/alice/sales/q1.csv"})
    assert result.permitted is True
    assert result.output == "DATA:/data/alice/sales/q1.csv"
    assert ran == ["/data/alice/sales/q1.csv"]  # body ran exactly once


def test_golden_flow_survives_json_roundtrip():
    # FDK serialises to JSON; AuthGate parses it off the wire. Same outcome.
    gate, authorized, _unauth, ran = _build()
    wire = json.loads(json.dumps(_decision("ALLOW")))
    result = enforce_legitimacy(wire, gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is True
    assert ran == ["/x"]


# ── responsibility split: legitimacy passes, authority decides ────────────────

def test_allow_but_unauthorized_is_denied_by_authgate():
    # Legitimacy says ALLOW, but the bot holds no capability on config.
    gate, _auth, unauthorized, ran = _build()
    result = enforce_legitimacy(_decision("ALLOW", action_id="read-config"),
                                gate, unauthorized, "read_sales", {"path": "/etc/x"})
    assert result.permitted is False
    assert "capability gate" in (result.denied_reason or "")
    assert ran == []  # authority failed → body never ran


def test_passing_a_parsed_decision_object_works():
    gate, authorized, _unauth, ran = _build()
    decision = PolicyDecision(verdict=Verdict.ALLOW, action_id="read-sales")
    result = enforce_legitimacy(decision, gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is True
    assert ran == ["/x"]


# ── fail-closed: every non-ALLOW path blocks before AuthGate ──────────────────

def test_deny_verdict_blocks_and_body_never_runs():
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(
        _decision("DENY", reasons=["A3: bot uses 'x' it does not own"], axiom_trace=["A3"]),
        gate, authorized, "read_sales", {"path": "/x"},
    )
    assert result.permitted is False
    assert "legitimacy gate DENY" in (result.denied_reason or "")
    assert "A3" in (result.denied_reason or "")
    assert ran == []


def test_defer_verdict_blocks():
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(_decision("DEFER", reasons=["irreversible — confirm"]),
                                gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is False
    assert "legitimacy gate DEFER" in (result.denied_reason or "")
    assert ran == []


def test_fail_closed_flag_blocks_even_when_verdict_is_allow():
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(_decision("ALLOW", fail_closed=True),
                                gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is False
    assert ran == []


def test_action_id_mismatch_is_rejected():
    # A legitimacy verdict for a different action must not authorise this one.
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(_decision("ALLOW", action_id="some-other-action"),
                                gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is False
    assert "does not match" in (result.denied_reason or "")
    assert ran == []


# ── fail-closed: malformed contract payloads ──────────────────────────────────

@pytest.mark.parametrize("bad", [
    ["not", "a", "dict"],
    {"action_id": "read-sales"},                 # missing verdict
    {"verdict": "MAYBE", "action_id": "read-sales"},  # unknown verdict
    {"verdict": "ALLOW", "action_id": ""},       # empty action_id
    {"verdict": "ALLOW"},                        # missing action_id
])
def test_malformed_payload_fails_closed(bad):
    gate, authorized, _unauth, ran = _build()
    result = enforce_legitimacy(bad, gate, authorized, "read_sales", {"path": "/x"})
    assert result.permitted is False
    assert "contract error" in (result.denied_reason or "")
    assert ran == []


# ── the parser, directly ──────────────────────────────────────────────────────

def test_parse_extracts_axiom_trace_and_reasons():
    decision = parse_policy_decision(_decision(
        "DENY", reasons=["A7: no delegation"], axiom_trace=["A7"]))
    assert decision.verdict is Verdict.DENY
    assert decision.axiom_trace == ("A7",)
    assert decision.is_allow is False


def test_parse_rejects_non_object():
    with pytest.raises(PolicyContractError):
        parse_policy_decision("ALLOW")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
