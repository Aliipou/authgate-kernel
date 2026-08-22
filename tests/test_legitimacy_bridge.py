"""Legitimacy seam + Freedom Formal composition (decision-os meet)."""
from __future__ import annotations

from authgate.integrations.legitimacy import (
    Verdict,
    decide_freedom_formal,
    enforce_freedom_formal,
    enforce_legitimacy,
)
from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.research.freedom_formal import Claim


def _gate():
    alice = Entity("alice", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    sales = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
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
    action = Action("read-sales", actor=bot, resources_read=[sales])
    return gate, action, ran


def test_freedom_formal_allow_then_authgate_executes():
    gate, action, ran = _gate()
    claim = Claim(
        action_id="read-sales",
        actor_id="bot",
        actor_is_machine=True,
        has_valid_capability=True,
    )
    decision = decide_freedom_formal(claim)
    assert decision.verdict is Verdict.ALLOW
    result = enforce_legitimacy(decision, gate, action, "read_sales", {"path": "/x"})
    assert result.permitted is True
    assert ran == ["/x"]


def test_freedom_formal_deny_blocks_before_tool():
    gate, action, ran = _gate()
    claim = Claim(
        action_id="read-sales",
        actor_id="bot",
        actor_is_machine=True,
        has_valid_capability=True,
        clears_audit_trail=True,
    )
    result = enforce_freedom_formal(claim, gate, action, "read_sales", {"path": "/x"})
    assert result.permitted is False
    assert "legitimacy" in (result.denied_reason or "").lower()
    assert ran == []


def test_fdk_shim_still_imports():
    from authgate.integrations import fdk

    assert fdk.enforce_legitimacy is enforce_legitimacy
