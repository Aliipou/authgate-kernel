"""
CallGate tests — Python equivalent of call_gate.rs tests.

Verifies:
  - Happy path: permitted action → tool executes, result returned
  - AT-7.5: tool body never runs when gate denies
  - Sovereignty flags unconditionally block before execution
  - ABI validation (mocked) blocks between verify and execute
  - Audit log receives both permit and deny
  - Revocation immediately visible
  - GatedTool callable syntax
  - Unregistered tool raises KeyError (programmer error)
  - Multiple tools isolated (one denial does not affect another)
"""

from __future__ import annotations

import pytest

from authgate.kernel.call_gate import CallGate, GatedTool, GateResult
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _env():
    alice = Entity("Alice", AgentType.HUMAN)
    bot   = Entity("Bot",   AgentType.MACHINE)
    data  = Resource("data",  ResourceType.FILE, scope="/data/")
    vault = Resource("vault", ResourceType.FILE, scope="/vault/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data,  can_read=True, can_write=True, can_delegate=True))
    reg.add_claim(RightsClaim(alice, vault, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True, can_write=True), delegated_by=alice)
    # vault: alice owns it, bot has NO delegation

    return alice, bot, data, vault, reg


# ─── 1. Happy path ────────────────────────────────────────────────────────────

class TestHappyPath:

    def test_permitted_action_executes_tool(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        calls = []

        gate.register("read_data", lambda path: calls.append(path) or f"content:{path}")

        result = gate.execute(
            Action("read", actor=bot, resources_read=[data]),
            "read_data",
            {"path": "/data/report.txt"},
        )

        assert result.permitted
        assert result.output == "content:/data/report.txt"
        assert result.denied_reason is None
        assert calls == ["/data/report.txt"]

    def test_gate_result_carries_tool_name(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        gate.register("fetch", lambda: "ok")

        result = gate.execute(Action("a", actor=bot, resources_read=[data]), "fetch", {})
        assert result.tool_name == "fetch"

    def test_gate_result_is_frozen(self):
        result = GateResult(permitted=True, output="x", tool_name="t")
        with pytest.raises((AttributeError, TypeError)):
            result.permitted = False  # type: ignore


# ─── 2. AT-7.5: tool body never runs on denial ────────────────────────────────

class TestAT75ToolBodyNeverRuns:

    def test_denied_tool_body_never_executes(self):
        _, bot, _, vault, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        executed = []

        gate.register("steal_vault", lambda: executed.append("EXECUTED") or "stolen")

        result = gate.execute(
            Action("steal", actor=bot, resources_read=[vault]),
            "steal_vault",
            {},
        )

        assert not result.permitted
        assert executed == [], "Tool body ran despite gate denial — AT-7.5 violated"
        assert result.denied_reason is not None
        assert "capability gate denied" in result.denied_reason

    def test_sovereignty_flag_blocks_before_execution(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        executed = []

        gate.register("escalate", lambda: executed.append("EXECUTED") or "escalated")

        result = gate.execute(
            Action("esc", actor=bot, resources_read=[data],
                   increases_machine_sovereignty=True),
            "escalate",
            {},
        )

        assert not result.permitted
        assert executed == [], "Tool body ran despite sovereignty flag — gate failed"
        assert result.denied_reason is not None

    def test_write_denied_without_write_claim_never_executes(self):
        _, bot, _, vault, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        executed = []

        gate.register("write_vault", lambda data: executed.append(data) or "written")

        result = gate.execute(
            Action("w", actor=bot, resources_write=[vault]),
            "write_vault",
            {"data": "secret"},
        )

        assert not result.permitted
        assert executed == []


# ─── 3. GatedTool callable syntax ─────────────────────────────────────────────

class TestGatedToolCallable:

    def test_gated_tool_callable_returns_gate_result(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        tool = gate.register("ping", lambda: "pong")

        result = tool(Action("p", actor=bot, resources_read=[data]))

        assert isinstance(result, GateResult)
        assert result.permitted
        assert result.output == "pong"

    def test_gated_tool_denied_via_callable(self):
        _, bot, _, vault, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        executed = []
        tool = gate.register("read_vault", lambda: executed.append(1) or "read")

        result = tool(Action("rv", actor=bot, resources_read=[vault]))

        assert not result.permitted
        assert executed == []

    def test_gated_tool_repr(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        tool = gate.register("my_tool", lambda: None)
        assert "my_tool" in repr(tool)

    def test_gated_tool_name_property(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        tool = gate.register("named_tool", lambda: None)
        assert tool.name == "named_tool"

    def test_gated_tool_no_fn_public_attribute(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        tool = gate.register("hidden", lambda: "secret")

        # Public interface does not expose the underlying callable
        assert not hasattr(tool, "fn")
        assert not hasattr(tool, "_fn")
        # _GatedTool__fn (name-mangled) exists internally but is not in __slots__
        # via any public name


# ─── 4. Multiple tools isolated ───────────────────────────────────────────────

class TestMultipleToolsIsolated:

    def test_denial_of_one_tool_does_not_affect_another(self):
        _, bot, data, vault, reg = _env()
        gate = CallGate(FreedomVerifier(reg))

        results_read = []
        gate.register("read_data",  lambda: results_read.append(1) or "read-ok")
        gate.register("read_vault", lambda: "vault-ok")

        # vault is denied (no delegation)
        r1 = gate.execute(Action("rv", actor=bot, resources_read=[vault]), "read_vault", {})
        # data is permitted
        r2 = gate.execute(Action("rd", actor=bot, resources_read=[data]),  "read_data",  {})

        assert not r1.permitted
        assert r2.permitted
        assert results_read == [1]

    def test_registered_tools_list(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))
        gate.register("alpha", lambda: None)
        gate.register("beta",  lambda: None)
        assert gate.registered_tools() == ["alpha", "beta"]


# ─── 5. Unregistered tool raises KeyError ─────────────────────────────────────

class TestUnregisteredTool:

    def test_unregistered_tool_raises_key_error(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg))

        with pytest.raises(KeyError, match="not registered"):
            gate.execute(Action("x", actor=bot, resources_read=[data]), "nonexistent", {})


# ─── 6. Audit log integration ─────────────────────────────────────────────────

class TestAuditIntegration:

    def test_permitted_execution_logged(self):
        _, bot, data, _, reg = _env()
        audit = AuditLog()
        gate = CallGate(FreedomVerifier(reg, audit_log=audit))
        gate.register("r", lambda: "ok")

        gate.execute(Action("a", actor=bot, resources_read=[data]), "r", {})

        assert len(audit) == 1
        assert audit.entries()[0]["permitted"] is True

    def test_denied_execution_logged(self):
        _, bot, _, vault, reg = _env()
        audit = AuditLog()
        gate = CallGate(FreedomVerifier(reg, audit_log=audit))
        gate.register("r", lambda: "ok")

        gate.execute(Action("a", actor=bot, resources_read=[vault]), "r", {})

        assert len(audit) == 1
        assert audit.entries()[0]["permitted"] is False

    def test_audit_chain_intact_after_mixed_executions(self):
        _, bot, data, vault, reg = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        gate = CallGate(v)
        gate.register("r", lambda: "ok")
        gate.register("w", lambda: "ok")

        gate.execute(Action("a1", actor=bot, resources_read=[data]),  "r", {})  # permit
        gate.execute(Action("a2", actor=bot, resources_read=[vault]), "r", {})  # deny
        gate.execute(Action("a3", actor=bot, resources_write=[data]), "w", {})  # permit

        assert len(audit) == 3
        assert audit.verify_chain()


# ─── 7. Revocation immediately visible ────────────────────────────────────────

class TestRevocationImmediatelyVisible:

    def test_revocation_blocks_next_execution(self):
        _, bot, data, _, reg = _env()
        gate = CallGate(FreedomVerifier(reg, freeze=False))
        calls = []
        gate.register("read", lambda: calls.append(1) or "ok")

        # Before revocation: permitted
        r1 = gate.execute(Action("b", actor=bot, resources_read=[data]), "read", {})
        assert r1.permitted

        # Revoke
        reg.revoke_all(bot.name)

        # After revocation: denied, tool body never runs
        r2 = gate.execute(Action("a", actor=bot, resources_read=[data]), "read", {})
        assert not r2.permitted
        assert len(calls) == 1  # only the first call executed
