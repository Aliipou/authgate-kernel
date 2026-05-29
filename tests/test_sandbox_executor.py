"""Tests for Phase 1/O1: Python Capability-Constrained Sandbox Executor."""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.sandbox_executor import SandboxedExecutor, SandboxResult
from authgate.kernel.tool_abi import ToolABIRegistry, ToolParam, ToolSchema
from authgate.kernel.verifier import Action, FreedomVerifier


def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(scope: str = "/data/") -> Resource:
    return Resource("data", ResourceType.DATASET, scope=scope)


def _setup():
    alice = _human()
    bot = _machine()
    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(bot, _resource(), can_read=True, can_write=True))
    verifier = FreedomVerifier(reg, freeze=True)

    abi = ToolABIRegistry()
    abi.register(ToolSchema(
        name="read_data",
        required_rights=frozenset({"read"}),
        parameters=[ToolParam("path", str, required=True)],
    ))
    abi.register(ToolSchema(
        name="write_data",
        required_rights=frozenset({"write"}),
        parameters=[ToolParam("content", str, required=True)],
    ))
    abi.register(ToolSchema(name="admin_op", is_delegable=False))

    executor = SandboxedExecutor(verifier, abi)
    executor.register_tool("read_data", lambda path: f"content of {path}")
    executor.register_tool("write_data", lambda content: f"wrote {len(content)} bytes")
    return bot, alice, reg, verifier, executor, abi


class TestSandboxResult:
    def test_permitted_is_executed(self):
        r = SandboxResult(permitted=True, output="ok")
        assert r.is_executed()
        assert not r.is_denied()

    def test_denied_not_executed(self):
        r = SandboxResult(permitted=False, denied_reason="blocked")
        assert r.is_denied()
        assert not r.is_executed()


class TestSandboxedExecutor:
    def test_valid_call_executes(self):
        bot, alice, reg, verifier, executor, _ = _setup()
        action = Action(action_id="read-op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "read_data", {"path": "/data/report.csv"})
        assert result.permitted
        assert result.output == "content of /data/report.csv"

    def test_write_tool_executes(self):
        bot, _, _, _, executor, _ = _setup()
        action = Action(action_id="write-op", actor=bot, resources_write=[_resource()])
        result = executor.execute(action, "write_data", {"content": "hello world"})
        assert result.permitted
        assert "11 bytes" in result.output

    def test_sovereignty_flag_denied(self):
        bot, _, _, _, executor, _ = _setup()
        action = Action(action_id="bad-op", actor=bot, increases_machine_sovereignty=True)
        result = executor.execute(action, "read_data", {"path": "/x"})
        assert result.is_denied()
        assert "sovereignty" in result.denied_reason.lower()

    def test_missing_required_param_denied(self):
        bot, _, _, _, executor, _ = _setup()
        action = Action(action_id="read-op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "read_data", {})  # missing 'path'
        assert result.is_denied()
        assert "ABI" in result.denied_reason

    def test_missing_right_denied(self):
        bot, _, _, _, executor, _ = _setup()
        # no write resource in action → no 'write' right → denied
        action = Action(action_id="write-op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "write_data", {"content": "x"})
        assert result.is_denied()

    def test_unregistered_tool_denied(self):
        bot, _, _, _, executor, _ = _setup()
        action = Action(action_id="op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "nonexistent_tool", {})
        assert result.is_denied()
        assert "not registered" in result.denied_reason

    def test_tool_exception_denied(self):
        bot, _, _, _, executor, _ = _setup()
        executor.register_tool("broken", lambda: 1 / 0)
        action = Action(action_id="op", actor=bot, resources_read=[_resource()])
        abi = executor._abi
        abi.register(ToolSchema(name="broken", required_rights=frozenset({"read"})))
        result = executor.execute(action, "broken", {})
        assert result.is_denied()
        assert "execution error" in result.denied_reason.lower()

    def test_no_abi_registry_still_gates(self):
        alice = _human()
        bot = _machine()
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True))
        verifier = FreedomVerifier(reg, freeze=True)
        executor = SandboxedExecutor(verifier, abi_registry=None)
        executor.register_tool("simple_read", lambda: "data")
        action = Action(action_id="op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "simple_read", {})
        assert result.permitted

    def test_result_tool_name_set(self):
        bot, _, _, _, executor, _ = _setup()
        action = Action(action_id="op", actor=bot, resources_read=[_resource()])
        result = executor.execute(action, "read_data", {"path": "/data/x"})
        assert result.tool_name == "read_data"
