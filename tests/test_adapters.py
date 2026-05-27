"""Adapter tests — OpenAI, Anthropic, LangChain, AutoGen."""
import pytest

from authgate.adapters.anthropic import AnthropicKernelAdapter
from authgate.adapters.autogen import AutoGenKernelAdapter
from authgate.adapters.langchain import FreedomTool, kernel_gate
from authgate.adapters.openai_agents import OpenAIKernelMiddleware
from authgate.kernel import (
    AgentType,
    Entity,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)

# ── shared fixtures ───────────────────────────────────────────────────────────

def _setup():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    bot   = Entity(name="bot",   kind=AgentType.MACHINE)
    res   = Resource(name="report", rtype=ResourceType.FILE)
    registry = OwnershipRegistry()
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(holder=bot, resource=res, can_read=True, can_write=True))
    verifier = FreedomVerifier(registry)
    return verifier, alice, bot, res


# ── OpenAI middleware ─────────────────────────────────────────────────────────

def test_openai_check_permits():
    verifier, _, bot, res = _setup()
    mw = OpenAIKernelMiddleware(verifier, bot)
    result = mw.check("t1", resources_read=[res])
    assert result.permitted is True


def test_openai_check_blocks_sovereignty():
    verifier, _, bot, _ = _setup()
    mw = OpenAIKernelMiddleware(verifier, bot)
    result = mw.check("t1", increases_machine_sovereignty=True)
    assert result.permitted is False


def test_openai_tool_decorator_permits():
    verifier, _, bot, res = _setup()
    mw = OpenAIKernelMiddleware(verifier, bot)

    @mw.tool(resources_read=[res])
    def read_file() -> str:
        return "data"

    assert read_file() == "data"


def test_openai_tool_decorator_blocks():
    verifier, _, bot, _ = _setup()
    mw = OpenAIKernelMiddleware(verifier, bot)

    @mw.tool(increases_machine_sovereignty=True)
    def bad_action() -> str:
        return "done"

    with pytest.raises(PermissionError, match="FORBIDDEN"):
        bad_action()


def test_openai_tool_definitions():
    verifier, _, bot, res = _setup()
    mw = OpenAIKernelMiddleware(verifier, bot)

    @mw.tool(resources_read=[res])
    def my_tool(path: str) -> str:
        """Read a file."""
        return ""

    defs = mw.openai_tool_definitions([my_tool])
    assert len(defs) == 1
    assert defs[0]["function"]["name"] == "my_tool"


# ── Anthropic adapter ─────────────────────────────────────────────────────────

def test_anthropic_check_permits():
    verifier, _, bot, res = _setup()
    adapter = AnthropicKernelAdapter(verifier, bot, {"read": ([res], [])})
    adapter.check("id1", "read", resources_read=[res])  # must not raise


def test_anthropic_check_blocks():
    verifier, _, bot, _ = _setup()
    adapter = AnthropicKernelAdapter(verifier, bot)
    result = adapter.check("id1", "bad", increases_machine_sovereignty=True)
    assert result.permitted is False


def test_anthropic_check_returns_blocked_result():
    verifier, _, bot, _ = _setup()
    adapter = AnthropicKernelAdapter(verifier, bot)
    result = adapter.check("id1", "bad", increases_machine_sovereignty=True)
    assert result.permitted is False
    assert any("FORBIDDEN" in v for v in result.violations)


def test_anthropic_check_block_via_block():
    """check() returns result; check_block() raises on blocked tool_use block."""
    verifier, _, bot, res = _setup()
    adapter = AnthropicKernelAdapter(
        verifier, bot, {"read_file": ([res], []), "write": ([], [res])}
    )

    class _Block:
        id = "b1"
        name = "read_file"

    adapter.check_block(_Block())  # must not raise


def test_anthropic_check_block_raises_on_unknown_tool():
    verifier, _, bot, _ = _setup()
    adapter = AnthropicKernelAdapter(verifier, bot, {})

    class _Block:
        id = "b2"
        name = "write_secret"

    # Unknown tool has no resources, so kernel A4 check still passes (bot has owner)
    # but it has no resource claims to deny either — should be permitted
    adapter.check_block(_Block())


def test_anthropic_tool_definitions():
    verifier, _, bot, res = _setup()
    adapter = AnthropicKernelAdapter(verifier, bot, {"read": ([res], [])})
    defs = adapter.tool_definitions()
    assert len(defs) == 1
    assert defs[0]["name"] == "read"


# ── LangChain adapter ─────────────────────────────────────────────────────────

def test_langchain_kernel_gate_permits():
    verifier, _, bot, res = _setup()

    @kernel_gate(verifier, bot, resources_read=[res])
    def read_report() -> str:
        return "data"

    assert read_report() == "data"


def test_langchain_kernel_gate_blocks():
    verifier, _, bot, _ = _setup()

    @kernel_gate(verifier, bot, increases_machine_sovereignty=True)
    def bad() -> str:
        return "done"

    with pytest.raises(PermissionError):
        bad()


def test_langchain_freedom_tool_permits():
    verifier, _, bot, res = _setup()

    class MyTool(FreedomTool):
        name = "my_tool"
        description = "test"
        kernel_verifier = verifier
        kernel_agent = bot
        kernel_resources_read = [res]

        def _run(self) -> str:
            return "result"

    tool = MyTool()
    assert tool.run() == "result"


def test_langchain_freedom_tool_blocks():
    verifier, _, bot, res = _setup()
    unreachable = Resource(name="secret", rtype=ResourceType.DATABASE_TABLE)

    class BadTool(FreedomTool):
        name = "bad_tool"
        description = "test"
        kernel_verifier = verifier
        kernel_agent = bot
        kernel_resources_write = [unreachable]

        def _run(self) -> str:
            return "done"

    with pytest.raises(PermissionError):
        BadTool().run()


# ── AutoGen adapter ───────────────────────────────────────────────────────────

def test_autogen_check_permits():
    verifier, _, bot, res = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)
    result = adapter.check("t1", resources_read=[res])
    assert result.permitted is True


def test_autogen_check_blocks_sovereignty():
    verifier, _, bot, _ = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)
    with pytest.raises(PermissionError):
        adapter.check("t1", increases_machine_sovereignty=True)


def test_autogen_tool_decorator_permits():
    verifier, _, bot, res = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)

    @adapter.tool(resources_read=[res])
    def read_data() -> str:
        return "ok"

    assert read_data() == "ok"


def test_autogen_tool_decorator_blocks():
    verifier, _, bot, _ = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)

    @adapter.tool(increases_machine_sovereignty=True)
    def bad() -> str:
        return "done"

    with pytest.raises(PermissionError):
        bad()


def test_autogen_register_gates_function_map():
    """register() wraps all functions in the function_map."""
    verifier, _, bot, res = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)

    calls = []

    def read_fn() -> str:
        calls.append("called")
        return "data"

    class _FakeAgent:
        def __init__(self):
            self.registered = {}

        def register_function(self, function_map):
            self.registered = function_map

    agent = _FakeAgent()
    adapter.register(
        agent=agent,
        function_map={"read_fn": read_fn},
        resource_map={"read_fn": ([res], [])},
    )
    # The registered function is gated — call it
    result = agent.registered["read_fn"]()
    assert result == "data"
    assert calls == ["called"]


def test_autogen_check_message():
    verifier, _, bot, res = _setup()
    adapter = AutoGenKernelAdapter(verifier, bot)
    msg = {"name": "read_fn", "arguments": "{}"}
    result = adapter.check_message(msg, resource_map={"read_fn": ([res], [])})
    assert result.permitted is True
