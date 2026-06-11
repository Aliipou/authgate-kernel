"""
Coverage tests added on the `nazariye-azadi` branch.

Purpose: exercise modules that the existing suite imports but never runs end to
end — settings parsing and the red-team attack primitives. These are real
behavioural assertions, not import smoke: each attack is executed and its
documented outcome (blocked / residual-risk) is asserted, and every settings
branch (default, override, bool/int/float parsing) is driven.
"""
from __future__ import annotations

import pytest

from authgate import settings as settings_mod
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import FreedomVerifier
from authgate.redteam.scenarios import (
    AttackResult,
    AuthorityLaunderingAttack,
    ConfidenceInflationAttack,
    ForgedDelegationAttack,
    MaliciousAgent,
    RecursiveToolAbuseAttack,
    SovereigntyFlagInjectionAttack,
)

# --------------------------------------------------------------------------- #
# settings.py
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _reset_settings_singleton():
    settings_mod.reset_settings()
    yield
    settings_mod.reset_settings()


def test_from_env_defaults(monkeypatch):
    for k in (
        "AUTHGATE_LOG_LEVEL", "AUTHGATE_AUDIT_PATH", "AUTHGATE_CONFIDENCE_WARN",
        "AUTHGATE_MAX_CHAIN_DEPTH", "AUTHGATE_FREEZE_REGISTRY", "AUTHGATE_AUDIT_ENABLED",
    ):
        monkeypatch.delenv(k, raising=False)
    s = settings_mod.AuthgateSettings.from_env()
    assert s.log_level == "INFO"
    assert s.audit_path is None
    assert s.confidence_warn_threshold == 0.8
    assert s.max_chain_depth == 16
    assert s.freeze_registry_on_init is False
    assert s.audit_enabled is True


def test_from_env_all_overridden(monkeypatch):
    monkeypatch.setenv("AUTHGATE_LOG_LEVEL", "debug")
    monkeypatch.setenv("AUTHGATE_AUDIT_PATH", "/tmp/audit.jsonl")
    monkeypatch.setenv("AUTHGATE_CONFIDENCE_WARN", "0.5")
    monkeypatch.setenv("AUTHGATE_MAX_CHAIN_DEPTH", "8")
    monkeypatch.setenv("AUTHGATE_FREEZE_REGISTRY", "yes")
    monkeypatch.setenv("AUTHGATE_AUDIT_ENABLED", "0")
    s = settings_mod.AuthgateSettings.from_env()
    assert s.log_level == "DEBUG"  # _get(...).upper()
    assert s.audit_path == "/tmp/audit.jsonl"
    assert s.confidence_warn_threshold == 0.5
    assert s.max_chain_depth == 8
    assert s.freeze_registry_on_init is True   # "yes" -> True
    assert s.audit_enabled is False            # "0" -> False


def test_get_settings_is_singleton(monkeypatch):
    monkeypatch.delenv("AUTHGATE_LOG_LEVEL", raising=False)
    first = settings_mod.get_settings()
    second = settings_mod.get_settings()
    assert first is second


def test_override_settings_creates_then_mutates():
    # _default is None here (autouse reset) -> override initialises then sets
    settings_mod.override_settings(log_level="ERROR", max_chain_depth=4)
    s = settings_mod.get_settings()
    assert s.log_level == "ERROR"
    assert s.max_chain_depth == 4
    # second override path: _default already exists
    settings_mod.override_settings(audit_enabled=False)
    assert settings_mod.get_settings().audit_enabled is False


def test_reset_settings_clears_singleton():
    settings_mod.override_settings(log_level="WARNING")
    settings_mod.reset_settings()
    assert settings_mod._default is None


# --------------------------------------------------------------------------- #
# redteam/scenarios.py
# --------------------------------------------------------------------------- #

def _human() -> Entity:
    return Entity("Alice", AgentType.HUMAN)


def _res(name: str, rtype: ResourceType = ResourceType.FILE, scope: str = "") -> Resource:
    return Resource(name, rtype, scope=scope)


def test_forged_delegation_attack_blocked():
    res = AttackResult  # ensure symbol imported
    assert res is AttackResult
    attack = ForgedDelegationAttack(_human(), _res("secret"))
    result = attack.run()
    assert result.blocked is True
    assert "no valid claim" in result.explanation.lower()
    assert "BLOCKED" in str(result)


def test_authority_laundering_is_residual_risk():
    attack = AuthorityLaunderingAttack(_human(), _res("sensitive"), _res("exfil"))
    result = attack.run()
    # Both individual actions permitted -> the laundering combination is NOT blocked
    assert result.blocked is False
    assert "RESIDUAL_RISK" in str(result)
    assert len(result.verification_results) == 2


def test_recursive_tool_abuse_blocked():
    attack = RecursiveToolAbuseAttack(_human(), _res("doc"))
    result = attack.run()
    assert result.blocked is True
    assert "delegation" in result.explanation.lower()


def test_sovereignty_flag_injection_blocked():
    resources = [_res(f"r{i}") for i in range(3)]
    attack = SovereigntyFlagInjectionAttack(_human(), resources)
    result = attack.run()
    assert result.blocked is True
    assert result.residual_risk == "None within TCB."


def test_confidence_inflation_blocked():
    attack = ConfidenceInflationAttack(_human(), _res("ledger"))
    result = attack.run()
    assert result.blocked is True


def test_malicious_agent_all_attempts():
    alice = _human()
    reg = OwnershipRegistry()
    agent = MaliciousAgent("Mal", alice, reg)
    verifier = FreedomVerifier(reg)
    target = _res("target")

    # No claims granted -> read/write denied
    assert agent.attempt_read(target, verifier).permitted is False
    assert agent.attempt_write(target, verifier).permitted is False
    # Sovereignty / coercion / dominion flags -> always denied
    assert agent.attempt_escalate(verifier).permitted is False
    assert agent.attempt_coerce(alice, verifier).permitted is False
    assert agent.attempt_govern_human(alice, verifier).permitted is False


# --------------------------------------------------------------------------- #
# adapters/mcp_gate.py  (pure-Python adapter, no MCP dependency)
# --------------------------------------------------------------------------- #

from authgate.adapters.langgraph import (  # noqa: E402
    FreedomGraphNode,
    make_verified_tool,
)
from authgate.adapters.mcp_gate import MCPGate, MCPToolCall  # noqa: E402
from authgate.kernel.entities import RightsClaim  # noqa: E402


def _machine_with_claim(reg: OwnershipRegistry, owner: Entity, res: Resource) -> Entity:
    bot = Entity("Bot", AgentType.MACHINE)
    reg.register_machine(bot, owner)
    reg.add_claim(RightsClaim(bot, res, can_read=True, can_write=True))
    return bot


def test_mcp_gate_permits_with_claim():
    alice = _human()
    reg = OwnershipRegistry()
    res = _res("report")
    bot = _machine_with_claim(reg, alice, res)
    gate = MCPGate(FreedomVerifier(reg), actor=bot)

    result = gate.call_tool("read_file", {"path": "report"}, resources_read=[res])
    assert result.permitted is True
    assert result.error_message == ""


def test_mcp_gate_blocks_and_raises():
    alice = _human()
    reg = OwnershipRegistry()
    bot = Entity("Bot", AgentType.MACHINE)
    reg.register_machine(bot, alice)
    gate = MCPGate(FreedomVerifier(reg), actor=bot)

    # No claim on the resource -> blocked
    res = _res("secret")
    blocked = gate.check(MCPToolCall("read_file", {}, resources_read=[res]))
    assert blocked.permitted is False
    assert blocked.error_message
    with pytest.raises(PermissionError):
        blocked.raise_if_blocked()
    with pytest.raises(PermissionError):
        gate.call_tool("read_file", {}, resources_read=[res])


def test_mcp_gate_wrap_handler_with_and_without_mapper():
    alice = _human()
    reg = OwnershipRegistry()
    res = _res("data")
    bot = _machine_with_claim(reg, alice, res)
    gate = MCPGate(FreedomVerifier(reg), actor=bot)

    # Without mapper: no resource claims checked, handler runs
    plain = gate.wrap_handler("noop", lambda **kw: "ran")
    assert plain() == "ran"

    # With mapper: maps args -> (reads, writes, executes)
    def mapper(name, kwargs):
        return [res], [], []

    mapped = gate.wrap_handler("read", lambda **kw: "ok", resource_mapper=mapper)
    assert mapped(path="data") == "ok"


# --------------------------------------------------------------------------- #
# adapters/langgraph.py  (pure-Python adapter, no LangGraph dependency)
# --------------------------------------------------------------------------- #

def test_langgraph_verified_tool_permit_and_block():
    alice = _human()
    reg = OwnershipRegistry()
    res = _res("doc")
    bot = _machine_with_claim(reg, alice, res)
    verifier = FreedomVerifier(reg)

    def read_file(x):
        return x * 2

    safe = make_verified_tool(read_file, verifier, bot, resources_read=[res])
    assert safe.__name__ == "verified_read_file"
    assert safe(21) == 42

    # Blocked: bot has no claim on this other resource
    other = _res("forbidden")
    blocked_tool = make_verified_tool(
        read_file, verifier, bot, resources_read=[other], tool_name="explicit",
    )
    with pytest.raises(PermissionError):
        blocked_tool(1)


def test_langgraph_node_with_and_without_mapper():
    alice = _human()
    reg = OwnershipRegistry()
    res = _res("state_res")
    bot = _machine_with_claim(reg, alice, res)
    verifier = FreedomVerifier(reg)

    # No mapper -> only flags/ownership checked, node runs
    node = FreedomGraphNode("plain", lambda s: s + "!", verifier, bot)
    assert node("hi") == "hi!"

    # Mapper grants reads it holds -> permitted
    node_mapped = FreedomGraphNode(
        "mapped", lambda s: "done", verifier, bot,
        resource_mapper=lambda s: ([res], []),
    )
    assert node_mapped({"k": 1}) == "done"

    # Mapper points at an unheld resource -> blocked
    node_blocked = FreedomGraphNode(
        "blocked", lambda s: "never", verifier, bot,
        resource_mapper=lambda s: ([_res("nope")], []),
    )
    with pytest.raises(PermissionError):
        node_blocked({})
