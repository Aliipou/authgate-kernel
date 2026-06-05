"""
Coverage tests (batch 9) added on the `nazariye-azadi` branch.

Targets constitutional-economy concentration branches, the sandbox executor
edges, schema-version parsing, the extensions facade, the policy DSL indent
error, and the multi-agent dependency analyzer.
"""
from __future__ import annotations

import pytest

from authgate.analysis.constitutional_economy import (
    ConstitutionalEconomyChecker,
    EconomicViolation,
)
from authgate.analysis.multi_agent_coordinator import (
    AgentStep,
    CoalitionSignal,
    CoalitionViolation,
    DependencyAnalyzer,
    MultiAgentPlan,
)
from authgate.extensions import ExtendedFreedomVerifier, ProposedRule
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.policy_dsl import PolicyDSL, PolicyDSLSyntaxError
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.sandbox_executor import SandboxedExecutor
from authgate.kernel.schema_version import SchemaVersion
from authgate.kernel.verifier import Action


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


def _res(name, rtype=ResourceType.FILE, scope=""):
    return Resource(name, rtype, scope=scope)


# --------------------------------------------------------------------------- #
# constitutional_economy.py
# --------------------------------------------------------------------------- #

def test_economy_resource_concentration_and_unowned_machine():
    reg = OwnershipRegistry()
    m1, m2 = _machine("M1"), _machine("M2")
    # Machines hold claims but are NOT registered -> name_to_owner miss (line 136 continue)
    for r in ("r1", "r2", "r3"):
        reg.add_claim(RightsClaim(m1, _res(r)))
    reg.add_claim(RightsClaim(m2, _res("r4")))

    signals = ConstitutionalEconomyChecker().analyze(reg)
    # HHI across 2 machines exceeds threshold -> RESOURCE_CONCENTRATION (lines 113-114)
    assert any(s.violation == EconomicViolation.RESOURCE_CONCENTRATION for s in signals)


# --------------------------------------------------------------------------- #
# sandbox_executor.py
# --------------------------------------------------------------------------- #

class _PermitVerifier:
    def __init__(self):
        self.registry = OwnershipRegistry()

    def verify(self, action):
        from authgate.kernel.verifier import VerificationResult
        return VerificationResult(action.action_id, True, (), (), 1.0, False)


def test_sandbox_unregistered_tool_denied():
    ex = SandboxedExecutor(_PermitVerifier())
    res = ex.execute(Action("a", _machine()), "ghost", {})  # line 125
    assert res.permitted is False
    assert "not registered" in res.denied_reason


def test_sandbox_extract_rights_all_branches():
    ex = SandboxedExecutor(_PermitVerifier())
    action = Action(
        "a", _machine(),
        resources_read=[_res("net", ResourceType.NETWORK_ENDPOINT)],
        resources_write=[_res("w", ResourceType.MODEL_WEIGHTS)],
        resources_delegate=[_res("d")],
    )
    rights = ex._extract_rights(action)  # lines 151, 160, 162
    assert {"read", "write", "delegate", "network", "model_invoke"} <= rights


# --------------------------------------------------------------------------- #
# schema_version.py
# --------------------------------------------------------------------------- #

def test_schema_version_parse_non_integer():
    with pytest.raises(ValueError):  # lines 34-35
        SchemaVersion.parse("a.b.c")
    with pytest.raises(ValueError):
        SchemaVersion.parse("1.2")  # wrong arity


# --------------------------------------------------------------------------- #
# extensions/__init__.py — facade methods
# --------------------------------------------------------------------------- #

def test_extended_verifier_admit_rule_and_hook():
    ev = ExtendedFreedomVerifier(OwnershipRegistry())
    ok, msg = ev.admit_rule(ProposedRule("r1", "desc"))  # line 127
    assert ok is True
    ev.register_induction_hook(lambda rules: [])           # line 130


# --------------------------------------------------------------------------- #
# policy_dsl.py — indented line without a preceding statement
# --------------------------------------------------------------------------- #

def test_policy_dsl_indented_without_header_raises():
    # Two lines so textwrap.dedent (no common prefix) keeps the first line indented;
    # an indented first line with no open statement -> error (line 191)
    with pytest.raises(PolicyDSLSyntaxError):
        PolicyDSL.parse("    READ proj/x\nALLOW foo")


# --------------------------------------------------------------------------- #
# multi_agent_coordinator.py
# --------------------------------------------------------------------------- #

def test_coalition_signal_is_blocking():
    sig = CoalitionSignal(
        violation=list(CoalitionViolation)[0],
        agents_involved=("a", "b"),
        description="x",
        severity="CRITICAL",
    )
    assert sig.is_blocking() is True  # line 40
    low = CoalitionSignal(list(CoalitionViolation)[0], ("a",), "x", "LOW")
    assert low.is_blocking() is False


def test_dependency_analyzer_missing_step_dependency():
    plan = MultiAgentPlan(plan_id="p")
    # step depends on a step_id that does not exist -> dfs hits step is None (93-94)
    plan.add_step(AgentStep(step_id="s1", actor_name="Bot", action_id="a", depends_on=["ghost"]))
    cycles = DependencyAnalyzer().find_cycles(plan)
    assert cycles == []
