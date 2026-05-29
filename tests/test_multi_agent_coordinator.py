"""Tests for Phase 3/O2: Multi-Agent Coordination."""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.multi_agent_coordinator import (
    AgentStep,
    CoalitionChecker,
    CoalitionViolation,
    DependencyAnalyzer,
    MultiAgentPlan,
)
from authgate.kernel.registry import OwnershipRegistry


def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(scope: str = "/data/", rtype: ResourceType = ResourceType.DATASET) -> Resource:
    return Resource("data", rtype, scope=scope)


def _reg(*machines_and_owners) -> OwnershipRegistry:
    reg = OwnershipRegistry()
    for machine, owner in machines_and_owners:
        reg.register_machine(machine, owner)
    return reg


class TestMultiAgentPlan:
    def test_add_steps(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "read", resources_read=[_resource()]))
        plan.add_step(AgentStep("s2", "bot-b", "write", resources_write=[_resource()]))
        assert len(plan.steps) == 2
        assert plan.actors() == {"bot-a", "bot-b"}

    def test_step_ids(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot", "read"))
        plan.add_step(AgentStep("s2", "bot", "write"))
        assert plan.step_ids() == {"s1", "s2"}


class TestDependencyAnalyzer:
    def test_no_cycles_linear_plan(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "read"))
        plan.add_step(AgentStep("s2", "bot-b", "write", depends_on=["s1"]))
        analyzer = DependencyAnalyzer()
        assert analyzer.find_cycles(plan) == []

    def test_detects_direct_cycle(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "a", depends_on=["s2"]))
        plan.add_step(AgentStep("s2", "bot-b", "b", depends_on=["s1"]))
        analyzer = DependencyAnalyzer()
        cycles = analyzer.find_cycles(plan)
        assert cycles  # at least one cycle detected

    def test_topological_order_no_cycles(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "read"))
        plan.add_step(AgentStep("s2", "bot-b", "transform", depends_on=["s1"]))
        plan.add_step(AgentStep("s3", "bot-c", "write", depends_on=["s2"]))
        analyzer = DependencyAnalyzer()
        order = analyzer.topological_order(plan)
        assert order is not None
        assert order.index("s1") < order.index("s2") < order.index("s3")

    def test_topological_order_with_cycle_returns_none(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "a", depends_on=["s2"]))
        plan.add_step(AgentStep("s2", "bot-b", "b", depends_on=["s1"]))
        analyzer = DependencyAnalyzer()
        assert analyzer.topological_order(plan) is None

    def test_orphaned_step_detected(self):
        alice = _human()
        bot_registered = _machine("bot-registered")
        reg = OwnershipRegistry()
        reg.register_machine(bot_registered, alice)

        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-unknown", "read"))  # not in registry
        plan.add_step(AgentStep("s2", "bot-registered", "write"))
        analyzer = DependencyAnalyzer()
        orphaned = analyzer.find_orphaned_steps(plan, reg)
        assert "s1" in orphaned
        assert "s2" not in orphaned


class TestCoalitionChecker:
    def test_clean_plan_no_signals(self):
        alice = _human()
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        reg.add_claim(RightsClaim(bot_a, _resource("/data/a/"), can_read=True))
        reg.add_claim(RightsClaim(bot_b, _resource("/data/b/"), can_write=True))

        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "read", resources_read=[_resource("/data/a/")]))
        plan.add_step(AgentStep("s2", "bot-b", "write", resources_write=[_resource("/data/b/")]))

        checker = CoalitionChecker()
        signals = checker.check(plan, reg)
        blocking = [s for s in signals if s.is_blocking()]
        assert blocking == []

    def test_cycle_is_critical(self):
        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "a", depends_on=["s2"]))
        plan.add_step(AgentStep("s2", "bot-b", "b", depends_on=["s1"]))
        reg = OwnershipRegistry()
        checker = CoalitionChecker()
        signals = checker.check(plan, reg)
        cycles = [s for s in signals if s.violation == CoalitionViolation.CIRCULAR_DEPENDENCY]
        assert cycles
        assert cycles[0].severity == "CRITICAL"

    def test_resource_contention_detected(self):
        alice = _human()
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        shared = _resource("/shared/")
        reg.add_claim(RightsClaim(bot_a, shared, can_write=True))
        reg.add_claim(RightsClaim(bot_b, shared, can_write=True))

        plan = MultiAgentPlan(plan_id="p1")
        plan.add_step(AgentStep("s1", "bot-a", "write", resources_write=[shared]))
        plan.add_step(AgentStep("s2", "bot-b", "write", resources_write=[shared]))

        checker = CoalitionChecker()
        signals = checker.check(plan, reg)
        contention = [s for s in signals if s.violation == CoalitionViolation.RESOURCE_CONTENTION]
        assert contention

    def test_scope_escalation_detected(self):
        alice = _human()
        bot = _machine("bot-a")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource("/data/"), can_read=True))

        plan = MultiAgentPlan(plan_id="p1")
        # Bot tries to access /etc/ — outside its /data/ scope
        plan.add_step(AgentStep("s1", "bot-a", "read",
                                resources_read=[Resource("cfg", ResourceType.FILE, scope="/etc/")]))

        checker = CoalitionChecker()
        signals = checker.check(plan, reg)
        escalations = [s for s in signals if s.violation == CoalitionViolation.SCOPE_ESCALATION]
        assert escalations

    def test_authority_aggregation_root_scope(self):
        alice = _human()
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        # Agents only have /data/ scope
        reg.add_claim(RightsClaim(bot_a, _resource("/data/"), can_read=True))
        reg.add_claim(RightsClaim(bot_b, _resource("/data/"), can_read=True))

        plan = MultiAgentPlan(plan_id="p1")
        # But coalition plan accesses root scope
        root_res = Resource("all", ResourceType.FILE, scope="")
        plan.add_step(AgentStep("s1", "bot-a", "read", resources_read=[root_res]))
        plan.add_step(AgentStep("s2", "bot-b", "read", resources_read=[root_res]))

        checker = CoalitionChecker()
        signals = checker.check(plan, reg)
        agg = [s for s in signals if s.violation == CoalitionViolation.AUTHORITY_AGGREGATION]
        assert agg
