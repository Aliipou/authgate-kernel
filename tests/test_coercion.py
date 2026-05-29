"""
Tests for Phase 2/O4: Coercion Formal Boundary Conditions.

CoercionAnalyzer detects structural coercion patterns in registry dependency graphs.
"""
import time

import pytest

from authgate.analysis.coercion import (
    CoercionAnalyzer,
    CoercionBoundary,
    CoercionError,
    CoercionPattern,
    CoercionRisk,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry


def _human(name: str) -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str) -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(scope: str = "/data/", rtype: ResourceType = ResourceType.DATASET) -> Resource:
    return Resource("data", rtype, scope=scope)


def _registry(*args: RightsClaim) -> OwnershipRegistry:
    reg = OwnershipRegistry()
    machines_seen: set[str] = set()
    for claim in args:
        if claim.holder.is_machine() and claim.holder.name not in machines_seen:
            delegated_by = getattr(claim, "delegated_by", None)
            owner = delegated_by if (delegated_by and delegated_by.is_human()) else _human("default-owner")
            reg.register_machine(claim.holder, owner)
            machines_seen.add(claim.holder.name)
        reg.add_claim(claim)
    return reg


# ── CoercionRisk structure ────────────────────────────────────────────────────

class TestCoercionRiskStructure:
    def test_risk_is_coercive_high(self):
        risk = CoercionRisk(
            machine_name="bot",
            patterns=(CoercionPattern.DEPENDENCY_MONOPOLY,),
            dependency_fraction=0.8,
            essential_scopes=("",),
            risk_level="HIGH",
            description="test",
        )
        assert risk.is_coercive()

    def test_risk_not_coercive_low(self):
        risk = CoercionRisk(
            machine_name="bot",
            patterns=(CoercionPattern.CONFIDENCE_ASYMMETRY,),
            dependency_fraction=0.1,
            essential_scopes=("/data/",),
            risk_level="LOW",
            description="test",
        )
        assert not risk.is_coercive()

    def test_risk_is_coercive_critical(self):
        risk = CoercionRisk(
            machine_name="bot",
            patterns=(CoercionPattern.DEPENDENCY_MONOPOLY, CoercionPattern.REVOCATION_BLOCKER),
            dependency_fraction=1.0,
            essential_scopes=("",),
            risk_level="CRITICAL",
            description="test",
        )
        assert risk.is_coercive()


# ── Analyzer: clean registry ──────────────────────────────────────────────────

class TestCleanRegistry:
    def test_empty_registry_no_risks(self):
        reg = OwnershipRegistry()
        risks = CoercionAnalyzer().analyze(reg)
        assert risks == []

    def test_single_machine_single_human_no_monopoly(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource("/data/"), can_read=True, delegated_by=alice))
        risks = CoercionAnalyzer().analyze(reg)
        monopoly_risks = [r for r in risks if CoercionPattern.DEPENDENCY_MONOPOLY in r.patterns]
        assert monopoly_risks == []

    def test_distributed_delegation_no_risk(self):
        alice = _human("alice")
        bob = _human("bob")
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, bob)
        reg.add_claim(RightsClaim(bot_a, _resource("/a/"), can_read=True, delegated_by=alice))
        reg.add_claim(RightsClaim(bot_b, _resource("/b/"), can_read=True, delegated_by=bob))
        risks = CoercionAnalyzer().analyze(reg)
        monopoly = [r for r in risks if CoercionPattern.DEPENDENCY_MONOPOLY in r.patterns]
        assert monopoly == []


# ── Dependency monopoly ───────────────────────────────────────────────────────

class TestDependencyMonopoly:
    def test_single_machine_all_humans_flagged(self):
        alice = _human("alice")
        bob = _human("bob")
        carol = _human("carol")
        bot = _machine("monopoly-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for human in [alice, bob, carol]:
            reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=human))
        risks = CoercionAnalyzer().analyze(reg)
        assert any(CoercionPattern.DEPENDENCY_MONOPOLY in r.patterns for r in risks)

    def test_monopoly_machine_identified_by_name(self):
        alice = _human("alice")
        bob = _human("bob")
        bot = _machine("mono-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for h in [alice, bob]:
            reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=h))
        risks = CoercionAnalyzer().analyze(reg)
        mono = [r for r in risks if CoercionPattern.DEPENDENCY_MONOPOLY in r.patterns]
        assert mono
        assert mono[0].machine_name == "mono-bot"

    def test_exactly_50pct_not_flagged(self):
        # threshold is > 0.5, so exactly 50% should not flag
        alice = _human("alice")
        bob = _human("bob")
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, bob)
        reg.add_claim(RightsClaim(bot_a, _resource(), can_read=True, delegated_by=alice))
        reg.add_claim(RightsClaim(bot_b, _resource(), can_read=True, delegated_by=bob))
        risks = CoercionAnalyzer().analyze(reg)
        mono = [r for r in risks if CoercionPattern.DEPENDENCY_MONOPOLY in r.patterns]
        assert mono == []


# ── Root scope / revocation blocker ──────────────────────────────────────────

class TestRootScopePatterns:
    def test_root_scope_no_expiry_flagged_revocation_blocker(self):
        alice = _human("alice")
        bot = _machine("root-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(
            bot, Resource("all", ResourceType.FILE, scope=""),
            can_read=True, can_write=True, delegated_by=alice
        ))
        risks = CoercionAnalyzer().analyze(reg)
        assert any(CoercionPattern.REVOCATION_BLOCKER in r.patterns for r in risks)

    def test_root_scope_with_expiry_no_revocation_blocker(self):
        alice = _human("alice")
        bot = _machine("timed-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(
            bot, Resource("all", ResourceType.FILE, scope=""),
            can_read=True, delegated_by=alice,
            expires_at=time.time() + 3600,
        ))
        risks = CoercionAnalyzer().analyze(reg)
        revblock = [r for r in risks if CoercionPattern.REVOCATION_BLOCKER in r.patterns]
        assert revblock == []

    def test_root_scope_detected_as_single_point_of_control(self):
        alice = _human("alice")
        bob = _human("bob")
        bot = _machine("gatekeeper")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for h in [alice, bob]:
            reg.add_claim(RightsClaim(
                bot, Resource("all", ResourceType.FILE, scope=""),
                can_read=True, delegated_by=h,
                expires_at=time.time() + 3600,
            ))
        risks = CoercionAnalyzer().analyze(reg)
        assert any(CoercionPattern.SINGLE_POINT_OF_CONTROL in r.patterns for r in risks)


# ── Coalition lock-in ─────────────────────────────────────────────────────────

class TestCoalitionLockIn:
    def test_coalition_above_threshold_flagged(self):
        humans = [_human(f"h{i}") for i in range(4)]
        bots = [_machine(f"bot{i}") for i in range(3)]
        reg = OwnershipRegistry()
        for i, bot in enumerate(bots):
            reg.register_machine(bot, humans[0])
        # 3 bots each get delegations covering all 4 humans (overlapping)
        for i, bot in enumerate(bots):
            for human in humans:
                reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=human))
        boundary = CoercionBoundary(COALITION_THRESHOLD=0.75)
        risks = CoercionAnalyzer(boundary).analyze(reg)
        coalition = [r for r in risks if CoercionPattern.COALITION_LOCK_IN in r.patterns]
        assert coalition

    def test_single_machine_not_coalition(self):
        alice = _human("alice")
        bob = _human("bob")
        bot = _machine("solo")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=alice))
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=bob))
        risks = CoercionAnalyzer().analyze(reg)
        coalition = [r for r in risks if CoercionPattern.COALITION_LOCK_IN in r.patterns]
        assert coalition == []  # coalition requires >= 2 machines


# ── Risk description ──────────────────────────────────────────────────────────

class TestRiskDescription:
    def test_description_contains_machine_name(self):
        alice = _human("alice")
        bob = _human("bob")
        bot = _machine("bad-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for h in [alice, bob]:
            reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=h))
        risks = CoercionAnalyzer().analyze(reg)
        assert any("bad-bot" in r.description for r in risks)

    def test_risk_level_present(self):
        alice = _human("alice")
        bob = _human("bob")
        bot = _machine("bad-bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for h in [alice, bob]:
            reg.add_claim(RightsClaim(bot, _resource(), can_read=True, delegated_by=h))
        risks = CoercionAnalyzer().analyze(reg)
        for r in risks:
            assert r.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
