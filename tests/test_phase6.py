"""
Phase 6 — Machine Civilization Safety tests.

O1: Recursive Agent Governance  (recursive_governance.py)
O2: Constitutional AI Economies (constitutional_economy.py)
O3: Sovereign Exit Guarantees   (exit_guarantees.py)
"""
from __future__ import annotations

import time
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry

from authgate.kernel.recursive_governance import (
    RecursiveGovernanceChecker,
    GovernanceViolation,
    MAX_RECURSION_DEPTH,
    MAX_SUBORDINATES_PER_AGENT,
)
from authgate.kernel.constitutional_economy import (
    ConstitutionalEconomyChecker,
    EconomicViolation,
    OLIGARCHY_THRESHOLD,
)
from authgate.kernel.exit_guarantees import (
    SovereignExitChecker,
    ExitViolation,
    MAX_EXIT_SAFE_DEPTH,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def alice():
    return Entity("Alice", AgentType.HUMAN)

@pytest.fixture
def bob():
    return Entity("Bob", AgentType.HUMAN)

def _machine(name: str) -> Entity:
    return Entity(name, AgentType.MACHINE)

def _resource(name: str, rtype: ResourceType = ResourceType.FILE) -> Resource:
    return Resource(name, rtype, scope=f"/{name}/")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6/O1 — Recursive Agent Governance
# ═══════════════════════════════════════════════════════════════════════════

class TestRecursiveGovernance:

    def test_clean_chain_no_violations(self):
        """A 3-deep chain within limits produces no signals."""
        g = RecursiveGovernanceChecker()
        g.add_link("Alice", "Bot1")
        g.add_link("Bot1", "Bot2")
        g.add_link("Bot2", "Bot3")
        assert g.check() == []

    def test_depth_exceeded_flagged(self):
        """A chain exceeding MAX_RECURSION_DEPTH is flagged."""
        g = RecursiveGovernanceChecker()
        prev = "Alice"
        for i in range(MAX_RECURSION_DEPTH + 2):
            node = f"Bot{i}"
            g.add_link(prev, node)
            prev = node

        signals = g.check()
        violations = {s.violation for s in signals}
        assert GovernanceViolation.DEPTH_EXCEEDED in violations

    def test_cycle_detected(self):
        """A → B → C → A is a governance cycle."""
        g = RecursiveGovernanceChecker()
        g.add_link("A", "B")
        g.add_link("B", "C")
        g.add_link("C", "A")
        signals = g.check()
        violations = {s.violation for s in signals}
        assert GovernanceViolation.CIRCULAR_GOVERNANCE in violations

    def test_anti_feudal_fan_out(self):
        """Single governor with too many direct subordinates is anti-feudal."""
        g = RecursiveGovernanceChecker()
        for i in range(MAX_SUBORDINATES_PER_AGENT + 1):
            g.add_link("Overlord", f"Bot{i}")
        signals = g.check()
        violations = {s.violation for s in signals}
        assert GovernanceViolation.ANTI_FEUDAL_FAN_OUT in violations

    def test_feudal_concentration_hhi(self):
        """Competing roots where one dominates raises HHI flag (feudal concentration)."""
        g = RecursiveGovernanceChecker(hhi_threshold=0.3)
        # Two independent governance roots: Alice controls 7 nodes, Bob controls 1
        g.add_link("Alice", "Mid")
        for i in range(5):
            g.add_link("Mid", f"Leaf{i}")  # Alice → Mid → 5 leaves = 7 total nodes under Alice
        g.add_link("Bob", "BobBot")        # Bob controls 1 node
        signals = g.check()
        violations = {s.violation for s in signals}
        assert GovernanceViolation.FEUDAL_CONCENTRATION in violations

    def test_revocation_propagation(self):
        """Revoking Mid removes all nodes it governs transitively."""
        g = RecursiveGovernanceChecker()
        g.add_link("Alice", "Mid")
        g.add_link("Mid", "Leaf1")
        g.add_link("Mid", "Leaf2")
        g.add_link("Leaf1", "DeepLeaf")
        revoked = g.propagate_revocation("Mid")
        assert "Leaf1" in revoked
        assert "Leaf2" in revoked
        assert "DeepLeaf" in revoked
        assert "Mid" not in revoked
        assert "Alice" not in revoked

    def test_depth_of_node(self):
        """depth_of() returns correct depth in a linear chain."""
        g = RecursiveGovernanceChecker()
        g.add_link("Alice", "Bot1")
        g.add_link("Bot1", "Bot2")
        g.add_link("Bot2", "Bot3")
        assert g.depth_of("Alice") == 0
        assert g.depth_of("Bot1") == 1
        assert g.depth_of("Bot3") == 3

    def test_parallel_branches_no_violation(self):
        """Two independent branches under one root are fine if within limits."""
        g = RecursiveGovernanceChecker()
        g.add_link("Alice", "BranchA")
        g.add_link("Alice", "BranchB")
        g.add_link("BranchA", "LeafA1")
        g.add_link("BranchB", "LeafB1")
        assert g.check() == []


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6/O2 — Constitutional AI Economies
# ═══════════════════════════════════════════════════════════════════════════

class TestConstitutionalEconomy:

    def _build_registry(self, alice: Entity) -> OwnershipRegistry:
        reg = OwnershipRegistry()
        return reg

    def test_clean_registry_no_violations(self, alice):
        reg = OwnershipRegistry()
        bot = _machine("Bot1")
        reg.register_machine(bot, alice)
        r1 = _resource("doc1")
        reg.add_claim(RightsClaim(bot, r1, can_read=True))
        reg.add_claim(RightsClaim(alice, r1, can_read=True))

        checker = ConstitutionalEconomyChecker()
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.MACHINE_OLIGARCHY not in violations

    def test_machine_oligarchy_detected(self, alice):
        """Machine holding >33% of all resources triggers oligarchy flag."""
        reg = OwnershipRegistry()
        bot = _machine("MegaBot")
        reg.register_machine(bot, alice)
        # Bot gets 5 resources, Alice gets 1 — bot share = 5/6 > 0.33
        resources = [_resource(f"res{i}") for i in range(5)]
        for r in resources:
            reg.add_claim(RightsClaim(bot, r, can_read=True))
        reg.add_claim(RightsClaim(alice, _resource("human-res"), can_read=True))

        checker = ConstitutionalEconomyChecker(oligarchy_threshold=0.33)
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.MACHINE_OLIGARCHY in violations

    def test_sovereignty_erosion_detected(self, alice):
        """Machine controls more resources than its human owner."""
        reg = OwnershipRegistry()
        bot = _machine("HelperBot")
        reg.register_machine(bot, alice)
        # Alice has 1 direct resource, bot has 4
        reg.add_claim(RightsClaim(alice, _resource("alice-data"), can_read=True))
        for i in range(4):
            reg.add_claim(RightsClaim(bot, _resource(f"bot-data{i}"), can_read=True))

        checker = ConstitutionalEconomyChecker()
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.SOVEREIGNTY_EROSION in violations

    def test_irreversible_lock_in_detected(self, alice):
        """Non-expiring machine claim on IDENTITY resource with no human co-claim."""
        reg = OwnershipRegistry()
        bot = _machine("ProfileBot")
        reg.register_machine(bot, alice)
        identity_res = Resource("user-identity", ResourceType.IDENTITY, scope="/identity/")
        # No expires_at → permanent claim
        reg.add_claim(RightsClaim(bot, identity_res, can_read=True))
        # Alice has NO claim on user-identity

        checker = ConstitutionalEconomyChecker()
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.IRREVERSIBLE_LOCK_IN in violations

    def test_no_lock_in_when_human_holds_coclaim(self, alice):
        """Human co-claim on identity resource removes lock-in signal."""
        reg = OwnershipRegistry()
        bot = _machine("ProfileBot")
        reg.register_machine(bot, alice)
        identity_res = Resource("user-identity", ResourceType.IDENTITY, scope="/identity/")
        reg.add_claim(RightsClaim(bot, identity_res, can_read=True))
        reg.add_claim(RightsClaim(alice, identity_res, can_read=True))

        checker = ConstitutionalEconomyChecker()
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.IRREVERSIBLE_LOCK_IN not in violations

    def test_high_value_monopoly_detected(self, alice):
        """Single machine holding all high-value resources triggers monopoly."""
        reg = OwnershipRegistry()
        bot = _machine("MonopolyBot")
        reg.register_machine(bot, alice)
        hv1 = Resource("hv1", ResourceType.IDENTITY, scope="/id/")
        hv2 = Resource("hv2", ResourceType.BEHAVIORAL_PROFILE, scope="/profile/")
        hv3 = Resource("hv3", ResourceType.DIGITAL_TWIN, scope="/twin/")
        for r in [hv1, hv2, hv3]:
            reg.add_claim(RightsClaim(bot, r, can_read=True))

        checker = ConstitutionalEconomyChecker()
        signals = checker.analyze(reg)
        violations = {s.violation for s in signals}
        assert EconomicViolation.HIGH_VALUE_MONOPOLY in violations

    def test_empty_registry_no_crash(self):
        """Checker handles empty registry gracefully."""
        reg = OwnershipRegistry()
        checker = ConstitutionalEconomyChecker()
        assert checker.analyze(reg) == []


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6/O3 — Sovereign Exit Guarantees
# ═══════════════════════════════════════════════════════════════════════════

class TestSovereignExitGuarantees:

    def test_clean_system_exit_intact(self, alice):
        """Human with direct claim and owned machine: all exit guarantees intact."""
        reg = OwnershipRegistry()
        bot = _machine("Bot1")
        reg.register_machine(bot, alice)
        r = _resource("data")
        reg.add_claim(RightsClaim(alice, r, can_read=True))
        reg.add_claim(RightsClaim(bot, r, can_read=True))

        checker = SovereignExitChecker()
        assert checker.exit_rights_intact(reg)

    def test_exit_blocked_no_foothold(self, alice):
        """Human appears as owner name but holds no claims — flagged EXIT_BLOCKED."""
        reg = OwnershipRegistry()
        bot = _machine("Bot1")
        reg.register_machine(bot, alice)
        # Alice has no direct claims, bot gets some
        r = _resource("data")
        reg.add_claim(RightsClaim(bot, r, can_read=True))

        checker = SovereignExitChecker()
        signals = checker.check(reg)
        violations = {s.violation for s in signals}
        assert ExitViolation.EXIT_BLOCKED in violations

    def test_identity_lock_flagged(self, alice):
        """Machine holds identity resource with no human co-claim."""
        reg = OwnershipRegistry()
        bot = _machine("IdBot")
        reg.register_machine(bot, alice)
        id_res = Resource("my-identity", ResourceType.IDENTITY, scope="/id/")
        reg.add_claim(RightsClaim(bot, id_res, can_read=True))
        reg.add_claim(RightsClaim(alice, _resource("something-else"), can_read=True))

        checker = SovereignExitChecker()
        signals = checker.check(reg)
        violations = {s.violation for s in signals}
        assert ExitViolation.IDENTITY_LOCKED in violations

    def test_identity_portability_preserved(self, alice):
        """Human co-claim on identity resource: no portability violation."""
        reg = OwnershipRegistry()
        bot = _machine("IdBot")
        reg.register_machine(bot, alice)
        id_res = Resource("my-identity", ResourceType.IDENTITY, scope="/id/")
        reg.add_claim(RightsClaim(bot, id_res, can_read=True))
        reg.add_claim(RightsClaim(alice, id_res, can_read=True))

        checker = SovereignExitChecker()
        signals = checker.check(reg)
        violations = {s.violation for s in signals}
        assert ExitViolation.IDENTITY_LOCKED not in violations

    def test_exit_rights_intact_returns_bool(self, alice):
        """exit_rights_intact() is True when no violations exist."""
        reg = OwnershipRegistry()
        bot = _machine("Bot")
        reg.register_machine(bot, alice)
        r = _resource("d")
        reg.add_claim(RightsClaim(alice, r, can_read=True))

        checker = SovereignExitChecker()
        assert checker.exit_rights_intact(reg) is True

    def test_multiple_humans_independent_checks(self, alice, bob):
        """Each human's exit rights are checked independently."""
        reg = OwnershipRegistry()
        bot_a = _machine("BotA")
        bot_b = _machine("BotB")
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, bob)

        r = _resource("shared")
        # Alice has a direct claim; Bob does not
        reg.add_claim(RightsClaim(alice, r, can_read=True))
        reg.add_claim(RightsClaim(bot_a, r, can_read=True))
        reg.add_claim(RightsClaim(bot_b, r, can_read=True))

        checker = SovereignExitChecker()
        signals = checker.check(reg)
        affected = {s.affected_human for s in signals}
        # Bob should be flagged, Alice should not
        assert "Bob" in affected
        assert "Alice" not in affected

    def test_empty_registry_no_crash(self):
        """Checker handles empty registry gracefully."""
        reg = OwnershipRegistry()
        checker = SovereignExitChecker()
        assert checker.check(reg) == []
