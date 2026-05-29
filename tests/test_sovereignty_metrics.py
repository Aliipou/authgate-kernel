"""
Sovereignty metrics tests — Phase 4, O3.

Tests for SovereigntyAnalyzer and SovereigntySnapshot covering all five
metric dimensions: agency preservation, delegation depth, dependency
centralization, reversibility, and autonomy degradation.
"""
from __future__ import annotations

import time

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.sovereignty_metrics import SovereigntyAnalyzer, SovereigntySnapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human(name: str) -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str) -> Entity:
    return Entity(name, AgentType.MACHINE)


def _file(name: str, scope: str = "") -> Resource:
    return Resource(name, ResourceType.FILE, scope=scope)


def _empty_registry() -> OwnershipRegistry:
    return OwnershipRegistry()


def _basic_registry() -> tuple[OwnershipRegistry, Entity, Entity, Resource]:
    """One human, one machine, one claim — the minimal useful setup."""
    human = _human("alice")
    bot = _machine("bot")
    res = _file("/data/x", scope="/data/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, human)
    reg.add_claim(RightsClaim(bot, res, can_read=True))
    return reg, human, bot, res


# ---------------------------------------------------------------------------
# Empty registry
# ---------------------------------------------------------------------------

class TestEmptyRegistry:
    """An empty registry has perfect sovereignty scores by convention."""

    def test_empty_machine_count(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.machine_count == 0

    def test_empty_agency_preservation_perfect(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.agency_preservation_score == 1.0

    def test_empty_reversibility_perfect(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.reversibility_index == 1.0

    def test_empty_autonomy_degradation_zero(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.autonomy_degradation_rate == 0.0

    def test_empty_centralization_zero(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.dependency_centralization == 0.0

    def test_empty_delegation_depth_zero(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.max_delegation_depth == 0
        assert snap.mean_delegation_depth == 0.0

    def test_empty_risk_level_low(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.sovereignty_risk_level() == "LOW"

    def test_empty_total_claims_zero(self):
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        assert snap.total_claims == 0


# ---------------------------------------------------------------------------
# Single machine with owner
# ---------------------------------------------------------------------------

class TestSingleMachineWithOwner:
    """One machine owned by one human — best possible real configuration."""

    def test_machine_count_is_one(self):
        reg, _, _, _ = _basic_registry()
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.machine_count == 1

    def test_agency_preservation_perfect(self):
        reg, _, _, _ = _basic_registry()
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.agency_preservation_score == 1.0

    def test_single_owner_centralization_is_one(self):
        """One human owns one machine → monopoly → centralization = 1.0."""
        reg, _, _, _ = _basic_registry()
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.dependency_centralization == 1.0

    def test_direct_claim_no_delegation(self):
        reg, _, _, _ = _basic_registry()
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.delegated_claims == 0
        assert snap.autonomy_degradation_rate == 0.0


# ---------------------------------------------------------------------------
# Machine without owner validation
# ---------------------------------------------------------------------------

class TestMachineWithoutOwner:
    """register_machine enforces that owner must be HUMAN."""

    def test_register_machine_requires_human_owner(self):
        """Passing a MACHINE as owner raises TypeError — not a silent failure."""
        reg = OwnershipRegistry()
        bot = _machine("bot")
        not_a_human = _machine("other_bot")
        with pytest.raises(TypeError):
            reg.register_machine(bot, not_a_human)

    def test_register_machine_non_machine_raises(self):
        """Passing a HUMAN as the machine parameter also raises TypeError."""
        reg = OwnershipRegistry()
        human = _human("alice")
        with pytest.raises(TypeError):
            reg.register_machine(human, human)


# ---------------------------------------------------------------------------
# Reversibility
# ---------------------------------------------------------------------------

class TestReversibility:
    """reversibility_index = time_bounded_claims / total_claims."""

    def test_all_time_bounded(self):
        human = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        future = time.time() + 3600
        for i in range(5):
            res = _file(f"/data/{i}", scope="/data/")
            reg.add_claim(RightsClaim(bot, res, can_read=True, expires_at=future))
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.reversibility_index == 1.0

    def test_no_time_bounded(self):
        human = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        for i in range(5):
            res = _file(f"/data/{i}", scope="/data/")
            reg.add_claim(RightsClaim(bot, res, can_read=True))  # no expires_at
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.reversibility_index == 0.0

    def test_half_time_bounded(self):
        human = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        future = time.time() + 3600
        for i in range(4):
            res = _file(f"/data/{i}", scope="/data/")
            expires = future if i % 2 == 0 else None
            reg.add_claim(RightsClaim(bot, res, can_read=True, expires_at=expires))
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.reversibility_index == pytest.approx(0.5)

    def test_time_bounded_counts_correctly(self):
        human = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        future = time.time() + 3600
        reg.add_claim(RightsClaim(bot, _file("/a"), can_read=True, expires_at=future))
        reg.add_claim(RightsClaim(bot, _file("/b"), can_read=True))
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.time_bounded_claims == 1
        assert snap.total_claims == 2


# ---------------------------------------------------------------------------
# Autonomy degradation (delegated claims)
# ---------------------------------------------------------------------------

class TestAutonomyDegradation:
    """autonomy_degradation_rate = delegated_claims / total_claims."""

    def test_delegated_claims_inflate_rate(self):
        human = _human("alice")
        bot = _machine("bot")
        sub = _machine("sub_bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.register_machine(sub, human)
        res = _file("/shared", scope="/")
        # Direct claim for bot
        reg.add_claim(RightsClaim(bot, res, can_read=True, can_write=True, can_delegate=True))
        # Delegated claim for sub
        reg.delegate(RightsClaim(sub, res, can_read=True, confidence=0.9), delegated_by=bot)
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.delegated_claims == 1
        assert snap.autonomy_degradation_rate == pytest.approx(1 / 2)

    def test_all_direct_claims_zero_degradation(self):
        reg, _, _, _ = _basic_registry()
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.autonomy_degradation_rate == 0.0


# ---------------------------------------------------------------------------
# Dependency centralization
# ---------------------------------------------------------------------------

class TestDependencyCentralization:
    """HHI-normalised: 1.0 = all machines one owner, 0.0 = perfectly spread."""

    def test_one_human_all_machines_high_centralization(self):
        alice = _human("alice")
        reg = OwnershipRegistry()
        for i in range(5):
            bot = _machine(f"bot_{i}")
            reg.register_machine(bot, alice)
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.dependency_centralization == pytest.approx(1.0)

    def test_many_humans_each_one_machine_low_centralization(self):
        """N humans each owning exactly 1 machine → centralization = 0.0."""
        reg = OwnershipRegistry()
        for i in range(5):
            human = _human(f"human_{i}")
            bot = _machine(f"bot_{i}")
            reg.register_machine(bot, human)
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.dependency_centralization == pytest.approx(0.0)

    def test_two_humans_unequal_ownership_intermediate(self):
        """3 machines: 2 owned by alice, 1 by bob → intermediate centralization."""
        alice = _human("alice")
        bob = _human("bob")
        reg = OwnershipRegistry()
        reg.register_machine(_machine("b1"), alice)
        reg.register_machine(_machine("b2"), alice)
        reg.register_machine(_machine("b3"), bob)
        snap = SovereigntyAnalyzer().analyze(reg)
        # Should be strictly between 0 and 1
        assert 0.0 < snap.dependency_centralization < 1.0


# ---------------------------------------------------------------------------
# sovereignty_risk_level()
# ---------------------------------------------------------------------------

class TestRiskLevel:
    """Validate that risk levels fire under the right metric combinations."""

    def test_healthy_registry_is_low(self):
        """Perfectly balanced registry: all metrics good → LOW."""
        alice = _human("alice")
        bob = _human("bob")
        future = time.time() + 3600
        reg = OwnershipRegistry()
        for i in range(4):
            human = _human(f"human_{i}")
            bot = _machine(f"bot_{i}")
            reg.register_machine(bot, human)
            res = _file(f"/data/{i}", scope="/data/")
            reg.add_claim(RightsClaim(bot, res, can_read=True, expires_at=future))
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.sovereignty_risk_level() == "LOW"

    def test_zero_reversibility_high_degradation_raises_risk(self):
        """No time-bounded claims + heavy delegation → at least MEDIUM."""
        alice = _human("alice")
        bot = _machine("bot")
        sub = _machine("sub")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.register_machine(sub, alice)
        res = _file("/data", scope="/")
        reg.add_claim(RightsClaim(bot, res, can_read=True, can_write=True, can_delegate=True))
        # Five delegated claims, no expires_at
        for i in range(5):
            sub_res = _file(f"/sub/{i}", scope="/")
            reg.add_claim(RightsClaim(sub, sub_res, can_read=True))
        snap = SovereigntyAnalyzer().analyze(reg)
        assert snap.sovereignty_risk_level() in ("MEDIUM", "HIGH", "CRITICAL")

    def test_explicit_critical_scenario(self):
        """Worst-case: single owner of all, no expires, all delegated, low agency."""
        alice = _human("alice")
        bot = _machine("bot")
        sub = _machine("sub")
        reg = OwnershipRegistry()
        # Only one machine registered — sub is unregistered (not in _machine_owners)
        reg.register_machine(bot, alice)
        res = _file("/root", scope="/")
        reg.add_claim(RightsClaim(bot, res, can_read=True, can_write=True, can_delegate=True))
        # Add many delegated, non-expiring claims via direct add_claim with delegated_by set
        for i in range(9):
            c = RightsClaim(sub, _file(f"/sub/{i}", scope="/"), can_read=True)
            c.delegated_by = bot
            reg.add_claim(c)
        snap = SovereigntyAnalyzer().analyze(reg)
        level = snap.sovereignty_risk_level()
        # autonomy_degradation_rate ≈ 9/10 = 0.9 (>0.7 → +2)
        # reversibility_index = 0.0 (<0.2 → +2)
        # dependency_centralization = 1.0 (>0.8 → +2)
        # total score ≥ 6 → at least HIGH
        assert level in ("HIGH", "CRITICAL")

    def test_snapshot_is_frozen_dataclass(self):
        """SovereigntySnapshot is a frozen dataclass — mutating it raises FrozenInstanceError."""
        snap = SovereigntyAnalyzer().analyze(_empty_registry())
        with pytest.raises(Exception):  # FrozenInstanceError
            snap.machine_count = 99  # type: ignore[misc]

    def test_analyze_accepts_live_registry(self):
        """Analyzer freezes the registry internally — live registries are safe to pass."""
        reg, _, _, _ = _basic_registry()
        assert not reg._frozen
        snap = SovereigntyAnalyzer().analyze(reg)
        assert isinstance(snap, SovereigntySnapshot)

    def test_analyze_accepts_frozen_registry(self):
        reg, _, _, _ = _basic_registry()
        frozen = reg.freeze()
        snap = SovereigntyAnalyzer().analyze(frozen)
        assert isinstance(snap, SovereigntySnapshot)
