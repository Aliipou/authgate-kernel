"""Tests for Phase 2/O3: Human Override Lock-in Detector."""
import time

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.analysis.override_detector import (
    LockInPattern,
    LockInRisk,
    MAX_SAFE_CHAIN_DEPTH,
    OverrideDetector,
)
from authgate.kernel.registry import OwnershipRegistry


def _human(name: str) -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str) -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(scope: str = "/data/") -> Resource:
    return Resource("data", ResourceType.DATASET, scope=scope)


class TestCleanRegistry:
    def test_empty_registry_no_risks(self):
        reg = OwnershipRegistry()
        assert OverrideDetector().detect(reg) == []

    def test_human_with_direct_claim_no_owner_lockout(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, _resource(), can_read=True))
        risks = OverrideDetector().detect(reg)
        lockouts = [r for r in risks if r.pattern == LockInPattern.OWNER_LOCKOUT]
        assert lockouts == []


class TestOwnerLockout:
    def test_owner_without_direct_claims_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        # Alice owns bot but has no direct claims herself
        risks = OverrideDetector().detect(reg)
        lockouts = [r for r in risks if r.pattern == LockInPattern.OWNER_LOCKOUT]
        assert lockouts
        assert "alice" in lockouts[0].affected_humans

    def test_owner_with_direct_claim_not_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, _resource(), can_read=True))
        risks = OverrideDetector().detect(reg)
        lockouts = [r for r in risks if r.pattern == LockInPattern.OWNER_LOCKOUT]
        assert lockouts == []


class TestNoDirectHumanClaims:
    def test_scope_with_only_machine_claims_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource("/machine-only/"), can_read=True))
        risks = OverrideDetector().detect(reg)
        no_human = [r for r in risks if r.pattern == LockInPattern.NO_DIRECT_HUMAN_CLAIMS]
        assert no_human

    def test_scope_with_human_claim_not_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, _resource("/shared/"), can_read=True))
        reg.add_claim(RightsClaim(bot, _resource("/shared/"), can_read=True))
        risks = OverrideDetector().detect(reg)
        no_human = [
            r for r in risks
            if r.pattern == LockInPattern.NO_DIRECT_HUMAN_CLAIMS and r.scope == "/shared/"
        ]
        assert no_human == []


class TestOverrideHorizon:
    def test_claim_beyond_horizon_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        far_future = time.time() + 365 * 24 * 3600  # 1 year
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True, expires_at=far_future))
        detector = OverrideDetector(override_horizon=7 * 24 * 3600)  # 7-day horizon
        risks = detector.detect(reg)
        horizon_risks = [r for r in risks if r.pattern == LockInPattern.OVERRIDE_HORIZON_EXCEEDED]
        assert horizon_risks

    def test_claim_within_horizon_not_flagged(self):
        alice = _human("alice")
        bot = _machine("bot")
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        near_future = time.time() + 3600  # 1 hour
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True, expires_at=near_future))
        detector = OverrideDetector(override_horizon=7 * 24 * 3600)
        risks = detector.detect(reg)
        horizon_risks = [r for r in risks if r.pattern == LockInPattern.OVERRIDE_HORIZON_EXCEEDED]
        assert horizon_risks == []


class TestLockInRisk:
    def test_is_critical(self):
        risk = LockInRisk(
            pattern=LockInPattern.OWNER_LOCKOUT,
            scope="",
            affected_humans=("alice",),
            severity="CRITICAL",
            description="test",
        )
        assert risk.is_critical()

    def test_not_critical_low(self):
        risk = LockInRisk(
            pattern=LockInPattern.OVERRIDE_HORIZON_EXCEEDED,
            scope="",
            affected_humans=(),
            severity="LOW",
            description="test",
        )
        assert not risk.is_critical()
