"""
ConsentCapability tests — authgate-kernel Phase 2 seed.

Tests: consent validity, expiry, scope containment, human-only constraint,
       ConsentVerifier integration with kernel gate.

Run: pytest tests/test_consent.py -v
"""
from __future__ import annotations

import time

import pytest

from authgate.kernel.consent import ConsentCapability, ConsentVerifier, ConsentViolation
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human(name="alice"):  return Entity(name, AgentType.HUMAN)
def _machine(name="bot"):  return Entity(name, AgentType.MACHINE)
def _resource(name="data", scope="/data/"):
    return Resource(name, ResourceType.DATASET, scope=scope)

def _claim(bot, res):
    return RightsClaim(bot, res, can_read=True, can_write=True)


# ---------------------------------------------------------------------------
# ConsentCapability.is_consent_valid
# ---------------------------------------------------------------------------

class TestConsentValid:
    def test_no_consent_required_always_valid(self):
        cap = ConsentCapability(claim=_claim(_machine(), _resource()), consent_required=False)
        assert cap.is_consent_valid()

    def test_consent_required_with_valid_human(self):
        human = _human()
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
        )
        assert cap.is_consent_valid()

    def test_consent_required_no_giver_invalid(self):
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
        )
        assert not cap.is_consent_valid()

    def test_consent_given_by_machine_invalid(self):
        bot = _machine("bot2")  # machine trying to give consent
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=bot,
        )
        assert not cap.is_consent_valid()

    def test_consent_expired(self):
        human = _human()
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
            consent_expires_at=time.time() - 1.0,  # in the past
        )
        assert not cap.is_consent_valid()

    def test_consent_not_yet_expired(self):
        human = _human()
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
            consent_expires_at=time.time() + 3600,
        )
        assert cap.is_consent_valid()

    def test_consent_scope_exact_match(self):
        human = _human()
        res = _resource(scope="/data/alice/")
        cap = ConsentCapability(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",
        )
        assert cap.is_consent_valid()

    def test_consent_scope_child_within_parent(self):
        human = _human()
        res = _resource(scope="/data/alice/reports/")
        cap = ConsentCapability(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",  # resource is within consent scope
        )
        assert cap.is_consent_valid()

    def test_consent_scope_outside_parent(self):
        human = _human()
        res = _resource(scope="/data/bob/")
        cap = ConsentCapability(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",  # bob's scope NOT within alice's
        )
        assert not cap.is_consent_valid()

    def test_consent_violation_reason_no_giver(self):
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
        )
        reason = cap.consent_violation_reason()
        assert reason is not None
        assert "no human" in reason

    def test_consent_violation_reason_machine_giver(self):
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=_machine("bot2"),
        )
        reason = cap.consent_violation_reason()
        assert reason is not None
        assert "not a human" in reason

    def test_consent_violation_reason_expired(self):
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=_human(),
            consent_expires_at=time.time() - 1,
        )
        reason = cap.consent_violation_reason()
        assert "expired" in reason

    def test_no_violation_reason_when_valid(self):
        cap = ConsentCapability(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=_human(),
        )
        assert cap.consent_violation_reason() is None


# ---------------------------------------------------------------------------
# ConsentVerifier
# ---------------------------------------------------------------------------

class TestConsentVerifier:
    def _setup(self):
        human = _human()
        bot   = _machine()
        res   = _resource()
        registry = OwnershipRegistry()
        registry.register_machine(bot, human)
        registry.add_claim(RightsClaim(bot, res, can_read=True, can_write=True))
        frozen   = registry.freeze()
        verifier = FreedomVerifier(frozen)
        return verifier, human, bot, res

    def test_no_consent_caps_no_violations(self):
        verifier, human, bot, res = self._setup()
        cv = ConsentVerifier()
        action = Action("read", actor=bot, resources_read=[res])
        violations = cv.check(action)
        assert violations == []

    def test_valid_consent_no_violations(self):
        verifier, human, bot, res = self._setup()
        claim = _claim(bot, res)
        cap = ConsentCapability(
            claim=claim,
            consent_required=True,
            consent_given_by=human,
        )
        cv = ConsentVerifier(capabilities=[cap])
        action = Action("read", actor=bot, resources_read=[res])
        violations = cv.check(action)
        assert violations == []

    def test_missing_consent_returns_violation(self):
        verifier, human, bot, res = self._setup()
        claim = _claim(bot, res)
        cap = ConsentCapability(
            claim=claim,
            consent_required=True,
            # consent_given_by not set
        )
        cv = ConsentVerifier(capabilities=[cap])
        action = Action("read", actor=bot, resources_read=[res])
        violations = cv.check(action)
        assert len(violations) == 1
        assert isinstance(violations[0], ConsentViolation)
        assert violations[0].action_id == "read"

    def test_consent_str_representation(self):
        v = ConsentViolation("act1", "res1", "expired")
        assert "act1" in str(v)
        assert "expired" in str(v)

    def test_add_capability_dynamically(self):
        verifier, human, bot, res = self._setup()
        cv = ConsentVerifier()
        cap = ConsentCapability(
            claim=_claim(bot, res),
            consent_required=True,
            consent_given_by=human,
        )
        cv.add_capability(cap)
        action = Action("read", actor=bot, resources_read=[res])
        assert cv.check(action) == []
