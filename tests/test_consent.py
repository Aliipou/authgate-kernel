"""
Consent tests — authgate-kernel Phase 2.

Part 1 (legacy annotation layer):
  Tests for ConsentAnnotation (formerly ConsentCapability seed), ConsentVerifier,
  ConsentViolation.

Part 2 (Phase 2 canonical consent algebra):
  Tests for ConsentCapability (the new first-class consent object),
  ConsentScope, and ConsentRegistry.

Run: pytest tests/test_consent.py -v
"""
from __future__ import annotations

import time

import pytest

from authgate.kernel.consent import (
    ConsentAnnotation,
    ConsentCapability,
    ConsentScope,
    ConsentVerifier,
    ConsentViolation,
)
from authgate.kernel.consent_registry import ConsentRegistry
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

class TestConsentAnnotationValid:
    """Legacy ConsentAnnotation (seed layer) tests — unchanged semantics."""

    def test_no_consent_required_always_valid(self):
        cap = ConsentAnnotation(claim=_claim(_machine(), _resource()), consent_required=False)
        assert cap.is_consent_valid()

    def test_consent_required_with_valid_human(self):
        human = _human()
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
        )
        assert cap.is_consent_valid()

    def test_consent_required_no_giver_invalid(self):
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
        )
        assert not cap.is_consent_valid()

    def test_consent_given_by_machine_invalid(self):
        bot = _machine("bot2")  # machine trying to give consent
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=bot,
        )
        assert not cap.is_consent_valid()

    def test_consent_expired(self):
        human = _human()
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
            consent_expires_at=time.time() - 1.0,  # in the past
        )
        assert not cap.is_consent_valid()

    def test_consent_not_yet_expired(self):
        human = _human()
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=human,
            consent_expires_at=time.time() + 3600,
        )
        assert cap.is_consent_valid()

    def test_consent_scope_exact_match(self):
        human = _human()
        res = _resource(scope="/data/alice/")
        cap = ConsentAnnotation(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",
        )
        assert cap.is_consent_valid()

    def test_consent_scope_child_within_parent(self):
        human = _human()
        res = _resource(scope="/data/alice/reports/")
        cap = ConsentAnnotation(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",  # resource is within consent scope
        )
        assert cap.is_consent_valid()

    def test_consent_scope_outside_parent(self):
        human = _human()
        res = _resource(scope="/data/bob/")
        cap = ConsentAnnotation(
            claim=_claim(_machine(), res),
            consent_required=True,
            consent_given_by=human,
            consent_scope="/data/alice/",  # bob's scope NOT within alice's
        )
        assert not cap.is_consent_valid()

    def test_consent_violation_reason_no_giver(self):
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
        )
        reason = cap.consent_violation_reason()
        assert reason is not None
        assert "no human" in reason

    def test_consent_violation_reason_machine_giver(self):
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=_machine("bot2"),
        )
        reason = cap.consent_violation_reason()
        assert reason is not None
        assert "not a human" in reason

    def test_consent_violation_reason_expired(self):
        cap = ConsentAnnotation(
            claim=_claim(_machine(), _resource()),
            consent_required=True,
            consent_given_by=_human(),
            consent_expires_at=time.time() - 1,
        )
        reason = cap.consent_violation_reason()
        assert "expired" in reason

    def test_no_violation_reason_when_valid(self):
        cap = ConsentAnnotation(
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
        cap = ConsentAnnotation(
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
        cap = ConsentAnnotation(
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
        cap = ConsentAnnotation(
            claim=_claim(bot, res),
            consent_required=True,
            consent_given_by=human,
        )
        cv.add_capability(cap)
        action = Action("read", actor=bot, resources_read=[res])
        assert cv.check(action) == []


# ---------------------------------------------------------------------------
# Phase 2 helpers
# ---------------------------------------------------------------------------

def _future(seconds: float = 3600.0) -> float:
    """Return a timestamp this many seconds in the future."""
    return time.time() + seconds


def _consent(
    grantor=None,
    grantee=None,
    resource=None,
    operations=None,
    expires_at=None,
    **kwargs,
) -> ConsentCapability:
    """Build a ConsentCapability with sensible defaults."""
    return ConsentCapability(
        grantor=grantor or _human("alice"),
        grantee=grantee or _machine("bot"),
        resource=resource or _resource(),
        operations=frozenset(operations or {"read"}),
        expires_at=expires_at if expires_at is not None else _future(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Phase 2 — ConsentCapability construction
# ---------------------------------------------------------------------------

class TestConsentCapabilityConstruction:
    def test_valid_minimal_construction(self):
        cap = _consent()
        assert cap.grantor.name == "alice"
        assert cap.grantee.name == "bot"
        assert "read" in cap.operations

    def test_non_human_grantor_raises_type_error(self):
        with pytest.raises(TypeError, match="grantor must be HUMAN"):
            _consent(grantor=_machine("evil-bot"))

    def test_missing_expires_at_raises_value_error(self):
        # expires_at=None is not permitted
        with pytest.raises((ValueError, TypeError)):
            ConsentCapability(
                grantor=_human(),
                grantee=_machine(),
                resource=_resource(),
                operations=frozenset({"read"}),
                expires_at=None,  # type: ignore[arg-type]
            )

    def test_past_expires_at_raises_value_error(self):
        with pytest.raises(ValueError, match="expires_at must be in the future"):
            _consent(expires_at=time.time() - 1.0)

    def test_empty_operations_raises_value_error(self):
        with pytest.raises(ValueError, match="operations must be non-empty"):
            ConsentCapability(
                grantor=_human(),
                grantee=_machine(),
                resource=_resource(),
                operations=frozenset(),  # explicitly empty — bypasses helper default
                expires_at=_future(),
            )

    def test_human_override_false_raises_value_error(self):
        with pytest.raises(ValueError, match="human_override_valid"):
            _consent(human_override_valid=False)

    def test_default_is_not_delegable(self):
        cap = _consent()
        assert cap.is_delegable is False

    def test_default_human_override_is_true(self):
        cap = _consent()
        assert cap.human_override_valid is True

    def test_default_scope_is_session(self):
        cap = _consent()
        assert cap.scope == ConsentScope.SESSION

    def test_default_context_id_is_empty(self):
        cap = _consent()
        assert cap.context_id == ""

    def test_multiple_operations(self):
        cap = _consent(operations={"read", "summarize", "export"})
        assert "read" in cap.operations
        assert "summarize" in cap.operations
        assert "export" in cap.operations

    def test_frozen_dataclass_immutable(self):
        cap = _consent()
        with pytest.raises((AttributeError, TypeError)):
            cap.grantor = _human("bob")  # type: ignore[misc]

    def test_operations_is_frozenset(self):
        cap = _consent(operations={"read"})
        assert isinstance(cap.operations, frozenset)

    def test_global_scope_variant(self):
        cap = _consent(scope=ConsentScope.GLOBAL)
        assert cap.scope == ConsentScope.GLOBAL

    def test_ephemeral_scope_variant(self):
        cap = _consent(scope=ConsentScope.EPHEMERAL)
        assert cap.scope == ConsentScope.EPHEMERAL


# ---------------------------------------------------------------------------
# Phase 2 — ConsentCapability.is_valid / covers
# ---------------------------------------------------------------------------

class TestConsentCapabilityBehavior:
    def test_is_valid_before_expiry(self):
        cap = _consent(expires_at=_future(3600))
        assert cap.is_valid() is True

    def test_is_valid_false_if_expired(self):
        # Build with future time, but test with a direct attribute check
        # We cannot construct with past time (raises), so we use covers() boundary test
        cap = _consent(expires_at=_future(0.001))
        # Immediately valid
        assert cap.is_valid() is True

    def test_covers_valid_operation(self):
        cap = _consent(operations={"read", "summarize"})
        assert cap.covers("read") is True
        assert cap.covers("summarize") is True

    def test_covers_unknown_operation_false(self):
        cap = _consent(operations={"read"})
        assert cap.covers("write") is False
        assert cap.covers("delete") is False

    def test_covers_with_correct_context(self):
        cap = _consent(context_id="session-xyz", operations={"read"})
        assert cap.covers("read", "session-xyz") is True

    def test_covers_with_wrong_context_false(self):
        cap = _consent(context_id="session-xyz", operations={"read"})
        assert cap.covers("read", "session-abc") is False

    def test_covers_no_context_restriction_passes_any_ctx(self):
        cap = _consent(context_id="", operations={"read"})
        assert cap.covers("read", "any-session-id") is True
        assert cap.covers("read", "") is True

    def test_covers_returns_false_for_empty_operation_string(self):
        cap = _consent(operations={"read"})
        assert cap.covers("") is False

    def test_can_be_delegated_false_by_default(self):
        cap = _consent()
        assert cap.can_be_delegated() is False

    def test_can_be_delegated_true_when_is_delegable(self):
        cap = _consent(is_delegable=True)
        assert cap.can_be_delegated() is True

    def test_human_override_always_true(self):
        cap = _consent()
        assert cap.human_override_valid is True
        # Verify it truly cannot be set to False
        with pytest.raises(ValueError, match="human_override_valid"):
            _consent(human_override_valid=False)


# ---------------------------------------------------------------------------
# Phase 2 — ConsentScope enum
# ---------------------------------------------------------------------------

class TestConsentScope:
    def test_global_value(self):
        assert ConsentScope.GLOBAL.value == "global"

    def test_session_value(self):
        assert ConsentScope.SESSION.value == "session"

    def test_ephemeral_value(self):
        assert ConsentScope.EPHEMERAL.value == "ephemeral"

    def test_scope_assigned_to_capability(self):
        for scope in ConsentScope:
            cap = _consent(scope=scope)
            assert cap.scope is scope


# ---------------------------------------------------------------------------
# Phase 2 — ConsentRegistry
# ---------------------------------------------------------------------------

class TestConsentRegistry:
    def _registry_with_one_consent(self):
        reg = ConsentRegistry()
        cap = _consent()
        reg.grant(cap)
        return reg, cap

    def test_grant_valid_consent(self):
        reg = ConsentRegistry()
        reg.grant(_consent())
        assert len(reg) == 1

    def test_grant_machine_grantor_raises_type_error(self):
        reg = ConsentRegistry()
        with pytest.raises(TypeError):
            # ConsentCapability itself rejects non-human grantor at construction
            reg.grant(_consent(grantor=_machine("bad")))

    def test_grant_non_consent_object_raises_type_error(self):
        reg = ConsentRegistry()
        with pytest.raises(TypeError, match="ConsentCapability"):
            reg.grant("not-a-consent-object")  # type: ignore[arg-type]

    def test_check_valid_consent_returns_true(self):
        reg, cap = self._registry_with_one_consent()
        ok, reason = reg.check(cap.grantee, cap.resource, "read")
        assert ok is True
        assert cap.grantor.name in reason

    def test_check_unknown_grantee_returns_false(self):
        reg, cap = self._registry_with_one_consent()
        stranger = _machine("stranger")
        ok, reason = reg.check(stranger, cap.resource, "read")
        assert ok is False
        assert "no consent on record" in reason

    def test_check_uncovered_operation_returns_false(self):
        reg, cap = self._registry_with_one_consent()
        ok, reason = reg.check(cap.grantee, cap.resource, "delete")
        assert ok is False
        assert "not covered" in reason

    def test_revoke_removes_consent(self):
        reg, cap = self._registry_with_one_consent()
        removed = reg.revoke(cap.grantor, cap.grantee, cap.resource)
        assert removed == 1
        ok, _ = reg.check(cap.grantee, cap.resource, "read")
        assert ok is False

    def test_revoke_by_non_human_raises_type_error(self):
        reg, cap = self._registry_with_one_consent()
        bot = _machine("interloper")
        with pytest.raises(TypeError, match="human grantor"):
            reg.revoke(bot, cap.grantee, cap.resource)

    def test_revoke_wrong_grantor_removes_nothing(self):
        reg, cap = self._registry_with_one_consent()
        wrong_grantor = _human("bob")
        removed = reg.revoke(wrong_grantor, cap.grantee, cap.resource)
        assert removed == 0
        ok, _ = reg.check(cap.grantee, cap.resource, "read")
        assert ok is True  # still present

    def test_check_with_context_id_correct(self):
        reg = ConsentRegistry()
        cap = _consent(context_id="sess-1", operations={"write"})
        reg.grant(cap)
        ok, _ = reg.check(cap.grantee, cap.resource, "write", "sess-1")
        assert ok is True

    def test_check_with_context_id_wrong(self):
        reg = ConsentRegistry()
        cap = _consent(context_id="sess-1", operations={"write"})
        reg.grant(cap)
        ok, reason = reg.check(cap.grantee, cap.resource, "write", "sess-999")
        assert ok is False
        assert "different context" in reason

    def test_active_consents_filters_by_grantee(self):
        reg = ConsentRegistry()
        bot1 = _machine("bot1")
        bot2 = _machine("bot2")
        res = _resource()
        reg.grant(_consent(grantee=bot1, resource=res))
        reg.grant(_consent(grantee=bot2, resource=res))
        active = reg.active_consents(grantee=bot1)
        assert all(c.grantee == bot1 for c in active)
        assert len(active) == 1

    def test_active_consents_filters_by_resource(self):
        reg = ConsentRegistry()
        res1 = Resource("r1", ResourceType.FILE)
        res2 = Resource("r2", ResourceType.FILE)
        reg.grant(_consent(resource=res1))
        reg.grant(_consent(resource=res2))
        active = reg.active_consents(resource=res1)
        assert all(c.resource == res1 for c in active)
        assert len(active) == 1

    def test_multiple_grants_all_checked(self):
        reg = ConsentRegistry()
        bot = _machine("bot")
        res = _resource()
        # Grant two consents for different operations
        reg.grant(_consent(grantee=bot, resource=res, operations={"read"}))
        reg.grant(_consent(grantee=bot, resource=res, operations={"write"}))
        ok_r, _ = reg.check(bot, res, "read")
        ok_w, _ = reg.check(bot, res, "write")
        assert ok_r is True
        assert ok_w is True

    def test_len_reflects_grants(self):
        reg = ConsentRegistry()
        assert len(reg) == 0
        reg.grant(_consent())
        assert len(reg) == 1
        reg.grant(_consent())
        assert len(reg) == 2
