"""
Inalienable rights layer tests — Phase 2, O2.

Tests InnalienableRightsChecker against structurally invalid authority transfers.
The checker catches violations that are STRUCTURALLY forbidden, not just
policy-forbidden — even if cryptographically valid.
"""
import time

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.inalienable import (
    InnalienableRightsChecker,
    InnalienableRightsError,
    InnalienableViolation,
    StructuralViolation,
    assert_claim_valid,
    check_claim,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(name: str = "data", scope: str = "/data/", rtype: ResourceType = ResourceType.DATASET) -> Resource:
    return Resource(name, rtype, scope=scope)


# ── Checker structure ─────────────────────────────────────────────────────────

class TestCheckerStructure:
    def test_checker_instantiates(self):
        checker = InnalienableRightsChecker()
        assert checker is not None

    def test_max_delegation_depth_set(self):
        assert InnalienableRightsChecker.MAX_SAFE_DELEGATION_DEPTH == 4

    def test_violation_has_all_types(self):
        types = {v.name for v in InnalienableViolation}
        assert "PERMANENT_DELEGATION" in types
        assert "TOTAL_AGENCY_SURRENDER" in types
        assert "BEHAVIORAL_OWNERSHIP" in types
        assert "SELF_PERPETUATING_CHAIN" in types
        assert "MONOPOLY_DELEGATION" in types


# ── PERMANENT_DELEGATION ──────────────────────────────────────────────────────

class TestPermanentDelegation:
    def test_machine_to_machine_delegation_without_expiry_flagged(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = _resource()
        claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)  # no expires_at
        violations = check_claim(claim)
        assert any(v.violation_type == InnalienableViolation.PERMANENT_DELEGATION for v in violations)

    def test_machine_to_machine_delegation_with_expiry_ok(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = _resource()
        claim = RightsClaim(
            child, resource, can_read=True,
            delegated_by=delegator,
            expires_at=time.time() + 3600,
        )
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.PERMANENT_DELEGATION for v in violations)

    def test_direct_human_grant_without_expiry_is_ok(self):
        human = _human()
        machine = _machine()
        resource = _resource()
        # Direct grant: delegated_by=None (not delegated) — no expiry required
        claim = RightsClaim(machine, resource, can_read=True)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.PERMANENT_DELEGATION for v in violations)

    def test_human_delegating_without_expiry_not_flagged(self):
        human = _human("alice")
        machine = _machine()
        resource = _resource()
        # Human delegates directly to machine — human retains registry control
        claim = RightsClaim(machine, resource, can_read=True, delegated_by=human)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.PERMANENT_DELEGATION for v in violations)

    def test_violation_contains_helpful_description(self):
        delegator = _machine("delegator-bot")
        child = _machine("child-bot")
        resource = _resource()
        claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)
        violations = check_claim(claim)
        perm = [v for v in violations if v.violation_type == InnalienableViolation.PERMANENT_DELEGATION]
        assert len(perm) == 1
        assert "expires_at" in perm[0].description.lower() or "expiry" in perm[0].description.lower()


# ── TOTAL_AGENCY_SURRENDER ────────────────────────────────────────────────────

class TestTotalAgencySurrender:
    def test_root_scope_all_rights_full_confidence_flagged(self):
        human = _human()
        machine = _machine()
        resource = Resource("everything", ResourceType.FILE, scope="")  # root scope
        claim = RightsClaim(machine, resource, can_read=True, can_write=True, can_delegate=True, confidence=1.0)
        violations = check_claim(claim)
        assert any(v.violation_type == InnalienableViolation.TOTAL_AGENCY_SURRENDER for v in violations)

    def test_scoped_resource_all_rights_not_flagged(self):
        machine = _machine()
        resource = Resource("data", ResourceType.FILE, scope="/data/")  # scoped
        claim = RightsClaim(machine, resource, can_read=True, can_write=True, can_delegate=True, confidence=1.0)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.TOTAL_AGENCY_SURRENDER for v in violations)

    def test_missing_delegate_right_not_flagged(self):
        machine = _machine()
        resource = Resource("data", ResourceType.FILE, scope="")
        claim = RightsClaim(machine, resource, can_read=True, can_write=True, can_delegate=False, confidence=1.0)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.TOTAL_AGENCY_SURRENDER for v in violations)

    def test_lower_confidence_not_flagged(self):
        machine = _machine()
        resource = Resource("data", ResourceType.FILE, scope="")
        claim = RightsClaim(machine, resource, can_read=True, can_write=True, can_delegate=True, confidence=0.9)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.TOTAL_AGENCY_SURRENDER for v in violations)


# ── BEHAVIORAL_OWNERSHIP ──────────────────────────────────────────────────────

class TestBehavioralOwnership:
    def test_machine_claim_on_human_profile_resource_flagged(self):
        machine = _machine()
        resource = Resource("user-behavioral-profile", ResourceType.BEHAVIORAL_PROFILE, scope="/profiles/")
        claim = RightsClaim(machine, resource, can_read=True, can_write=True)
        violations = check_claim(claim)
        assert any(v.violation_type == InnalienableViolation.BEHAVIORAL_OWNERSHIP for v in violations)

    def test_machine_claim_on_identity_resource_flagged(self):
        machine = _machine()
        resource = Resource("user-identity", ResourceType.IDENTITY, scope="/identities/")
        claim = RightsClaim(machine, resource, can_read=True)
        violations = check_claim(claim)
        assert any(v.violation_type == InnalienableViolation.BEHAVIORAL_OWNERSHIP for v in violations)

    def test_human_claim_on_identity_resource_not_flagged(self):
        human = _human()
        resource = Resource("user-identity", ResourceType.IDENTITY, scope="/identities/")
        claim = RightsClaim(human, resource, can_read=True)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.BEHAVIORAL_OWNERSHIP for v in violations)

    def test_machine_claim_on_normal_dataset_not_flagged(self):
        machine = _machine()
        resource = Resource("sales-data", ResourceType.DATASET, scope="/data/")
        claim = RightsClaim(machine, resource, can_read=True)
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.BEHAVIORAL_OWNERSHIP for v in violations)


# ── SELF_PERPETUATING_CHAIN ───────────────────────────────────────────────────

class TestSelfPerpetualingChain:
    def test_delegated_can_delegate_at_root_flagged(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = Resource("root", ResourceType.FILE, scope="")  # root scope
        claim = RightsClaim(
            child, resource,
            can_read=True, can_delegate=True,
            delegated_by=delegator,
            expires_at=time.time() + 3600,
        )
        violations = check_claim(claim)
        assert any(v.violation_type == InnalienableViolation.SELF_PERPETUATING_CHAIN for v in violations)

    def test_delegated_can_delegate_at_scoped_resource_not_flagged(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = Resource("data", ResourceType.FILE, scope="/data/")  # scoped
        claim = RightsClaim(
            child, resource,
            can_read=True, can_delegate=True,
            delegated_by=delegator,
            expires_at=time.time() + 3600,
        )
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.SELF_PERPETUATING_CHAIN for v in violations)

    def test_delegated_no_delegate_at_root_not_flagged(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = Resource("root", ResourceType.FILE, scope="")
        claim = RightsClaim(
            child, resource,
            can_read=True, can_delegate=False,
            delegated_by=delegator,
            expires_at=time.time() + 3600,
        )
        violations = check_claim(claim)
        assert not any(v.violation_type == InnalienableViolation.SELF_PERPETUATING_CHAIN for v in violations)


# ── MONOPOLY_DELEGATION ───────────────────────────────────────────────────────

class TestMonopolyDelegation:
    def test_single_machine_gets_majority_human_delegations_flagged(self):
        alice = _human("alice")
        bob = _human("bob")
        carol = _human("carol")
        machine = _machine("big-bot")
        resource = _resource()

        claims = [
            RightsClaim(machine, resource, can_read=True, delegated_by=alice),
            RightsClaim(machine, resource, can_read=True, delegated_by=bob),
            RightsClaim(machine, resource, can_read=True, delegated_by=carol),
        ]
        checker = InnalienableRightsChecker()
        violations = checker.check_claims(claims)
        assert any(v.violation_type == InnalienableViolation.MONOPOLY_DELEGATION for v in violations)

    def test_distributed_delegation_not_flagged(self):
        alice = _human("alice")
        bob = _human("bob")
        bot_a = _machine("bot-a")
        bot_b = _machine("bot-b")
        resource = _resource()

        claims = [
            RightsClaim(bot_a, resource, can_read=True, delegated_by=alice),
            RightsClaim(bot_b, resource, can_read=True, delegated_by=bob),
        ]
        checker = InnalienableRightsChecker()
        violations = checker.check_claims(claims)
        assert not any(v.violation_type == InnalienableViolation.MONOPOLY_DELEGATION for v in violations)

    def test_single_human_single_machine_not_flagged(self):
        alice = _human()
        bot = _machine()
        resource = _resource()
        claims = [RightsClaim(bot, resource, can_read=True, delegated_by=alice)]
        checker = InnalienableRightsChecker()
        violations = checker.check_claims(claims)
        assert not any(v.violation_type == InnalienableViolation.MONOPOLY_DELEGATION for v in violations)


# ── assert_claim_valid convenience function ───────────────────────────────────

class TestAssertClaimValid:
    def test_valid_claim_does_not_raise(self):
        machine = _machine()
        resource = _resource()
        claim = RightsClaim(machine, resource, can_read=True)
        assert_claim_valid(claim)  # should not raise

    def test_invalid_claim_raises_inalienable_error(self):
        delegator = _machine("delegator")
        child = _machine("child")
        resource = _resource()
        # No expiry on machine-to-machine delegation → PERMANENT_DELEGATION
        claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)
        with pytest.raises(InnalienableRightsError):
            assert_claim_valid(claim)


# ── StructuralViolation string representation ─────────────────────────────────

class TestStructuralViolation:
    def test_str_contains_violation_type(self):
        sv = StructuralViolation(
            violation_type=InnalienableViolation.PERMANENT_DELEGATION,
            description="test",
        )
        assert "PERMANENT_DELEGATION" in str(sv)
        assert "INALIENABLE" in str(sv)

    def test_all_violations_are_critical_or_high(self):
        for vtype in InnalienableViolation:
            sv = StructuralViolation(violation_type=vtype, description="test")
            assert sv.severity in ("CRITICAL", "HIGH")
