"""
AuthoritySource tests — III-1 from INFRASTRUCTURE_PLAN.md.

Tests the AuthoritySource abstraction and HumanDelegationSource adapter.
"""

from __future__ import annotations

import time

import pytest

from authgate.authority import HumanDelegationSource, AuthoritySource, CapabilityRequest
from authgate.authority.base import IssuedCapability
from authgate.authority.human_delegation import MarketOracleSource, ReputationGateSource
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import FreedomVerifier


def _env():
    alice = Entity("alice", AgentType.HUMAN)
    bot   = Entity("bot",   AgentType.MACHINE)
    data  = Resource("data", ResourceType.FILE, scope="/data/")
    secrets = Resource("secrets", ResourceType.FILE, scope="/secrets/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)

    v = FreedomVerifier(reg)
    return alice, bot, data, secrets, reg, v


class TestHumanDelegationSource:

    def test_protocol_satisfied(self):
        """HumanDelegationSource implements AuthoritySource protocol."""
        _, _, _, _, _, v = _env()
        source = HumanDelegationSource(v)
        assert isinstance(source, AuthoritySource)

    def test_issues_capability_for_authorized_agent(self):
        _, bot, data, _, _, v = _env()
        source = HumanDelegationSource(v)

        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name,
            resource_id=data.name,
            rights=frozenset(["read"]),
        ))

        assert cap is not None
        assert cap.subject_id == bot.name
        assert cap.resource_id == data.name
        assert "read" in cap.rights
        assert cap.source_type == "human_delegation"
        assert cap.revocable is True

    def test_denies_capability_for_unauthorized_resource(self):
        _, bot, _, secrets, _, v = _env()
        source = HumanDelegationSource(v)

        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name,
            resource_id=secrets.name,
            rights=frozenset(["read"]),
        ))

        assert cap is None, "Unauthorized resource should return None"

    def test_issued_capability_has_future_expiry(self):
        _, bot, data, _, _, v = _env()
        source = HumanDelegationSource(v, ttl_seconds=600)

        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name,
            resource_id=data.name,
            rights=frozenset(["read"]),
        ))

        assert cap is not None
        now = time.time()
        assert cap.valid_until > now
        assert cap.valid_until - cap.valid_from == pytest.approx(600, abs=1)

    def test_revocation_prevents_further_issuance(self):
        _, bot, data, _, _, v = _env()
        source = HumanDelegationSource(v)

        # Before revocation: issued
        cap1 = source.request_capability(CapabilityRequest(
            subject_id=bot.name, resource_id=data.name, rights=frozenset(["read"])
        ))
        assert cap1 is not None

        # Revoke
        result = source.revoke(bot.name, data.name)
        assert result.success

        # After revocation: None
        cap2 = source.request_capability(CapabilityRequest(
            subject_id=bot.name, resource_id=data.name, rights=frozenset(["read"])
        ))
        assert cap2 is None, "Revoked agent should not receive new capabilities"

    def test_is_valid_checks_expiry(self):
        _, bot, data, _, _, v = _env()
        source = HumanDelegationSource(v, ttl_seconds=1)

        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name, resource_id=data.name, rights=frozenset(["read"])
        ))
        assert cap is not None

        # Valid now
        assert source.is_valid(cap, time.time(), 1)

        # Expired in the future
        far_future = cap.valid_until + 100
        assert not source.is_valid(cap, far_future, 1)

    def test_is_valid_checks_epoch(self):
        _, bot, data, _, _, v = _env()
        source = HumanDelegationSource(v, epoch=5)

        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name, resource_id=data.name, rights=frozenset(["read"])
        ))
        assert cap is not None
        assert cap.epoch == 5

        # Valid with min_epoch <= 5
        assert source.is_valid(cap, time.time(), 5)
        assert source.is_valid(cap, time.time(), 4)

        # Invalid with min_epoch > 5 (stale epoch)
        assert not source.is_valid(cap, time.time(), 6)


class TestAuthoritySourceProtocol:

    def test_market_oracle_satisfies_protocol(self):
        source = MarketOracleSource("http://market.example.com")
        assert isinstance(source, AuthoritySource)
        assert source.source_type == "market_oracle"
        # Stub returns None for all requests
        cap = source.request_capability(CapabilityRequest("agent1", "resource1", frozenset(["read"])))
        assert cap is None

    def test_reputation_gate_satisfies_protocol(self):
        source = ReputationGateSource()
        assert isinstance(source, AuthoritySource)
        assert source.source_type == "reputation_gate"
        cap = source.request_capability(CapabilityRequest("agent1", "resource1", frozenset(["read"])))
        assert cap is None

    def test_capability_request_immutable(self):
        req = CapabilityRequest("bot", "data", frozenset(["read"]))
        assert req.subject_id == "bot"
        assert req.resource_id == "data"
        assert "read" in req.rights

    def test_issued_capability_validity_window(self):
        now = time.time()
        cap = IssuedCapability(
            subject_id="bot",
            resource_id="data",
            rights=frozenset(["read"]),
            valid_from=now,
            valid_until=now + 3600,
            epoch=5,
            issuer_id="test",
            source_type="human_delegation",
        )
        assert cap.is_valid_at(now + 1, 5)
        assert cap.is_valid_at(now + 3599, 5)
        assert not cap.is_valid_at(now + 3601, 5)   # expired
        assert not cap.is_valid_at(now + 1, 6)       # stale epoch

    def test_source_ids_are_unique(self):
        _, _, _, _, _, v = _env()
        s1 = HumanDelegationSource(v)
        s2 = HumanDelegationSource(v)
        assert s1.source_id != s2.source_id
