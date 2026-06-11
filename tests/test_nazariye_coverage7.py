"""
Coverage tests (batch 7) added on the `nazariye-azadi` branch.

Targets the authority sources, the override lock-in detector, the sovereign
exit checker, and the hardened verifier's trust-anchoring branches.
"""
from __future__ import annotations

import time

import pytest

from authgate.analysis.exit_guarantees import SovereignExitChecker
from authgate.analysis.override_detector import LockInPattern, OverrideDetector
from authgate.authority.base import CapabilityRequest, IssuedCapability
from authgate.authority.human_delegation import (
    HumanDelegationSource,
    MarketOracleSource,
    ReputationGateSource,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.hardened import HardenedVerifier, TrustBoundaryError
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action


def _human(name):
    return Entity(name, AgentType.HUMAN)


def _machine(name, token=None):
    return Entity(name, AgentType.MACHINE, identity_token=token)


def _res(name, rtype=ResourceType.FILE, scope=""):
    return Resource(name, rtype, scope=scope)


def _chain_registry(depth: int) -> OwnershipRegistry:
    """Registry with a delegation chain of machines: alice -> m1 -> m2 -> ..."""
    reg = OwnershipRegistry()
    alice = _human("Alice")
    res = _res("doc", scope="proj")
    root = RightsClaim(alice, res, can_read=True, can_delegate=True)
    reg.add_claim(root)
    prev = alice
    for i in range(1, depth + 1):
        m = _machine(f"m{i}")
        reg.register_machine(m, alice)
        c = RightsClaim(m, res, can_read=True, can_delegate=True)
        c.delegated_by = prev
        reg.add_claim(c)
        prev = m
    return reg


# --------------------------------------------------------------------------- #
# authority/human_delegation.py
# --------------------------------------------------------------------------- #

def test_human_delegation_no_registry_returns_none():
    src = HumanDelegationSource(verifier=object())  # object() has no .registry -> line 78
    req = CapabilityRequest("bot", "res", frozenset({"read"}))
    assert src.request_capability(req) is None


def test_human_delegation_is_valid_and_revoked():
    src = HumanDelegationSource(verifier=object())
    cap = IssuedCapability(
        subject_id="bot", resource_id="res", rights=frozenset({"read"}),
        valid_from=0.0, valid_until=1e12, epoch=1,
        issuer_id="h", source_type="human_delegation",
    )
    assert src.is_valid(cap, now=1.0, min_epoch=1) is True
    # wrong source type -> False (line 133 tail)
    other = IssuedCapability(
        subject_id="bot", resource_id="res", rights=frozenset({"read"}),
        valid_from=0.0, valid_until=1e12, epoch=1, issuer_id="h", source_type="other",
    )
    assert src.is_valid(other, now=1.0, min_epoch=1) is False
    # revoked -> False (line 131-132)
    src.revoke("bot", "res")
    assert src.is_valid(cap, now=time.time() + 1, min_epoch=1) is False


def test_market_oracle_source_stub():
    mo = MarketOracleSource(market_endpoint="tcp://x")
    assert mo.source_id.startswith("market_oracle")     # line 156
    assert mo.source_type == "market_oracle"
    with pytest.raises(NotImplementedError):
        mo.request_capability(CapabilityRequest("a", "b", frozenset()))
    assert mo.revoke("a", "b").success is False          # line 170
    cap = IssuedCapability("a", "b", frozenset(), 0.0, 1e12, 1, "i", "market_oracle")
    assert mo.is_valid(cap, now=1.0, min_epoch=1) is True  # line 174


def test_reputation_gate_source_stub():
    rg = ReputationGateSource()
    assert rg.source_id.startswith("reputation_gate")   # line 196
    assert rg.source_type == "reputation_gate"
    with pytest.raises(NotImplementedError):
        rg.request_capability(CapabilityRequest("a", "b", frozenset()))
    assert rg.revoke("a", "b").success is False          # line 211
    cap = IssuedCapability("a", "b", frozenset(), 0.0, 1e12, 1, "i", "reputation_gate")
    assert rg.is_valid(cap, now=1.0, min_epoch=1) is True  # line 215


# --------------------------------------------------------------------------- #
# analysis/override_detector.py
# --------------------------------------------------------------------------- #

def test_override_owner_lockout_skips_none_owner():
    detector = OverrideDetector()
    machine = _machine("m1")
    # machines_map with a None owner -> line 102 continue, no risk emitted
    risks = detector._check_owner_lockout(claims=[], machines_map={machine: None})
    assert risks == []


def test_override_deep_chain_detected():
    reg = _chain_registry(depth=5)  # depth exceeds MAX_SAFE_CHAIN_DEPTH=4
    risks = OverrideDetector().detect(reg)
    assert any(r.pattern == LockInPattern.DEEP_DELEGATION_CHAIN for r in risks)


def test_override_chain_depth_parent_not_found():
    # A claim delegated by an entity that holds no claim -> _chain_depth hits the
    # "parent is None -> return 1" branch (line 225)
    reg = OwnershipRegistry()
    alice = _human("Alice")
    bot = _machine("m1")
    reg.register_machine(bot, alice)
    c = RightsClaim(bot, _res("doc"), can_read=True)
    c.delegated_by = _human("Phantom")  # Phantom holds no claim in the registry
    reg.add_claim(c)
    # detect() walks the chain; no DEEP risk (depth 1), but the branch executes
    risks = OverrideDetector().detect(reg)
    assert all(r.pattern != LockInPattern.DEEP_DELEGATION_CHAIN for r in risks)


# --------------------------------------------------------------------------- #
# analysis/exit_guarantees.py
# --------------------------------------------------------------------------- #

def test_exit_checker_deep_chain_revocation_unreachable():
    reg = _chain_registry(depth=5)  # > MAX_EXIT_SAFE_DEPTH (3)
    signals = SovereignExitChecker().check(reg)
    from authgate.analysis.exit_guarantees import ExitViolation
    assert any(s.violation == ExitViolation.REVOCATION_UNREACHABLE for s in signals)
    assert SovereignExitChecker().exit_rights_intact(reg) is False


def test_exit_checker_delegation_cycle_guard():
    # m1 <-> m2 delegated_by cycle exercises the cycle guard (line 120)
    reg = OwnershipRegistry()
    alice = _human("Alice")
    m1, m2 = _machine("m1"), _machine("m2")
    reg.register_machine(m1, alice)
    reg.register_machine(m2, alice)
    res = _res("doc")
    c1 = RightsClaim(m1, res, can_read=True)
    c1.delegated_by = m2
    c2 = RightsClaim(m2, res, can_read=True)
    c2.delegated_by = m1
    reg.add_claim(c1)
    reg.add_claim(c2)
    # Must terminate (cycle guard) and return a list
    assert isinstance(SovereignExitChecker().check(reg), list)


def test_exit_checker_clean_when_human_has_direct_claim():
    reg = OwnershipRegistry()
    alice = _human("Alice")
    reg.add_claim(RightsClaim(alice, _res("own"), can_read=True))
    # Alice holds a direct claim and there are no machines -> no exit violations
    assert SovereignExitChecker().exit_rights_intact(reg) is True


# --------------------------------------------------------------------------- #
# kernel/hardened.py
# --------------------------------------------------------------------------- #

def test_hardened_rejects_zero_confidence_floor():
    with pytest.raises(TrustBoundaryError):
        HardenedVerifier(OwnershipRegistry(), min_confidence=0.0)


def test_hardened_resolve_resource_strips_unknown_public():
    hv = HardenedVerifier(OwnershipRegistry())
    sneaky = _res("unknown")
    sneaky = Resource("unknown", ResourceType.FILE, is_public=True)
    resolved = hv._resolve_resource(sneaky)  # line 75
    assert resolved.is_public is False


def test_hardened_identity_unenrolled_and_anonymous():
    reg = OwnershipRegistry()
    hv = HardenedVerifier(reg)
    snap = reg.freeze()
    # unenrolled identity -> False (line 83)
    assert hv._identity_registered_and_matched(snap, _machine("ghost", token="t")) is False

    # anonymous enrollment (token=None) -> not an identity (line 86)
    reg2 = OwnershipRegistry()
    anon = _machine("anon", token=None)
    reg2.register_machine(anon, _human("Alice"))
    snap2 = reg2.freeze()
    assert hv._identity_registered_and_matched(snap2, anon) is False


def test_hardened_verify_logs_advisory_flags():
    reg = OwnershipRegistry()
    alice = _human("Alice")
    bot = _machine("Bot", token="secret")
    reg.register_machine(bot, alice)
    hv = HardenedVerifier(reg, require_identity=True)
    # principal matches enrolled token; action self-declares a flag (advisory only)
    action = Action("a1", bot, increases_machine_sovereignty=True)
    result = hv.verify(action, principal=bot)
    # flag is advisory -> appears in warnings, never as a violation (line 156)
    assert any("advisory-flag" in w for w in result.warnings)
