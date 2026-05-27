"""Phase 5 — OwnershipRegistry.freeze() tests."""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry


def _registry_with_claim():
    registry = OwnershipRegistry()
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    res = Resource(name="/data", rtype=ResourceType.FILE)
    claim = RightsClaim(holder=alice, resource=res, can_read=True)
    registry.add_claim(claim)
    return registry, alice, res


def test_freeze_returns_snapshot_with_same_claims():
    registry, alice, res = _registry_with_claim()
    snap = registry.freeze()
    assert len(snap.claims_for(alice, res)) == 1


def test_frozen_add_claim_raises():
    registry, alice, res = _registry_with_claim()
    snap = registry.freeze()
    new_claim = RightsClaim(holder=alice, resource=res, can_read=True)
    with pytest.raises(RuntimeError, match="frozen"):
        snap.add_claim(new_claim)


def test_frozen_register_machine_raises():
    registry = OwnershipRegistry()
    snap = registry.freeze()
    bot = Entity(name="bot", kind=AgentType.MACHINE)
    owner = Entity(name="alice", kind=AgentType.HUMAN)
    with pytest.raises(RuntimeError, match="frozen"):
        snap.register_machine(bot, owner)


def test_frozen_delegate_raises():
    registry, alice, res = _registry_with_claim()
    delegatable = RightsClaim(
        holder=alice, resource=res, can_read=True, can_delegate=True
    )
    registry.add_claim(delegatable)
    snap = registry.freeze()
    bob = Entity(name="bob", kind=AgentType.HUMAN)
    delegated = RightsClaim(holder=bob, resource=res, can_read=True)
    with pytest.raises(RuntimeError, match="frozen"):
        snap.delegate(delegated, delegated_by=alice)


def test_original_still_mutable_after_freeze():
    registry, alice, res = _registry_with_claim()
    _ = registry.freeze()
    extra = RightsClaim(holder=alice, resource=res, can_read=True)
    registry.add_claim(extra)  # must not raise
    assert len(registry.claims_for(alice, res)) == 2


def test_snapshot_isolated_from_original():
    registry, alice, res = _registry_with_claim()
    snap = registry.freeze()
    extra = RightsClaim(holder=alice, resource=res, can_read=True)
    registry.add_claim(extra)
    # snapshot was taken before the second claim — must not reflect it
    assert len(snap.claims_for(alice, res)) == 1
    assert len(registry.claims_for(alice, res)) == 2


def test_can_act_on_frozen_snapshot():
    registry, alice, res = _registry_with_claim()
    snap = registry.freeze()
    ok, conf, reason = snap.can_act(alice, res, "read")
    assert ok is True
    assert conf > 0.0
