"""
Tests for the pure JSON-wire serialization that feeds the verified Rust engine.

These need no compiled extension — they exercise the marshalling functions and
the valid-claim filter directly, so they run everywhere (including CI without the
extension) and pin the exact shape the engine consumes.
"""
from __future__ import annotations

from authgate.kernel.entities import (
    AgentType,
    Entity,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action
from authgate.runtime.rust_backend import (
    _action_wire,
    _claim_wire,
    _entity_wire,
    _live_claims,
    _resource_wire,
)


def test_entity_wire_maps_kind():
    assert _entity_wire(Entity("a", AgentType.MACHINE)) == {"name": "a", "kind": "MACHINE"}
    assert _entity_wire(Entity("op", AgentType.HUMAN))["kind"] == "HUMAN"


def test_resource_wire_shape():
    r = Resource("sales", ResourceType.DATASET, scope="/data/", is_public=True)
    w = _resource_wire(r)
    assert w["name"] == "sales"
    assert w["rtype"] == "DATASET"
    assert w["scope"] == "/data/"
    assert w["is_public"] is True


def test_claim_wire_carries_rights_and_confidence():
    c = RightsClaim(
        Entity("a", AgentType.MACHINE),
        Resource("compute", ResourceType.COMPUTE_SLOT),
        can_read=True, can_delegate=True, confidence=0.9,
    )
    w = _claim_wire(c)
    assert w["can_read"] is True
    assert w["can_delegate"] is True
    assert w["confidence"] == 0.9
    assert w["holder"]["name"] == "a"


def test_action_wire_includes_resources_and_flags():
    agent = Entity("a", AgentType.MACHINE)
    res = Resource("compute", ResourceType.COMPUTE_SLOT)
    action = Action("act1", agent, resources_read=[res], coerces=True)
    w = _action_wire(action)
    assert w["action_id"] == "act1"
    assert w["actor"]["name"] == "a"
    assert len(w["resources_read"]) == 1
    assert w["coerces"] is True
    assert w["bypasses_verifier"] is False


def _registry_with_claim(epoch: int = 1):
    owner = Entity("operator", AgentType.HUMAN)
    agent = Entity("agent-1", AgentType.MACHINE)
    res = Resource("compute", ResourceType.COMPUTE_SLOT)
    reg = OwnershipRegistry()
    reg.register_machine(agent, owner)
    reg.add_claim(RightsClaim(owner, res, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(agent, res, can_read=True), delegated_by=owner)
    return reg


def test_live_claims_includes_valid_claims():
    reg = _registry_with_claim()
    live = _live_claims(reg, min_epoch=0)
    # owner's claim + delegated agent claim, both valid at epoch 0
    assert len(live) == 2


def test_live_claims_filters_by_epoch():
    reg = _registry_with_claim()
    # claims default to epoch 1; requiring epoch 2 filters them all out
    assert _live_claims(reg, min_epoch=2) == []
    reg.advance_epoch(2)
    assert len(_live_claims(reg, min_epoch=2)) == 2


def test_live_claims_excludes_revoked():
    reg = _registry_with_claim()
    reg.revoke_all("agent-1")
    holders = {c.holder.name for c in _live_claims(reg, min_epoch=0)}
    assert "agent-1" not in holders
