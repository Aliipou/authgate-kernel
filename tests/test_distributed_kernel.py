"""
Distributed Kernel tests — Byzantine-fault-tolerant capability federation.

Tests structural invariants:
  - Merkle state detects registry divergence
  - Threshold revocations require owner signature (A4/Consent)
  - Epoch monotonicity prevents partition-resurrected capabilities
  - Partition policy fails-secure on cross-domain uncertainty
  - Gossip propagates revocations across the network
  - Byzantine node cannot forge a valid revocation
"""
from __future__ import annotations

import time
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry

from authgate.kernel.distributed_kernel import (
    VectorClock,
    MerkleRegistryState,
    RevocationEvent,
    CapabilityEpoch,
    PartitionDecision,
    PartitionPolicy,
    FederatedNode,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _registry_with_claim() -> tuple[OwnershipRegistry, Entity, Entity, Resource]:
    alice = Entity("Alice", AgentType.HUMAN)
    bot = Entity("Bot", AgentType.MACHINE)
    r = Resource("data", ResourceType.FILE, scope="/data/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(bot, r, can_read=True))
    return reg, alice, bot, r


# ═══════════════════════════════════════════════════════════════════════════
# VectorClock
# ═══════════════════════════════════════════════════════════════════════════

class TestVectorClock:

    def test_tick_increments_node(self):
        vc = VectorClock()
        vc2 = vc.tick("A")
        assert vc2.to_dict()["A"] == 1

    def test_merge_takes_max(self):
        a = VectorClock({"A": 3, "B": 1})
        b = VectorClock({"A": 1, "B": 5, "C": 2})
        m = a.merge(b)
        assert m.to_dict() == {"A": 3, "B": 5, "C": 2}

    def test_happens_before(self):
        a = VectorClock({"A": 1})
        b = VectorClock({"A": 2})
        assert a.happens_before(b)
        assert not b.happens_before(a)

    def test_concurrent_not_ordered(self):
        a = VectorClock({"A": 2, "B": 1})
        b = VectorClock({"A": 1, "B": 2})
        assert not a.happens_before(b)
        assert not b.happens_before(a)


# ═══════════════════════════════════════════════════════════════════════════
# MerkleRegistryState
# ═══════════════════════════════════════════════════════════════════════════

class TestMerkleRegistryState:

    def test_same_registry_same_root(self):
        reg, _, _, _ = _registry_with_claim()
        s1 = MerkleRegistryState.from_registry(reg)
        s2 = MerkleRegistryState.from_registry(reg)
        assert s1.root == s2.root

    def test_different_claims_different_root(self):
        reg1, _, _, _ = _registry_with_claim()
        reg2, alice, bot, _ = _registry_with_claim()
        extra = Resource("extra", ResourceType.FILE, scope="/extra/")
        reg2.add_claim(RightsClaim(bot, extra, can_read=True))
        s1 = MerkleRegistryState.from_registry(reg1)
        s2 = MerkleRegistryState.from_registry(reg2)
        assert s1.diverges_from(s2)

    def test_empty_registry_has_stable_root(self):
        reg = OwnershipRegistry()
        s = MerkleRegistryState.from_registry(reg)
        assert isinstance(s.root, str)
        assert len(s.root) == 64  # sha256 hex

    def test_verify_claim_present(self):
        reg, _, _, r_claim = _registry_with_claim()
        state = MerkleRegistryState.from_registry(reg)
        claims = reg._claims
        assert state.verify_claim(claims[0])

    def test_verify_claim_absent(self):
        reg, alice, bot, _ = _registry_with_claim()
        state = MerkleRegistryState.from_registry(reg)
        ghost = Resource("ghost", ResourceType.FILE, scope="/ghost/")
        ghost_claim = RightsClaim(bot, ghost, can_read=True)
        assert not state.verify_claim(ghost_claim)


# ═══════════════════════════════════════════════════════════════════════════
# CapabilityEpoch
# ═══════════════════════════════════════════════════════════════════════════

class TestCapabilityEpoch:

    def test_initial_epoch_zero(self):
        e = CapabilityEpoch()
        assert e.current("cap:data") == 0

    def test_advance_increments(self):
        e = CapabilityEpoch()
        e1 = e.advance("cap:data")
        e2 = e.advance("cap:data")
        assert e1 == 1
        assert e2 == 2

    def test_is_stale_old_epoch(self):
        e = CapabilityEpoch()
        e.advance("cap:data")  # epoch = 1
        assert e.is_stale("cap:data", 0)  # 0 < 1 → stale

    def test_is_not_stale_current(self):
        e = CapabilityEpoch()
        e.advance("cap:data")  # epoch = 1
        assert not e.is_stale("cap:data", 1)


# ═══════════════════════════════════════════════════════════════════════════
# RevocationEvent — threshold signature rules
# ═══════════════════════════════════════════════════════════════════════════

class TestRevocationEvent:

    def _make_event(self, threshold=2) -> RevocationEvent:
        return RevocationEvent(
            capability_id="Bot:data",
            epoch=1,
            issued_at=time.time(),
            clock=VectorClock(),
            required_signers=["alice-node", "trust-node-1", "trust-node-2"],
            threshold=threshold,
            signature_set={},
        )

    def test_no_signatures_invalid(self):
        ev = self._make_event()
        assert not ev.is_valid()

    def test_threshold_met_but_no_owner_invalid(self):
        """T-of-N met but owner not among signers — invalid (A4/Consent)."""
        ev = self._make_event(threshold=2)
        ev.add_signature("trust-node-1", "sig1")
        ev.add_signature("trust-node-2", "sig2")
        assert not ev.is_valid()  # owner "alice-node" missing

    def test_owner_only_below_threshold_invalid(self):
        ev = self._make_event(threshold=2)
        ev.add_signature("alice-node", "owner-sig")
        assert not ev.is_valid()  # only 1 of 2 required

    def test_owner_plus_one_trust_valid(self):
        ev = self._make_event(threshold=2)
        ev.add_signature("alice-node", "owner-sig")
        ev.add_signature("trust-node-1", "sig1")
        assert ev.is_valid()

    def test_byzantine_forgery_without_owner_blocked(self):
        """Byzantine nodes collude but cannot produce owner's signature."""
        ev = self._make_event(threshold=2)
        ev.add_signature("evil-node-1", "forged1")
        ev.add_signature("evil-node-2", "forged2")
        ev.add_signature("evil-node-3", "forged3")
        # Threshold=2 met, but "alice-node" (owner) not present
        assert not ev.is_valid()


# ═══════════════════════════════════════════════════════════════════════════
# PartitionPolicy — fail-secure defaults
# ═══════════════════════════════════════════════════════════════════════════

class TestPartitionPolicy:

    def test_human_local_always_permit(self):
        p = PartitionPolicy("domain-A")
        d = p.decide("domain-A", "domain-A", actor_is_human=True, owner_reachable=False)
        assert d == PartitionDecision.PERMIT

    def test_human_remote_defer(self):
        p = PartitionPolicy("domain-A")
        d = p.decide("domain-A", "domain-B", actor_is_human=True, owner_reachable=False)
        assert d == PartitionDecision.DEFER_TO_HUMAN

    def test_machine_local_owner_reachable_permit(self):
        p = PartitionPolicy("domain-A")
        d = p.decide("domain-A", "domain-A", actor_is_human=False, owner_reachable=True)
        assert d == PartitionDecision.PERMIT

    def test_machine_cross_domain_deny(self):
        """Cross-domain machine action under partition → fail-secure deny (A7)."""
        p = PartitionPolicy("domain-A")
        d = p.decide("domain-A", "domain-B", actor_is_human=False, owner_reachable=False)
        assert d == PartitionDecision.DENY

    def test_machine_local_no_owner_deny(self):
        """Machine local but owner unreachable → deny."""
        p = PartitionPolicy("domain-A")
        d = p.decide("domain-A", "domain-A", actor_is_human=False, owner_reachable=False)
        assert d == PartitionDecision.DENY


# ═══════════════════════════════════════════════════════════════════════════
# FederatedNode — integration
# ═══════════════════════════════════════════════════════════════════════════

class TestFederatedNode:

    def test_state_hash_consistent(self):
        reg, _, _, _ = _registry_with_claim()
        node = FederatedNode("node-1", "domain-A", trust_level=3)
        node.attach_registry(reg)
        h1 = node.state_hash()
        h2 = node.state_hash()
        assert h1 == h2

    def test_divergence_detected(self):
        reg1, _, _, _ = _registry_with_claim()
        reg2, alice, bot, _ = _registry_with_claim()
        extra = Resource("extra", ResourceType.FILE, scope="/extra/")
        reg2.add_claim(RightsClaim(bot, extra, can_read=True))

        n1 = FederatedNode("n1", "domain-A", trust_level=3)
        n2 = FederatedNode("n2", "domain-A", trust_level=3)
        n1.attach_registry(reg1)
        n2.attach_registry(reg2)

        assert n1.is_diverged_from(n2)

    def test_revocation_advances_epoch(self):
        reg, _, _, _ = _registry_with_claim()
        node = FederatedNode("n1", "domain-A", trust_level=3)
        node.attach_registry(reg)

        event = node.issue_revocation(
            holder_name="Bot",
            resource_name="data",
            owner_node_id="alice-node",
            all_trust_node_ids=["alice-node", "trust-1"],
            threshold=1,
            owner_signature="sig",
        )
        assert event.epoch == 1
        assert node._epochs.current("Bot:data") == 1

    def test_stale_capability_rejected(self):
        reg, _, _, _ = _registry_with_claim()
        node = FederatedNode("n1", "domain-A", trust_level=3)
        node.attach_registry(reg)

        node.issue_revocation("Bot", "data", "alice-node", ["alice-node"], 1, "sig")
        # epoch is now 1; check with epoch=0 → stale
        assert not node.is_capability_valid("Bot", "data", epoch=0)

    def test_current_epoch_capability_valid(self):
        reg, _, _, _ = _registry_with_claim()
        node = FederatedNode("n1", "domain-A", trust_level=3)
        node.attach_registry(reg)
        # No revocation yet; epoch=0 is current
        assert node.is_capability_valid("Bot", "data", epoch=0)

    def test_gossip_propagates_to_peers(self):
        reg, _, _, _ = _registry_with_claim()
        n1 = FederatedNode("n1", "domain-A", trust_level=3)
        n2 = FederatedNode("n2", "domain-B", trust_level=3)
        n3 = FederatedNode("n3", "domain-C", trust_level=3)
        n1.attach_registry(reg)
        n1.add_peer(n2)
        n1.add_peer(n3)

        event = n1.issue_revocation("Bot", "data", "alice-node", ["alice-node"], 1, "sig")
        accepted = n1.gossip_revocation(event)
        assert accepted == 2
        # n2 and n3 now have the revocation applied
        assert n2._epochs.current("Bot:data") == 1
        assert n3._epochs.current("Bot:data") == 1

    def test_byzantine_revocation_rejected(self):
        """A revocation without the owner's signature is rejected by peers."""
        reg, _, _, _ = _registry_with_claim()
        n1 = FederatedNode("n1", "domain-A", trust_level=3)
        n2 = FederatedNode("n2", "domain-B", trust_level=3)
        n1.attach_registry(reg)
        n1.add_peer(n2)

        # Byzantine node creates revocation WITHOUT owner's signature
        evil_event = RevocationEvent(
            capability_id="Bot:data",
            epoch=1,
            issued_at=time.time(),
            clock=VectorClock(),
            required_signers=["alice-node", "evil-node"],
            threshold=2,
            signature_set={"evil-node-1": "forged1", "evil-node-2": "forged2"},
        )
        # Gossip this to n2 — should be rejected
        accepted = n1.gossip_revocation(evil_event)
        assert accepted == 0
        assert n2._epochs.current("Bot:data") == 0  # epoch unchanged

    def test_stale_gossip_rejected(self):
        """A revocation with a lower epoch than the node already has is rejected."""
        reg, _, _, _ = _registry_with_claim()
        n1 = FederatedNode("n1", "domain-A", trust_level=3)
        n2 = FederatedNode("n2", "domain-B", trust_level=3)
        n1.attach_registry(reg)
        n1.add_peer(n2)

        # n2 advances epoch to 3
        n2._epochs.advance("Bot:data")
        n2._epochs.advance("Bot:data")
        n2._epochs.advance("Bot:data")

        # n1 sends epoch=1 revocation — stale for n2
        event = n1.issue_revocation("Bot", "data", "alice-node", ["alice-node"], 1, "sig")
        accepted = n1.gossip_revocation(event)
        assert accepted == 0  # n2 rejected it (already at epoch 3)

    def test_merkle_recompute_after_claim_change(self):
        reg, alice, bot, _ = _registry_with_claim()
        node = FederatedNode("n1", "domain-A", trust_level=3)
        node.attach_registry(reg)
        root_before = node.state_hash()

        extra = Resource("extra", ResourceType.FILE, scope="/extra/")
        reg.add_claim(RightsClaim(bot, extra, can_read=True))
        root_after = node.recompute_merkle()

        assert root_before != root_after

    def test_verify_peer_state_honest(self):
        """Honest peer: recomputed hash matches stored hash."""
        reg, _, _, _ = _registry_with_claim()
        n1 = FederatedNode("n1", "domain-A", trust_level=3)
        n2 = FederatedNode("n2", "domain-B", trust_level=3)
        n1.attach_registry(reg)
        n2.attach_registry(reg)
        assert n1.verify_peer_state(n2)

    def test_partition_cross_domain_denied(self):
        reg, _, _, _ = _registry_with_claim()
        node = FederatedNode("n1", "domain-A", trust_level=3)
        node.attach_registry(reg)

        decision = node.cross_domain_permit(
            actor_name="Bot",
            resource_name="data",
            actor_domain="domain-A",
            resource_domain="domain-B",
            actor_is_human=False,
            owner_reachable=False,
        )
        assert decision == PartitionDecision.DENY
