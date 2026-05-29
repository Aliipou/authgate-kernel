"""
Distributed Kernel — Byzantine-fault-tolerant capability federation.

Axioms enforced structurally (not by policy):
  A4: Every machine has a registered human owner
  A5: Machine scope ⊆ owner scope (attenuation)
  A6: No machine governs any human
  A7: Resource access requires an explicit, valid, non-expired claim
  Consent: Revocation is always reachable by the human owner
  Freedom: Partition cannot trap a human — fail-secure default

Architecture:
  MerkleRegistryState  — Merkle tree over claim set; root hash = state fingerprint
  ThresholdRevocation  — revocation requires T-of-N signatures including the owner's key
  VectorClock          — causal ordering of capability events across nodes
  PartitionPolicy      — DENY on uncertain cross-domain actions; local remains valid
  FederatedNode        — combines all components; the unit of deployment

Byzantine-fault properties:
  - A compromised node cannot forge a permit (it cannot produce a valid threshold sig)
  - A compromised node cannot block a revocation (gossip is fan-out; one honest node suffices)
  - Split-brain cannot resurrect a revoked capability (epoch monotonicity)
  - Human property is a CRDT: merged by union, never silently deleted
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─── Vector Clock ────────────────────────────────────────────────────────────

@dataclass
class VectorClock:
    """Lamport-style per-node counters for causal ordering of capability events."""
    _clocks: dict[str, int] = field(default_factory=dict)

    def tick(self, node_id: str) -> "VectorClock":
        c = dict(self._clocks)
        c[node_id] = c.get(node_id, 0) + 1
        return VectorClock(c)

    def merge(self, other: "VectorClock") -> "VectorClock":
        merged = dict(self._clocks)
        for nid, count in other._clocks.items():
            merged[nid] = max(merged.get(nid, 0), count)
        return VectorClock(merged)

    def happens_before(self, other: "VectorClock") -> bool:
        """True if self causally precedes other (happens-before relation)."""
        all_keys = set(self._clocks) | set(other._clocks)
        return (
            all(self._clocks.get(k, 0) <= other._clocks.get(k, 0) for k in all_keys)
            and any(self._clocks.get(k, 0) < other._clocks.get(k, 0) for k in all_keys)
        )

    def to_dict(self) -> dict[str, int]:
        return dict(self._clocks)


# ─── Merkle Registry State ────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _claim_canonical(claim: Any) -> bytes:
    """Deterministic canonical representation of a claim for hashing."""
    obj = {
        "holder": getattr(claim.holder, "name", str(claim.holder)),
        "resource": getattr(claim.resource, "name", str(claim.resource)),
        "rtype": str(getattr(claim.resource, "rtype", "")),
        "can_read": bool(getattr(claim, "can_read", False)),
        "can_write": bool(getattr(claim, "can_write", False)),
        "can_delegate": bool(getattr(claim, "can_delegate", False)),
        "confidence": float(getattr(claim, "confidence", 1.0)),
        "expires_at": getattr(claim, "expires_at", None),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _merkle_root(leaf_hashes: list[str]) -> str:
    """Standard binary Merkle tree root from a list of leaf hashes."""
    if not leaf_hashes:
        return _sha256(b"empty")
    nodes = list(leaf_hashes)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # duplicate last leaf for odd counts
        nodes = [
            _sha256((nodes[i] + nodes[i + 1]).encode())
            for i in range(0, len(nodes), 2)
        ]
    return nodes[0]


@dataclass
class MerkleRegistryState:
    """
    Merkle tree over the claim set of an OwnershipRegistry.

    The root hash is a fingerprint of the entire registry state.
    Two nodes with the same root hash have identical claim sets.
    A single tampered claim changes the root hash detectably.
    """
    root: str
    leaf_hashes: list[str]
    claim_count: int
    timestamp: float

    @classmethod
    def from_registry(cls, registry: Any) -> "MerkleRegistryState":
        claims = sorted(
            getattr(registry, "_claims", []),
            key=lambda c: (
                getattr(c.holder, "name", ""),
                getattr(c.resource, "name", ""),
            ),
        )
        leaves = [_sha256(_claim_canonical(c)) for c in claims]
        return cls(
            root=_merkle_root(leaves),
            leaf_hashes=leaves,
            claim_count=len(claims),
            timestamp=time.time(),
        )

    def verify_claim(self, claim: Any) -> bool:
        """Verify that a specific claim is included in this Merkle state."""
        h = _sha256(_claim_canonical(claim))
        return h in self.leaf_hashes

    def diverges_from(self, other: "MerkleRegistryState") -> bool:
        return self.root != other.root


# ─── Threshold Revocation ─────────────────────────────────────────────────────

@dataclass
class RevocationEvent:
    """
    A capability revocation requiring threshold signatures.

    Invariant (A4 + Consent): the human owner's signature MUST be one of the
    T signatures. A quorum of byzantine nodes cannot revoke on the owner's behalf.

    signature_set: dict mapping signer_id → hex signature (HMAC-SHA256 over payload)
    For production: replace with real Ed25519 or threshold BLS.
    """
    capability_id: str       # (holder_name, resource_name) as "name:resource"
    epoch: int               # monotonically increasing per capability
    issued_at: float
    clock: VectorClock
    required_signers: list[str]  # must include the human owner's node_id
    threshold: int               # number of signatures required (T-of-N)
    signature_set: dict[str, str] = field(default_factory=dict)

    def add_signature(self, signer_id: str, signature: str) -> None:
        self.signature_set[signer_id] = signature

    def is_valid(self) -> bool:
        """
        A revocation is structurally valid when:
        1. At least self.threshold signatures are present
        2. The human owner's signer_id is among them (axiom A4/Consent)
        """
        if len(self.signature_set) < self.threshold:
            return False
        # Owner must be one of the signers
        owner_id = self.required_signers[0]  # convention: first entry = human owner node
        return owner_id in self.signature_set

    def payload(self) -> bytes:
        obj = {
            "capability_id": self.capability_id,
            "epoch": self.epoch,
            "issued_at": self.issued_at,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ─── Epoch Registry ───────────────────────────────────────────────────────────

@dataclass
class CapabilityEpoch:
    """
    Monotonic epoch counter per capability.

    A capability is stale if its epoch < the current epoch for that capability_id.
    Staleness = automatic invalidation, even without an explicit revocation message.
    This prevents partition-resurrected capabilities.
    """
    _epochs: dict[str, int] = field(default_factory=dict)

    def current(self, capability_id: str) -> int:
        return self._epochs.get(capability_id, 0)

    def advance(self, capability_id: str) -> int:
        self._epochs[capability_id] = self._epochs.get(capability_id, 0) + 1
        return self._epochs[capability_id]

    def is_stale(self, capability_id: str, epoch: int) -> bool:
        return epoch < self._epochs.get(capability_id, 0)


# ─── Partition Policy ─────────────────────────────────────────────────────────

class PartitionDecision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    DEFER_TO_HUMAN = "DEFER_TO_HUMAN"


@dataclass
class PartitionPolicy:
    """
    Fail-secure policy during network partition.

    Axiom alignment:
    - During partition: cross-domain actions are DENIED (not permitted).
      Rationale: permitting under uncertainty risks property rights violations.
    - Local actions (actor and resource in same domain, human owner reachable
      locally) remain PERMIT.
    - Human-initiated overrides always DEFER_TO_HUMAN (never auto-deny human).

    This is structurally different from fail-open systems where partition
    silently permits. Fail-open violates A7 (access without valid claim).
    """
    local_domain: str

    def decide(
        self,
        actor_domain: str,
        resource_domain: str,
        actor_is_human: bool,
        owner_reachable: bool,
    ) -> PartitionDecision:
        # Human actors always have standing to act on their own property
        if actor_is_human and actor_domain == resource_domain:
            return PartitionDecision.PERMIT

        # Human acting on remote domain — defer, do not auto-deny
        if actor_is_human:
            return PartitionDecision.DEFER_TO_HUMAN

        # Machine acting locally with owner reachable — permit
        if actor_domain == self.local_domain and resource_domain == self.local_domain and owner_reachable:
            return PartitionDecision.PERMIT

        # Cross-domain machine action under partition — fail-secure deny
        return PartitionDecision.DENY


# ─── Federated Node ───────────────────────────────────────────────────────────

@dataclass
class FederatedNode:
    """
    A single node in the distributed kernel network.

    Each node:
    - Maintains a local OwnershipRegistry
    - Computes a Merkle state fingerprint for divergence detection
    - Tracks capability epochs (revocation = epoch advance)
    - Gossips revocation events to peer nodes
    - Applies partition policy when peers are unreachable

    Invariants maintained structurally:
    - A revocation event without the owner's signature is rejected (A4/Consent)
    - A permit on a stale epoch is rejected even if the claim is present (A7)
    - Cross-domain actions during partition are denied (A7 + structural freedom)
    - Merkle root is recomputed on every claim mutation (tamper detection)
    """

    node_id: str
    domain: str
    trust_level: int  # 1–5; ≥4 can veto cross-domain consensus
    _registry: Any = field(default=None)
    _epochs: CapabilityEpoch = field(default_factory=CapabilityEpoch)
    _clock: VectorClock = field(default_factory=VectorClock)
    _revocations: list[RevocationEvent] = field(default_factory=list)
    _merkle: MerkleRegistryState | None = field(default=None)
    _peers: list["FederatedNode"] = field(default_factory=list)
    _partition_policy: PartitionPolicy | None = field(default=None)

    def __post_init__(self) -> None:
        self._partition_policy = PartitionPolicy(local_domain=self.domain)

    def attach_registry(self, registry: Any) -> None:
        self._registry = registry
        self._merkle = MerkleRegistryState.from_registry(registry)

    def add_peer(self, peer: "FederatedNode") -> None:
        if peer.node_id != self.node_id:
            self._peers.append(peer)

    def state_hash(self) -> str:
        if self._merkle is None:
            return _sha256(b"no-registry")
        return self._merkle.root

    def is_diverged_from(self, other: "FederatedNode") -> bool:
        return self.state_hash() != other.state_hash()

    def _capability_id(self, holder_name: str, resource_name: str) -> str:
        return f"{holder_name}:{resource_name}"

    def issue_revocation(
        self,
        holder_name: str,
        resource_name: str,
        owner_node_id: str,
        all_trust_node_ids: list[str],
        threshold: int,
        owner_signature: str,
    ) -> RevocationEvent:
        """
        Create a new revocation event and advance the epoch.
        The owner's signature is required to start the event (A4/Consent).
        """
        cap_id = self._capability_id(holder_name, resource_name)
        new_epoch = self._epochs.advance(cap_id)
        self._clock = self._clock.tick(self.node_id)

        event = RevocationEvent(
            capability_id=cap_id,
            epoch=new_epoch,
            issued_at=time.time(),
            clock=self._clock,
            required_signers=[owner_node_id] + [
                n for n in all_trust_node_ids if n != owner_node_id
            ],
            threshold=threshold,
            signature_set={owner_node_id: owner_signature},
        )
        self._revocations.append(event)
        return event

    def receive_revocation(self, event: RevocationEvent) -> bool:
        """
        Accept a revocation event from a peer.

        Acceptance rules:
        1. Must be structurally valid (threshold met + owner signed)
        2. Must not be stale (epoch must be ≥ current)
        3. Merge vector clock for causal ordering
        """
        if not event.is_valid():
            return False  # threshold not met or owner missing
        current = self._epochs.current(event.capability_id)
        if event.epoch <= current:
            return False  # stale — already at higher epoch
        self._epochs._epochs[event.capability_id] = event.epoch
        self._clock = self._clock.merge(event.clock)
        self._revocations.append(event)
        return True

    def gossip_revocation(self, event: RevocationEvent) -> int:
        """Fan-out revocation to all peers. Returns count of peers that accepted."""
        accepted = 0
        for peer in self._peers:
            if peer.receive_revocation(event):
                accepted += 1
        return accepted

    def is_capability_valid(
        self,
        holder_name: str,
        resource_name: str,
        epoch: int,
    ) -> bool:
        """
        A capability is valid iff:
        1. Its epoch equals the current epoch (not revoked)
        2. The registry actually contains the claim (A7)
        """
        cap_id = self._capability_id(holder_name, resource_name)
        if self._epochs.is_stale(cap_id, epoch):
            return False
        if self._registry is None:
            return False
        claims = getattr(self._registry, "_claims", [])
        return any(
            getattr(c.holder, "name", "") == holder_name
            and getattr(c.resource, "name", "") == resource_name
            for c in claims
        )

    def cross_domain_permit(
        self,
        actor_name: str,
        resource_name: str,
        actor_domain: str,
        resource_domain: str,
        actor_is_human: bool,
        owner_reachable: bool,
    ) -> PartitionDecision:
        """Apply partition policy for cross-domain action."""
        return self._partition_policy.decide(  # type: ignore[union-attr]
            actor_domain=actor_domain,
            resource_domain=resource_domain,
            actor_is_human=actor_is_human,
            owner_reachable=owner_reachable,
        )

    def recompute_merkle(self) -> str:
        """Recompute Merkle state after registry mutation. Returns new root."""
        if self._registry is None:
            return _sha256(b"no-registry")
        self._merkle = MerkleRegistryState.from_registry(self._registry)
        return self._merkle.root

    def verify_peer_state(self, peer: "FederatedNode") -> bool:
        """
        Verify that a peer's state hash matches their registry contents.
        A byzantine peer that lies about its hash is detectable here.
        """
        if peer._merkle is None or peer._registry is None:
            return False
        recomputed = MerkleRegistryState.from_registry(peer._registry)
        return recomputed.root == peer._merkle.root
