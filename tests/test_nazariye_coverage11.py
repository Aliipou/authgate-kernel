"""
Coverage tests (batch 11, final) added on the `nazariye-azadi` branch.

Targets the last uncovered branches: anti-capture owner mismatch, recursive
governance subtree BFS, distributed kernel Merkle/state/verify paths, and the
federation consensus + decision validation.
"""
from __future__ import annotations

import time

from authgate.analysis.anti_capture import AntiCaptureChecker
from authgate.analysis.recursive_governance import RecursiveGovernanceChecker
from authgate.distributed import distributed_kernel as dk
from authgate.distributed.distributed_kernel import FederatedNode, RevocationEvent, VectorClock
from authgate.distributed.federation import (
    ConsensusResult,
    FederatedDecision,
    FederatedDecisionType,
    FederatedKernelID,
    FederationGateway,
)
from authgate.kernel.entities import AgentType, Entity
from authgate.kernel.verifier import Action


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


# --------------------------------------------------------------------------- #
# analysis/anti_capture.py
# --------------------------------------------------------------------------- #

def test_anti_capture_owner_mismatch_unregistered_actor():
    from authgate.kernel.registry import OwnershipRegistry
    checker = AntiCaptureChecker()
    bot = _machine()  # NOT registered in the registry
    action = Action("a", bot, governs_humans=[_human("Carol")])
    # registered_owner is None -> returns [] (line 177)
    assert checker._check_owner_mismatch(action, bot, OwnershipRegistry()) == []


# --------------------------------------------------------------------------- #
# analysis/recursive_governance.py — subtree BFS revisits a shared child
# --------------------------------------------------------------------------- #

def test_recursive_governance_subtree_diamond():
    g = RecursiveGovernanceChecker()
    g.add_link("A", "B")
    g.add_link("A", "C")
    g.add_link("B", "D")
    g.add_link("C", "D")  # D reachable via two paths -> BFS revisits (line 121)
    nodes = g._subtree_nodes("A")
    assert {"A", "B", "C", "D"} <= nodes


# --------------------------------------------------------------------------- #
# distributed/distributed_kernel.py
# --------------------------------------------------------------------------- #

def test_merkle_root_odd_leaf_count():
    root = dk._merkle_root(["h1", "h2", "h3"])  # odd -> duplicates last (line 92)
    assert isinstance(root, str) and len(root) == 64


def test_revocation_event_payload():
    ev = RevocationEvent(
        capability_id="bot:doc", epoch=1, issued_at=1.0, clock=VectorClock(),
        required_signers=["owner-node"], threshold=1,
    )
    payload = ev.payload()  # lines 177-182
    assert b"capability_id" in payload


def test_federated_node_no_registry_paths():
    node = FederatedNode(node_id="n1", domain="d1", trust_level=3)  # _registry None
    # state_hash with no merkle -> "no-registry" hash (line 302)
    assert isinstance(node.state_hash(), str)
    # is_capability_valid with no registry -> False (line 384)
    assert node.is_capability_valid("bot", "doc", 1) is False
    # recompute_merkle with no registry -> "no-registry" hash (line 412)
    assert isinstance(node.recompute_merkle(), str)
    # verify_peer_state on a peer with no merkle -> False (line 422)
    peer = FederatedNode(node_id="n2", domain="d2", trust_level=3)
    assert node.verify_peer_state(peer) is False


# --------------------------------------------------------------------------- #
# distributed/federation.py
# --------------------------------------------------------------------------- #

def test_consensus_result_consensus_achieved():
    res = ConsensusResult(
        action_id="a1", permitted=True, permit_count=2, deny_count=0,
        abstain_count=0, total_kernels=2, threshold=0.5, achieved_fraction=1.0,
        denying_kernels=(), reason="ok",
    )
    assert res.consensus_achieved is True  # line 119


def test_federation_validate_decision_bad_proof_length():
    gw = FederationGateway()
    kid = FederatedKernelID("k1", "finance", 3)
    gw.register_kernel(kid)
    decision = FederatedDecision(
        kernel_id=kid,
        action_id="a1",
        decision=FederatedDecisionType.PERMIT,
        proof_commitment="too-short",  # len != 64 -> line 247
        timestamp=time.time(),
    )
    assert gw.validate_decision(decision) is False
