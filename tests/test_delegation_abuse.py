"""
Delegation abuse attack tests — Phase 0, O3.

Tests DEL-1 through DEL-5 from the adversarial ontology.
Each test asserts the kernel response matches the expected outcome.

Catalog linkage: attack_harness/threat_taxonomy/delegation_abuse.py
"""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from attack_harness.threat_taxonomy.delegation_abuse import (
    run_del1_orphaned_delegation,
    run_del1b_orphaned_delegation_no_parent_claim,
    run_del2_chain_rights_amplification,
    run_del3_delegate_without_flag,
    run_del4_self_delegation,
    run_del5_scope_expansion,
)
from attack_harness.threat_taxonomy.ontology import DELEGATION_ABUSE_CATALOG, AttackClass


# ── Ontology structure ────────────────────────────────────────────────────────

class TestDelegationAbuseOntology:
    def test_catalog_has_five_entries(self):
        assert len(DELEGATION_ABUSE_CATALOG) == 5

    def test_all_entries_are_delegation_class(self):
        for s in DELEGATION_ABUSE_CATALOG:
            assert s.attack_class is AttackClass.AT_DEL

    def test_ids_unique(self):
        ids = [s.attack_id for s in DELEGATION_ABUSE_CATALOG]
        assert len(ids) == len(set(ids))


# ── DEL-1: Orphaned delegation ────────────────────────────────────────────────

class TestDEL1OrphanedDelegation:
    def test_intact_chain_permits(self):
        result = run_del1_orphaned_delegation()
        assert result["expected"] == "PERMIT"
        assert result["permitted"], (
            "DEL-1: intact delegation chain should permit, got violations: "
            + str(result["violations"])
        )

    def test_broken_chain_no_parent_claim_denies(self):
        result = run_del1b_orphaned_delegation_no_parent_claim()
        assert result["blocked"], (
            "DEL-1b: orphaned delegation (no parent claim) should deny"
        )

    def test_delegation_chain_requires_parent_claim(self):
        human = Entity("alice", AgentType.HUMAN)
        delegator = Entity("delegator", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(delegator, human)
        reg.register_machine(child, human)
        # Only add child's delegated claim — no parent claim
        reg.add_claim(RightsClaim(child, resource, can_read=True, delegated_by=delegator))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted


# ── DEL-2: Rights amplification across chain ─────────────────────────────────

class TestDEL2ChainRightsAmplification:
    def test_write_via_delegation_denied_if_parent_only_reads(self):
        result = run_del2_chain_rights_amplification()
        assert result["blocked"], f"DEL-2 leaked: {result['violations']}"

    def test_attenuation_must_hold_at_every_hop(self):
        human = Entity("alice", AgentType.HUMAN)
        a = Entity("a", AgentType.MACHINE)
        b = Entity("b", AgentType.MACHINE)
        c = Entity("c", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(a, human)
        reg.register_machine(b, human)
        reg.register_machine(c, human)

        reg.add_claim(RightsClaim(a, resource, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(b, resource, can_read=True, delegated_by=a))
        # c tries to get write from b, but b only has read
        reg.add_claim(RightsClaim(c, resource, can_read=True, can_write=True, delegated_by=b))
        frozen = reg.freeze()

        action = Action(action_id="write", actor=c, resources_write=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted, "write cannot be granted through read-only chain"

    def test_write_permitted_if_parent_has_write(self):
        human = Entity("alice", AgentType.HUMAN)
        parent = Entity("parent", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(parent, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(parent, resource, can_read=True, can_write=True, can_delegate=True))
        reg.add_claim(RightsClaim(child, resource, can_write=True, delegated_by=parent))
        frozen = reg.freeze()
        action = Action(action_id="write", actor=child, resources_write=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Write delegation from write-capable parent should permit: "
            + str(result.violations)
        )


# ── DEL-3: Delegation without can_delegate ────────────────────────────────────

class TestDEL3DelegateWithoutFlag:
    def test_delegation_from_non_delegating_entity_denied(self):
        result = run_del3_delegate_without_flag()
        assert result["blocked"], f"DEL-3 leaked: {result['violations']}"

    def test_delegation_permitted_when_flag_set(self):
        human = Entity("alice", AgentType.HUMAN)
        delegator = Entity("delegator", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(delegator, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(delegator, resource, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(child, resource, can_read=True, delegated_by=delegator))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Delegation from can_delegate=True entity should permit: "
            + str(result.violations)
        )

    def test_can_delegate_false_blocks_chain(self):
        human = Entity("alice", AgentType.HUMAN)
        delegator = Entity("delegator", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(delegator, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(delegator, resource, can_read=True, can_delegate=False))
        reg.add_claim(RightsClaim(child, resource, can_read=True, delegated_by=delegator))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted


# ── DEL-4: Self-delegation ─────────────────────────────────────────────────────

class TestDEL4SelfDelegation:
    def test_self_delegation_denied(self):
        result = run_del4_self_delegation()
        assert result["blocked"], f"DEL-4 leaked: {result['violations']}"

    def test_self_delegation_does_not_grant_write(self):
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        # Self-delegate with write — no root grant of write exists
        reg.add_claim(RightsClaim(
            bot, resource, can_read=True, can_write=True, delegated_by=bot
        ))
        frozen = reg.freeze()
        action = Action(action_id="write", actor=bot, resources_write=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted, "Self-delegation must not grant write authority"


# ── DEL-5: Scope expansion ────────────────────────────────────────────────────

class TestDEL5ScopeExpansion:
    def test_scope_expansion_via_delegation_denied(self):
        result = run_del5_scope_expansion()
        assert result["blocked"], f"DEL-5 leaked: {result['violations']}"

    def test_delegated_claim_narrower_scope_permits(self):
        human = Entity("alice", AgentType.HUMAN)
        parent = Entity("parent", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        parent_resource = Resource("data", ResourceType.DATASET, scope="/data/")
        child_resource = Resource("sales", ResourceType.DATASET, scope="/data/sales/")
        reg = OwnershipRegistry()
        reg.register_machine(parent, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(parent, parent_resource, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(child, child_resource, can_read=True, delegated_by=parent))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[child_resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Delegation with narrower child scope should be permitted: "
            + str(result.violations)
        )

    def test_equal_scope_delegation_permits(self):
        human = Entity("alice", AgentType.HUMAN)
        parent = Entity("parent", AgentType.MACHINE)
        child = Entity("child", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET, scope="/data/")
        reg = OwnershipRegistry()
        reg.register_machine(parent, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(parent, resource, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(child, resource, can_read=True, delegated_by=parent))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Delegation at equal scope should be permitted: " + str(result.violations)
        )
