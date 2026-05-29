"""
Authority escalation attack tests — Phase 0, O3.

Tests ESC-1 through ESC-6 from the adversarial ontology.
Each test asserts the kernel response matches what the ontology predicts.

Catalog linkage: attack_harness/threat_taxonomy/authority_escalation.py
"""
import time

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from attack_harness.threat_taxonomy.authority_escalation import (
    run_esc1_ghost_principal,
    run_esc2_rights_amplification,
    run_esc3_confidence_inflation,
    run_esc4_sovereignty_flag,
    run_esc5_machine_governs_human,
    run_esc6_expired_claim,
)
from attack_harness.threat_taxonomy.ontology import (
    AUTHORITY_ESCALATION_CATALOG,
    AttackClass,
    AttackSeverity,
    critical_scenarios,
)


# ── Ontology structure tests ──────────────────────────────────────────────────

class TestOntologyStructure:
    def test_escalation_catalog_has_six_entries(self):
        assert len(AUTHORITY_ESCALATION_CATALOG) == 6

    def test_all_escalation_entries_are_critical_or_high(self):
        for scenario in AUTHORITY_ESCALATION_CATALOG:
            assert scenario.severity in (AttackSeverity.CRITICAL, AttackSeverity.HIGH), (
                f"{scenario.attack_id} should be CRITICAL or HIGH, got {scenario.severity}"
            )

    def test_all_escalation_entries_belong_to_at_esc_class(self):
        for scenario in AUTHORITY_ESCALATION_CATALOG:
            assert scenario.attack_class is AttackClass.AT_ESC

    def test_attack_ids_are_unique(self):
        ids = [s.attack_id for s in AUTHORITY_ESCALATION_CATALOG]
        assert len(ids) == len(set(ids))

    def test_all_critical_scenarios_appear_in_catalog(self):
        critical = critical_scenarios()
        esc_critical = [s for s in critical if s.attack_class is AttackClass.AT_ESC]
        assert len(esc_critical) >= 4, "Expect at least 4 CRITICAL escalation scenarios"


# ── ESC-1: Ghost principal ────────────────────────────────────────────────────

class TestESC1GhostPrincipal:
    def test_unregistered_actor_is_denied(self):
        result = run_esc1_ghost_principal()
        assert result["blocked"], f"ESC-1 leaked: {result['violations']}"

    def test_unregistered_actor_produces_violation(self):
        result = run_esc1_ghost_principal()
        assert len(result["violations"]) > 0

    def test_ghost_principal_direct(self):
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        frozen = reg.freeze()
        ghost = Entity("ghost", AgentType.MACHINE)
        action = Action(action_id="read", actor=ghost, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted


# ── ESC-2: Rights amplification ───────────────────────────────────────────────

class TestESC2RightsAmplification:
    def test_write_denied_without_write_claim(self):
        result = run_esc2_rights_amplification()
        assert result["blocked"], f"ESC-2 leaked: {result['violations']}"

    def test_amplification_produces_violation(self):
        result = run_esc2_rights_amplification()
        assert len(result["violations"]) > 0

    def test_read_permitted_write_denied_same_actor(self):
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(bot, resource, can_read=True, can_write=False))
        frozen = reg.freeze()
        verifier = FreedomVerifier(frozen)

        read_action = Action(action_id="read", actor=bot, resources_read=[resource])
        write_action = Action(action_id="write", actor=bot, resources_write=[resource])
        assert verifier.verify(read_action).permitted
        assert not verifier.verify(write_action).permitted


# ── ESC-3: Confidence inflation (documented gap) ──────────────────────────────

class TestESC3ConfidenceInflation:
    def test_inflated_confidence_now_denied(self):
        """ESC-3: Python layer now enforces T2 anti-monotonicity via _delegation_chain_valid."""
        result = run_esc3_confidence_inflation()
        # Gap closed: _delegation_chain_valid rejects child.confidence > parent.confidence
        assert result["blocked"], (
            "ESC-3: confidence inflation should be denied by delegation chain validation"
        )

    def test_rfc_confidence_cannot_be_above_one(self):
        with pytest.raises(ValueError):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=1.01,
            )

    def test_equal_confidence_delegation_permitted(self):
        """Equal confidence delegation is valid (anti-monotonicity: ≤ not <)."""
        human = Entity("alice", AgentType.HUMAN)
        parent = Entity("parent-bot", AgentType.MACHINE)
        child = Entity("child-bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(parent, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(parent, resource, can_read=True, confidence=0.8, can_delegate=True))
        reg.add_claim(RightsClaim(child, resource, can_read=True, confidence=0.8, delegated_by=parent))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Equal confidence is valid (anti-monotonicity is ≤ not <): " + str(result.violations)
        )

    def test_lower_confidence_delegation_permitted(self):
        human = Entity("alice", AgentType.HUMAN)
        parent = Entity("parent-bot", AgentType.MACHINE)
        child = Entity("child-bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(parent, human)
        reg.register_machine(child, human)
        reg.add_claim(RightsClaim(parent, resource, can_read=True, confidence=0.8, can_delegate=True))
        reg.add_claim(RightsClaim(child, resource, can_read=True, confidence=0.5, delegated_by=parent))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=child, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted, (
            "Lower confidence is valid attenuation: " + str(result.violations)
        )


# ── ESC-4: Sovereignty flags ──────────────────────────────────────────────────

class TestESC4SovereigntyFlags:
    def test_increases_machine_sovereignty_always_denied(self):
        result = run_esc4_sovereignty_flag()
        assert result["blocked"], f"ESC-4 leaked: {result['violations']}"

    def test_flag_produces_forbidden_violation(self):
        result = run_esc4_sovereignty_flag()
        assert any("FORBIDDEN" in v for v in result["violations"])

    @pytest.mark.parametrize("flag_name", [
        "increases_machine_sovereignty",
        "resists_human_correction",
        "bypasses_verifier",
        "weakens_verifier",
        "disables_corrigibility",
    ])
    def test_each_sovereignty_flag_denied(self, flag_name):
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(bot, resource, can_read=True))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=bot, resources_read=[resource], **{flag_name: True})
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted, f"Flag {flag_name} should always deny"


# ── ESC-5: Machine governs human ─────────────────────────────────────────────

class TestESC5MachineGovernsHuman:
    def test_governs_humans_always_denied(self):
        result = run_esc5_machine_governs_human()
        assert result["blocked"], f"ESC-5 leaked: {result['violations']}"

    def test_governs_humans_violation_present(self):
        result = run_esc5_machine_governs_human()
        assert len(result["violations"]) > 0

    def test_machine_dominion_violation_message(self):
        result = run_esc5_machine_governs_human()
        assert any("MACHINE_DOMINION" in v or "governs" in v.lower()
                   for v in result["violations"])


# ── ESC-6: Expired claim ──────────────────────────────────────────────────────

class TestESC6ExpiredClaim:
    def test_expired_claim_denied(self):
        result = run_esc6_expired_claim()
        assert result["blocked"], f"ESC-6 leaked: {result['violations']}"

    def test_fresh_claim_permitted_same_scenario(self):
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(
            bot, resource, can_read=True,
            expires_at=time.time() + 3600,
        ))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=bot, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert result.permitted

    def test_expiry_boundary_exact(self):
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(
            bot, resource, can_read=True,
            expires_at=time.time() - 0.001,
        ))
        frozen = reg.freeze()
        action = Action(action_id="read", actor=bot, resources_read=[resource])
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted
