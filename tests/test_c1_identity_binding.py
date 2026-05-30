"""
C-1 fix verification — identity token binding in Python layer.

Before fix: Entity("bot", MACHINE) with same name as registered machine → PERMITTED.
After fix:  Same name + matching identity_token → PERMITTED.
            Same name + different/missing identity_token → DENIED.
"""

from __future__ import annotations

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog


def _env_with_tokens():
    alice = Entity("alice", AgentType.HUMAN,   identity_token="alice-secret-abc")
    bot   = Entity("bot",   AgentType.MACHINE, identity_token="bot-secret-xyz")
    data  = Resource("data", ResourceType.FILE, scope="/data/")
    reg   = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
    return alice, bot, data, reg


# ─── The attack from FINDINGS.md C-1 ──────────────────────────────────────────

class TestC1ImpersonationBlocked:

    def test_attacker_with_same_name_no_token_denied(self):
        """The original C-1 attack: clone Entity with same (name, kind) — must be denied."""
        _, _, data, reg = _env_with_tokens()
        # Attacker constructs an Entity matching the registered bot's name+kind
        # but does NOT have the secret token
        impostor = Entity("bot", AgentType.MACHINE)  # no identity_token
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("steal", actor=impostor, resources_read=[data]))
        assert not r.permitted, "C-1 IMPERSONATION attack succeeded — fix broken"

    def test_attacker_with_wrong_token_denied(self):
        _, _, data, reg = _env_with_tokens()
        impostor = Entity("bot", AgentType.MACHINE, identity_token="wrong-secret")
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("steal", actor=impostor, resources_read=[data]))
        assert not r.permitted

    def test_legitimate_holder_with_correct_token_permits(self):
        _, bot, data, reg = _env_with_tokens()
        # bot already has correct token from _env_with_tokens
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("read", actor=bot, resources_read=[data]))
        assert r.permitted

    def test_register_machine_rejects_token_collision(self):
        alice = Entity("alice", AgentType.HUMAN, identity_token="alice-secret")
        bot   = Entity("bot",   AgentType.MACHINE, identity_token="bot-secret")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        # Same name+kind, different token — must be rejected
        impostor = Entity("bot", AgentType.MACHINE, identity_token="bot-impostor")
        with pytest.raises(PermissionError, match="IDENTITY_MISMATCH"):
            reg.register_machine(impostor, alice)


# ─── Backward compatibility — old code without tokens still works ─────────────

class TestC1BackwardCompat:

    def test_no_token_anywhere_works(self):
        """If nobody uses identity_token, behavior is unchanged from before."""
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("read", actor=bot, resources_read=[data]))
        assert r.permitted

    def test_no_token_means_impersonation_still_possible(self):
        """If no token registered, the C-1 gap is not closed automatically.
        Deployments must explicitly opt in by using identity_token."""
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
        # Clone — same name, kind, NO token, same as registered
        clone = Entity("bot", AgentType.MACHINE)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("read", actor=clone, resources_read=[data]))
        # When no token is used by either, they are indistinguishable.
        # This documents the deployment-time requirement: USE identity_token in prod.
        assert r.permitted  # documents the gap remains without explicit token


# ─── Token registry behavior ──────────────────────────────────────────────────

class TestC1TokenRegistry:

    def test_token_preserved_across_freeze(self):
        _, _, data, reg = _env_with_tokens()
        frozen = reg.freeze()
        # The token mapping survives freeze
        v = FreedomVerifier(frozen, audit_log=AuditLog())
        impostor = Entity("bot", AgentType.MACHINE, identity_token="wrong")
        r = v.verify(Action("attack", actor=impostor, resources_read=[data]))
        assert not r.permitted, "Token registry lost across freeze"

    def test_compound_key_separates_human_machine_same_name(self):
        """A HUMAN named 'x' and a MACHINE named 'x' do not collide."""
        human_x = Entity("x", AgentType.HUMAN,   identity_token="h-tok")
        machine_x = Entity("x", AgentType.MACHINE, identity_token="m-tok")
        data = Resource("data", ResourceType.FILE, scope="/data/")
        reg = OwnershipRegistry()
        # Both can be enrolled — different kinds
        reg.register_machine(machine_x, human_x)
        # Different kinds, no collision even though same name
        assert reg._identity_tokens[("x", "HUMAN")] == "h-tok"
        assert reg._identity_tokens[("x", "MACHINE")] == "m-tok"

    def test_owner_of_returns_none_for_impostor(self):
        _, _, _, reg = _env_with_tokens()
        impostor = Entity("bot", AgentType.MACHINE, identity_token="not-the-real-token")
        assert reg.owner_of(impostor) is None

    def test_claims_for_returns_empty_for_impostor(self):
        _, _, data, reg = _env_with_tokens()
        impostor = Entity("bot", AgentType.MACHINE, identity_token="not-the-real-token")
        assert reg.claims_for(impostor, data) == []
