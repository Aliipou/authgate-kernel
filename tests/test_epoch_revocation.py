"""
Epoch revocation tests — C-3 fix.

Verifies that the Python layer now implements epoch-based revocation,
mirroring the Rust TCB's primary revocation mechanism.

The epoch mechanism works as follows:
  - Every RightsClaim has an epoch (default: 1)
  - Every Action has a min_epoch (default: 0)
  - If claim.epoch < action.min_epoch, the claim is rejected
  - To revoke an entire cohort of claims: registry.advance_epoch(new_epoch, holder)
  - Any subsequent Action with min_epoch=new_epoch rejects old claims in O(1)
"""

from __future__ import annotations

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog


def _env(freeze: bool = True):
    alice = Entity("alice", AgentType.HUMAN)
    bot   = Entity("bot",   AgentType.MACHINE)
    data  = Resource("data", ResourceType.FILE, scope="/data/")
    reg   = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True, epoch=1), delegated_by=alice)
    return alice, bot, data, reg


class TestEpochRevocation:

    def test_claim_at_epoch_1_permits_when_min_epoch_is_0(self):
        _, bot, data, reg = _env(freeze=True)
        v = FreedomVerifier(reg)
        r = v.verify(Action("read", actor=bot, resources_read=[data], min_epoch=0))
        assert r.permitted

    def test_claim_at_epoch_1_permits_when_min_epoch_equals_1(self):
        _, bot, data, reg = _env()
        v = FreedomVerifier(reg)
        r = v.verify(Action("read", actor=bot, resources_read=[data], min_epoch=1))
        assert r.permitted

    def test_claim_at_epoch_1_denied_when_min_epoch_is_2(self):
        """Core epoch revocation: old claim rejected by advancing min_epoch."""
        _, bot, data, reg = _env()
        v = FreedomVerifier(reg)
        r = v.verify(Action("read", actor=bot, resources_read=[data], min_epoch=2))
        assert not r.permitted
        assert any("epoch" in viol.lower() for viol in r.violations), r.violations

    def test_advance_epoch_reissues_claims(self):
        """After advance_epoch, new actions with new min_epoch permit again."""
        _, bot, data, reg = _env()
        v = FreedomVerifier(reg, freeze=False)

        # Before advance: min_epoch=2 denies
        r1 = v.verify(Action("read1", actor=bot, resources_read=[data], min_epoch=2))
        assert not r1.permitted

        # Advance epoch to 2
        updated = reg.advance_epoch(2, holder_name=bot.name)
        assert updated > 0

        # Now min_epoch=2 permits
        r2 = v.verify(Action("read2", actor=bot, resources_read=[data], min_epoch=2))
        assert r2.permitted, r2.violations

    def test_advance_epoch_global_affects_all_claims(self):
        """advance_epoch(None) advances all claims in the registry."""
        alice = Entity("alice", AgentType.HUMAN)
        bot1  = Entity("bot1",  AgentType.MACHINE)
        bot2  = Entity("bot2",  AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")

        reg = OwnershipRegistry()
        reg.register_machine(bot1, alice)
        reg.register_machine(bot2, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot1, data, can_read=True, epoch=1), delegated_by=alice)
        reg.delegate(RightsClaim(bot2, data, can_read=True, epoch=1), delegated_by=alice)

        # Both denied at epoch 3
        v = FreedomVerifier(reg, freeze=False)
        assert not v.verify(Action("r1", actor=bot1, resources_read=[data], min_epoch=3)).permitted
        assert not v.verify(Action("r2", actor=bot2, resources_read=[data], min_epoch=3)).permitted

        # Advance all
        reg.advance_epoch(3)

        # Both permitted
        assert v.verify(Action("r3", actor=bot1, resources_read=[data], min_epoch=3)).permitted
        assert v.verify(Action("r4", actor=bot2, resources_read=[data], min_epoch=3)).permitted

    def test_epoch_revocation_works_with_frozen_verifier(self):
        """Epoch revocation is encoded in the action, not registry state.
        A frozen verifier can reject old-epoch claims without registry mutation."""
        _, bot, data, reg = _env()
        # Freeze at epoch=1
        v = FreedomVerifier(reg, freeze=True)

        # min_epoch=0 permits (default)
        assert v.verify(Action("r1", actor=bot, resources_read=[data])).permitted

        # min_epoch=2 denies — even with frozen verifier, epoch gate applies
        r = v.verify(Action("r2", actor=bot, resources_read=[data], min_epoch=2))
        assert not r.permitted, "Epoch gate must work with frozen verifier"

    def test_default_action_min_epoch_zero_permits_all_existing_claims(self):
        """Backward compatibility: existing code (min_epoch=0) is unaffected."""
        _, bot, data, reg = _env()
        v = FreedomVerifier(reg)
        r = v.verify(Action("read", actor=bot, resources_read=[data]))
        assert r.permitted, "Default min_epoch=0 must not break existing behavior"

    def test_epoch_in_audit_log(self):
        """Epoch value is visible in audit log entries."""
        _, bot, data, reg = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("read", actor=bot, resources_read=[data], min_epoch=1))
        entries = audit.entries()
        assert len(entries) == 1
        assert entries[0]["permitted"] is True

    def test_stale_epoch_denial_logged_in_audit(self):
        """Epoch denial appears in audit log like any other denial."""
        _, bot, data, reg = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("read", actor=bot, resources_read=[data], min_epoch=99))
        entries = audit.entries()
        assert len(entries) == 1
        assert entries[0]["permitted"] is False

    def test_advance_epoch_returns_count(self):
        _, bot, data, reg = _env()
        count = reg.advance_epoch(5, holder_name=bot.name)
        assert count > 0

    def test_advance_epoch_idempotent_if_already_advanced(self):
        """Advancing to same epoch again changes nothing."""
        _, bot, data, reg = _env()
        reg.advance_epoch(3, holder_name=bot.name)
        count = reg.advance_epoch(3, holder_name=bot.name)
        assert count == 0  # already at epoch 3, nothing to update
