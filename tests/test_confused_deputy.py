"""Confused-deputy adversarial test (AT-CONFUSED).

A deputy (bot) legitimately holds a delegated READ capability scoped to /data/.
The classic confused-deputy attack tries to make that privileged deputy exercise its
authority on /secrets/ (which it was never delegated), or to let an unprivileged
attacker borrow it. Authority here is resource-scoped and bound to the actor's own
capability chain — it cannot be redirected or borrowed. Every attack below must be denied.

Tests that PASS mean the attack was blocked.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _env():
    alice = Entity("alice", AgentType.HUMAN)
    attacker = Entity("attacker", AgentType.MACHINE)
    bot = Entity("bot", AgentType.MACHINE)
    data = Resource("data", ResourceType.FILE, scope="/data/")
    secrets = Resource("secrets", ResourceType.FILE, scope="/secrets/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.register_machine(attacker, alice)  # owned, but granted nothing
    reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
    reg.add_claim(RightsClaim(alice, secrets, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
    return alice, attacker, bot, data, secrets, reg


class TestConfusedDeputy(unittest.TestCase):
    def test_deputy_reads_its_own_scope(self):
        _, _, bot, data, _, reg = _env()
        v = FreedomVerifier(reg)
        self.assertTrue(v.verify(Action("read", actor=bot, resources_read=[data])).permitted)

    def test_deputy_cannot_be_confused_onto_another_resource(self):
        # Redirect the deputy's READ authority at /secrets/ — it has no claim there.
        _, _, bot, _, secrets, reg = _env()
        v = FreedomVerifier(reg)
        self.assertFalse(v.verify(Action("read", actor=bot, resources_read=[secrets])).permitted)

    def test_unprivileged_attacker_cannot_borrow_deputy_authority(self):
        # The deputy can read /data/; the attacker cannot — authority is non-transferable.
        _, attacker, _, data, _, reg = _env()
        v = FreedomVerifier(reg)
        self.assertFalse(v.verify(Action("read", actor=attacker, resources_read=[data])).permitted)


if __name__ == "__main__":
    unittest.main()
