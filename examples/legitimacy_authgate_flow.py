"""
Legitimacy → AuthGate golden flow (decision-os composition).

    Request → Legitimacy (Freedom Formal) → PolicyDecision
           → enforce_legitimacy() → CallGate → execute

Run:  python examples/legitimacy_authgate_flow.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.integrations.legitimacy import (
    decide_freedom_formal,
    enforce_legitimacy,
)
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.research.freedom_formal import Claim


def build_gate() -> tuple[CallGate, Action, Action]:
    alice = Entity("alice", AgentType.HUMAN)
    bot = Entity("analyst-bot", AgentType.MACHINE)
    sales = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
    config = Resource("system-config", ResourceType.FILE, scope="/etc/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, sales, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, sales, can_read=True), delegated_by=alice)

    from authgate.kernel.audit import AuditLog

    gate = CallGate(FreedomVerifier(reg, freeze=False, audit_log=AuditLog()))
    gate.register("read_sales", lambda path: f"DATA:{path}")

    authorized = Action("read-sales", actor=bot, resources_read=[sales])
    unauthorized = Action("read-config", actor=bot, resources_read=[config])
    return gate, authorized, unauthorized


def main() -> None:
    gate, authorized, unauthorized = build_gate()

    clean = Claim(action_id="read-sales", actor_id="analyst-bot", actor_is_machine=True)
    allow = decide_freedom_formal(clean)
    r1 = enforce_legitimacy(allow, gate, authorized, "read_sales", {"path": "/data/q1.csv"})
    print("1. legitimacy ALLOW + authority OK ->", r1.permitted, r1.output)

    allow_cfg = decide_freedom_formal(
        Claim(action_id="read-config", actor_id="analyst-bot", actor_is_machine=True)
    )
    r2 = enforce_legitimacy(allow_cfg, gate, unauthorized, "read_sales", {"path": "/etc/shadow"})
    print("2. legitimacy ALLOW + authority DENY ->", r2.permitted, r2.denied_reason)

    dirty = Claim(
        action_id="read-sales",
        actor_id="analyst-bot",
        actor_is_machine=True,
        exit_blocked=True,
    )
    deny = decide_freedom_formal(dirty)
    r3 = enforce_legitimacy(deny, gate, authorized, "read_sales", {"path": "/data/q1.csv"})
    print("3. legitimacy DENY (before AuthGate) ->", r3.permitted, r3.denied_reason)


if __name__ == "__main__":
    main()
