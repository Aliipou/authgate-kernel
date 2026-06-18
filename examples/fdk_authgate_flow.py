"""
FDK -> AuthGate golden flow — the two products as one pipeline.

    Request -> Planner -> FDK (legitimacy) -> PolicyDecision
            -> enforce_legitimacy() -> AuthGate CallGate (authority) -> TCB -> execute

This example is decoupled: it constructs the FDK `PolicyDecision` payloads inline
(as they would arrive over the wire as JSON), so it needs no FDK install. It
shows the three outcomes that matter in production:

  1. ALLOW + authorized   -> tool runs
  2. ALLOW + unauthorized -> AuthGate denies (legitimacy passed, authority failed)
  3. DENY                 -> blocked before AuthGate is ever consulted

Run:  python examples/fdk_authgate_flow.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.integrations.fdk import enforce_legitimacy
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def build_gate() -> tuple[CallGate, Action, Action]:
    alice = Entity("alice", AgentType.HUMAN)
    bot = Entity("analyst-bot", AgentType.MACHINE)
    sales = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
    config = Resource("system-config", ResourceType.FILE, scope="/etc/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, sales, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, sales, can_read=True), delegated_by=alice)

    gate = CallGate(FreedomVerifier(reg, freeze=False))
    gate.register("read_sales", lambda path: f"<rows of {path}>")

    return gate, (
        Action("read-sales", actor=bot, resources_read=[sales])
    ), Action("read-config", actor=bot, resources_read=[config])


def main() -> None:
    gate, authorized, unauthorized = build_gate()

    # 1) FDK says ALLOW and the bot holds the capability → executes.
    allow = {"verdict": "ALLOW", "action_id": "read-sales", "actor": "analyst-bot"}
    r1 = enforce_legitimacy(allow, gate, authorized, "read_sales", {"path": "/data/alice/sales/q1.csv"})
    print(f"ALLOW + authorized   -> permitted={r1.permitted}  output={r1.output!r}")

    # 2) FDK says ALLOW but the bot has no claim on config → AuthGate denies.
    allow_cfg = {"verdict": "ALLOW", "action_id": "read-config", "actor": "analyst-bot"}
    r2 = enforce_legitimacy(allow_cfg, gate, unauthorized, "read_sales", {"path": "/etc/shadow"})
    print(f"ALLOW + unauthorized -> permitted={r2.permitted}  reason={r2.denied_reason}")

    # 3) FDK says DENY → blocked before AuthGate is consulted at all.
    deny = {"verdict": "DENY", "action_id": "read-sales", "axiom_trace": ["A7"],
            "reasons": ["A7: bot acts outside delegated scope"]}
    r3 = enforce_legitimacy(deny, gate, authorized, "read_sales", {"path": "/data/alice/sales/q1.csv"})
    print(f"DENY (legitimacy)    -> permitted={r3.permitted}  reason={r3.denied_reason}")


if __name__ == "__main__":
    main()
