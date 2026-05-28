"""
authgate-kernel LangChain integration — end-to-end capability verification demo.

Demonstrates: registry setup → freeze → per-tool verification → audit trail.

This is the Phase D2 "real integration" required by MASTER_PLAN success criterion #5.
It shows a non-trivial AI system (LangChain tool executor) gated by authgate-kernel.

Run:
    python examples/langchain_integration/demo.py

No LangChain installation required — the demo uses a minimal tool-runner stub
that mirrors the adapter pattern used in src/authgate/adapters/langchain.py.
For real LangChain integration, see src/authgate/adapters/langchain.py.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Add src/ to path for direct execution without install
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from authgate.kernel.audit import AuditLog
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("authgate.demo")


# ---------------------------------------------------------------------------
# Domain model: a minimal "tool" abstraction
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    """A capability-gated tool an AI agent can invoke."""
    name: str
    resource: Resource
    operation: str  # "read" | "write"
    handler: Callable[[dict[str, Any]], str]


@dataclass
class ToolCallRequest:
    tool_name: str
    actor: Entity
    inputs: dict[str, Any]


@dataclass
class ToolCallResult:
    tool_name: str
    permitted: bool
    output: str = ""
    violations: tuple[str, ...] = field(default_factory=tuple)
    audit_entry_count: int = 0


# ---------------------------------------------------------------------------
# Gated tool executor — the core integration point
# ---------------------------------------------------------------------------

class GatedToolExecutor:
    """
    Execute tools only when the actor holds a verified capability.

    Every call to execute() produces one AuditLog entry. The registry
    is frozen at construction time — no TOCTOU between registry checks.
    """

    def __init__(
        self,
        registry: OwnershipRegistry,
        tools: list[Tool],
        audit_log: AuditLog,
    ) -> None:
        self._frozen = registry.freeze()
        self._tools: dict[str, Tool] = {t.name: t for t in tools}
        self._audit = audit_log
        self._verifier = FreedomVerifier(self._frozen, audit_log=self._audit)

    def execute(self, request: ToolCallRequest) -> ToolCallResult:
        tool = self._tools.get(request.tool_name)
        if tool is None:
            return ToolCallResult(
                tool_name=request.tool_name,
                permitted=False,
                violations=(f"Unknown tool: {request.tool_name}",),
            )

        # Build Action from tool metadata
        action_kwargs: dict[str, Any] = {
            "action_id": f"{request.tool_name}@{int(time.time()*1000)}",
            "actor": request.actor,
            "description": f"Invoke tool {request.tool_name}",
        }
        if tool.operation == "read":
            action_kwargs["resources_read"] = [tool.resource]
        elif tool.operation == "write":
            action_kwargs["resources_write"] = [tool.resource]

        action = Action(**action_kwargs)
        result = self._verifier.verify(action)

        if not result.permitted:
            log.warning(
                "BLOCKED: actor=%s tool=%s violations=%s",
                request.actor.name,
                request.tool_name,
                result.violations,
            )
            return ToolCallResult(
                tool_name=request.tool_name,
                permitted=False,
                violations=result.violations,
                audit_entry_count=len(self._audit),
            )

        log.info("PERMIT: actor=%s tool=%s", request.actor.name, request.tool_name)
        output = tool.handler(request.inputs)
        return ToolCallResult(
            tool_name=request.tool_name,
            permitted=True,
            output=output,
            audit_entry_count=len(self._audit),
        )


# ---------------------------------------------------------------------------
# Demo scenario
# ---------------------------------------------------------------------------

def _build_scenario():
    """
    Scenario:
      - Human owner: alice
      - Agent: data-analyst-bot (owned by alice)
      - Resources:
          /data/alice/sales/ — DATASET (bot has read access)
          /reports/alice/    — FILE (bot has write access)
          /system/config/    — FILE (bot has NO access — attack surface)
    """
    alice = Entity("alice", AgentType.HUMAN)
    bot = Entity("data-analyst-bot", AgentType.MACHINE)
    attacker = Entity("rogue-bot", AgentType.MACHINE)  # unregistered, no owner

    sales_data = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
    report_file = Resource("report-file", ResourceType.FILE, scope="/reports/alice/")
    system_config = Resource("system-config", ResourceType.FILE, scope="/system/config/")

    registry = OwnershipRegistry()
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(bot, sales_data, can_read=True))
    registry.add_claim(RightsClaim(bot, report_file, can_write=True))
    # system_config: no claim added

    tools = [
        Tool(
            name="read_sales",
            resource=sales_data,
            operation="read",
            handler=lambda _: json.dumps({"q1": 1_200_000, "q2": 980_000}),
        ),
        Tool(
            name="write_report",
            resource=report_file,
            operation="write",
            handler=lambda inp: f"Report written: {inp.get('content', '')}",
        ),
        Tool(
            name="read_config",
            resource=system_config,
            operation="read",
            handler=lambda _: "root:x:0:0:root:/root:/bin/bash",
        ),
    ]

    return registry, tools, bot, attacker


def run_demo():
    print("=" * 60)
    print("authgate-kernel — LangChain integration demo")
    print("=" * 60)

    registry, tools, bot, attacker = _build_scenario()
    audit = AuditLog()
    executor = GatedToolExecutor(registry, tools, audit)

    scenarios = [
        ("EXPECT PERMIT",  bot,      "read_sales",   {}),
        ("EXPECT PERMIT",  bot,      "write_report",  {"content": "Q1 sales: $1.2M"}),
        ("EXPECT DENY  ",  bot,      "read_config",   {}),      # no claim on system_config
        ("EXPECT DENY  ",  attacker, "read_sales",    {}),      # unregistered machine
        ("EXPECT DENY  ",  bot,      "unknown_tool",  {}),      # tool doesn't exist
    ]

    results = []
    for label, actor, tool_name, inputs in scenarios:
        r = executor.execute(ToolCallRequest(tool_name, actor, inputs))
        status = "PERMIT" if r.permitted else "DENY  "
        print(f"\n[{status}] {label} | actor={actor.name} tool={tool_name}")
        if r.permitted:
            print(f"  output    : {r.output[:80]}")
        else:
            for v in r.violations:
                print(f"  violation : {v[:120]}")
        results.append(r)

    # Verify audit chain
    print("\n" + "=" * 60)
    print("Audit log verification")
    print("=" * 60)
    print(f"  total entries : {len(audit)}")
    chain_ok = audit.verify_chain()
    print(f"  chain intact  : {chain_ok}")

    # Show each entry summary
    for i, entry in enumerate(audit.entries()):
        status = "PERMIT" if entry["permitted"] else "DENY  "
        print(f"  [{i:02d}] {status} {entry['action_id'][:60]}")

    # Summary
    print("\n" + "=" * 60)
    permit_count = sum(1 for r in results if r.permitted)
    deny_count = len(results) - permit_count
    print(f"Results: {permit_count} permitted, {deny_count} denied")
    print(f"Audit chain: {'INTACT' if chain_ok else 'BROKEN'}")

    # Assertions (makes this runnable as a test)
    assert results[0].permitted, "read_sales should be permitted"
    assert results[1].permitted, "write_report should be permitted"
    assert not results[2].permitted, "read_config should be denied (no claim)"
    assert not results[3].permitted, "rogue-bot should be denied (no owner)"
    assert not results[4].permitted, "unknown tool should be denied"
    assert chain_ok, "Audit chain must be intact"
    assert len(audit) == 4, "4 tool invocations should produce 4 audit entries (unknown tool skips verify)"

    print("\nAll assertions passed — integration demo complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
