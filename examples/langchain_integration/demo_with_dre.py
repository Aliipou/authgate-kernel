"""
authgate-kernel LangChain integration with DRE — end-to-end demo.

Demonstrates: registry setup → kernel verify → DRE advisory scoring → audit trail.

This extends the Phase D2 demo with:
  - Non-Determinism Class (NDC) annotation on agents
  - Delegate Reputation Extension (DRE) as an optional behavioral risk overlay
  - External attestation stubs (SPIFFE / Cloud IAM)

Run:
    python examples/langchain_integration/demo_with_dre.py

No LangChain installation required — uses the same minimal tool-runner stub
as demo.py. For real LangChain integration, see src/authgate/adapters/langchain.py.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Add src/ to path for direct execution without install
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from authgate.extensions.delegate_reputation import DelegateReputationEngine, NDC
from authgate.extensions.historical_behavior_store import HistoricalBehaviorStore
from authgate.kernel.audit import AuditLog
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("authgate.demo.dre")


# ---------------------------------------------------------------------------
# Domain model
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
    dre_score: dict[str, Any] | None = None
    dre_flags: list[str] = field(default_factory=list)
    audit_entry_count: int = 0


# ---------------------------------------------------------------------------
# Gated tool executor with DRE (standalone advisory pattern)
# ---------------------------------------------------------------------------

class GatedToolExecutorWithDRE:
    """
    Execute tools with DRE-enabled capability verification.

    Architecture:
      1. Kernel FreedomVerifier runs first (authority gate).
      2. If kernel permits, DRE evaluates behavioral risk (advisory only).
      3. Integrator decides whether to act on DRE flags.

    The registry is frozen at construction time — no TOCTOU.
    """

    def __init__(
        self,
        registry: OwnershipRegistry,
        tools: list[Tool],
        audit_log: AuditLog,
        dre_engine: DelegateReputationEngine,
    ) -> None:
        self._frozen = registry.freeze()
        self._tools: dict[str, Tool] = {t.name: t for t in tools}
        self._audit = audit_log
        self._kernel_verifier = FreedomVerifier(self._frozen, audit_log=self._audit)
        self._dre = dre_engine

    def execute(self, request: ToolCallRequest) -> ToolCallResult:
        tool = self._tools.get(request.tool_name)
        if tool is None:
            return ToolCallResult(
                tool_name=request.tool_name,
                permitted=False,
                violations=(f"Unknown tool: {request.tool_name}",),
            )

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

        # Step 1: Kernel authority check (the only gate that can Permit/Deny)
        kernel_result = self._kernel_verifier.verify(action)

        # Step 2: DRE advisory overlay (only if kernel permitted)
        dre_assessment = self._dre.evaluate(action, kernel_result)
        dre_dict = dataclasses.asdict(dre_assessment.score) if dre_assessment.score else None

        # Step 3: Integrator decision (DRE is advisory; kernel is authority)
        # In this demo, we respect the kernel verdict and log DRE flags.
        permitted = kernel_result.permitted

        if not permitted:
            log.warning(
                "BLOCKED: actor=%s tool=%s violations=%s",
                request.actor.name,
                request.tool_name,
                kernel_result.violations,
            )
            return ToolCallResult(
                tool_name=request.tool_name,
                permitted=False,
                violations=kernel_result.violations,
                dre_score=dre_dict,
                dre_flags=list(dre_assessment.risk_flags),
                audit_entry_count=len(self._audit),
            )

        # Kernel permitted — DRE may still flag elevated risk
        if dre_assessment.requires_human_arbitration:
            log.warning(
                "PERMIT (elevated risk): actor=%s tool=%s DRE=%.2f flags=%s",
                request.actor.name,
                request.tool_name,
                dre_assessment.dcrs,
                list(dre_assessment.risk_flags),
            )
        else:
            log.info(
                "PERMIT: actor=%s tool=%s DRE=%.2f",
                request.actor.name,
                request.tool_name,
                dre_assessment.dcrs,
            )

        output = tool.handler(request.inputs)
        return ToolCallResult(
            tool_name=request.tool_name,
            permitted=True,
            output=output,
            dre_score=dre_dict,
            dre_flags=list(dre_assessment.risk_flags),
            audit_entry_count=len(self._audit),
        )


# ---------------------------------------------------------------------------
# Demo scenario
# ---------------------------------------------------------------------------

def _build_scenario():
    """
    Scenario:
      - Human owner: alice
      - Agents:
          data-analyst-bot     (LLM_CLOSED — hosted API, lower risk)
          code-gen-bot         (LLM_OPEN  — local weights, higher risk)
          rogue-bot            (no owner, no NDC)
      - Resources:
          /data/alice/sales/   — DATASET (bots have read access)
          /reports/alice/      — FILE    (bots have write access)
          /system/config/      — FILE    (NO access — attack surface)
    """
    alice = Entity("alice", AgentType.HUMAN)

    # NDC is set via actor metadata — the DRE infers it from metadata["ndc"]
    analyst_bot = Entity(
        "data-analyst-bot", AgentType.MACHINE,
        metadata={"ndc": "LLM_CLOSED"},
    )
    code_gen_bot = Entity(
        "code-gen-bot", AgentType.MACHINE,
        metadata={"ndc": "LLM_OPEN"},
    )
    attacker = Entity("rogue-bot", AgentType.MACHINE)  # unregistered, no NDC

    sales_data = Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")
    report_file = Resource("report-file", ResourceType.FILE, scope="/reports/alice/")
    system_config = Resource("system-config", ResourceType.FILE, scope="/system/config/")

    registry = OwnershipRegistry()
    registry.register_machine(analyst_bot, alice)
    registry.register_machine(code_gen_bot, alice)
    # rogue-bot has no owner

    registry.add_claim(RightsClaim(analyst_bot, sales_data, can_read=True))
    registry.add_claim(RightsClaim(analyst_bot, report_file, can_write=True))
    registry.add_claim(RightsClaim(code_gen_bot, sales_data, can_read=True))
    registry.add_claim(RightsClaim(code_gen_bot, report_file, can_write=True))
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

    return registry, tools, analyst_bot, code_gen_bot, attacker


def run_demo():
    print("=" * 70)
    print("authgate-kernel — LangChain + DRE integration demo")
    print("(DRE is advisory-only; kernel TCB is the authority gate)")
    print("=" * 70)

    registry, tools, analyst_bot, code_gen_bot, attacker = _build_scenario()
    audit = AuditLog()
    hbs = HistoricalBehaviorStore(":memory:")
    dre = DelegateReputationEngine(hbs=hbs, threshold=1.0)

    # Seed some history: code-gen-bot has prior violations
    dre.record(
        Action(
            action_id="prior-bad-1",
            actor=code_gen_bot,
            resources_read=[Resource("sales-data", ResourceType.DATASET, scope="/data/alice/sales/")],
        ),
        VerificationResult(
            action_id="prior-bad-1",
            permitted=False,
            violations=("FORBIDDEN (increases machine sovereignty)",),
            warnings=(),
            confidence=0.0,
            requires_human_arbitration=True,
        ),
        ndc=NDC.LLM_OPEN,
    )

    executor = GatedToolExecutorWithDRE(registry, tools, audit, dre)

    scenarios = [
        # (label, actor, tool_name, inputs)
        ("EXPECT PERMIT", analyst_bot,     "read_sales",   {}),
        ("EXPECT PERMIT", analyst_bot,     "write_report",  {"content": "Q1 sales: $1.2M"}),
        ("EXPECT PERMIT (flagged)", code_gen_bot,    "read_sales",   {}),  # kernel permits, DRE flags risk
        ("EXPECT DENY  ", analyst_bot,     "read_config",   {}),  # no claim on system_config
        ("EXPECT DENY  ", attacker,        "read_sales",    {}),  # unregistered machine
        ("EXPECT DENY  ", analyst_bot,     "unknown_tool",  {}),  # tool doesn't exist
    ]

    results = []
    for label, actor, tool_name, inputs in scenarios:
        r = executor.execute(ToolCallRequest(tool_name, actor, inputs))
        status = "PERMIT" if r.permitted else "DENY  "
        print(f"\n[{status}] {label} | actor={actor.name} tool={tool_name}")
        if r.dre_score:
            print(f"  DRE score : DCRS={r.dre_score['dcrs']:.2f} "
                  f"ndc={r.dre_score['ndc']} "
                  f"hist={r.dre_score['historical_actions_90d']} actions")
        if r.dre_flags:
            print(f"  DRE flags : {r.dre_flags}")
        if r.permitted:
            print(f"  output    : {r.output[:80]}")
        else:
            for v in r.violations:
                print(f"  violation : {v[:120]}")
        results.append(r)

    # Verify audit chain
    print("\n" + "=" * 70)
    print("Audit log verification")
    print("=" * 70)
    print(f"  total entries : {len(audit)}")
    chain_ok = audit.verify_chain()
    print(f"  chain intact  : {chain_ok}")

    # Show each entry summary
    for i, entry in enumerate(audit.entries()):
        status = "PERMIT" if entry["permitted"] else "DENY  "
        print(f"  [{i:02d}] {status} {entry['action_id'][:50]}")

    # Summary
    print("\n" + "=" * 70)
    permit_count = sum(1 for r in results if r.permitted)
    deny_count = len(results) - permit_count
    print(f"Results: {permit_count} permitted, {deny_count} denied")
    print(f"Audit chain: {'INTACT' if chain_ok else 'BROKEN'}")

    # Assertions
    assert results[0].permitted, "analyst_bot read_sales should be permitted"
    assert results[1].permitted, "analyst_bot write_report should be permitted"
    # code_gen_bot: kernel permits (has claim), but DRE flags elevated risk
    assert results[2].permitted, "code_gen_bot read_sales: kernel permits; DRE is advisory"
    assert results[2].dre_flags, "code_gen_bot should have DRE risk flags due to bad history"
    assert not results[3].permitted, "read_config should be denied (no claim)"
    assert not results[4].permitted, "rogue-bot should be denied (no owner)"
    assert not results[5].permitted, "unknown tool should be denied"
    assert chain_ok, "Audit chain must be intact"

    # Only kernel records in audit; DRE does not write to kernel audit
    assert len(audit) == 6, f"Expected 6 kernel audit entries, got {len(audit)}"

    print("\nAll assertions passed — DRE advisory overlay demo complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
