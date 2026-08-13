"""
AgentRuntime — the MVP agent loop (non-TCB orchestration).

This is the whole runtime, and it is deliberately tiny (planmvp.md STEP 1):

    plan = planner.plan(intent)
    for step in plan:
        action = build_action(step)          # typed capability request
        result = gate.execute(action, ...)   # kernel verifies + runs (or denies)
        run_log.record(...)                  # trace it
        if denied: stop                       # a denial halts the plan

Every security decision happens inside the kernel `CallGate` / `FreedomVerifier`;
this module only *sequences* steps and turns each one into a typed `Action`. It
holds no authority of its own — if the agent lacks a capability, the gate denies
the step and the loop stops, with nothing further executed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate, GateResult
from authgate.kernel.entities import AgentType, Entity, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.runtime.planner import Planner, PlanStep
from authgate.runtime.run_log import RunLog
from authgate.runtime.tools import Tool, ToolRegistry, build_default_tools


@dataclass(frozen=True)
class StepOutcome:
    """One executed (or denied) plan step and its gate result."""

    step: PlanStep
    result: GateResult

    @property
    def permitted(self) -> bool:
        return self.result.permitted


@dataclass(frozen=True)
class RunResult:
    """Outcome of running one intent through the runtime."""

    intent: str
    agent_id: str
    outcomes: list[StepOutcome] = field(default_factory=list)
    stopped_early: bool = False

    @property
    def permitted_count(self) -> int:
        return sum(1 for o in self.outcomes if o.permitted)

    @property
    def denied_count(self) -> int:
        return sum(1 for o in self.outcomes if not o.permitted)

    def outputs(self) -> list[Any]:
        """Outputs of the permitted steps, in order — used for reproducibility checks."""
        return [o.result.output for o in self.outcomes if o.permitted]


class AgentRuntime:
    """Sequences a plan through the kernel gate. Owns no authority itself."""

    def __init__(
        self,
        agent: Entity,
        gate: CallGate,
        tools: ToolRegistry,
        planner: Planner,
        run_log: RunLog | None = None,
        min_epoch: int = 0,
    ) -> None:
        self._agent = agent
        self._gate = gate
        self._tools = tools
        self._planner = planner
        self._run_log = run_log or RunLog()
        self._min_epoch = min_epoch

    @property
    def run_log(self) -> RunLog:
        return self._run_log

    def run(self, intent: str) -> RunResult:
        """Plan the intent, then gate-execute each step until done or denied."""
        steps = self._planner.plan(intent)
        outcomes: list[StepOutcome] = []
        stopped_early = False

        for index, step in enumerate(steps):
            result = self._execute_step(index, step)
            outcomes.append(StepOutcome(step=step, result=result))
            if not result.permitted:
                # A denied step halts the plan: later steps may depend on it, and
                # continuing would let an agent "probe" past a denial.
                stopped_early = index < len(steps) - 1
                break

        return RunResult(
            intent=intent, agent_id=self._agent.name,
            outcomes=outcomes, stopped_early=stopped_early,
        )

    def _execute_step(self, index: int, step: PlanStep) -> GateResult:
        """Build the typed Action for a step and run it through the gate."""
        try:
            tool = self._tools.get(step.tool)
        except KeyError as exc:
            # A planner (or prompt-injected plan) naming an unknown tool is a
            # denial, not a crash — there is no capability to grant for it.
            result = GateResult(permitted=False,
                                denied_reason=f"unknown tool: {exc}", tool_name=step.tool)
            self._log(index, step, result)
            return result

        action = self._build_action(index, step, tool)
        result = self._gate.execute(action, tool.name, step.args)
        self._log(index, step, result)
        return result

    def _build_action(self, index: int, step: PlanStep, tool: Tool) -> Action:
        """Turn a plan step into a typed capability request for the tool's resource."""
        reads = [tool.resource] if tool.mode == "read" else []
        writes = [tool.resource] if tool.mode == "write" else []
        return Action(
            action_id=f"{self._agent.name}-step{index}-{tool.name}",
            actor=self._agent,
            description=step.rationale,
            resources_read=reads,
            resources_write=writes,
            argument=json.dumps(step.args, sort_keys=True, default=str),
            min_epoch=self._min_epoch,
        )

    def _log(self, index: int, step: PlanStep, result: GateResult) -> None:
        self._run_log.record(
            agent_id=self._agent.name, step_index=index,
            tool=step.tool, args=step.args,
            permitted=result.permitted, output=result.output,
            denied_reason=result.denied_reason,
        )


def _make_verifier(backend: str, registry: OwnershipRegistry, audit: AuditLog, freeze: bool):
    """Select the authorization engine. "python" = reference verifier; "rust" =
    the formally-verified Rust engine (requires the built extension); "auto" =
    Rust when available, else Python."""
    if backend == "python":
        return FreedomVerifier(registry, audit_log=audit, freeze=freeze)
    from authgate.runtime.rust_backend import RustBackedVerifier, rust_backend_available
    if backend == "rust":
        return RustBackedVerifier(registry, audit_log=audit, freeze=freeze)
    if backend == "auto":
        if rust_backend_available():
            return RustBackedVerifier(registry, audit_log=audit, freeze=freeze)
        return FreedomVerifier(registry, audit_log=audit, freeze=freeze)
    raise ValueError(f"unknown backend {backend!r}; use 'python', 'rust', or 'auto'")


def _make_sandboxed_fn(tool_name: str, sandbox_root: Path, policy: Any):
    """Wrap a tool so it executes in an isolated subprocess under `policy`. A
    limit breach (timeout/OOM/crash) surfaces as an exception, which the gate
    turns into a clean denial — same contract as an in-process tool raising."""
    from authgate.runtime.sandbox import run_tool_sandboxed

    def run(**args: Any) -> Any:
        result = run_tool_sandboxed(tool_name, args, sandbox_root, policy)
        if result.ok:
            return result.output
        raise RuntimeError(result.error or "sandbox denied")

    return run


def build_runtime(
    intent_planner: Planner,
    sandbox_root: Path,
    granted_tools: list[str] | None = None,
    audit_log: AuditLog | None = None,
    run_log: RunLog | None = None,
    freeze: bool = False,
    backend: str = "python",
    sandbox_policy: Any = None,
) -> tuple[AgentRuntime, OwnershipRegistry]:
    """Wire a single-agent runtime for demos/tests.

    Creates a human owner, a machine agent it owns, and delegates read claims for
    each tool in `granted_tools` (default: all). Tools NOT granted will be denied
    by the gate when the planner tries to use them — exactly the MVP behavior.

    backend: "python" (default), "rust" (verified Rust engine via JSON wire), or
        "auto". sandbox_policy: when set (a SandboxPolicy), tools run in an
        isolated subprocess under OS resource limits instead of in-process.

    Returns (runtime, registry). The registry is returned so callers can revoke
    claims / advance epochs and observe the gate react (when freeze=False).
    """
    owner = Entity("operator", AgentType.HUMAN)
    agent = Entity("agent-1", AgentType.MACHINE)
    tools = build_default_tools(sandbox_root)
    granted = set(tools.names() if granted_tools is None else granted_tools)

    registry = OwnershipRegistry()
    registry.register_machine(agent, owner)
    for tool in tools:
        if tool.name not in granted:
            continue
        # Owner asserts authority over the resource, then delegates read to the agent.
        registry.add_claim(RightsClaim(owner, tool.resource, can_read=True, can_delegate=True))
        registry.delegate(RightsClaim(agent, tool.resource, can_read=True),
                          delegated_by=owner)

    audit = audit_log if audit_log is not None else AuditLog()
    verifier = _make_verifier(backend, registry, audit, freeze)
    gate = CallGate(verifier)
    for tool in tools:
        fn = _make_sandboxed_fn(tool.name, sandbox_root, sandbox_policy) if sandbox_policy else tool.fn
        gate.register(tool.name, fn)

    runtime = AgentRuntime(agent=agent, gate=gate, tools=tools,
                           planner=intent_planner, run_log=run_log)
    return runtime, registry
