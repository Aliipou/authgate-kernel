"""
authgate.runtime — minimal capability-gated AI agent runtime (MVP).

This is the operational layer described in planmvp.md. It is NOT part of the TCB.
It turns an agent intent into a tool plan, then executes each step through the
existing kernel CallGate so that no tool runs without a verified capability:

    intent -> Planner -> [PlanStep] -> AgentRuntime loop
                                          |
                                          v  per step
                                    build Action
                                          |
                                          v
                                 CallGate.verify + execute   (kernel TCB)
                                          |
                              permit -> sandboxed tool runs
                              deny   -> stop, nothing further runs
                                          |
                                          v
                              RunLog (jsonl) + hash-chained AuditLog

Design constraints (planmvp.md): single agent, 3 tools, mock planner,
AuthGate verify per call, simple sandbox, append-only log. No delegation graph,
no epoch DSL, no multi-agent, no federation in this layer.
"""
from __future__ import annotations

from authgate.runtime.agent import AgentRuntime, RunResult, StepOutcome, build_runtime
from authgate.runtime.planner import MockPlanner, Planner, PlanStep, ScriptedPlanner
from authgate.runtime.run_log import RunLog
from authgate.runtime.tools import Tool, ToolRegistry, build_default_tools

__all__ = [
    "AgentRuntime",
    "RunResult",
    "StepOutcome",
    "build_runtime",
    "Planner",
    "PlanStep",
    "MockPlanner",
    "ScriptedPlanner",
    "RunLog",
    "Tool",
    "ToolRegistry",
    "build_default_tools",
]
