"""
MCP (Model Context Protocol) runtime gate for FreedomVerifier.

Intercepts MCP tool calls before execution, converts them to Action IR,
runs verify(), and either allows or blocks the call. Blocked calls surface
the violation to the MCP client as a structured error.

This adapter is NOT in the TCB. It is integration glue between the MCP
protocol and the kernel gate. Bugs here cannot produce false PERMITTED verdicts
from engine.rs — but they could fail to call verify() at all, which is a
misconfiguration, not a kernel vulnerability.

Usage:
    from authgate.adapters.mcp_gate import MCPGate
    from authgate.kernel.registry import OwnershipRegistry
    from authgate.kernel.verifier import FreedomVerifier

    registry = OwnershipRegistry()
    # ... register machines, add claims ...
    verifier = FreedomVerifier(registry)

    gate = MCPGate(verifier, actor=my_agent_entity)

    # Wrap tool execution:
    result = gate.call_tool("read_file", {"path": "/data/report.txt"}, resources_read=[report_resource])
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


@dataclass
class MCPToolCall:
    """Typed representation of an MCP tool invocation."""
    tool_name: str
    arguments: dict[str, Any]
    resources_read: list[Resource] = field(default_factory=list)
    resources_write: list[Resource] = field(default_factory=list)
    resources_execute: list[Resource] = field(default_factory=list)


@dataclass
class MCPGateResult:
    permitted: bool
    verification: VerificationResult
    tool_name: str
    error_message: str = ""

    def raise_if_blocked(self) -> None:
        if not self.permitted:
            raise PermissionError(
                f"MCP tool '{self.tool_name}' blocked by capability gate: "
                + "; ".join(self.verification.violations)
            )


class MCPGate:
    """
    Gate that intercepts MCP tool calls and verifies them against the kernel.

    Attach this to any MCP server or client that handles tool dispatch.
    Every tool call goes through verify() before execution.
    """

    def __init__(self, verifier: FreedomVerifier, actor: Entity) -> None:
        self._verifier = verifier
        self._actor = actor

    def check(self, call: MCPToolCall) -> MCPGateResult:
        """
        Verify an MCP tool call. Returns MCPGateResult.
        Call result.raise_if_blocked() to enforce the decision.
        """
        action = Action(
            action_id=f"mcp:{call.tool_name}",
            actor=self._actor,
            description=f"MCP tool call: {call.tool_name}",
            resources_read=call.resources_read,
            resources_write=call.resources_write,
            resources_delegate=call.resources_execute,
        )
        verification = self._verifier.verify(action)
        return MCPGateResult(
            permitted=verification.permitted,
            verification=verification,
            tool_name=call.tool_name,
            error_message="; ".join(verification.violations) if not verification.permitted else "",
        )

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_execute: list[Resource] | None = None,
    ) -> MCPGateResult:
        """
        Convenience method: verify a named tool call and raise if blocked.

        Callers should map MCP tool arguments to Resource objects before calling.
        Resource mapping is a caller responsibility — the kernel does not parse
        tool argument strings into resource identifiers.
        """
        call = MCPToolCall(
            tool_name=tool_name,
            arguments=arguments,
            resources_read=resources_read or [],
            resources_write=resources_write or [],
            resources_execute=resources_execute or [],
        )
        result = self.check(call)
        result.raise_if_blocked()
        return result

    def wrap_handler(self, tool_name: str, handler: Any, resource_mapper: Any = None) -> Any:
        """
        Return a wrapped version of handler that gates on verify() before calling through.

        resource_mapper(tool_name, arguments) -> (reads, writes, executes) — optional callable
        that maps tool arguments to resource lists. If None, no resource claims are checked
        (only sovereignty flags and ownership are verified).
        """
        def gated(*args: Any, **kwargs: Any) -> Any:
            reads, writes, executes = [], [], []
            if resource_mapper is not None:
                reads, writes, executes = resource_mapper(tool_name, kwargs)
            result = self.call_tool(
                tool_name, kwargs,
                resources_read=reads,
                resources_write=writes,
                resources_execute=executes,
            )
            return handler(*args, **kwargs)
        return gated
