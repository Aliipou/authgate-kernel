"""
LangGraph integration for FreedomVerifier.

Wraps LangGraph node execution so that before each node invokes a tool,
the tool call is converted to an Action IR and verified. Blocked calls
raise PermissionError and halt the graph at that node.

This adapter is NOT in the TCB. It is integration glue. Bugs here cannot
produce false PERMITTED verdicts from engine.rs.

Usage:
    from authgate.adapters.langgraph import FreedomGraphNode, make_verified_tool

    # Wrap a tool function so it is gated before each call:
    safe_read = make_verified_tool(
        tool_fn=read_file,
        verifier=verifier,
        actor=bot_entity,
        resources_read=[file_resource],
    )

    # Or wrap an entire LangGraph node:
    node = FreedomGraphNode(
        name="research",
        node_fn=my_research_node,
        verifier=verifier,
        actor=bot_entity,
        resource_mapper=my_mapper,
    )
    graph.add_node("research", node)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.verifier import Action, FreedomVerifier


def make_verified_tool(
    tool_fn: Callable[..., Any],
    verifier: FreedomVerifier,
    actor: Entity,
    resources_read: list[Resource] | None = None,
    resources_write: list[Resource] | None = None,
    tool_name: str | None = None,
) -> Callable[..., Any]:
    """
    Wrap a callable tool so that verify() runs before each invocation.

    If the action is blocked, raises PermissionError with violation details.
    The tool_fn is only called if the kernel permits the action.
    """
    name = tool_name or getattr(tool_fn, "__name__", "unknown_tool")

    def verified(*args: Any, **kwargs: Any) -> Any:
        action = Action(
            action_id=f"langgraph:{name}",
            actor=actor,
            description=f"LangGraph tool: {name}",
            resources_read=resources_read or [],
            resources_write=resources_write or [],
        )
        result = verifier.verify(action)
        if not result.permitted:
            raise PermissionError(
                f"LangGraph tool '{name}' blocked by capability gate: "
                + "; ".join(result.violations)
            )
        return tool_fn(*args, **kwargs)

    verified.__name__ = f"verified_{name}"
    verified.__doc__ = f"Capability-gated wrapper around {name}."
    return verified


@dataclass
class FreedomGraphNode:
    """
    A LangGraph-compatible node that runs verify() before each node execution.

    resource_mapper(state) -> (reads, writes) maps graph state to resource lists.
    If None, only sovereignty flags and ownership are checked (no claim check).

    Usage with LangGraph:
        node = FreedomGraphNode("fetch", fetch_fn, verifier, actor, resource_mapper)
        graph.add_node("fetch", node)
    """
    name: str
    node_fn: Callable[..., Any]
    verifier: FreedomVerifier
    actor: Entity
    resource_mapper: Callable[[Any], tuple[list[Resource], list[Resource]]] | None = None

    def __call__(self, state: Any) -> Any:
        reads, writes = [], []
        if self.resource_mapper is not None:
            reads, writes = self.resource_mapper(state)

        action = Action(
            action_id=f"langgraph_node:{self.name}",
            actor=self.actor,
            description=f"LangGraph node: {self.name}",
            resources_read=reads,
            resources_write=writes,
        )
        result = self.verifier.verify(action)
        if not result.permitted:
            raise PermissionError(
                f"LangGraph node '{self.name}' blocked by capability gate: "
                + "; ".join(result.violations)
            )
        return self.node_fn(state)
