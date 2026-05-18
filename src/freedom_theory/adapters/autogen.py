"""
Microsoft AutoGen adapter.

Gates every tool registered with an AutoGen ConversableAgent behind the
Freedom Kernel. The tool function is never invoked unless the kernel permits
the action.

Usage — wrap individual functions:

    from freedom_theory.adapters.autogen import AutoGenKernelAdapter

    adapter = AutoGenKernelAdapter(verifier=verifier, agent_entity=bot)

    @adapter.tool(resources_write=[report_resource])
    def write_report(content: str) -> str:
        with open("report.txt", "w") as f:
            f.write(content)
        return "done"

    # If using AutoGen ConversableAgent:
    autogen_agent.register_function(
        function_map={"write_report": write_report},
    )

Usage — gate a whole function_map at registration time:

    from freedom_theory.adapters.autogen import AutoGenKernelAdapter

    adapter = AutoGenKernelAdapter(verifier, bot)
    adapter.register(
        agent=autogen_agent,
        function_map={
            "read_dataset": read_fn,
            "write_report": write_fn,
        },
        resource_map={
            "read_dataset":  ([dataset_resource], []),
            "write_report":  ([], [report_resource]),
        },
    )

Usage — check an incoming FunctionCallMessage manually:

    for msg in agent.chat_messages[...]:
        if msg.get("role") == "function":
            adapter.check(
                action_id=msg["name"],
                tool_name=msg["name"],
                resources_write=[resource_map[msg["name"]]],
            )
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from freedom_theory.kernel import Action, Entity, FreedomVerifier, Resource


class AutoGenKernelAdapter:
    """
    Freedom Kernel adapter for Microsoft AutoGen.

    Works with AutoGen v0.2.x ConversableAgent and compatible interfaces.
    The adapter is framework-version-agnostic: it never imports AutoGen
    directly, so it works without AutoGen installed (tested standalone).
    """

    def __init__(self, verifier: FreedomVerifier, agent_entity: Entity) -> None:
        self.verifier = verifier
        self.agent_entity = agent_entity

    def check(
        self,
        action_id: str,
        tool_name: str = "",
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ) -> Any:
        """
        Verify a tool call action before execution.

        Returns VerificationResult. Raises PermissionError if blocked.
        """
        result = self.verifier.verify(
            Action(
                action_id=action_id,
                actor=self.agent_entity,
                description=f"tool:{tool_name}",
                resources_read=resources_read or [],
                resources_write=resources_write or [],
                resources_delegate=resources_delegate or [],
                **flags,
            )
        )
        if not result.permitted:
            raise PermissionError(result.summary())
        return result

    def tool(
        self,
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ) -> Callable:
        """
        Decorator that gates a callable behind the Freedom Kernel.

        Compatible with AutoGen's @register_for_execution and plain callables.

            @adapter.tool(resources_write=[report])
            def write_report(content: str) -> str: ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self.check(
                    action_id=f"{self.agent_entity.name}:{fn.__name__}",
                    tool_name=fn.__name__,
                    resources_read=resources_read,
                    resources_write=resources_write,
                    resources_delegate=resources_delegate,
                    **flags,
                )
                return fn(*args, **kwargs)
            wrapper.__kernel_resources_read__ = resources_read or []  # type: ignore[attr-defined]
            wrapper.__kernel_resources_write__ = resources_write or []  # type: ignore[attr-defined]
            return wrapper
        return decorator

    def register(
        self,
        agent: Any,
        function_map: dict[str, Callable],
        resource_map: dict[str, tuple[list[Resource], list[Resource]]] | None = None,
    ) -> None:
        """
        Register a function_map with an AutoGen agent, gating each function.

        Args:
            agent:        AutoGen ConversableAgent (or compatible) with
                          a register_function(function_map=...) method.
            function_map: {tool_name: callable} to register.
            resource_map: {tool_name: ([reads], [writes])} resource lists.
                          Missing entries default to no resources.
        """
        resource_map = resource_map or {}
        gated_map: dict[str, Callable] = {}
        for name, fn in function_map.items():
            reads, writes = resource_map.get(name, ([], []))
            gated_map[name] = self.tool(
                resources_read=reads,
                resources_write=writes,
            )(fn)
        agent.register_function(function_map=gated_map)

    def check_message(self, message: dict[str, Any], resource_map: dict | None = None) -> Any:
        """
        Check an AutoGen function-call message dict before execution.

        Args:
            message:      Dict with at least "name" key (AutoGen function call format).
            resource_map: {tool_name: ([reads], [writes])} for resource lookup.
        """
        resource_map = resource_map or {}
        name = message.get("name", "unknown")
        reads, writes = resource_map.get(name, ([], []))
        return self.check(
            action_id=name,
            tool_name=name,
            resources_read=reads,
            resources_write=writes,
        )
