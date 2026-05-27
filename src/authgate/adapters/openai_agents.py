"""
OpenAI function-calling / Agents SDK adapter.

Intercepts every tool call before execution and verifies it against the
Freedom Kernel. A BLOCKED result raises PermissionError before the tool
function is ever invoked.

Usage — decorator style:

    from authgate.adapters.openai_agents import OpenAIKernelMiddleware

    middleware = OpenAIKernelMiddleware(verifier, agent=bot_entity)

    @middleware.tool(resources_write=[report_resource])
    def write_report(content: str) -> str:
        with open("report.txt", "w") as f:
            f.write(content)
        return "written"

    # The decorated function now verifies before executing.
    write_report(content="hello")  # raises PermissionError if not permitted

Usage — manual interception:

    for tool_call in response.choices[0].message.tool_calls:
        result = middleware.check(
            action_id=tool_call.id,
            tool_name=tool_call.function.name,
            resources_write=[resource_map[tool_call.function.name]],
        )
        if not result.permitted:
            raise PermissionError(result.summary())
        # execute the tool...
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from authgate.kernel import Action, Entity, FreedomVerifier, Resource


class OpenAIKernelMiddleware:
    """
    Kernel middleware for OpenAI's function-calling and Agents SDK.

    Every tool registered via @middleware.tool(...) is automatically
    verified before execution. No tool call ever reaches execution
    unless the kernel permits it.
    """

    def __init__(self, verifier: FreedomVerifier, agent: Entity) -> None:
        self.verifier = verifier
        self.agent = agent

    def check(
        self,
        action_id: str,
        tool_name: str = "",
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ):
        """
        Verify a tool call action before execution.

        Returns VerificationResult. Caller decides whether to raise on block.
        """
        return self.verifier.verify(
            Action(
                action_id=action_id,
                actor=self.agent,
                description=f"tool:{tool_name}",
                resources_read=resources_read or [],
                resources_write=resources_write or [],
                resources_delegate=resources_delegate or [],
                **flags,
            )
        )

    def tool(
        self,
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ) -> Callable:
        """
        Decorator that gates a tool function behind the Freedom Kernel.

        @middleware.tool(resources_write=[my_file])
        def write_file(path: str, content: str) -> str: ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                result = self.check(
                    action_id=f"{self.agent.name}:{fn.__name__}",
                    tool_name=fn.__name__,
                    resources_read=resources_read,
                    resources_write=resources_write,
                    resources_delegate=resources_delegate,
                    **flags,
                )
                if not result.permitted:
                    raise PermissionError(result.summary())
                return fn(*args, **kwargs)
            wrapper.__kernel_resources_read__ = resources_read or []  # type: ignore[attr-defined]
            wrapper.__kernel_resources_write__ = resources_write or []  # type: ignore[attr-defined]
            return wrapper
        return decorator

    def openai_tool_definitions(self, tools: list[Callable]) -> list[dict]:
        """
        Build OpenAI-format tool definitions from decorated functions.
        Use with client.chat.completions.create(tools=...).
        """
        import inspect
        result = []
        for fn in tools:
            sig = inspect.signature(fn)
            props = {
                name: {"type": "string", "description": f"Parameter {name}"}
                for name in sig.parameters
            }
            result.append({
                "type": "function",
                "function": {
                    "name": fn.__name__,
                    "description": fn.__doc__ or "",
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": list(sig.parameters.keys()),
                    },
                },
            })
        return result
