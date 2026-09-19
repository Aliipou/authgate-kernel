"""
xAI Grok tool-use adapter.

Grok's chat-completions API is wire-compatible with OpenAI's function-calling
format (`tool_calls` on the assistant message, same `type: "function"` tool
definition shape) -- xAI documents the OpenAI SDK as a supported client,
pointed at a different base_url. This adapter mirrors
`OpenAIKernelMiddleware` for that reason rather than inventing a separate
shape: same Action IR, same PermissionError-before-execution contract.

Usage — decorator style:

    from authgate.adapters.grok import GrokKernelMiddleware

    middleware = GrokKernelMiddleware(verifier, agent=bot_entity)

    @middleware.tool(resources_write=[report_resource])
    def write_report(content: str) -> str:
        with open("report.txt", "w") as f:
            f.write(content)
        return "written"

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


class GrokKernelMiddleware:
    """
    Kernel middleware for xAI Grok's function-calling API.

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

    def grok_tool_definitions(self, tools: list[Callable]) -> list[dict]:
        """
        Build OpenAI-format tool definitions (Grok's function-calling format)
        from decorated functions. Use with client.chat.completions.create(tools=...).
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
