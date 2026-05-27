"""
LangChain tool adapter.

Wraps a Python function as a LangChain BaseTool with Freedom Kernel
verification. The tool is blocked before execution if the kernel
denies the action.

Usage:

    from authgate.adapters.langchain import FreedomTool

    class WriteReportTool(FreedomTool):
        name = "write_report"
        description = "Write the analysis report to disk."
        kernel_verifier = verifier
        kernel_agent = bot_entity
        kernel_resources_write = [report_resource]

        def _run(self, content: str) -> str:
            with open("report.txt", "w") as f:
                f.write(content)
            return "written"

    # Use with LangChain agent
    tools = [WriteReportTool()]
    agent = initialize_agent(tools, llm, ...)

The Freedom Kernel check happens in _run before your logic executes.
No LangChain-internal modification needed.

For LangChain v0.2+ with the new tools API:

    from langchain_core.tools import tool
    from authgate.adapters.langchain import kernel_gate

    @tool
    @kernel_gate(verifier, agent=bot, resources_write=[report])
    def write_report(content: str) -> str:
        "Write the report."
        ...
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from authgate.kernel import Action, Entity, FreedomVerifier, Resource


def kernel_gate(
    verifier: FreedomVerifier,
    agent: Entity,
    resources_read: list[Resource] | None = None,
    resources_write: list[Resource] | None = None,
    **flags: bool,
) -> Callable:
    """
    Decorator that gates any callable behind the Freedom Kernel.

    Compatible with LangChain @tool decorator (apply kernel_gate first,
    then @tool on top — or the other way; both work).

        @tool
        @kernel_gate(verifier, agent=bot, resources_write=[report])
        def write_report(content: str) -> str: ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = verifier.verify(
                Action(
                    action_id=f"{agent.name}:{fn.__name__}",
                    actor=agent,
                    description=f"tool:{fn.__name__}",
                    resources_read=resources_read or [],
                    resources_write=resources_write or [],
                    **flags,
                )
            )
            if not result.permitted:
                raise PermissionError(result.summary())
            return fn(*args, **kwargs)
        return wrapper
    return decorator


class FreedomTool:
    """
    Base class for LangChain tools with built-in Freedom Kernel verification.

    Subclass this instead of LangChain's BaseTool when you want automatic
    kernel gating. If LangChain is installed, this class inherits from
    BaseTool. If not, it works as a standalone callable.

    Required class attributes:
        name                     — tool name
        description              — tool description
        kernel_verifier          — FreedomVerifier instance
        kernel_agent             — Entity acting as this tool
        kernel_resources_read    — list[Resource] (default: [])
        kernel_resources_write   — list[Resource] (default: [])
    """

    name: str = ""
    description: str = ""
    kernel_verifier: FreedomVerifier | None = None
    kernel_agent: Entity | None = None
    kernel_resources_read: list[Resource] = []
    kernel_resources_write: list[Resource] = []

    def _verify(self, action_id: str | None = None) -> None:
        if self.kernel_verifier is None or self.kernel_agent is None:
            return
        result = self.kernel_verifier.verify(
            Action(
                action_id=action_id or f"{self.kernel_agent.name}:{self.name}",
                actor=self.kernel_agent,
                description=f"tool:{self.name}",
                resources_read=list(self.kernel_resources_read),
                resources_write=list(self.kernel_resources_write),
            )
        )
        if not result.permitted:
            raise PermissionError(result.summary())

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("Implement _run in your tool subclass.")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        self._verify()
        return self._run(*args, **kwargs)

    # LangChain compatibility: if BaseTool is available, forward _run through kernel
    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        try:
            from langchain_core.tools import BaseTool  # type: ignore[import]
            if not issubclass(cls, BaseTool):
                original_run = cls._run

                @functools.wraps(original_run)
                def gated_run(self: Any, *args: Any, **kwargs: Any) -> Any:
                    self._verify()
                    return original_run(self, *args, **kwargs)

                cls._run = gated_run  # type: ignore[method-assign]
        except ImportError:
            pass
