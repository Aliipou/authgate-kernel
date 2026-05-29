"""
CrewAI adapter — Phase 1, O3.

Gates every CrewAI Task execution behind the Freedom Kernel. A BLOCKED result
raises PermissionError before the task's action function is ever invoked.

Two integration patterns:

1. Decorator pattern — wrap any callable as a kernel-gated CrewAI task:

    from authgate.adapters.crewai import CrewAIKernelGate

    gate = CrewAIKernelGate(verifier, agent=bot_entity)

    @gate.task(resources_write=[report_resource])
    def write_report(content: str) -> str:
        with open("report.txt", "w") as f:
            f.write(content)
        return "written"

    write_report(content="hello")  # raises PermissionError if not permitted

2. Task-level guard — wrap a CrewAI Task object before execution:

    from crewai import Task
    task = Task(description="Write report", agent=crewai_agent, ...)
    gate.guard_task(task, resources_write=[report_resource])
    # task._kernel_gate is now set; CrewAI Crew will verify before executing.

3. Crew-level middleware — wrap all tasks in a Crew at once:

    crew = Crew(agents=[...], tasks=[task1, task2])
    gate.wrap_crew(crew, task_resource_map={
        task1: {"resources_write": [r1]},
        task2: {"resources_read": [r2]},
    })
    crew.kickoff()  # all tasks verified before execution

Design notes:
  - No CrewAI dependency at import time — uses duck typing for compatibility.
  - Works with CrewAI ≥0.28 (task.execute() / execute_sync() / task.action())
  - The gate is transparent: if the kernel permits, the original function executes
    with the original return value. No CrewAI behavior is modified.
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from authgate.kernel import Action, Entity, FreedomVerifier, Resource
from authgate.errors import AuthgateError


class KernelDeniedError(AuthgateError):
    """Raised when the kernel denies a CrewAI task execution."""


class CrewAIKernelGate:
    """
    Kernel gate for CrewAI agents and tasks.

    Thread-safe: a single gate instance may be shared across multiple tasks
    and agents within a crew.
    """

    def __init__(self, verifier: FreedomVerifier, agent: Entity) -> None:
        self.verifier = verifier
        self.agent = agent

    def verify(
        self,
        action_id: str,
        task_description: str = "",
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ):
        """
        Verify a task action before execution.

        Returns VerificationResult. Does not raise — caller decides on deny.
        """
        return self.verifier.verify(
            Action(
                action_id=action_id,
                actor=self.agent,
                description=f"crewai-task:{task_description}",
                resources_read=resources_read or [],
                resources_write=resources_write or [],
                resources_delegate=resources_delegate or [],
                **flags,
            )
        )

    def task(
        self,
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ) -> Callable:
        """
        Decorator: gate a callable behind the kernel before execution.

        Usage:
            @gate.task(resources_write=[report_resource])
            def write_report(content: str) -> str:
                ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                action_id = f"crewai:{fn.__name__}"
                result = self.verify(
                    action_id=action_id,
                    task_description=fn.__doc__ or fn.__name__,
                    resources_read=resources_read,
                    resources_write=resources_write,
                    resources_delegate=resources_delegate,
                    **flags,
                )
                if not result.permitted:
                    raise KernelDeniedError(
                        f"CrewAI task '{fn.__name__}' blocked by kernel: "
                        f"{result.summary()}"
                    )
                return fn(*args, **kwargs)
            wrapper._kernel_gated = True
            return wrapper
        return decorator

    def guard_task(
        self,
        task: Any,
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        resources_delegate: list[Resource] | None = None,
        **flags: bool,
    ) -> Any:
        """
        Wrap a CrewAI Task object so its action is kernel-gated before execution.

        Compatible with CrewAI Task objects that have an `execute`,
        `execute_sync`, or `action` callable attribute.
        Modifies task in-place and returns it.
        """
        gate = self
        task_desc = getattr(task, "description", str(task))

        for attr in ("execute", "execute_sync", "action", "_execute_core"):
            original = getattr(task, attr, None)
            if original is not None and callable(original):
                def _guarded(*args: Any, _orig=original, _attr=attr, **kwargs: Any) -> Any:
                    action_id = f"crewai-task:{id(task)}"
                    result = gate.verify(
                        action_id=action_id,
                        task_description=task_desc,
                        resources_read=resources_read,
                        resources_write=resources_write,
                        resources_delegate=resources_delegate,
                        **flags,
                    )
                    if not result.permitted:
                        raise KernelDeniedError(
                            f"CrewAI task blocked by kernel: {result.summary()}"
                        )
                    return _orig(*args, **kwargs)
                setattr(task, attr, _guarded)
                break

        task._kernel_gate = self
        task._kernel_gate_resources = {
            "read": resources_read or [],
            "write": resources_write or [],
            "delegate": resources_delegate or [],
        }
        return task

    def wrap_crew(
        self,
        crew: Any,
        task_resource_map: dict[Any, dict[str, list[Resource]]] | None = None,
    ) -> Any:
        """
        Wrap all tasks in a CrewAI Crew with kernel gates.

        task_resource_map: maps task objects to their resource kwargs.
        Tasks not in the map are wrapped with empty resource lists
        (will be denied if they require resource access without a claim).

        Returns the crew with all tasks guarded.
        """
        tasks = getattr(crew, "tasks", [])
        resource_map = task_resource_map or {}
        for task in tasks:
            resources = resource_map.get(task, {})
            self.guard_task(
                task,
                resources_read=resources.get("resources_read"),
                resources_write=resources.get("resources_write"),
                resources_delegate=resources.get("resources_delegate"),
            )
        return crew
