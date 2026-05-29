"""
DSPy Adapter — Phase 1, O3 (remaining).

Wraps a DSPy module or signature so every .forward() call passes through
the FreedomVerifier before execution. DSPy is a framework for programming
language models with structured inputs/outputs.

The adapter:
- Intercepts the .forward() / __call__ on any DSPy Module
- Creates a typed Action from the module's declared I/O signature
- Runs FreedomVerifier.verify(action)
- Only calls the original .forward() if the action is permitted

Usage:
    import dspy
    from authgate.adapters.dspy_adapter import DSPyKernelGate

    lm = dspy.OpenAI(...)
    gate = DSPyKernelGate(verifier, actor=bot_entity, resource=model_resource)

    class MyModule(dspy.Module):
        def forward(self, question: str) -> dspy.Prediction:
            ...

    guarded = gate.guard(MyModule())
    result = guarded(question="What is the capital?")
    # Raises KernelDeniedError if the action is blocked

This adapter uses duck typing — it does NOT import dspy at module load time.
It wraps any object with a .forward() or __call__ method.
"""
from __future__ import annotations

from typing import Any


class KernelDeniedError(Exception):
    """Raised when the authgate kernel denies a DSPy module invocation."""


class DSPyKernelGate:
    """
    Wraps a DSPy module with authgate capability enforcement.

    Parameters
    ----------
    verifier   : FreedomVerifier instance
    actor      : Entity — the machine agent making the invocation
    resource   : Resource — the model resource being accessed
    action_prefix : prefix for auto-generated action_id (default: "dspy-invoke")
    """

    def __init__(
        self,
        verifier: Any,
        actor: Any,
        resource: Any,
        action_prefix: str = "dspy-invoke",
    ) -> None:
        self._verifier = verifier
        self._actor = actor
        self._resource = resource
        self._prefix = action_prefix

    def guard(self, module: Any) -> "_GuardedDSPyModule":
        """Wrap a DSPy module with this gate. Returns a guarded module."""
        return _GuardedDSPyModule(module, self)

    def verify_invocation(self, action_id: str, **kwargs: Any) -> None:
        """
        Run the capability gate for a DSPy invocation.
        Raises KernelDeniedError if the action is not permitted.
        """
        from authgate.kernel.verifier import Action
        action = Action(
            action_id=f"{self._prefix}-{action_id}",
            actor=self._actor,
            resources_read=[self._resource],
        )
        result = self._verifier.verify(action)
        if not result.permitted:
            raise KernelDeniedError(
                f"DSPy invocation '{action_id}' denied by authgate: "
                + "; ".join(result.violations)
            )


class _GuardedDSPyModule:
    """
    Proxy that intercepts forward()/call() and runs the gate check first.
    Delegates all other attribute access to the wrapped module.
    """

    def __init__(self, module: Any, gate: DSPyKernelGate) -> None:
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_gate", gate)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        gate = object.__getattribute__(self, "_gate")
        module = object.__getattribute__(self, "_module")
        name = getattr(module, "__class__", type(module)).__name__
        gate.verify_invocation(name, **kwargs)
        return module(*args, **kwargs)

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        gate = object.__getattribute__(self, "_gate")
        module = object.__getattribute__(self, "_module")
        name = getattr(module, "__class__", type(module)).__name__
        gate.verify_invocation(f"{name}.forward", **kwargs)
        return module.forward(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        module = object.__getattribute__(self, "_module")
        return getattr(module, name)

    def __setattr__(self, name: str, value: Any) -> None:
        module = object.__getattribute__(self, "_module")
        setattr(module, name, value)
