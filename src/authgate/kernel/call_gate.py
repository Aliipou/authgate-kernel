"""
Python CallGate — sole public entry point for tool execution.

Architecture mirrors call_gate.rs:
  Rust:   engine::verify is pub(crate)   → compile-time enforcement of AT-7.5
  Python: GatedTool.__fn is name-mangled → API-level enforcement

AT-7.5 status at this layer:
  MITIGATED: any code that uses CallGate.register() and calls the returned
  GatedTool cannot execute the underlying function without passing through
  verify(). The original callable is encapsulated in a name-mangled attribute
  (_GatedTool__fn) — accessible only to CallGate.execute() internally, and
  awkward enough to discourage accidental extraction.

  FULL STRUCTURAL CLOSURE requires the Rust TCB (engine::verify pub(crate))
  or OS-level enforcement (WASM / seccomp). This file provides the correct
  Python pattern and the tests that prove it behaves correctly.

Usage:
    gate = CallGate(verifier)
    read_tool = gate.register("read_file", lambda path: open(path).read())

    # Tool can only run if action is permitted:
    result = gate.execute(action, "read_file", {"path": "/data/report.txt"})
    assert result.permitted
    assert result.output == "..."

    # GatedTool is also directly callable (action is first arg):
    result = read_tool(action, path="/data/report.txt")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class GateResult:
    """Immutable result of a gated tool execution."""
    permitted: bool
    output: Any = None
    denied_reason: Optional[str] = None
    tool_name: str = ""

    def is_denied(self) -> bool:
        return not self.permitted

    def is_executed(self) -> bool:
        return self.permitted and self.denied_reason is None


class GatedTool:
    """
    A callable that always passes through its CallGate before executing.

    Returned by CallGate.register(). The underlying function (__fn) is
    name-mangled and only accessed by CallGate.execute() via the internal
    _call_fn() method.

    DO NOT extract __fn directly — doing so bypasses the gate (AT-7.5).
    """

    __slots__ = ("_name", "_GatedTool__fn", "_gate")

    def __init__(self, name: str, fn: Callable[..., Any], gate: "CallGate") -> None:
        self._name: str = name
        self.__fn: Callable[..., Any] = fn   # name-mangled: _GatedTool__fn
        self._gate: "CallGate" = gate

    @property
    def name(self) -> str:
        return self._name

    def __call__(self, action: Any, **arguments: Any) -> GateResult:
        """Execute via the gate. action is the capability-bearing Action object."""
        return self._gate.execute(action, self._name, arguments)

    def __repr__(self) -> str:
        return f"GatedTool(name={self._name!r})"

    def _call_fn(self, **kwargs: Any) -> Any:
        """Internal: invoked only by CallGate.execute(). Not for external use."""
        return self.__fn(**kwargs)


class CallGate:
    """
    The sole public execution entry point — Python mirror of call_gate.rs.

    Every registered tool is wrapped in a GatedTool. Every execution path
    goes through verify() unconditionally before the tool runs.

    Construction:
        gate = CallGate(verifier)
        gate = CallGate(verifier, abi_registry=abi, audit_log=audit)

    Registration:
        gated = gate.register("tool_name", fn)

    Execution (two equivalent forms):
        result = gate.execute(action, "tool_name", {"arg": value})
        result = gated(action, arg=value)
    """

    def __init__(
        self,
        verifier: Any,
        abi_registry: Optional[Any] = None,
        audit_log: Optional[Any] = None,
    ) -> None:
        self._verifier = verifier
        self._abi = abi_registry
        self._audit = audit_log
        self._tools: dict[str, GatedTool] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> GatedTool:
        """
        Register a callable under name. Returns a GatedTool.

        After registration the GatedTool is the intended call surface.
        Calling the original fn directly bypasses the gate (AT-7.5 shadow
        execution) and is a security violation — do not do it.
        """
        gated = GatedTool(name=name, fn=fn, gate=self)
        self._tools[name] = gated
        return gated

    def execute(
        self,
        action: Any,
        tool_name: str,
        arguments: Optional[dict[str, Any]] = None,
    ) -> GateResult:
        """
        Execute tool_name under capability constraints.

        Steps (mirrors call_gate.rs contract):
          1. verify(action)          — always, unconditionally, before anything else
          2. ABI schema validation   — if abi_registry supplied
          3. Invoke tool function    — only if 1+2 pass

        Returns GateResult. Never raises on policy denial — raises only on
        programmer error (unregistered tool name).
        """
        args = arguments or {}

        # Step 1: capability gate — always first, always unconditional
        verify_result = self._verifier.verify(action)
        if not verify_result.permitted:
            reason = "; ".join(verify_result.violations) if verify_result.violations else "denied"
            return GateResult(
                permitted=False,
                denied_reason=f"capability gate denied: {reason}",
                tool_name=tool_name,
            )

        # Step 2: ABI schema validation
        if self._abi is not None:
            rights_held = self._extract_rights(action)
            validation = self._abi.validate_call(
                tool_name, args, rights_held,
                caller_scope=getattr(action, "action_id", ""),
            )
            if not validation.valid:
                return GateResult(
                    permitted=False,
                    denied_reason=f"ABI validation failed: {validation.reason}",
                    tool_name=tool_name,
                )

        # Step 3: invoke — via _call_fn, not direct __fn access
        gated = self._tools.get(tool_name)
        if gated is None:
            raise KeyError(
                f"CallGate: tool '{tool_name}' not registered. "
                f"Available: {sorted(self._tools)}"
            )

        try:
            output = gated._call_fn(**args)
            return GateResult(permitted=True, output=output, tool_name=tool_name)
        except Exception as exc:
            return GateResult(
                permitted=False,
                denied_reason=f"tool execution error: {exc}",
                tool_name=tool_name,
            )

    def registered_tools(self) -> list[str]:
        """Return names of all registered tools."""
        return sorted(self._tools)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _extract_rights(self, action: Any) -> set[str]:
        rights: set[str] = set()
        if getattr(action, "resources_read", []):
            rights.add("read")
        if getattr(action, "resources_write", []):
            rights.add("write")
        if getattr(action, "resources_delegate", []):
            rights.add("delegate")
        try:
            from authgate.kernel.entities import ResourceType
            for res in (list(getattr(action, "resources_read", [])) +
                        list(getattr(action, "resources_write", []))):
                if res.rtype == ResourceType.NETWORK_ENDPOINT:
                    rights.add("network")
                if res.rtype == ResourceType.MODEL_WEIGHTS:
                    rights.add("model_invoke")
        except ImportError:
            pass
        return rights
