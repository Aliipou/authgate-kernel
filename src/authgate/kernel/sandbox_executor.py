"""
Python Capability-Constrained Sandbox Executor — Phase 1, O1 (Python layer).

Mirrors the Rust SandboxedExecutor API exactly so callers are unaffected when
the Rust/WASM executor is available. This Python layer enforces at the
ToolABIRegistry boundary (not at WASM instantiation) but provides the same
Permit/Deny contract:

  executor = SandboxedExecutor(registry, verifier)
  result = executor.execute(action, tool_name, arguments)
  # result.permitted  → bool
  # result.output     → Any
  # result.denied_reason → str | None

Unlike the Rust sandbox (which fails at WASM instantiation if an import is
not linked), this layer fails at the ToolABIRegistry.validate_call() boundary
before any tool function is invoked.

Right mapping (matches Rust sandbox.rs authgate host functions):
  "read"         → can_read in best_claim
  "write"        → can_write in best_claim
  "delegate"     → can_delegate in best_claim
  "network"      → ResourceType.NETWORK_ENDPOINT claim required
  "model_invoke" → ResourceType.MODEL_WEIGHTS claim required
  "spawn"        → can_delegate + machine actor required
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class SandboxResult:
    """Result of a sandboxed tool execution."""
    permitted: bool
    output: Any = None
    denied_reason: str | None = None
    tool_name: str = ""

    def is_denied(self) -> bool:
        return not self.permitted

    def is_executed(self) -> bool:
        return self.permitted and self.denied_reason is None


class SandboxedExecutor:
    """
    Capability-constrained tool executor.

    Steps on every execute() call:
    1. Gate: FreedomVerifier.verify(action) — if DENY, return SandboxResult(permitted=False)
    2. ABI: ToolABIRegistry.validate_call(tool_name, arguments, rights_held) — if invalid,
       return SandboxResult(permitted=False, denied_reason=...)
    3. Execute: call registered tool function with validated arguments
    4. Return SandboxResult(permitted=True, output=...)

    This matches the Rust sandbox.rs enforce-at-boundary contract:
    - Step 1 = Rust CallGate.execute()
    - Step 2 = WASM instantiation failure (unlisted import)
    - Step 3 = WASM execution
    """

    def __init__(
        self,
        verifier: Any,
        abi_registry: Any | None = None,
    ) -> None:
        self._verifier = verifier
        self._abi = abi_registry
        self._tools: dict[str, Callable[..., Any]] = {}

    def register_tool(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a callable under a tool name. Must match a schema in the ABI registry."""
        self._tools[name] = fn

    def execute(
        self,
        action: Any,
        tool_name: str,
        arguments: dict[str, Any],
        caller_scope: str = "",
    ) -> SandboxResult:
        """
        Execute a tool call under capability constraints.

        1. Verify the action (sovereignty gate).
        2. Validate ABI schema (rights + parameter types).
        3. Invoke the tool.
        """
        # Step 1: capability gate
        result = self._verifier.verify(action)
        if not result.permitted:
            return SandboxResult(
                permitted=False,
                denied_reason=f"Capability gate denied: {'; '.join(result.violations)}",
                tool_name=tool_name,
            )

        # Step 2: ABI schema validation
        if self._abi is not None:
            rights_held = self._extract_rights(action)
            is_delegated = any(
                getattr(c, "delegated_by", None) is not None
                for c in getattr(self._verifier.registry, "_claims", [])
                if c.holder == action.actor
            )
            validation = self._abi.validate_call(
                tool_name, arguments, rights_held,
                is_delegated=is_delegated,
                caller_scope=caller_scope,
            )
            if not validation.valid:
                return SandboxResult(
                    permitted=False,
                    denied_reason=f"ABI validation failed: {validation.reason}",
                    tool_name=tool_name,
                )

        # Step 3: invoke tool
        fn = self._tools.get(tool_name)
        if fn is None:
            return SandboxResult(
                permitted=False,
                denied_reason=f"Tool '{tool_name}' not registered in executor",
                tool_name=tool_name,
            )

        try:
            output = fn(**arguments)
            return SandboxResult(permitted=True, output=output, tool_name=tool_name)
        except Exception as exc:
            return SandboxResult(
                permitted=False,
                denied_reason=f"Tool execution error: {exc}",
                tool_name=tool_name,
            )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _extract_rights(self, action: Any) -> set[str]:
        """Map action fields to right names for ABI validation."""
        rights: set[str] = set()
        if getattr(action, "resources_read", []):
            rights.add("read")
        if getattr(action, "resources_write", []):
            rights.add("write")
        if getattr(action, "resources_delegate", []):
            rights.add("delegate")
        # Check for network resources
        from authgate.kernel.entities import ResourceType
        all_res = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
        )
        for res in all_res:
            if res.rtype == ResourceType.NETWORK_ENDPOINT:
                rights.add("network")
            if res.rtype == ResourceType.MODEL_WEIGHTS:
                rights.add("model_invoke")
        return rights
