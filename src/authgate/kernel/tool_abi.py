"""
Typed Tool ABI — Phase 1, O2.

From ultimate-plan.md P1/O2:
  Tools are typed capabilities — not arbitrary string commands.
  A tool schema defines:
  - Which rights are required to call it
  - What argument fields it accepts (with types and constraints)
  - What scope it operates in
  - Whether it can be delegated

This enforces the "Typed Tool ABI" contract:
  Tool[ReadEmail{ mailbox: str, scope: str, expiry: int }]
  Tool[WriteFile{ path: str, content: bytes, scope: str }]

Usage:
    registry = ToolABIRegistry()
    registry.register(ToolSchema(
        name="read_file",
        required_rights={"read"},
        parameters=[ToolParam("path", str, required=True, scope_constrained=True)],
    ))
    result = registry.validate_call("read_file", {"path": "/data/report.csv"}, rights_held={"read"})
    if not result.valid:
        raise ToolABIError(result.reason)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Parameter definition ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ToolParam:
    """
    A single parameter in a tool's typed interface.

    scope_constrained: if True, the value must be a path-like string and will be
    validated against the caller's resource scope at call time.
    """
    name: str
    type: type
    required: bool = True
    scope_constrained: bool = False
    allowed_values: tuple[Any, ...] | None = None   # None = unrestricted
    max_length: int | None = None                    # for str params


# ── Schema ────────────────────────────────────────────────────────────────────

TOOL_ABI_VERSION = "1.0.0"


@dataclass
class ToolSchema:
    """
    Declares the typed interface contract for a single tool.

    required_rights: set of right names from {"read", "write", "delegate", "network",
                     "model_invoke", "spawn"} that the caller must hold.
    parameters: ordered list of typed parameters.
    is_delegable: if False, the tool cannot be called via a delegated claim.
    resource_scope: if set, restricts which scope paths are valid for this tool.
    schema_version: ABI version this schema conforms to. Bump MAJOR on breaking
                    semantic changes (II-3 / proof-versioning.md).
    """
    name: str
    required_rights: frozenset[str] = field(default_factory=frozenset)
    parameters: list[ToolParam] = field(default_factory=list)
    is_delegable: bool = True
    resource_scope: str = ""      # "" = root (no scope restriction from schema)
    description: str = ""
    schema_version: str = TOOL_ABI_VERSION

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("ToolSchema.name must be non-empty")
        self.required_rights = frozenset(self.required_rights)

    def to_json_schema(self) -> dict:
        """Export as a JSON Schema dict for external implementers (IV-1)."""
        type_map = {str: "string", int: "integer", float: "number",
                    bool: "boolean", bytes: "string", list: "array", dict: "object"}
        properties: dict = {}
        required: list = []
        for p in self.parameters:
            entry: dict = {"type": type_map.get(p.type, "string")}
            if p.allowed_values is not None:
                entry["enum"] = list(p.allowed_values)
            if p.max_length is not None:
                entry["maxLength"] = p.max_length
            if p.scope_constrained:
                entry["x-scope-constrained"] = True
            properties[p.name] = entry
            if p.required:
                required.append(p.name)
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": self.name,
            "description": self.description,
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
            "x-authgate-tool-abi-version": self.schema_version,
            "x-required-rights": sorted(self.required_rights),
            "x-is-delegable": self.is_delegable,
            "x-resource-scope": self.resource_scope,
        }


# ── Validation result ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ToolCallValidation:
    valid: bool
    reason: str = ""
    missing_rights: tuple[str, ...] = ()
    invalid_params: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.valid


# ── Registry ──────────────────────────────────────────────────────────────────

class ToolABIRegistry:
    """
    Central registry of typed tool schemas.

    Thread-safe for concurrent reads; register() is not called concurrently
    after initialization (schemas are loaded once at startup).
    """

    def __init__(self) -> None:
        self._schemas: dict[str, ToolSchema] = {}

    def register(self, schema: ToolSchema) -> None:
        if schema.name in self._schemas:
            raise ValueError(f"Tool '{schema.name}' is already registered")
        self._schemas[schema.name] = schema

    def get(self, name: str) -> ToolSchema | None:
        return self._schemas.get(name)

    def names(self) -> list[str]:
        return list(self._schemas.keys())

    def validate_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rights_held: set[str] | frozenset[str],
        is_delegated: bool = False,
        caller_scope: str = "",
    ) -> ToolCallValidation:
        """
        Validate a tool invocation against its schema.

        rights_held: set of rights the caller currently holds (e.g. {"read", "write"})
        is_delegated: True if the call comes via a delegated (not direct) claim
        caller_scope: the resource scope the caller is operating in
        """
        schema = self._schemas.get(tool_name)
        if schema is None:
            return ToolCallValidation(
                valid=False,
                reason=f"Unknown tool '{tool_name}' — not registered in ToolABIRegistry",
            )

        # Rights check
        missing = tuple(schema.required_rights - frozenset(rights_held))
        if missing:
            return ToolCallValidation(
                valid=False,
                reason=f"Caller lacks required rights for '{tool_name}': {sorted(missing)}",
                missing_rights=missing,
            )

        # Delegation check
        if is_delegated and not schema.is_delegable:
            return ToolCallValidation(
                valid=False,
                reason=f"Tool '{tool_name}' is not delegable — must be called by the direct principal",
            )

        # Parameter validation
        invalid: list[str] = []
        for param in schema.parameters:
            if param.name not in arguments:
                if param.required:
                    invalid.append(f"{param.name}: required but missing")
                continue
            val = arguments[param.name]

            # Type check
            if not isinstance(val, param.type):
                invalid.append(
                    f"{param.name}: expected {param.type.__name__}, got {type(val).__name__}"
                )
                continue

            # Allowed values
            if param.allowed_values is not None and val not in param.allowed_values:
                invalid.append(
                    f"{param.name}: value {val!r} not in allowed set {param.allowed_values}"
                )

            # Max length (str only)
            if param.max_length is not None and isinstance(val, str) and len(val) > param.max_length:
                invalid.append(
                    f"{param.name}: length {len(val)} exceeds max {param.max_length}"
                )

            # Scope constraint
            if param.scope_constrained and caller_scope:
                from authgate.kernel.entities import scope_contains
                if not scope_contains(caller_scope, str(val)):
                    invalid.append(
                        f"{param.name}: path '{val}' is outside caller scope '{caller_scope}'"
                    )

        # Unknown parameters
        schema_names = {p.name for p in schema.parameters}
        unknown = set(arguments) - schema_names
        if unknown:
            invalid.append(f"unknown parameters: {sorted(unknown)}")

        if invalid:
            return ToolCallValidation(
                valid=False,
                reason=f"Parameter validation failed for '{tool_name}': {'; '.join(invalid)}",
                invalid_params=tuple(invalid),
            )

        return ToolCallValidation(valid=True, reason="ok")


# ── Error ─────────────────────────────────────────────────────────────────────

class ToolABIError(Exception):
    """Raised when a tool call fails ABI validation."""
