"""
Agent runtime tools — the non-TCB action layer.

These tools are NOT part of the trusted computing base. They are the concrete
side effects an agent can request (compute, file read, web search). Every tool
declares the capability (Resource + mode) it requires so the kernel can gate
invocation; the tools themselves perform the actual work once a capability check
has passed elsewhere.

Defense in depth: `file_read` enforces its OWN sandbox boundary in addition to
the capability gate. Even if a capability were mis-issued, the tool still refuses
to read outside `sandbox_root`. Tools therefore assume they may be called with
hostile arguments and validate accordingly.
"""
from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authgate.kernel.entities import Resource, ResourceType

_VALID_MODES = {"read", "write"}


@dataclass(frozen=True)
class Tool:
    name: str
    fn: Callable[..., Any]
    resource: Resource  # the capability this tool requires
    mode: str  # "read" or "write"

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {self.mode!r}")


class ToolRegistry:
    """Name-keyed collection of tools. Not a security boundary — just a lookup."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool {name!r}; available: {self.names()}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def __iter__(self):
        return iter(self._tools.values())

    def __contains__(self, name: str) -> bool:
        return name in self._tools


# --- calculator ------------------------------------------------------------

# Explicit allow-list of operators; anything absent here is rejected by default,
# which is the safe failure mode for evaluating untrusted expressions.
_BIN_OPS: dict[type[ast.operator], Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS: dict[type[ast.unaryop], Callable[[Any], Any]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Resource-exhaustion bounds. Rejecting names/calls is not enough: pure arithmetic
# can still be a denial-of-service. `2**2**2**2**2**2` is valid arithmetic that asks
# for a number with ~10^19728 digits and hangs the process. These caps keep every
# accepted expression cheap to evaluate; anything past them is refused, not computed.
_MAX_EXPR_LEN = 256       # reject pathological inputs before they reach the parser
_MAX_POW_EXPONENT = 1000  # `a ** b` with |b| above this is refused (no giant ints)
_MAX_RESULT_BITS = 8192   # cap any intermediate integer's magnitude (~2466 digits)


def _check_pow(exponent: Any) -> None:
    """Refuse exponents large enough to make `**` build an astronomically large int."""
    if isinstance(exponent, int) and abs(exponent) > _MAX_POW_EXPONENT:
        raise ValueError(f"unsafe expression: exponent {exponent} exceeds {_MAX_POW_EXPONENT}")


def _check_magnitude(value: Any) -> None:
    """Refuse intermediate ints whose magnitude could exhaust memory/CPU downstream."""
    if isinstance(value, int) and value.bit_length() > _MAX_RESULT_BITS:
        raise ValueError("unsafe expression: intermediate result too large")


def _eval_node(node: ast.AST) -> Any:
    """Recursively evaluate only the arithmetic AST nodes we allow."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        if type(node.op) is ast.Pow:
            _check_pow(right)
        result = _BIN_OPS[type(node.op)](left, right)
        _check_magnitude(result)
        return result
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError(f"unsafe expression: {ast.dump(node)}")


def calculate(expression: str) -> str:
    """Evaluate an arithmetic expression without eval(); names/calls are rejected.

    The tool's contract is total: it either returns a numeric string or raises
    ValueError. Resource-exhaustion and numeric-domain failures (overflow,
    divide-by-zero) are normalized to ValueError so the CallGate sees a clean
    denial rather than a hang or an uncaught error type.
    """
    if len(expression) > _MAX_EXPR_LEN:
        raise ValueError(f"unsafe expression: too long ({len(expression)} > {_MAX_EXPR_LEN})")
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError, MemoryError, RecursionError) as e:
        raise ValueError(f"unsafe expression: {e}") from e
    try:
        return str(_eval_node(tree.body))
    except (OverflowError, ZeroDivisionError) as e:
        raise ValueError(f"unsafe expression: {e}") from e


# --- file_read -------------------------------------------------------------

# Windows reinterprets these basenames as DEVICES regardless of directory or
# extension: 'CON', 'CON.txt', and 'sub/NUL' all open a device, not a file. Such a
# path passes the sandbox containment check (it resolves nominally *inside* root)
# yet escapes it at open() time — 'CON' blocks forever waiting on console input
# (DoS), 'NUL'/'COMn'/'LPTn' touch real devices. So they must be refused by name.
_WINDOWS_RESERVED_DEVICES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def _is_reserved_device(path: Path) -> bool:
    """True if any path component is a Windows reserved device name."""
    for part in path.parts:
        if part.split(".")[0].strip().upper() in _WINDOWS_RESERVED_DEVICES:
            return True
    return False


def _make_read_file(sandbox_root: Path) -> Callable[[str], str]:
    """Build a reader bound to one sandbox root; the closure is the boundary."""
    root = sandbox_root.resolve()

    def read_file(filename: str) -> str:
        # Resolve THEN verify containment so ../ traversal and absolute paths
        # both collapse to a path we can prefix-check against the real root.
        target = (root / filename).resolve()
        if root != target and root not in target.parents:
            raise PermissionError(f"path escapes sandbox: {filename}")
        # Containment is necessary but not sufficient on Windows: a reserved
        # device name resolves inside root yet opens a device, not a file.
        if _is_reserved_device(Path(filename)) or _is_reserved_device(target):
            raise PermissionError(f"reserved device name refused: {filename}")
        return target.read_text(encoding="utf-8")

    return read_file


# --- web_search ------------------------------------------------------------

# Deterministic mock: same query always yields the same string (MVP requires
# reproducibility, and we do not make real network calls).
_CANNED_ANSWERS: dict[str, str] = {
    "what is a capability": (
        "A capability is an unforgeable token that both names a resource and "
        "grants authority to use it."
    ),
    "authgate": (
        "authgate is a capability-constrained authorization kernel that gates "
        "agent tool execution."
    ),
}


def web_search(query: str) -> str:
    key = query.strip().lower()
    if key in _CANNED_ANSWERS:
        return _CANNED_ANSWERS[key]
    return f"[mock] no indexed results for {query!r}"


# --- default registry ------------------------------------------------------

def build_default_tools(sandbox_root: Path) -> ToolRegistry:
    """Registry of the 3 MVP tools, each wired to the capability it requires."""
    registry = ToolRegistry()
    registry.register(Tool(
        name="calculator", fn=calculate,
        resource=Resource("compute", ResourceType.COMPUTE_SLOT), mode="read",
    ))
    registry.register(Tool(
        name="file_read", fn=_make_read_file(sandbox_root),
        resource=Resource("sandbox-fs", ResourceType.FILE, scope=str(sandbox_root)),
        mode="read",
    ))
    registry.register(Tool(
        name="web_search", fn=web_search,
        resource=Resource("web", ResourceType.NETWORK_ENDPOINT), mode="read",
    ))
    return registry
