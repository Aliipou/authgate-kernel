"""Component 1 — Graph Engine (hardened against evasion).

Builds the cross-layer import graph from source. Beyond plain `import` / `from`
statements it also resolves dynamic imports with a constant module argument
(`importlib.import_module("x")`, `__import__("x")`, aliased forms), assigns files
that match no declared layer to a synthetic `(unscoped)` source so forbidden
dependencies cannot be laundered through glue code, and records files it could
not parse so they cannot become silent blind spots.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# Source files under scan that match no declared layer. They cannot *receive*
# trust (they are not a layer), but an import *from* them to a layer is still a
# real dependency, so we keep those edges and judge them by explicit forbids.
UNSCOPED = "(unscoped)"


@dataclass(frozen=True)
class ImportEdge:
    src_file: str
    lineno: int
    src_layer: str
    dst_layer: str
    module: str
    dynamic: bool = False


def _layer_of_path(path: Path, root_to_layer: dict[str, str]) -> str | None:
    for part in path.parts:
        if part in root_to_layer:
            return root_to_layer[part]
    return None


def _dynamic_import_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Resolve local names that mean "dynamic import": direct callables (e.g. an
    aliased import_module, __import__) and module aliases for importlib."""
    callables = {"__import__"}
    importlib_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "importlib":
                    importlib_aliases.add(a.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib" and not node.level:
            for a in node.names:
                if a.name == "import_module":
                    callables.add(a.asname or "import_module")
    return callables, importlib_aliases


def _imports(tree: ast.AST):
    """Yield (top_level_module, lineno, is_dynamic) for every resolvable import."""
    callables, importlib_aliases = _dynamic_import_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0], node.lineno, False
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import -> same package, not a boundary crossing
                continue
            if node.module:
                yield node.module.split(".")[0], node.lineno, False
        elif isinstance(node, ast.Call):
            fn = node.func
            is_dyn = (
                (isinstance(fn, ast.Name) and fn.id in callables)
                or (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "import_module"
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id in importlib_aliases
                )
            )
            if is_dyn and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    yield first.value.split(".")[0], node.lineno, True


class ImportGraph:
    def __init__(self, edges: list[ImportEdge], skipped: list[str] | None = None):
        self.edges = list(edges)
        self.skipped = list(skipped or [])  # files that could not be parsed

    @classmethod
    def from_sources(cls, paths, root_to_layer: dict[str, str]) -> "ImportGraph":
        edges: list[ImportEdge] = []
        skipped: list[str] = []
        for root in paths:
            for py in sorted(Path(root).rglob("*.py")):
                try:
                    tree = ast.parse(py.read_text(encoding="utf-8"))
                except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
                    skipped.append(str(py))
                    continue
                src_layer = _layer_of_path(py, root_to_layer) or UNSCOPED
                for mod, lineno, dynamic in _imports(tree):
                    dst_layer = root_to_layer.get(mod)
                    if dst_layer is None or dst_layer == src_layer:
                        continue
                    edges.append(ImportEdge(str(py), lineno, src_layer, dst_layer, mod, dynamic))
        return cls(edges, skipped)

    def layer_edges(self) -> set[tuple[str, str]]:
        return {(e.src_layer, e.dst_layer) for e in self.edges}

    def adjacency(self) -> dict[str, set[str]]:
        adj: dict[str, set[str]] = {}
        for s, d in self.layer_edges():
            adj.setdefault(s, set()).add(d)
        return adj

    def cycles(self) -> list[list[str]]:
        """Layer-level dependency cycles. A layered architecture must be acyclic."""
        adj = self.adjacency()
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {}
        stack: list[str] = []
        found: list[list[str]] = []

        def dfs(u: str) -> None:
            color[u] = GRAY
            stack.append(u)
            for v in sorted(adj.get(u, ())):
                c = color.get(v, WHITE)
                if c == GRAY:
                    found.append(stack[stack.index(v):] + [v])
                elif c == WHITE:
                    dfs(v)
            stack.pop()
            color[u] = BLACK

        for node in sorted(adj):
            if color.get(node, WHITE) == WHITE:
                dfs(node)
        return found
