"""Component 5 — Drift Detection.

A baseline is the set of cross-layer edges that existed at a known-good point.
Drift = edges that appeared since (new structural coupling), or disappeared.
New edges are the dangerous ones: they are how an architecture quietly rots even
when no single edge is yet forbidden.
"""

from __future__ import annotations

import json
from pathlib import Path

from .graph import ImportGraph


def snapshot(graph: ImportGraph) -> list[str]:
    return sorted(f"{s} -> {d}" for (s, d) in graph.layer_edges())


def write_baseline(graph: ImportGraph, path) -> None:
    Path(path).write_text(
        json.dumps({"edges": snapshot(graph)}, indent=2) + "\n", encoding="utf-8"
    )


def diff(baseline_path, graph: ImportGraph) -> tuple[list[str], list[str]]:
    base = set(json.loads(Path(baseline_path).read_text(encoding="utf-8")).get("edges", []))
    current = set(snapshot(graph))
    return sorted(current - base), sorted(base - current)
