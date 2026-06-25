"""Component 3 — Enforcement (hardened).

Judges the graph against the policy and emits findings:

  - forbidden:    an edge the policy explicitly forbids (always a failure)
  - cycle:        a layer dependency cycle (always a failure)
  - unanalyzable: a source file that could not be parsed (a blind spot; --strict)
  - undeclared:   a cross-layer edge that is neither allowed nor forbidden
                  (only reported in --strict; this is creeping drift)

Edges from the synthetic `(unscoped)` source (glue code outside any declared
layer) are judged only by explicit forbids — never reported as "undeclared" —
so laundering a forbidden dependency through a non-layer module is still caught
without drowning the report in noise.
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import UNSCOPED, ImportGraph
from .policy import Policy


@dataclass(frozen=True)
class Finding:
    kind: str
    src_layer: str
    dst_layer: str
    reason: str
    locations: tuple[str, ...] = ()


def check(graph: ImportGraph, policy: Policy, strict: bool = False) -> list[Finding]:
    locs: dict[tuple[str, str], list[str]] = {}
    for e in graph.edges:
        tag = " [dynamic]" if e.dynamic else ""
        locs.setdefault((e.src_layer, e.dst_layer), []).append(
            f"{e.src_file}:{e.lineno} (import {e.module}{tag})"
        )

    findings: list[Finding] = []
    for (src, dst), locations in sorted(locs.items()):
        reason = policy.is_forbidden(src, dst)
        if reason is not None:
            findings.append(Finding("forbidden", src, dst, reason or "forbidden by policy", tuple(locations)))
        elif src == UNSCOPED:
            continue  # glue code: only explicit forbids apply, never "undeclared"
        elif policy.is_allowed(src, dst):
            continue
        elif strict:
            findings.append(Finding(
                "undeclared", src, dst,
                "cross-layer dependency not declared in policy", tuple(locations),
            ))

    for cyc in graph.cycles():
        findings.append(Finding("cycle", cyc[0], cyc[-1], "layer cycle: " + " -> ".join(cyc)))

    if strict:
        for path in graph.skipped:
            findings.append(Finding(
                "unanalyzable", UNSCOPED, "-",
                f"source could not be parsed — a blind spot: {path}", (path,),
            ))

    return findings
