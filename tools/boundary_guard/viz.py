"""Component 6 — Visualization.

Renders the policy as a Mermaid flowchart (GitHub renders these natively) or
Graphviz DOT. Demo value, not engineering value — solid arrows are allowed
edges, dotted red arrows are forbidden ones.
"""

from __future__ import annotations

from .policy import Policy


def _id(name: str) -> str:
    return name.replace("-", "_")


def to_mermaid(policy: Policy) -> str:
    lines = ["flowchart TD"]
    for layer in policy.layers:
        lines.append(f"    {_id(layer)}[{layer}]")
    for s, d in sorted(policy.allow):
        if "*" not in (s, d):
            lines.append(f"    {_id(s)} --> {_id(d)}")
    for s, d in sorted(policy.forbid):
        if "*" not in (s, d):
            lines.append(f"    {_id(s)} -.->|forbidden| {_id(d)}")
    return "\n".join(lines)


def to_dot(policy: Policy) -> str:
    lines = ["digraph boundaries {", "  rankdir=BT;"]
    for layer in policy.layers:
        lines.append(f'  "{layer}";')
    for s, d in sorted(policy.allow):
        if "*" not in (s, d):
            lines.append(f'  "{s}" -> "{d}";')
    for s, d in sorted(policy.forbid):
        if "*" not in (s, d):
            lines.append(f'  "{s}" -> "{d}" [style=dashed, color=red, label="forbidden"];')
    lines.append("}")
    return "\n".join(lines)
