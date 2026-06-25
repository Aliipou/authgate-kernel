"""Component 4 — Repository Profiles.

One master policy, many repos. A repo's profile says which layers it can legitimately
see and which source roots to scan. `restrict_policy` projects the master policy down
to just that repo's visible layers, so each repo enforces only the edges it can produce.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .policy import Policy


@dataclass
class Profile:
    repo: str
    roots: list[str] = field(default_factory=lambda: ["."])
    visible_layers: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path) -> "Profile":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(d["repo"], d.get("roots", ["."]), d.get("visible_layers", []))


def restrict_policy(policy: Policy, visible_layers) -> Policy:
    vis = set(visible_layers)

    def visible(side: str) -> bool:
        return side == "*" or side in vis

    layers = {k: v for k, v in policy.layers.items() if k in vis}
    allow = {(s, d) for (s, d) in policy.allow if visible(s) and visible(d)}
    forbid = {(s, d): r for (s, d), r in policy.forbid.items() if visible(s) and visible(d)}
    return Policy(layers, _roots(layers), allow, forbid)


def _roots(layers: dict[str, list[str]]) -> dict[str, str]:
    return {root: layer for layer, roots in layers.items() for root in roots}
