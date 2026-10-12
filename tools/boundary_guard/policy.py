"""Component 2 — Policy DSL.

A small, readable policy language (and a JSON loader for back-compat). Declares
layers, the allowed one-way dependency direction, and hard-forbidden edges.

DSL grammar (one statement per line, '#' starts a comment):

    layer NAME = root1, root2, ...
    allow  A -> B
    forbid A -> B : reason text

'*' is a wildcard for either side. forbid always wins over allow.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


def _parse_edge(s: str) -> tuple[str, str]:
    src, sep, dst = s.partition("->")
    if not sep:
        raise ValueError(f"expected 'A -> B', got {s!r}")
    return src.strip(), dst.strip()


@dataclass
class Policy:
    layers: dict[str, list[str]]          # layer -> import roots
    root_to_layer: dict[str, str]
    allow: set[tuple[str, str]]
    forbid: dict[tuple[str, str], str]    # edge -> reason

    @classmethod
    def from_file(cls, path) -> "Policy":
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        return cls.from_json(json.loads(text)) if p.suffix == ".json" else cls.from_dsl(text)

    @classmethod
    def from_json(cls, data: dict) -> "Policy":
        layers = {k: list(v) for k, v in data["layers"].items()}
        allow = {(r["from"], r["to"]) for r in data.get("allow", [])}
        forbid = {(r["from"], r["to"]): r.get("why", "") for r in data.get("forbidden", [])}
        return cls(layers, _roots(layers), allow, forbid)

    @classmethod
    def from_dsl(cls, text: str) -> "Policy":
        layers: dict[str, list[str]] = {}
        allow: set[tuple[str, str]] = set()
        forbid: dict[tuple[str, str], str] = {}
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("layer "):
                name, _, rest = line[len("layer "):].partition("=")
                layers[name.strip()] = [x.strip() for x in rest.split(",") if x.strip()]
            elif line.startswith("allow "):
                allow.add(_parse_edge(line[len("allow "):]))
            elif line.startswith("forbid "):
                body, _, reason = line[len("forbid "):].partition(":")
                forbid[_parse_edge(body)] = reason.strip()
            else:
                raise ValueError(f"unrecognized policy line: {raw!r}")
        return cls(layers, _roots(layers), allow, forbid)

    def is_forbidden(self, src: str, dst: str) -> str | None:
        for key in ((src, dst), (src, "*"), ("*", dst), ("*", "*")):
            if key in self.forbid:
                return self.forbid[key]
        return None

    def is_allowed(self, src: str, dst: str) -> bool:
        if src == dst:
            return True
        return any(k in self.allow for k in ((src, dst), (src, "*"), ("*", dst), ("*", "*")))

    def validate(self) -> list[str]:
        """Semantic checks beyond parsing. A typo'd layer name silently disables a
        rule, so catching it is the difference between a real gate and a fake one."""
        errors: list[str] = []
        declared = set(self.layers)
        if not declared:
            errors.append("no layers declared")

        seen: dict[str, str] = {}
        for layer, roots in self.layers.items():
            if not roots:
                errors.append(f"layer '{layer}' has no import roots")
            for r in roots:
                if r in seen and seen[r] != layer:
                    errors.append(f"root '{r}' is claimed by both '{seen[r]}' and '{layer}'")
                seen[r] = layer

        def known(side: str) -> bool:
            return side == "*" or side in declared

        if ("*", "*") in self.allow:
            errors.append("allow '* -> *' disables undeclared-edge detection — remove it")
        for s, d in sorted(self.allow):
            if not (known(s) and known(d)):
                errors.append(f"allow references an undeclared layer: {s} -> {d}")
        for s, d in sorted(self.forbid):
            if not (known(s) and known(d)):
                errors.append(f"forbid references an undeclared layer: {s} -> {d}")
        return errors


def _roots(layers: dict[str, list[str]]) -> dict[str, str]:
    return {root: layer for layer, roots in layers.items() for root in roots}
