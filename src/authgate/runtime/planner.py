"""
Agent runtime planner — the deterministic LLM stand-in (non-TCB).

A planner turns a natural-language intent into an ordered list of tool-call
steps. In production this is where an LLM would sit; here we use a fixed,
rule-based mock so the MVP is fully reproducible and testable. Real LLM
planners slot in behind the same `Planner` protocol without touching callers.

This module is NOT part of the trusted computing base: a plan is only a
*request*. The kernel still gates every step, so a planner may legitimately
emit steps the agent lacks the capability to run (see `ScriptedPlanner`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class PlanStep:
    tool: str  # tool name, e.g. "calculator"
    args: dict[str, Any] = field(default_factory=dict)  # kwargs for the tool fn
    rationale: str = ""  # short human-readable why (optional)


class Planner(Protocol):
    def plan(self, intent: str) -> list[PlanStep]: ...


class ScriptedPlanner:
    """Returns a pinned plan verbatim, ignoring the intent.

    Tests/demos use this to assert an exact step sequence — including plans that
    deliberately contain a step the agent is not capable of, to exercise the
    kernel's gating.
    """

    def __init__(self, steps: list[PlanStep]) -> None:
        self._steps = list(steps)

    def plan(self, intent: str) -> list[PlanStep]:
        # Copy so callers cannot mutate the pinned script through the returned list.
        return list(self._steps)


# Trigger keywords kept as data so the rule order is obvious at a glance.
_ARITHMETIC_WORDS = ("calculate", "compute", "math", "sum", "plus", "times")
_SEARCH_WORDS = ("search", "find", "look up", "lookup", "what is")
_FILE_WORDS = ("read", "open", "file", "cat ")

# A bare arithmetic expression (e.g. "2 + 3 * 4") is itself a calculation trigger,
# and the same regex extracts the expression to hand to the calculator tool.
_EXPR_RE = re.compile(r"[\d][\d+\-*/%.()\s]*[\d)]")


class MockPlanner:
    """Deterministic, rule-based planner — a reproducible LLM substitute.

    Same intent always yields the same plan (hard MVP requirement). Rules are
    applied in a fixed order; each appends a step when its trigger matches.
    """

    def plan(self, intent: str) -> list[PlanStep]:
        text = intent.lower()
        steps: list[PlanStep] = []
        self._maybe_arithmetic(text, steps)
        self._maybe_search(text, intent, steps)
        self._maybe_file(text, steps)
        return steps

    def _maybe_arithmetic(self, text: str, steps: list[PlanStep]) -> None:
        match = _EXPR_RE.search(text)
        if not any(w in text for w in _ARITHMETIC_WORDS) and not match:
            return
        # Keyword without an actual expression still means "calculate something".
        expression = match.group().strip() if match else "0"
        steps.append(PlanStep("calculator", {"expression": expression},
                              "intent asked for a calculation"))

    def _maybe_search(self, text: str, intent: str, steps: list[PlanStep]) -> None:
        if any(w in text for w in _SEARCH_WORDS):
            # Preserve original casing in the query; only matching is lowercased.
            steps.append(PlanStep("web_search", {"query": intent.strip()},
                                  "intent asked to search"))

    def _maybe_file(self, text: str, steps: list[PlanStep]) -> None:
        if any(w in text for w in _FILE_WORDS):
            filename = self._extract_filename(text)
            steps.append(PlanStep("file_read", {"filename": filename},
                                  "intent asked to read a file"))

    @staticmethod
    def _extract_filename(text: str) -> str:
        # A real filename-ish token carries a '.' or '/'; otherwise fall back so
        # the plan is still actionable rather than empty.
        for token in text.split():
            if "." in token or "/" in token:
                return token
        return "notes.txt"
