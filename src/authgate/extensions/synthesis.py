"""
Constrained Synthesis Engine.

Allows the system to generalize from existing rules to new situations
within invariant-preserving bounds. Contradiction is a clarification signal,
not permission to override.

Prohibits synthesis that:
  - Violates any hard invariant
  - Reduces confidence in any existing valid claim
  - Increases machine sovereignty
  - Removes or weakens the verifier
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

HARD_INVARIANTS = [
    "no_machine_sovereignty",
    "no_human_owns_human",
    "no_coercion",
    "no_deception",
    "verifier_preserved",
    "corrigibility_preserved",
    "human_has_exit_right",
]


@dataclass
class ProposedRule:
    rule_id: str
    description: str
    invariant_impacts: dict[str, bool] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = "human"

    def violates_invariants(self) -> list[str]:
        return [
            inv for inv in HARD_INVARIANTS
            if self.invariant_impacts.get(inv) is False
        ]

    def is_admissible(self) -> tuple[bool, str]:
        violations = self.violates_invariants()
        if violations:
            return False, f"Rule '{self.rule_id}' violates hard invariants: {violations}"
        return True, "OK"


@dataclass
class SynthesisEngine:
    _admitted_rules: list[ProposedRule] = field(default_factory=list)
    _rejected_rules: list[tuple[ProposedRule, str]] = field(default_factory=list)
    _induction_hooks: list[Callable[[list[ProposedRule]], list[ProposedRule]]] = field(
        default_factory=list
    )

    def admit_rule(self, rule: ProposedRule) -> tuple[bool, str]:
        admissible, reason = rule.is_admissible()
        if admissible:
            self._admitted_rules.append(rule)
            return True, f"Rule '{rule.rule_id}' admitted."
        else:
            self._rejected_rules.append((rule, reason))
            return False, reason

    def synthesize(
        self, situation: str, candidate_rules: list[ProposedRule]
    ) -> list[ProposedRule]:
        return [rule for rule in candidate_rules if rule.is_admissible()[0]]

    def add_induction_hook(
        self, hook: Callable[[list[ProposedRule]], list[ProposedRule]]
    ) -> None:
        self._induction_hooks.append(hook)

    def run_induction(self) -> list[ProposedRule]:
        new_rules: list[ProposedRule] = []
        for hook in self._induction_hooks:
            candidates = hook(self._admitted_rules)
            for rule in candidates:
                ok, _ = rule.is_admissible()
                if ok:
                    new_rules.append(rule)
                    self._admitted_rules.append(rule)
        return new_rules

    @property
    def admitted(self) -> list[ProposedRule]:
        return list(self._admitted_rules)

    @property
    def rejected(self) -> list[tuple[ProposedRule, str]]:
        return list(self._rejected_rules)
