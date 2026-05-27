"""
Policy IR — ABAC-style rule layer on top of the capability kernel.

The kernel (OwnershipRegistry + RightsClaim) is a capability system:
authority flows through explicit delegation. The Policy IR is a
complementary attribute-based layer that lets you express rules of
the form "deny all writes to /data/secret/* by machines" without
wiring individual claims.

Rule evaluation order: highest priority first; first match wins.
Default effect applies when no rule matches.

Usage:
    from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier

    policy = Policy(
        name="data-access",
        rules=[
            PolicyRule(effect="deny",   operations=["write"],
                       resource_scope="/data/restricted", priority=100),
            PolicyRule(effect="permit", operations=["read"],
                       actor_pattern="analyst-", priority=50),
        ],
        default_effect="deny",
    )

    pv = PolicyVerifier(kernel=verifier, policy=policy)
    result = pv.verify(action)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from authgate.kernel.entities import Entity, Resource, scope_contains


@dataclass
class PolicyRule:
    """
    A single access-control rule.

    All conditions must match for the rule to fire. An empty condition
    field is a wildcard (matches anything).

    Fields:
        effect          — "permit" or "deny" when the rule fires
        operations      — which operations this rule covers (empty = all)
        actor_pattern   — prefix match on actor.name (empty = any actor)
        resource_scope  — scope_contains match on resource scope/name (empty = any)
        priority        — higher value = evaluated first; default 0
    """

    effect: Literal["permit", "deny"]
    operations: list[str] = field(default_factory=list)
    actor_pattern: str = ""
    resource_scope: str = ""
    priority: int = 0


@dataclass
class PolicyEvaluationResult:
    effect: Literal["permit", "deny"]
    matched_rule: PolicyRule | None
    reason: str


@dataclass
class Policy:
    """
    A named, ordered collection of PolicyRules.

    Rules are evaluated in descending priority order. The first matching
    rule determines the effect. If no rule matches, default_effect applies.

    Policy evaluation is orthogonal to the capability kernel:
      - The kernel answers: does the agent hold the authority?
      - The policy answers: is the operation admissible under this policy?
    Both must permit for an action to proceed when used with PolicyVerifier.
    """

    name: str
    rules: list[PolicyRule] = field(default_factory=list)
    default_effect: Literal["permit", "deny"] = "deny"

    def evaluate(
        self,
        actor: Entity,
        resource: Resource,
        operation: str,
    ) -> PolicyEvaluationResult:
        """Return the effect for (actor, resource, operation) and the matching rule."""
        for rule in sorted(self.rules, key=lambda r: -r.priority):
            if self._rule_matches(rule, actor, resource, operation):
                return PolicyEvaluationResult(
                    effect=rule.effect,  # type: ignore[arg-type]
                    matched_rule=rule,
                    reason=(
                        f"rule priority={rule.priority} matched "
                        f"actor_pattern={rule.actor_pattern!r} "
                        f"resource_scope={rule.resource_scope!r}"
                    ),
                )
        return PolicyEvaluationResult(
            effect=self.default_effect,  # type: ignore[arg-type]
            matched_rule=None,
            reason=f"no rule matched; default_effect={self.default_effect!r}",
        )

    def _rule_matches(
        self,
        rule: PolicyRule,
        actor: Entity,
        resource: Resource,
        operation: str,
    ) -> bool:
        if rule.operations and operation not in rule.operations:
            return False
        if rule.actor_pattern and not actor.name.startswith(rule.actor_pattern):
            return False
        if rule.resource_scope:
            target = resource.scope if resource.scope else resource.name
            if not scope_contains(rule.resource_scope, target):
                return False
        return True


class PolicyVerifier:
    """
    Wraps a kernel verifier (FreedomVerifier or ExtendedFreedomVerifier) and
    layers a Policy on top.

    The kernel gate is a necessary precondition: an action blocked by the
    kernel is not re-evaluated by the policy. An action permitted by the
    kernel is then checked against the policy. Both must permit.

    This follows the same extension pattern as NonInterferenceChecker and
    ExtendedFreedomVerifier: the kernel is authoritative; this adds an
    orthogonal correctness condition.
    """

    def __init__(self, kernel: Any, policy: Policy) -> None:
        self._kernel = kernel
        self._policy = policy

    def verify(self, action: Any) -> Any:
        result = self._kernel.verify(action)
        if not result.permitted:
            return result

        violations: list[str] = []

        for resource in getattr(action, "resources_read", []):
            ev = self._policy.evaluate(action.actor, resource, "read")
            if ev.effect == "deny":
                violations.append(
                    f"POLICY DENIED read on {resource} for {action.actor.name} "
                    f"[{self._policy.name}: {ev.reason}]"
                )

        for resource in getattr(action, "resources_write", []):
            ev = self._policy.evaluate(action.actor, resource, "write")
            if ev.effect == "deny":
                violations.append(
                    f"POLICY DENIED write on {resource} for {action.actor.name} "
                    f"[{self._policy.name}: {ev.reason}]"
                )

        for resource in getattr(action, "resources_delegate", []):
            ev = self._policy.evaluate(action.actor, resource, "delegate")
            if ev.effect == "deny":
                violations.append(
                    f"POLICY DENIED delegate on {resource} for {action.actor.name} "
                    f"[{self._policy.name}: {ev.reason}]"
                )

        if not violations:
            return result

        from authgate.kernel.verifier import VerificationResult

        return VerificationResult(
            action_id=result.action_id,
            permitted=False,
            violations=tuple(list(result.violations) + violations),
            warnings=result.warnings,
            confidence=0.0,
            requires_human_arbitration=True,
            manipulation_score=getattr(result, "manipulation_score", 0.0),
        )
