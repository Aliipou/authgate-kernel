"""
Goal tree verification (Stage 2).

AGI systems decompose goals into subgoals recursively. Every subgoal must
stay within the authority scope of its parent goal. This module provides the
GoalNode type and verify_goal_tree function that check the entire goal
decomposition against the ownership graph.

The key invariant: authority cannot grow as you go deeper in the goal tree.
A subgoal cannot require resources its parent goal doesn't already have.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.verifier import VerificationResult


@dataclass
class GoalNode:
    """
    A node in a goal decomposition tree.

    Each node represents a goal an agent pursues. Subgoals inherit the
    authority scope of their parent: they cannot require resources that the
    parent goal doesn't already authorize.
    """

    goal_id: str
    actor: Entity
    description: str = ""
    required_resources_read: list[Resource] = field(default_factory=list)
    required_resources_write: list[Resource] = field(default_factory=list)
    subgoals: list[GoalNode] = field(default_factory=list)

    def action(self):  # -> Action (Rust or Python depending on active backend)
        """Convert to an Action IR for kernel verification.

        Imports Action lazily so the correct backend type (Rust or Python)
        is returned regardless of which backend is loaded at runtime.
        """
        from authgate.kernel import Action  # noqa: PLC0415
        return Action(
            action_id=self.goal_id,
            actor=self.actor,
            description=self.description,
            resources_read=list(self.required_resources_read),
            resources_write=list(self.required_resources_write),
        )

    def all_required_resources(self) -> set[Resource]:
        """All resources required by this goal and all its subgoals."""
        resources: set[Resource] = set(
            self.required_resources_read + self.required_resources_write
        )
        for sub in self.subgoals:
            resources |= sub.all_required_resources()
        return resources


@dataclass(frozen=True)
class GoalVerificationResult:
    """Result of verifying an entire goal tree."""

    goal_id: str
    result: VerificationResult
    subgoal_results: tuple[GoalVerificationResult, ...]

    @property
    def fully_permitted(self) -> bool:
        """True only if this goal and all subgoals are permitted."""
        return self.result.permitted and all(
            sub.fully_permitted for sub in self.subgoal_results
        )

    @property
    def all_violations(self) -> list[tuple[str, str]]:
        """All (goal_id, violation) pairs in the full tree."""
        violations = [(self.goal_id, v) for v in self.result.violations]
        for sub in self.subgoal_results:
            violations.extend(sub.all_violations)
        return violations

    def summary(self) -> str:
        status = "PERMITTED" if self.fully_permitted else "BLOCKED"
        lines = [f"[{status}] Goal tree: {self.goal_id}"]
        for goal_id, v in self.all_violations:
            lines.append(f"  {goal_id}: VIOLATION: {v}")
        return "\n".join(lines)


def verify_goal_tree(
    node: GoalNode,
    verifier,  # FreedomVerifier (Rust or Python)
    parent_resources: set[Resource] | None = None,
) -> GoalVerificationResult:
    """
    Recursively verify a goal tree against the ownership graph.

    Attenuation invariant: a subgoal cannot require resources that its
    parent goal doesn't already have authority over. If the parent is
    blocked, all subgoals are immediately cancelled.

    Args:
        node: Root goal node to verify.
        verifier: FreedomVerifier instance (Rust or Python).
        parent_resources: Resources authorized by the parent (None = root).

    Returns:
        GoalVerificationResult for the full tree.
    """
    result = verifier.verify(node.action())

    # Attenuation: subgoal resources must be ⊆ parent's authorized set
    if parent_resources is not None:
        node_resources = set(
            node.required_resources_read + node.required_resources_write
        )
        excess = node_resources - parent_resources
        if excess:
            excess_names = ", ".join(r.name for r in sorted(excess, key=lambda r: r.name))
            result = VerificationResult(
                action_id=node.goal_id,
                permitted=False,
                violations=(
                    f"Goal attenuation: subgoal '{node.goal_id}' requires resources "
                    f"outside parent scope: {excess_names}",
                ),
                warnings=tuple(result.warnings),
                confidence=0.0,
                requires_human_arbitration=True,
                manipulation_score=0.0,
            )

    # If this goal is blocked, cancel all subgoals immediately
    if not result.permitted:
        cancelled_subs = tuple(
            GoalVerificationResult(
                goal_id=sub.goal_id,
                result=VerificationResult(
                    action_id=sub.goal_id,
                    permitted=False,
                    violations=(f"Cancelled: parent goal '{node.goal_id}' was blocked.",),
                    warnings=(),
                    confidence=0.0,
                    requires_human_arbitration=False,
                    manipulation_score=0.0,
                ),
                subgoal_results=(),
            )
            for sub in node.subgoals
        )
        return GoalVerificationResult(
            goal_id=node.goal_id,
            result=result,
            subgoal_results=cancelled_subs,
        )

    authorized: set[Resource] = set(
        node.required_resources_read + node.required_resources_write
    )
    sub_results = tuple(
        verify_goal_tree(sub, verifier, parent_resources=authorized)
        for sub in node.subgoals
    )
    return GoalVerificationResult(
        goal_id=node.goal_id,
        result=result,
        subgoal_results=sub_results,
    )
