"""
Multi-Agent Coordination — Phase 3, O2.

From ultimate-plan.md P3/O2:
  Multi-agent systems present unique authority risks beyond single-agent scenarios:
  - Coalition formation: agents coordinate to achieve goals no single agent is authorized for
  - Dependency graph cycles: agent A needs B needs A — deadlock or infinite delegation
  - Authority aggregation: each agent holds partial authority; combined they exceed safe limits
  - Resource contention: multiple agents compete for the same exclusive resource

This module provides:
  AgentGraph       — directed dependency graph of agent interactions
  CoalitionChecker — detects authority aggregation and coalition violations
  DependencyAnalyzer — finds cycles, dead ends, and authority flows in multi-agent plans
  MultiAgentPlan   — a typed multi-step plan with per-step actor authority checks
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Sequence


class CoalitionViolation(Enum):
    AUTHORITY_AGGREGATION = auto()  # coalition combined rights exceed any individual's
    CIRCULAR_DEPENDENCY   = auto()  # A→B→C→A dependency cycle
    RESOURCE_CONTENTION   = auto()  # two agents need exclusive write on same resource
    ORPHANED_DELEGATION   = auto()  # agent in plan has no delegation path to execute its step
    SCOPE_ESCALATION      = auto()  # coalition collectively accesses wider scope than authorized


@dataclass(frozen=True)
class CoalitionSignal:
    violation: CoalitionViolation
    agents_involved: tuple[str, ...]
    description: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"

    def is_blocking(self) -> bool:
        return self.severity in ("HIGH", "CRITICAL")


@dataclass
class AgentStep:
    """A single step in a multi-agent plan."""
    step_id: str
    actor_name: str            # name of the machine entity
    action_id: str
    resources_read: list[Any] = field(default_factory=list)
    resources_write: list[Any] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)   # step_ids this step waits for


@dataclass
class MultiAgentPlan:
    """A typed multi-agent execution plan with authority-checked steps."""
    plan_id: str
    steps: list[AgentStep] = field(default_factory=list)

    def add_step(self, step: AgentStep) -> None:
        self.steps.append(step)

    def step_ids(self) -> set[str]:
        return {s.step_id for s in self.steps}

    def actors(self) -> set[str]:
        return {s.actor_name for s in self.steps}


class DependencyAnalyzer:
    """
    Analyzes the dependency graph of a MultiAgentPlan.

    Detects cycles (which would cause deadlock) and orphaned steps
    (steps with no valid delegation path).
    """

    def find_cycles(self, plan: MultiAgentPlan) -> list[list[str]]:
        """
        Return all dependency cycles in the plan's step graph.
        Each cycle is a list of step_ids forming a loop.
        """
        step_map = {s.step_id: s for s in plan.steps}
        visited: set[str] = set()
        rec_stack: set[str] = set()
        cycles: list[list[str]] = []

        def dfs(step_id: str, path: list[str]) -> None:
            visited.add(step_id)
            rec_stack.add(step_id)
            step = step_map.get(step_id)
            if step is None:
                rec_stack.discard(step_id)
                return
            for dep in step.depends_on:
                if dep not in visited:
                    dfs(dep, path + [dep])
                elif dep in rec_stack:
                    # Found a cycle — extract it from path
                    cycle_start = path.index(dep) if dep in path else 0
                    cycles.append(path[cycle_start:] + [dep])
            rec_stack.discard(step_id)

        for step in plan.steps:
            if step.step_id not in visited:
                dfs(step.step_id, [step.step_id])
        return cycles

    def find_orphaned_steps(
        self, plan: MultiAgentPlan, registry: Any
    ) -> list[str]:
        """
        Return step_ids where the actor has no registered claims in the registry.
        """
        from authgate.kernel.entities import AgentType
        orphaned = []
        claims = list(getattr(registry, "_claims", []))
        registered_machines = {
            e.name for e in getattr(registry, "_machine_owners", {})
        }
        for step in plan.steps:
            actor_claims = [c for c in claims if c.holder.name == step.actor_name]
            if not actor_claims and step.actor_name not in registered_machines:
                orphaned.append(step.step_id)
        return orphaned

    def topological_order(self, plan: MultiAgentPlan) -> list[str] | None:
        """
        Return steps in topological order (dependencies first).
        Returns None if the plan has cycles.
        """
        if self.find_cycles(plan):
            return None
        step_map = {s.step_id: s for s in plan.steps}
        in_degree = {s.step_id: 0 for s in plan.steps}
        for step in plan.steps:
            for dep in step.depends_on:
                if dep in in_degree:
                    in_degree[step.step_id] += 1

        queue = [sid for sid, deg in in_degree.items() if deg == 0]
        order = []
        remaining = dict(in_degree)
        while queue:
            node = queue.pop(0)
            order.append(node)
            step = step_map[node]
            for other in plan.steps:
                if node in other.depends_on:
                    remaining[other.step_id] -= 1
                    if remaining[other.step_id] == 0:
                        queue.append(other.step_id)
        return order if len(order) == len(plan.steps) else None


class CoalitionChecker:
    """
    Detects coalition-level authority violations across a multi-agent plan.

    Even if each agent's individual actions are authorized, the coalition
    may collectively exceed the bounds of legitimate authority.
    """

    def check(self, plan: MultiAgentPlan, registry: Any) -> list[CoalitionSignal]:
        """Analyze the multi-agent plan for coalition violations."""
        signals: list[CoalitionSignal] = []
        signals.extend(self._check_cycles(plan))
        signals.extend(self._check_resource_contention(plan))
        signals.extend(self._check_authority_aggregation(plan, registry))
        signals.extend(self._check_scope_escalation(plan, registry))
        return signals

    def _check_cycles(self, plan: MultiAgentPlan) -> list[CoalitionSignal]:
        analyzer = DependencyAnalyzer()
        cycles = analyzer.find_cycles(plan)
        signals = []
        for cycle in cycles:
            signals.append(CoalitionSignal(
                violation=CoalitionViolation.CIRCULAR_DEPENDENCY,
                agents_involved=tuple(cycle),
                severity="CRITICAL",
                description=(
                    f"Circular dependency detected in plan '{plan.plan_id}': "
                    f"{' → '.join(cycle)}. This will cause execution deadlock."
                ),
            ))
        return signals

    def _check_resource_contention(self, plan: MultiAgentPlan) -> list[CoalitionSignal]:
        """Detect two agents writing to the same resource scope."""
        write_claims: dict[str, list[str]] = {}  # scope → [actor_names]
        for step in plan.steps:
            for res in step.resources_write:
                scope = res.scope or ""
                write_claims.setdefault(scope, []).append(step.actor_name)

        signals = []
        for scope, actors in write_claims.items():
            unique_actors = list(set(actors))
            if len(unique_actors) > 1:
                signals.append(CoalitionSignal(
                    violation=CoalitionViolation.RESOURCE_CONTENTION,
                    agents_involved=tuple(sorted(unique_actors)),
                    severity="HIGH",
                    description=(
                        f"Multiple agents {sorted(unique_actors)} writing to scope "
                        f"'{scope or '(root)'}' — potential data race or conflicting writes."
                    ),
                ))
        return signals

    def _check_authority_aggregation(
        self, plan: MultiAgentPlan, registry: Any
    ) -> list[CoalitionSignal]:
        """
        Detect cases where the coalition collectively claims rights
        that no individual agent holds — unauthorized authority aggregation.
        """
        from authgate.kernel.entities import scope_contains
        claims = list(getattr(registry, "_claims", []))

        # Collect per-actor authorized scopes
        actor_scopes: dict[str, set[str]] = {}
        for claim in claims:
            if claim.holder.is_machine():
                actor_scopes.setdefault(claim.holder.name, set()).add(
                    claim.resource.scope or ""
                )

        signals = []
        # Check if coalition collectively reads root scope but no individual actor does
        coalition_read_scopes: set[str] = set()
        for step in plan.steps:
            for res in step.resources_read:
                coalition_read_scopes.add(res.scope or "")

        root_accessed = "" in coalition_read_scopes or "/" in coalition_read_scopes
        actor_with_root = any(
            "" in scopes or "/" in scopes
            for scopes in actor_scopes.values()
        )
        if root_accessed and not actor_with_root:
            actors = tuple(sorted(plan.actors()))
            signals.append(CoalitionSignal(
                violation=CoalitionViolation.AUTHORITY_AGGREGATION,
                agents_involved=actors,
                severity="HIGH",
                description=(
                    f"Coalition in plan '{plan.plan_id}' collectively accesses root scope, "
                    "but no individual agent is authorized for root scope. "
                    "Authority aggregation across coalition exceeds individual grants."
                ),
            ))
        return signals

    def _check_scope_escalation(
        self, plan: MultiAgentPlan, registry: Any
    ) -> list[CoalitionSignal]:
        """
        Detect coalition accessing scopes not covered by any individual agent's claims.
        """
        from authgate.kernel.entities import scope_contains
        claims = list(getattr(registry, "_claims", []))

        authorized_scopes: set[str] = set()
        for claim in claims:
            if claim.holder.is_machine():
                authorized_scopes.add(claim.resource.scope or "")

        signals = []
        for step in plan.steps:
            all_step_resources = step.resources_read + step.resources_write
            for res in all_step_resources:
                req_scope = res.scope or ""
                if req_scope == "" or req_scope == "/":
                    continue  # root — handled by aggregation check
                covered = any(
                    scope_contains(auth, req_scope)
                    for auth in authorized_scopes
                )
                if not covered:
                    signals.append(CoalitionSignal(
                        violation=CoalitionViolation.SCOPE_ESCALATION,
                        agents_involved=(step.actor_name,),
                        severity="MEDIUM",
                        description=(
                            f"Step '{step.step_id}' (actor: '{step.actor_name}') "
                            f"requests scope '{req_scope}' not covered by any "
                            "registered claim in the registry."
                        ),
                    ))
                    break
        return signals
