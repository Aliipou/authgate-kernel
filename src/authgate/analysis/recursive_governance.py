"""
Phase 6/O1 — Recursive Agent Governance.

Agents governing agents governing agents requires bounded structural invariants:
- MAX_RECURSION_DEPTH: delegation trees cannot grow without limit
- Anti-feudal: no single agent node may govern too many subordinates
- Revocation propagation: revoking a governor revokes all governed subtree
- Feudal concentration: HHI-based power concentration across governance layers
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


MAX_RECURSION_DEPTH = 5
MAX_SUBORDINATES_PER_AGENT = 10
FEUDAL_HHI_THRESHOLD = 0.4


class GovernanceViolation(str, Enum):
    DEPTH_EXCEEDED = "DEPTH_EXCEEDED"
    FEUDAL_CONCENTRATION = "FEUDAL_CONCENTRATION"
    ANTI_FEUDAL_FAN_OUT = "ANTI_FEUDAL_FAN_OUT"
    CIRCULAR_GOVERNANCE = "CIRCULAR_GOVERNANCE"
    ORPHANED_GOVERNOR = "ORPHANED_GOVERNOR"


@dataclass(frozen=True)
class GovernanceLink:
    governor: str
    governed: str
    depth: int


@dataclass
class GovernanceSignal:
    violation: GovernanceViolation
    description: str
    actors: list[str] = field(default_factory=list)


class RecursiveGovernanceChecker:
    """
    Analyzes a governance graph for Phase 6/O1 invariants.

    Governance graph: directed edges governor → governed (agent supervises agent).
    Humans may govern machines but machines may not govern humans.
    """

    def __init__(
        self,
        max_depth: int = MAX_RECURSION_DEPTH,
        max_subordinates: int = MAX_SUBORDINATES_PER_AGENT,
        hhi_threshold: float = FEUDAL_HHI_THRESHOLD,
    ) -> None:
        self._max_depth = max_depth
        self._max_subordinates = max_subordinates
        self._hhi_threshold = hhi_threshold
        self._links: list[GovernanceLink] = []
        # governor → set of governed
        self._graph: dict[str, set[str]] = defaultdict(set)
        # governed → governor (single parent per node)
        self._parent: dict[str, str] = {}

    def add_link(self, governor: str, governed: str) -> None:
        """Record that governor supervises governed."""
        depth = self._compute_depth(governor) + 1
        self._links.append(GovernanceLink(governor, governed, depth))
        self._graph[governor].add(governed)
        self._parent[governed] = governor

    def _compute_depth(self, node: str) -> int:
        depth = 0
        current = node
        seen = set()
        while current in self._parent:
            if current in seen:
                return depth  # cycle — depth check handles this separately
            seen.add(current)
            current = self._parent[current]
            depth += 1
        return depth

    def _all_nodes(self) -> set[str]:
        nodes: set[str] = set()
        for link in self._links:
            nodes.add(link.governor)
            nodes.add(link.governed)
        return nodes

    def _find_cycles(self) -> list[list[str]]:
        visited: set[str] = set()
        rec_stack: set[str] = set()
        cycles: list[list[str]] = []

        def dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            for neighbor in self._graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    idx = path.index(neighbor)
                    cycles.append(path[idx:])
            path.pop()
            rec_stack.discard(node)

        for node in self._all_nodes():
            if node not in visited:
                dfs(node, [])
        return cycles

    def _subtree_nodes(self, root: str) -> set[str]:
        visited: set[str] = set()
        queue = deque([root])
        while queue:
            n = queue.popleft()
            if n in visited:
                continue
            visited.add(n)
            for child in self._graph.get(n, set()):
                queue.append(child)
        return visited

    def check(self) -> list[GovernanceSignal]:
        signals: list[GovernanceSignal] = []

        # Cycle detection
        for cycle in self._find_cycles():
            signals.append(GovernanceSignal(
                violation=GovernanceViolation.CIRCULAR_GOVERNANCE,
                description=f"Governance cycle detected: {' → '.join(cycle + [cycle[0]])}",
                actors=cycle,
            ))

        # Depth exceeded
        for node in self._all_nodes():
            d = self._compute_depth(node)
            if d > self._max_depth:
                signals.append(GovernanceSignal(
                    violation=GovernanceViolation.DEPTH_EXCEEDED,
                    description=(
                        f"Node '{node}' at governance depth {d} exceeds maximum {self._max_depth}"
                    ),
                    actors=[node],
                ))

        # Fan-out (anti-feudal)
        for governor, subordinates in self._graph.items():
            if len(subordinates) > self._max_subordinates:
                signals.append(GovernanceSignal(
                    violation=GovernanceViolation.ANTI_FEUDAL_FAN_OUT,
                    description=(
                        f"'{governor}' directly governs {len(subordinates)} agents "
                        f"(max {self._max_subordinates})"
                    ),
                    actors=[governor],
                ))

        # Feudal HHI concentration — only meaningful with multiple root governors
        # (nodes that have no parent, i.e. independent governance roots)
        all_nodes = self._all_nodes()
        total = len(all_nodes)
        root_governors = [
            g for g in self._graph
            if g not in self._parent  # no parent → governance root
        ]
        if total >= 3 and len(root_governors) >= 2:
            subtree_sizes = {
                g: len(self._subtree_nodes(g)) for g in root_governors
            }
            if subtree_sizes:
                hhi = sum((s / total) ** 2 for s in subtree_sizes.values())
                if hhi > self._hhi_threshold:
                    top = max(subtree_sizes, key=lambda k: subtree_sizes[k])
                    signals.append(GovernanceSignal(
                        violation=GovernanceViolation.FEUDAL_CONCENTRATION,
                        description=(
                            f"Governance HHI={hhi:.3f} exceeds threshold {self._hhi_threshold}. "
                            f"'{top}' controls {subtree_sizes[top]}/{total} nodes."
                        ),
                        actors=[top],
                    ))

        return signals

    def propagate_revocation(self, revoked_governor: str) -> set[str]:
        """Return all nodes that lose authority when revoked_governor is revoked."""
        return self._subtree_nodes(revoked_governor) - {revoked_governor}

    def depth_of(self, node: str) -> int:
        return self._compute_depth(node)
