"""
Sovereignty metrics — Phase 4, O3.

Quantitative indicators of human agency preservation in a registry snapshot.
These metrics do not gate actions — they inform humans about structural risks.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from authgate.kernel.registry import OwnershipRegistry


@dataclass(frozen=True)
class SovereigntySnapshot:
    """Point-in-time sovereignty measurement for a frozen registry."""

    # Agency preservation: fraction of machines with human oversight
    machine_count: int
    machines_with_owner: int
    agency_preservation_score: float  # machines_with_owner / machine_count (0.0-1.0)

    # Delegation depth: max delegation chain depth in registry
    max_delegation_depth: int
    mean_delegation_depth: float

    # Dependency centralization: how concentrated machine ownership is
    # (1.0 = all machines owned by one human; 0.0 = perfectly distributed)
    dependency_centralization: float

    # Reversibility: fraction of claims that are time-bounded (have expires_at)
    total_claims: int
    time_bounded_claims: int
    reversibility_index: float  # time_bounded_claims / total_claims (0.0-1.0)

    # Autonomy degradation: fraction of claims delegated (not directly granted)
    delegated_claims: int
    autonomy_degradation_rate: float  # delegated_claims / total_claims (0.0-1.0)

    def sovereignty_risk_level(self) -> str:
        """Return 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' based on metrics.

        Scoring rules (each dimension contributes a risk point):
          - agency_preservation_score < 0.5  → +2 points (critical gap)
          - agency_preservation_score < 0.8  → +1 point
          - dependency_centralization  > 0.8 → +2 points (monopoly ownership)
          - dependency_centralization  > 0.5 → +1 point
          - autonomy_degradation_rate  > 0.7 → +2 points (most claims delegated)
          - autonomy_degradation_rate  > 0.4 → +1 point
          - reversibility_index        < 0.2 → +2 points (few claims time-bounded)
          - reversibility_index        < 0.5 → +1 point
          - max_delegation_depth       > 4   → +1 point (deep chains)

        Total score → 0-3 LOW, 4-5 MEDIUM, 6-8 HIGH, 9+ CRITICAL
        """
        score = 0

        # Agency preservation
        if self.agency_preservation_score < 0.5:
            score += 2
        elif self.agency_preservation_score < 0.8:
            score += 1

        # Dependency centralization
        if self.dependency_centralization > 0.8:
            score += 2
        elif self.dependency_centralization > 0.5:
            score += 1

        # Autonomy degradation
        if self.autonomy_degradation_rate > 0.7:
            score += 2
        elif self.autonomy_degradation_rate > 0.4:
            score += 1

        # Reversibility (low reversibility = high risk)
        if self.reversibility_index < 0.2:
            score += 2
        elif self.reversibility_index < 0.5:
            score += 1

        # Deep delegation chains
        if self.max_delegation_depth > 4:
            score += 1

        if score >= 9:
            return "CRITICAL"
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"


def _delegation_depth(claim, all_claims) -> int:
    """Walk the delegated_by chain and return its depth (0 = not delegated)."""
    depth = 0
    seen = set()
    current = getattr(claim, "delegated_by", None)
    while current is not None:
        if id(current) in seen:
            break  # cycle guard
        seen.add(id(current))
        depth += 1
        # Find a claim held by `current` that was itself delegated, to walk further
        parent_claims = [
            c for c in all_claims if c.holder == current and getattr(c, "delegated_by", None) is not None
        ]
        if not parent_claims:
            break
        # Pick the deepest parent chain to represent max depth from this node
        current = getattr(parent_claims[0], "delegated_by", None)
    return depth


class SovereigntyAnalyzer:
    """Compute sovereignty metrics from a registry snapshot."""

    def analyze(self, registry: OwnershipRegistry) -> SovereigntySnapshot:
        """Compute sovereignty metrics from a registry snapshot."""
        # Work on a frozen copy so metrics are consistent even on a live registry
        if not registry._frozen:
            registry = registry.freeze()

        claims = list(registry._claims)
        machine_owners = dict(registry._machine_owners)

        # --- Agency preservation ---
        machine_count = len(machine_owners)
        # All machines in _machine_owners have an owner by construction;
        # machines that were never registered have no entry.
        machines_with_owner = sum(1 for owner in machine_owners.values() if owner is not None)
        if machine_count == 0:
            agency_preservation_score = 1.0  # vacuously perfect — no machines at risk
        else:
            agency_preservation_score = machines_with_owner / machine_count

        # --- Delegation depth ---
        depths = [_delegation_depth(c, claims) for c in claims]
        max_delegation_depth = max(depths) if depths else 0
        mean_delegation_depth = sum(depths) / len(depths) if depths else 0.0

        # --- Dependency centralization (Herfindahl-Hirschman style) ---
        # Counts how many machines each human owns.
        if machine_count == 0:
            dependency_centralization = 0.0
        else:
            owner_counts = Counter(machine_owners.values())
            # HHI: sum of squared shares; 1.0 = monopoly, 1/n = uniform
            hhi = sum((count / machine_count) ** 2 for count in owner_counts.values())
            n = len(owner_counts)
            if n == 1:
                dependency_centralization = 1.0
            else:
                # Normalise to [0, 1]: 0 = perfectly equal, 1 = monopoly
                min_hhi = 1.0 / n
                dependency_centralization = (hhi - min_hhi) / (1.0 - min_hhi)

        # --- Reversibility ---
        total_claims = len(claims)
        time_bounded_claims = sum(1 for c in claims if c.expires_at is not None)
        if total_claims == 0:
            reversibility_index = 1.0  # vacuously perfect — nothing to expire
        else:
            reversibility_index = time_bounded_claims / total_claims

        # --- Autonomy degradation ---
        delegated_claims = sum(1 for c in claims if getattr(c, "delegated_by", None) is not None)
        if total_claims == 0:
            autonomy_degradation_rate = 0.0
        else:
            autonomy_degradation_rate = delegated_claims / total_claims

        return SovereigntySnapshot(
            machine_count=machine_count,
            machines_with_owner=machines_with_owner,
            agency_preservation_score=agency_preservation_score,
            max_delegation_depth=max_delegation_depth,
            mean_delegation_depth=mean_delegation_depth,
            dependency_centralization=dependency_centralization,
            total_claims=total_claims,
            time_bounded_claims=time_bounded_claims,
            reversibility_index=reversibility_index,
            delegated_claims=delegated_claims,
            autonomy_degradation_rate=autonomy_degradation_rate,
        )
