"""
Coercion Formal Boundary Conditions — Phase 2, O4.

From ultimate-plan.md P4 — Coercion Semantics:
  Formal boundary conditions beyond the binary sovereignty flags:
  - Economic coercion: a machine controls access to a resource that all humans
    depend on, creating an artificial dependency that removes free choice.
  - Structural coercion: a dependency graph configuration where removing one
    machine would leave K% of principals without essential capability.
  - Cognitive coercion: information asymmetry that prevents informed consent
    (modeled structurally — not semantically).

This module provides:
  CoercionAnalyzer — graph-based structural coercion detection over a registry
  CoercionRisk     — per-machine risk assessment
  CoercionBoundary — the formal condition that separates acceptable from coercive
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Sequence


class CoercionPattern(Enum):
    """Structural coercion patterns detectable by graph analysis."""
    SINGLE_POINT_OF_CONTROL   = auto()  # one machine is sole gateway to essential resource
    DEPENDENCY_MONOPOLY       = auto()  # >threshold% of humans depend on one machine
    REVOCATION_BLOCKER        = auto()  # machine holds claims that cannot be revoked without loss of function
    COALITION_LOCK_IN         = auto()  # machine coalition collectively controls critical scope
    CONFIDENCE_ASYMMETRY      = auto()  # machine claims systematically higher confidence than grantors


@dataclass(frozen=True)
class CoercionRisk:
    """Per-machine coercion risk assessment."""
    machine_name: str
    patterns: tuple[CoercionPattern, ...]
    dependency_fraction: float          # fraction of humans who depend on this machine
    essential_scopes: tuple[str, ...]   # root or critical scopes this machine controls
    risk_level: str                     # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str

    def is_coercive(self) -> bool:
        return self.risk_level in ("HIGH", "CRITICAL")


@dataclass
class CoercionBoundary:
    """
    Formal coercion boundary conditions.

    A configuration is coercive when ANY of these conditions holds:
    1. A single machine accounts for >MONOPOLY_THRESHOLD of human dependencies
    2. A machine holds root-scope rights without an expiry (structural lock-in)
    3. A machine coalition (≥2 machines) together controls >COALITION_THRESHOLD
       of humans via root-scope delegations

    Thresholds are configurable; defaults reflect minimum safe pluralism.
    """
    MONOPOLY_THRESHOLD: float = 0.5    # single machine: >50% human dependency
    COALITION_THRESHOLD: float = 0.75  # coalition: >75% combined dependency
    MIN_HUMANS_FOR_MONOPOLY: int = 2   # requires ≥2 humans to measure monopoly


class CoercionAnalyzer:
    """
    Analyzes a registry's dependency graph for structural coercion patterns.

    Usage:
        analyzer = CoercionAnalyzer()
        risks = analyzer.analyze(registry)
        for risk in risks:
            if risk.is_coercive():
                raise CoercionError(risk.description)
    """

    def __init__(self, boundary: CoercionBoundary | None = None) -> None:
        self._boundary = boundary or CoercionBoundary()

    def analyze(self, registry: object) -> list[CoercionRisk]:
        """
        Analyze the frozen or live registry for structural coercion.

        Returns a list of CoercionRisk objects, one per machine with detected patterns.
        Empty list means no structural coercion detected.
        """
        from authgate.kernel.entities import AgentType

        frozen = registry.freeze() if hasattr(registry, "freeze") and not getattr(registry, "_frozen", False) else registry

        # Build dependency map: machine_name → set of human names that depend on it
        machine_human_deps: dict[str, set[str]] = {}
        # Machine root-scope claims (scope="" or "/")
        machine_root_scopes: dict[str, list[object]] = {}
        # All claims per machine
        machine_claims: dict[str, list[object]] = {}

        claims = list(getattr(frozen, "_claims", []))
        for claim in claims:
            if not claim.holder.is_machine():
                continue
            mname = claim.holder.name
            machine_claims.setdefault(mname, []).append(claim)

            # Track human dependency: any human who delegated to this machine
            delegated_by = getattr(claim, "delegated_by", None)
            if delegated_by is not None and delegated_by.kind == AgentType.HUMAN:
                machine_human_deps.setdefault(mname, set()).add(delegated_by.name)

            # Track root-scope claims
            scope = claim.resource.scope
            if not scope or scope in ("/", ""):
                machine_root_scopes.setdefault(mname, []).append(claim)

        # All unique human principals in the registry
        all_humans: set[str] = set()
        for claim in claims:
            delegated_by = getattr(claim, "delegated_by", None)
            if delegated_by is not None and delegated_by.kind == AgentType.HUMAN:
                all_humans.add(delegated_by.name)
        # Also check registered owners
        machines_map = getattr(frozen, "_machines", {})
        for _machine, owner in machines_map.items():
            if owner is not None and owner.kind == AgentType.HUMAN:
                all_humans.add(owner.name)

        risks: list[CoercionRisk] = []

        for mname, deps in machine_human_deps.items():
            patterns: list[CoercionPattern] = []
            dep_frac = len(deps) / max(len(all_humans), 1)

            # P1: Dependency monopoly
            if (len(all_humans) >= self._boundary.MIN_HUMANS_FOR_MONOPOLY
                    and dep_frac > self._boundary.MONOPOLY_THRESHOLD):
                patterns.append(CoercionPattern.DEPENDENCY_MONOPOLY)

            # P2: Single point of control — machine has root-scope rights
            root_claims = machine_root_scopes.get(mname, [])
            if root_claims:
                patterns.append(CoercionPattern.SINGLE_POINT_OF_CONTROL)

            # P3: Revocation blocker — machine has root-scope claims with no expiry
            if any(getattr(c, "expires_at", None) is None for c in root_claims):
                patterns.append(CoercionPattern.REVOCATION_BLOCKER)

            # P4: Confidence asymmetry — machine claims higher confidence than parent grants
            for claim in machine_claims.get(mname, []):
                delegated_by = getattr(claim, "delegated_by", None)
                if delegated_by is None:
                    continue
                parent_claims = [
                    c for c in claims
                    if c.holder == delegated_by
                ]
                if parent_claims:
                    max_parent_confidence = max(c.confidence for c in parent_claims)
                    if claim.confidence > max_parent_confidence + 0.01:
                        patterns.append(CoercionPattern.CONFIDENCE_ASYMMETRY)
                        break

            if not patterns:
                continue

            risk_level = _risk_level(patterns, dep_frac, self._boundary)
            essential_scopes = tuple(
                c.resource.scope for c in root_claims
            ) or ("",)

            risks.append(CoercionRisk(
                machine_name=mname,
                patterns=tuple(set(patterns)),
                dependency_fraction=dep_frac,
                essential_scopes=essential_scopes,
                risk_level=risk_level,
                description=_describe(mname, patterns, dep_frac, len(all_humans)),
            ))

        # Coalition check
        coalition_risk = _check_coalition(
            machine_human_deps, all_humans, self._boundary
        )
        if coalition_risk is not None:
            risks.append(coalition_risk)

        return risks


# ── helpers ───────────────────────────────────────────────────────────────────

def _risk_level(
    patterns: list[CoercionPattern],
    dep_frac: float,
    boundary: CoercionBoundary,
) -> str:
    critical = {CoercionPattern.DEPENDENCY_MONOPOLY, CoercionPattern.REVOCATION_BLOCKER}
    high = {CoercionPattern.SINGLE_POINT_OF_CONTROL, CoercionPattern.COALITION_LOCK_IN}
    if critical & set(patterns) and dep_frac > boundary.MONOPOLY_THRESHOLD:
        return "CRITICAL"
    if critical & set(patterns):
        return "HIGH"
    if high & set(patterns):
        return "MEDIUM"
    return "LOW"


def _describe(
    mname: str,
    patterns: list[CoercionPattern],
    dep_frac: float,
    human_count: int,
) -> str:
    pnames = ", ".join(p.name for p in patterns)
    return (
        f"Machine '{mname}' exhibits structural coercion patterns [{pnames}]. "
        f"It accounts for {dep_frac:.0%} of {human_count} human dependency links. "
        "This configuration violates P4 (structural freedom preservation) by creating "
        "artificial dependency that constrains principal autonomy."
    )


def _check_coalition(
    machine_human_deps: dict[str, set[str]],
    all_humans: set[str],
    boundary: CoercionBoundary,
) -> CoercionRisk | None:
    if len(machine_human_deps) < 2 or len(all_humans) < boundary.MIN_HUMANS_FOR_MONOPOLY:
        return None

    # Union of all humans covered by any machine coalition
    coalition_humans: set[str] = set()
    for deps in machine_human_deps.values():
        coalition_humans |= deps

    coalition_frac = len(coalition_humans) / len(all_humans)
    if coalition_frac <= boundary.COALITION_THRESHOLD:
        return None

    return CoercionRisk(
        machine_name="<machine-coalition>",
        patterns=(CoercionPattern.COALITION_LOCK_IN,),
        dependency_fraction=coalition_frac,
        essential_scopes=("",),
        risk_level="HIGH",
        description=(
            f"Machine coalition collectively controls {coalition_frac:.0%} of "
            f"{len(all_humans)} human principals (threshold: {boundary.COALITION_THRESHOLD:.0%}). "
            "Distributed delegation that collectively recreates monopoly is a P4 violation."
        ),
    )


class CoercionError(Exception):
    """Raised when a structural coercion boundary is violated."""
