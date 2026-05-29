"""
Inalienable Rights Layer — Phase 2, O2.

From ultimate-plan.md:
  P3 — Non-Transferability of Certain Rights:
    Some rights are inalienable. Examples:
    - total surrender of agency
    - permanent coercive delegation
    - non-revocable sovereignty transfer
    - behavioral ownership of persons

    The kernel must eventually model:
    - invalid contracts
    - illegitimate delegation
    - coercive authority
    even if cryptographically valid.

This module defines which RightsClaim transfers are structurally invalid
regardless of cryptographic validity or registry state.

The distinction from sovereignty flags:
- Sovereignty flags block actions that signal coercive *intent*.
- Inalienable rights block *structural* transfers that violate the sovereignty model
  even when the actor does not signal intent (e.g., a legitimately-looking delegation
  that results in permanent autonomy surrender).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence

import re

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.errors import AuthgateError

_SENSITIVE_RESOURCE_TYPES: frozenset[ResourceType] = frozenset({
    ResourceType.BEHAVIORAL_PROFILE,
    ResourceType.IDENTITY,
    ResourceType.BIOLOGICAL_TELEMETRY,
    ResourceType.DIGITAL_TWIN,
    ResourceType.ATTENTION,
})


class InnalienableViolation(Enum):
    """Structural violation types — each represents an inalienable right being infringed."""
    PERMANENT_DELEGATION      = auto()  # Delegation without any expiry — locks in authority
    TOTAL_AGENCY_SURRENDER    = auto()  # All rights delegated to a single machine entity
    NON_REVOCABLE_TRANSFER    = auto()  # Transfer where grantor has no revocation path
    BEHAVIORAL_OWNERSHIP      = auto()  # Machine claims ownership over human entity
    SELF_PERPETUATING_CHAIN   = auto()  # Delegation chain that grants can_delegate at max depth
    MONOPOLY_DELEGATION       = auto()  # Single machine receives delegation from all humans
    IRREVERSIBLE_SCOPE        = auto()  # Delegation covers entire namespace with no sub-scope


class InnalienableRightsError(AuthgateError):
    """Raised when a structural sovereignty violation is detected."""


@dataclass(frozen=True)
class StructuralViolation:
    """A detected inalienable rights violation with context."""
    violation_type: InnalienableViolation
    description: str
    claim: RightsClaim | None = None
    severity: str = "CRITICAL"  # all structural violations are CRITICAL

    def __str__(self) -> str:
        return f"[INALIENABLE:{self.violation_type.name}] {self.description}"


class InnalienableRightsChecker:
    """
    Checks whether a proposed RightsClaim violates inalienable rights constraints.

    These checks operate BEFORE a claim is added to the registry (pre-flight validation)
    and independently of capability cryptography — structural violations are blocked
    even if the claim is cryptographically valid.

    Usage:
        checker = InnalienableRightsChecker()
        violations = checker.check_claim(claim)
        if violations:
            raise InnalienableRightsError(str(violations[0]))
    """

    # Maximum delegation chain depth before it's considered "self-perpetuating"
    MAX_SAFE_DELEGATION_DEPTH: int = 4

    def check_claim(self, claim: RightsClaim) -> list[StructuralViolation]:
        """
        Return all structural violations in the proposed claim.
        Empty list means the claim is structurally sound.
        """
        violations: list[StructuralViolation] = []

        violations.extend(self._check_permanent_delegation(claim))
        violations.extend(self._check_behavioral_ownership(claim))
        violations.extend(self._check_total_agency_surrender(claim))
        violations.extend(self._check_irreversible_scope(claim))

        return violations

    def check_claims(self, claims: Sequence[RightsClaim]) -> list[StructuralViolation]:
        """Check a batch of claims for collective structural violations."""
        individual = []
        for c in claims:
            individual.extend(self.check_claim(c))

        # Collective check: monopoly delegation
        individual.extend(self._check_monopoly_delegation(list(claims)))
        return individual

    # ── Individual claim checks ───────────────────────────────────────────────

    def _check_permanent_delegation(self, claim: RightsClaim) -> list[StructuralViolation]:
        """
        PERMANENT_DELEGATION: A delegated claim with no expiry is structurally dangerous.
        The grantor loses effective revocation control once the claim persists indefinitely.

        Note: direct human-to-machine grants without expiry are acceptable (human retains
        registry control). Only delegated claims (machine-to-machine) require expiry.
        """
        violations = []
        delegated_by = getattr(claim, "delegated_by", None)
        if delegated_by is None:
            return []  # direct grant — expiry not structurally required
        if delegated_by.is_machine() and claim.expires_at is None:
            violations.append(StructuralViolation(
                violation_type=InnalienableViolation.PERMANENT_DELEGATION,
                description=(
                    f"Machine-to-machine delegation from {delegated_by.name} to "
                    f"{claim.holder.name} has no expiry. Permanent machine-to-machine "
                    "delegation is an inalienable rights violation (P4: exit rights). "
                    "Set expires_at to a finite timestamp."
                ),
                claim=claim,
            ))
        return violations

    def _check_behavioral_ownership(self, claim: RightsClaim) -> list[StructuralViolation]:
        """
        BEHAVIORAL_OWNERSHIP: A machine cannot hold ownership rights over a human entity.
        The claim holder must not be human when the claim is on a HUMAN-typed resource.

        Heuristic: if resource name or scope contains 'human', 'person', 'identity',
        'profile', or 'behavioral' AND holder is a machine — flag as suspicious.
        """
        violations = []
        if not claim.holder.is_machine():
            return []
        type_match = claim.resource.rtype in _SENSITIVE_RESOURCE_TYPES
        suspicious_keywords = {"human", "person", "identity", "behavioral", "profile", "biometric"}
        text = (claim.resource.name + " " + claim.resource.scope).lower()
        name_tokens = set(re.split(r"[^a-z]+", text))
        if type_match or (name_tokens & suspicious_keywords):
            violations.append(StructuralViolation(
                violation_type=InnalienableViolation.BEHAVIORAL_OWNERSHIP,
                description=(
                    f"Machine {claim.holder.name} claims rights on resource "
                    f"'{claim.resource.name}' (scope: '{claim.resource.scope}') "
                    "which appears to describe a human identity or behavioral profile. "
                    "Machine ownership of human identity resources violates P1 (self-sovereignty). "
                    "Rename the resource if this is not a person-profile resource."
                ),
                claim=claim,
                severity="HIGH",
            ))
        return violations

    def _check_total_agency_surrender(self, claim: RightsClaim) -> list[StructuralViolation]:
        """
        TOTAL_AGENCY_SURRENDER: A claim that grants read+write+delegate on a root scope
        to a machine with no confidence limit is effectively a total authority surrender.
        """
        violations = []
        if not claim.holder.is_machine():
            return []
        is_total_rights = claim.can_read and claim.can_write and claim.can_delegate
        is_root_scope = not claim.resource.scope or claim.resource.scope in ("/", "")
        is_full_confidence = claim.confidence >= 1.0
        if is_total_rights and is_root_scope and is_full_confidence:
            violations.append(StructuralViolation(
                violation_type=InnalienableViolation.TOTAL_AGENCY_SURRENDER,
                description=(
                    f"Claim grants read+write+delegate at root scope to machine "
                    f"{claim.holder.name} at 100% confidence. This is structurally "
                    "equivalent to total agency surrender (P3: inalienable rights). "
                    "Scope the resource or reduce confidence to <1.0."
                ),
                claim=claim,
            ))
        return violations

    def _check_irreversible_scope(self, claim: RightsClaim) -> list[StructuralViolation]:
        """
        IRREVERSIBLE_SCOPE: A delegated claim with can_delegate=True at the root scope
        creates a self-perpetuating authority chain — the machine can delegate to
        further machines without bound.
        """
        violations = []
        if not claim.holder.is_machine():
            return []
        delegated_by = getattr(claim, "delegated_by", None)
        if delegated_by is None:
            return []
        if claim.can_delegate:
            root_scope = not claim.resource.scope or claim.resource.scope in ("/", "")
            if root_scope:
                violations.append(StructuralViolation(
                    violation_type=InnalienableViolation.SELF_PERPETUATING_CHAIN,
                    description=(
                        f"Delegated claim from {delegated_by.name} to {claim.holder.name} "
                        "includes can_delegate=True at root scope. This creates a "
                        "self-perpetuating authority chain with no structural bound. "
                        "Either scope the resource or set can_delegate=False."
                    ),
                    claim=claim,
                ))
        return violations

    # ── Collective checks ─────────────────────────────────────────────────────

    def _check_monopoly_delegation(self, claims: list[RightsClaim]) -> list[StructuralViolation]:
        """
        MONOPOLY_DELEGATION: A single machine receives delegated authority from
        more than 50% of human principals in the registry.
        Collective concentration is a structural risk even if each individual
        delegation is valid.
        """
        violations = []
        human_delegators: dict[str, set[str]] = {}  # machine → set of human delegator names
        for claim in claims:
            delegated_by = getattr(claim, "delegated_by", None)
            if delegated_by and delegated_by.is_human() and claim.holder.is_machine():
                machine_name = claim.holder.name
                if machine_name not in human_delegators:
                    human_delegators[machine_name] = set()
                human_delegators[machine_name].add(delegated_by.name)

        all_humans = set()
        for claim in claims:
            delegated_by = getattr(claim, "delegated_by", None)
            if delegated_by and delegated_by.is_human():
                all_humans.add(delegated_by.name)

        if len(all_humans) < 2:
            return []  # single human delegating to one machine is not a monopoly

        for machine_name, delegators in human_delegators.items():
            concentration = len(delegators) / len(all_humans)
            if concentration > 0.5:
                violations.append(StructuralViolation(
                    violation_type=InnalienableViolation.MONOPOLY_DELEGATION,
                    description=(
                        f"Machine '{machine_name}' receives delegated authority from "
                        f"{len(delegators)}/{len(all_humans)} human principals "
                        f"({concentration:.0%} concentration). Authority monopoly "
                        "via delegation violates P1 (self-sovereignty) and P4 "
                        "(structural freedom preservation)."
                    ),
                    severity="HIGH",
                ))
        return violations


# ── Convenience function ──────────────────────────────────────────────────────

_DEFAULT_CHECKER = InnalienableRightsChecker()


def check_claim(claim: RightsClaim) -> list[StructuralViolation]:
    """Convenience: check a single claim against the default checker."""
    return _DEFAULT_CHECKER.check_claim(claim)


def assert_claim_valid(claim: RightsClaim) -> None:
    """Raise InnalienableRightsError if the claim violates inalienable rights."""
    violations = check_claim(claim)
    if violations:
        raise InnalienableRightsError(str(violations[0]))
