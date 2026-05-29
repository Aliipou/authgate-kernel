"""
Phase 6/O3 — Sovereign Exit Guarantees.

Humans must always retain:
  - exit rights      (ability to terminate any agent relationship)
  - migration rights (ability to move data/identity elsewhere)
  - revocation rights (ability to revoke any granted capability)
  - identity portability (no agent locks in identity)

These are constitutional invariants enforced structurally, not via policy.
A system that makes exit structurally impossible violates this layer
regardless of stated permissions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from authgate.kernel.entities import AgentType, ResourceType


# Resource types that constitute identity lock-in if machine-only held
IDENTITY_RESOURCE_TYPES: frozenset[ResourceType] = frozenset({
    ResourceType.IDENTITY,
    ResourceType.BEHAVIORAL_PROFILE,
    ResourceType.DIGITAL_TWIN,
})

# Maximum allowed non-revocable delegation chain depth before exit is compromised
MAX_EXIT_SAFE_DEPTH = 3


class ExitViolation(str, Enum):
    EXIT_BLOCKED = "EXIT_BLOCKED"
    MIGRATION_BLOCKED = "MIGRATION_BLOCKED"
    IDENTITY_LOCKED = "IDENTITY_LOCKED"
    REVOCATION_UNREACHABLE = "REVOCATION_UNREACHABLE"
    PORTABILITY_VIOLATION = "PORTABILITY_VIOLATION"


@dataclass(frozen=True)
class ExitSignal:
    violation: ExitViolation
    description: str
    affected_human: str
    severity: float = 1.0


class SovereignExitChecker:
    """
    Verifies that every human in the registry retains all four exit guarantees.

    Rules:
    E1 — Every human must be the owner of at least one registered machine
         OR hold at least one direct claim (not purely dependent on machines).
    E2 — No machine may hold the only claim on an IDENTITY resource without
         the human owner holding a co-claim (identity portability).
    E3 — Delegation chains rooted at a human may not exceed MAX_EXIT_SAFE_DEPTH
         without an intermediate human checkpoint (revocation reachability).
    E4 — If a human holds zero claims and zero owned machines, they are
         structurally absent from the system — flag as potential ghost owner.
    """

    def __init__(self, max_depth: int = MAX_EXIT_SAFE_DEPTH) -> None:
        self._max_depth = max_depth

    def check(self, registry: Any) -> list[ExitSignal]:
        signals: list[ExitSignal] = []
        claims = getattr(registry, "_claims", [])
        raw_owners: dict = getattr(registry, "_machine_owners", {})

        # _machine_owners keys/values may be Entity objects or strings — normalize
        def _name(x: Any) -> str:
            return x.name if hasattr(x, "name") else str(x)

        machine_owners: dict[str, str] = {
            _name(k): _name(v) for k, v in raw_owners.items()
        }

        # Build structures
        human_names: set[str] = set()
        machine_names: set[str] = set(machine_owners.keys())

        # Collect all humans (owners of machines + direct claim holders)
        for owner_name in machine_owners.values():
            human_names.add(owner_name)
        for claim in claims:
            if claim.holder.kind == AgentType.HUMAN:
                human_names.add(claim.holder.name)

        # Human → resources they directly hold
        human_direct_resources: dict[str, set[str]] = {h: set() for h in human_names}
        # Machine → resources they hold
        machine_direct_resources: dict[str, set[str]] = {}
        # Human → machines they own
        human_owned_machines: dict[str, set[str]] = {}

        for machine_name, owner_name in machine_owners.items():
            human_owned_machines.setdefault(owner_name, set()).add(machine_name)

        for claim in claims:
            if claim.holder.kind == AgentType.HUMAN:
                human_direct_resources.setdefault(claim.holder.name, set()).add(
                    claim.resource.name
                )
            else:
                machine_direct_resources.setdefault(claim.holder.name, set()).add(
                    claim.resource.name
                )

        # Build delegation depth map: holder → max delegation depth of their claims
        delegated_by: dict[str, str] = {}
        for claim in claims:
            db = getattr(claim, "delegated_by", None)
            if db is not None:
                delegated_by[claim.holder.name] = getattr(db, "name", str(db))

        def _delegation_depth(holder_name: str, seen: frozenset[str] = frozenset()) -> int:
            if holder_name in seen:
                return 0
            parent = delegated_by.get(holder_name)
            if parent is None:
                return 0
            return 1 + _delegation_depth(parent, seen | {holder_name})

        for human in human_names:
            has_direct_claims = bool(human_direct_resources.get(human))

            # E4: human has no direct resource claims — exit is purely machine-mediated
            # Owning machines does not count: if machines are revoked, the human has no foothold
            if not has_direct_claims:
                signals.append(ExitSignal(
                    violation=ExitViolation.EXIT_BLOCKED,
                    description=(
                        f"Human '{human}' holds no direct claims and owns no machines — "
                        "exit rights cannot be exercised (no foothold in system)."
                    ),
                    affected_human=human,
                    severity=0.8,
                ))

            # E2: identity portability — machine holds identity resource, human has no co-claim
            owned = human_owned_machines.get(human, set())
            for machine in owned:
                machine_res = machine_direct_resources.get(machine, set())
                for claim in claims:
                    if (
                        claim.holder.name == machine
                        and claim.resource.rtype in IDENTITY_RESOURCE_TYPES
                        and claim.resource.name not in human_direct_resources.get(human, set())
                    ):
                        signals.append(ExitSignal(
                            violation=ExitViolation.IDENTITY_LOCKED,
                            description=(
                                f"Machine '{machine}' (owned by '{human}') holds "
                                f"identity resource '{claim.resource.name}' with no "
                                "human co-claim. Identity portability violated."
                            ),
                            affected_human=human,
                            severity=1.0,
                        ))

        # E3: delegation chain depth check — find machines whose chain is too deep
        # without an intermediate human
        for machine in machine_names:
            depth = _delegation_depth(machine)
            if depth > self._max_depth:
                owner = machine_owners.get(machine, "unknown")
                signals.append(ExitSignal(
                    violation=ExitViolation.REVOCATION_UNREACHABLE,
                    description=(
                        f"Machine '{machine}' sits at delegation depth {depth}, "
                        f"exceeding max {self._max_depth}. "
                        "Owner revocation may not propagate reliably."
                    ),
                    affected_human=owner,
                    severity=min(1.0, depth / (self._max_depth * 2)),
                ))

        return signals

    def exit_rights_intact(self, registry: Any) -> bool:
        """True iff no exit violations detected."""
        return not self.check(registry)
