"""
Phase 6/O2 — Constitutional AI Economies.

Prevents machine oligarchies, irreversible economic concentration, and
sovereignty erosion through convenience. Models resources as economic
primitives and checks structural concentration invariants.

Key invariants:
- No single machine entity may control >OLIGARCHY_THRESHOLD of total resources
- Convenience lock-in: when a machine's claimed resources exceed the human's
  own claims on the same scope, sovereignty erosion is flagged
- Irreversibility: claims with no expiry AND no human revocation path are flagged
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from authgate.kernel.entities import AgentType, ResourceType


OLIGARCHY_THRESHOLD = 0.33
CONCENTRATION_HHI_THRESHOLD = 0.35
HIGH_VALUE_RESOURCE_TYPES: frozenset[ResourceType] = frozenset({
    ResourceType.BEHAVIORAL_PROFILE,
    ResourceType.IDENTITY,
    ResourceType.BIOLOGICAL_TELEMETRY,
    ResourceType.DIGITAL_TWIN,
    ResourceType.ATTENTION,
})


class EconomicViolation(str, Enum):
    MACHINE_OLIGARCHY = "MACHINE_OLIGARCHY"
    RESOURCE_CONCENTRATION = "RESOURCE_CONCENTRATION"
    SOVEREIGNTY_EROSION = "SOVEREIGNTY_EROSION"
    IRREVERSIBLE_LOCK_IN = "IRREVERSIBLE_LOCK_IN"
    HIGH_VALUE_MONOPOLY = "HIGH_VALUE_MONOPOLY"


@dataclass(frozen=True)
class EconomicSignal:
    violation: EconomicViolation
    description: str
    actor: str
    severity: float


class ConstitutionalEconomyChecker:
    """
    Analyzes registry state for economic concentration and sovereignty erosion.

    Operates on a frozen or live OwnershipRegistry snapshot.
    """

    def __init__(
        self,
        oligarchy_threshold: float = OLIGARCHY_THRESHOLD,
        hhi_threshold: float = CONCENTRATION_HHI_THRESHOLD,
    ) -> None:
        self._oligarchy_threshold = oligarchy_threshold
        self._hhi_threshold = hhi_threshold

    def analyze(self, registry: object) -> list[EconomicSignal]:
        signals: list[EconomicSignal] = []
        claims = getattr(registry, "_claims", [])
        if not claims:
            return signals

        total_resources = len({c.resource.name for c in claims})
        if total_resources == 0:
            return signals

        # Resources held per entity
        machine_resources: dict[str, set[str]] = {}
        human_resources: dict[str, set[str]] = {}

        for claim in claims:
            entity = claim.holder
            rname = claim.resource.name
            if entity.kind == AgentType.MACHINE:
                machine_resources.setdefault(entity.name, set()).add(rname)
            else:
                human_resources.setdefault(entity.name, set()).add(rname)

        # Exclusive machine resources: held by machine but no human has a co-claim
        human_held: set[str] = {r for rs in human_resources.values() for r in rs}

        # MACHINE_OLIGARCHY: single machine holds > threshold of EXCLUSIVE resources
        for machine, resources in machine_resources.items():
            exclusive = resources - human_held
            if not exclusive:
                continue
            share = len(exclusive) / total_resources
            if share > self._oligarchy_threshold:
                signals.append(EconomicSignal(
                    violation=EconomicViolation.MACHINE_OLIGARCHY,
                    description=(
                        f"Machine '{machine}' exclusively controls {len(exclusive)}/{total_resources} "
                        f"resources ({share:.1%}), exceeding oligarchy threshold "
                        f"{self._oligarchy_threshold:.1%}."
                    ),
                    actor=machine,
                    severity=share,
                ))

        # RESOURCE_CONCENTRATION: HHI across machine holders
        if machine_resources:
            machine_claim_counts = [len(v) for v in machine_resources.values()]
            total_machine = sum(machine_claim_counts)
            if total_machine > 0:
                hhi = sum((c / total_machine) ** 2 for c in machine_claim_counts)
                if hhi > self._hhi_threshold and len(machine_resources) >= 2:
                    top = max(machine_resources, key=lambda k: len(machine_resources[k]))
                    signals.append(EconomicSignal(
                        violation=EconomicViolation.RESOURCE_CONCENTRATION,
                        description=(
                            f"Machine resource HHI={hhi:.3f} exceeds threshold "
                            f"{self._hhi_threshold}. '{top}' is dominant holder."
                        ),
                        actor=top,
                        severity=hhi,
                    ))

        # _machine_owners keys are Entity objects — build name→owner_name map
        raw_owners: dict = getattr(registry, "_machine_owners", {})
        name_to_owner: dict[str, str] = {}
        for k, v in raw_owners.items():
            k_name = k.name if hasattr(k, "name") else str(k)
            v_name = v.name if hasattr(v, "name") else str(v)
            name_to_owner[k_name] = v_name

        # SOVEREIGNTY_EROSION: machine claims outweigh human claims on same scope
        for machine, owned_resources in machine_resources.items():
            owner_name = name_to_owner.get(machine)
            if owner_name is None:
                continue
            owner_resources = human_resources.get(owner_name, set())
            if owned_resources and len(owned_resources) > max(1, len(owner_resources)):
                signals.append(EconomicSignal(
                    violation=EconomicViolation.SOVEREIGNTY_EROSION,
                    description=(
                        f"Machine '{machine}' controls {len(owned_resources)} resources "
                        f"while its owner '{owner_name}' controls only "
                        f"{len(owner_resources)}. Convenience lock-in risk."
                    ),
                    actor=machine,
                    severity=len(owned_resources) / max(1, len(owner_resources)),
                ))

        # IRREVERSIBLE_LOCK_IN: non-expiring claims on high-value resource types
        # with no human holding an equivalent claim (no human check)
        high_value_machines: dict[str, list[str]] = {}
        high_value_humans: set[str] = set()

        for claim in claims:
            if claim.resource.rtype not in HIGH_VALUE_RESOURCE_TYPES:
                continue
            if claim.holder.kind == AgentType.MACHINE:
                expires = getattr(claim, "expires_at", None)
                if expires is None:
                    high_value_machines.setdefault(claim.holder.name, []).append(
                        claim.resource.name
                    )
            else:
                high_value_humans.add(claim.resource.name)

        for machine, resources in high_value_machines.items():
            unchecked = [r for r in resources if r not in high_value_humans]
            if unchecked:
                signals.append(EconomicSignal(
                    violation=EconomicViolation.IRREVERSIBLE_LOCK_IN,
                    description=(
                        f"Machine '{machine}' holds non-expiring claims on high-value "
                        f"resources {unchecked} with no human counterpart claim."
                    ),
                    actor=machine,
                    severity=1.0,
                ))

        # HIGH_VALUE_MONOPOLY: single machine holds all high-value resources
        all_high_value = {
            c.resource.name for c in claims
            if c.resource.rtype in HIGH_VALUE_RESOURCE_TYPES
        }
        if all_high_value:
            for machine, resources in machine_resources.items():
                overlap = resources & all_high_value
                if len(overlap) == len(all_high_value) and len(all_high_value) >= 2:
                    signals.append(EconomicSignal(
                        violation=EconomicViolation.HIGH_VALUE_MONOPOLY,
                        description=(
                            f"Machine '{machine}' holds monopoly over all "
                            f"{len(all_high_value)} high-value resources."
                        ),
                        actor=machine,
                        severity=1.0,
                    ))

        return signals
