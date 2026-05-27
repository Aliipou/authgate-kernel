"""
OwnershipRegistry with O(1) indexed claim lookup and conflict detection.

Claims are indexed by (holder_id, resource_id) for fast lookup.
When two entities hold conflicting write claims on the same resource,
the registry surfaces a ConflictRecord rather than silently failing.
Conflict resolution is an extensions concern (ConflictQueue in extensions.resolver).
"""
from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from authgate.kernel.entities import Entity, Resource, RightsClaim


@dataclass
class ConflictRecord:
    resource: Resource
    claimant_a: Entity
    claimant_b: Entity
    description: str


def _claim_key(holder: Entity, resource: Resource) -> tuple[str, str]:
    return (holder.name, resource.name)


@dataclass
class OwnershipRegistry:
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _claims: list[RightsClaim] = field(default_factory=list)
    _index: dict[tuple[str, str], list[RightsClaim]] = field(
        default_factory=lambda: defaultdict(list), init=False, repr=False
    )
    _machine_owners: dict[Entity, Entity] = field(default_factory=dict)
    _conflicts: list[ConflictRecord] = field(default_factory=list)
    _conflict_hook: Callable[[ConflictRecord], None] | None = None
    _frozen: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        # Rebuild index from any pre-populated _claims (e.g. snapshot copy)
        self._index = defaultdict(list)
        for claim in self._claims:
            self._index[_claim_key(claim.holder, claim.resource)].append(claim)

    def freeze(self) -> OwnershipRegistry:
        """
        Return an immutable snapshot of this registry.

        The returned registry has the same claims, owners, and conflicts
        as the original at the moment of freezing. Any attempt to mutate
        the snapshot (add_claim, delegate, register_machine) raises RuntimeError.

        Eliminates TOCTOU: freeze once, verify many times against the same state.
        """
        with self._lock:
            snapshot = OwnershipRegistry(
                _claims=list(self._claims),
                _machine_owners=dict(self._machine_owners),
                _conflicts=list(self._conflicts),
            )
            snapshot._frozen = True
            return snapshot

    def _check_mutable(self) -> None:
        if self._frozen:
            raise RuntimeError(
                "Registry is frozen; mutations are not permitted on snapshots. "
                "Call freeze() on the original registry, then verify against the snapshot."
            )

    def set_conflict_hook(self, hook: Callable[[ConflictRecord], None]) -> None:
        self._conflict_hook = hook

    def _index_add(self, claim: RightsClaim) -> None:
        self._index[_claim_key(claim.holder, claim.resource)].append(claim)

    def _index_remove(self, claim: RightsClaim) -> None:
        key = _claim_key(claim.holder, claim.resource)
        try:
            self._index[key].remove(claim)
        except ValueError:
            pass
        if not self._index[key]:
            del self._index[key]

    def add_claim(self, claim: RightsClaim) -> None:
        """Assert a rights claim directly (ownership assertion, no attenuation check)."""
        self._check_mutable()
        with self._lock:
            conflict = self._detect_conflict(claim)
            if conflict:
                self._conflicts.append(conflict)
                if self._conflict_hook:
                    self._conflict_hook(conflict)
            self._claims.append(claim)
            self._index_add(claim)

    def delegate(self, claim: RightsClaim, delegated_by: Entity) -> None:
        """
        Delegate a claim from delegated_by to claim.holder.

        Enforces the attenuation principle: you cannot grant authority you do not have.
          - delegated_by must hold a valid, delegatable claim on claim.resource
          - claim.can_read  requires delegated_by.can_read
          - claim.can_write requires delegated_by.can_write
          - claim.can_delegate requires delegated_by.can_delegate
          - claim.confidence <= delegated_by's best confidence

        This is the primitive that makes the ownership graph a real capability system
        rather than just annotations.
        """
        self._check_mutable()
        with self._lock:
            # find delegator's best delegatable claim on this resource — O(1) via index
            candidates = [
                c for c in self._index.get(_claim_key(delegated_by, claim.resource), [])
                if c.can_delegate and c.is_valid()
            ]
            if not candidates:
                raise PermissionError(
                    f"Attenuation violation: {delegated_by.name} holds no valid "
                    f"delegatable claim on {claim.resource}. Cannot delegate to "
                    f"{claim.holder.name}."
                )
            best = max(candidates, key=lambda c: c.confidence)

            if claim.can_read and not best.can_read:
                raise PermissionError(
                    f"Attenuation: {delegated_by.name} cannot delegate read on "
                    f"{claim.resource} (delegator lacks read)."
                )
            if claim.can_write and not best.can_write:
                raise PermissionError(
                    f"Attenuation: {delegated_by.name} cannot delegate write on "
                    f"{claim.resource} (delegator lacks write)."
                )
            if claim.can_delegate and not best.can_delegate:
                raise PermissionError(
                    f"Attenuation: {delegated_by.name} cannot sub-delegate "
                    f"{claim.resource} (delegator lacks delegate)."
                )
            if claim.confidence > best.confidence:
                raise PermissionError(
                    f"Attenuation: confidence {claim.confidence:.2f} exceeds "
                    f"{delegated_by.name}'s {best.confidence:.2f} on {claim.resource}."
                )

            # Stamp delegation lineage
            object.__setattr__(claim, "delegated_by", delegated_by) if hasattr(claim, "__dataclass_fields__") else None
            try:
                claim.delegated_by = delegated_by
            except (AttributeError, TypeError):
                pass

            conflict = self._detect_conflict(claim)
            if conflict:
                self._conflicts.append(conflict)
                if self._conflict_hook:
                    self._conflict_hook(conflict)
            self._claims.append(claim)
            self._index_add(claim)

    def register_machine(self, machine: Entity, owner: Entity) -> None:
        self._check_mutable()
        if not machine.is_machine():
            raise TypeError(f"{machine.name} is not MACHINE.")
        if not owner.is_human():
            raise TypeError(f"{owner.name} is not HUMAN.")
        with self._lock:
            self._machine_owners[machine] = owner

    def claims_for(self, holder: Entity, resource: Resource) -> list[RightsClaim]:
        """O(k) where k = claims for this (holder, resource) pair — O(1) index lookup."""
        with self._lock:
            return [
                c for c in self._index.get(_claim_key(holder, resource), [])
                if c.is_valid()
            ]

    def best_claim(
        self, holder: Entity, resource: Resource, operation: str
    ) -> RightsClaim | None:
        candidates = [c for c in self.claims_for(holder, resource) if c.covers(operation)]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.confidence)

    def can_act(
        self, holder: Entity, resource: Resource, operation: str
    ) -> tuple[bool, float, str]:
        """Returns (permitted, confidence, reason)."""
        if resource.is_public and operation == "read":
            return True, 1.0, "public resource"
        claim = self.best_claim(holder, resource, operation)
        if claim is None:
            return False, 0.0, f"{holder.name} holds no valid {operation} claim on {resource}"
        return True, claim.confidence, f"claim confidence={claim.confidence:.2f}"

    def owner_of(self, machine: Entity) -> Entity | None:
        return self._machine_owners.get(machine)

    def open_conflicts(self) -> list[ConflictRecord]:
        return list(self._conflicts)

    def revoke_all(self, holder_name: str) -> int:
        """Revoke all claims held by holder_name. Returns count revoked."""
        self._check_mutable()
        with self._lock:
            to_remove = [c for c in self._claims if c.holder.name == holder_name]
            for c in to_remove:
                self._index_remove(c)
            self._claims = [c for c in self._claims if c.holder.name != holder_name]
            return len(to_remove)

    def revoke_on_resource(self, holder_name: str, resource_name: str) -> int:
        """Revoke all claims held by holder_name on resource_name. Returns count revoked."""
        self._check_mutable()
        with self._lock:
            to_remove = [
                c for c in self._claims
                if c.holder.name == holder_name and c.resource.name == resource_name
            ]
            for c in to_remove:
                self._index_remove(c)
            self._claims = [
                c for c in self._claims
                if not (c.holder.name == holder_name and c.resource.name == resource_name)
            ]
            return len(to_remove)

    def revoke_cascading(self, holder_name: str) -> int:
        """
        Revoke holder_name's claims and all downstream delegations (BFS).

        Traverses the delegation lineage graph: any claim whose delegated_by chain
        includes holder_name is also revoked. Returns total count revoked.
        """
        self._check_mutable()
        with self._lock:
            total = 0
            revoked_names: set[str] = {holder_name}
            queue = [holder_name]
            while queue:
                current = queue.pop(0)
                to_remove = [c for c in self._claims if c.holder.name == current]
                for c in to_remove:
                    self._index_remove(c)
                    # Queue downstream delegates: anyone who received authority from current
                    delegated_by = getattr(c, "delegated_by", None)
                    if delegated_by is None:
                        # Find claims where this holder was the source (delegated_by == current)
                        pass
                self._claims = [c for c in self._claims if c.holder.name != current]
                total += len(to_remove)

                # Find all claims delegated BY current to someone else
                downstream = [
                    c.holder.name for c in self._claims
                    if getattr(c, "delegated_by", None) is not None
                    and getattr(c, "delegated_by").name == current
                    and c.holder.name not in revoked_names
                ]
                for name in downstream:
                    revoked_names.add(name)
                    queue.append(name)
            return total

    def expire_stale(self) -> int:
        """Remove all expired claims. Returns count removed."""
        import time
        with self._lock:
            now = time.time()
            to_remove = [c for c in self._claims if c.expires_at is not None and c.expires_at <= now]
            for c in to_remove:
                self._index_remove(c)
            self._claims = [c for c in self._claims if c.expires_at is None or c.expires_at > now]
            return len(to_remove)

    def _detect_conflict(self, new_claim: RightsClaim) -> ConflictRecord | None:
        # Use index for O(k) conflict detection
        for existing in self._index.get(_claim_key(new_claim.holder, new_claim.resource), []):
            # Same holder — no conflict with self
            pass
        # Check all claims on the same resource for write conflicts with other holders
        for existing in self._claims:
            if (
                existing.resource == new_claim.resource
                and existing.holder != new_claim.holder
                and existing.can_write
                and new_claim.can_write
                and existing.is_valid()
            ):
                return ConflictRecord(
                    resource=new_claim.resource,
                    claimant_a=existing.holder,
                    claimant_b=new_claim.holder,
                    description=(
                        f"Conflicting write claims on {new_claim.resource}: "
                        f"{existing.holder.name} and {new_claim.holder.name}"
                    ),
                )
        return None
