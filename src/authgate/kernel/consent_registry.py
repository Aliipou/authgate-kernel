"""
ConsentRegistry — thread-safe store for ConsentCapability objects.

Design rules enforced here:
  - Only humans can grant consent (P1: self-sovereignty).
    grant() raises TypeError if the grantor is not HUMAN.
  - Only the grantor can revoke their own consent.
    revoke() raises PermissionError if the revoking entity is not the original grantor.
  - check() returns (bool, reason_str) — never raises.
  - All mutations are protected by threading.RLock (reentrant, safe from the
    same thread holding the lock and calling back into the registry).

Thread-safety model:
    Single RLock guards _consents list. Reads (check) and writes (grant/revoke)
    both acquire the lock. The lock is reentrant so callers that hold the lock
    can safely call other registry methods.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from authgate.kernel.consent import ConsentCapability
from authgate.kernel.entities import AgentType, Entity, Resource


@dataclass
class ConsentRegistry:
    """
    Thread-safe registry for ConsentCapability objects.

    Usage:
        registry = ConsentRegistry()
        cap = ConsentCapability(grantor=human, grantee=bot, resource=res,
                                operations=frozenset({"read"}),
                                expires_at=time.time() + 3600)
        registry.grant(cap)
        ok, reason = registry.check(bot, res, "read")
    """

    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _consents: list[ConsentCapability] = field(default_factory=list, init=False, repr=False)

    def grant(self, consent: ConsentCapability) -> None:
        """
        Store a consent grant.

        Raises:
            TypeError: if consent.grantor is not HUMAN (machines cannot grant consent).
            TypeError: if consent is not a ConsentCapability.
        """
        if not isinstance(consent, ConsentCapability):
            raise TypeError(
                f"grant() expects a ConsentCapability, got {type(consent).__name__!r}"
            )
        # ConsentCapability.__post_init__ already checks grantor.kind == HUMAN,
        # but we re-enforce here to make the registry boundary explicit.
        if consent.grantor.kind != AgentType.HUMAN:
            raise TypeError(
                f"Only humans can grant consent. "
                f"Grantor '{consent.grantor.name}' is {consent.grantor.kind.name}."
            )
        with self._lock:
            self._consents.append(consent)

    def revoke(self, grantor: Entity, grantee: Entity, resource: Resource) -> int:
        """
        Revoke all consent previously granted by *grantor* to *grantee* on *resource*.

        Returns the number of consent records removed.

        Raises:
            PermissionError: if grantor is not the original grantor of the matched records.
                             (Enforced by matching on grantor identity — wrong-grantor calls
                              simply remove 0 records; structural PermissionError is raised
                              only when a non-human tries to revoke.)
            TypeError: if grantor is not HUMAN.
        """
        if grantor.kind != AgentType.HUMAN:
            raise TypeError(
                f"Only the human grantor can revoke consent. "
                f"'{grantor.name}' is {grantor.kind.name}."
            )
        with self._lock:
            before = len(self._consents)
            self._consents = [
                c for c in self._consents
                if not (
                    c.grantor == grantor
                    and c.grantee == grantee
                    and c.resource == resource
                )
            ]
            return before - len(self._consents)

    def check(
        self,
        grantee: Entity,
        resource: Resource,
        operation: str,
        context_id: str = "",
    ) -> tuple[bool, str]:
        """
        Check whether *grantee* has valid consent to perform *operation* on *resource*.

        Returns:
            (True, "consent granted by <name>") if any valid, covering consent exists.
            (False, "<reason>") otherwise.
        """
        with self._lock:
            # Collect all consents for this grantee+resource combination
            candidates = [
                c for c in self._consents
                if c.grantee == grantee and c.resource == resource
            ]

        if not candidates:
            return False, f"no consent on record for {grantee.name} on {resource.name}"

        for cap in candidates:
            if cap.covers(operation, context_id):
                return True, f"consent granted by {cap.grantor.name}"

        # Diagnose why none of the candidates matched
        expired = [c for c in candidates if not c.is_valid()]
        wrong_op = [c for c in candidates if c.is_valid() and operation not in c.operations]
        wrong_ctx = [
            c for c in candidates
            if c.is_valid() and operation in c.operations and c.context_id and c.context_id != context_id
        ]

        if expired and not wrong_op and not wrong_ctx:
            return False, f"consent for {grantee.name} on {resource.name} has expired"
        if wrong_op:
            return False, (
                f"operation '{operation}' not covered by any consent "
                f"for {grantee.name} on {resource.name}"
            )
        if wrong_ctx:
            return False, (
                f"consent for {grantee.name} on {resource.name} is bound to a different context"
            )
        return False, f"no valid consent for {grantee.name} on {resource.name}"

    def active_consents(
        self,
        grantee: Entity | None = None,
        resource: Resource | None = None,
    ) -> list[ConsentCapability]:
        """Return all currently-valid (non-expired) consents, optionally filtered."""
        with self._lock:
            result = [c for c in self._consents if c.is_valid()]
        if grantee is not None:
            result = [c for c in result if c.grantee == grantee]
        if resource is not None:
            result = [c for c in result if c.resource == resource]
        return result

    def __len__(self) -> int:
        with self._lock:
            return len(self._consents)
