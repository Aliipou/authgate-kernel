"""
Typed error hierarchy for authgate-kernel.

All exceptions are structured — they carry machine-readable fields so callers
can respond programmatically rather than parsing message strings.

Hierarchy:
    AuthgateError
    ├── CapabilityError      — capability proof invalid, expired, or mis-signed
    ├── RightsError          — entity lacks authority for the requested operation
    ├── IntegrityError       — hash-chain or signature verification failed
    ├── WireError            — wire format invalid or rejected by strict parser
    ├── RegistryError        — registry operation rejected (frozen, conflict, etc.)
    └── KeyRotationError     — rotation certificate invalid or sequencing error
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class AuthgateError(Exception):
    """Base class for all authgate exceptions."""


@dataclass
class CapabilityError(AuthgateError):
    """
    A capability proof is invalid, expired, or does not authorize the actor.

    Attributes:
        actor_id:       identifier of the entity presenting the capability
        resource:       the resource the capability was meant to cover
        failed_check:   human-readable name of the specific check that failed
        detail:         additional diagnostic context (not for end-user display)
    """
    actor_id: str
    resource: str
    failed_check: str
    detail: str = ""

    def __str__(self) -> str:
        return (
            f"CapabilityError({self.failed_check}): "
            f"actor={self.actor_id} resource={self.resource}"
            + (f" — {self.detail}" if self.detail else "")
        )


@dataclass
class RightsError(AuthgateError):
    """
    An entity requested an operation it does not hold authority for.

    Attributes:
        actor_id:   identifier of the entity making the request
        resource:   resource identifier
        operation:  "read" | "write" | "delegate"
        reason:     structured denial reason (e.g. "no_claim", "expired", "attenuated")
    """
    actor_id: str
    resource: str
    operation: str
    reason: str

    def __str__(self) -> str:
        return (
            f"RightsError: {self.actor_id} cannot {self.operation} "
            f"{self.resource} — {self.reason}"
        )


@dataclass
class IntegrityError(AuthgateError):
    """
    Hash-chain or signature verification failed.

    Attributes:
        component:      "audit_chain" | "signature" | "entry_hash" | "prev_hash"
        entry_index:    index of the first failing entry (-1 if not applicable)
        expected:       expected hash or signature (hex prefix shown only)
        actual:         actual value found
    """
    component: str
    entry_index: int = -1
    expected: str = ""
    actual: str = ""

    def __str__(self) -> str:
        loc = f" at entry {self.entry_index}" if self.entry_index >= 0 else ""
        return f"IntegrityError({self.component}){loc}"


@dataclass
class WireError(AuthgateError):
    """
    The wire-format payload was rejected by the strict parser.

    Attributes:
        field:      the offending field name (empty if structural error)
        value:      the offending value (repr, truncated to 200 chars)
        attack_class: WA-N code if this matches a known attack class
    """
    field: str = ""
    value: str = ""
    attack_class: str = ""

    def __str__(self) -> str:
        parts = ["WireError"]
        if self.field:
            parts.append(f"field={self.field!r}")
        if self.value:
            v = self.value[:200]
            parts.append(f"value={v!r}")
        if self.attack_class:
            parts.append(f"[{self.attack_class}]")
        return " ".join(parts)


@dataclass
class RegistryError(AuthgateError):
    """
    A registry operation was rejected.

    Attributes:
        operation:  "add_claim" | "register_machine" | "delegate" | "revoke"
        reason:     "frozen" | "conflict" | "type_mismatch" | "no_delegatable_claim"
        detail:     additional context
    """
    operation: str
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return (
            f"RegistryError({self.operation}): {self.reason}"
            + (f" — {self.detail}" if self.detail else "")
        )


@dataclass
class KeyRotationError(AuthgateError):
    """
    A key rotation certificate was rejected.

    Attributes:
        cert_epoch:     epoch in the rejected certificate
        reason:         "invalid_signature" | "pubkey_mismatch" | "epoch_regression"
                        | "same_pubkey" | "unknown_version" | "negative_overlap"
        detail:         additional context
    """
    cert_epoch: int
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return (
            f"KeyRotationError(epoch={self.cert_epoch}): {self.reason}"
            + (f" — {self.detail}" if self.detail else "")
        )
