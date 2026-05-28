"""
ConsentCapability — Phase 2 seed: consent algebra for human-directed actions.

Extends the base capability model with explicit consent semantics. A ConsentCapability
wraps a RightsClaim and adds:
  - consent_required: bool — this action requires active consent from a human principal
  - consent_given_by: Entity | None — the human who gave consent
  - consent_expires_at: float | None — consent expiry (separate from claim expiry)
  - consent_scope: str — the specific scope for which consent was given

Design constraints:
  - ConsentCapability is NOT TCB — it is an extension layer
  - A ConsentCapability with consent_required=True and no consent_given_by is invalid
  - The kernel gate (FreedomVerifier) does NOT check consent — this is checked by
    ConsentVerifier, which runs AFTER the kernel gate
  - Consent is always from a HUMAN — machine consent is not a valid concept here

Formal rule (Phase 2):
  ConsentValid(cap) iff:
    ¬cap.consent_required
    ∨ (cap.consent_required
       ∧ cap.consent_given_by ≠ None
       ∧ cap.consent_given_by.is_human()
       ∧ (cap.consent_expires_at = None ∨ now < cap.consent_expires_at)
       ∧ scope_contains(cap.consent_scope, cap.claim.resource.scope))
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from authgate.kernel.entities import Entity, scope_contains
from authgate.kernel.verifier import Action, VerificationResult


@dataclass
class ConsentCapability:
    """
    A rights claim annotated with explicit human consent requirements.

    Use for actions that affect human principals directly — data about humans,
    actions on behalf of humans, or actions with irreversible personal effects.
    """
    claim: Any  # RightsClaim
    consent_required: bool = False
    consent_given_by: Entity | None = None
    consent_expires_at: float | None = None
    consent_scope: str = ""

    def is_consent_valid(self, now: float | None = None) -> bool:
        """Return True iff consent is present and valid."""
        if not self.consent_required:
            return True
        if self.consent_given_by is None:
            return False
        if not self.consent_given_by.is_human():
            return False
        ts = now if now is not None else time.time()
        if self.consent_expires_at is not None and ts >= self.consent_expires_at:
            return False
        if self.consent_scope:
            resource_scope = getattr(self.claim.resource, "scope", "")
            if not scope_contains(self.consent_scope, resource_scope):
                return False
        return True

    def consent_violation_reason(self, now: float | None = None) -> str | None:
        """Return a human-readable reason if consent is invalid, else None."""
        if not self.consent_required:
            return None
        if self.consent_given_by is None:
            return "consent_required but no human gave consent"
        if not self.consent_given_by.is_human():
            return f"consent_given_by {self.consent_given_by.name} is not a human"
        ts = now if now is not None else time.time()
        if self.consent_expires_at is not None and ts >= self.consent_expires_at:
            return "consent has expired"
        if self.consent_scope:
            resource_scope = getattr(self.claim.resource, "scope", "")
            if not scope_contains(self.consent_scope, resource_scope):
                return (
                    f"resource scope {resource_scope!r} not within "
                    f"consent scope {self.consent_scope!r}"
                )
        return None


@dataclass
class ConsentViolation:
    """Raised or returned when a consent check fails."""
    action_id: str
    resource: str
    reason: str

    def __str__(self) -> str:
        return f"ConsentViolation({self.action_id}): {self.reason} on {self.resource}"


@dataclass
class ConsentVerifier:
    """
    Checks consent validity for actions that require human consent.

    Runs AFTER the kernel gate (FreedomVerifier). The kernel gate is a
    necessary condition; consent is an orthogonal condition.

    Usage:
        result = kernel_verifier.verify(action)
        if not result.permitted:
            return result   # kernel denied — no need to check consent
        violations = consent_verifier.check(action, capabilities)
        if violations:
            block(action)
    """
    capabilities: list[ConsentCapability] = field(default_factory=list)

    def check(
        self,
        action: Action,
        now: float | None = None,
    ) -> list[ConsentViolation]:
        """
        Check consent validity for all resources in the action.

        Returns a list of ConsentViolation — empty means all consent is valid.
        """
        violations: list[ConsentViolation] = []
        ts = now if now is not None else time.time()

        all_resources = (
            list(action.resources_read)
            + list(action.resources_write)
            + list(action.resources_delegate)
        )

        for resource in all_resources:
            matching_caps = [
                cap for cap in self.capabilities
                if cap.claim.holder == action.actor
                and cap.claim.resource == resource
                and cap.consent_required
            ]
            for cap in matching_caps:
                reason = cap.consent_violation_reason(ts)
                if reason is not None:
                    violations.append(ConsentViolation(
                        action_id=action.action_id,
                        resource=str(resource),
                        reason=reason,
                    ))

        return violations

    def add_capability(self, cap: ConsentCapability) -> None:
        self.capabilities.append(cap)
