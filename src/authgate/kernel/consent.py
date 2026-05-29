"""
Consent Algebra — Phase 2, O1: explicit, bounded human consent as a first-class object.

Two layers of consent modelling live here:

Layer 1 (ConsentAnnotation, legacy seed):
  ConsentAnnotation wraps a RightsClaim with explicit human-consent metadata.
  Used by ConsentVerifier for annotation-based consent checking.

Layer 2 (ConsentCapability, Phase 2 canonical):
  ConsentCapability IS the consent — it is not a wrapper around a RightsClaim.
  It models an explicit, bounded agreement from a human principal to a machine
  grantee for a specific set of operations, scoped to a context, with mandatory
  expiry and inalienable human override.

Design principles encoded here:
  P1  — self-sovereignty: only humans can grant consent (grantor must be HUMAN)
  P3  — non-transferability: is_delegable=False by default; inalienable rights
        cannot be re-delegated even if the underlying RightsClaim permits it
  P4  — structural freedom / exit right: human_override_valid is always True;
        it cannot be set False at construction or any time thereafter

Formal rules:
  ConsentValid(cap) iff:
    cap.is_valid()                          # time.time() < cap.expires_at
    ∧ operation ∈ cap.operations            # partial consent check
    ∧ (cap.context_id = "" ∨ ctx = cap.context_id)   # contextual binding

  DelegationAllowed(cap) iff:
    cap.is_delegable ∧ cap.is_valid()

  HumanOverrideAlways(cap) iff:
    cap.human_override_valid = True         # inalienable — enforced in __post_init__
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from authgate.kernel.entities import AgentType, Entity, Resource, scope_contains
from authgate.kernel.verifier import Action, VerificationResult


# ---------------------------------------------------------------------------
# Layer 2 — Phase 2 canonical consent model
# ---------------------------------------------------------------------------

class ConsentScope(Enum):
    """Temporal/spatial scope of a consent grant."""
    GLOBAL = "global"       # applies everywhere, all sessions
    SESSION = "session"     # one conversation / session
    EPHEMERAL = "ephemeral" # single request only


@dataclass(frozen=True)
class ConsentCapability:
    """
    Consent is not a permission bit — it is an explicit, bounded agreement.

    Distinct from RightsClaim (which handles authority): ConsentCapability
    handles the principal's agreement to a specific use of authority.
    The grantor is always a human; the grantee is always a machine.

    Invariants enforced at construction (frozen dataclass, __post_init__):
      - grantor.kind == HUMAN           (P1: self-sovereignty)
      - expires_at > time.time()        (mandatory, finite expiry)
      - operations non-empty            (partial consent, not binary)
      - human_override_valid == True    (P4: inalienable exit right)
    """
    grantor: Entity           # who gave consent — MUST be human
    grantee: Entity           # who received consent — typically machine
    resource: Resource
    operations: frozenset     # e.g. frozenset({"read", "summarize"})
    expires_at: float         # MANDATORY — no permanent consent

    scope: ConsentScope = ConsentScope.SESSION
    context_id: str = ""        # bound to specific session/request if non-empty
    is_delegable: bool = False  # explicitly non-delegable by default (P3)
    human_override_valid: bool = True  # inalienable — cannot be set False (P4)

    def __post_init__(self) -> None:
        # P1: only humans can be grantors
        if not isinstance(self.grantor, Entity):
            raise TypeError(
                f"grantor must be an Entity, got {type(self.grantor).__name__!r}"
            )
        if self.grantor.kind != AgentType.HUMAN:
            raise TypeError(
                f"ConsentCapability.grantor must be HUMAN, got {self.grantor.kind.name}. "
                "Machines cannot grant consent on behalf of humans."
            )

        # Mandatory expiry — no permanent consent
        if self.expires_at is None:
            raise ValueError(
                "ConsentCapability.expires_at is mandatory — consent must have a finite lifetime."
            )
        if time.time() >= self.expires_at:
            raise ValueError(
                f"ConsentCapability.expires_at must be in the future "
                f"(got {self.expires_at:.3f}, now={time.time():.3f})."
            )

        # Partial consent: operations must be non-empty
        if not self.operations:
            raise ValueError(
                "ConsentCapability.operations must be non-empty — "
                "consent must cover at least one operation."
            )

        # P4: human override is inalienable — cannot be disabled
        if not self.human_override_valid:
            raise ValueError(
                "ConsentCapability.human_override_valid must be True — "
                "the human right to override/revoke consent is inalienable (P4)."
            )

    def is_valid(self) -> bool:
        """Return True iff consent has not yet expired."""
        return time.time() < self.expires_at

    def covers(self, operation: str, context_id: str = "") -> bool:
        """
        Return True iff this consent covers *operation* in the given context.

        Checks (in order):
          1. Consent has not expired
          2. operation is in the declared operations set
          3. If context_id is bound on this capability, the caller's context matches
        """
        if not self.is_valid():
            return False
        if operation not in self.operations:
            return False
        if self.context_id and context_id != self.context_id:
            return False  # contextual consent: caller is in the wrong context
        return True

    def can_be_delegated(self) -> bool:
        """Return True iff this consent can be re-delegated to another grantee."""
        return self.is_delegable and self.is_valid()


# ---------------------------------------------------------------------------
# Layer 1 — legacy ConsentAnnotation (was ConsentCapability in seed code)
# ---------------------------------------------------------------------------

@dataclass
class ConsentAnnotation:
    """
    A rights claim annotated with explicit human consent requirements.

    Use for actions that affect human principals directly — data about humans,
    actions on behalf of humans, or actions with irreversible personal effects.

    .. deprecated::
        Prefer ConsentCapability (Phase 2) for new code. ConsentAnnotation
        exists for backward compatibility with ConsentVerifier callers.
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
    capabilities: list[ConsentAnnotation] = field(default_factory=list)

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

    def add_capability(self, cap: ConsentAnnotation) -> None:
        self.capabilities.append(cap)
