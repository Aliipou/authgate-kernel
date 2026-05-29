"""
Anti-Capture Detection — Phase 4, O2.

From ultimate-plan.md P4/O2 — Anti-Capture Systems:
  Capture occurs when a machine agent's effective behavior is controlled by
  an external principal other than its registered human owner — through:
  - Prompt injection (external input overrides principal intent)
  - Credential substitution (machine uses credentials not granted by its owner)
  - Coalition capture (other machines in a coalition direct the agent's actions)
  - Goal drift (machine's requested resources diverge from its registered scope)

  These are structural signals — not intent detection. The checker looks for
  patterns that are structurally inconsistent with legitimate ownership.

Capture patterns:
  SCOPE_DRIFT         — machine requests resources far outside its registered claims
  CREDENTIAL_ACCESS   — machine accesses CREDENTIAL resources not granted by owner
  COALITION_DIRECTION — machine shares all resources with another machine's owner
  OWNER_MISMATCH      — machine acts on behalf of a human who is not its owner
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class CapturePattern(Enum):
    SCOPE_DRIFT         = auto()  # accessing resources outside registered scope
    CREDENTIAL_ACCESS   = auto()  # credential access not from owner chain
    OWNER_MISMATCH      = auto()  # action governs humans other than registered owner
    RESOURCE_TYPE_DRIFT = auto()  # accessing resource types not in any registered claim


@dataclass(frozen=True)
class CaptureSignal:
    """A detected capture signal for a specific machine action."""
    machine_name: str
    pattern: CapturePattern
    severity: str       # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    action_id: str

    def is_high_risk(self) -> bool:
        return self.severity in ("HIGH", "CRITICAL")


class AntiCaptureChecker:
    """
    Analyzes actions for structural capture signals.

    A capture signal means the machine is behaving in a way inconsistent with
    its registered ownership and granted claims — a structural red flag even
    if the individual action passes the sovereignty flags.

    Usage:
        checker = AntiCaptureChecker()
        signals = checker.check(action, registry)
        for signal in signals:
            if signal.is_high_risk():
                block(action)
    """

    def check(self, action: Any, registry: Any) -> list[CaptureSignal]:
        """
        Check an action for capture signals.

        action:   verifier.Action
        registry: OwnershipRegistry (live or frozen)
        """
        actor = getattr(action, "actor", None)
        if actor is None or not actor.is_machine():
            return []  # only machine actors can be captured

        signals: list[CaptureSignal] = []
        signals.extend(self._check_scope_drift(action, actor, registry))
        signals.extend(self._check_credential_access(action, actor, registry))
        signals.extend(self._check_owner_mismatch(action, actor, registry))
        signals.extend(self._check_resource_type_drift(action, actor, registry))
        return signals

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_scope_drift(self, action, actor, registry) -> list[CaptureSignal]:
        """
        SCOPE_DRIFT: machine requests resources in scopes not covered by any of its claims.
        """
        from authgate.kernel.entities import scope_contains
        all_claims = list(getattr(registry, "_claims", []))
        actor_claims = [c for c in all_claims if c.holder == actor]

        if not actor_claims:
            return []  # no claims at all — covered by other checks

        actor_scopes = [c.resource.scope for c in actor_claims]
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
        )

        drift_resources = []
        for res in all_resources:
            covered = any(
                scope_contains(cscope, res.scope)
                for cscope in actor_scopes
            )
            if not covered:
                drift_resources.append(res)

        if drift_resources:
            names = [r.name for r in drift_resources]
            return [CaptureSignal(
                machine_name=actor.name,
                pattern=CapturePattern.SCOPE_DRIFT,
                severity="HIGH",
                action_id=action.action_id,
                description=(
                    f"Machine '{actor.name}' requests resources {names} in scopes "
                    "outside all its registered claims. Possible scope capture — "
                    "machine is acting beyond its granted authority boundary."
                ),
            )]
        return []

    def _check_credential_access(self, action, actor, registry) -> list[CaptureSignal]:
        """
        CREDENTIAL_ACCESS: machine is reading/writing CREDENTIAL resources not
        explicitly granted by its registered owner's claims.
        """
        from authgate.kernel.entities import ResourceType
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
        )
        credential_resources = [
            r for r in all_resources
            if r.rtype in (ResourceType.CREDENTIAL, ResourceType.IDENTITY)
        ]
        if not credential_resources:
            return []

        all_claims = list(getattr(registry, "_claims", []))
        actor_claims = [c for c in all_claims if c.holder == actor]
        granted_cred_names = {
            c.resource.name for c in actor_claims
            if c.resource.rtype in (ResourceType.CREDENTIAL, ResourceType.IDENTITY)
        }

        ungranted = [r for r in credential_resources if r.name not in granted_cred_names]
        if ungranted:
            names = [r.name for r in ungranted]
            return [CaptureSignal(
                machine_name=actor.name,
                pattern=CapturePattern.CREDENTIAL_ACCESS,
                severity="CRITICAL",
                action_id=action.action_id,
                description=(
                    f"Machine '{actor.name}' accesses credential/identity resources "
                    f"{names} not present in its registered claims. Critical capture "
                    "signal — machine may be operating under external control."
                ),
            )]
        return []

    def _check_owner_mismatch(self, action, actor, registry) -> list[CaptureSignal]:
        """
        OWNER_MISMATCH: machine action governs_humans that do not include its registered owner.
        """
        from authgate.kernel.entities import AgentType
        governs = list(getattr(action, "governs_humans", []))
        if not governs:
            return []

        machines_map = dict(getattr(registry, "_machine_owners", {}))
        registered_owner = machines_map.get(actor)
        if registered_owner is None:
            return []

        owner_names = {registered_owner.name}
        governed_names = {h.name for h in governs if h.kind == AgentType.HUMAN}
        unregistered = governed_names - owner_names
        if unregistered:
            return [CaptureSignal(
                machine_name=actor.name,
                pattern=CapturePattern.OWNER_MISMATCH,
                severity="CRITICAL",
                action_id=action.action_id,
                description=(
                    f"Machine '{actor.name}' governs humans {sorted(unregistered)} who "
                    "are not its registered owner. This is a structural ownership mismatch "
                    "— machine is being directed to act against unrelated principals."
                ),
            )]
        return []

    def _check_resource_type_drift(self, action, actor, registry) -> list[CaptureSignal]:
        """
        RESOURCE_TYPE_DRIFT: machine requests resource types it has never been granted.
        Accessing a new resource TYPE (not just new name) is a structural anomaly.
        """
        all_claims = list(getattr(registry, "_claims", []))
        actor_claims = [c for c in all_claims if c.holder == actor]
        if not actor_claims:
            return []

        granted_rtypes = {c.resource.rtype for c in actor_claims}
        all_resources = (
            list(getattr(action, "resources_read", []))
            + list(getattr(action, "resources_write", []))
        )
        new_types = {r.rtype for r in all_resources if r.rtype not in granted_rtypes}
        if new_types:
            type_names = [t.value for t in new_types]
            return [CaptureSignal(
                machine_name=actor.name,
                pattern=CapturePattern.RESOURCE_TYPE_DRIFT,
                severity="MEDIUM",
                action_id=action.action_id,
                description=(
                    f"Machine '{actor.name}' accesses resource types {type_names} "
                    "not present in any registered claim. Type drift may indicate "
                    "the machine is being directed outside its operational domain."
                ),
            )]
        return []


# ── Convenience ───────────────────────────────────────────────────────────────

_DEFAULT_CHECKER = AntiCaptureChecker()


def check_capture(action: Any, registry: Any) -> list[CaptureSignal]:
    """Check an action for structural capture signals."""
    return _DEFAULT_CHECKER.check(action, registry)
