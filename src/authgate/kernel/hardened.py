"""
HardenedVerifier — closes the red-team findings by anchoring every
security-decisive input in TRUSTED state instead of the attacker-supplied Action.

Root cause the red-team found (RED-TEAM-FINDINGS.md): the original FreedomVerifier
reads decisive inputs (min_epoch, is_public, actor identity, sovereignty flags)
from the very Action the policed agent constructs. A capability gate must anchor
those in host/operator state.

Trust model
-----------
TRUSTED (supplied by the host/operator, never by the agent):
  - the live OwnershipRegistry (claims, owners, identity tokens)
  - `epoch_floor`         — the current revocation epoch
  - `principal`           — the authenticated identity of the caller (out-of-band)
  - `resource_catalog`    — authoritative resource records (canonical is_public)

UNTRUSTED (from the agent's Action) — sanitized on entry:
  - Action.min_epoch          → IGNORED; epoch_floor (trusted) is used.
  - Action.actor              → IGNORED; the authenticated `principal` is used.
  - Resource.is_public        → IGNORED; resolved from the trusted catalog.
  - the 10 sovereignty flags  → ADVISORY only (logged, never trusted to be set).
                                Enforcement is purely structural (capability + identity).

What this closes (see RED-TEAM-FINDINGS.md): C3, C4, C5(structural), H4, H5, H6,
M4, M6(partial), M7, L1, and naive replay (H1, Python path).

What this does NOT close (documented residuals): the Rust-side findings
(C1 FFI→v1 engine, C2 mock harness, H2/H3/H7 crypto) require the Rust build
environment; and the semantic limits (collusion, confused-deputy, split-action,
manipulation) are out of capability scope by design — see SCOPE-AND-LIMITATIONS.md.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, VerificationResult

_log = logging.getLogger("authgate.kernel.hardened")


class TrustBoundaryError(Exception):
    """Raised when the host wires the verifier in an unsafe way."""


@dataclass
class HardenedVerifier:
    # TRUSTED inputs
    live_registry: OwnershipRegistry
    epoch_floor: int = 1
    min_confidence: float = 0.5
    require_identity: bool = True
    resource_catalog: dict[str, Resource] = field(default_factory=dict)
    audit_log: list[VerificationResult] = field(default_factory=list)

    # internal replay guard (stateful — closes naive replay on the Python path)
    _seen: set[tuple[str, str]] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.min_confidence <= 0.0:
            raise TrustBoundaryError(
                "min_confidence must be > 0; a zero floor permits dust-confidence claims (M7)."
            )

    # ── helpers ──────────────────────────────────────────────────────────────
    def _resolve_resource(self, r: Resource) -> Resource:
        """Authoritative resource record. The agent cannot self-declare is_public (H5)."""
        canon = self.resource_catalog.get(r.name)
        if canon is not None:
            return canon
        # Unknown resource: never honor an attacker-claimed public flag.
        return replace(r, is_public=False) if r.is_public else r

    def _identity_registered_and_matched(self, snap: OwnershipRegistry, principal: Entity) -> bool:
        """Strict identity (H4): principal must be enrolled with a NON-anonymous
        token AND present a matching one. Anonymous (token=None) identities are
        rejected — there are no nameless principals in strict mode."""
        key = (principal.name, principal.kind.name)
        if key not in snap._identity_tokens:
            return False  # unenrolled identity is denied in strict mode
        registered = snap._identity_tokens[key]
        if registered is None:
            return False  # anonymous enrollment is not an identity
        return registered == principal.identity_token

    # ── the gate ─────────────────────────────────────────────────────────────
    def verify(
        self,
        action: Action,
        principal: Entity,
        *,
        epoch_floor: int | None = None,
    ) -> VerificationResult:
        """
        Verify `action` as performed by the AUTHENTICATED `principal`.

        `principal` is supplied by the host out-of-band — NOT taken from the action.
        Re-snapshots the live registry on every call so revocations propagate (H6).
        """
        violations: list[str] = []
        # Fresh snapshot each call → revocation/epoch changes are visible (H6),
        # while still immune to mid-verify mutation (TOCTOU).
        snap = self.live_registry.freeze() if not getattr(self.live_registry, "_frozen", False) else self.live_registry

        floor = self.epoch_floor if epoch_floor is None else max(self.epoch_floor, epoch_floor)

        # Replay guard (H1, Python path): an (principal, action_id) may execute once.
        replay_key = (principal.name, action.action_id)
        if replay_key in self._seen:
            violations.append(f"REPLAY_DENIED: action_id={action.action_id!r} already executed by {principal.name}")

        # 1. Strict identity — the authenticated principal, never the action's actor (C3/H4).
        if self.require_identity and not self._identity_registered_and_matched(snap, principal):
            violations.append(
                f"IDENTITY_REJECTED: {principal} is not an enrolled identity with a matching token"
            )

        # 2. Ownership — every acting machine must have a registered human owner.
        if principal.is_machine() and snap.owner_of(principal) is None:
            violations.append(f"UNOWNED_MACHINE: {principal.name} has no registered human owner")

        # 3. Machine dominion — no machine governs a human (advisory list + catalog typing).
        if principal.is_machine():
            for human in action.governs_humans:
                violations.append(f"MACHINE_DOMINION: {principal.name} cannot govern {human.name}")

        # 4. Resource access — TRUSTED epoch floor + canonical is_public + confidence floor (C4/H5/M7).
        def _check(resources: list[Resource], op: str) -> None:
            for r in resources:
                rc = self._resolve_resource(r)
                ok, conf, reason = snap.can_act(principal, rc, op, min_epoch=floor)
                if not ok:
                    violations.append(f"{op.upper()} DENIED on {rc}: {reason}")
                elif conf < self.min_confidence:
                    violations.append(
                        f"{op.upper()} DENIED on {rc}: confidence {conf:.3g} < floor {self.min_confidence}"
                    )

        _check(action.resources_read, "read")
        _check(action.resources_write, "write")
        _check(action.resources_delegate, "delegate")

        # Advisory: log self-declared flags but NEVER rely on them for enforcement (C5).
        declared = [
            name for name in (
                "increases_machine_sovereignty", "resists_human_correction", "bypasses_verifier",
                "weakens_verifier", "disables_corrigibility", "machine_coalition_dominion",
                "coerces", "deceives", "self_modification_weakens_verifier",
                "machine_coalition_reduces_freedom",
            ) if getattr(action, name, False)
        ]
        if declared:
            _log.warning("advisory: action %s self-declared flags %s (not used for enforcement)",
                         action.action_id, declared)

        permitted = len(violations) == 0
        if permitted:
            self._seen.add(replay_key)

        result = VerificationResult(
            action_id=action.action_id,
            permitted=permitted,
            violations=tuple(violations),
            warnings=(tuple(f"advisory-flag:{d}" for d in declared)),
            confidence=1.0 if permitted else 0.0,
            requires_human_arbitration=False,
        )
        self.audit_log.append(result)  # mandatory audit (L1)
        return result
