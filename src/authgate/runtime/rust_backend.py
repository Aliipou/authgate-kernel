"""
RustBackedVerifier — route the runtime's authorization decision through the
formally-verified Rust TCB engine, without importing Rust pyclass objects.

Motivation (the honest gap this closes): the Kani/Lean proofs cover
``authgate-kernel/src/engine.rs``. The Python runtime, however, decides with
``authgate.kernel.verifier`` — a *different* implementation. So "the verified
kernel gates every call" and "the code that actually ran" were two codebases.

This adapter makes the running system's permit/deny decision come from the
verified engine. The trust boundary is **JSON**: the Python registry + action are
serialized to the kernel wire format and handed to ``authgate_kernel.verify_json``
(which calls ``crate::engine::verify`` and returns an ed25519-signed verdict).
Only JSON crosses — no Rust ``Entity``/``Action`` objects enter the Python
process, so the dual-type ``"Entity cannot be converted to Entity"`` problem
that forced ``AUTHGATE_BACKEND=python`` simply cannot occur here.

Semantic reconciliation: the wire/engine has no *epoch* concept (the Python
verifier's revocation mechanism). We preserve it by serializing only the claims
the Python registry considers **currently valid** — unexpired, identity-matched,
delegation-chain-valid, and at or above the action's ``min_epoch``. The verified
engine then independently re-derives permit/deny from claim existence, machine
ownership (A4), no-dominion (A6), and the forbidden-flag set. Revocation and
epoch therefore behave identically to the pure-Python path, while the actual
decision is made by verified code.
"""
from __future__ import annotations

import importlib
import json
from typing import Any

from authgate.kernel.entities import Entity, Resource, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, VerificationResult


def rust_backend_available() -> bool:
    """True iff the compiled verified-kernel extension can be imported."""
    try:
        importlib.import_module("authgate_kernel")
        return True
    except ImportError:
        return False


def _entity_wire(e: Entity) -> dict[str, str]:
    return {"name": e.name, "kind": e.kind.name}


def _resource_wire(r: Resource) -> dict[str, Any]:
    return {
        "name": r.name,
        "rtype": r.rtype.name,
        "scope": r.scope,
        "is_public": r.is_public,
        "ifc_label": r.ifc_label,
    }


def _claim_wire(c: RightsClaim) -> dict[str, Any]:
    return {
        "holder": _entity_wire(c.holder),
        "resource": _resource_wire(c.resource),
        "can_read": c.can_read,
        "can_write": c.can_write,
        "can_delegate": c.can_delegate,
        "confidence": c.confidence,
        "expires_at": c.expires_at,
        "delegation_depth": 0,
    }


# Action boolean flags, mapped 1:1 to the wire field names the engine reads.
_FLAG_FIELDS = (
    "increases_machine_sovereignty",
    "resists_human_correction",
    "bypasses_verifier",
    "weakens_verifier",
    "disables_corrigibility",
    "machine_coalition_dominion",
    "coerces",
    "deceives",
    "self_modification_weakens_verifier",
    "machine_coalition_reduces_freedom",
)


def _action_wire(action: Action) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "action_id": action.action_id,
        "actor": _entity_wire(action.actor),
        "description": action.description,
        "resources_read": [_resource_wire(r) for r in action.resources_read],
        "resources_write": [_resource_wire(r) for r in action.resources_write],
        "resources_delegate": [_resource_wire(r) for r in action.resources_delegate],
        "governs_humans": [_entity_wire(h) for h in action.governs_humans],
        "argument": action.argument,
        "delegation_depth": 0,
    }
    for flag in _FLAG_FIELDS:
        wire[flag] = getattr(action, flag)
    return wire


def _live_claims(registry: OwnershipRegistry, min_epoch: int) -> list[RightsClaim]:
    """The claims the Python registry currently treats as valid — the set the
    verified engine should see. This is where epoch/revocation/identity live."""
    live: list[RightsClaim] = []
    for c in registry._claims:
        if not c.is_valid():
            continue
        if not registry._identity_matches(c.holder):
            continue
        if not registry._delegation_chain_valid(c):
            continue
        if c.epoch < min_epoch:
            continue
        live.append(c)
    return live


class RustBackedVerifier:
    """Drop-in replacement for FreedomVerifier whose decision is made by the
    verified Rust engine. Same ``verify(action) -> VerificationResult`` contract,
    so CallGate, the audit log, and the runtime are unchanged."""

    def __init__(
        self,
        registry: OwnershipRegistry,
        audit_log: object = None,
        freeze: bool = True,
    ) -> None:
        # Mirror FreedomVerifier's TOCTOU stance: snapshot unless told otherwise.
        self.registry = (
            registry.freeze() if freeze and not getattr(registry, "_frozen", False) else registry
        )
        self._audit_log = audit_log
        self._ak = importlib.import_module("authgate_kernel")

    def verify(self, action: Action) -> VerificationResult:
        registry_wire = {
            "claims": [_claim_wire(c) for c in _live_claims(self.registry, action.min_epoch)],
            "machine_owners": [
                {"machine": _entity_wire(m), "owner": _entity_wire(o)}
                for m, o in self.registry._machine_owners.items()
            ],
            "trust_domains": [],
        }
        payload = {"registry": registry_wire, "action": _action_wire(action)}
        out = json.loads(self._ak.verify_json(json.dumps(payload)))

        result = VerificationResult(
            action_id=out["action_id"],
            permitted=out["permitted"],
            violations=tuple(out["violations"]),
            warnings=tuple(out.get("warnings", ())),
            confidence=out.get("confidence", 0.0),
            requires_human_arbitration=out.get("requires_human_arbitration", False),
        )
        if self._audit_log is not None:
            self._audit_log.record(result)  # type: ignore[attr-defined]
        return result
