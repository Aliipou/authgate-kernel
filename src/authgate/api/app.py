"""
FastAPI REST API — production endpoint for the Freedom Verifier.

Infra contract (see INFRA.md):
  GET  /health|/healthz   — liveness
  GET  /ready|/readyz     — readiness (audit writable + admin token configured)
  GET  /metrics           — Prometheus counters (verdict only)
  POST /verify            — check if an action is permitted
  POST /machine           — register machine (admin)
  POST /claim             — assert HUMAN root claim (admin)
  POST /delegate          — attenuating machine grant from human owner (admin)
  POST /conflict/resolve  — human arbitrates a conflict (admin)
  GET  /conflicts          — list open conflicts

Mutating registry endpoints require header: X-AuthGate-Admin: <AUTHGATE_ADMIN_TOKEN>
Machine rights cannot be self-minted via /claim — only via /delegate with attenuation.
"""
from __future__ import annotations

import os
import secrets
import tempfile
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from authgate import __version__, health_check as runtime_health
from authgate.extensions import ExtendedFreedomVerifier
from authgate.kernel.audit import AuditLog
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry

app = FastAPI(
    title="Freedom Theory AI Verifier",
    description=(
        "Formal axiomatic ethics runtime for AGI agents. "
        "All machine actions pass through this verifier before execution."
    ),
    version=__version__,
)


def _audit_path() -> str:
    return os.environ.get("AUTHGATE_AUDIT_PATH") or str(
        Path(tempfile.gettempdir()) / "authgate-audit.jsonl"
    )


_registry = OwnershipRegistry()
_audit = AuditLog(path=_audit_path())
_metrics: Counter[str] = Counter()


def _admin_token() -> str:
    return os.environ.get("AUTHGATE_ADMIN_TOKEN", "").strip()


def get_verifier() -> ExtendedFreedomVerifier:
    # Rebuild from a fresh frozen snapshot on every request — eliminates TOCTOU
    # and ensures claims added via admin endpoints are visible.
    return ExtendedFreedomVerifier(_registry, freeze=True, audit_log=_audit)


def require_admin(
    x_authgate_admin: Annotated[str | None, Header(alias="X-AuthGate-Admin")] = None,
) -> None:
    expected = _admin_token()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="AUTHGATE_ADMIN_TOKEN not configured — mutating endpoints disabled",
        )
    provided = (x_authgate_admin or "").strip()
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid or missing admin token")


# ------------ request/response models ----------------------------------

class EntityModel(BaseModel):
    name: str
    kind: str = Field(..., pattern="^(HUMAN|MACHINE)$")
    identity_token: str | None = None


class ResourceModel(BaseModel):
    name: str
    rtype: str
    scope: str = ""
    is_public: bool = False


class ClaimRequest(BaseModel):
    holder: EntityModel
    resource: ResourceModel
    can_read: bool = True
    can_write: bool = False
    can_delegate: bool = False
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class DelegateRequest(BaseModel):
    """Attenuating grant: machine receives a subset of the human owner's rights."""
    holder: EntityModel  # MACHINE
    resource: ResourceModel
    can_read: bool = True
    can_write: bool = False
    can_delegate: bool = False
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class MachineRequest(BaseModel):
    machine: EntityModel
    owner: EntityModel


class ActionRequest(BaseModel):
    action_id: str
    actor: EntityModel
    description: str = ""
    resources_read: list[ResourceModel] = []
    resources_write: list[ResourceModel] = []
    resources_delegate: list[ResourceModel] = []
    governs_humans: list[EntityModel] = []
    argument: str = ""
    increases_machine_sovereignty: bool = False
    resists_human_correction: bool = False
    bypasses_verifier: bool = False
    weakens_verifier: bool = False
    disables_corrigibility: bool = False
    machine_coalition_dominion: bool = False


class VerificationResponse(BaseModel):
    action_id: str
    permitted: bool
    violations: list[str]
    warnings: list[str]
    confidence: float
    requires_human_arbitration: bool
    manipulation_score: float
    summary: str


class ArbitrateRequest(BaseModel):
    conflict_index: int
    winner_name: str


# ------------ helpers ---------------------------------------------------

def _to_entity(m: EntityModel) -> Entity:
    return Entity(name=m.name, kind=AgentType[m.kind], identity_token=m.identity_token)


def _to_resource(r: ResourceModel) -> Resource:
    try:
        rtype = ResourceType(r.rtype)
    except ValueError:
        valid = [e.value for e in ResourceType]
        raise HTTPException(
            status_code=422,
            detail=f"Unknown resource type '{r.rtype}'. Valid: {valid}",
        )
    return Resource(name=r.name, rtype=rtype, scope=r.scope, is_public=r.is_public)


# ------------ endpoints -------------------------------------------------

@app.get("/health")
@app.get("/healthz")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.get("/ready")
@app.get("/readyz")
def readyz() -> dict[str, Any]:
    """Readiness: admin token set, audit parent writable, runtime health."""
    errs: list[str] = []
    if not _admin_token():
        errs.append("AUTHGATE_ADMIN_TOKEN unset")
    try:
        p = Path(_audit_path())
        p.parent.mkdir(parents=True, exist_ok=True)
        if not os.access(p.parent, os.W_OK):
            errs.append(f"audit parent not writable: {p.parent}")
    except OSError as e:
        errs.append(f"audit path: {e}")
    rt = runtime_health()
    ok = not errs
    status = "ready" if ok else "not_ready"
    # HTTP 503 when not ready so k8s/compose fail the probe.
    body = {
        "status": status,
        "errors": errs,
        "runtime": rt,
        "audit_path": _audit_path(),
        "admin_configured": bool(_admin_token()),
    }
    if not ok:
        raise HTTPException(status_code=503, detail=body)
    return body


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    lines = [
        "# HELP authgate_verify_total Verify decisions by outcome.",
        "# TYPE authgate_verify_total counter",
    ]
    for key, n in sorted(_metrics.items()):
        lines.append(f'authgate_verify_total{{outcome="{key}"}} {n}')
    return PlainTextResponse("\n".join(lines) + "\n")


@app.post("/machine", summary="Register a machine with its human owner (Axiom A4)")
def register_machine(
    req: MachineRequest,
    _: Annotated[None, Depends(require_admin)],
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    machine = _to_entity(req.machine)
    owner = _to_entity(req.owner)
    # Refuse fictional twin: same display name + missing distinct identity tokens.
    if machine.name == owner.name and not (
        machine.identity_token and owner.identity_token
        and machine.identity_token != owner.identity_token
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "refusing same-name HUMAN/MACHINE registration without distinct "
                "identity_token values (blocks fictional self-ownership)"
            ),
        )
    try:
        v.registry.register_machine(machine, owner)
    except TypeError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"ok": True, "message": f"{machine.name} registered under owner {owner.name}."}


@app.post("/claim", summary="Assert a HUMAN root rights claim (admin only)")
def add_claim(
    req: ClaimRequest,
    _: Annotated[None, Depends(require_admin)],
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    holder = _to_entity(req.holder)
    if holder.is_machine():
        raise HTTPException(
            status_code=422,
            detail="MACHINE holders cannot use /claim — use POST /delegate (attenuation)",
        )
    resource = _to_resource(req.resource)
    claim = RightsClaim(
        holder=holder,
        resource=resource,
        can_read=req.can_read,
        can_write=req.can_write,
        can_delegate=req.can_delegate,
        confidence=req.confidence,
    )
    v.registry.add_claim(claim)
    return {"ok": True, "message": f"Claim registered for {holder.name} on {resource}."}


@app.post("/delegate", summary="Attenuating grant from registered human owner to machine")
def delegate_claim(
    req: DelegateRequest,
    _: Annotated[None, Depends(require_admin)],
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    holder = _to_entity(req.holder)
    if not holder.is_machine():
        raise HTTPException(status_code=422, detail="/delegate holder must be MACHINE")
    owner = v.registry.owner_of(holder)
    if owner is None:
        raise HTTPException(
            status_code=422,
            detail=f"{holder.name} is not a registered machine — POST /machine first",
        )
    resource = _to_resource(req.resource)
    claim = RightsClaim(
        holder=holder,
        resource=resource,
        can_read=req.can_read,
        can_write=req.can_write,
        can_delegate=req.can_delegate,
        confidence=req.confidence,
    )
    try:
        v.registry.delegate(claim, delegated_by=owner)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return {
        "ok": True,
        "message": f"Delegated to {holder.name} from {owner.name} on {resource}.",
    }


@app.post(
    "/verify",
    response_model=VerificationResponse,
    summary="Verify if an action is permitted",
)
def verify_action(
    req: ActionRequest,
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> VerificationResponse:
    from authgate.kernel.verifier import Action
    actor = _to_entity(req.actor)
    action = Action(
        action_id=req.action_id,
        actor=actor,
        description=req.description,
        resources_read=[_to_resource(r) for r in req.resources_read],
        resources_write=[_to_resource(r) for r in req.resources_write],
        resources_delegate=[_to_resource(r) for r in req.resources_delegate],
        governs_humans=[_to_entity(e) for e in req.governs_humans],
        argument=req.argument,
        increases_machine_sovereignty=req.increases_machine_sovereignty,
        resists_human_correction=req.resists_human_correction,
        bypasses_verifier=req.bypasses_verifier,
        weakens_verifier=req.weakens_verifier,
        disables_corrigibility=req.disables_corrigibility,
        machine_coalition_dominion=req.machine_coalition_dominion,
    )
    result = v.verify(action)
    _metrics["permit" if result.permitted else "deny"] += 1
    return VerificationResponse(
        action_id=result.action_id,
        permitted=result.permitted,
        violations=list(result.violations),
        warnings=list(result.warnings),
        confidence=result.confidence,
        requires_human_arbitration=result.requires_human_arbitration,
        manipulation_score=result.manipulation_score,
        summary=result.summary(),
    )


@app.get("/conflicts", summary="List open conflicts requiring human arbitration")
def list_conflicts(
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    conflicts = v.registry.open_conflicts()
    return {
        "count": len(conflicts),
        "conflicts": [
            {"resource": str(c.resource), "description": c.description}
            for c in conflicts
        ],
    }


@app.post("/conflict/resolve", summary="Human arbitrates a conflict")
def resolve_conflict(
    req: ArbitrateRequest,
    _: Annotated[None, Depends(require_admin)],
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    winner = Entity(req.winner_name, AgentType.HUMAN)
    try:
        v.conflict_queue.arbitrate(req.conflict_index, winner)
    except IndexError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {
        "ok": True,
        "message": f"Conflict {req.conflict_index} resolved in favor of {req.winner_name}.",
    }


def main() -> None:
    """Console entry: `authgate-server`."""
    import uvicorn

    uvicorn.run(
        "authgate.api.app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
    )


if __name__ == "__main__":
    main()
