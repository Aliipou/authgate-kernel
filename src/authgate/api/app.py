"""
FastAPI REST API — production endpoint for the Freedom Verifier.

  POST /verify            — check if an action is permitted
  POST /claim             — register a rights claim
  POST /machine           — register a machine with its human owner
  POST /conflict/resolve  — human arbitrates a conflict
  GET  /conflicts         — list open conflicts
  GET  /health            — liveness check
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from authgate.extensions import ExtendedFreedomVerifier
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry

app = FastAPI(
    title="Freedom Theory AI Verifier",
    description=(
        "Formal axiomatic ethics runtime for AGI agents. "
        "All machine actions pass through this verifier before execution."
    ),
    version="1.0.0",
)

_registry = OwnershipRegistry()
_verifier = ExtendedFreedomVerifier(_registry)


def get_verifier() -> ExtendedFreedomVerifier:
    return _verifier


# ------------ request/response models ----------------------------------

class EntityModel(BaseModel):
    name: str
    kind: str = Field(..., pattern="^(HUMAN|MACHINE)$")


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
    return Entity(name=m.name, kind=AgentType[m.kind])


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
def health() -> dict:
    return {"status": "ok", "version": "1.0.0"}


@app.post("/machine", summary="Register a machine with its human owner (Axiom A4)")
def register_machine(
    req: MachineRequest,
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    machine = _to_entity(req.machine)
    owner = _to_entity(req.owner)
    try:
        v.registry.register_machine(machine, owner)
    except TypeError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"ok": True, "message": f"{machine.name} registered under owner {owner.name}."}


@app.post("/claim", summary="Register a rights claim on a resource")
def add_claim(
    req: ClaimRequest,
    v: Annotated[ExtendedFreedomVerifier, Depends(get_verifier)],
) -> dict:
    holder = _to_entity(req.holder)
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
