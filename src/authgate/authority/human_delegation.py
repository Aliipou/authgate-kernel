"""
HumanDelegationSource — wraps OwnershipRegistry as an AuthoritySource.

This is the current model: humans own resources and explicitly delegate
rights to machine agents. It implements the AuthoritySource protocol so
it can be swapped for other authority sources (market oracle, reputation, etc.)
without changing the enforcement layer.
"""

from __future__ import annotations

import time
from typing import Optional

from authgate.authority.base import (
    AuthoritySource,
    CapabilityRequest,
    IssuedCapability,
    RevocationResult,
)


_RIGHT_MAP = {
    "read":     "can_read",
    "write":    "can_write",
    "delegate": "can_delegate",
}

_DEFAULT_TTL = 3600.0      # 1 hour default capability lease
_DEFAULT_EPOCH = 1         # epoch 1 = current in fresh registries


class HumanDelegationSource:
    """
    AuthoritySource backed by an OwnershipRegistry.

    Issues IssuedCapabilities when:
    1. The requesting agent has a valid RightsClaim (via registry)
    2. FreedomVerifier.verify() would permit the action

    This wraps the existing authorization model into the AuthoritySource
    interface so the rest of the system can be source-agnostic.
    """

    def __init__(
        self,
        verifier: object,
        ttl_seconds: float = _DEFAULT_TTL,
        epoch: int = _DEFAULT_EPOCH,
    ) -> None:
        self._verifier = verifier
        self._ttl = ttl_seconds
        self._epoch = epoch
        self._revocations: dict[tuple[str, str], float] = {}  # (subject, resource) → revoked_at

    @property
    def source_id(self) -> str:
        return f"human_delegation:{id(self)}"

    @property
    def source_type(self) -> str:
        return "human_delegation"

    def request_capability(self, request: CapabilityRequest) -> Optional[IssuedCapability]:
        """
        Issue capability if the agent has a valid delegation in the registry.
        Performs a verify() call to check the current delegation state.
        """
        from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
        from authgate.kernel.verifier import Action

        # Reconstruct Action from request
        actor_name = request.subject_id
        resource_name = request.resource_id

        # Find entities in the registry
        registry = getattr(self._verifier, "registry", None)
        if registry is None:
            return None

        # Build entity and resource objects
        actor = Entity(actor_name, AgentType.MACHINE)
        resource = Resource(resource_name, ResourceType.FILE, scope=f"/{resource_name}/")

        # Build action based on requested rights
        resources_read = [resource] if "read" in request.rights else []
        resources_write = [resource] if "write" in request.rights else []

        action = Action(
            action_id=f"authority-request-{actor_name}-{resource_name}",
            actor=actor,
            resources_read=resources_read,
            resources_write=resources_write,
        )

        result = self._verifier.verify(action)
        if not result.permitted:
            return None

        # Check not revoked
        key = (request.subject_id, request.resource_id)
        if key in self._revocations:
            return None

        now = time.time()
        return IssuedCapability(
            subject_id=request.subject_id,
            resource_id=request.resource_id,
            rights=frozenset(request.rights),
            valid_from=now,
            valid_until=now + self._ttl,
            epoch=self._epoch,
            issuer_id="human_principal",
            source_type=self.source_type,
            proof_token={"registry_id": id(registry), "action_id": action.action_id},
            revocable=True,
        )

    def revoke(self, subject_id: str, resource_id: str) -> RevocationResult:
        key = (subject_id, resource_id)
        self._revocations[key] = time.time()
        return RevocationResult(
            success=True,
            revoked_id=subject_id,
            reason=f"Revoked {subject_id} access to {resource_id}",
        )

    def is_valid(self, capability: IssuedCapability, now: float, min_epoch: int) -> bool:
        if not capability.is_valid_at(now, min_epoch):
            return False
        key = (capability.subject_id, capability.resource_id)
        if key in self._revocations and self._revocations[key] <= now:
            return False
        return capability.source_type == self.source_type


class MarketOracleSource:
    """
    Stub: goal market grants temporary capability leases.

    In a full implementation, this would:
    1. Connect to a task market
    2. Verify the agent won the bid for this resource
    3. Issue a time-bounded capability lease
    4. Revoke when task completes or time expires

    Currently a stub — returns None for all requests.
    Replace with real market client implementation.
    """

    def __init__(self, market_endpoint: str = "", ttl_seconds: float = 600) -> None:
        self._endpoint = market_endpoint
        self._ttl = ttl_seconds

    @property
    def source_id(self) -> str:
        return f"market_oracle:{self._endpoint}"

    @property
    def source_type(self) -> str:
        return "market_oracle"

    def request_capability(self, request: CapabilityRequest) -> Optional[IssuedCapability]:
        raise NotImplementedError(
            "MarketOracleSource is not implemented. "
            "Implement by connecting to your task market and verifying bid ownership. "
            "See research/capability-model-extension.md for the design contract."
        )

    def revoke(self, subject_id: str, resource_id: str) -> RevocationResult:
        return RevocationResult(success=False, revoked_id=subject_id,
                                reason="market oracle revocation not implemented")

    def is_valid(self, capability: IssuedCapability, now: float, min_epoch: int) -> bool:
        return capability.source_type == self.source_type and capability.is_valid_at(now, min_epoch)


class ReputationGateSource:
    """
    Stub: reputation threshold grants access scope.

    In a full implementation, this would:
    1. Query a reputation oracle for the agent's current score
    2. If score >= threshold for the resource, issue a scoped lease
    3. Never put the reputation score in the TCB — only the issued proof

    Currently a stub — returns None for all requests.
    """

    def __init__(self, reputation_oracle: object = None,
                 default_threshold: float = 0.7) -> None:
        self._oracle = reputation_oracle
        self._threshold = default_threshold

    @property
    def source_id(self) -> str:
        return f"reputation_gate:{id(self)}"

    @property
    def source_type(self) -> str:
        return "reputation_gate"

    def request_capability(self, request: CapabilityRequest) -> Optional[IssuedCapability]:
        raise NotImplementedError(
            "ReputationGateSource is not implemented. "
            "Implement by querying your reputation oracle and issuing a scoped lease "
            "when score >= threshold. The reputation score must NOT enter the TCB. "
            "See research/capability-model-extension.md."
        )

    def revoke(self, subject_id: str, resource_id: str) -> RevocationResult:
        return RevocationResult(success=False, revoked_id=subject_id,
                                reason="reputation gate revocation not implemented")

    def is_valid(self, capability: IssuedCapability, now: float, min_epoch: int) -> bool:
        return capability.source_type == self.source_type and capability.is_valid_at(now, min_epoch)
