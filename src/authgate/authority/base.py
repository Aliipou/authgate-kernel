"""
AuthoritySource base protocol — the "who signs capabilities" abstraction.

Every authority source produces IssuedCapabilities that the TCB can verify.
The TCB never sees the AuthoritySource — only its output (capability proofs).

Implementations (current and future):
  HumanDelegationSource  — OwnershipRegistry + manual delegation (current)
  MarketOracleSource     — Goal market grants temporary leases (future)
  ReputationGateSource   — Reputation threshold → access scope (future)
  SmartContractSource    — Token holding → capability proof (future)
  DAOVoteSource          — Governance quorum → capability (future)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class CapabilityRequest:
    """
    What capability an agent is requesting.
    Source-agnostic — the authority source decides whether to issue it.
    """
    subject_id: str           # Agent requesting access
    resource_id: str          # Resource to access
    rights: frozenset[str]    # Requested right names (e.g. {"read", "write"})
    context: dict = field(default_factory=dict, compare=False)
    # context: arbitrary source-specific metadata
    # For market sources: {"task_id": "...", "bid_amount": 100}
    # For reputation: {"reputation_score": 0.85, "guild": "analysts"}
    # For delegation: {"delegated_by": "alice"}


@dataclass
class IssuedCapability:
    """
    A capability issued by an AuthoritySource.
    Carries enough information to construct a CapabilityProof (or equivalent).
    """
    subject_id: str
    resource_id: str
    rights: frozenset[str]
    valid_from: float         # Unix timestamp
    valid_until: float        # Unix timestamp (expiry)
    epoch: int                # Revocation epoch at issuance
    issuer_id: str            # Identity of the authority that issued this
    source_type: str          # "human_delegation" | "market_oracle" | "reputation" | ...
    proof_token: Any = None   # Source-specific proof artifact (signature, token, etc.)
    revocable: bool = True
    metadata: dict = field(default_factory=dict)

    def is_valid_at(self, now: float, min_epoch: int) -> bool:
        return (self.valid_from <= now <= self.valid_until and
                self.epoch >= min_epoch)


@dataclass
class RevocationResult:
    success: bool
    revoked_id: str
    reason: str = ""


@runtime_checkable
class AuthoritySource(Protocol):
    """
    Protocol for capability issuance.

    Any object implementing this protocol can serve as an authority source
    for the authgate system. The TCB does not reference this protocol —
    authority sources produce proofs that are independently verifiable.
    """

    @property
    def source_id(self) -> str:
        """Unique identifier for this authority source instance."""
        ...

    @property
    def source_type(self) -> str:
        """Type tag: 'human_delegation' | 'market_oracle' | 'reputation' | ..."""
        ...

    def request_capability(self, request: CapabilityRequest) -> Optional[IssuedCapability]:
        """
        Issue a capability for the given request, or return None if denied.

        Implementations must:
        - Verify the requester's eligibility (owns resource, won bid, has reputation, etc.)
        - Set a reasonable expiry
        - Set the current epoch
        - Return None instead of raising on denial
        """
        ...

    def revoke(self, subject_id: str, resource_id: str) -> RevocationResult:
        """Revoke all capabilities from subject_id on resource_id."""
        ...

    def is_valid(self, capability: IssuedCapability, now: float, min_epoch: int) -> bool:
        """Check if an issued capability is still valid."""
        ...
