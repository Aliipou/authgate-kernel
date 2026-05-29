"""
AuthoritySource abstraction — III-1 from INFRASTRUCTURE_PLAN.md.

Decouples "who signs capabilities" from the TCB verification logic.

Current model:    Human principal signs RightsClaim directly.
Future models:    Market oracle, reputation gate, DAO vote, smart contract.

The TCB (engine.rs) does not care about the source — it only verifies
that a proof chain exists and is valid. AuthoritySource adapters produce
those proof chains from different upstream authority mechanisms.

See research/capability-model-extension.md for the architectural rationale.
"""

from authgate.authority.base import AuthoritySource, CapabilityRequest, IssuedCapability
from authgate.authority.human_delegation import HumanDelegationSource

__all__ = [
    "AuthoritySource",
    "CapabilityRequest",
    "IssuedCapability",
    "HumanDelegationSource",
]
