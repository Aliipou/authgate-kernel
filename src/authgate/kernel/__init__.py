"""
Freedom Kernel — capability-security gate for agentic AI.

LLM → Action IR → FreedomVerifier → Execute | Block

  entities  — typed data (Entity, Resource, RightsClaim)
  registry  — ownership graph + conflict detection
  verifier  — deterministic gate (verify, verify_plan, verify_signed)
  context   — ExecutionContext (bounded authority scope)
  goals     — GoalNode + verify_goal_tree (Stage 2)
"""
try:
    from authgate_kernel import (  # type: ignore[import]
        Action,
        AgentType,
        ConflictRecord,
        Entity,
        FreedomVerifier,
        OwnershipRegistry,
        Resource,
        ResourceType,
        RightsClaim,
        VerificationResult,
    )
    _BACKEND = "rust"
except ImportError:
    from authgate.kernel._pure import (  # noqa: F401
        Action,
        AgentType,
        ConflictRecord,
        Entity,
        FreedomVerifier,
        OwnershipRegistry,
        Resource,
        ResourceType,
        RightsClaim,
        VerificationResult,
    )
    _BACKEND = "python"

__all__ = [
    "AgentType",
    "Entity",
    "Resource",
    "ResourceType",
    "RightsClaim",
    "ConflictRecord",
    "OwnershipRegistry",
    "Action",
    "FreedomVerifier",
    "VerificationResult",
]
