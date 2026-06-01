"""
Freedom Kernel — capability-security gate for agentic AI.

LLM → Action IR → FreedomVerifier → Execute | Block

  entities  — typed data (Entity, Resource, RightsClaim)
  registry  — ownership graph + conflict detection
  verifier  — deterministic gate (verify, verify_plan, verify_signed)
  context   — ExecutionContext (bounded authority scope)
  goals     — GoalNode + verify_goal_tree (Stage 2)
"""
import os

# Backend selection. Set AUTHGATE_BACKEND=python to force the pure-Python
# reference implementation even when the Rust extension is installed — this keeps
# a single Entity/Action type system within one process (mixing the PyO3 Rust
# types and the pure-Python types raises "Entity cannot be converted to Entity").
# The Rust TCB is validated separately by the cargo test / Kani jobs.
_FORCE_PYTHON = os.environ.get("AUTHGATE_BACKEND", "").lower() == "python"

if not _FORCE_PYTHON:
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
        _FORCE_PYTHON = True

if _FORCE_PYTHON:
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
