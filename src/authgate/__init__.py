"""
authgate-kernel — capability-security gate for autonomous agents.

Architecture:
  kernel/     — minimal formal gate (FreedomVerifier, CallGate, AuditLog)
  adapters/   — framework adapters (OpenAI, Anthropic, LangChain, AutoGen)
  extensions/ — heuristic layers (manipulation detection, synthesis, compass)
  authority/  — AuthoritySource adapters (human delegation, market oracle stubs)

Backend:
  _BACKEND = "rust"   — Rust TCB via PyO3 (install freedom-kernel crate)
  _BACKEND = "python" — Python mirror (not formally verified; see FINDINGS.md C-1..C-4)
"""

__version__ = "1.0.0"
__schema_version__ = "1.0.0"   # capability proof schema; bump on breaking semantic change
from authgate.adapters.anthropic import AnthropicKernelAdapter
from authgate.adapters.autogen import AutoGenKernelAdapter
from authgate.adapters.langchain import FreedomTool, kernel_gate
from authgate.adapters.openai_agents import OpenAIKernelMiddleware
from authgate.extensions import (
    ExtendedFreedomVerifier,
    IFCViolation,
    NonInterferenceChecker,
    SecurityLattice,
)
from authgate.extensions.compass import WorldState
from authgate.extensions.compass import score as compass_score
from authgate.extensions.detection import detect as detect_manipulation
from authgate.extensions.synthesis import ProposedRule, SynthesisEngine
from authgate.kernel import (
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
from authgate.kernel.audit import AuditLog
from authgate.kernel.context import ExecutionContext
from authgate.kernel.goals import GoalNode, GoalVerificationResult, verify_goal_tree
from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier
from authgate.errors import (
    AuthgateError,
    CapabilityError,
    IntegrityError,
    KeyRotationError,
    RegistryError,
    RightsError,
    WireError,
)
from authgate.key_rotation import ActiveKeySet, RotationCertificate, issue_rotation, verify_rotation
from authgate.kernel.hooks import HookRegistry, MetricsCollector, VerificationEvent
from authgate.kernel.call_gate import CallGate, GatedTool, GateResult
from authgate.kernel.schema_version import CURRENT_SCHEMA_VERSION, check_version_compatibility


def health_check() -> dict:
    """
    Return a dict describing the current runtime state.
    Use in container health checks and deployment validation.

    Returns:
        {
            "status": "ok" | "degraded",
            "version": "1.0.0",
            "schema_version": "1.0.0",
            "backend": "rust" | "python",
            "python_identity_warning": bool,  # True = C-1 gap is active (Python mode)
            "epoch_revocation": bool,         # True = min_epoch is supported
            "issues": [str, ...]              # List of active warnings
        }
    """
    from authgate.kernel import _BACKEND
    issues = []

    if _BACKEND == "python":
        issues.append(
            "C-1: Python mode uses name-based identity (no cryptographic binding). "
            "Install authgate-kernel Rust crate for SHA-256(pubkey) identity binding."
        )
        issues.append(
            "C-2: Python mode cannot prevent subprocess/ctypes escape. "
            "Use SeccompCallGate on Linux or WASM sandbox for OS-level enforcement."
        )

    return {
        "status": "degraded" if issues else "ok",
        "version": __version__,
        "schema_version": __schema_version__,
        "backend": _BACKEND,
        "python_identity_warning": _BACKEND == "python",
        "epoch_revocation": True,  # C-3 fixed: min_epoch wired through Python layer
        "issues": issues,
    }


__all__ = [
    # Core kernel
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
    # Stage 2: bounded contexts + goal verification
    "ExecutionContext",
    "GoalNode",
    "GoalVerificationResult",
    "verify_goal_tree",
    # Stage 3: framework adapters
    "OpenAIKernelMiddleware",
    "AnthropicKernelAdapter",
    "FreedomTool",
    "kernel_gate",
    "AutoGenKernelAdapter",
    # Policy IR
    "Policy",
    "PolicyRule",
    "PolicyVerifier",
    # Extensions
    "ExtendedFreedomVerifier",
    "WorldState",
    "compass_score",
    "detect_manipulation",
    "ProposedRule",
    "SynthesisEngine",
    # IFC
    "IFCViolation",
    "NonInterferenceChecker",
    "SecurityLattice",
    # Audit
    "AuditLog",
    # Errors
    "AuthgateError",
    "CapabilityError",
    "IntegrityError",
    "KeyRotationError",
    "RegistryError",
    "RightsError",
    "WireError",
    # Key rotation
    "RotationCertificate",
    "ActiveKeySet",
    "issue_rotation",
    "verify_rotation",
    # Observability hooks
    "HookRegistry",
    "MetricsCollector",
    "VerificationEvent",
    # CallGate (enforcement layer)
    "CallGate",
    "GatedTool",
    "GateResult",
    # Versioning
    "__version__",
    "__schema_version__",
    "CURRENT_SCHEMA_VERSION",
    "check_version_compatibility",
    # Deployment
    "health_check",
]
