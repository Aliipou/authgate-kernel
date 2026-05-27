"""
Freedom Kernel — Capability-security operating layer for autonomous agents.

Architecture:
  kernel/     — minimal formal gate (FreedomVerifier, ExecutionContext, GoalNode)
  adapters/   — framework adapters (OpenAI, Anthropic, LangChain, AutoGen)
  extensions/ — pluggable layers on top (manipulation detection, synthesis, compass)
"""
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
]
