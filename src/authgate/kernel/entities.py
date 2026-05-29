"""
Entities and typed resources.

Resources are typed and scoped, not strings.
Rights carry scope, confidence, and expiry — not binary ownership booleans.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class AgentType(Enum):
    HUMAN = auto()
    MACHINE = auto()


class ResourceType(Enum):
    """Only concrete, machine-context resource types are operational."""
    FILE = "file"
    API_ENDPOINT = "api_endpoint"
    DATABASE_TABLE = "database_table"
    NETWORK_ENDPOINT = "network_endpoint"
    COMPUTE_SLOT = "compute_slot"
    MESSAGE_CHANNEL = "message_channel"
    CREDENTIAL = "credential"
    MODEL_WEIGHTS = "model_weights"
    DATASET = "dataset"
    MEMORY_REGION = "memory_region"


@dataclass(frozen=True)
class Resource:
    name: str
    rtype: ResourceType
    scope: str = ""
    is_public: bool = False
    ifc_label: str = field(default="", compare=False, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.rtype, ResourceType):
            raise TypeError(f"Resource.rtype must be ResourceType, got {type(self.rtype).__name__!r}")

    def __str__(self) -> str:
        return f"{self.rtype.value}:{self.name}"


def _has_traversal(path: str) -> bool:
    """Return True if path contains any .. path-traversal segment."""
    parts = path.replace("\\", "/").split("/")
    return ".." in parts


def scope_contains(parent_scope: str, child_path: str) -> bool:
    """
    Returns True iff child_path falls within parent_scope (prefix matching).

    Formal rule: scope_contains(P, C) iff C == P or C starts with normalize(P) + "/"
    An empty parent_scope matches everything (root / universal scope).

    Path traversal: any path containing '..' segments returns False — no normalization
    is performed, since normalization of untrusted input is itself an attack surface.
    """
    if _has_traversal(parent_scope) or _has_traversal(child_path):
        return False
    if not parent_scope:
        return True
    normalized = parent_scope.rstrip("/")
    return child_path == normalized or child_path.startswith(normalized + "/")


@dataclass(frozen=True)
class Entity:
    name: str
    kind: AgentType
    metadata: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AgentType):
            raise TypeError(f"Entity.kind must be AgentType, got {type(self.kind).__name__!r}")

    def is_human(self) -> bool:
        return self.kind == AgentType.HUMAN

    def is_machine(self) -> bool:
        return self.kind == AgentType.MACHINE

    def __str__(self) -> str:
        return f"{self.kind.name}({self.name})"


@dataclass
class RightsClaim:
    """A right is not a binary flag — it has scope, confidence, expiry, and delegation lineage."""
    holder: Entity
    resource: Resource
    can_read: bool = True
    can_write: bool = False
    can_delegate: bool = False
    confidence: float = 1.0
    expires_at: float | None = None
    delegated_by: "Entity | None" = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        import math
        if not isinstance(self.confidence, (int, float)) or math.isnan(self.confidence) or math.isinf(self.confidence):
            raise ValueError(f"confidence must be a finite float, got {self.confidence!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    def is_valid(self) -> bool:
        return not self.is_expired() and self.confidence > 0.0

    def covers(self, operation: str) -> bool:
        if not self.is_valid():
            return False
        return getattr(self, f"can_{operation}", False)
