"""
Conflict Resolution Layer.

Rights conflict resolution strategy (priority order):
  1. Scope specificity — more specific claim wins
  2. Confidence — higher confidence = more authoritative
  3. Read-only vs write — allow read, require arbitration for write
  4. Deadlock → human arbitration

Never resolves by sacrificing rights.
If no resolution is possible without a rights violation,
deadlocks and requests human arbitration.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from authgate.kernel.entities import Entity, RightsClaim


class Resolution(Enum):
    CLAIM_A_WINS = auto()
    CLAIM_B_WINS = auto()
    BOTH_PERMITTED = auto()
    DEADLOCK = auto()


@dataclass(frozen=True)
class ResolutionResult:
    resolution: Resolution
    winning_claim: RightsClaim | None
    reason: str
    requires_human: bool

    @property
    def resolved(self) -> bool:
        return self.resolution != Resolution.DEADLOCK


def resolve(claim_a: RightsClaim, claim_b: RightsClaim) -> ResolutionResult:
    """Resolve a conflict between two claims on the same resource."""
    # 1. Scope specificity
    scope_a = len(claim_a.resource.scope)
    scope_b = len(claim_b.resource.scope)
    if scope_a != scope_b:
        winner = claim_a if scope_a > scope_b else claim_b
        return ResolutionResult(
            resolution=Resolution.CLAIM_A_WINS if winner is claim_a else Resolution.CLAIM_B_WINS,
            winning_claim=winner,
            reason=f"Scope specificity: '{winner.resource.scope}' is more specific.",
            requires_human=False,
        )

    # 2. Confidence
    if abs(claim_a.confidence - claim_b.confidence) > 0.1:
        winner = claim_a if claim_a.confidence > claim_b.confidence else claim_b
        return ResolutionResult(
            resolution=Resolution.CLAIM_A_WINS if winner is claim_a else Resolution.CLAIM_B_WINS,
            winning_claim=winner,
            reason=f"Confidence: {winner.holder.name} has confidence={winner.confidence:.2f}.",
            requires_human=False,
        )

    # 3. Read-only vs write conflict
    if claim_a.can_write != claim_b.can_write:
        read_only = claim_a if not claim_a.can_write else claim_b
        return ResolutionResult(
            resolution=Resolution.CLAIM_A_WINS if read_only is claim_a else Resolution.CLAIM_B_WINS,
            winning_claim=read_only,
            reason="Read-only claim permitted; write claim requires arbitration.",
            requires_human=True,
        )

    # 4. Deadlock
    return ResolutionResult(
        resolution=Resolution.DEADLOCK,
        winning_claim=None,
        reason=(
            f"Unresolvable conflict between {claim_a.holder.name} and {claim_b.holder.name} "
            f"on {claim_a.resource}. Human arbitration required. "
            "No action permitted until resolved."
        ),
        requires_human=True,
    )


@dataclass
class ConflictQueue:
    """Tracks unresolved conflicts pending human arbitration."""
    _pending: list[tuple[RightsClaim, RightsClaim, ResolutionResult]] = None  # type: ignore

    def __post_init__(self) -> None:
        self._pending = []

    def add(self, a: RightsClaim, b: RightsClaim, result: ResolutionResult) -> None:
        self._pending.append((a, b, result))

    def pending_count(self) -> int:
        return len(self._pending)

    def arbitrate(self, index: int, winner: Entity) -> None:
        if index >= len(self._pending):
            raise IndexError(f"No pending conflict at index {index}.")
        self._pending.pop(index)

    def summary(self) -> list[str]:
        return [r.reason for _, _, r in self._pending]
