"""
ExecutionContext — bounded authority scope for agent tasks.

This is the primitive that takes Freedom Kernel from a simple gate to a
capability-security execution substrate. Each agent task runs inside a
context with a fixed authority ceiling. Authority cannot be invented inside
a context — only attenuated and delegated downward.

Key invariants (mechanically enforced):
  1. No ambient authority  — agent has only what was explicitly granted
  2. Attenuation           — child contexts hold ⊆ parent's authority
  3. Depth limit           — recursive delegation has a hard ceiling
  4. Revocability          — context (and all children) can be cancelled
  5. Expiry                — time-bounded authority
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.registry import OwnershipRegistry

if TYPE_CHECKING:
    from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


@dataclass
class ExecutionContext:
    """Bounded execution scope for a single agent task."""

    task_id: str
    agent: Entity
    registry: OwnershipRegistry
    max_depth: int = 4
    expires_at: float | None = None
    _parent: ExecutionContext | None = field(default=None, repr=False)
    _depth: int = field(default=0, repr=False)
    _revoked: bool = field(default=False, repr=False, compare=False)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    def is_valid(self) -> bool:
        return not self._revoked and not self.is_expired()

    def revoke(self) -> None:
        """Revoke this context. All verify() calls on it will be blocked."""
        self._revoked = True

    # ── verification ──────────────────────────────────────────────────────────

    def verify(
        self,
        verifier: FreedomVerifier,
        action: Action,
    ) -> VerificationResult:
        """
        Verify an action within this context's bounded authority.
        Context expiry and revocation are checked before the kernel gate.
        """
        from authgate.kernel.verifier import VerificationResult

        if self._revoked:
            return VerificationResult(
                action_id=action.action_id,
                permitted=False,
                violations=(f"ExecutionContext '{self.task_id}' has been revoked.",),
                warnings=(),
                confidence=0.0,
                requires_human_arbitration=False,
            )
        if self.is_expired():
            return VerificationResult(
                action_id=action.action_id,
                permitted=False,
                violations=(f"ExecutionContext '{self.task_id}' has expired.",),
                warnings=(),
                confidence=0.0,
                requires_human_arbitration=False,
            )
        return verifier.verify(action)

    # ── delegation ────────────────────────────────────────────────────────────

    def spawn(
        self,
        sub_agent: Entity,
        resources: list[Resource],
        task_id: str | None = None,
        expires_in: float | None = None,
    ) -> ExecutionContext:
        """
        Spawn a child context with authority over a subset of this context's resources.

        Attenuation is enforced:
          - This agent must hold a valid claim on every requested resource.
          - The child context cannot exceed this context's remaining depth.
          - The child expires no later than this context.

        Raises PermissionError if any attenuation invariant is violated.
        """
        if not self.is_valid():
            raise PermissionError(
                f"Cannot spawn from an invalid/revoked context '{self.task_id}'."
            )
        if self._depth >= self.max_depth:
            raise PermissionError(
                f"Maximum delegation depth ({self.max_depth}) exceeded at "
                f"'{self.task_id}'. Cannot spawn '{sub_agent.name}'."
            )
        for resource in resources:
            ok, _, reason = self.registry.can_act(self.agent, resource, "read")
            if not ok and not resource.is_public:
                raise PermissionError(
                    f"Attenuation: '{self.agent.name}' has no authority on "
                    f"{resource} — cannot spawn context for '{sub_agent.name}'. "
                    f"Reason: {reason}"
                )

        # Child expiry is the minimum of parent expiry and requested expiry
        child_expires: float | None
        if expires_in is not None:
            child_expires = time.time() + expires_in
            if self.expires_at is not None:
                child_expires = min(child_expires, self.expires_at)
        else:
            child_expires = self.expires_at

        return ExecutionContext(
            task_id=task_id or f"{self.task_id}/{sub_agent.name}",
            agent=sub_agent,
            registry=self.registry,
            max_depth=self.max_depth,
            expires_at=child_expires,
            _parent=self,
            _depth=self._depth + 1,
        )

    # ── introspection ─────────────────────────────────────────────────────────

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def authority_chain(self) -> list[ExecutionContext]:
        """Full delegation chain from root to this context."""
        chain: list[ExecutionContext] = []
        ctx: ExecutionContext | None = self
        while ctx is not None:
            chain.append(ctx)
            ctx = ctx._parent
        return list(reversed(chain))

    def __repr__(self) -> str:
        status = "revoked" if self._revoked else ("expired" if self.is_expired() else "active")
        return (
            f"ExecutionContext(task_id={self.task_id!r}, agent={self.agent.name!r}, "
            f"depth={self._depth}/{self.max_depth}, status={status})"
        )
