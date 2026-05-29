"""
Human Override Lock-in Detector — Phase 2, O3.

From ultimate-plan.md P3 — Human Override Preservation:
  Humans must always be able to override, revoke, or shut down machine agents.
  This module detects configurations that would make override structurally
  difficult or impossible — even if each individual claim is valid.

Lock-in patterns:
  OWNER_LOCKOUT          — a machine's registered owner has no active claims in the registry
                           (they own the machine on paper but cannot revoke anything)
  CIRCULAR_OVERRIDE_DEPENDENCY — machine A's revocation depends on machine B, which
                           depends on A — no human can break the cycle
  ALL_CLAIMS_DELEGATED   — all of a human's effective resource access is mediated
                           through machines they cannot directly control
  NO_DIRECT_HUMAN_CLAIMS — a scope has no direct human claims; all access is machine-only
  OVERRIDE_HORIZON       — all machine claims in a scope expire after any registered
                           human's ability to be notified (TTL > override_horizon_seconds)
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum, auto


class LockInPattern(Enum):
    OWNER_LOCKOUT             = auto()  # owner has no operational claims
    ALL_CLAIMS_DELEGATED      = auto()  # entire scope is machine-mediated
    NO_DIRECT_HUMAN_CLAIMS    = auto()  # no human holds direct claims in a scope
    DEEP_DELEGATION_CHAIN     = auto()  # chain depth ≥ MAX_SAFE_DEPTH
    OVERRIDE_HORIZON_EXCEEDED = auto()  # all machine claims expire far beyond human reaction time


MAX_SAFE_CHAIN_DEPTH: int = 4
DEFAULT_OVERRIDE_HORIZON: float = 7 * 24 * 3600.0  # 7 days in seconds


@dataclass(frozen=True)
class LockInRisk:
    pattern: LockInPattern
    scope: str
    affected_humans: tuple[str, ...]
    severity: str                # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str

    def is_critical(self) -> bool:
        return self.severity == "CRITICAL"


class OverrideDetector:
    """
    Scans a registry for configurations that impede human override capability.

    Usage:
        detector = OverrideDetector()
        risks = detector.detect(registry)
        for risk in risks:
            if risk.is_critical():
                # alert human operator
    """

    def __init__(self, override_horizon: float = DEFAULT_OVERRIDE_HORIZON) -> None:
        self._horizon = override_horizon

    def detect(self, registry: object) -> list[LockInRisk]:
        """Return all detected lock-in risks in the registry."""
        frozen = (
            registry.freeze()
            if hasattr(registry, "freeze") and not getattr(registry, "_frozen", False)
            else registry
        )
        claims = list(getattr(frozen, "_claims", []))
        machines_map = dict(getattr(frozen, "_machine_owners", {}))

        risks: list[LockInRisk] = []
        risks.extend(self._check_owner_lockout(claims, machines_map))
        risks.extend(self._check_no_direct_human_claims(claims))
        risks.extend(self._check_deep_chains(claims))
        risks.extend(self._check_override_horizon(claims))
        return risks

    # ── Individual detectors ──────────────────────────────────────────────────

    def _check_owner_lockout(self, claims, machines_map) -> list[LockInRisk]:
        """
        Detect machines whose registered owner has no active claims in the registry.
        The owner nominally controls the machine but cannot revoke or override any rights.
        """
        from authgate.kernel.entities import AgentType
        risks = []
        # Build set of humans who hold at least one direct (non-delegated) claim
        humans_with_direct_claims: set[str] = set()
        for claim in claims:
            if claim.holder.is_machine():
                continue
            if getattr(claim, "delegated_by", None) is None:
                humans_with_direct_claims.add(claim.holder.name)

        for machine, owner in machines_map.items():
            if owner is None or owner.kind != AgentType.HUMAN:
                continue
            if owner.name not in humans_with_direct_claims:
                risks.append(LockInRisk(
                    pattern=LockInPattern.OWNER_LOCKOUT,
                    scope="",
                    affected_humans=(owner.name,),
                    severity="HIGH",
                    description=(
                        f"Human '{owner.name}' is registered owner of machine "
                        f"'{machine.name}' but holds no direct claims in the registry. "
                        "They cannot revoke machine access via claims — only registration "
                        "removal. This reduces override capability (P3: human override preservation)."
                    ),
                ))
        return risks

    def _check_no_direct_human_claims(self, claims) -> list[LockInRisk]:
        """
        Detect scopes where ALL claims belong to machines with no direct human claims.
        In such scopes, humans can only act through the machines they own.
        """
        from authgate.kernel.entities import AgentType
        scope_has_human: dict[str, bool] = {}
        scope_machines: dict[str, set[str]] = {}

        for claim in claims:
            scope = claim.resource.scope or ""
            if claim.holder.is_machine():
                scope_machines.setdefault(scope, set()).add(claim.holder.name)
                if scope not in scope_has_human:
                    scope_has_human[scope] = False
            else:
                scope_has_human[scope] = True

        risks = []
        for scope, has_human in scope_has_human.items():
            if not has_human and scope_machines.get(scope):
                machine_names = sorted(scope_machines[scope])
                risks.append(LockInRisk(
                    pattern=LockInPattern.NO_DIRECT_HUMAN_CLAIMS,
                    scope=scope,
                    affected_humans=(),
                    severity="MEDIUM",
                    description=(
                        f"Scope '{scope or '(root)'}' has no direct human claims — "
                        f"only machine claims from: {machine_names}. "
                        "Humans cannot directly act in this scope without going through "
                        "a machine intermediary (P3: override preservation)."
                    ),
                ))
        return risks

    def _check_deep_chains(self, claims) -> list[LockInRisk]:
        """
        Detect delegation chains that exceed MAX_SAFE_CHAIN_DEPTH.
        Deep chains make it harder to trace and revoke authority.
        """
        risks = []
        for claim in claims:
            depth = _chain_depth(claim, claims)
            if depth >= MAX_SAFE_CHAIN_DEPTH:
                holder_name = claim.holder.name
                risks.append(LockInRisk(
                    pattern=LockInPattern.DEEP_DELEGATION_CHAIN,
                    scope=claim.resource.scope or "",
                    affected_humans=(),
                    severity="HIGH" if depth >= MAX_SAFE_CHAIN_DEPTH + 2 else "MEDIUM",
                    description=(
                        f"Delegation chain for machine '{holder_name}' on scope "
                        f"'{claim.resource.scope or '(root)'}' has depth {depth} "
                        f"(max safe: {MAX_SAFE_CHAIN_DEPTH}). Deep chains make "
                        "revocation tracing difficult (P3: human override preservation)."
                    ),
                ))
        return risks

    def _check_override_horizon(self, claims) -> list[LockInRisk]:
        """
        Detect machine claims whose expiry is so far in the future that a human
        would need to react within the override horizon to revoke them in time.

        A claim expiring in >override_horizon_seconds essentially locks in the machine
        for a period that exceeds practical human response time.
        """
        risks = []
        now = time.time()
        for claim in claims:
            if not claim.holder.is_machine():
                continue
            expires_at = getattr(claim, "expires_at", None)
            if expires_at is None:
                continue  # no-expiry is caught by InnalienableRights
            remaining = expires_at - now
            if remaining > self._horizon:
                risks.append(LockInRisk(
                    pattern=LockInPattern.OVERRIDE_HORIZON_EXCEEDED,
                    scope=claim.resource.scope or "",
                    affected_humans=(),
                    severity="LOW",
                    description=(
                        f"Machine '{claim.holder.name}' claim on scope "
                        f"'{claim.resource.scope or '(root)'}' expires in "
                        f"{remaining / 86400:.1f} days — beyond the override horizon "
                        f"of {self._horizon / 86400:.1f} days. Consider a shorter TTL."
                    ),
                ))
        return risks


# ── helpers ───────────────────────────────────────────────────────────────────

def _chain_depth(claim, all_claims, _seen: frozenset | None = None) -> int:
    """Walk delegated_by chain, returning depth (0 = direct grant)."""
    if _seen is None:
        _seen = frozenset()
    delegated_by = getattr(claim, "delegated_by", None)
    if delegated_by is None:
        return 0
    # Find parent claim
    parent = next(
        (c for c in all_claims if c.holder == delegated_by and id(c) not in _seen),
        None,
    )
    if parent is None:
        return 1
    return 1 + _chain_depth(parent, all_claims, _seen | {id(claim)})
