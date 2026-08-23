"""
HBS write-protection layer — rate-limiting and anomaly detection for the
HistoricalBehaviorStore.

This module provides a GuardedBehaviorStore wrapper that prevents history
poisoning, burst attacks, and NDC spoofing by validating writes before they
reach the underlying store.

SECURITY NOTE: These guards are heuristic defenses. A determined attacker with
write access to the HBS can still poison it, but these measures raise the cost
and create audit noise.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from authgate.extensions.historical_behavior_store import (
    BehaviorRecord,
    HistoricalBehaviorStore,
)

logger = logging.getLogger("authgate.extensions.hbs_protection")


@dataclass(frozen=True)
class WriteGuardResult:
    """Result of a write-guard check."""
    allowed: bool
    reason: str = ""
    severity: str = "info"  # info | warning | block


@dataclass
class _ActorWindow:
    """Sliding-window state for a single actor."""
    writes: deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    last_ndc: str | None = None
    ndc_change_count: int = 0
    daily_resources: set[str] = field(default_factory=set)
    last_resource_reset: float = field(default_factory=time.time)


class GuardedBehaviorStore:
    """
    Wrapper around HistoricalBehaviorStore with write guards.

    Guards (all configurable, all disabled by default):
      - rate_limit: max writes per actor per window_seconds
      - burst_threshold: flag if more than N writes in window_seconds
      - ndc_mismatch_limit: flag after N NDC changes in window_seconds
      - daily_resource_limit: flag if actor touches >N unique resources/day
    """

    def __init__(
        self,
        store: HistoricalBehaviorStore,
        *,
        rate_limit: int | None = None,
        rate_window_seconds: float = 60.0,
        burst_threshold: int | None = None,
        burst_window_seconds: float = 60.0,
        ndc_mismatch_limit: int | None = None,
        ndc_window_seconds: float = 3600.0,
        daily_resource_limit: int | None = None,
    ) -> None:
        self.store = store
        self.rate_limit = rate_limit
        self.rate_window = rate_window_seconds
        self.burst_threshold = burst_threshold
        self.burst_window = burst_window_seconds
        self.ndc_mismatch_limit = ndc_mismatch_limit
        self.ndc_window = ndc_window_seconds
        self.daily_resource_limit = daily_resource_limit

        self._actor_state: dict[str, _ActorWindow] = defaultdict(_ActorWindow)
        self._global_last_prune = time.time()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, record: BehaviorRecord) -> WriteGuardResult:
        """
        Append a record if all guards pass. Returns WriteGuardResult.
        If blocked, the record is NOT written.
        """
        actor_id = record.actor_id
        now = record.ts
        state = self._actor_state[actor_id]

        # 1. Rate limit
        if self.rate_limit is not None:
            recent_writes = self._count_in_window(state.writes, now, self.rate_window)
            if recent_writes >= self.rate_limit:
                logger.warning(
                    "HBS rate limit hit for %s (%d writes in %.0fs)",
                    actor_id, recent_writes, self.rate_window,
                )
                return WriteGuardResult(
                    allowed=False,
                    reason=f"rate limit: {self.rate_limit} writes per {self.rate_window:.0f}s",
                    severity="block",
                )

        # 2. Burst detection
        if self.burst_threshold is not None:
            recent_writes = self._count_in_window(state.writes, now, self.burst_window)
            if recent_writes >= self.burst_threshold:
                logger.warning(
                    "HBS burst detected for %s (%d writes in %.0fs)",
                    actor_id, recent_writes, self.burst_window,
                )
                return WriteGuardResult(
                    allowed=False,
                    reason=f"burst: {recent_writes} writes in {self.burst_window:.0f}s",
                    severity="block",
                )

        # 3. NDC mismatch / spoofing detection
        if self.ndc_mismatch_limit is not None:
            if state.last_ndc is not None and state.last_ndc != record.ndc:
                state.ndc_change_count += 1
                logger.info(
                    "NDC change for %s: %s -> %s (count=%d)",
                    actor_id, state.last_ndc, record.ndc, state.ndc_change_count,
                )
            state.last_ndc = record.ndc

            # Prune old NDC changes
            self._prune_actor_state(actor_id, now)
            if state.ndc_change_count >= self.ndc_mismatch_limit:
                return WriteGuardResult(
                    allowed=False,
                    reason=f"NDC spoofing: {state.ndc_change_count} changes in {self.ndc_window:.0f}s",
                    severity="block",
                )

        # 4. Daily resource breadth explosion
        if self.daily_resource_limit is not None:
            # Reset daily counter if >24h since last reset
            if now - state.last_resource_reset > 86400:
                state.daily_resources.clear()
                state.last_resource_reset = now

            state.daily_resources.update(record.resources_accessed)
            if len(state.daily_resources) > self.daily_resource_limit:
                return WriteGuardResult(
                    allowed=False,
                    reason=f"resource breadth: {len(state.daily_resources)} unique resources today",
                    severity="block",
                )

        # All guards passed — write to store
        state.writes.append(now)
        self.store.append(record)
        return WriteGuardResult(allowed=True, reason="ok", severity="info")

    def query(self, actor_id: str, window_days: int = 90) -> list[BehaviorRecord]:
        return self.store.query(actor_id, window_days)

    def query_flagged(self, actor_id: str, window_days: int = 90) -> list[BehaviorRecord]:
        return self.store.query_flagged(actor_id, window_days)

    def count_actions(self, actor_id: str, window_days: int = 90) -> int:
        return self.store.count_actions(actor_id, window_days)

    def unique_resources(self, actor_id: str, window_days: int = 90) -> set[str]:
        return self.store.unique_resources(actor_id, window_days)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_in_window(timestamps: deque[float], now: float, window: float) -> int:
        """Count timestamps within [now - window, now]."""
        cutoff = now - window
        return sum(1 for ts in timestamps if ts >= cutoff)

    def _prune_actor_state(self, actor_id: str, now: float) -> None:
        """Remove stale NDC change counts and old write timestamps."""
        state = self._actor_state[actor_id]
        cutoff = now - self.ndc_window
        # We don't have per-change timestamps, so we decay by halving
        # if the window has passed since the last prune.
        if now - self._global_last_prune > self.ndc_window:
            state.ndc_change_count = max(0, state.ndc_change_count // 2)
            self._global_last_prune = now
