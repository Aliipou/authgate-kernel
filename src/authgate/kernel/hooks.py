"""
Verification event hooks — lightweight observability for authgate-kernel.

Hooks allow external code to subscribe to verification events without
modifying the kernel. This enables:
  - Metrics collection (permit/deny counters, latency histograms)
  - Alerting (deny on high-value resource, sovereignty flag triggered)
  - Audit correlation (link kernel events to application traces)
  - Testing (assert specific events fired, count calls)

All hooks are called synchronously in verify(). Slow hooks will slow
verify() — use async dispatch or queuing in the hook implementation if needed.

Usage:
    from authgate.kernel.hooks import VerificationHook, HookRegistry

    def my_hook(event: VerificationEvent) -> None:
        metrics.increment("authgate.verify", tags={"permitted": event.permitted})

    HookRegistry.register(my_hook)

    # Hooks are called automatically by FreedomVerifier.verify()
    # when HookRegistry is wired in (see FreedomVerifier.__init__ hook_registry param)
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass(frozen=True)
class VerificationEvent:
    """Emitted after every FreedomVerifier.verify() call."""
    action_id: str
    actor_name: str
    permitted: bool
    confidence: float
    violation_count: int
    warning_count: int
    requires_arbitration: bool
    duration_ms: float  # wall-clock time for this verify() call


VerificationHook = Callable[[VerificationEvent], None]


class HookRegistry:
    """
    Thread-safe registry of verification event hooks.

    Hooks are called in registration order. Exceptions in hooks are caught
    and do not propagate to the caller — the kernel decision is never affected
    by hook failures.
    """
    _lock: threading.Lock = threading.Lock()
    _hooks: list[VerificationHook] = []

    @classmethod
    def register(cls, hook: VerificationHook) -> None:
        """Register a hook. Called every time verify() completes."""
        with cls._lock:
            cls._hooks.append(hook)

    @classmethod
    def unregister(cls, hook: VerificationHook) -> None:
        """Unregister a previously registered hook."""
        with cls._lock:
            try:
                cls._hooks.remove(hook)
            except ValueError:
                pass

    @classmethod
    def clear(cls) -> None:
        """Remove all hooks. Use in test teardown."""
        with cls._lock:
            cls._hooks.clear()

    @classmethod
    def emit(cls, event: VerificationEvent) -> None:
        """Emit an event to all registered hooks. Exceptions are swallowed."""
        with cls._lock:
            hooks = list(cls._hooks)
        for hook in hooks:
            try:
                hook(event)
            except Exception:
                pass  # hooks must never affect the kernel decision

    @classmethod
    def hook_count(cls) -> int:
        with cls._lock:
            return len(cls._hooks)


class MetricsCollector:
    """
    Simple built-in metrics collector — no external dependencies.

    Tracks permit/deny counts, running latency average, and violation/warning counts.
    Thread-safe. Reset with reset().

    Usage:
        collector = MetricsCollector()
        HookRegistry.register(collector.on_event)
        # ... run verifications ...
        print(collector.summary())
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._permit_count = 0
        self._deny_count = 0
        self._total_duration_ms = 0.0
        self._total_violations = 0
        self._total_warnings = 0
        self._arbitration_count = 0

    def on_event(self, event: VerificationEvent) -> None:
        with self._lock:
            if event.permitted:
                self._permit_count += 1
            else:
                self._deny_count += 1
            self._total_duration_ms += event.duration_ms
            self._total_violations += event.violation_count
            self._total_warnings += event.warning_count
            if event.requires_arbitration:
                self._arbitration_count += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            total = self._permit_count + self._deny_count
            avg_ms = (self._total_duration_ms / total) if total > 0 else 0.0
            return {
                "total": total,
                "permitted": self._permit_count,
                "denied": self._deny_count,
                "avg_duration_ms": round(avg_ms, 3),
                "total_violations": self._total_violations,
                "total_warnings": self._total_warnings,
                "arbitration_required": self._arbitration_count,
            }

    def summary(self) -> str:
        s = self.snapshot()
        deny_rate = (s["denied"] / s["total"] * 100) if s["total"] > 0 else 0.0
        return (
            f"authgate metrics: {s['total']} calls, "
            f"{s['permitted']} permit, {s['denied']} deny ({deny_rate:.1f}%), "
            f"avg {s['avg_duration_ms']:.3f}ms, "
            f"{s['total_violations']} violations, "
            f"{s['arbitration_required']} arbitration"
        )

    def reset(self) -> None:
        with self._lock:
            self._permit_count = 0
            self._deny_count = 0
            self._total_duration_ms = 0.0
            self._total_violations = 0
            self._total_warnings = 0
            self._arbitration_count = 0
