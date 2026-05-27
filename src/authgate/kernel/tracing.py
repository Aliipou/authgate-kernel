"""
Observability tracing for FreedomVerifier.

TraceCollector records each guard check in the verification pipeline with
timing. Attaching one to FreedomVerifier produces VerificationTrace objects
per call that expose the execution graph for debugging and monitoring.

This module is NOT in the TCB — it wraps the verifier without touching
the decision path. A bug here cannot produce a false PERMITTED verdict.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GuardTrace:
    """Record of a single guard check within a verify() call."""
    guard: str               # e.g. "sovereignty_flags", "machine_ownership", "claim_check"
    passed: bool
    duration_us: float       # microseconds
    detail: str = ""         # short description of what was checked


@dataclass
class VerificationTrace:
    """Full execution trace for a single verify() call."""
    action_id: str
    total_duration_us: float
    guards: list[GuardTrace] = field(default_factory=list)
    permitted: bool = False

    def summary(self) -> str:
        status = "PERMITTED" if self.permitted else "BLOCKED"
        lines = [f"[{status}] {self.action_id} ({self.total_duration_us:.1f}µs total)"]
        for g in self.guards:
            mark = "✓" if g.passed else "✗"
            lines.append(f"  {mark} {g.guard:<30} {g.duration_us:6.1f}µs  {g.detail}")
        return "\n".join(lines)


class TraceCollector:
    """
    Attach to FreedomVerifier to collect VerificationTrace objects.

    Usage:
        tracer = TraceCollector()
        verifier = FreedomVerifier(registry, tracer=tracer)
        verifier.verify(action)
        print(tracer.last().summary())
    """

    def __init__(self) -> None:
        self._traces: list[VerificationTrace] = []
        self._current: VerificationTrace | None = None

    def begin(self, action_id: str) -> None:
        self._current = VerificationTrace(action_id=action_id, total_duration_us=0.0)
        self._start = time.perf_counter()

    def record_guard(self, guard: str, passed: bool, detail: str = "") -> None:
        if self._current is None:
            return
        now = time.perf_counter()
        # duration is measured from the previous guard or begin
        last_t = getattr(self, "_guard_start", self._start)
        duration_us = (now - last_t) * 1_000_000
        self._guard_start = now
        self._current.guards.append(GuardTrace(guard=guard, passed=passed, duration_us=duration_us, detail=detail))

    def finish(self, permitted: bool) -> VerificationTrace:
        if self._current is None:
            raise RuntimeError("TraceCollector.finish() called before begin()")
        self._current.permitted = permitted
        self._current.total_duration_us = (time.perf_counter() - self._start) * 1_000_000
        trace = self._current
        self._traces.append(trace)
        self._current = None
        return trace

    def last(self) -> VerificationTrace | None:
        return self._traces[-1] if self._traces else None

    def all(self) -> list[VerificationTrace]:
        return list(self._traces)

    def clear(self) -> None:
        self._traces.clear()
