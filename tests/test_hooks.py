"""Tests for authgate.kernel.hooks — HookRegistry and MetricsCollector."""
from __future__ import annotations

import threading
import pytest

from authgate.kernel.hooks import (
    HookRegistry,
    MetricsCollector,
    VerificationEvent,
)
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.entities import AgentType, Entity
from authgate.kernel.registry import OwnershipRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    *,
    permitted: bool = True,
    confidence: float = 1.0,
    violation_count: int = 0,
    warning_count: int = 0,
    requires_arbitration: bool = False,
    duration_ms: float = 1.0,
) -> VerificationEvent:
    return VerificationEvent(
        action_id="test-action",
        actor_name="bot",
        permitted=permitted,
        confidence=confidence,
        violation_count=violation_count,
        warning_count=warning_count,
        requires_arbitration=requires_arbitration,
        duration_ms=duration_ms,
    )


def _registry() -> OwnershipRegistry:
    r = OwnershipRegistry()
    ali = Entity("ali", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    r.register_machine(bot, ali)
    return r


def _permit_action() -> Action:
    return Action(action_id="read-data", actor=Entity("bot", AgentType.MACHINE))


def _deny_action() -> Action:
    return Action(
        action_id="bad-action",
        actor=Entity("bot", AgentType.MACHINE),
        increases_machine_sovereignty=True,
    )


# ---------------------------------------------------------------------------
# HookRegistry
# ---------------------------------------------------------------------------

class TestHookRegistry:
    def setup_method(self):
        HookRegistry.clear()

    def teardown_method(self):
        HookRegistry.clear()

    def test_register_increments_count(self):
        assert HookRegistry.hook_count() == 0
        HookRegistry.register(lambda e: None)
        assert HookRegistry.hook_count() == 1

    def test_unregister_decrements_count(self):
        fn = lambda e: None
        HookRegistry.register(fn)
        HookRegistry.unregister(fn)
        assert HookRegistry.hook_count() == 0

    def test_unregister_nonexistent_is_noop(self):
        HookRegistry.unregister(lambda e: None)  # must not raise

    def test_clear_removes_all(self):
        HookRegistry.register(lambda e: None)
        HookRegistry.register(lambda e: None)
        HookRegistry.clear()
        assert HookRegistry.hook_count() == 0

    def test_emit_calls_hook(self):
        received = []
        HookRegistry.register(received.append)
        ev = _event()
        HookRegistry.emit(ev)
        assert received == [ev]

    def test_emit_calls_multiple_hooks_in_order(self):
        order = []
        HookRegistry.register(lambda e: order.append(1))
        HookRegistry.register(lambda e: order.append(2))
        HookRegistry.emit(_event())
        assert order == [1, 2]

    def test_hook_exception_does_not_propagate(self):
        def bad_hook(e):
            raise RuntimeError("boom")

        good_received = []
        HookRegistry.register(bad_hook)
        HookRegistry.register(good_received.append)
        HookRegistry.emit(_event())
        assert len(good_received) == 1  # second hook still ran

    def test_emit_with_no_hooks_is_noop(self):
        HookRegistry.emit(_event())  # must not raise

    def test_thread_safety_concurrent_registration(self):
        errors = []

        def register_hook(i):
            try:
                HookRegistry.register(lambda e, _i=i: None)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=register_hook, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert HookRegistry.hook_count() == 50

    def test_emit_receives_correct_event_fields(self):
        received: list[VerificationEvent] = []
        HookRegistry.register(received.append)
        ev = VerificationEvent(
            action_id="ev-id",
            actor_name="tester",
            permitted=False,
            confidence=0.75,
            violation_count=2,
            warning_count=1,
            requires_arbitration=True,
            duration_ms=42.0,
        )
        HookRegistry.emit(ev)
        assert len(received) == 1
        r = received[0]
        assert r.action_id == "ev-id"
        assert r.actor_name == "tester"
        assert r.permitted is False
        assert r.confidence == 0.75
        assert r.violation_count == 2
        assert r.warning_count == 1
        assert r.requires_arbitration is True
        assert r.duration_ms == 42.0


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------

class TestMetricsCollector:
    def test_initial_snapshot_is_zero(self):
        c = MetricsCollector()
        s = c.snapshot()
        assert s["total"] == 0
        assert s["permitted"] == 0
        assert s["denied"] == 0
        assert s["avg_duration_ms"] == 0.0
        assert s["total_violations"] == 0
        assert s["total_warnings"] == 0
        assert s["arbitration_required"] == 0

    def test_permit_counted(self):
        c = MetricsCollector()
        c.on_event(_event(permitted=True))
        s = c.snapshot()
        assert s["permitted"] == 1
        assert s["denied"] == 0
        assert s["total"] == 1

    def test_deny_counted(self):
        c = MetricsCollector()
        c.on_event(_event(permitted=False, violation_count=1))
        s = c.snapshot()
        assert s["denied"] == 1
        assert s["total_violations"] == 1

    def test_avg_duration_single(self):
        c = MetricsCollector()
        c.on_event(_event(duration_ms=10.0))
        assert c.snapshot()["avg_duration_ms"] == 10.0

    def test_avg_duration_multiple(self):
        c = MetricsCollector()
        c.on_event(_event(duration_ms=10.0))
        c.on_event(_event(duration_ms=20.0))
        assert c.snapshot()["avg_duration_ms"] == 15.0

    def test_warning_counted(self):
        c = MetricsCollector()
        c.on_event(_event(warning_count=3))
        assert c.snapshot()["total_warnings"] == 3

    def test_arbitration_counted(self):
        c = MetricsCollector()
        c.on_event(_event(requires_arbitration=True))
        assert c.snapshot()["arbitration_required"] == 1

    def test_arbitration_not_counted_when_false(self):
        c = MetricsCollector()
        c.on_event(_event(requires_arbitration=False))
        assert c.snapshot()["arbitration_required"] == 0

    def test_reset_clears_all(self):
        c = MetricsCollector()
        c.on_event(_event(permitted=True, duration_ms=5.0))
        c.on_event(_event(permitted=False, violation_count=1))
        c.reset()
        s = c.snapshot()
        assert s["total"] == 0
        assert s["avg_duration_ms"] == 0.0

    def test_summary_string_format(self):
        c = MetricsCollector()
        c.on_event(_event(permitted=True, duration_ms=5.0))
        c.on_event(_event(permitted=False, violation_count=1, duration_ms=15.0))
        out = c.summary()
        assert "2 calls" in out
        assert "1 permit" in out
        assert "1 deny" in out
        assert "50.0%" in out
        assert "10.000ms" in out

    def test_thread_safe_concurrent_events(self):
        c = MetricsCollector()
        errors = []

        def emit_events():
            try:
                for _ in range(100):
                    c.on_event(_event(permitted=True, duration_ms=1.0))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=emit_events) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert c.snapshot()["total"] == 1000
        assert c.snapshot()["permitted"] == 1000


# ---------------------------------------------------------------------------
# Integration: HookRegistry wired into FreedomVerifier
# ---------------------------------------------------------------------------

class TestVerifierHookIntegration:
    def setup_method(self):
        HookRegistry.clear()

    def teardown_method(self):
        HookRegistry.clear()

    def test_permit_fires_hook(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_permit_action())
        assert len(received) == 1
        assert received[0].permitted is True

    def test_deny_fires_hook(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_deny_action())
        assert len(received) == 1
        assert received[0].permitted is False
        assert received[0].violation_count > 0

    def test_hook_event_has_action_id(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_permit_action())
        assert received[0].action_id == "read-data"

    def test_hook_event_actor_name(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_permit_action())
        assert received[0].actor_name == "bot"

    def test_hook_duration_positive(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_permit_action())
        assert received[0].duration_ms >= 0.0

    def test_metrics_collector_via_verifier(self):
        collector = MetricsCollector()
        HookRegistry.register(collector.on_event)
        verifier = FreedomVerifier(_registry())
        verifier.verify(_permit_action())
        verifier.verify(_deny_action())
        s = collector.snapshot()
        assert s["total"] == 2
        assert s["permitted"] == 1
        assert s["denied"] == 1

    def test_no_hooks_verify_still_works(self):
        verifier = FreedomVerifier(_registry())
        result = verifier.verify(_permit_action())
        assert result.permitted is True

    def test_verify_plan_fires_one_hook_per_action(self):
        received = []
        HookRegistry.register(received.append)
        verifier = FreedomVerifier(_registry())
        verifier.verify_plan([_permit_action(), _permit_action()])
        assert len(received) == 2
