"""
Tests for HBS write-protection layer (rate-limiting, burst detection,
NDC spoofing detection, resource breadth limits).
"""
from __future__ import annotations

import time

import pytest

from authgate.extensions.hbs_protection import GuardedBehaviorStore, WriteGuardResult
from authgate.extensions.historical_behavior_store import BehaviorRecord, HistoricalBehaviorStore


@pytest.fixture
def hbs() -> HistoricalBehaviorStore:
    return HistoricalBehaviorStore(":memory:")


def _make_record(actor_id: str = "bot", ndc: str = "LLM_CLOSED", resources: tuple[str, ...] = ()) -> BehaviorRecord:
    return BehaviorRecord(
        ts=time.time(),
        actor_id=actor_id,
        action_id="action-001",
        result="permitted",
        sovereignty_flags_triggered=0,
        violations=(),
        warnings=(),
        ndc=ndc,
        delegation_depth=1,
        resources_accessed=resources,
        external_attestation_valid=True,
        confidence=1.0,
    )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_blocks_after_threshold(hbs: HistoricalBehaviorStore) -> None:
    """GuardedBehaviorStore should block writes beyond rate_limit."""
    guard = GuardedBehaviorStore(hbs, rate_limit=3, rate_window_seconds=60.0)

    for i in range(3):
        r = _make_record()
        r = BehaviorRecord(**{**r.__dict__, "action_id": f"action-{i}"})
        result = guard.append(r)
        assert result.allowed is True

    # 4th write should be blocked
    result = guard.append(_make_record())
    assert result.allowed is False
    assert "rate limit" in result.reason.lower()
    assert result.severity == "block"


def test_rate_limit_resets_after_window(hbs: HistoricalBehaviorStore) -> None:
    """Rate limit should reset after window_seconds passes."""
    guard = GuardedBehaviorStore(hbs, rate_limit=2, rate_window_seconds=1.0)

    for _ in range(2):
        assert guard.append(_make_record()).allowed is True

    assert guard.append(_make_record()).allowed is False

    # Wait for window to expire
    time.sleep(1.1)
    assert guard.append(_make_record()).allowed is True


# ---------------------------------------------------------------------------
# Burst detection
# ---------------------------------------------------------------------------

def test_burst_detection_blocks_flood(hbs: HistoricalBehaviorStore) -> None:
    """Burst detection should block rapid-fire writes."""
    guard = GuardedBehaviorStore(hbs, burst_threshold=5, burst_window_seconds=60.0)

    for i in range(5):
        r = _make_record()
        r = BehaviorRecord(**{**r.__dict__, "action_id": f"action-{i}"})
        assert guard.append(r).allowed is True

    result = guard.append(_make_record())
    assert result.allowed is False
    assert "burst" in result.reason.lower()


# ---------------------------------------------------------------------------
# NDC spoofing detection
# ---------------------------------------------------------------------------

def test_ndc_mismatch_blocks_after_limit(hbs: HistoricalBehaviorStore) -> None:
    """Frequent NDC changes should be flagged as spoofing."""
    guard = GuardedBehaviorStore(hbs, ndc_mismatch_limit=3, ndc_window_seconds=60.0)

    # First NDC
    assert guard.append(_make_record(ndc="LLM_CLOSED")).allowed is True
    # Switch once
    assert guard.append(_make_record(ndc="DETERMINISTIC")).allowed is True
    # Switch twice
    assert guard.append(_make_record(ndc="LLM_CLOSED")).allowed is True

    # Third switch should block
    result = guard.append(_make_record(ndc="SWARM"))
    assert result.allowed is False
    assert "NDC spoofing" in result.reason


def test_ndc_stable_passes(hbs: HistoricalBehaviorStore) -> None:
    """Same NDC repeatedly should never trigger mismatch guard."""
    guard = GuardedBehaviorStore(hbs, ndc_mismatch_limit=3, ndc_window_seconds=60.0)

    for _ in range(10):
        assert guard.append(_make_record(ndc="LLM_CLOSED")).allowed is True


# ---------------------------------------------------------------------------
# Daily resource breadth limit
# ---------------------------------------------------------------------------

def test_resource_breadth_blocks_after_limit(hbs: HistoricalBehaviorStore) -> None:
    """Accessing too many unique resources in a day should block."""
    guard = GuardedBehaviorStore(hbs, daily_resource_limit=5)

    for i in range(5):
        r = _make_record(resources=(f"res-{i}",))
        assert guard.append(r).allowed is True

    # 6th unique resource should block
    result = guard.append(_make_record(resources=("res-5",)))
    assert result.allowed is False
    assert "resource breadth" in result.reason.lower()


def test_resource_breadth_allows_reuse(hbs: HistoricalBehaviorStore) -> None:
    """Re-accessing the same resource should not count toward the limit."""
    guard = GuardedBehaviorStore(hbs, daily_resource_limit=3)

    for _ in range(10):
        assert guard.append(_make_record(resources=("res-a",))).allowed is True


# ---------------------------------------------------------------------------
# Combined guards
# ---------------------------------------------------------------------------

def test_combined_guards_all_enabled(hbs: HistoricalBehaviorStore) -> None:
    """All guards should work together without interference."""
    guard = GuardedBehaviorStore(
        hbs,
        rate_limit=100,
        burst_threshold=10,
        ndc_mismatch_limit=5,
        daily_resource_limit=50,
    )

    for i in range(9):
        r = _make_record(resources=(f"res-{i}",))
        assert guard.append(r).allowed is True

    # Verify store received all 20 records
    assert hbs.count_actions("bot", window_days=1) == 9


# ---------------------------------------------------------------------------
# Pass-through methods
# ---------------------------------------------------------------------------

def test_query_passes_through(hbs: HistoricalBehaviorStore) -> None:
    guard = GuardedBehaviorStore(hbs)
    guard.append(_make_record())
    assert len(guard.query("bot")) == 1


def test_count_actions_passes_through(hbs: HistoricalBehaviorStore) -> None:
    guard = GuardedBehaviorStore(hbs)
    guard.append(_make_record())
    assert guard.count_actions("bot", window_days=1) == 1
