"""
DRE Performance Benchmark

Measures DRE evaluation latency on a history store with 10k entries.
Target: p99 < 5ms per evaluation.

Usage:
    PYTHONPATH=src python benchmarks/dre_benchmark.py
"""
from __future__ import annotations

import statistics
import time
from typing import Any

from authgate.extensions.delegate_reputation import (
    DEFAULT_NDC_RISK,
    DelegateReputationEngine,
    NDC,
)
from authgate.extensions.historical_behavior_store import BehaviorRecord, HistoricalBehaviorStore
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType
from authgate.kernel.verifier import Action, VerificationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_action(actor_name: str = "bot") -> Action:
    return Action(
        action_id="benchmark-action",
        actor=Entity(actor_name, AgentType.MACHINE),
        resources_read=[Resource("sales-data", ResourceType.DATASET, scope="/data/sales/")],
    )


def _make_permitted_result() -> VerificationResult:
    return VerificationResult(
        action_id="benchmark-action",
        permitted=True,
        violations=(),
        warnings=(),
        confidence=1.0,
        requires_human_arbitration=False,
    )


def _seed_hbs(hbs: HistoricalBehaviorStore, actor_id: str, count: int) -> None:
    """Populate HBS with `count` records for a single actor."""
    now = time.time()
    for i in range(count):
        # Mix of permitted/denied, some with flags, varying resources
        result = "denied" if i % 10 == 0 else "permitted"
        flagged = 1 if i % 20 == 0 else 0
        resources = (f"resource-{i % 100}",)
        hbs.append(BehaviorRecord(
            ts=now - (i * 3600),  # spaced 1 hour apart, within 90 days
            actor_id=actor_id,
            action_id=f"action-{i:05d}",
            result=result,
            sovereignty_flags_triggered=flagged,
            violations=("FORBIDDEN",) if flagged else (),
            warnings=(),
            ndc="LLM_CLOSED",
            delegation_depth=1,
            resources_accessed=resources,
            external_attestation_valid=True,
            confidence=1.0,
        ))


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark_dre_latency(
    history_size: int = 10_000,
    evaluations: int = 1_000,
    warmup: int = 100,
) -> dict[str, Any]:
    """Run benchmark and return latency statistics."""
    hbs = HistoricalBehaviorStore(":memory:")
    actor_id = "MACHINE:bot"
    _seed_hbs(hbs, actor_id, history_size)

    engine = DelegateReputationEngine(
        hbs=hbs,
        threshold=1.0,
        window_days=90,
    )

    action = _make_action()
    base_result = _make_permitted_result()

    # Warmup
    for _ in range(warmup):
        engine.evaluate(action, base_result, ndc=NDC.LLM_CLOSED)

    # Timed runs
    latencies_ms: list[float] = []
    for _ in range(evaluations):
        t0 = time.perf_counter()
        engine.evaluate(action, base_result, ndc=NDC.LLM_CLOSED)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000)

    engine.close()

    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]
    p999 = latencies_ms[int(len(latencies_ms) * 0.999)]
    mean = statistics.mean(latencies_ms)
    std = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0.0
    min_ms = latencies_ms[0]
    max_ms = latencies_ms[-1]

    return {
        "history_size": history_size,
        "evaluations": evaluations,
        "mean_ms": round(mean, 3),
        "std_ms": round(std, 3),
        "min_ms": round(min_ms, 3),
        "p50_ms": round(p50, 3),
        "p99_ms": round(p99, 3),
        "p99.9_ms": round(p999, 3),
        "max_ms": round(max_ms, 3),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("DRE Performance Benchmark")
    print("=" * 60)

    result = benchmark_dre_latency(history_size=10_000, evaluations=1_000, warmup=100)

    print(f"History store size: {result['history_size']:,} entries")
    print(f"Evaluations:        {result['evaluations']:,}")
    print()
    print(f"Mean:   {result['mean_ms']:>8.3f} ms")
    print(f"Std:    {result['std_ms']:>8.3f} ms")
    print(f"Min:    {result['min_ms']:>8.3f} ms")
    print(f"p50:    {result['p50_ms']:>8.3f} ms")
    print(f"p99:    {result['p99_ms']:>8.3f} ms")
    print(f"p99.9:  {result['p99.9_ms']:>8.3f} ms")
    print(f"Max:    {result['max_ms']:>8.3f} ms")
    print()

    target = 5.0
    if result["p99_ms"] < target:
        print(f"✅ PASS — p99 ({result['p99_ms']:.3f} ms) < target ({target} ms)")
    else:
        print(f"❌ FAIL — p99 ({result['p99_ms']:.3f} ms) >= target ({target} ms)")
