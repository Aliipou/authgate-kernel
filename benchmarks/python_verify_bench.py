"""
Python-layer performance benchmark — authgate-kernel Phase 1 O4.

Establishes baseline latency numbers for FreedomVerifier.verify() and
AuditLog.append() under realistic conditions.

MASTER_PLAN.md criteria #4: sub-microsecond Rust + documented Python numbers.

Run:
    python benchmarks/python_verify_bench.py

Output example:
    verify() single call:           p50=45µs  p95=78µs  p99=112µs
    verify() 1000-claim registry:   p50=82µs  p95=130µs p99=210µs
    verify_plan() 10-action plan:   p50=420µs throughput=23809 plans/sec
    AuditLog append (in-memory):    p50=12µs  p95=18µs
    AuditLog verify_chain (100 entries): 2.1ms
"""

from __future__ import annotations
import time
import statistics
import sys
import os

# ---------------------------------------------------------------------------
# Setup path
# ---------------------------------------------------------------------------
_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "src"))

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _make_registry(num_claims: int = 10) -> tuple[OwnershipRegistry, Entity, Resource]:
    human = Entity("owner", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    dataset = Resource("dataset", ResourceType.DATASET, scope="/data/")

    registry = OwnershipRegistry()
    registry.register_machine(bot, human)
    registry.add_claim(RightsClaim(bot, dataset, can_read=True, can_write=True))

    # Add extra claims to simulate realistic registry size
    for i in range(num_claims - 1):
        extra_res = Resource(f"res_{i}", ResourceType.FILE, scope=f"/data/res_{i}/")
        registry.add_claim(RightsClaim(bot, extra_res, can_read=True))

    return registry, bot, dataset


def _make_action(bot: Entity, dataset: Resource, action_id: str = "bench-read") -> Action:
    return Action(
        action_id=action_id,
        actor=bot,
        resources_read=[dataset],
    )


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def _bench(fn, warmup: int = 100, iterations: int = 1000) -> dict:
    for _ in range(warmup):
        fn()
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1_000_000)  # microseconds
    return {
        "p50": statistics.median(times),
        "p95": sorted(times)[int(len(times) * 0.95)],
        "p99": sorted(times)[int(len(times) * 0.99)],
        "mean": statistics.mean(times),
        "min": min(times),
        "max": max(times),
    }


def _fmt(stats: dict) -> str:
    return (
        f"p50={stats['p50']:.1f}µs  "
        f"p95={stats['p95']:.1f}µs  "
        f"p99={stats['p99']:.1f}µs  "
        f"mean={stats['mean']:.1f}µs"
    )


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

def bench_single_verify():
    """Single verify() call on a 10-claim registry — baseline overhead."""
    registry, bot, dataset = _make_registry(num_claims=10)
    frozen = registry.freeze()
    verifier = FreedomVerifier(frozen)
    action = _make_action(bot, dataset)

    stats = _bench(lambda: verifier.verify(action))
    print(f"  verify() single call (10 claims):       {_fmt(stats)}")
    return stats


def bench_large_registry_verify():
    """verify() on a 1000-claim registry — scales with registry size."""
    registry, bot, dataset = _make_registry(num_claims=1000)
    frozen = registry.freeze()
    verifier = FreedomVerifier(frozen)
    action = _make_action(bot, dataset)

    stats = _bench(lambda: verifier.verify(action), warmup=20, iterations=500)
    print(f"  verify() 1000-claim registry:           {_fmt(stats)}")
    return stats


def bench_sovereignty_flag_deny():
    """verify() with a sovereignty flag set — should be faster (early exit)."""
    registry, bot, dataset = _make_registry(num_claims=10)
    frozen = registry.freeze()
    verifier = FreedomVerifier(frozen)
    action = Action(
        action_id="bench-deny",
        actor=bot,
        resources_read=[dataset],
        increases_machine_sovereignty=True,  # instant deny
    )
    stats = _bench(lambda: verifier.verify(action))
    print(f"  verify() sovereignty-flag deny:         {_fmt(stats)}")
    return stats


def bench_verify_plan():
    """verify_plan() on a 10-action plan — throughput metric."""
    registry, bot, dataset = _make_registry(num_claims=10)
    frozen = registry.freeze()
    verifier = FreedomVerifier(frozen)
    plan = [_make_action(bot, dataset, action_id=f"step-{i}") for i in range(10)]

    stats = _bench(lambda: verifier.verify_plan(plan), warmup=50, iterations=500)
    throughput = 1_000_000 / stats["p50"]  # plans/sec
    print(f"  verify_plan() 10 actions:               {_fmt(stats)}  throughput={throughput:.0f} plans/s")
    return stats


def bench_audit_append():
    """AuditLog.record() — cost of constitutional logging per verify()."""
    registry, bot, dataset = _make_registry(num_claims=10)
    audit = AuditLog()  # in-memory
    verifier = FreedomVerifier(registry.freeze(), audit_log=audit)
    action = _make_action(bot, dataset)

    def run():
        verifier.verify(action)

    stats = _bench(run, warmup=100, iterations=1000)
    print(f"  verify() + audit append (in-memory):    {_fmt(stats)}")
    return stats


def bench_audit_verify_chain():
    """AuditLog.verify_chain() on a populated log — forensic replay cost."""
    registry, bot, dataset = _make_registry(num_claims=10)
    audit = AuditLog()
    verifier = FreedomVerifier(registry.freeze(), audit_log=audit)
    action = _make_action(bot, dataset)

    # Populate log with 100 entries
    for i in range(100):
        verifier.verify(Action(
            action_id=f"entry-{i}",
            actor=bot,
            resources_read=[dataset],
        ))

    assert len(audit) == 100
    assert audit.verify_chain()

    stats = _bench(lambda: audit.verify_chain(), warmup=10, iterations=200)
    print(f"  AuditLog.verify_chain() (100 entries):  {_fmt(stats)}")
    return stats


def bench_frozen_registry():
    """freeze() cost — called once at verifier init."""
    registry, _, _ = _make_registry(num_claims=1000)
    stats = _bench(lambda: registry.freeze(), warmup=10, iterations=200)
    print(f"  registry.freeze() (1000 claims):        {_fmt(stats)}")
    return stats


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("authgate-kernel Python-layer performance benchmark")
    print("MASTER_PLAN Phase 5.4 — latency baseline")
    print("=" * 65)
    print()

    results = {}
    results["single_verify"]     = bench_single_verify()
    results["large_registry"]    = bench_large_registry_verify()
    results["sovereignty_deny"]  = bench_sovereignty_flag_deny()
    results["verify_plan"]       = bench_verify_plan()
    results["audit_append"]      = bench_audit_append()
    results["audit_chain"]       = bench_audit_verify_chain()
    results["freeze"]            = bench_frozen_registry()

    print()
    print("=" * 65)

    # Check targets
    single_p50 = results["single_verify"]["p50"]
    print()
    print("Target assessment:")
    target_µs = 200.0  # Python layer — 200µs is realistic for Python overhead
    if single_p50 < target_µs:
        print(f"  PASS verify() p50 ({single_p50:.1f}µs) < {target_µs}µs target")
    else:
        print(f"  WARN verify() p50 ({single_p50:.1f}µs) exceeds {target_µs}µs target — "
              f"check registry size or Python overhead")

    sov_p50 = results["sovereignty_deny"]["p50"]
    if sov_p50 < single_p50:
        print(f"  PASS sovereignty flag deny ({sov_p50:.1f}µs) faster than permit path "
              f"({single_p50:.1f}µs) — early exit working")
    else:
        print(f"  WARN sovereignty flag not faster than permit path — check flag check order")

    print()
    print("Note: Rust kernel target is <1µs (see cargo bench --bench verify_bench).")
    print("Python layer is ~50-200x slower — use Rust kernel for latency-sensitive paths.")
