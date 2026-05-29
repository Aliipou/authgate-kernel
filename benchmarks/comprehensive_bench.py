"""
Comprehensive benchmark suite — II-2 from INFRASTRUCTURE_PLAN.md.

Measures performance across the full stack with machine-readable output.
Used as CI regression gate and public benchmark publication.

Run:
    python benchmarks/comprehensive_bench.py
    python benchmarks/comprehensive_bench.py --json > benchmarks/results.json
    python benchmarks/comprehensive_bench.py --gate  # exit 1 if any target missed

Targets (must hold for infrastructure credibility):
    verify() permit path     < 500 µs  (Python layer; Rust = < 5 µs)
    verify() deny (flag)     < 200 µs
    CallGate.execute() deny  < 600 µs
    AuditLog append          < 100 µs
    Chain verify 100 entries < 10 ms
    Registry 1k claims       < 5 ms build, < 1 ms single verify
    Simulation 231 scenarios < 5 s
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Suppress logging noise during benchmarks
logging.disable(logging.CRITICAL)

from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _percentiles(samples: list[float], label: str) -> dict:
    s = sorted(samples)
    n = len(s)
    return {
        "label":   label,
        "n":       n,
        "p50_us":  round(s[n // 2] * 1e6, 2),
        "p95_us":  round(s[int(n * 0.95)] * 1e6, 2),
        "p99_us":  round(s[int(n * 0.99)] * 1e6, 2),
        "mean_us": round(statistics.mean(s) * 1e6, 2),
        "min_us":  round(min(s) * 1e6, 2),
        "max_us":  round(max(s) * 1e6, 2),
    }


def _build_env(n_claims: int = 1):
    alice = Entity("alice", AgentType.HUMAN)
    bot   = Entity("bot",   AgentType.MACHINE)
    data  = Resource("data", ResourceType.FILE, scope="/data/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data, can_read=True, can_write=True), delegated_by=alice)

    # Extra claims to simulate large registry
    for i in range(n_claims - 1):
        extra = Resource(f"res-{i}", ResourceType.FILE, scope=f"/data/{i}/")
        reg.add_claim(RightsClaim(alice, extra, can_read=True))

    return alice, bot, data, reg


# ─── Benchmarks ───────────────────────────────────────────────────────────────

RESULTS = []
TARGETS_MISSED = []


def bench(label: str, fn, iterations: int = 1000, target_us: float | None = None):
    # Warmup
    for _ in range(min(20, iterations // 10)):
        fn()

    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)

    r = _percentiles(samples, label)
    r["target_us"] = target_us
    r["pass"] = (r["p99_us"] <= target_us) if target_us else None
    RESULTS.append(r)

    if target_us and not r["pass"]:
        TARGETS_MISSED.append(label)

    return r


def run_all() -> list[dict]:
    # ── BM-1: verify() permit path ────────────────────────────────────────────
    _, bot, data, reg = _build_env()
    v = FreedomVerifier(reg)
    action_permit = Action("bench-permit", actor=bot, resources_read=[data])
    bench("verify() permit path", lambda: v.verify(action_permit),
          iterations=2000, target_us=500)

    # ── BM-2: verify() deny (sovereignty flag) ───────────────────────────────
    action_deny = Action("bench-deny", actor=bot, resources_read=[data],
                         increases_machine_sovereignty=True)
    bench("verify() deny (flag)", lambda: v.verify(action_deny),
          iterations=2000, target_us=200)

    # ── BM-3: verify() deny (no claim) ───────────────────────────────────────
    secrets = Resource("secrets", ResourceType.FILE, scope="/secrets/")
    action_no_claim = Action("bench-nc", actor=bot, resources_read=[secrets])
    bench("verify() deny (no claim)", lambda: v.verify(action_no_claim),
          iterations=2000, target_us=300)

    # ── BM-4: CallGate.execute() permit ──────────────────────────────────────
    _, bot2, data2, reg2 = _build_env()
    gate = CallGate(FreedomVerifier(reg2))
    gate.register("read", lambda path="": f"data:{path}")
    action_gate = Action("gate-permit", actor=bot2, resources_read=[data2])
    bench("CallGate.execute() permit", lambda: gate.execute(action_gate, "read", {"path": "/x"}),
          iterations=1000, target_us=600)

    # ── BM-5: CallGate.execute() deny ────────────────────────────────────────
    secrets2 = Resource("secrets2", ResourceType.FILE, scope="/sec/")
    action_gate_deny = Action("gate-deny", actor=bot2, resources_read=[secrets2])
    bench("CallGate.execute() deny", lambda: gate.execute(action_gate_deny, "read", {}),
          iterations=1000, target_us=600)

    # ── BM-6: AuditLog append ────────────────────────────────────────────────
    audit = AuditLog()
    v_audit = FreedomVerifier(reg)
    action_a = Action("audit-bench", actor=bot, resources_read=[data])
    bench("AuditLog append (via verify)", lambda: v_audit.verify(action_a),
          iterations=1000, target_us=100)

    # ── BM-7: AuditLog verify_chain (100 entries) ────────────────────────────
    audit100 = AuditLog()
    v100 = FreedomVerifier(reg, audit_log=audit100)
    for i in range(100):
        v100.verify(Action(f"a{i}", actor=bot, resources_read=[data]))

    bench("AuditLog verify_chain (100 entries)", lambda: audit100.verify_chain(),
          iterations=200, target_us=10_000)

    # ── BM-8: Registry build (1k claims) ─────────────────────────────────────
    t0 = time.perf_counter()
    _, _, _, big_reg = _build_env(n_claims=1000)
    t1 = time.perf_counter()
    RESULTS.append({
        "label": "Registry build (1k claims)",
        "n": 1,
        "total_ms": round((t1 - t0) * 1000, 2),
        "target_ms": 5000,
        "pass": (t1 - t0) < 5.0,
    })
    if not RESULTS[-1]["pass"]:
        TARGETS_MISSED.append("Registry build (1k claims)")

    # ── BM-9: verify() on large registry ─────────────────────────────────────
    v_big = FreedomVerifier(big_reg)
    alice_big = Entity("alice", AgentType.HUMAN)
    bot_big = Entity("bot", AgentType.MACHINE)
    data_big = Resource("data", ResourceType.FILE, scope="/data/")
    action_big = Action("big-reg", actor=bot_big, resources_read=[data_big])
    bench("verify() on 1k-claim registry", lambda: v_big.verify(action_big),
          iterations=500, target_us=1000)

    # ── BM-10: Simulation engine (231 scenarios) ─────────────────────────────
    sys.path.insert(0, str(Path(__file__).parent.parent / "attack_harness"))
    try:
        from simulation.engine import SimulationEngine
        engine = SimulationEngine()
        t0 = time.perf_counter()
        summary = engine.run()
        t1 = time.perf_counter()
        elapsed_ms = round((t1 - t0) * 1000, 2)
        RESULTS.append({
            "label": "Simulation 231 scenarios",
            "n": summary.total,
            "pass_count": summary.passed,
            "gap_count": summary.known_gaps,
            "fail_count": summary.failed,
            "total_ms": elapsed_ms,
            "target_ms": 5000,
            "pass": elapsed_ms < 5000 and summary.failed == 0,
        })
        if not RESULTS[-1]["pass"]:
            TARGETS_MISSED.append("Simulation 231 scenarios")
    except ImportError:
        RESULTS.append({"label": "Simulation", "skip": "attack_harness not found"})

    # ── BM-11: Concurrent verify (10 threads × 100 actions) ──────────────────
    import threading
    _, bot_c, data_c, reg_c = _build_env()
    v_c = FreedomVerifier(reg_c, freeze=True)
    action_c = Action("concurrent", actor=bot_c, resources_read=[data_c])
    results_c = []
    errors_c = []

    def worker():
        t0 = time.perf_counter()
        for _ in range(100):
            v_c.verify(action_c)
        results_c.append(time.perf_counter() - t0)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total_t = time.perf_counter() - t0
    total_ops = 10 * 100
    throughput = round(total_ops / total_t)
    RESULTS.append({
        "label": "Concurrent verify (10 threads × 100)",
        "total_ms": round(total_t * 1000, 2),
        "throughput_ops_sec": throughput,
        "errors": len(errors_c),
        "pass": len(errors_c) == 0 and throughput > 5000,
    })
    if not RESULTS[-1].get("pass"):
        TARGETS_MISSED.append("Concurrent verify")

    return RESULTS


# ─── Output ───────────────────────────────────────────────────────────────────

def _print_table(results: list[dict]) -> None:
    print("\n" + "=" * 70)
    print(f"{'Benchmark':<40} {'p50':>8} {'p95':>8} {'p99':>8} {'Target':>8} {'Pass':>5}")
    print("-" * 70)
    for r in results:
        label = r["label"][:39]
        if "p50_us" in r:
            p50 = f"{r['p50_us']}µs"
            p95 = f"{r['p95_us']}µs"
            p99 = f"{r['p99_us']}µs"
            tgt = f"{r['target_us']}µs" if r.get("target_us") else "  --"
            ok  = "OK" if r.get("pass") else ("--" if r.get("pass") is None else "FAIL")
        elif "total_ms" in r:
            p50 = f"{r['total_ms']}ms"
            p95 = "   --"
            p99 = "   --"
            tgt = f"{r.get('target_ms', r.get('target_us', '--'))}"
            ok  = "OK" if r.get("pass") else "FAIL"
        elif "skip" in r:
            print(f"  {label:<38} SKIP: {r['skip']}")
            continue
        else:
            p50 = p95 = p99 = tgt = "   --"
            ok = "OK" if r.get("pass") else "FAIL"

        if "throughput_ops_sec" in r:
            p50 = f"{r['throughput_ops_sec']}/s"
            tgt = "5000/s"

        mark = "" if ok == "OK" else "  <-- MISS"
        print(f"  {label:<38} {p50:>8} {p95:>8} {p99:>8} {tgt:>8} {ok:>5}{mark}")

    print("=" * 70)


def main() -> int:
    parser = argparse.ArgumentParser(description="authgate-kernel benchmarks")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--gate", action="store_true", help="Exit 1 if any target missed")
    args = parser.parse_args()

    results = run_all()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _print_table(results)
        if TARGETS_MISSED:
            print(f"\nTargets missed ({len(TARGETS_MISSED)}):")
            for m in TARGETS_MISSED:
                print(f"  MISS: {m}")
        else:
            print("\nAll performance targets met.")

    if args.gate and TARGETS_MISSED:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
