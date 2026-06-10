"""
Benchmark: cost of an authorization decision, pure-Python verifier vs the
verified Rust engine reached over the JSON wire (RustBackedVerifier).

This is the decision-relevant number for the runtime: every gated tool call pays
one verify(). It answers "what does routing through the verified TCB cost per
call?" Run:  AUTHGATE_BACKEND=python python redteam/bench_verify.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("AUTHGATE_BACKEND", "python")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from authgate.kernel.entities import (  # noqa: E402
    AgentType,
    Entity,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.registry import OwnershipRegistry  # noqa: E402
from authgate.kernel.verifier import Action, FreedomVerifier  # noqa: E402
from authgate.runtime.rust_backend import RustBackedVerifier, rust_backend_available  # noqa: E402


def _scenario():
    owner = Entity("operator", AgentType.HUMAN)
    agent = Entity("agent-1", AgentType.MACHINE)
    resource = Resource("compute", ResourceType.COMPUTE_SLOT)
    registry = OwnershipRegistry()
    registry.register_machine(agent, owner)
    registry.add_claim(RightsClaim(owner, resource, can_read=True, can_delegate=True))
    registry.delegate(RightsClaim(agent, resource, can_read=True), delegated_by=owner)
    return registry, Action("t1", agent, resources_read=[resource])


def _bench(label: str, verify, action, n: int) -> None:
    verify(action)  # warm up
    t0 = time.perf_counter()
    for _ in range(n):
        verify(action)
    elapsed = time.perf_counter() - t0
    per = elapsed / n * 1e6  # microseconds per decision
    print(f"  {label:32} {per:9.2f} us/decision   {n/elapsed:12,.0f} decisions/s")


def main() -> int:
    registry, action = _scenario()
    n = 20000
    print(f"verify() latency over {n:,} permitted decisions (AUTHGATE_BACKEND="
          f"{os.environ.get('AUTHGATE_BACKEND')}):")
    _bench("pure-Python FreedomVerifier", FreedomVerifier(registry).verify, action, n)
    if rust_backend_available():
        _bench("verified Rust engine (JSON wire)", RustBackedVerifier(registry).verify, action, n)
    else:
        print("  verified Rust engine: SKIPPED (authgate_kernel extension not built)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
