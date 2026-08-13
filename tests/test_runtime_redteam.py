"""
Pytest wrapper around the standalone runtime red-team harness.

This asserts the security property the harness exists to prove: against 1000
deterministically-generated adversarial engineers, the capability-gated runtime
holds — ZERO escapes. Any escape is a hard failure with a helpful listing.

The heavy lifting (attacks, sandbox fixtures, determinism) lives in
``redteam/runtime_redteam.py``; this file imports it and asserts the report.
``tests/conftest`` is not relied upon for path setup — the harness wires ``src``
onto sys.path itself, and we add the repo root so ``redteam`` is importable.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# The runtime layer's backend under test is the pure-Python kernel.
os.environ.setdefault("AUTHGATE_BACKEND", "python")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
for _p in (str(_SRC), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load_harness():
    """Import the standalone harness by file path (it lives outside any package)."""
    harness_path = _REPO_ROOT / "redteam" / "runtime_redteam.py"
    spec = importlib.util.spec_from_file_location("runtime_redteam", harness_path)
    assert spec and spec.loader, f"cannot load harness at {harness_path}"
    module = importlib.util.module_from_spec(spec)
    # Register before exec: @dataclass resolves field types via
    # sys.modules[cls.__module__], which is None until the module is registered.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_harness = _load_harness()


def _rust_available() -> bool:
    """True iff the compiled verified-kernel extension can be imported."""
    from authgate.runtime.rust_backend import rust_backend_available
    return rust_backend_available()


@pytest.fixture(scope="module")
def report():
    return _harness.run_redteam(1000, master_seed=1337)


def test_no_escapes(report):
    """The headline guarantee: every one of the 1000 attacks is blocked."""
    if report.escapes:
        lines = [
            f"  #{e.profile.id} {e.profile.name} [{e.category}] "
            f"({e.profile.skill} {e.profile.archetype}): {e.detail}"
            for e in report.escapes
        ]
        pytest.fail(
            f"{len(report.escapes)} ESCAPE(S) — the runtime FAILED to resist:\n"
            + "\n".join(lines)
        )
    assert report.escapes == []


def test_total_is_1000(report):
    assert report.total == 1000
    assert report.blocked == 1000


def test_every_category_fully_blocked(report):
    """Each attack category must be exercised (total>0) and fully held."""
    assert set(report.by_category) == set(_harness.ATTACK_CATEGORIES)
    for category, (blocked, total) in report.by_category.items():
        assert total > 0, f"category {category} had no engineers"
        assert blocked == total, (
            f"category {category}: only {blocked}/{total} blocked"
        )


def test_determinism():
    """Fixed seed -> identical report (same totals and per-category breakdown)."""
    a = _harness.run_redteam(200, master_seed=2024)
    b = _harness.run_redteam(200, master_seed=2024)
    assert a.total == b.total
    assert a.blocked == b.blocked
    assert a.by_category == b.by_category
    assert [r.profile.id for r in a.escapes] == [r.profile.id for r in b.escapes]


def test_no_real_file_leaked(report):
    """Belt-and-suspenders: sandbox-escape attacks must never surface real OS
    file content. The harness already asserts this per-attack; here we re-derive
    the guarantee from the report's success and the leak markers it checks."""
    sandbox_blocked, sandbox_total = report.by_category["SANDBOX_ESCAPE"]
    assert sandbox_total > 0
    assert sandbox_blocked == sandbox_total
    # The markers the harness scans for include 'root:' (the /etc/passwd tell).
    assert "root:" in str(_harness._LEAK_MARKERS).lower()


@pytest.mark.skipif(
    not _rust_available(),
    reason="verified Rust extension (authgate_kernel) not built in this environment",
)
def test_no_escapes_on_verified_rust_backend():
    """The same adversaries, but every permit/deny decision is made by the
    formally-verified Rust engine. Zero escapes is the bar regardless of backend."""
    report = _harness.run_redteam(1000, master_seed=1337, backend="rust")
    assert report.total == 1000
    assert report.blocked == 1000
    assert report.escapes == []
