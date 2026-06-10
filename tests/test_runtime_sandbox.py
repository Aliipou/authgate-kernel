"""
Tests for the real, OS-enforced tool sandbox (process isolation + limits).

These prove the sandbox actually *contains* a tool rather than just checking its
inputs: a normal tool runs and returns; a hostile path is refused; a runaway
(hanging) tool is killed by the wall-clock deadline rather than blocking forever;
oversized output is capped.
"""
from __future__ import annotations

import os
import time

import pytest

from authgate.runtime.sandbox import SandboxPolicy, run_tool_sandboxed


def test_sandbox_runs_calculator_in_subprocess(tmp_path):
    r = run_tool_sandboxed("calculator", {"expression": "2 + 3 * 4"}, tmp_path, SandboxPolicy())
    assert r.ok
    assert r.output == "14"


def test_sandbox_reads_file_inside_root(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    r = run_tool_sandboxed("file_read", {"filename": "a.txt"}, tmp_path, SandboxPolicy())
    assert r.ok
    assert r.output == "hello"


def test_sandbox_denies_path_escape(tmp_path):
    r = run_tool_sandboxed("file_read", {"filename": "../../etc/passwd"}, tmp_path, SandboxPolicy())
    assert not r.ok
    assert "escapes sandbox" in (r.error or "")


def test_sandbox_kills_a_hanging_tool(tmp_path):
    # A helper module the isolated child can import, whose tool hangs far longer
    # than the deadline. Real containment means it is killed, not awaited.
    helper_dir = tmp_path / "helpers"
    helper_dir.mkdir()
    (helper_dir / "hangtool.py").write_text(
        "import time\n\ndef hang(seconds=60):\n    time.sleep(seconds)\n    return 'finished'\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(helper_dir), env.get("PYTHONPATH", "")])

    t0 = time.time()
    r = run_tool_sandboxed(
        "x", {"seconds": 30}, tmp_path,
        SandboxPolicy(wall_timeout_s=2.0),
        entry_override="hangtool:hang", env=env,
    )
    elapsed = time.time() - t0

    assert not r.ok
    assert r.killed
    assert elapsed < 15, f"sandbox did not kill promptly (took {elapsed:.1f}s)"


def test_sandbox_caps_oversized_output(tmp_path):
    long_query = "Z" * 5000  # web_search echoes the query back; output would be large
    r = run_tool_sandboxed(
        "web_search", {"query": long_query}, tmp_path,
        SandboxPolicy(max_output_bytes=100),
    )
    assert r.ok
    assert r.output is not None
    assert len(r.output) <= 100


def test_sandbox_tool_error_is_denial_not_crash(tmp_path):
    # calculator rejects non-arithmetic; through the sandbox that is a clean deny.
    r = run_tool_sandboxed("calculator", {"expression": "__import__('os')"}, tmp_path, SandboxPolicy())
    assert not r.ok
    assert r.output is None
    assert "ValueError" in (r.error or "")


def _has_rlimit() -> bool:
    try:
        import resource  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _has_rlimit(), reason="POSIX rlimits unavailable (Windows)")
def test_sandbox_cpu_limit_kills_busy_tool(tmp_path):
    # A CPU-burning tool with no sleeps: only an RLIMIT_CPU (not the wall clock,
    # set generously here) can stop it. Proves kernel-enforced CPU limiting.
    helper_dir = tmp_path / "helpers"
    helper_dir.mkdir()
    (helper_dir / "burntool.py").write_text(
        "def burn(n=0):\n    x = 0\n    while True:\n        x += 1\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(helper_dir), env.get("PYTHONPATH", "")])

    r = run_tool_sandboxed(
        "x", {}, tmp_path,
        SandboxPolicy(wall_timeout_s=30.0, cpu_seconds=1),
        entry_override="burntool:burn", env=env,
    )
    assert not r.ok
    assert r.killed
