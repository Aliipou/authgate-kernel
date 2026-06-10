"""
Real, OS-enforced sandbox for tool execution (non-TCB).

`tools.py` validates the inputs it can foresee. This module contains the inputs
it cannot: it runs each tool in a separate OS process under resource limits and a
wall-clock deadline, so a tool that hangs, allocates without bound, or crashes the
interpreter is *killed by the OS / reaped by the parent* — it cannot take the
runtime down or block it forever. That is the difference between an in-process
prefix check (which the previous "sandbox" was) and actual containment.

Honest platform scope:
  * Always on (every platform): the parent's wall-clock timeout and the output
             cap. These reliably kill hangs and bound output everywhere.
  * POSIX, opt-in: CPU seconds, address space, and file size as hard kernel
             limits (setrlimit in the child). Off by default — a too-tight
             RLIMIT_AS/RLIMIT_FSIZE can stop the interpreter starting or writing
             .pyc — so callers enable them with a known headroom budget.
  * Windows — setrlimit does not exist; the rlimits are no-ops and enforcement is
             the wall-clock timeout and output cap. Production confinement targets
             Linux (the existing seccomp/WASM executors).

What this is NOT: it is not a network/syscall jail. It bounds time, memory, and
output and isolates crashes. Network and filesystem confinement beyond the
file_read sandbox root require OS namespaces / seccomp / WASM (tracked elsewhere).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import authgate
from authgate.runtime._sandbox_runner import RESULT_MARKER

# The child runs `python -m authgate.runtime._sandbox_runner`, so it must be able
# to import `authgate`. Derive the src root from this package's location and put
# it on the child's PYTHONPATH; this works whether or not the package is installed.
_SRC_ROOT = str(Path(authgate.__file__).resolve().parent.parent)

# Tools expressed as importable entry points (pure functions). file_read is bound
# to a per-runtime sandbox root, so it is dispatched as a builtin (see runner).
_ENTRY_POINTS = {
    "calculator": "authgate.runtime.tools:calculate",
    "web_search": "authgate.runtime.tools:web_search",
}
_ROOT_BOUND = {"file_read"}


@dataclass(frozen=True)
class SandboxPolicy:
    """Resource envelope for one tool call.

    Cross-platform, always-on guards: the wall-clock timeout (parent kills the
    child) and the output cap. The POSIX rlimits (cpu/memory/file-size) are
    opt-in (0 = off) because a too-tight RLIMIT_AS or RLIMIT_FSIZE can prevent
    the interpreter from starting or writing .pyc files — turning hardening into
    spurious failures. Set them explicitly when running on Linux with a known
    headroom budget. They are no-ops on Windows (no `resource` module)."""

    wall_timeout_s: float = 5.0       # parent kills the child past this (all platforms)
    cpu_seconds: int = 0              # RLIMIT_CPU (POSIX); 0 = off
    max_memory_mb: int = 0           # RLIMIT_AS (POSIX); 0 = off
    max_file_bytes: int = 0          # RLIMIT_FSIZE (POSIX); 0 = off
    max_output_bytes: int = 64 * 1024  # parent/child cap on returned output size

    def _limits(self) -> dict[str, int]:
        return {
            "cpu_seconds": self.cpu_seconds,
            "max_memory_bytes": self.max_memory_mb * 1024 * 1024,
            "max_file_bytes": self.max_file_bytes,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True)
class SandboxResult:
    """Outcome of one sandboxed execution."""

    ok: bool
    output: str | None = None
    error: str | None = None
    killed: bool = False  # True iff a resource/time limit terminated the child


def _build_job(tool: str, args: dict[str, Any], sandbox_root: Path, policy: SandboxPolicy) -> dict[str, Any]:
    job: dict[str, Any] = {"args": args, "limits": policy._limits()}
    if tool in _ROOT_BOUND:
        job["builtin"] = tool
        job["sandbox_root"] = str(sandbox_root)
    elif tool in _ENTRY_POINTS:
        job["entry"] = _ENTRY_POINTS[tool]
    else:
        # An unknown tool never reaches a process; the caller treats it as a denial.
        job["entry"] = ""
    return job


def run_tool_sandboxed(
    tool: str,
    args: dict[str, Any],
    sandbox_root: Path,
    policy: SandboxPolicy,
    *,
    entry_override: str | None = None,
    env: dict[str, str] | None = None,
) -> SandboxResult:
    """Run one tool call in an isolated child process under `policy`.

    `entry_override` ("module:function") is for tests that need to exercise the
    sandbox against a deliberately hostile callable (e.g. one that hangs); the
    runtime itself never sets it — tool identity comes from the registry.
    """
    job = _build_job(tool, args, sandbox_root, policy)
    if entry_override is not None:
        job.pop("builtin", None)
        job.pop("sandbox_root", None)
        job["entry"] = entry_override

    child_env = dict(env) if env is not None else dict(os.environ)
    existing_pp = child_env.get("PYTHONPATH", "")
    if _SRC_ROOT not in existing_pp.split(os.pathsep):
        child_env["PYTHONPATH"] = os.pathsep.join(p for p in (_SRC_ROOT, existing_pp) if p)
    # No .pyc writes: keeps an opt-in RLIMIT_FSIZE from tripping on bytecode caching.
    child_env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "authgate.runtime._sandbox_runner"],
            input=json.dumps(job),
            capture_output=True,
            text=True,
            timeout=policy.wall_timeout_s,
            env=child_env,
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(ok=False, error="wall-clock timeout exceeded", killed=True)

    marker_at = proc.stdout.rfind(RESULT_MARKER)
    if marker_at == -1:
        # No result line: the child was killed before it could report (OOM, CPU
        # limit -> SIGXCPU, segfault). That is containment working, not a bug.
        detail = (proc.stderr or "").strip()[-200:]
        return SandboxResult(
            ok=False,
            error=f"child terminated without result (rc={proc.returncode}): {detail}",
            killed=True,
        )

    payload = proc.stdout[marker_at + len(RESULT_MARKER):].strip()
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        return SandboxResult(ok=False, error=f"unparseable sandbox result: {exc}", killed=True)

    if result.get("ok"):
        return SandboxResult(ok=True, output=result.get("output"))
    return SandboxResult(ok=False, error=result.get("error", "tool denied"))
