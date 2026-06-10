"""
Sandbox child process — runs ONE tool call under OS resource limits, then exits.

This module is the body of the isolated process spawned by `sandbox.py`. It is
never imported by the runtime in-process; it is executed as
``python -m authgate.runtime._sandbox_runner`` with a JSON job on stdin and a
single JSON result line on stdout (prefixed by a sentinel so tool chatter on
stdout cannot be mistaken for the result).

Why a separate process at all: in-process input validation (see tools.py) stops
the inputs we thought of. Process isolation stops the ones we didn't — a tool
that hangs, allocates without bound, or crashes the interpreter takes down only
this child, and the parent reaps it and returns a denial. On POSIX the limits are
enforced by the kernel via setrlimit (CPU seconds, address space, file size); on
Windows, where setrlimit does not exist, the parent's wall-clock timeout and
output cap are the enforcement (documented honestly, not pretended otherwise).
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

# Sentinel framing: the parent reads the line AFTER this marker as the result, so
# anything a tool or an import writes to stdout before it is harmless noise.
RESULT_MARKER = "\x00AUTHGATE_SANDBOX_RESULT\x00"


def _apply_posix_limits(limits: dict[str, int]) -> None:
    """Enforce kernel resource limits. No-op where `resource` is unavailable (Windows).

    Attributes are read dynamically so this stays type-clean on platforms whose
    stubs lack the POSIX-only `setrlimit`/`RLIMIT_*` names. Each limit is applied
    only when explicitly requested (> 0): a too-low RLIMIT_AS can stop the
    interpreter from starting and RLIMIT_FSIZE=0 can break .pyc writes, so these
    are opt-in hardening, not silent defaults.
    """
    try:
        import resource  # POSIX-only
    except ImportError:
        return
    setrlimit = getattr(resource, "setrlimit", None)
    if setrlimit is None:
        return
    for limit_key, rlimit_name in (
        ("cpu_seconds", "RLIMIT_CPU"),
        ("max_memory_bytes", "RLIMIT_AS"),
        ("max_file_bytes", "RLIMIT_FSIZE"),
    ):
        value = int(limits.get(limit_key, 0))
        rlimit = getattr(resource, rlimit_name, None)
        if value > 0 and rlimit is not None:
            setrlimit(rlimit, (value, value))


def _resolve_tool(job: dict[str, Any]):
    """Map a job to the concrete callable. Tool identity comes from the trusted
    parent (build_runtime), never from attacker-controlled plan data."""
    builtin = job.get("builtin")
    if builtin == "file_read":
        # file_read is a closure bound to the sandbox root; rebuild it here.
        from authgate.runtime.tools import _make_read_file
        return _make_read_file(Path(job["sandbox_root"]))
    entry = job.get("entry")
    if entry:
        module_name, _, func_name = entry.partition(":")
        module = importlib.import_module(module_name)
        return getattr(module, func_name)
    raise ValueError("job names neither a builtin nor an importable entry")


def main() -> int:
    raw = sys.stdin.read()
    try:
        job = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(RESULT_MARKER + json.dumps({"ok": False, "error": f"bad job: {exc}"}))
        return 0

    _apply_posix_limits(job.get("limits", {}))
    max_out = int(job.get("limits", {}).get("max_output_bytes", 65536))
    if max_out <= 0:
        max_out = 65536

    try:
        fn = _resolve_tool(job)
        output = fn(**job.get("args", {}))
        text = str(output)
        truncated = len(text.encode("utf-8", "replace")) > max_out
        result = {"ok": True, "output": text[:max_out], "truncated": truncated}
    except Exception as exc:  # any tool failure is a denial, surfaced to the parent
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    print(RESULT_MARKER + json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
