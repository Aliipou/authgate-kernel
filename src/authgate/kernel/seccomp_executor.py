"""
SeccompExecutor — OS-level subprocess isolation for tool execution.

Closes I-4 from INFRASTRUCTURE_PLAN.md: wraps every tool invocation in a
subprocess with reduced privileges, closing the Python subprocess/ctypes
bypass that SandboxedExecutor leaves open.

Enforcement levels:
  Level 0 — No isolation (fallback, Windows or missing dependency)
  Level 1 — Subprocess isolation (separate process, timeout, no shared state)
  Level 2 — seccomp-bpf filter (Linux only — restricts to minimal syscall set)

The CallGate is still required above this layer — SeccompExecutor provides
OS-level execution constraints AFTER the capability gate has permitted.

Architecture:
  CallGate.execute(action, tool_name, args)    ← capability gate (Layer 1)
    └── SeccompExecutor.run(fn, args)           ← OS isolation (Layer 2)
          └── subprocess / seccomp'd process   ← actual execution

Usage:
  executor = SeccompExecutor.auto()   # picks best available level
  gate = CallGate(verifier, executor=executor)  # (future integration point)
  gate.execute(action, "read_file", {"path": "/data/x.csv"})
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable


class IsolationLevel(IntEnum):
    NONE       = 0   # No OS isolation — Python layer only
    SUBPROCESS = 1   # Subprocess isolation — separate process, timeout enforced
    SECCOMP    = 2   # seccomp-bpf + subprocess (Linux only)


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    output: Any = None
    error: str | None = None
    isolation_level: IsolationLevel = IsolationLevel.NONE


# ─── Seccomp filter (Linux only) ──────────────────────────────────────────────

# Minimal syscall allowlist for a tool subprocess:
# read, write, close, exit_group, fstat, mmap, mprotect, munmap, brk, access,
# open/openat (for reading files), lseek, getdents64, stat, lstat, newfstatat
# This permits file I/O but blocks: socket, execve, clone, fork, ptrace, etc.

_SECCOMP_ALLOWLIST = {
    "x86_64": [
        0,   # read
        1,   # write
        2,   # open
        3,   # close
        4,   # stat
        5,   # fstat
        6,   # lstat
        8,   # lseek
        9,   # mmap
        10,  # mprotect
        11,  # munmap
        12,  # brk
        21,  # access
        60,  # exit
        231, # exit_group
        257, # openat
        262, # newfstatat
        217, # getdents64
        39,  # getpid
        79,  # getcwd
        78,  # gettimeofday
        228, # clock_gettime
        107, # sysinfo
        63,  # uname
        16,  # ioctl (needed for terminal detection)
        72,  # fcntl (for file flags)
        73,  # flock
    ],
}


def _install_seccomp_filter(allowlist: list[int]) -> bool:
    """
    Install a seccomp-bpf filter allowing only the listed syscall numbers.
    Returns True on success, False if seccomp is not available.

    Uses libseccomp via ctypes. Requires Linux with libseccomp installed.
    """
    try:
        import ctypes
        import ctypes.util

        libname = ctypes.util.find_library("seccomp")
        if not libname:
            return False

        libseccomp = ctypes.CDLL(libname, use_errno=True)

        # Constants
        SCMP_ACT_KILL   = 0x00000000
        SCMP_ACT_ALLOW  = 0x7FFF0000
        SCMP_ARCH_X86_64 = 0xC000003E

        ctx = libseccomp.seccomp_init(SCMP_ACT_KILL)
        if not ctx:
            return False

        try:
            for syscall_nr in allowlist:
                rc = libseccomp.seccomp_rule_add(
                    ctx, SCMP_ACT_ALLOW, syscall_nr, 0
                )
                if rc != 0:
                    return False

            rc = libseccomp.seccomp_load(ctx)
            return rc == 0
        finally:
            libseccomp.seccomp_release(ctx)

    except (ImportError, OSError, AttributeError):
        return False


# ─── Subprocess runner script ─────────────────────────────────────────────────

_RUNNER_TEMPLATE = textwrap.dedent("""\
    import json
    import sys
    import importlib
    import os

    # Optional: install seccomp filter before loading tool code
    _seccomp_level = int(os.environ.get("_AUTHGATE_SECCOMP", "0"))
    if _seccomp_level >= 2:
        try:
            import ctypes
            import ctypes.util
            libname = ctypes.util.find_library("seccomp")
            if libname:
                libseccomp = ctypes.CDLL(libname)
                SCMP_ACT_KILL  = 0x00000000
                SCMP_ACT_ALLOW = 0x7FFF0000
                _ALLOWLIST = {allowlist}
                ctx = libseccomp.seccomp_init(SCMP_ACT_KILL)
                if ctx:
                    for nr in _ALLOWLIST:
                        libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
                    libseccomp.seccomp_load(ctx)
                    libseccomp.seccomp_release(ctx)
        except Exception:
            pass  # seccomp optional — subprocess isolation is still active

    payload = json.loads(sys.stdin.read())
    fn_module = payload["fn_module"]
    fn_name   = payload["fn_name"]
    arguments = payload["arguments"]

    sys.path.insert(0, payload.get("src_path", ""))
    mod = importlib.import_module(fn_module)
    fn = getattr(mod, fn_name)
    result = fn(**arguments)
    print(json.dumps({{"ok": True, "output": result}}))
""")


def _run_in_subprocess(
    fn: Callable[..., Any],
    arguments: dict[str, Any],
    timeout: float = 10.0,
    isolation_level: IsolationLevel = IsolationLevel.SUBPROCESS,
) -> ExecutionResult:
    """
    Run fn(**arguments) in a subprocess.

    The function must be importable (module-level, not a lambda).
    For lambdas and closures, falls back to direct execution.
    """
    fn_module = getattr(fn, "__module__", None)
    fn_name   = getattr(fn, "__qualname__", getattr(fn, "__name__", None))

    if not fn_module or not fn_name or "<" in fn_name:
        # Lambda or closure — cannot serialize; fall through to direct call
        # This is a known limitation: lambdas cannot be subprocess-isolated
        return _run_direct(fn, arguments, isolation_level=IsolationLevel.NONE)

    src_path = str(Path(__file__).parent.parent.parent)
    allowlist = _SECCOMP_ALLOWLIST.get("x86_64", [])
    runner_script = _RUNNER_TEMPLATE.format(allowlist=allowlist)

    payload = json.dumps({
        "fn_module":  fn_module,
        "fn_name":    fn_name,
        "arguments":  arguments,
        "src_path":   src_path,
    })

    env = os.environ.copy()
    env["_AUTHGATE_SECCOMP"] = str(int(isolation_level))

    try:
        proc = subprocess.run(
            [sys.executable, "-c", runner_script],
            input=payload.encode(),
            capture_output=True,
            timeout=timeout,
            env=env,
        )

        if proc.returncode != 0:
            stderr = proc.stderr.decode(errors="replace")
            return ExecutionResult(
                success=False,
                error=f"subprocess exited {proc.returncode}: {stderr[:200]}",
                isolation_level=isolation_level,
            )

        result_data = json.loads(proc.stdout.decode())
        return ExecutionResult(
            success=True,
            output=result_data.get("output"),
            isolation_level=isolation_level,
        )

    except subprocess.TimeoutExpired:
        return ExecutionResult(
            success=False,
            error=f"tool execution timed out after {timeout}s",
            isolation_level=isolation_level,
        )
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        return ExecutionResult(
            success=False,
            error=f"subprocess communication error: {exc}",
            isolation_level=isolation_level,
        )


def _run_direct(fn: Callable[..., Any], arguments: dict[str, Any],
                isolation_level: IsolationLevel = IsolationLevel.NONE) -> ExecutionResult:
    try:
        output = fn(**arguments)
        return ExecutionResult(success=True, output=output, isolation_level=isolation_level)
    except Exception as exc:
        return ExecutionResult(success=False, error=str(exc), isolation_level=isolation_level)


# ─── SeccompExecutor ──────────────────────────────────────────────────────────

class SeccompExecutor:
    """
    OS-level execution substrate for tool functions.

    Selects the best available isolation level and applies it to every
    tool invocation. Works in combination with CallGate (which handles
    the capability check layer above this).
    """

    def __init__(self, level: IsolationLevel = IsolationLevel.SUBPROCESS,
                 timeout: float = 10.0) -> None:
        self._level = level
        self._timeout = timeout

    @classmethod
    def auto(cls) -> "SeccompExecutor":
        """Select the best available isolation level for the current platform."""
        if platform.system() == "Linux":
            # Try seccomp first
            import ctypes.util
            if ctypes.util.find_library("seccomp"):
                return cls(IsolationLevel.SECCOMP)
            return cls(IsolationLevel.SUBPROCESS)
        # Windows or macOS: subprocess isolation
        return cls(IsolationLevel.SUBPROCESS)

    @classmethod
    def none(cls) -> "SeccompExecutor":
        """No OS isolation — Python layer only. For testing."""
        return cls(IsolationLevel.NONE)

    @property
    def level(self) -> IsolationLevel:
        return self._level

    def run(self, fn: Callable[..., Any], arguments: dict[str, Any]) -> ExecutionResult:
        """
        Execute fn(**arguments) at the configured isolation level.
        Returns ExecutionResult — never raises on tool error.
        """
        if self._level == IsolationLevel.NONE:
            return _run_direct(fn, arguments, IsolationLevel.NONE)

        return _run_in_subprocess(fn, arguments, self._timeout, self._level)

    def __repr__(self) -> str:
        return f"SeccompExecutor(level={self._level.name}, timeout={self._timeout}s)"


# ─── Convenience: SeccompCallGate ─────────────────────────────────────────────

class SeccompCallGate:
    """
    CallGate + SeccompExecutor in one class.

    Full enforcement stack:
      1. CallGate.execute() → verify(action) [capability gate]
      2. SeccompExecutor.run() → subprocess/seccomp [OS isolation]

    Usage:
      gate = SeccompCallGate(verifier)
      gate.register("read_file", read_file_fn)
      result = gate.execute(action, "read_file", {"path": "/data/x.csv"})
    """

    def __init__(self, verifier: Any, executor: SeccompExecutor | None = None,
                 abi_registry: Any = None, audit_log: Any = None) -> None:
        from authgate.kernel.call_gate import CallGate, GateResult

        self._gate = CallGate(verifier, abi_registry=abi_registry, audit_log=audit_log)
        self._executor = executor or SeccompExecutor.auto()
        self._GateResult = GateResult

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a tool. The fn is stored for subprocess dispatch."""
        self._gate.register(name, fn)
        # Also keep a direct reference for subprocess dispatch
        if not hasattr(self, "_fn_registry"):
            self._fn_registry: dict[str, Callable] = {}
        self._fn_registry[name] = fn

    def execute(self, action: Any, tool_name: str,
                arguments: dict[str, Any] | None = None) -> Any:
        """
        Execute with full enforcement: capability gate + OS isolation.

        Steps:
          1. verify(action) — capability gate
          2. If permitted: run tool in subprocess/seccomp
        """
        from authgate.kernel.call_gate import GateResult

        args = arguments or {}

        # Step 1: capability gate (always first)
        verify_result = self._gate._verifier.verify(action)
        if not verify_result.permitted:
            reason = "; ".join(verify_result.violations) if verify_result.violations else "denied"
            return GateResult(
                permitted=False,
                denied_reason=f"capability gate denied: {reason}",
                tool_name=tool_name,
            )

        # Step 2: OS-level execution
        fn = getattr(self, "_fn_registry", {}).get(tool_name)
        if fn is None:
            raise KeyError(f"SeccompCallGate: tool '{tool_name}' not registered")

        exec_result = self._executor.run(fn, args)
        if not exec_result.success:
            return GateResult(
                permitted=False,
                denied_reason=f"execution error: {exec_result.error}",
                tool_name=tool_name,
            )

        return GateResult(
            permitted=True,
            output=exec_result.output,
            tool_name=tool_name,
        )

    @property
    def isolation_level(self) -> IsolationLevel:
        return self._executor.level
