"""
Seccomp adversarial tests — syscall-level enforcement on Linux.

Definition of done (gap #3): a tool process attempting execve when granted
only read rights is killed/blocked, not merely logged.
"""
from __future__ import annotations

import platform
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.kernel.seccomp_executor import (
    RIGHT_NETWORK,
    RIGHT_READ,
    RIGHT_SPAWN,
    SYSCALL_EXECVE_X86_64,
    SYSCALL_SOCKET_X86_64,
    allowlist_for_rights,
)


class TestSeccompAllowlist:
    def test_read_only_blocks_execve_and_socket(self):
        lst = allowlist_for_rights(RIGHT_READ)
        assert SYSCALL_EXECVE_X86_64 not in lst
        assert SYSCALL_SOCKET_X86_64 not in lst

    def test_network_adds_socket_not_execve(self):
        lst = allowlist_for_rights(RIGHT_READ | RIGHT_NETWORK)
        assert SYSCALL_SOCKET_X86_64 in lst
        assert SYSCALL_EXECVE_X86_64 not in lst

    def test_spawn_adds_execve(self):
        lst = allowlist_for_rights(RIGHT_READ | RIGHT_SPAWN)
        assert SYSCALL_EXECVE_X86_64 in lst


@pytest.mark.skipif(platform.system() != "Linux", reason="seccomp-bpf is Linux-only")
class TestSeccompAdversarial:
    @pytest.fixture(autouse=True)
    def _require_libseccomp(self):
        import ctypes.util

        if not ctypes.util.find_library("seccomp"):
            pytest.skip("libseccomp not installed")

    def _run_with_filter(self, allowlist: list[int], tool_body: str) -> subprocess.CompletedProcess:
        setup = f"""import ctypes, ctypes.util, json, sys, os
libname = ctypes.util.find_library("seccomp")
lib = ctypes.CDLL(libname)
SCMP_ACT_KILL, SCMP_ACT_ALLOW = 0x00000000, 0x7FFF0000
ctx = lib.seccomp_init(SCMP_ACT_KILL)
for nr in {allowlist!r}:
    lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
lib.seccomp_load(ctx)
lib.seccomp_release(ctx)
"""
        runner = setup + textwrap.dedent(tool_body).strip() + "\n"
        return subprocess.run(
            [sys.executable, "-c", runner],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_execve_killed_under_read_only_allowlist(self):
        """Tool attempting execve(/bin/sh) must be SIGSYS-killed, not succeed."""
        allowlist = allowlist_for_rights(RIGHT_READ)
        proc = self._run_with_filter(
            allowlist,
            'import os\nos.execve("/bin/sh", ["sh", "-c", "echo pwned"], os.environ)',
        )
        assert proc.returncode != 0, f"execve must not succeed: stdout={proc.stdout!r}"
        assert "pwned" not in (proc.stdout or "")
