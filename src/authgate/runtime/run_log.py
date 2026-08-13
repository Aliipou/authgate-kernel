"""
RunLog — append-only execution trace for the agent runtime (non-TCB).

This is the human/operator-facing record of *what the runtime did*: for each
plan step, the decision (permit/deny) and, when permitted, the tool output. It
complements — does not replace — the kernel's hash-chained `AuditLog`:

  * kernel AuditLog : tamper-evident record of every *verification decision*
                      (the security-critical integrity log).
  * RunLog          : operational trace including *tool results*, for debugging
                      and reproducibility checks.

Format: one JSON object per line (.jsonl), append-only. Tool output is stored as
a truncated string so the trace never becomes an exfiltration channel for large
payloads and stays cheap to write.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

_MAX_OUTPUT_CHARS = 2000  # keep traces bounded; full output lives in RunResult


@dataclass
class RunLog:
    """Append-only jsonl trace of executed steps. path=None keeps it in memory."""

    path: str | None = None
    _entries: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)

    def record(
        self,
        agent_id: str,
        step_index: int,
        tool: str,
        args: dict[str, Any],
        permitted: bool,
        output: Any = None,
        denied_reason: str | None = None,
    ) -> None:
        """Append one step outcome. Never raises on policy denial."""
        entry = {
            "ts": time.time(),
            "agent_id": agent_id,
            "step": step_index,
            "tool": tool,
            "args": args,
            "decision": "permit" if permitted else "deny",
            "output": (str(output)[:_MAX_OUTPUT_CHARS] if permitted else None),
            "denied_reason": denied_reason,
        }
        self._entries.append(entry)
        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def entries(self) -> list[dict[str, Any]]:
        """Snapshot of all recorded entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
