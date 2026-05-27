"""
AuditLog — structured, tamper-evident, append-only audit trail for FreedomVerifier decisions.

Every call to FreedomVerifier.verify() that has an AuditLog attached appends
one JSON record. Each record is hash-chained to the previous entry (SHA-256),
forming a cryptographic chain that detects any tampering or deletion.

Records include: timestamp, action_id, permitted, confidence, violations,
warnings, optional signature, prev_hash, and entry_hash.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any


def _compute_hash(entry: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of an entry (excluding entry_hash itself)."""
    stable = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class AuditLog:
    """
    Append-only, hash-chained audit log for verification decisions.

    Usage:
        log = AuditLog(path="/var/log/kernel.jsonl")
        verifier = FreedomVerifier(registry, audit_log=log)
        # every verify() call is logged automatically

    path=None keeps entries in-memory only.
    verify_chain() checks that no entry has been altered or removed.
    """
    path: str | None = None
    _records: list[dict[str, Any]] = field(
        default_factory=list, init=False, repr=False
    )
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    _last_hash: str = field(default="0" * 64, init=False, repr=False)

    def record(self, result: Any) -> None:
        """Append a verification result to the log (called by FreedomVerifier)."""
        entry: dict[str, Any] = {
            "ts": time.time(),
            "action_id": result.action_id,
            "permitted": result.permitted,
            "confidence": result.confidence,
            "violations": list(result.violations),
            "warnings": list(result.warnings),
            "signature": getattr(result, "signature", None),
            "prev_hash": self._last_hash,
        }
        entry["entry_hash"] = _compute_hash(entry)
        with self._lock:
            self._last_hash = entry["entry_hash"]
            self._records.append(entry)
            if self.path is not None:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")

    def entries(self) -> list[dict[str, Any]]:
        """Return a snapshot of all in-memory log entries."""
        with self._lock:
            return list(self._records)

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the hash chain.

        Returns True if every entry's entry_hash matches its contents and
        its prev_hash matches the prior entry's entry_hash.
        Returns False if any tampering or deletion is detected.
        """
        with self._lock:
            records = list(self._records)

        prev = "0" * 64
        for entry in records:
            if entry.get("prev_hash") != prev:
                return False
            expected = _compute_hash(entry)
            if entry.get("entry_hash") != expected:
                return False
            prev = entry["entry_hash"]
        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
