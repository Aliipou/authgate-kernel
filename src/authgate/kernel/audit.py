"""
AuditLog — structured, tamper-evident, append-only audit trail.

Every call to FreedomVerifier.verify() appends one JSON record.
Records are SHA-256 hash-chained: entry_hash = SHA-256(prev_hash || entry_fields).
Any tampering or deletion is detected by verify_chain().

Thread safety: record() holds the lock during hash computation and append,
so concurrent appends always form a valid linear chain (no duplicate prev_hash).

Wire format (one JSON object per line, .jsonl):
  {
    "ts":         float,    # Unix timestamp
    "action_id":  str,
    "permitted":  bool,
    "confidence": float,
    "violations": [str, ...],
    "warnings":   [str, ...],
    "signature":  str | null,
    "prev_hash":  str,      # hex SHA-256 of prior entry ("0"*64 for first)
    "entry_hash": str       # hex SHA-256 of this entry (excluding itself)
  }
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _compute_hash(entry: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of entry, excluding 'entry_hash' key."""
    stable = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


GENESIS_HASH = "0" * 64


@dataclass
class AuditLog:
    """
    Append-only, hash-chained audit log for verification decisions.

    Usage:
        log = AuditLog(path="/var/log/authgate.jsonl")
        verifier = FreedomVerifier(registry, audit_log=log)
        # every verify() call is automatically logged

    path=None: in-memory only (for testing / ephemeral sessions).
    """
    path: str | None = None
    _records: list[dict[str, Any]] = field(
        default_factory=list, init=False, repr=False
    )
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    _last_hash: str = field(default=GENESIS_HASH, init=False, repr=False)

    def record(self, result: Any) -> None:
        """
        Append a verification result. Thread-safe.

        The entire hash computation + append is inside the lock so that
        concurrent calls always produce a valid linear chain — no two entries
        share the same prev_hash.
        """
        entry: dict[str, Any] = {
            "ts":         time.time(),
            "action_id":  result.action_id,
            "permitted":  result.permitted,
            "confidence": result.confidence,
            "violations": list(result.violations),
            "warnings":   list(result.warnings),
            "signature":  getattr(result, "signature", None),
        }
        with self._lock:
            entry["prev_hash"]  = self._last_hash
            entry["entry_hash"] = _compute_hash(entry)
            self._last_hash     = entry["entry_hash"]
            self._records.append(entry)
            if self.path is not None:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")

    # ------------------------------------------------------------------
    # Read interface
    # ------------------------------------------------------------------

    def entries(self) -> list[dict[str, Any]]:
        """Return a snapshot of all in-memory entries."""
        with self._lock:
            return list(self._records)

    def head_hash(self) -> str:
        """Current chain tip hash. Use to anchor the log in external systems."""
        with self._lock:
            return self._last_hash

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ------------------------------------------------------------------
    # Chain integrity
    # ------------------------------------------------------------------

    def verify_chain(self) -> bool:
        """
        Recompute every entry hash and check prev_hash linkage.

        Returns True if the chain is intact.
        Returns False if any entry was altered, added out-of-order, or deleted.
        """
        with self._lock:
            records = list(self._records)

        prev = GENESIS_HASH
        for entry in records:
            if entry.get("prev_hash") != prev:
                return False
            if entry.get("entry_hash") != _compute_hash(entry):
                return False
            prev = entry["entry_hash"]
        return True

    def chain_errors(self) -> list[str]:
        """
        Return a list of human-readable errors found in the chain.
        Empty list means the chain is intact.
        """
        with self._lock:
            records = list(self._records)

        errors: list[str] = []
        prev = GENESIS_HASH
        for i, entry in enumerate(records):
            aid = entry.get("action_id", f"entry-{i}")
            if entry.get("prev_hash") != prev:
                errors.append(
                    f"entry {i} ({aid}): prev_hash mismatch "
                    f"(expected {prev[:8]}..., got {str(entry.get('prev_hash', ''))[:8]}...)"
                )
            computed = _compute_hash(entry)
            if entry.get("entry_hash") != computed:
                errors.append(
                    f"entry {i} ({aid}): entry_hash mismatch — content was altered"
                )
            prev = entry.get("entry_hash", "")
        return errors

    # ------------------------------------------------------------------
    # Forensic replay
    # ------------------------------------------------------------------

    def replay(self, entry_idx: int) -> dict[str, Any]:
        """
        Return the audit entry at index entry_idx for forensic reconstruction.

        Raises IndexError if out of bounds.
        Raises ValueError if the entry's hash is invalid (tampered).
        """
        with self._lock:
            if entry_idx < 0 or entry_idx >= len(self._records):
                raise IndexError(
                    f"entry_idx {entry_idx} out of range (log has {len(self._records)} entries)"
                )
            entry = dict(self._records[entry_idx])

        if entry.get("entry_hash") != _compute_hash(entry):
            raise ValueError(
                f"Entry {entry_idx} ({entry.get('action_id')}) has been tampered — "
                "hash mismatch. Forensic replay cannot be trusted."
            )
        return entry

    def replay_range(self, start: int, stop: int) -> list[dict[str, Any]]:
        """Return entries[start:stop], each verified for individual hash integrity."""
        return [self.replay(i) for i in range(start, stop)]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @classmethod
    def load_from_file(cls, path: str) -> "AuditLog":
        """
        Reconstruct an AuditLog from a persisted .jsonl file.

        Raises ValueError if the file contains invalid JSON on any line.
        Does NOT verify chain integrity automatically — call verify_chain()
        after loading if integrity must be confirmed.

        The returned log is in append mode: new entries will be appended to
        the same file and linked to the last loaded entry.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Audit log file not found: {path}")

        log = cls(path=path)
        with p.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Invalid JSON on line {lineno} of {path}: {e}"
                    ) from e
                log._records.append(entry)

        if log._records:
            log._last_hash = log._records[-1].get("entry_hash", GENESIS_HASH)

        return log

    @classmethod
    def load_and_verify(cls, path: str) -> tuple["AuditLog", list[str]]:
        """
        Load from file and immediately verify chain integrity.

        Returns (log, errors). If errors is empty, the chain is intact.
        """
        log = cls.load_from_file(path)
        errors = log.chain_errors()
        return log, errors
