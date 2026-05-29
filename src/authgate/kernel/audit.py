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

import base64
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
        log = AuditLog(path="/var/log/authgate.jsonl", max_entries=100_000)
        verifier = FreedomVerifier(registry, audit_log=log)
        # every verify() call is automatically logged

    path=None: in-memory only (for testing / ephemeral sessions).
    max_entries: rotate in-memory buffer when this size is reached.
                 Entries beyond max_entries are flushed to path (if set)
                 and dropped from memory. Chain integrity is preserved across rotations.
                 None = unbounded (S-2 fix: use this only for short-lived sessions).
    """
    path: str | None = None
    max_entries: int | None = None   # S-2 fix: cap in-memory growth
    _records: list[dict[str, Any]] = field(
        default_factory=list, init=False, repr=False
    )
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    _last_hash: str = field(default=GENESIS_HASH, init=False, repr=False)
    _total_count: int = field(default=0, init=False, repr=False)  # includes rotated

    def record(self, result: Any) -> None:
        """
        Append a verification result. Thread-safe.

        When max_entries is set and the buffer is full, the oldest entries are
        flushed to disk (if path is set) and removed from memory. The chain
        hash is preserved so integrity can still be verified from disk.
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
            self._total_count  += 1
            if self.path is not None:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            # S-2 fix: rotate in-memory buffer if max_entries is set
            if self.max_entries is not None and len(self._records) > self.max_entries:
                self._records = self._records[-self.max_entries:]

    @property
    def total_count(self) -> int:
        """Total decisions recorded, including those rotated out of memory."""
        with self._lock:
            return self._total_count

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

    # ------------------------------------------------------------------
    # Signed export  (Phase 1/O4)
    # ------------------------------------------------------------------

    def export_signed(self, private_key: Any) -> dict[str, Any]:
        """
        Produce a signed audit export anchored to the current chain head.

        The signed payload covers: head_hash, entry_count, and export_ts.
        Signature algorithm: Ed25519 (from cryptography library).

        Returns a dict with keys:
          head_hash, entry_count, export_ts, signature (base64), verifying_key (base64)
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be Ed25519PrivateKey")

        with self._lock:
            head = self._last_hash
            count = len(self._records)

        ts = time.time()
        payload = json.dumps(
            {"head_hash": head, "entry_count": count, "export_ts": ts},
            sort_keys=True, separators=(",", ":"),
        ).encode()

        sig_bytes = private_key.sign(payload)
        vk_bytes = private_key.public_key().public_bytes_raw()

        return {
            "head_hash": head,
            "entry_count": count,
            "export_ts": ts,
            "signature": base64.b64encode(sig_bytes).decode(),
            "verifying_key": base64.b64encode(vk_bytes).decode(),
        }

    @staticmethod
    def verify_signed_export(export: dict[str, Any], verifying_key: Any | None = None) -> bool:
        """
        Verify the Ed25519 signature on a signed audit export.

        verifying_key: Ed25519PublicKey (optional — if None, uses the key embedded in the export).
        Returns True if the signature is valid.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if verifying_key is None:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            vk_bytes = base64.b64decode(export["verifying_key"])
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            verifying_key = Ed25519PublicKey.from_public_bytes(vk_bytes)

        payload = json.dumps(
            {
                "head_hash": export["head_hash"],
                "entry_count": export["entry_count"],
                "export_ts": export["export_ts"],
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()

        sig_bytes = base64.b64decode(export["signature"])
        try:
            verifying_key.verify(sig_bytes, payload)
            return True
        except InvalidSignature:
            return False
