"""
HistoricalBehaviorStore — append-only record of per-principal behavior for
the Delegate Reputation Extension (DRE).

SECURITY NOTE: This store is NOT part of the TCB. It is a heuristic signal
source. A compromised or poisoned HBS can cause false-positive blocks (denial
of service) but cannot cause false-negative permits (security bypass), because
the TCB gate runs first and the DRE can only escalate Permit → Deny.

Storage: SQLite (default) or PostgreSQL (production). All writes are
append-only; historical records are never mutated.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BehaviorRecord:
    """One immutable entry in the historical behavior log."""
    ts: float
    actor_id: str
    action_id: str
    result: str  # "permitted" | "denied"
    sovereignty_flags_triggered: int
    violations: tuple[str, ...]
    warnings: tuple[str, ...]
    ndc: str  # Non-Determinism Class
    delegation_depth: int
    resources_accessed: tuple[str, ...]
    external_attestation_valid: bool
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "actor_id": self.actor_id,
            "action_id": self.action_id,
            "result": self.result,
            "sovereignty_flags_triggered": self.sovereignty_flags_triggered,
            "violations": list(self.violations),
            "warnings": list(self.warnings),
            "ndc": self.ndc,
            "delegation_depth": self.delegation_depth,
            "resources_accessed": list(self.resources_accessed),
            "external_attestation_valid": self.external_attestation_valid,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BehaviorRecord:
        return cls(
            ts=float(d["ts"]),
            actor_id=str(d["actor_id"]),
            action_id=str(d["action_id"]),
            result=str(d["result"]),
            sovereignty_flags_triggered=int(d["sovereignty_flags_triggered"]),
            violations=tuple(d.get("violations", [])),
            warnings=tuple(d.get("warnings", [])),
            ndc=str(d["ndc"]),
            delegation_depth=int(d["delegation_depth"]),
            resources_accessed=tuple(d.get("resources_accessed", [])),
            external_attestation_valid=bool(d["external_attestation_valid"]),
            confidence=float(d.get("confidence", 1.0)),
        )


class HistoricalBehaviorStore:
    """
    SQLite-backed append-only store of per-principal behavior.

    Thread-safe via connection-per-thread pattern (check_same_thread=False
    with explicit locking for schema mutations).
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS behavior_records (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          REAL    NOT NULL,
        actor_id    TEXT    NOT NULL,
        action_id   TEXT    NOT NULL,
        result      TEXT    NOT NULL,
        sovereignty_flags_triggered INTEGER NOT NULL DEFAULT 0,
        violations  TEXT,    -- JSON array
        warnings    TEXT,    -- JSON array
        ndc         TEXT    NOT NULL DEFAULT 'UNKNOWN',
        delegation_depth INTEGER NOT NULL DEFAULT 0,
        resources_accessed TEXT,  -- JSON array
        external_attestation_valid INTEGER NOT NULL DEFAULT 1,
        confidence  REAL    NOT NULL DEFAULT 1.0
    );

    CREATE INDEX IF NOT EXISTS idx_actor_ts
        ON behavior_records(actor_id, ts);

    -- Covering index: query_summary can be answered entirely from the index
    CREATE INDEX IF NOT EXISTS idx_actor_ts_covering
        ON behavior_records(actor_id, ts, result, sovereignty_flags_triggered, external_attestation_valid);

    -- Partial index: only rows with sovereignty_flags_triggered > 0
    CREATE INDEX IF NOT EXISTS idx_actor_flagged
        ON behavior_records(actor_id, ts)
        WHERE sovereignty_flags_triggered > 0;

    -- Partial index: only rows with failed external attestation
    CREATE INDEX IF NOT EXISTS idx_actor_failed_attest
        ON behavior_records(actor_id, ts)
        WHERE external_attestation_valid = 0;

    CREATE INDEX IF NOT EXISTS idx_actor_result
        ON behavior_records(actor_id, result);
    """

    def __init__(self, db_path: str | None = None, max_records_per_actor: int | None = None) -> None:
        """
        Args:
            db_path: Path to SQLite database. If None, uses in-memory store.
            max_records_per_actor: If set, older records are pruned per actor
                                   when this limit is exceeded.
        """
        self.db_path = db_path or ":memory:"
        self.max_records = max_records_per_actor
        self._lock = threading.RLock()
        self._local = threading.local()
        self._ensure_schema()

    def _conn(self) -> sqlite3.Connection:
        """Get or create a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # autocommit mode
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._conn()
            conn.executescript(self._SCHEMA)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def append(self, record: BehaviorRecord) -> None:
        """Append a behavior record. Thread-safe."""
        with self._lock:
            conn = self._conn()
            conn.execute(
                """
                INSERT INTO behavior_records
                (ts, actor_id, action_id, result, sovereignty_flags_triggered,
                 violations, warnings, ndc, delegation_depth,
                 resources_accessed, external_attestation_valid, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.ts,
                    record.actor_id,
                    record.action_id,
                    record.result,
                    record.sovereignty_flags_triggered,
                    json.dumps(list(record.violations)),
                    json.dumps(list(record.warnings)),
                    record.ndc,
                    record.delegation_depth,
                    json.dumps(list(record.resources_accessed)),
                    1 if record.external_attestation_valid else 0,
                    record.confidence,
                ),
            )

        if self.max_records is not None:
            self._prune_old_records(record.actor_id)

    def _prune_old_records(self, actor_id: str) -> None:
        """Remove oldest records for actor_id if over max_records."""
        with self._lock:
            conn = self._conn()
            count_row = conn.execute(
                "SELECT COUNT(*) FROM behavior_records WHERE actor_id = ?",
                (actor_id,),
            ).fetchone()
            if count_row is None:
                return
            count = count_row[0]
            if count > self.max_records:
                to_delete = count - self.max_records
                conn.execute(
                    """
                    DELETE FROM behavior_records
                    WHERE id IN (
                        SELECT id FROM behavior_records
                        WHERE actor_id = ?
                        ORDER BY ts ASC
                        LIMIT ?
                    )
                    """,
                    (actor_id, to_delete),
                )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query(
        self,
        actor_id: str,
        window_days: int = 90,
        result_filter: str | None = None,
    ) -> list[BehaviorRecord]:
        """
        Return behavior records for actor_id within the last window_days.

        Args:
            result_filter: If set, filter to "permitted" or "denied" only.
        """
        cutoff = time.time() - (window_days * 86400)
        sql = """
            SELECT * FROM behavior_records
            WHERE actor_id = ? AND ts >= ?
        """
        params: list[Any] = [actor_id, cutoff]
        if result_filter is not None:
            sql += " AND result = ?"
            params.append(result_filter)
        sql += " ORDER BY ts DESC"

        with self._lock:
            conn = self._conn()
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_record(row) for row in rows]

    def query_flagged(self, actor_id: str, window_days: int = 90) -> list[BehaviorRecord]:
        """Return records where sovereignty_flags_triggered > 0."""
        cutoff = time.time() - (window_days * 86400)
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                """
                SELECT * FROM behavior_records
                WHERE actor_id = ? AND ts >= ? AND sovereignty_flags_triggered > 0
                ORDER BY ts DESC
                """,
                (actor_id, cutoff),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def query_denied(self, actor_id: str, window_days: int = 90) -> list[BehaviorRecord]:
        """Return denied records."""
        return self.query(actor_id, window_days=window_days, result_filter="denied")

    def count_actions(self, actor_id: str, window_days: int = 90) -> int:
        """Count total actions in window."""
        cutoff = time.time() - (window_days * 86400)
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT COUNT(*) FROM behavior_records WHERE actor_id = ? AND ts >= ?",
                (actor_id, cutoff),
            ).fetchone()
        return row[0] if row else 0

    def unique_resources(self, actor_id: str, window_days: int = 90) -> set[str]:
        """Return set of unique resource names accessed in window."""
        cutoff = time.time() - (window_days * 86400)
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT resources_accessed FROM behavior_records WHERE actor_id = ? AND ts >= ?",
                (actor_id, cutoff),
            ).fetchall()

        resources: set[str] = set()
        for row in rows:
            if row[0]:
                resources.update(json.loads(row[0]))
        return resources

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def query_summary(self, actor_id: str, window_days: int = 90) -> dict[str, Any]:
        """
        Return aggregated statistics for actor_id in a single SQL query.
        Much faster than fetching all rows when only counts are needed.
        """
        cutoff = time.time() - (window_days * 86400)
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN sovereignty_flags_triggered > 0 THEN 1 ELSE 0 END) as flagged,
                    SUM(CASE WHEN result = 'denied' THEN 1 ELSE 0 END) as denied,
                    SUM(CASE WHEN external_attestation_valid = 0 THEN 1 ELSE 0 END) as failed_attest,
                    MAX(ts) as most_recent_ts
                FROM behavior_records
                WHERE actor_id = ? AND ts >= ?
                """,
                (actor_id, cutoff),
            ).fetchone()

        return {
            "total": row["total"] or 0,
            "flagged": row["flagged"] or 0,
            "denied": row["denied"] or 0,
            "failed_attestations": row["failed_attest"] or 0,
            "most_recent_ts": row["most_recent_ts"] or 0.0,
        }

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> BehaviorRecord:
        return BehaviorRecord(
            ts=row["ts"],
            actor_id=row["actor_id"],
            action_id=row["action_id"],
            result=row["result"],
            sovereignty_flags_triggered=row["sovereignty_flags_triggered"],
            violations=tuple(json.loads(row["violations"] or "[]")),
            warnings=tuple(json.loads(row["warnings"] or "[]")),
            ndc=row["ndc"],
            delegation_depth=row["delegation_depth"],
            resources_accessed=tuple(json.loads(row["resources_accessed"] or "[]")),
            external_attestation_valid=bool(row["external_attestation_valid"]),
            confidence=row["confidence"],
        )

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self) -> HistoricalBehaviorStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
