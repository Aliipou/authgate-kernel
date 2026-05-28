"""
Audit log hardening tests — Phase 5.3 completion.

Tests load_from_file, replay, chain_errors, and the thread-safety
fix (prev_hash computed inside lock).
"""
from __future__ import annotations
import json
import os
import tempfile
import threading

import pytest

from authgate.kernel.audit import AuditLog, GENESIS_HASH
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _setup():
    human = Entity("owner", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    res = Resource("data", ResourceType.DATASET, scope="/data/")
    registry = OwnershipRegistry()
    registry.register_machine(bot, human)
    registry.add_claim(RightsClaim(bot, res, can_read=True, can_write=True))
    return registry, bot, res


# ------------------------------------------------------------------
# load_from_file
# ------------------------------------------------------------------

class TestLoadFromFile:
    def test_roundtrip_persist_and_load(self):
        """Write entries to file, load them back, verify chain intact."""
        registry, bot, res = _setup()
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            log = AuditLog(path=path)
            verifier = FreedomVerifier(registry.freeze(), audit_log=log)
            for i in range(10):
                verifier.verify(Action(f"entry-{i}", actor=bot, resources_read=[res]))

            loaded, errors = AuditLog.load_and_verify(path)
            assert errors == [], f"Chain errors after load: {errors}"
            assert len(loaded) == 10
            assert loaded.entries()[0]["action_id"] == "entry-0"
            assert loaded.entries()[9]["action_id"] == "entry-9"
        finally:
            os.unlink(path)

    def test_load_and_continue_appending(self):
        """After loading, new entries link correctly to the loaded chain."""
        registry, bot, res = _setup()
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            log = AuditLog(path=path)
            verifier = FreedomVerifier(registry.freeze(), audit_log=log)
            for i in range(5):
                verifier.verify(Action(f"pre-{i}", actor=bot, resources_read=[res]))

            # Load and continue
            loaded = AuditLog.load_from_file(path)
            verifier2 = FreedomVerifier(registry.freeze(), audit_log=loaded)
            for i in range(5):
                verifier2.verify(Action(f"post-{i}", actor=bot, resources_read=[res]))

            assert len(loaded) == 10
            assert loaded.verify_chain(), "Chain broken after loading and continuing"
        finally:
            os.unlink(path)

    def test_load_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            AuditLog.load_from_file("/nonexistent/path/audit.jsonl")

    def test_load_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"valid": true}\n')
            f.write('not json at all\n')
            path = f.name
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                AuditLog.load_from_file(path)
        finally:
            os.unlink(path)

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            log = AuditLog.load_from_file(path)
            assert len(log) == 0
            assert log.head_hash() == GENESIS_HASH
            assert log.verify_chain()
        finally:
            os.unlink(path)


# ------------------------------------------------------------------
# replay / forensic reconstruction
# ------------------------------------------------------------------

class TestReplay:
    def _populated_log(self, n=10):
        registry, bot, res = _setup()
        log = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=log)
        for i in range(n):
            verifier.verify(Action(f"entry-{i}", actor=bot, resources_read=[res]))
        return log

    def test_replay_returns_correct_entry(self):
        log = self._populated_log(10)
        entry = log.replay(5)
        assert entry["action_id"] == "entry-5"
        assert entry["permitted"] is True

    def test_replay_first_and_last(self):
        log = self._populated_log(10)
        assert log.replay(0)["action_id"] == "entry-0"
        assert log.replay(9)["action_id"] == "entry-9"

    def test_replay_out_of_range_raises(self):
        log = self._populated_log(5)
        with pytest.raises(IndexError):
            log.replay(5)
        with pytest.raises(IndexError):
            log.replay(-1)

    def test_replay_detects_tampered_entry(self):
        log = self._populated_log(5)
        with log._lock:
            log._records[2]["permitted"] = not log._records[2]["permitted"]
        with pytest.raises(ValueError, match="tampered"):
            log.replay(2)

    def test_replay_range(self):
        log = self._populated_log(10)
        entries = log.replay_range(3, 7)
        assert len(entries) == 4
        assert entries[0]["action_id"] == "entry-3"
        assert entries[3]["action_id"] == "entry-6"

    def test_head_hash_is_last_entry_hash(self):
        log = self._populated_log(5)
        entries = log.entries()
        assert log.head_hash() == entries[-1]["entry_hash"]

    def test_head_hash_empty_log(self):
        log = AuditLog()
        assert log.head_hash() == GENESIS_HASH


# ------------------------------------------------------------------
# chain_errors — detailed error reporting
# ------------------------------------------------------------------

class TestChainErrors:
    def test_valid_chain_no_errors(self):
        registry, bot, res = _setup()
        log = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=log)
        for i in range(5):
            verifier.verify(Action(f"e{i}", actor=bot, resources_read=[res]))
        assert log.chain_errors() == []

    def test_altered_content_reported(self):
        registry, bot, res = _setup()
        log = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=log)
        for i in range(5):
            verifier.verify(Action(f"e{i}", actor=bot, resources_read=[res]))
        with log._lock:
            log._records[2]["confidence"] = 0.0  # tamper content
        errors = log.chain_errors()
        assert any("entry_hash mismatch" in e for e in errors)
        assert any("e2" in e for e in errors)

    def test_broken_prev_hash_reported(self):
        registry, bot, res = _setup()
        log = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=log)
        for i in range(5):
            verifier.verify(Action(f"e{i}", actor=bot, resources_read=[res]))
        with log._lock:
            log._records[3]["prev_hash"] = "deadbeef" * 8  # corrupt linkage
        errors = log.chain_errors()
        assert any("prev_hash mismatch" in e for e in errors)


# ------------------------------------------------------------------
# Thread safety: prev_hash computed inside lock
# ------------------------------------------------------------------

class TestPrevHashAtomicity:
    def test_concurrent_append_chain_valid(self):
        """
        The core thread-safety fix: prev_hash must be read and set inside
        the lock so concurrent appends never produce duplicate prev_hash values.

        Run 200 concurrent appends and verify the resulting chain is valid.
        """
        registry, bot, res = _setup()
        log = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=log)

        errors = []
        lock = threading.Lock()

        def append_one(i):
            try:
                verifier.verify(Action(f"concurrent-{i}", actor=bot, resources_read=[res]))
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=append_one, args=(i,)) for i in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent append: {errors}"
        assert len(log) == 200
        chain_errors = log.chain_errors()
        assert chain_errors == [], (
            f"Chain broken under concurrent appends — "
            f"prev_hash atomicity fix not working:\n" + "\n".join(chain_errors[:5])
        )
