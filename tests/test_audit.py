"""Phase 5 — AuditLog tests."""
import json
import os
import tempfile

from authgate.kernel.audit import AuditLog
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _setup():
    registry = OwnershipRegistry()
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    bot = Entity(name="bot", kind=AgentType.MACHINE)
    res = Resource(name="/data/alice", rtype=ResourceType.FILE)
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(holder=bot, resource=res, can_read=True, can_write=True))
    return registry, bot, res


def test_audit_log_records_permitted():
    registry, bot, res = _setup()
    log = AuditLog()
    verifier = FreedomVerifier(registry, audit_log=log)
    action = Action(action_id="act1", actor=bot, resources_read=[res])
    verifier.verify(action)
    assert len(log) == 1
    entry = log.entries()[0]
    assert entry["action_id"] == "act1"
    assert entry["permitted"] is True
    assert "ts" in entry


def test_audit_log_records_blocked():
    registry, bot, res = _setup()
    log = AuditLog()
    verifier = FreedomVerifier(registry, audit_log=log)
    action = Action(action_id="bad", actor=bot, increases_machine_sovereignty=True)
    verifier.verify(action)
    assert len(log) == 1
    assert log.entries()[0]["permitted"] is False


def test_audit_log_accumulates():
    registry, bot, res = _setup()
    log = AuditLog()
    verifier = FreedomVerifier(registry, audit_log=log)
    for i in range(5):
        action = Action(action_id=f"a{i}", actor=bot, resources_read=[res])
        verifier.verify(action)
    assert len(log) == 5


def test_audit_log_writes_to_file():
    registry, bot, res = _setup()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
    try:
        log = AuditLog(path=path)
        verifier = FreedomVerifier(registry, audit_log=log)
        action = Action(action_id="file_test", actor=bot, resources_read=[res])
        verifier.verify(action)
        with open(path) as f:
            lines = [line for line in f.readlines() if line.strip()]
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["action_id"] == "file_test"
    finally:
        os.unlink(path)


def test_no_audit_log_no_error():
    registry, bot, res = _setup()
    verifier = FreedomVerifier(registry)  # no audit_log
    action = Action(action_id="no_log", actor=bot, resources_read=[res])
    result = verifier.verify(action)
    assert result.permitted is True


def test_audit_log_entries_snapshot():
    registry, bot, res = _setup()
    log = AuditLog()
    verifier = FreedomVerifier(registry, audit_log=log)
    action = Action(action_id="snap", actor=bot, resources_read=[res])
    verifier.verify(action)
    snap1 = log.entries()
    snap2 = log.entries()
    assert snap1 == snap2
    snap1.clear()
    assert len(log) == 1  # original unaffected
