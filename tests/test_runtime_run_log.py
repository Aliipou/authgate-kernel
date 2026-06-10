"""Unit tests for authgate.runtime.run_log.RunLog."""
from __future__ import annotations

import json

from authgate.runtime.run_log import RunLog


def test_record_permit_entry_shape():
    log = RunLog()
    log.record("agent-1", 0, "calculator", {"expression": "1+1"}, True, output="2")
    entry = log.entries()[0]
    assert entry["agent_id"] == "agent-1"
    assert entry["step"] == 0
    assert entry["tool"] == "calculator"
    assert entry["args"] == {"expression": "1+1"}
    assert entry["decision"] == "permit"
    assert entry["output"] == "2"
    assert entry["denied_reason"] is None
    assert "ts" in entry


def test_record_deny_entry_shape():
    log = RunLog()
    log.record(
        "agent-1", 1, "file_read", {"filename": "a.txt"}, False,
        output="should be dropped", denied_reason="capability gate denied",
    )
    entry = log.entries()[0]
    assert entry["decision"] == "deny"
    assert entry["output"] is None  # output suppressed on denial
    assert entry["denied_reason"] == "capability gate denied"


def test_record_output_is_stringified():
    log = RunLog()
    log.record("a", 0, "calculator", {}, True, output=42)
    assert log.entries()[0]["output"] == "42"


def test_record_output_truncated_at_2000_chars():
    log = RunLog()
    big = "x" * 5000
    log.record("a", 0, "tool", {}, True, output=big)
    assert len(log.entries()[0]["output"]) == 2000


def test_record_output_under_limit_not_truncated():
    log = RunLog()
    payload = "y" * 1999
    log.record("a", 0, "tool", {}, True, output=payload)
    assert log.entries()[0]["output"] == payload


def test_entries_returns_copy():
    log = RunLog()
    log.record("a", 0, "tool", {}, True, output="ok")
    snapshot = log.entries()
    snapshot.append({"injected": True})
    assert len(log.entries()) == 1  # internal state unaffected


def test_len_tracks_record_count():
    log = RunLog()
    assert len(log) == 0
    log.record("a", 0, "tool", {}, True, output="ok")
    log.record("a", 1, "tool", {}, False, denied_reason="no")
    assert len(log) == 2


def test_path_mode_writes_valid_jsonl(tmp_path):
    log_path = tmp_path / "run.jsonl"
    log = RunLog(path=str(log_path))
    log.record("a", 0, "calculator", {"expression": "1+1"}, True, output="2")
    log.record("a", 1, "file_read", {"filename": "x"}, False, denied_reason="denied")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["decision"] == "permit"
    assert parsed[0]["output"] == "2"
    assert parsed[1]["decision"] == "deny"
    assert parsed[1]["output"] is None
    assert parsed[1]["denied_reason"] == "denied"


def test_path_mode_appends_across_records(tmp_path):
    log_path = tmp_path / "run.jsonl"
    log = RunLog(path=str(log_path))
    for i in range(3):
        log.record("a", i, "tool", {}, True, output=str(i))
    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 3


def test_memory_mode_creates_no_file(tmp_path):
    log = RunLog()  # path=None
    log.record("a", 0, "tool", {}, True, output="ok")
    assert list(tmp_path.iterdir()) == []
