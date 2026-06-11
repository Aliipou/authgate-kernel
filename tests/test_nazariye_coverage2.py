"""
Coverage tests (batch 2) added on the `nazariye-azadi` branch.

Targets the typed error hierarchy, the observability tracer, and the wire
validator — all pure modules whose branches the existing suite did not drive.
"""
from __future__ import annotations

import sys

import pytest

from authgate import errors
from authgate import wire_validator as wv
from authgate.kernel.tracing import TraceCollector

# --------------------------------------------------------------------------- #
# errors.py — every __str__ branch, with and without optional fields
# --------------------------------------------------------------------------- #

def test_capability_error_str_with_and_without_detail():
    bare = errors.CapabilityError("a1", "file:x", "expired")
    assert "CapabilityError(expired)" in str(bare)
    assert "—" not in str(bare)
    detailed = errors.CapabilityError("a1", "file:x", "expired", detail="t+5")
    assert "t+5" in str(detailed)


def test_rights_error_str():
    e = errors.RightsError("a1", "file:x", "write", "no_claim")
    s = str(e)
    assert "cannot write" in s and "no_claim" in s


def test_integrity_error_str_with_and_without_index():
    assert "at entry 3" in str(errors.IntegrityError("audit_chain", entry_index=3))
    assert "at entry" not in str(errors.IntegrityError("signature"))


def test_wire_error_str_all_fields_and_empty():
    assert str(errors.WireError()) == "WireError"
    full = errors.WireError(field="nonce", value="x" * 300, attack_class="WA-7")
    s = str(full)
    assert "field='nonce'" in s and "[WA-7]" in s
    assert len(s) < 300  # value truncated to 200


def test_registry_and_keyrotation_error_str():
    assert "RegistryError(add_claim): frozen" in str(
        errors.RegistryError("add_claim", "frozen")
    )
    assert "— ctx" in str(errors.RegistryError("delegate", "conflict", detail="ctx"))
    assert "epoch=2" in str(errors.KeyRotationError(2, "same_pubkey"))
    assert "— more" in str(errors.KeyRotationError(2, "same_pubkey", detail="more"))


def test_error_hierarchy_is_authgate_error():
    for exc in (
        errors.CapabilityError("a", "r", "c"),
        errors.RightsError("a", "r", "read", "x"),
        errors.IntegrityError("signature"),
        errors.WireError(),
        errors.RegistryError("op", "reason"),
        errors.KeyRotationError(1, "reason"),
    ):
        assert isinstance(exc, errors.AuthgateError)


# --------------------------------------------------------------------------- #
# tracing.py — full lifecycle plus the guard/edge branches
# --------------------------------------------------------------------------- #

def test_trace_collector_full_lifecycle_permitted_and_blocked():
    tracer = TraceCollector()
    assert tracer.last() is None  # empty

    tracer.begin("act-1")
    tracer.record_guard("sovereignty_flags", passed=True, detail="clear")
    tracer.record_guard("claim_check", passed=False, detail="conf=0.1")
    trace = tracer.finish(permitted=False)

    assert trace.action_id == "act-1"
    assert len(trace.guards) == 2
    assert trace.total_duration_us >= 0.0
    # blocked summary uses ✗ for failing guard
    s = trace.summary()
    assert "[BLOCKED]" in s and "✗" in s and "✓" in s

    # a second, permitted trace
    tracer.begin("act-2")
    tracer.record_guard("machine_ownership", passed=True)
    t2 = tracer.finish(permitted=True)
    assert "[PERMITTED]" in t2.summary()

    assert tracer.last() is t2
    assert len(tracer.all()) == 2
    tracer.clear()
    assert tracer.all() == []


def test_record_guard_before_begin_is_noop():
    tracer = TraceCollector()
    # _current is None -> record_guard returns without error
    tracer.record_guard("x", passed=True)
    assert tracer.last() is None


def test_finish_before_begin_raises():
    tracer = TraceCollector()
    with pytest.raises(RuntimeError):
        tracer.finish(permitted=True)


# --------------------------------------------------------------------------- #
# wire_validator.py — schema loading, jsonschema path, minimal fallback
# --------------------------------------------------------------------------- #

def test_load_schema_known_unknown_and_missing(monkeypatch):
    schema = wv.load_schema("gate_result")
    assert schema["title"] == "GateResult"

    with pytest.raises(ValueError):
        wv.load_schema("does_not_exist")

    # Register a name that points at a missing file -> FileNotFoundError
    monkeypatch.setitem(wv.SCHEMA_FILES, "phantom", "phantom.schema.json")
    with pytest.raises(FileNotFoundError):
        wv.load_schema("phantom")


def test_validate_jsonschema_valid_and_invalid():
    pytest.importorskip("jsonschema")
    ok = wv.validate({"permitted": True, "tool_name": "read"}, "gate_result")
    assert bool(ok) is True and ok.errors == ()

    bad = wv.validate({"permitted": "yes"}, "gate_result")  # wrong type + missing required
    assert bool(bad) is False
    assert len(bad.errors) >= 1


def test_validate_falls_back_to_minimal_when_jsonschema_absent(monkeypatch):
    # Force `import jsonschema` to raise ImportError inside validate()
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    result = wv.validate({"permitted": True, "tool_name": "x"}, "gate_result")
    assert bool(result) is True


def test_minimal_validate_branches():
    schema = {
        "required": ["a"],
        "additionalProperties": False,
        "properties": {
            "a": {"type": "string", "pattern": r"^[0-9a-f]+$"},
            "n": {"type": "integer", "minimum": 0, "maximum": 10},
        },
    }
    # non-dict instance
    assert wv._minimal_validate([], schema).valid is False
    # missing required + pattern mismatch + unknown field + out-of-range
    res = wv._minimal_validate(
        {"a": "ZZZ", "n": 99, "extra": 1}, schema
    )
    assert res.valid is False
    joined = " ".join(res.errors)
    assert "pattern" in joined
    assert "maximum" in joined
    assert "unknown field" in joined
    # missing required field 'a'
    res2 = wv._minimal_validate({"n": -1}, schema)
    assert any("missing required" in e for e in res2.errors)
    assert any("minimum" in e for e in res2.errors)
    # type mismatch
    res3 = wv._minimal_validate({"a": 123}, schema)
    assert any("expected string" in e for e in res3.errors)
    # all-valid case
    assert wv._minimal_validate({"a": "abc", "n": 5}, schema).valid is True


def test_check_type_all_kinds():
    assert wv._check_type("s", "string")
    assert wv._check_type(3, "integer")
    assert not wv._check_type(True, "integer")  # bool is not integer here
    assert wv._check_type(3.5, "number")
    assert not wv._check_type(True, "number")
    assert wv._check_type(True, "boolean")
    assert wv._check_type([], "array")
    assert wv._check_type({}, "object")
    assert wv._check_type(None, "null")
    assert wv._check_type("s", ["string", "integer"])  # union
    assert not wv._check_type(object(), "string")
    assert not wv._check_type("s", "unknown-type")
