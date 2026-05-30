"""
Wire format validator tests — IV-1.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from authgate.wire_validator import (
    SCHEMA_FILES, load_schema, validate, ValidationResult,
)


def _hex32():
    return "01" * 32

def _hex16():
    return "ab" * 16

def _hex64():
    return "11" * 64


class TestSchemaLoading:

    def test_load_canonical_action_schema(self):
        s = load_schema("canonical_action")
        assert s["title"] == "CanonicalAction"

    def test_load_gate_result_schema(self):
        s = load_schema("gate_result")
        assert s["title"] == "GateResult"

    def test_load_audit_entry_schema(self):
        s = load_schema("audit_entry")
        assert s["title"] == "AuditEntry"

    def test_unknown_schema_raises(self):
        with pytest.raises(ValueError, match="Unknown schema"):
            load_schema("nonexistent")


class TestCanonicalActionValidation:

    def _valid(self):
        return {
            "actor_id":        _hex32(),
            "resource_hash":   _hex32(),
            "required_rights": 1,
            "nonce":           _hex16(),
            "timestamp":       1000,
            "min_epoch":       0,
            "binding_hash":    _hex32(),
        }

    def test_valid_minimal_action_passes(self):
        r = validate(self._valid(), "canonical_action")
        assert r.valid, r.errors

    def test_missing_required_field_fails(self):
        v = self._valid()
        del v["actor_id"]
        r = validate(v, "canonical_action")
        assert not r.valid

    def test_invalid_hex_pattern_fails(self):
        v = self._valid()
        v["actor_id"] = "not-hex"
        r = validate(v, "canonical_action")
        assert not r.valid

    def test_required_rights_out_of_range_fails(self):
        v = self._valid()
        v["required_rights"] = 999  # > 255
        r = validate(v, "canonical_action")
        assert not r.valid

    def test_string_where_integer_expected_fails(self):
        v = self._valid()
        v["timestamp"] = "not-a-number"
        r = validate(v, "canonical_action")
        assert not r.valid


class TestGateResultValidation:

    def test_minimal_permit(self):
        v = {"permitted": True, "tool_name": "read"}
        r = validate(v, "gate_result")
        assert r.valid, r.errors

    def test_minimal_deny(self):
        v = {"permitted": False, "tool_name": "read", "denied_reason": "no claim"}
        r = validate(v, "gate_result")
        assert r.valid, r.errors

    def test_missing_permitted_fails(self):
        v = {"tool_name": "read"}
        r = validate(v, "gate_result")
        assert not r.valid


class TestAuditEntryValidation:

    def _valid(self):
        return {
            "ts": 1700000000.5,
            "action_id": "test-action",
            "permitted": True,
            "confidence": 1.0,
            "violations": [],
            "warnings": [],
            "signature": None,
            "prev_hash": _hex32(),
            "entry_hash": _hex32(),
        }

    def test_valid_entry_passes(self):
        r = validate(self._valid(), "audit_entry")
        assert r.valid, r.errors

    def test_invalid_hash_fails(self):
        v = self._valid()
        v["entry_hash"] = "short"
        r = validate(v, "audit_entry")
        assert not r.valid


class TestCLIValidate:

    def test_cli_validate_valid_action(self, tmp_path):
        from authgate.cli import main
        valid = {
            "actor_id":        _hex32(),
            "resource_hash":   _hex32(),
            "required_rights": 1,
            "nonce":           _hex16(),
            "timestamp":       1000,
            "min_epoch":       0,
            "binding_hash":    _hex32(),
        }
        path = tmp_path / "action.json"
        path.write_text(json.dumps(valid), encoding="utf-8")
        rc = main(["validate", "--schema", "canonical_action", str(path)])
        assert rc == 0

    def test_cli_validate_invalid_action(self, tmp_path):
        from authgate.cli import main
        invalid = {"actor_id": "bad"}  # missing required fields, bad hash pattern
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(invalid), encoding="utf-8")
        rc = main(["validate", "--schema", "canonical_action", str(path)])
        assert rc == 1
