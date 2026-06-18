"""
Contract conformance — AuthGate's FDK parser must stay in lockstep with the
published PolicyDecision schema (spec/policy_decision.schema.json).

The FDK<->AuthGate boundary is a hand-synced JSON contract across two repos. This
test pins the AuthGate half: the schema's `required` fields are exactly the ones
`parse_policy_decision` enforces, the verdict enum matches, and the parser accepts
a fully-populated payload. If the schema changes, this test breaks here so the
drift is caught in CI rather than in production.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from authgate.integrations.fdk import (
    PolicyContractError as Err,
)
from authgate.integrations.fdk import (
    Verdict,
    parse_policy_decision,
)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "spec" / "policy_decision.schema.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_file_exists_and_is_valid_json():
    schema = _schema()
    assert schema["title"] == "PolicyDecision"


def test_required_fields_match_parser_enforcement():
    required = set(_schema()["required"])
    assert required == {"verdict", "action_id"}
    # The parser must reject a payload missing each required field.
    for field in required:
        payload = {"verdict": "ALLOW", "action_id": "a-1"}
        del payload[field]
        with pytest.raises(Err):
            parse_policy_decision(payload)


def test_verdict_enum_matches_schema():
    schema_enum = set(_schema()["properties"]["verdict"]["enum"])
    assert schema_enum == {v.value for v in Verdict}


def test_parser_accepts_fully_populated_schema_payload():
    # One value per documented property — the parser must accept the superset.
    props = _schema()["properties"]
    payload = {
        "verdict": "DENY",
        "action_id": "a-1",
        "actor": "agent-7",
        "reasons": ["A7: no delegation"],
        "axiom_trace": ["A7"],
        "fail_closed": False,
        "fdk_version": "0.1.0",
        "freeze_version": "1.0",
        "decided_at": "2026-01-01T00:00:00+00:00",
    }
    assert set(payload) == set(props)  # test covers every documented field
    decision = parse_policy_decision(payload)
    assert decision.verdict is Verdict.DENY
    assert decision.axiom_trace == ("A7",)
    assert decision.is_allow is False
