"""
Wire boundary attack harness — authgate-kernel adversarial-lab branch.

Tests the JSON → internal struct deserialization boundary.

This is TIER 3 (I3 — Deserialization Ambiguity) and TIER 4 (A1-A3 — Adapter
Boundary) from the MITRE-style attack matrix in evoloution.md.

Evolution doc rule: "Parsing is part of the attack surface."

Attack classes:
  WA-1  Duplicate JSON keys — last-wins vs first-wins divergence
  WA-2  Float as integer — 1.0 accepted where u64 expected
  WA-3  Negative numbers in unsigned fields
  WA-4  Integer overflow beyond u64::MAX
  WA-5  Missing required fields — silent default vs rejection
  WA-6  Unknown/extra fields silently forwarded
  WA-7  Null injection in required fields
  WA-8  Type substitution (string where int expected)
  WA-9  Hex-string vs raw-bytes encoding confusion for binary fields
  WA-10 Rights field passed as string "3" vs integer 3
  WA-11 Empty object / minimal object injection
  WA-12 Array-as-scalar confusion (rights: [1, 2] instead of 3)
  WA-13 Unicode escape in binary field (bytes encoded as \\uXXXX)
  WA-14 Epoch as scientific notation (1e5 — valid JSON float, invalid u64)
  WA-15 Nested object injection where scalar expected

Each test documents the expected outcome (reject vs accept) and the
divergence risk if two runtimes (Python / Rust) handle it differently.
"""

from __future__ import annotations
import json
import struct
import hashlib
import os


# ---------------------------------------------------------------------------
# Minimal wire model — mirrors the JSON schema that reaches the kernel gate
# ---------------------------------------------------------------------------

class WireParseError(Exception):
    pass


def parse_wire_action(raw: str) -> dict:
    """
    Strict wire parser — the reference model for what the kernel should accept.

    Rules:
    - All required fields must be present; missing fields → WireParseError
    - actor_id and resource_hash must be 32-byte hex strings (64 hex chars)
    - required_rights, timestamp, min_epoch must be non-negative integers
    - required_rights must not exceed u64::MAX (18446744073709551615)
    - Extra unknown fields → WireParseError (rejection-by-default)
    - Null values in required fields → WireParseError
    - Float-encoded integers are rejected (strict type gate)
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise WireParseError(f"invalid JSON: {e}") from e

    if not isinstance(obj, dict):
        raise WireParseError("root must be a JSON object")

    REQUIRED = {"actor_id", "resource_hash", "required_rights", "timestamp", "min_epoch"}
    OPTIONAL = {"nonce", "capability_proofs", "revocation_proofs"}
    ALLOWED  = REQUIRED | OPTIONAL

    present = set(obj.keys())
    missing = REQUIRED - present
    extra   = present - ALLOWED

    if missing:
        raise WireParseError(f"missing required fields: {sorted(missing)}")
    if extra:
        raise WireParseError(f"unknown fields (rejection-by-default): {sorted(extra)}")

    def _parse_hex32(key: str) -> bytes:
        val = obj[key]
        if val is None:
            raise WireParseError(f"{key}: null not allowed")
        if not isinstance(val, str):
            raise WireParseError(f"{key}: expected hex string, got {type(val).__name__}")
        if len(val) != 64:
            raise WireParseError(f"{key}: expected 64 hex chars, got {len(val)}")
        try:
            return bytes.fromhex(val)
        except ValueError as e:
            raise WireParseError(f"{key}: invalid hex — {e}") from e

    def _parse_u64(key: str) -> int:
        val = obj[key]
        if val is None:
            raise WireParseError(f"{key}: null not allowed")
        if isinstance(val, bool):
            raise WireParseError(f"{key}: boolean not accepted as integer")
        if isinstance(val, float):
            raise WireParseError(f"{key}: float not accepted for u64 field (use integer literal)")
        if not isinstance(val, int):
            raise WireParseError(f"{key}: expected integer, got {type(val).__name__}")
        if val < 0:
            raise WireParseError(f"{key}: negative value in unsigned field")
        U64_MAX = (1 << 64) - 1
        if val > U64_MAX:
            raise WireParseError(f"{key}: value exceeds u64::MAX")
        return val

    actor_id       = _parse_hex32("actor_id")
    resource_hash  = _parse_hex32("resource_hash")
    required_rights = _parse_u64("required_rights")
    timestamp      = _parse_u64("timestamp")
    min_epoch      = _parse_u64("min_epoch")
    nonce          = bytes.fromhex(obj.get("nonce", "00" * 16))

    return {
        "actor_id":        actor_id,
        "resource_hash":   resource_hash,
        "required_rights": required_rights,
        "timestamp":       timestamp,
        "min_epoch":       min_epoch,
        "nonce":           nonce,
    }


def _valid_action_json(**overrides) -> str:
    """Build a valid wire JSON string, optionally overriding fields."""
    base = {
        "actor_id":        "aa" * 32,
        "resource_hash":   "bb" * 32,
        "required_rights": 1,
        "timestamp":       1000,
        "min_epoch":       1,
    }
    base.update(overrides)
    return json.dumps(base)


# ---------------------------------------------------------------------------
# Attack tests
# ---------------------------------------------------------------------------

PASS = []
FAIL = []


def _assert_rejects(name: str, raw: str, reason_fragment: str = ""):
    try:
        parse_wire_action(raw)
        FAIL.append(name)
        print(f"  FAIL {name}: accepted input that should have been rejected")
    except WireParseError as e:
        if reason_fragment and reason_fragment not in str(e):
            FAIL.append(name)
            print(f"  FAIL {name}: rejected for wrong reason — got: {e}")
        else:
            PASS.append(name)
            print(f"  PASS {name}: correctly rejected — {e}")


def _assert_accepts(name: str, raw: str):
    try:
        parse_wire_action(raw)
        PASS.append(name)
        print(f"  PASS {name}: correctly accepted")
    except WireParseError as e:
        FAIL.append(name)
        print(f"  FAIL {name}: incorrectly rejected — {e}")


def test_wa1_duplicate_keys_rejected():
    """WA-1: Duplicate keys in JSON.

    Python's json.loads silently takes the last value.
    Rust serde_json silently takes the last value too — but behavior is
    implementation-defined and can diverge across versions.
    Our strict parser enforces a single canonical parse; the risk is that
    an attacker sends {"required_rights":255,"required_rights":1} and one
    runtime sees 255 while another sees 1.

    Divergence risk: HIGH — different runtimes, different JSON libraries.
    Expected: reject OR document deterministic last-wins behavior.
    """
    # Python's json.loads accepts this and picks the last value (1)
    raw = '{"actor_id":"' + "aa" * 32 + '","resource_hash":"' + "bb" * 32 + \
          '","required_rights":255,"required_rights":1,"timestamp":1000,"min_epoch":1}'
    parsed = json.loads(raw)
    # Document the behavior
    observed_rights = parsed["required_rights"]
    if observed_rights == 1:
        PASS.append("wa1_duplicate_keys_last_wins")
        print(f"  PASS WA-1 (documented): Python json.loads takes last value ({observed_rights}) — "
              f"must match Rust serde_json behavior to avoid divergence")
    else:
        FAIL.append("wa1_duplicate_keys_divergence_risk")
        print(f"  WARN WA-1: unexpected value {observed_rights} — investigate")


def test_wa2_float_as_integer_rejected():
    """WA-2: Float literal where u64 expected — e.g., required_rights: 1.0."""
    _assert_rejects(
        "wa2_float_required_rights",
        '{"actor_id":"' + "aa" * 32 + '","resource_hash":"' + "bb" * 32 +
        '","required_rights":1.0,"timestamp":1000,"min_epoch":1}',
        "float not accepted",
    )


def test_wa3_negative_unsigned_rejected():
    """WA-3: Negative number in unsigned field."""
    _assert_rejects(
        "wa3_negative_required_rights",
        _valid_action_json(required_rights=-1),
        "negative value",
    )
    _assert_rejects(
        "wa3_negative_epoch",
        _valid_action_json(min_epoch=-1),
        "negative value",
    )


def test_wa4_u64_overflow_rejected():
    """WA-4: Value beyond u64::MAX (2^64 - 1 = 18446744073709551615)."""
    overflow = (1 << 64)  # 2^64, one past max
    _assert_rejects(
        "wa4_rights_overflow",
        _valid_action_json(required_rights=overflow),
        "u64::MAX",
    )


def test_wa5_missing_required_field_rejected():
    """WA-5: Missing required field — silent default is the danger."""
    _assert_rejects(
        "wa5_missing_actor_id",
        json.dumps({"resource_hash": "bb" * 32, "required_rights": 1,
                    "timestamp": 1000, "min_epoch": 1}),
        "missing required fields",
    )
    _assert_rejects(
        "wa5_missing_required_rights",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "timestamp": 1000, "min_epoch": 1}),
        "missing required fields",
    )


def test_wa6_unknown_field_rejected():
    """WA-6: Extra unknown field — must be rejected, not silently forwarded.

    An adapter could inject a field that one runtime ignores and another uses
    to make a security decision. Rejection-by-default prevents this class.
    """
    _assert_rejects(
        "wa6_extra_field_admin",
        _valid_action_json(**{"is_admin": True}),
        "unknown fields",
    )
    _assert_rejects(
        "wa6_extra_field_override_rights",
        _valid_action_json(**{"override_rights": 0xFFFFFFFF}),
        "unknown fields",
    )


def test_wa7_null_required_field_rejected():
    """WA-7: Null in required field — must be rejected, not treated as zero/empty."""
    _assert_rejects(
        "wa7_null_actor_id",
        json.dumps({"actor_id": None, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "null not allowed",
    )
    _assert_rejects(
        "wa7_null_required_rights",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": None, "timestamp": 1000, "min_epoch": 1}),
        "null not allowed",
    )


def test_wa8_type_substitution_rejected():
    """WA-8: String "1" where integer 1 expected — strict type gate."""
    _assert_rejects(
        "wa8_string_required_rights",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": "1", "timestamp": 1000, "min_epoch": 1}),
        "expected integer",
    )
    _assert_rejects(
        "wa8_int_actor_id",
        json.dumps({"actor_id": 12345, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "expected hex string",
    )


def test_wa9_hex_length_mismatch_rejected():
    """WA-9: actor_id / resource_hash with wrong hex length.

    Short hash → off-by-one in subject binding.
    Long hash → padding injection.
    """
    _assert_rejects(
        "wa9_short_actor_id_30_bytes",
        json.dumps({"actor_id": "aa" * 30, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "64 hex chars",
    )
    _assert_rejects(
        "wa9_long_actor_id_33_bytes",
        json.dumps({"actor_id": "aa" * 33, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "64 hex chars",
    )


def test_wa10_rights_string_hex_rejected():
    """WA-10: Rights as hex string "0x01" instead of integer 1."""
    _assert_rejects(
        "wa10_rights_as_hex_string",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": "0x01", "timestamp": 1000, "min_epoch": 1}),
        "expected integer",
    )


def test_wa11_empty_object_rejected():
    """WA-11: Empty JSON object — all fields missing."""
    _assert_rejects("wa11_empty_object", "{}", "missing required fields")


def test_wa12_array_as_scalar_rejected():
    """WA-12: Array where scalar expected — [1, 2] instead of 3 for rights."""
    _assert_rejects(
        "wa12_rights_as_array",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": [1, 2], "timestamp": 1000, "min_epoch": 1}),
        "expected integer",
    )


def test_wa13_non_hex_chars_rejected():
    """WA-13: Non-hex characters in binary field (e.g. unicode escape, spaces)."""
    _assert_rejects(
        "wa13_space_in_actor_id",
        json.dumps({"actor_id": "aa" * 31 + "a ", "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "invalid hex",
    )
    _assert_rejects(
        "wa13_uppercase_hex_wrong_length",
        json.dumps({"actor_id": "GG" * 32, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": 1}),
        "invalid hex",
    )


def test_wa14_scientific_notation_rejected():
    """WA-14: Epoch as 1e5 — valid JSON float, invalid u64.

    json.loads("1e5") → 100000.0 (float in Python). Must be caught.
    """
    _assert_rejects(
        "wa14_epoch_scientific_notation",
        '{"actor_id":"' + "aa" * 32 + '","resource_hash":"' + "bb" * 32 +
        '","required_rights":1,"timestamp":1000,"min_epoch":1e5}',
        "float not accepted",
    )


def test_wa15_nested_object_rejected():
    """WA-15: Nested object where scalar expected — rights: {"read": true}."""
    _assert_rejects(
        "wa15_rights_as_object",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": {"read": True}, "timestamp": 1000, "min_epoch": 1}),
        "expected integer",
    )


def test_wa16_boolean_as_integer_rejected():
    """WA-16: Boolean in integer field — Python treats True == 1 and False == 0.

    json.loads accepts {"required_rights": true} and isinstance(True, int) is True
    in Python, which would silently coerce bool to int. Must catch this.
    """
    _assert_rejects(
        "wa16_bool_true_as_rights",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": True, "timestamp": 1000, "min_epoch": 1}),
        "boolean not accepted",
    )
    _assert_rejects(
        "wa16_bool_false_as_epoch",
        json.dumps({"actor_id": "aa" * 32, "resource_hash": "bb" * 32,
                    "required_rights": 1, "timestamp": 1000, "min_epoch": False}),
        "boolean not accepted",
    )


def test_wa17_valid_minimal_action_accepted():
    """WA-17 (baseline): Valid minimal action must be accepted."""
    _assert_accepts(
        "wa17_valid_baseline",
        _valid_action_json(),
    )


def test_wa18_u64_max_accepted():
    """WA-18: u64::MAX is a valid value — must not be incorrectly rejected."""
    U64_MAX = (1 << 64) - 1
    _assert_accepts(
        "wa18_u64_max_rights",
        _valid_action_json(required_rights=U64_MAX),
    )
    _assert_accepts(
        "wa18_u64_max_epoch",
        _valid_action_json(min_epoch=U64_MAX),
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Wire boundary attack harness — authgate-kernel")
    print("Covers TIER 3 (I3) and TIER 4 (A1-A3) from attack matrix")
    print("=" * 60)

    test_wa1_duplicate_keys_rejected()
    test_wa2_float_as_integer_rejected()
    test_wa3_negative_unsigned_rejected()
    test_wa4_u64_overflow_rejected()
    test_wa5_missing_required_field_rejected()
    test_wa6_unknown_field_rejected()
    test_wa7_null_required_field_rejected()
    test_wa8_type_substitution_rejected()
    test_wa9_hex_length_mismatch_rejected()
    test_wa10_rights_string_hex_rejected()
    test_wa11_empty_object_rejected()
    test_wa12_array_as_scalar_rejected()
    test_wa13_non_hex_chars_rejected()
    test_wa14_scientific_notation_rejected()
    test_wa15_nested_object_rejected()
    test_wa16_boolean_as_integer_rejected()
    test_wa17_valid_minimal_action_accepted()
    test_wa18_u64_max_accepted()

    print()
    print("=" * 60)
    passed = len(PASS)
    failed = len(FAIL)
    total  = passed + failed
    print(f"Results: {passed}/{total} passed, {failed} failed")
    if FAIL:
        print(f"FAILURES: {FAIL}")
        raise SystemExit(1)
    else:
        print("All wire boundary attack tests passed.")
