"""
Wire format validator — IV-1.

Validates JSON objects against the published JSON Schemas in spec/.
External implementers can use this to verify their CanonicalAction
construction before submitting to authgate.

Falls back to a minimal validator when `jsonschema` package is not installed
(no hard dependency — keeps install footprint small).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SPEC_DIR = Path(__file__).parent.parent.parent / "spec"

SCHEMA_FILES = {
    "canonical_action": "canonical_action.schema.json",
    "gate_result":      "gate_result.schema.json",
    "audit_entry":      "audit_entry.schema.json",
}


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.valid


def load_schema(name: str) -> dict:
    """Load a schema by short name (e.g. 'canonical_action')."""
    if name not in SCHEMA_FILES:
        raise ValueError(
            f"Unknown schema {name!r}. Available: {sorted(SCHEMA_FILES)}"
        )
    path = SPEC_DIR / SCHEMA_FILES[name]
    if not path.exists():
        raise FileNotFoundError(f"Schema file missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: dict, schema_name: str) -> ValidationResult:
    """
    Validate `instance` against the named schema.

    Uses the `jsonschema` package if installed (full Draft 2020-12 support).
    Otherwise applies a minimal structural validator covering:
      - required fields present
      - types match
      - string patterns (for hex hashes)
    Returns ValidationResult(valid, errors).
    """
    schema = load_schema(schema_name)

    try:
        import jsonschema   # type: ignore
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
        if not errors:
            return ValidationResult(valid=True)
        return ValidationResult(
            valid=False,
            errors=tuple(f"{'.'.join(str(p) for p in e.path)}: {e.message}" for e in errors),
        )
    except ImportError:
        return _minimal_validate(instance, schema)


def _minimal_validate(instance: dict, schema: dict, path: str = "") -> ValidationResult:
    """Fallback validator covering required/type/pattern when jsonschema is unavailable."""
    import re
    errors: list[str] = []

    if not isinstance(instance, dict):
        return ValidationResult(False, (f"{path or 'root'}: expected object, got {type(instance).__name__}",))

    # Required fields
    for req in schema.get("required", []):
        if req not in instance:
            errors.append(f"{path or 'root'}.{req}: missing required field")

    # Properties: type + pattern
    properties = schema.get("properties", {})
    for key, value in instance.items():
        if key not in properties:
            if schema.get("additionalProperties") is False:
                errors.append(f"{path or 'root'}.{key}: unknown field (additionalProperties: false)")
            continue
        prop_schema = properties[key]
        expected_type = prop_schema.get("type")
        prop_path = f"{path}.{key}" if path else key

        if expected_type:
            type_ok = _check_type(value, expected_type)
            if not type_ok:
                errors.append(f"{prop_path}: expected {expected_type}, got {type(value).__name__}")
                continue

        pattern = prop_schema.get("pattern")
        if pattern and isinstance(value, str):
            if not re.match(pattern, value):
                errors.append(f"{prop_path}: does not match pattern {pattern!r}")

        if "minimum" in prop_schema and isinstance(value, (int, float)):
            if value < prop_schema["minimum"]:
                errors.append(f"{prop_path}: {value} < minimum {prop_schema['minimum']}")
        if "maximum" in prop_schema and isinstance(value, (int, float)):
            if value > prop_schema["maximum"]:
                errors.append(f"{prop_path}: {value} > maximum {prop_schema['maximum']}")

    return ValidationResult(valid=not errors, errors=tuple(errors))


def _check_type(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_check_type(value, t) for t in expected)
    return {
        "string":  isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number":  isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "array":   isinstance(value, list),
        "object":  isinstance(value, dict),
        "null":    value is None,
    }.get(expected, False)
