"""
Schema version tests — II-3 from INFRASTRUCTURE_PLAN.md.
"""

from __future__ import annotations

import pytest
from authgate.kernel.schema_version import (
    SchemaVersion, CURRENT_SCHEMA_VERSION, check_version_compatibility, version_tag
)


class TestSchemaVersion:

    def test_current_version_is_1_0_0(self):
        assert CURRENT_SCHEMA_VERSION == SchemaVersion(1, 0, 0)

    def test_parse_valid(self):
        v = SchemaVersion.parse("2.3.1")
        assert v.major == 2 and v.minor == 3 and v.patch == 1

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            SchemaVersion.parse("1.0")
        with pytest.raises(ValueError):
            SchemaVersion.parse("1.0.0.0")

    def test_str_roundtrip(self):
        v = SchemaVersion(1, 2, 3)
        assert str(v) == "1.2.3"
        assert SchemaVersion.parse(str(v)) == v

    def test_compatibility_same_major(self):
        v1 = SchemaVersion(1, 0, 0)
        v2 = SchemaVersion(1, 5, 3)
        assert v1.is_compatible_with(v2)
        assert v2.is_compatible_with(v1)

    def test_incompatibility_different_major(self):
        v1 = SchemaVersion(1, 0, 0)
        v2 = SchemaVersion(2, 0, 0)
        assert not v1.is_compatible_with(v2)
        assert v1.requires_reissuance(v2)

    def test_ordering(self):
        v1 = SchemaVersion(1, 0, 0)
        v2 = SchemaVersion(1, 1, 0)
        v3 = SchemaVersion(2, 0, 0)
        assert v1 < v2 < v3

    def test_check_compatible_same_major(self):
        ok, reason = check_version_compatibility("1.0.0")
        assert ok, reason

    def test_check_compatible_newer_minor(self):
        ok, reason = check_version_compatibility("1.5.0")
        assert ok, reason

    def test_check_incompatible_different_major(self):
        ok, reason = check_version_compatibility("2.0.0")
        assert not ok
        assert "MAJOR mismatch" in reason

    def test_check_invalid_version_string(self):
        ok, reason = check_version_compatibility("not-a-version")
        assert not ok
        assert "Invalid" in reason

    def test_version_tag_returns_string(self):
        tag = version_tag()
        assert tag == "1.0.0"
        assert SchemaVersion.parse(tag) == CURRENT_SCHEMA_VERSION
