"""
Typed Tool ABI versioning + JSON Schema export tests — III-2.
"""

from __future__ import annotations

from authgate.kernel.tool_abi import (
    TOOL_ABI_VERSION, ToolSchema, ToolParam, ToolABIRegistry,
)


class TestToolABIVersioning:

    def test_version_constant_is_1_0_0(self):
        assert TOOL_ABI_VERSION == "1.0.0"

    def test_schema_default_version_matches_constant(self):
        s = ToolSchema(name="t")
        assert s.schema_version == TOOL_ABI_VERSION

    def test_schema_explicit_version(self):
        s = ToolSchema(name="t", schema_version="2.0.0")
        assert s.schema_version == "2.0.0"


class TestToolABIJsonSchemaExport:

    def test_empty_schema_exports(self):
        s = ToolSchema(name="noop")
        export = s.to_json_schema()
        assert export["title"] == "noop"
        assert export["type"] == "object"
        assert export["properties"] == {}
        assert export["required"] == []
        assert export["x-authgate-tool-abi-version"] == TOOL_ABI_VERSION

    def test_schema_with_string_parameter(self):
        s = ToolSchema(
            name="read_file",
            required_rights={"read"},
            parameters=[ToolParam("path", str, required=True, scope_constrained=True)],
        )
        export = s.to_json_schema()
        assert "path" in export["properties"]
        assert export["properties"]["path"]["type"] == "string"
        assert export["properties"]["path"]["x-scope-constrained"] is True
        assert "path" in export["required"]
        assert "read" in export["x-required-rights"]

    def test_schema_with_optional_parameter(self):
        s = ToolSchema(name="t", parameters=[ToolParam("opt", str, required=False)])
        export = s.to_json_schema()
        assert "opt" in export["properties"]
        assert export["required"] == []

    def test_schema_with_allowed_values_becomes_enum(self):
        s = ToolSchema(name="t", parameters=[
            ToolParam("mode", str, allowed_values=("read", "write", "delegate"))
        ])
        export = s.to_json_schema()
        assert export["properties"]["mode"]["enum"] == ["read", "write", "delegate"]

    def test_schema_with_max_length(self):
        s = ToolSchema(name="t", parameters=[
            ToolParam("name", str, max_length=100)
        ])
        export = s.to_json_schema()
        assert export["properties"]["name"]["maxLength"] == 100

    def test_schema_with_int_parameter(self):
        s = ToolSchema(name="count", parameters=[ToolParam("n", int)])
        export = s.to_json_schema()
        assert export["properties"]["n"]["type"] == "integer"

    def test_schema_with_bool_parameter(self):
        s = ToolSchema(name="flag", parameters=[ToolParam("enabled", bool)])
        export = s.to_json_schema()
        assert export["properties"]["enabled"]["type"] == "boolean"

    def test_required_rights_serialized_as_sorted_list(self):
        s = ToolSchema(name="t", required_rights={"write", "read", "delegate"})
        export = s.to_json_schema()
        assert export["x-required-rights"] == ["delegate", "read", "write"]

    def test_resource_scope_preserved(self):
        s = ToolSchema(name="t", resource_scope="/data/")
        export = s.to_json_schema()
        assert export["x-resource-scope"] == "/data/"

    def test_is_delegable_preserved(self):
        s = ToolSchema(name="t", is_delegable=False)
        export = s.to_json_schema()
        assert export["x-is-delegable"] is False


class TestToolABIRegistryIntegration:

    def test_registry_validates_call(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="read",
            required_rights=frozenset({"read"}),
            parameters=[ToolParam("path", str, required=True)],
        ))
        result = reg.validate_call("read", {"path": "/data/x"}, rights_held={"read"})
        assert result.valid

    def test_registry_rejects_insufficient_rights(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="write",
            required_rights=frozenset({"write"}),
            parameters=[ToolParam("path", str, required=True)],
        ))
        result = reg.validate_call("write", {"path": "/data/x"}, rights_held={"read"})
        assert not result.valid
