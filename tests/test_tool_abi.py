"""
Tests for Phase 1/O2: Typed Tool ABI.

ToolSchema, ToolParam, ToolABIRegistry validate typed tool calls against schemas.
"""
import pytest

from authgate.kernel.tool_abi import (
    ToolABIError,
    ToolABIRegistry,
    ToolCallValidation,
    ToolParam,
    ToolSchema,
)


# ── ToolSchema construction ───────────────────────────────────────────────────

class TestToolSchema:
    def test_schema_instantiates(self):
        schema = ToolSchema(name="read_file", required_rights=frozenset({"read"}))
        assert schema.name == "read_file"

    def test_empty_name_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            ToolSchema(name="")

    def test_required_rights_frozen(self):
        schema = ToolSchema(name="op", required_rights={"read", "write"})
        assert isinstance(schema.required_rights, frozenset)

    def test_delegable_default_true(self):
        schema = ToolSchema(name="tool")
        assert schema.is_delegable is True

    def test_not_delegable(self):
        schema = ToolSchema(name="secret", is_delegable=False)
        assert not schema.is_delegable


# ── ToolParam ─────────────────────────────────────────────────────────────────

class TestToolParam:
    def test_param_fields(self):
        p = ToolParam("path", str, required=True, scope_constrained=True)
        assert p.name == "path"
        assert p.type is str
        assert p.scope_constrained

    def test_allowed_values(self):
        p = ToolParam("mode", str, allowed_values=("r", "w", "rw"))
        assert p.allowed_values == ("r", "w", "rw")


# ── ToolABIRegistry ───────────────────────────────────────────────────────────

class TestToolABIRegistry:
    def _make_registry(self) -> ToolABIRegistry:
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="read_file",
            required_rights=frozenset({"read"}),
            parameters=[ToolParam("path", str, required=True)],
        ))
        reg.register(ToolSchema(
            name="write_file",
            required_rights=frozenset({"write"}),
            parameters=[
                ToolParam("path", str, required=True),
                ToolParam("content", str, required=True, max_length=1024),
            ],
        ))
        return reg

    def test_register_and_get(self):
        reg = self._make_registry()
        assert reg.get("read_file") is not None
        assert reg.get("write_file") is not None
        assert reg.get("nonexistent") is None

    def test_duplicate_register_raises(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="already registered"):
            reg.register(ToolSchema(name="read_file"))

    def test_names_returns_all(self):
        reg = self._make_registry()
        assert set(reg.names()) == {"read_file", "write_file"}

    # -- Valid calls --

    def test_valid_call_passes(self):
        reg = self._make_registry()
        result = reg.validate_call("read_file", {"path": "/data/report.csv"}, rights_held={"read"})
        assert result.valid

    def test_valid_write_call_passes(self):
        reg = self._make_registry()
        result = reg.validate_call("write_file", {"path": "/out/x.txt", "content": "hello"}, rights_held={"write"})
        assert result.valid

    # -- Unknown tool --

    def test_unknown_tool_fails(self):
        reg = self._make_registry()
        result = reg.validate_call("nonexistent", {}, rights_held={"read"})
        assert not result.valid
        assert "Unknown tool" in result.reason

    # -- Missing rights --

    def test_missing_right_fails(self):
        reg = self._make_registry()
        result = reg.validate_call("write_file", {"path": "/x", "content": "y"}, rights_held={"read"})
        assert not result.valid
        assert "write" in result.reason
        assert "write" in result.missing_rights

    def test_partial_rights_fails(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(name="op", required_rights=frozenset({"read", "write"})))
        result = reg.validate_call("op", {}, rights_held={"read"})
        assert not result.valid

    # -- Required params --

    def test_missing_required_param_fails(self):
        reg = self._make_registry()
        result = reg.validate_call("read_file", {}, rights_held={"read"})
        assert not result.valid
        assert "path" in result.reason

    # -- Type validation --

    def test_wrong_param_type_fails(self):
        reg = self._make_registry()
        result = reg.validate_call("read_file", {"path": 42}, rights_held={"read"})
        assert not result.valid
        assert "path" in result.reason

    # -- Unknown params --

    def test_unknown_param_fails(self):
        reg = self._make_registry()
        result = reg.validate_call("read_file", {"path": "/x", "extra": "y"}, rights_held={"read"})
        assert not result.valid
        assert "unknown" in result.reason.lower()

    # -- Max length --

    def test_max_length_exceeded_fails(self):
        reg = self._make_registry()
        big = "x" * 2000
        result = reg.validate_call("write_file", {"path": "/x", "content": big}, rights_held={"write"})
        assert not result.valid
        assert "content" in result.reason

    def test_max_length_at_limit_passes(self):
        reg = self._make_registry()
        content = "a" * 1024
        result = reg.validate_call("write_file", {"path": "/x", "content": content}, rights_held={"write"})
        assert result.valid

    # -- Allowed values --

    def test_allowed_values_valid(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="chmod",
            parameters=[ToolParam("mode", str, allowed_values=("read", "write"))],
        ))
        result = reg.validate_call("chmod", {"mode": "read"}, rights_held=set())
        assert result.valid

    def test_allowed_values_invalid(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="chmod",
            parameters=[ToolParam("mode", str, allowed_values=("read", "write"))],
        ))
        result = reg.validate_call("chmod", {"mode": "exec"}, rights_held=set())
        assert not result.valid

    # -- Delegation --

    def test_non_delegable_tool_via_delegation_fails(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(name="admin_op", is_delegable=False))
        result = reg.validate_call("admin_op", {}, rights_held=set(), is_delegated=True)
        assert not result.valid
        assert "delegable" in result.reason.lower()

    def test_delegable_tool_via_delegation_passes(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(name="normal_op", is_delegable=True))
        result = reg.validate_call("normal_op", {}, rights_held=set(), is_delegated=True)
        assert result.valid

    # -- Scope constraint --

    def test_scope_constrained_param_within_scope_passes(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="read_data",
            required_rights=frozenset({"read"}),
            parameters=[ToolParam("path", str, scope_constrained=True)],
        ))
        result = reg.validate_call(
            "read_data",
            {"path": "/data/report.csv"},
            rights_held={"read"},
            caller_scope="/data/",
        )
        assert result.valid

    def test_scope_constrained_param_outside_scope_fails(self):
        reg = ToolABIRegistry()
        reg.register(ToolSchema(
            name="read_data",
            required_rights=frozenset({"read"}),
            parameters=[ToolParam("path", str, scope_constrained=True)],
        ))
        result = reg.validate_call(
            "read_data",
            {"path": "/etc/passwd"},
            rights_held={"read"},
            caller_scope="/data/",
        )
        assert not result.valid

    # -- ToolCallValidation bool protocol --

    def test_valid_result_is_truthy(self):
        r = ToolCallValidation(valid=True)
        assert r

    def test_invalid_result_is_falsy(self):
        r = ToolCallValidation(valid=False, reason="no")
        assert not r
