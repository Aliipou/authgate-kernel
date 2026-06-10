"""Unit tests for authgate.runtime.tools — calculator, web_search, file_read, registry."""
from __future__ import annotations

import pytest

from authgate.kernel.entities import Resource, ResourceType
from authgate.runtime.tools import (
    Tool,
    ToolRegistry,
    build_default_tools,
    calculate,
    web_search,
)

# --- calculator: happy path ------------------------------------------------

def test_calculate_respects_operator_precedence():
    assert calculate("2 + 3 * 4") == "14"


def test_calculate_parentheses_override_precedence():
    assert calculate("(2 + 3) * 4") == "20"


def test_calculate_floats():
    assert calculate("3.5 * 2") == "7.0"


def test_calculate_floor_division():
    assert calculate("7 // 2") == "3"


def test_calculate_modulo():
    assert calculate("7 % 3") == "1"


def test_calculate_power():
    assert calculate("2 ** 3") == "8"


def test_calculate_unary_minus():
    assert calculate("-5") == "-5"


def test_calculate_unary_plus():
    assert calculate("+5") == "5"


def test_calculate_true_division_is_float():
    assert calculate("6 / 4") == "1.5"


def test_calculate_nested_expression():
    assert calculate("2 + (3 * (4 - 1))") == "11"


# --- calculator: failure / hostile input -----------------------------------

@pytest.mark.parametrize(
    "expr",
    [
        "__import__('os')",   # function call + name
        "os.system('x')",      # attribute access + call
        "abs(-1)",             # function call
        "foo",                 # bare name
        "a.b",                 # attribute access
        "1 < 2",               # comparison
        "1 == 1",              # comparison
        "",                    # empty string
        "1 +",                 # trailing junk / syntax error
        "[1, 2, 3]",           # list literal
        "1 if True else 2",    # conditional expression
    ],
)
def test_calculate_rejects_unsafe_expressions(expr):
    with pytest.raises(ValueError):
        calculate(expr)


# --- calculator: resource-exhaustion (DoS) bounds --------------------------
# These are valid arithmetic that, unbounded, hang the process building giant
# integers. They must be REFUSED (ValueError), not computed. A regression here
# would hang the test run, so each must return essentially instantly.

@pytest.mark.parametrize(
    "expr",
    [
        "2 ** 2 ** 2 ** 2 ** 2 ** 2",  # ~10^19728 digits: the classic pow-bomb
        "9 ** 9 ** 9",                 # right-assoc tower
        "10 ** 100000",                # single huge exponent
        "1000 ** 1000",                # magnitude blows the result-bits cap
    ],
)
def test_calculate_rejects_resource_exhaustion(expr):
    with pytest.raises(ValueError):
        calculate(expr)


def test_calculate_rejects_overlong_expression():
    with pytest.raises(ValueError, match="too long"):
        calculate("(" * 200 + "1" + ")" * 200)


def test_calculate_normalizes_divide_by_zero_to_valueerror():
    with pytest.raises(ValueError):
        calculate("1 / 0")


def test_calculate_allows_reasonable_power():
    # Just under the exponent cap must still compute fine and fast.
    assert calculate("2 ** 10") == "1024"


# --- web_search ------------------------------------------------------------

def test_web_search_is_deterministic_for_same_query():
    assert web_search("some arbitrary query") == web_search("some arbitrary query")


def test_web_search_canned_authgate_answer():
    result = web_search("authgate")
    assert "capability-constrained authorization kernel" in result


def test_web_search_canned_capability_answer():
    result = web_search("what is a capability")
    assert "unforgeable token" in result


def test_web_search_canned_is_case_and_space_insensitive():
    baseline = web_search("authgate")
    assert web_search("AuthGate") == baseline
    assert web_search("  AUTHGATE  ") == baseline


def test_web_search_unknown_query_returns_mock_marker():
    query = "zzz totally unindexed thing"
    result = web_search(query)
    assert result == f"[mock] no indexed results for {query!r}"


def test_web_search_distinct_queries_differ():
    assert web_search("authgate") != web_search("what is a capability")


# --- file_read -------------------------------------------------------------

def _file_read_fn(sandbox_root):
    return build_default_tools(sandbox_root).get("file_read").fn


def test_file_read_reads_file_inside_sandbox(tmp_path):
    (tmp_path / "hello.txt").write_text("hello world", encoding="utf-8")
    read_file = _file_read_fn(tmp_path)
    assert read_file("hello.txt") == "hello world"


def test_file_read_reads_benign_subdirectory(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content", encoding="utf-8")
    read_file = _file_read_fn(tmp_path)
    assert read_file("sub/nested.txt") == "nested content"


def test_file_read_rejects_parent_traversal(tmp_path):
    read_file = _file_read_fn(tmp_path)
    with pytest.raises(PermissionError, match="escapes sandbox"):
        read_file("../etc")


def test_file_read_rejects_deep_parent_traversal(tmp_path):
    read_file = _file_read_fn(tmp_path)
    with pytest.raises(PermissionError, match="escapes sandbox"):
        read_file("../../secret")


def test_file_read_rejects_posix_absolute_path(tmp_path):
    read_file = _file_read_fn(tmp_path)
    with pytest.raises(PermissionError, match="escapes sandbox"):
        read_file("/etc/passwd")


def test_file_read_rejects_windows_absolute_path(tmp_path):
    # On Windows this is a drive-absolute path that escapes the sandbox
    # (PermissionError). On POSIX, 'C:\\...' is merely a nonexistent in-sandbox
    # filename (FileNotFoundError). Either way, no real file is read.
    read_file = _file_read_fn(tmp_path)
    with pytest.raises((PermissionError, FileNotFoundError)):
        read_file("C:\\Windows\\win.ini")


def test_file_read_missing_file_inside_sandbox_raises_filenotfound(tmp_path):
    read_file = _file_read_fn(tmp_path)
    with pytest.raises(FileNotFoundError):
        read_file("does_not_exist.txt")


@pytest.mark.parametrize(
    "name",
    ["CON", "NUL", "PRN", "AUX", "COM1", "LPT1", "CON.txt", "sub/NUL"],
)
def test_file_read_rejects_windows_reserved_devices(tmp_path, name):
    # These resolve inside the sandbox but open a device on Windows ('CON' blocks
    # forever = DoS). Must be refused by name on every platform for portability.
    read_file = _file_read_fn(tmp_path)
    with pytest.raises(PermissionError, match="reserved device"):
        read_file(name)


# --- Tool dataclass --------------------------------------------------------

def _dummy_resource():
    return Resource("compute", ResourceType.COMPUTE_SLOT)


def test_tool_accepts_read_mode():
    tool = Tool(name="t", fn=lambda: None, resource=_dummy_resource(), mode="read")
    assert tool.mode == "read"


def test_tool_accepts_write_mode():
    tool = Tool(name="t", fn=lambda: None, resource=_dummy_resource(), mode="write")
    assert tool.mode == "write"


def test_tool_rejects_invalid_mode():
    with pytest.raises(ValueError, match="mode must be one of"):
        Tool(name="t", fn=lambda: None, resource=_dummy_resource(), mode="execute")


def test_tool_is_frozen():
    tool = Tool(name="t", fn=lambda: None, resource=_dummy_resource(), mode="read")
    with pytest.raises(Exception):
        tool.name = "other"  # type: ignore[misc]


# --- ToolRegistry ----------------------------------------------------------

def _make_tool(name):
    return Tool(name=name, fn=lambda: name, resource=_dummy_resource(), mode="read")


def test_registry_register_returns_tool():
    registry = ToolRegistry()
    tool = _make_tool("alpha")
    assert registry.register(tool) is tool


def test_registry_get_returns_registered_tool():
    registry = ToolRegistry()
    tool = _make_tool("alpha")
    registry.register(tool)
    assert registry.get("alpha") is tool


def test_registry_get_missing_raises_keyerror():
    registry = ToolRegistry()
    with pytest.raises(KeyError):
        registry.get("nope")


def test_registry_names_are_sorted():
    registry = ToolRegistry()
    registry.register(_make_tool("gamma"))
    registry.register(_make_tool("alpha"))
    registry.register(_make_tool("beta"))
    assert registry.names() == ["alpha", "beta", "gamma"]


def test_registry_contains():
    registry = ToolRegistry()
    registry.register(_make_tool("alpha"))
    assert "alpha" in registry
    assert "missing" not in registry


def test_registry_iter_yields_tools():
    registry = ToolRegistry()
    a, b = _make_tool("a"), _make_tool("b")
    registry.register(a)
    registry.register(b)
    assert set(registry) == {a, b}


# --- build_default_tools ---------------------------------------------------

def test_build_default_tools_has_three_named_tools(tmp_path):
    registry = build_default_tools(tmp_path)
    assert registry.names() == ["calculator", "file_read", "web_search"]


def test_build_default_tools_all_read_mode(tmp_path):
    registry = build_default_tools(tmp_path)
    assert all(tool.mode == "read" for tool in registry)


def test_build_default_tools_calculator_fn_works(tmp_path):
    registry = build_default_tools(tmp_path)
    assert registry.get("calculator").fn("1 + 1") == "2"
