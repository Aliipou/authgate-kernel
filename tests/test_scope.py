"""
Resource scope containment tests — authgate-kernel Phase 1.3.

Formal rule (SEMANTICS.md §4):
  scope_contains(P, C) iff:
    - P is empty  (root scope — universal), OR
    - C == normalize(P), OR
    - C starts with normalize(P) + "/"
  where normalize(P) strips trailing slashes.

Run: pytest tests/test_scope.py -v
"""
from __future__ import annotations

import pytest

from authgate.kernel.entities import scope_contains


# ---------------------------------------------------------------------------
# Positive: scope_contains → True
# ---------------------------------------------------------------------------

def test_empty_parent_matches_everything():
    assert scope_contains("", "/any/path") is True
    assert scope_contains("", "") is True
    assert scope_contains("", "/data/alice") is True


def test_exact_match():
    assert scope_contains("/data/alice", "/data/alice") is True


def test_child_path():
    assert scope_contains("/data/alice", "/data/alice/file.csv") is True


def test_trailing_slash_on_parent():
    assert scope_contains("/data/alice/", "/data/alice/file.csv") is True


def test_nested_child():
    assert scope_contains("/data", "/data/alice/file.csv") is True
    assert scope_contains("/data/alice", "/data/alice/nested/deep.txt") is True


def test_scope_contains_itself():
    assert scope_contains("/data/alice", "/data/alice") is True


def test_root_scope():
    assert scope_contains("/", "/anything") is True
    assert scope_contains("/", "/deeply/nested/path") is True


def test_parent_without_trailing_slash_same_as_with():
    assert scope_contains("/data/alice/", "/data/alice/sub/file.txt")
    assert scope_contains("/data/alice", "/data/alice/sub/file.txt")


def test_deep_nesting():
    assert scope_contains("/a/b/c/", "/a/b/c/d/e/f/g.json")


def test_scope_with_dashes_and_dots():
    assert scope_contains("/tenant-42/data.set/", "/tenant-42/data.set/row-1")


def test_exact_match_trailing_slash_normalization():
    """P='/data/alice/' contains C='/data/alice' — normalization makes them equal."""
    assert scope_contains("/data/alice/", "/data/alice") is True


# ---------------------------------------------------------------------------
# Negative: scope_contains → False
# ---------------------------------------------------------------------------

def test_no_match_sibling():
    assert scope_contains("/data/alice", "/data/bob") is False


def test_no_match_prefix_not_directory():
    """/data/alice must NOT contain /data/alice2 (no slash boundary)."""
    assert scope_contains("/data/alice", "/data/alice2") is False


def test_no_match_parent_of_parent():
    assert scope_contains("/data/alice", "/data") is False


def test_etc_not_in_data():
    assert scope_contains("/data/", "/etc/passwd") is False


def test_partial_segment_match_rejected():
    """/proc must not contain /process/data."""
    assert scope_contains("/proc", "/process/data") is False


def test_empty_child_not_in_nonempty_parent():
    assert scope_contains("/data/", "") is False


def test_different_root():
    assert scope_contains("/var/log/", "/srv/www/index.html") is False


def test_longer_sibling_path_not_contained():
    assert scope_contains("/data/alice/private/", "/data/alice/public/report.pdf") is False


def test_child_does_not_contain_parent():
    assert scope_contains("/data/alice/file.csv", "/data/alice/") is False


# ---------------------------------------------------------------------------
# Path traversal — must NOT be treated as containment
# ---------------------------------------------------------------------------

def test_dotdot_not_contained():
    """/data/ does not contain /data/../etc/passwd (no path normalization)."""
    assert scope_contains("/data/", "/data/../etc/passwd") is False


def test_dotdot_escaping_child():
    assert scope_contains("/data/safe/", "/data/safe/../../../etc/shadow") is False


def test_double_slash_rejected():
    """//etc/passwd must not be confused with /etc/passwd."""
    assert scope_contains("/data/", "//etc/passwd") is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_unicode_scope():
    assert scope_contains("/تست/داده/", "/تست/داده/فایل.csv")
    assert not scope_contains("/تست/داده/", "/etc/passwd")


def test_scope_with_spaces():
    assert scope_contains("/my data/", "/my data/file.txt")
    assert not scope_contains("/my data/", "/my_data/file.txt")


def test_single_char_segments():
    assert scope_contains("/a/b/", "/a/b/c")
    assert not scope_contains("/a/b/", "/a/bc")


@pytest.mark.parametrize("parent,child,expected", [
    ("/data/",      "/data/file.csv",               True),
    ("/data/",      "/data/",                        True),
    ("/data/",      "/data",                         True),
    ("/data/",      "/datas/file.csv",               False),
    ("/",           "/root/key.pem",                 True),
    ("",            "/anything",                     True),
    ("/x/y/z/",    "/x/y/z/w/v",                   True),
    ("/x/y/z/",    "/x/y/za/w",                     False),
])
def test_parametrized_containment(parent, child, expected):
    assert scope_contains(parent, child) is expected
