"""Phase 1 — scope_contains formal rule tests."""
from authgate.kernel.entities import scope_contains


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


def test_no_match_sibling():
    assert scope_contains("/data/alice", "/data/bob") is False


def test_no_match_prefix_not_directory():
    assert scope_contains("/data/alice", "/data/alice2") is False


def test_no_match_parent_of_parent():
    assert scope_contains("/data/alice", "/data") is False


def test_nested_child():
    assert scope_contains("/data", "/data/alice/file.csv") is True
    assert scope_contains("/data/alice", "/data/alice/nested/deep.txt") is True


def test_scope_contains_itself():
    assert scope_contains("/data/alice", "/data/alice") is True


def test_root_scope():
    assert scope_contains("/", "/anything") is True
    assert scope_contains("/", "/deeply/nested/path") is True
