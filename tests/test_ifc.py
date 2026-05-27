"""Phase 2 — IFC / Bell-LaPadula non-interference tests."""
import pytest

from authgate.extensions.ifc import IFCViolation, NonInterferenceChecker, SecurityLattice
from authgate.kernel.entities import Resource, ResourceType

# ── SecurityLattice ──────────────────────────────────────────────────────────

def test_default_lattice_public_flows_up():
    lattice = SecurityLattice.default()
    assert lattice.can_flow("PUBLIC", "PUBLIC") is True
    assert lattice.can_flow("PUBLIC", "INTERNAL") is True
    assert lattice.can_flow("PUBLIC", "SECRET") is True


def test_default_lattice_secret_does_not_flow_down():
    lattice = SecurityLattice.default()
    assert lattice.can_flow("SECRET", "PUBLIC") is False
    assert lattice.can_flow("SECRET", "INTERNAL") is False
    assert lattice.can_flow("SECRET", "SECRET") is True


def test_default_lattice_internal_stays_in_place():
    lattice = SecurityLattice.default()
    assert lattice.can_flow("INTERNAL", "PUBLIC") is False
    assert lattice.can_flow("INTERNAL", "INTERNAL") is True
    assert lattice.can_flow("INTERNAL", "SECRET") is True


def test_empty_label_flows_everywhere():
    lattice = SecurityLattice.default()
    assert lattice.can_flow("", "PUBLIC") is True
    assert lattice.can_flow("", "SECRET") is True


def test_custom_lattice():
    lattice = SecurityLattice(flows_to={"LOW": ["LOW", "HIGH"], "HIGH": ["HIGH"]})
    assert lattice.can_flow("LOW", "HIGH") is True
    assert lattice.can_flow("HIGH", "LOW") is False


# ── NonInterferenceChecker ────────────────────────────────────────────────────

def _make_resource(name: str, label: str) -> Resource:
    return Resource(name=name, rtype=ResourceType.FILE, ifc_label=label)


def _make_action(action_id: str, reads: list, writes: list):
    class _Action:
        pass
    a = _Action()
    a.action_id = action_id
    a.resources_read = reads
    a.resources_write = writes
    return a


def test_no_violation_same_label():
    checker = NonInterferenceChecker(verifier=None)
    r = _make_resource("doc", "SECRET")
    w = _make_resource("log", "SECRET")
    action = _make_action("a1", [r], [w])
    checker.check_plan([action])  # must not raise


def test_no_violation_upward_flow():
    checker = NonInterferenceChecker(verifier=None)
    r = _make_resource("pub", "PUBLIC")
    w = _make_resource("sec", "SECRET")
    action = _make_action("a1", [r], [w])
    checker.check_plan([action])  # PUBLIC → SECRET is allowed


def test_violation_secret_to_public():
    checker = NonInterferenceChecker(verifier=None)
    r = _make_resource("sec", "SECRET")
    w = _make_resource("pub", "PUBLIC")
    action = _make_action("a1", [r], [w])
    with pytest.raises(IFCViolation) as exc_info:
        checker.check_plan([action])
    assert exc_info.value.source_label == "SECRET"
    assert exc_info.value.sink_label == "PUBLIC"


def test_taint_accumulates_across_actions():
    checker = NonInterferenceChecker(verifier=None)
    read_secret = _make_action("read_sec", [_make_resource("s", "SECRET")], [])
    write_public = _make_action("write_pub", [], [_make_resource("p", "PUBLIC")])
    with pytest.raises(IFCViolation) as exc_info:
        checker.check_plan([read_secret, write_public])
    assert exc_info.value.action_id == "write_pub"


def test_ifc_violation_attributes():
    checker = NonInterferenceChecker(verifier=None)
    r = _make_resource("sec", "INTERNAL")
    w = _make_resource("pub", "PUBLIC")
    action = _make_action("op1", [r], [w])
    with pytest.raises(IFCViolation) as exc_info:
        checker.check_action(action)
    err = exc_info.value
    assert err.action_id == "op1"
    assert err.source_label == "INTERNAL"
    assert err.sink_label == "PUBLIC"
    assert "op1" in str(err)


def test_no_reads_no_taint():
    checker = NonInterferenceChecker(verifier=None)
    w = _make_resource("pub", "PUBLIC")
    action = _make_action("a1", [], [w])
    checker.check_plan([action])  # no reads → no taint → allowed
