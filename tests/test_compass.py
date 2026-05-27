"""Tests for the Mahdavi Compass terminal goal scorer."""
import math

from authgate.extensions.compass import WorldState, score


def test_toward_final_order():
    before = WorldState(
        rights_violations=5, coercive_acts=3, voluntary_agreements=1, ownership_ambiguities=2
    )
    after = WorldState(
        rights_violations=3, coercive_acts=1, voluntary_agreements=3, ownership_ambiguities=1
    )
    result = score(before, after)
    assert result.permitted
    assert result.score > 0


def test_away_from_final_order():
    before = WorldState(rights_violations=1)
    after  = WorldState(rights_violations=5)
    result = score(before, after)
    assert result.score < 0


def test_machine_sovereignty_increase_is_hard_veto():
    """Book p.800: machine sovereignty increase is categorically forbidden."""
    before = WorldState(machine_sovereignty_incidents=0, rights_violations=10)
    after = WorldState(machine_sovereignty_incidents=1, rights_violations=0)
    result = score(before, after)
    assert not result.permitted
    assert math.isinf(result.score) and result.score < 0
    assert "VETO" in result.reason


def test_neutral_action():
    state = WorldState()
    result = score(state, state)
    assert result.permitted
    assert result.score == 0.0
