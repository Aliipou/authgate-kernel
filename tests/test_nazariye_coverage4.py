"""
Coverage tests (batch 4) added on the `nazariye-azadi` branch.

Targets the persuasion-boundary formal model and the sovereignty metrics —
both pure analysis modules whose scoring branches the existing suite did not
fully drive.
"""
from __future__ import annotations

from authgate.analysis.persuasion import (
    PersuasionBoundaryChecker,
    PersuasionCriterion,
    check_persuasion_boundary,
)
from authgate.analysis.sovereignty_metrics import (
    SovereigntyAnalyzer,
    SovereigntySnapshot,
    _delegation_depth,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


def _res(name, rtype=ResourceType.FILE, scope=""):
    return Resource(name, rtype, scope=scope)


# --------------------------------------------------------------------------- #
# persuasion.py
# --------------------------------------------------------------------------- #

def test_persuasion_clear_when_no_criteria():
    action = Action("plain-read", _machine(), resources_read=[_res("doc")])
    result = check_persuasion_boundary(action)
    assert result.verdict == "CLEAR"
    assert result.block is False
    assert result.score == 0


def test_persuasion_high_verdict_three_criteria():
    # credential resource fires S1 (info asymmetry) + S5 (reversibility);
    # urgency in action_id fires S2 -> 3 criteria -> HIGH
    cred = _res("token", ResourceType.CREDENTIAL)
    action = Action("urgent-grab", _machine(), resources_read=[cred])
    result = check_persuasion_boundary(action)
    assert result.verdict == "HIGH"
    assert result.block is True
    assert PersuasionCriterion.INFORMATION_ASYMMETRY in result.criteria_fired
    assert PersuasionCriterion.URGENCY_FRAMING in result.criteria_fired
    assert PersuasionCriterion.REVERSIBILITY_OBSCURING in result.criteria_fired


def test_persuasion_urgency_in_description_only():
    # action_id/argument clean, but description carries urgency -> S2 via description
    action = Action("calm-id", _machine(), description="this is an emergency", argument="")
    fired = PersuasionBoundaryChecker()._s2_urgency_framing(action)
    assert fired == [PersuasionCriterion.URGENCY_FRAMING]


def test_persuasion_s3_authority_amplification_with_registry():
    checker = PersuasionBoundaryChecker()
    reg = OwnershipRegistry()
    bot = _machine()
    reg.register_machine(bot, _human())

    # No claims granted -> requesting read amplifies authority (S3 read branch)
    a_read = Action("a", bot, resources_read=[_res("secret")])
    assert PersuasionCriterion.AUTHORITY_AMPLIFICATION in checker.check(a_read, reg).criteria_fired

    # No claims -> requesting write amplifies authority (S3 write branch)
    a_write = Action("a", bot, resources_write=[_res("secret")])
    assert PersuasionCriterion.AUTHORITY_AMPLIFICATION in checker.check(a_write, reg).criteria_fired


def test_persuasion_s3_skips_when_no_registry_or_human_actor():
    checker = PersuasionBoundaryChecker()
    # registry None -> S3 returns []
    assert checker._s3_authority_amplification(Action("a", _machine()), None) == []
    # human actor -> S3 returns []
    reg = OwnershipRegistry()
    human_action = Action("a", _human(), resources_read=[_res("x")])
    assert checker._s3_authority_amplification(human_action, reg) == []


def test_persuasion_s3_no_amplification_when_claims_held():
    checker = PersuasionBoundaryChecker()
    reg = OwnershipRegistry()
    bot = _machine()
    reg.register_machine(bot, _human())
    res = _res("doc")
    reg.add_claim(RightsClaim(bot, res, can_read=True))
    # actor holds the requested read claim -> S3 falls through to [] (line 163)
    action = Action("a", bot, resources_read=[res])
    assert checker._s3_authority_amplification(action, reg) == []


# --------------------------------------------------------------------------- #
# sovereignty_metrics.py — risk-level scoring branches
# --------------------------------------------------------------------------- #

def _snap(**overrides) -> SovereigntySnapshot:
    base = dict(
        machine_count=1, machines_with_owner=1, agency_preservation_score=1.0,
        max_delegation_depth=0, mean_delegation_depth=0.0,
        dependency_centralization=0.0, total_claims=1, time_bounded_claims=1,
        reversibility_index=1.0, delegated_claims=0, autonomy_degradation_rate=0.0,
    )
    base.update(overrides)
    return SovereigntySnapshot(**base)


def test_risk_level_low():
    assert _snap().sovereignty_risk_level() == "LOW"


def test_risk_level_critical_hits_all_high_branches():
    snap = _snap(
        agency_preservation_score=0.4,      # +2 (line 61)
        dependency_centralization=0.9,      # +2 (line 66)
        autonomy_degradation_rate=0.8,      # +2 (line 72)
        reversibility_index=0.1,            # +2 (line 78)
        max_delegation_depth=5,             # +1 (line 85)
    )  # total 9 -> CRITICAL (line 88)
    assert snap.sovereignty_risk_level() == "CRITICAL"


def test_risk_level_medium_hits_elif_branches():
    snap = _snap(
        agency_preservation_score=0.7,      # +1 (line 63, elif)
        dependency_centralization=0.6,      # +1 (line 69, elif)
        autonomy_degradation_rate=0.5,      # +1 (line 75, elif)
        reversibility_index=0.4,            # +1 (line 81, elif)
        max_delegation_depth=3,
    )  # total 4 -> MEDIUM (line 92)
    assert snap.sovereignty_risk_level() == "MEDIUM"


def test_risk_level_high_band():
    snap = _snap(
        agency_preservation_score=0.4,      # +2
        dependency_centralization=0.9,      # +2
        autonomy_degradation_rate=0.5,      # +1
        reversibility_index=1.0,
        max_delegation_depth=5,             # +1
    )  # total 6 -> HIGH
    assert snap.sovereignty_risk_level() == "HIGH"


def test_delegation_depth_walk_and_cycle_guard():
    alice, bob = _human("Alice"), _human("Bob")
    bot = _machine("Bot")
    res = _res("r")

    # Build a delegated_by cycle: bot<-alice, alice<-bob, bob<-alice
    c1 = RightsClaim(bot, res)
    c1.delegated_by = alice
    c2 = RightsClaim(alice, res)
    c2.delegated_by = bob
    c3 = RightsClaim(bob, res)
    c3.delegated_by = alice
    all_claims = [c1, c2, c3]
    # Walk terminates via cycle guard (line 103) and the parent-walk step (line 113)
    depth = _delegation_depth(c1, all_claims)
    assert depth >= 1


def test_sovereignty_analyzer_full_snapshot():
    reg = OwnershipRegistry()
    alice = _human()
    bot = _machine()
    reg.register_machine(bot, alice)
    res = _res("doc")
    reg.add_claim(RightsClaim(alice, res, can_read=True, can_delegate=True))
    child = RightsClaim(bot, res, can_read=True)
    child.delegated_by = alice
    reg.add_claim(child)

    snap = SovereigntyAnalyzer().analyze(reg)
    assert snap.machine_count == 1
    assert snap.delegated_claims == 1
    assert 0.0 <= snap.reversibility_index <= 1.0
