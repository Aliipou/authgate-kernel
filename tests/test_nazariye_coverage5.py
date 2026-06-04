"""
Coverage tests (batch 5) added on the `nazariye-azadi` branch.

Targets the structural coercion analyzer's pattern/risk branches.
"""
from __future__ import annotations

from authgate.analysis.coercion import (
    CoercionAnalyzer,
    CoercionBoundary,
    CoercionError,
    CoercionPattern,
    _check_coalition,
    _risk_level,
)
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry


def _human(name):
    return Entity(name, AgentType.HUMAN)


def _machine(name):
    return Entity(name, AgentType.MACHINE)


def _res(name, scope=""):
    return Resource(name, ResourceType.FILE, scope=scope)


def test_coercion_error_is_exception():
    assert issubclass(CoercionError, Exception)


def test_confidence_asymmetry_pattern_low_risk():
    reg = OwnershipRegistry()
    alice = _human("Alice")
    bot = _machine("Bot")
    reg.register_machine(bot, alice)
    res = _res("proj", scope="proj/x")  # non-root -> no single-point pattern

    # Human parent claim (claim.holder is human -> line 105 continue)
    reg.add_claim(RightsClaim(alice, res, can_read=True, can_delegate=True, confidence=0.5))
    # Machine claim with no delegated_by -> line 155 continue (added BEFORE the
    # asymmetry claim so it is processed before the break)
    reg.add_claim(RightsClaim(bot, _res("other", scope="o/x"), can_read=True))
    # Machine claim delegated by human with HIGHER confidence -> CONFIDENCE_ASYMMETRY
    hi = RightsClaim(bot, res, can_read=True, confidence=0.9)
    hi.delegated_by = alice
    reg.add_claim(hi)

    risks = CoercionAnalyzer().analyze(reg)
    bot_risk = next(r for r in risks if r.machine_name == "Bot")
    assert CoercionPattern.CONFIDENCE_ASYMMETRY in bot_risk.patterns
    assert bot_risk.risk_level == "LOW"  # confidence asymmetry alone -> LOW (line 208)
    assert bot_risk.is_coercive() is False


def test_revocation_blocker_high_when_low_dependency():
    reg = OwnershipRegistry()
    h1, h2, h3 = _human("H1"), _human("H2"), _human("H3")
    bot = _machine("Bot")
    # 3 humans in the registry (via machine ownership) -> dep_frac for bot = 1/3
    reg.register_machine(bot, h1)
    reg.register_machine(_machine("M2"), h2)
    reg.register_machine(_machine("M3"), h3)

    # bot holds a ROOT-scope claim with no expiry, delegated by one human
    root = RightsClaim(bot, _res("root", scope=""), can_read=True)
    root.delegated_by = h1
    reg.add_claim(root)

    risks = CoercionAnalyzer().analyze(reg)
    bot_risk = next(r for r in risks if r.machine_name == "Bot")
    # REVOCATION_BLOCKER is critical, but dep_frac (1/3) <= 0.5 -> HIGH (line 205)
    assert CoercionPattern.REVOCATION_BLOCKER in bot_risk.patterns
    assert bot_risk.risk_level == "HIGH"


def test_risk_level_helper_branches():
    b = CoercionBoundary()
    # critical pattern + high dependency -> CRITICAL
    assert _risk_level([CoercionPattern.DEPENDENCY_MONOPOLY], 0.9, b) == "CRITICAL"
    # critical pattern + low dependency -> HIGH
    assert _risk_level([CoercionPattern.REVOCATION_BLOCKER], 0.1, b) == "HIGH"
    # only high-tier pattern -> MEDIUM
    assert _risk_level([CoercionPattern.SINGLE_POINT_OF_CONTROL], 0.1, b) == "MEDIUM"
    # neither -> LOW
    assert _risk_level([CoercionPattern.CONFIDENCE_ASYMMETRY], 0.1, b) == "LOW"


def test_check_coalition_returns_none_below_threshold():
    # 2 machines each depend on a distinct human, 4 humans total -> 0.5 <= 0.75 -> None
    deps = {"M1": {"H1"}, "M2": {"H2"}}
    all_humans = {"H1", "H2", "H3", "H4"}
    assert _check_coalition(deps, all_humans, CoercionBoundary()) is None
    # too few machines -> None
    assert _check_coalition({"M1": {"H1"}}, all_humans, CoercionBoundary()) is None


def test_check_coalition_fires_above_threshold():
    deps = {"M1": {"H1", "H2"}, "M2": {"H3"}}
    all_humans = {"H1", "H2", "H3"}  # coalition covers 3/3 = 1.0 > 0.75
    risk = _check_coalition(deps, all_humans, CoercionBoundary())
    assert risk is not None
    assert risk.patterns == (CoercionPattern.COALITION_LOCK_IN,)
