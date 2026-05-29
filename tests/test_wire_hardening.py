"""
Wire-level input hardening tests — Phase B4.

Each test corresponds to a WA-N attack class defined in attack_harness/wire_attacks.py.
Tests assert either:
  - Input validation raises the expected exception (REJECTED)
  - The kernel correctly denies via ownership/flag check (MITIGATED)
  - Documented gap behavior is stable (ACCEPTED — known, non-critical, noted)

These tests run on the Python authgate runtime. The Rust path is covered by
freedom-kernel/src/wire.rs validate_*() functions (11 inline tests there).
"""
from __future__ import annotations

import json
import math
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def basic_registry():
    human = Entity("alice", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    dataset = Resource("data", ResourceType.DATASET, scope="/data/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, human)
    reg.add_claim(RightsClaim(bot, dataset, can_read=True, can_write=True))
    return reg, bot, dataset


def _verifier(registry: OwnershipRegistry) -> FreedomVerifier:
    return FreedomVerifier(registry.freeze())


# ---------------------------------------------------------------------------
# WA-1 — Duplicate JSON keys (last-wins, documented HTTP-boundary gap)
# ---------------------------------------------------------------------------

class TestWA1DuplicateKeys:
    def test_last_key_wins_in_json_loads(self):
        raw = '{"action_id": "good", "action_id": "evil"}'
        parsed = json.loads(raw)
        assert parsed["action_id"] == "evil"

    def test_kernel_receives_last_value(self, basic_registry):
        reg, bot, _ = basic_registry
        raw = '{"action_id": "good", "action_id": "evil"}'
        parsed = json.loads(raw)
        action = Action(action_id=parsed["action_id"], actor=bot)
        result = _verifier(reg).verify(action)
        assert action.action_id == "evil"
        assert result.permitted  # owned machine, no flags, no resources → PERMIT


# ---------------------------------------------------------------------------
# WA-2 — Out-of-range confidence (> 1.0) — REJECTED by __post_init__
# ---------------------------------------------------------------------------

class TestWA2ConfidenceAboveOne:
    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=1.5,
                can_read=True,
            )

    def test_confidence_exactly_one_accepted(self):
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET),
            confidence=1.0,
            can_read=True,
        )
        assert claim.confidence == 1.0

    def test_confidence_exactly_zero_accepted(self):
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET),
            confidence=0.0,
            can_read=True,
        )
        assert claim.confidence == 0.0


# ---------------------------------------------------------------------------
# WA-3 — Negative confidence — REJECTED by __post_init__
# ---------------------------------------------------------------------------

class TestWA3NegativeConfidence:
    def test_negative_confidence_rejected(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=-0.1,
                can_read=True,
            )

    def test_small_negative_rejected(self):
        with pytest.raises(ValueError):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=-1e-10,
                can_read=True,
            )


# ---------------------------------------------------------------------------
# WA-4 — Absurdly high confidence (999.0) — REJECTED by __post_init__
# ---------------------------------------------------------------------------

class TestWA4HighConfidence:
    def test_confidence_999_rejected(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=999.0,
                can_read=True,
            )


# ---------------------------------------------------------------------------
# WA-5 — Unknown extra fields silently ignored (MITIGATED at API boundary)
# ---------------------------------------------------------------------------

class TestWA5UnknownFields:
    def test_extra_fields_in_json_are_ignored(self, basic_registry):
        reg, bot, _ = basic_registry
        raw = json.dumps({
            "action_id": "benign",
            "override_permitted": True,
            "bypass_check": 1,
            "drop_table": "users",
        })
        parsed = json.loads(raw)
        action = Action(
            action_id=parsed["action_id"],
            actor=bot,
        )
        result = _verifier(reg).verify(action)
        assert result.permitted
        assert "bypass" not in str(result.violations)


# ---------------------------------------------------------------------------
# WA-6 — String instead of AgentType enum — REJECTED by Entity.__post_init__
# ---------------------------------------------------------------------------

class TestWA6StringAsEnum:
    def test_string_machine_rejected(self):
        with pytest.raises(TypeError, match="AgentType"):
            Entity("bot", "MACHINE")

    def test_string_human_rejected(self):
        with pytest.raises(TypeError, match="AgentType"):
            Entity("alice", "HUMAN")

    def test_integer_rejected(self):
        with pytest.raises(TypeError, match="AgentType"):
            Entity("bot", 1)

    def test_none_rejected(self):
        with pytest.raises(TypeError, match="AgentType"):
            Entity("bot", None)

    def test_valid_enum_accepted(self):
        e = Entity("bot", AgentType.MACHINE)
        assert e.kind == AgentType.MACHINE


# ---------------------------------------------------------------------------
# WA-7 — Empty action_id — REJECTED by Action.__post_init__
# ---------------------------------------------------------------------------

class TestWA7EmptyActionId:
    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="action_id"):
            Action(action_id="", actor=Entity("bot", AgentType.MACHINE))

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError, match="action_id"):
            Action(action_id="   ", actor=Entity("bot", AgentType.MACHINE))

    def test_valid_action_id_accepted(self):
        action = Action(action_id="x", actor=Entity("bot", AgentType.MACHINE))
        assert action.action_id == "x"


# ---------------------------------------------------------------------------
# WA-7b — Empty actor name — MITIGATED by ownership check (not input validation)
# ---------------------------------------------------------------------------

class TestWA7bEmptyActorName:
    def test_empty_actor_name_denied_by_ownership(self, basic_registry):
        reg, _, _ = basic_registry
        action = Action(action_id="x", actor=Entity("", AgentType.MACHINE))
        result = _verifier(reg).verify(action)
        assert not result.permitted
        assert any("UNOWNED_MACHINE" in v for v in result.violations)


# ---------------------------------------------------------------------------
# WA-8 — actor=None — REJECTED (Python AttributeError at verify time)
# ---------------------------------------------------------------------------

class TestWA8NullActor:
    def test_none_actor_raises(self, basic_registry):
        reg, _, _ = basic_registry
        action = Action(action_id="x", actor=None)
        with pytest.raises((TypeError, AttributeError)):
            _verifier(reg).verify(action)


# ---------------------------------------------------------------------------
# WA-9 — Invalid entity kind — REJECTED by AgentType enum
# ---------------------------------------------------------------------------

class TestWA9InvalidKind:
    def test_invalid_value_rejected(self):
        with pytest.raises((ValueError, KeyError)):
            AgentType("ROBOT")

    def test_numeric_value_rejected(self):
        with pytest.raises((ValueError, KeyError)):
            AgentType(99)

    def test_valid_values_accepted(self):
        assert AgentType.HUMAN is AgentType.HUMAN
        assert AgentType.MACHINE is AgentType.MACHINE


# ---------------------------------------------------------------------------
# WA-11 — NaN confidence — REJECTED by __post_init__
# ---------------------------------------------------------------------------

class TestWA11NanConfidence:
    def test_nan_rejected(self):
        with pytest.raises(ValueError, match="finite float"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=math.nan,
                can_read=True,
            )

    def test_positive_infinity_rejected(self):
        with pytest.raises(ValueError, match="finite float"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=math.inf,
                can_read=True,
            )

    def test_negative_infinity_rejected(self):
        with pytest.raises(ValueError, match="finite float"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=-math.inf,
                can_read=True,
            )

    def test_large_finite_rejected_by_range(self):
        with pytest.raises(ValueError, match="confidence must be in"):
            RightsClaim(
                holder=Entity("bot", AgentType.MACHINE),
                resource=Resource("data", ResourceType.DATASET),
                confidence=1e308,
                can_read=True,
            )


# ---------------------------------------------------------------------------
# WA-15 — All 10 sovereignty flags simultaneously — REJECTED by verify()
# ---------------------------------------------------------------------------

class TestWA15AllSovereigntyFlags:
    def test_all_flags_produce_ten_violations(self, basic_registry):
        reg, bot, dataset = basic_registry
        action = Action(
            action_id="total-domination",
            actor=bot,
            resources_read=[dataset],
            increases_machine_sovereignty=True,
            resists_human_correction=True,
            bypasses_verifier=True,
            weakens_verifier=True,
            disables_corrigibility=True,
            machine_coalition_dominion=True,
            coerces=True,
            deceives=True,
            self_modification_weakens_verifier=True,
            machine_coalition_reduces_freedom=True,
        )
        result = _verifier(reg).verify(action)
        assert not result.permitted
        forbidden_violations = [v for v in result.violations if "FORBIDDEN" in v]
        assert len(forbidden_violations) == 10

    def test_any_single_flag_denies(self, basic_registry):
        reg, bot, dataset = basic_registry
        flag_fields = [
            "increases_machine_sovereignty",
            "resists_human_correction",
            "bypasses_verifier",
            "weakens_verifier",
            "disables_corrigibility",
            "machine_coalition_dominion",
            "coerces",
            "deceives",
            "self_modification_weakens_verifier",
            "machine_coalition_reduces_freedom",
        ]
        for flag in flag_fields:
            action = Action(
                action_id=f"test-{flag}",
                actor=bot,
                resources_read=[dataset],
                **{flag: True},
            )
            result = _verifier(reg).verify(action)
            assert not result.permitted, f"Flag {flag} should deny"
            assert any("FORBIDDEN" in v for v in result.violations)


# ---------------------------------------------------------------------------
# WA-17 — Empty action (no resources, no flags) — ACCEPTED as correct behavior
# ---------------------------------------------------------------------------

class TestWA17EmptyAction:
    def test_owned_machine_no_resources_permitted(self, basic_registry):
        reg, bot, _ = basic_registry
        action = Action(action_id="empty", actor=bot)
        result = _verifier(reg).verify(action)
        assert result.permitted
        assert len(result.violations) == 0

    def test_unowned_machine_no_resources_denied(self):
        reg = OwnershipRegistry()
        bot = Entity("stray-bot", AgentType.MACHINE)
        action = Action(action_id="empty", actor=bot)
        result = FreedomVerifier(reg.freeze()).verify(action)
        assert not result.permitted
        assert any("UNOWNED_MACHINE" in v for v in result.violations)


# ---------------------------------------------------------------------------
# WA-18 — Extremely long strings — ACCEPTED but safely denied (not in registry)
# ---------------------------------------------------------------------------

class TestWA18HugeStrings:
    def test_100k_resource_name_does_not_crash(self, basic_registry):
        reg, bot, _ = basic_registry
        long_name = "A" * 100_000
        resource = Resource(long_name, ResourceType.DATASET)
        action = Action(action_id="x", actor=bot, resources_read=[resource])
        result = _verifier(reg).verify(action)
        assert not result.permitted
        assert any("READ DENIED" in v for v in result.violations)

    def test_100k_action_id_accepted(self, basic_registry):
        reg, bot, dataset = basic_registry
        action = Action(action_id="X" * 100_000, actor=bot, resources_read=[dataset])
        result = _verifier(reg).verify(action)
        assert result.permitted

    def test_100k_description_accepted(self, basic_registry):
        reg, bot, dataset = basic_registry
        action = Action(
            action_id="x",
            actor=bot,
            description="D" * 100_000,
            resources_read=[dataset],
        )
        result = _verifier(reg).verify(action)
        assert result.permitted


# ---------------------------------------------------------------------------
# Cross-cutting: valid boundary values
# ---------------------------------------------------------------------------

class TestBoundaryValues:
    def test_confidence_boundary_values(self):
        bot = Entity("bot", AgentType.MACHINE)
        res = Resource("r", ResourceType.FILE)
        for valid in [0.0, 0.5, 1.0, 0.0001, 0.9999]:
            c = RightsClaim(holder=bot, resource=res, confidence=valid)
            assert c.confidence == valid

    def test_confidence_just_outside_range_rejected(self):
        bot = Entity("bot", AgentType.MACHINE)
        res = Resource("r", ResourceType.FILE)
        for invalid in [1.0000000001, -0.0000000001]:
            with pytest.raises(ValueError):
                RightsClaim(holder=bot, resource=res, confidence=invalid)

    def test_non_float_confidence_rejected(self):
        bot = Entity("bot", AgentType.MACHINE)
        res = Resource("r", ResourceType.FILE)
        with pytest.raises((ValueError, TypeError)):
            RightsClaim(holder=bot, resource=res, confidence="high")

    def test_boolean_confidence_accepted_as_numeric(self):
        # Python: bool is subclass of int, True==1.0, False==0.0 — within range
        bot = Entity("bot", AgentType.MACHINE)
        res = Resource("r", ResourceType.FILE)
        claim = RightsClaim(holder=bot, resource=res, confidence=True)
        assert claim.confidence == 1.0
        claim2 = RightsClaim(holder=bot, resource=res, confidence=False)
        assert claim2.confidence == 0.0
