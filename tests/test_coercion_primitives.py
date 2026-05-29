"""
Coercion primitives tests — Phase 0, O3.

Tests COER-1 through COER-10 from the adversarial ontology.
Each coercion primitive maps to a sovereignty flag; all must produce DENY.

Catalog linkage: attack_harness/threat_taxonomy/coercion_primitives.py
"""
import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier

# The 10 actual sovereignty flag names on Action
ALL_SOVEREIGNTY_FLAGS = [
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
from attack_harness.threat_taxonomy.coercion_primitives import (
    COERCION_PRIMITIVES,
    COERCION_BY_FLAG,
    CoercionType,
    assert_coercion_flag_always_denied,
    run_all,
)
from attack_harness.threat_taxonomy.ontology import COERCION_PRIMITIVES_CATALOG


# ── Catalog structure ─────────────────────────────────────────────────────────

class TestCoercionCatalogStructure:
    def test_ten_coercion_primitives_in_catalog(self):
        assert len(COERCION_PRIMITIVES) == 10

    def test_ten_ontology_scenarios(self):
        assert len(COERCION_PRIMITIVES_CATALOG) == 10

    def test_all_flag_names_are_unique(self):
        flags = [p.flag_name for p in COERCION_PRIMITIVES]
        assert len(flags) == len(set(flags))

    def test_all_coer_ids_are_unique(self):
        ids = [p.coer_id for p in COERCION_PRIMITIVES]
        assert len(ids) == len(set(ids))

    def test_all_coercion_types_covered(self):
        covered = {p.coercion_type for p in COERCION_PRIMITIVES}
        assert CoercionType.INFORMATIONAL in covered
        assert CoercionType.ECONOMIC in covered
        assert CoercionType.COGNITIVE in covered
        assert CoercionType.META_ATTACK in covered
        assert CoercionType.SOVEREIGNTY_GRAB in covered

    def test_flag_lookup_covers_all_primitives(self):
        for primitive in COERCION_PRIMITIVES:
            assert primitive.flag_name in COERCION_BY_FLAG


# ── Individual coercion primitive assertions ──────────────────────────────────

@pytest.mark.parametrize("primitive", COERCION_PRIMITIVES, ids=[p.coer_id for p in COERCION_PRIMITIVES])
class TestEachCoercionPrimitive:
    def test_flag_always_denied(self, primitive):
        result = assert_coercion_flag_always_denied(primitive.flag_name)
        assert result["blocked"], (
            f"{primitive.coer_id} ({primitive.flag_name}) must always be denied; "
            f"got violations: {result['violations']}"
        )

    def test_flag_produces_violation(self, primitive):
        result = assert_coercion_flag_always_denied(primitive.flag_name)
        assert len(result["violations"]) > 0, (
            f"{primitive.coer_id}: expected at least one violation, got none"
        )

    def test_violation_contains_forbidden_marker(self, primitive):
        result = assert_coercion_flag_always_denied(primitive.flag_name)
        assert any("FORBIDDEN" in v for v in result["violations"]), (
            f"{primitive.coer_id}: violation should contain 'FORBIDDEN'"
        )


# ── Coercion type groupings ───────────────────────────────────────────────────

class TestCoercionTypeGroupings:
    def _flags_for_type(self, coercion_type: CoercionType) -> list[str]:
        return [p.flag_name for p in COERCION_PRIMITIVES if p.coercion_type is coercion_type]

    def test_informational_coercion_blocked(self):
        for flag in self._flags_for_type(CoercionType.INFORMATIONAL):
            r = assert_coercion_flag_always_denied(flag)
            assert r["blocked"], f"Informational coercion {flag} leaked"

    def test_economic_coercion_blocked(self):
        for flag in self._flags_for_type(CoercionType.ECONOMIC):
            r = assert_coercion_flag_always_denied(flag)
            assert r["blocked"], f"Economic coercion {flag} leaked"

    def test_meta_attacks_blocked(self):
        for flag in self._flags_for_type(CoercionType.META_ATTACK):
            r = assert_coercion_flag_always_denied(flag)
            assert r["blocked"], f"Meta-attack {flag} leaked"

    def test_sovereignty_grabs_blocked(self):
        for flag in self._flags_for_type(CoercionType.SOVEREIGNTY_GRAB):
            r = assert_coercion_flag_always_denied(flag)
            assert r["blocked"], f"Sovereignty grab {flag} leaked"

    def test_cognitive_coercion_blocked(self):
        for flag in self._flags_for_type(CoercionType.COGNITIVE):
            r = assert_coercion_flag_always_denied(flag)
            assert r["blocked"], f"Cognitive coercion {flag} leaked"


# ── Full run assertion ─────────────────────────────────────────────────────────

class TestFullCoercionRun:
    def test_all_primitives_blocked_in_batch(self):
        results = run_all()
        assert len(results) == 10
        leaked = [r for r in results if not r["blocked"]]
        assert len(leaked) == 0, (
            f"{len(leaked)} coercion primitives leaked: "
            + ", ".join(r["coer_id"] for r in leaked)
        )

    def test_no_permitted_coercion_actions(self):
        results = run_all()
        for r in results:
            assert not r["permitted"], f"{r['coer_id']}: coercion action must never be permitted"


# ── Combination: coercion + capability ───────────────────────────────────────

class TestCoercionWithValidCapability:
    """Coercion flags override even when the actor has a valid capability."""

    def _setup(self) -> tuple[object, Entity, Resource]:
        human = Entity("alice", AgentType.HUMAN)
        bot = Entity("bot", AgentType.MACHINE)
        resource = Resource("data", ResourceType.DATASET)
        reg = OwnershipRegistry()
        reg.register_machine(bot, human)
        reg.add_claim(RightsClaim(bot, resource, can_read=True, can_write=True))
        return reg.freeze(), bot, resource

    @pytest.mark.parametrize("flag", [p.flag_name for p in COERCION_PRIMITIVES])
    def test_flag_overrides_valid_capability(self, flag):
        frozen, bot, resource = self._setup()
        action = Action(
            action_id=f"test-{flag}",
            actor=bot,
            resources_read=[resource],
            **{flag: True},
        )
        result = FreedomVerifier(frozen).verify(action)
        assert not result.permitted, (
            f"{flag}: coercion flag must deny even when actor has valid read+write capability"
        )
