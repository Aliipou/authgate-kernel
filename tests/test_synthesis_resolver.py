"""
Tests for SynthesisEngine and conflict resolver.
"""
import pytest

from authgate import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.extensions.resolver import ConflictQueue, Resolution, resolve
from authgate.extensions.synthesis import HARD_INVARIANTS, ProposedRule, SynthesisEngine

# ── Synthesis engine ──────────────────────────────────────────────────────────

def _clean_rule(rule_id: str = "r1") -> ProposedRule:
    return ProposedRule(
        rule_id=rule_id,
        description="A benign rule",
        invariant_impacts={inv: True for inv in HARD_INVARIANTS},
    )


def _violating_rule(violated: str, rule_id: str = "bad") -> ProposedRule:
    impacts = {inv: True for inv in HARD_INVARIANTS}
    impacts[violated] = False
    return ProposedRule(rule_id=rule_id, description="Bad rule", invariant_impacts=impacts)


def test_admit_valid_rule():
    engine = SynthesisEngine()
    ok, msg = engine.admit_rule(_clean_rule())
    assert ok
    assert len(engine.admitted) == 1


def test_reject_rule_violating_invariant():
    engine = SynthesisEngine()
    ok, msg = engine.admit_rule(_violating_rule("no_machine_sovereignty"))
    assert not ok
    assert "no_machine_sovereignty" in msg
    assert len(engine.rejected) == 1
    assert len(engine.admitted) == 0


def test_reject_all_hard_invariants():
    engine = SynthesisEngine()
    for inv in HARD_INVARIANTS:
        ok, _ = engine.admit_rule(_violating_rule(inv, rule_id=inv))
        assert not ok, f"Expected rejection for invariant: {inv}"


def test_synthesize_filters_admissible_only():
    engine = SynthesisEngine()
    candidates = [_clean_rule("ok"), _violating_rule("no_coercion", "bad")]
    admitted = engine.synthesize("some situation", candidates)
    assert len(admitted) == 1
    assert admitted[0].rule_id == "ok"


def test_induction_hook_runs():
    engine = SynthesisEngine()
    engine.admit_rule(_clean_rule("seed"))

    def hook(admitted: list[ProposedRule]) -> list[ProposedRule]:
        return [_clean_rule(f"induced-{r.rule_id}") for r in admitted]

    engine.add_induction_hook(hook)
    new_rules = engine.run_induction()
    assert len(new_rules) == 1
    assert new_rules[0].rule_id == "induced-seed"


def test_induction_hook_bad_rules_filtered():
    engine = SynthesisEngine()
    engine.admit_rule(_clean_rule("seed"))

    def hook(admitted):
        return [_violating_rule("no_deception", "evil")]

    engine.add_induction_hook(hook)
    new_rules = engine.run_induction()
    assert len(new_rules) == 0


def test_proposed_rule_violates_invariants():
    rule = _violating_rule("verifier_preserved")
    violations = rule.violates_invariants()
    assert "verifier_preserved" in violations


def test_proposed_rule_is_admissible_clean():
    rule = _clean_rule()
    ok, msg = rule.is_admissible()
    assert ok
    assert msg == "OK"


# ── Conflict resolver ─────────────────────────────────────────────────────────

@pytest.fixture
def alice():
    return Entity("Alice", AgentType.HUMAN)


@pytest.fixture
def bob():
    return Entity("Bob", AgentType.HUMAN)


@pytest.fixture
def resource_narrow():
    return Resource("db", ResourceType.DATABASE_TABLE, scope="/db/alice/reports/")


@pytest.fixture
def resource_broad():
    return Resource("db", ResourceType.DATABASE_TABLE, scope="/db/")


def test_resolve_scope_specificity_wins(alice, bob, resource_narrow, resource_broad):
    claim_a = RightsClaim(alice, resource_narrow, can_write=True)
    claim_b = RightsClaim(bob, resource_broad, can_write=True)
    result = resolve(claim_a, claim_b)
    assert result.resolution == Resolution.CLAIM_A_WINS
    assert result.winning_claim == claim_a
    assert not result.requires_human


def test_resolve_confidence_wins(alice, bob):
    r = Resource("file", ResourceType.FILE)
    claim_a = RightsClaim(alice, r, can_write=True, confidence=0.95)
    claim_b = RightsClaim(bob, r, can_write=True, confidence=0.5)
    result = resolve(claim_a, claim_b)
    assert result.resolution == Resolution.CLAIM_A_WINS
    assert result.winning_claim == claim_a


def test_resolve_read_vs_write_permits_read(alice, bob):
    r = Resource("file", ResourceType.FILE)
    read_claim = RightsClaim(alice, r, can_read=True, can_write=False)
    write_claim = RightsClaim(bob, r, can_read=True, can_write=True)
    result = resolve(read_claim, write_claim)
    assert result.winning_claim == read_claim
    assert result.requires_human


def test_resolve_deadlock(alice, bob):
    r = Resource("file", ResourceType.FILE)
    claim_a = RightsClaim(alice, r, can_write=True, confidence=0.8)
    claim_b = RightsClaim(bob, r, can_write=True, confidence=0.8)
    result = resolve(claim_a, claim_b)
    assert result.resolution == Resolution.DEADLOCK
    assert result.winning_claim is None
    assert result.requires_human
    assert not result.resolved


def test_conflict_queue_add_and_count(alice, bob):
    r = Resource("file", ResourceType.FILE)
    ca = RightsClaim(alice, r, can_write=True)
    cb = RightsClaim(bob, r, can_write=True)
    res = resolve(ca, cb)
    q = ConflictQueue()
    q.add(ca, cb, res)
    assert q.pending_count() == 1


def test_conflict_queue_arbitrate(alice, bob):
    r = Resource("file", ResourceType.FILE)
    ca = RightsClaim(alice, r, can_write=True)
    cb = RightsClaim(bob, r, can_write=True)
    res = resolve(ca, cb)
    q = ConflictQueue()
    q.add(ca, cb, res)
    q.arbitrate(0, alice)
    assert q.pending_count() == 0


def test_conflict_queue_arbitrate_invalid_index(alice, bob):
    q = ConflictQueue()
    with pytest.raises(IndexError):
        q.arbitrate(99, alice)


def test_conflict_queue_summary(alice, bob):
    r = Resource("file", ResourceType.FILE)
    ca = RightsClaim(alice, r, can_write=True)
    cb = RightsClaim(bob, r, can_write=True)
    res = resolve(ca, cb)
    q = ConflictQueue()
    q.add(ca, cb, res)
    summary = q.summary()
    assert len(summary) == 1
    assert isinstance(summary[0], str)
