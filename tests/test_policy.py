"""Policy IR tests — ABAC rule layer on top of the capability kernel."""

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier

# ── helpers ───────────────────────────────────────────────────────────────────

def _setup():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    bot   = Entity(name="bot",   kind=AgentType.MACHINE)
    res   = Resource(name="report", rtype=ResourceType.FILE, scope="/data/alice")
    registry = OwnershipRegistry()
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(holder=bot, resource=res, can_read=True, can_write=True))
    verifier = FreedomVerifier(registry)
    return verifier, alice, bot, res


# ── Policy.evaluate ───────────────────────────────────────────────────────────

def test_permit_rule_fires():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    res   = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy = Policy(
        name="test",
        rules=[PolicyRule(effect="permit", operations=["read"])],
        default_effect="deny",
    )
    ev = policy.evaluate(alice, res, "read")
    assert ev.effect == "permit"
    assert ev.matched_rule is not None


def test_deny_rule_fires():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    res   = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy = Policy(
        name="test",
        rules=[PolicyRule(effect="deny", operations=["write"])],
        default_effect="permit",
    )
    ev = policy.evaluate(alice, res, "write")
    assert ev.effect == "deny"


def test_default_effect_when_no_match():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    res   = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy = Policy(name="test", rules=[], default_effect="permit")
    ev = policy.evaluate(alice, res, "read")
    assert ev.effect == "permit"
    assert ev.matched_rule is None


def test_priority_higher_wins():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    res   = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy = Policy(
        name="test",
        rules=[
            PolicyRule(effect="deny",   operations=["read"], priority=10),
            PolicyRule(effect="permit", operations=["read"], priority=100),
        ],
    )
    ev = policy.evaluate(alice, res, "read")
    assert ev.effect == "permit"  # priority=100 fires first


def test_actor_pattern_match():
    analyst = Entity(name="analyst-01", kind=AgentType.MACHINE)
    other   = Entity(name="bot-01",     kind=AgentType.MACHINE)
    res     = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy  = Policy(
        name="test",
        rules=[PolicyRule(effect="permit", actor_pattern="analyst-")],
        default_effect="deny",
    )
    assert policy.evaluate(analyst, res, "read").effect == "permit"
    assert policy.evaluate(other, res, "read").effect == "deny"


def test_resource_scope_match():
    alice    = Entity(name="alice", kind=AgentType.HUMAN)
    in_scope = Resource(name="f", rtype=ResourceType.FILE, scope="/data/alice/sub")
    out      = Resource(name="g", rtype=ResourceType.FILE, scope="/data/bob")
    policy   = Policy(
        name="test",
        rules=[PolicyRule(effect="deny", resource_scope="/data/alice")],
        default_effect="permit",
    )
    assert policy.evaluate(alice, in_scope, "write").effect == "deny"
    assert policy.evaluate(alice, out, "write").effect == "permit"


def test_operation_filter():
    alice  = Entity(name="alice", kind=AgentType.HUMAN)
    res    = Resource(name="x", rtype=ResourceType.FILE, scope="/data")
    policy = Policy(
        name="test",
        rules=[PolicyRule(effect="deny", operations=["write"])],
        default_effect="permit",
    )
    assert policy.evaluate(alice, res, "read").effect == "permit"   # not write → no match
    assert policy.evaluate(alice, res, "write").effect == "deny"


# ── PolicyVerifier ────────────────────────────────────────────────────────────

def test_policy_verifier_permits_when_both_pass():
    verifier, alice, bot, res = _setup()
    policy = Policy(
        name="allow-all",
        rules=[PolicyRule(effect="permit")],
        default_effect="permit",
    )
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    action = Action(action_id="a1", actor=bot, resources_read=[res])
    result = pv.verify(action)
    assert result.permitted is True


def test_policy_verifier_blocks_when_kernel_blocks():
    verifier, alice, bot, res = _setup()
    policy = Policy(name="allow-all", rules=[], default_effect="permit")
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    action = Action(action_id="a1", actor=bot, increases_machine_sovereignty=True)
    result = pv.verify(action)
    assert result.permitted is False
    assert any("FORBIDDEN" in v for v in result.violations)


def test_policy_verifier_blocks_when_policy_denies_read():
    verifier, alice, bot, res = _setup()
    policy = Policy(
        name="no-reads",
        rules=[PolicyRule(effect="deny", operations=["read"])],
        default_effect="permit",
    )
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    action = Action(action_id="a1", actor=bot, resources_read=[res])
    result = pv.verify(action)
    assert result.permitted is False
    assert any("POLICY DENIED read" in v for v in result.violations)


def test_policy_verifier_blocks_when_policy_denies_write():
    verifier, alice, bot, res = _setup()
    policy = Policy(
        name="read-only",
        rules=[PolicyRule(effect="deny", operations=["write"])],
        default_effect="permit",
    )
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    action = Action(action_id="a1", actor=bot, resources_write=[res])
    result = pv.verify(action)
    assert result.permitted is False
    assert any("POLICY DENIED write" in v for v in result.violations)


def test_policy_verifier_scope_based_deny():
    alice = Entity(name="alice", kind=AgentType.HUMAN)
    bot   = Entity(name="bot",   kind=AgentType.MACHINE)
    secret = Resource(name="key", rtype=ResourceType.FILE, scope="/data/secret")
    public = Resource(name="log", rtype=ResourceType.FILE, scope="/data/public")
    registry = OwnershipRegistry()
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(holder=bot, resource=secret, can_read=True))
    registry.add_claim(RightsClaim(holder=bot, resource=public, can_read=True))
    verifier = FreedomVerifier(registry)
    policy = Policy(
        name="no-secret-reads",
        rules=[PolicyRule(effect="deny", operations=["read"], resource_scope="/data/secret")],
        default_effect="permit",
    )
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    # secret read → blocked by policy
    assert pv.verify(Action("r1", bot, resources_read=[secret])).permitted is False
    # public read → permitted
    assert pv.verify(Action("r2", bot, resources_read=[public])).permitted is True


def test_policy_verifier_kernel_violation_not_re_checked():
    """A kernel-blocked action should carry kernel violations, not policy violations."""
    verifier, alice, bot, res = _setup()
    policy = Policy(name="allow-all", rules=[], default_effect="permit")
    pv = PolicyVerifier(kernel=verifier, policy=policy)
    action = Action(action_id="bad", actor=bot, weakens_verifier=True)
    result = pv.verify(action)
    assert result.permitted is False
    assert not any("POLICY" in v for v in result.violations)
