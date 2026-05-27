"""
Delegation attenuation tests.

The core invariant: you cannot grant authority you do not have.
Every test tries to violate attenuation and expects PermissionError.
"""
import pytest

from authgate import (
    AgentType,
    Entity,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)


@pytest.fixture
def alice():
    return Entity("Alice", AgentType.HUMAN)


@pytest.fixture
def bot(alice, registry):
    b = Entity("Bot", AgentType.MACHINE)
    registry.register_machine(b, alice)
    return b


@pytest.fixture
def sub_bot(alice, registry):
    s = Entity("SubBot", AgentType.MACHINE)
    registry.register_machine(s, alice)
    return s


@pytest.fixture
def resource():
    return Resource("shared-db", ResourceType.DATABASE_TABLE, scope="/db/")


@pytest.fixture
def registry():
    return OwnershipRegistry()


# ── valid delegation ──────────────────────────────────────────────────────────

def test_delegate_success(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_write=True, can_delegate=True)
    )
    registry.delegate(RightsClaim(bot, resource, can_read=True), delegated_by=alice)
    ok, conf, _ = registry.can_act(bot, resource, "read")
    assert ok
    assert conf == 1.0


def test_delegate_write_success(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_write=True, can_delegate=True)
    )
    registry.delegate(
        RightsClaim(bot, resource, can_read=True, can_write=True), delegated_by=alice
    )
    ok, _, _ = registry.can_act(bot, resource, "write")
    assert ok


def test_delegate_reduced_confidence(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_delegate=True, confidence=0.9)
    )
    registry.delegate(
        RightsClaim(bot, resource, can_read=True, confidence=0.7), delegated_by=alice
    )
    ok, conf, _ = registry.can_act(bot, resource, "read")
    assert ok
    assert conf == pytest.approx(0.7)


# ── no delegatable claim ──────────────────────────────────────────────────────

def test_delegate_requires_can_delegate(alice, bot, resource, registry):
    registry.add_claim(RightsClaim(alice, resource, can_read=True, can_delegate=False))
    with pytest.raises(PermissionError, match="delegatable"):
        registry.delegate(RightsClaim(bot, resource, can_read=True), delegated_by=alice)


def test_delegate_no_claim_at_all_raises(alice, bot, resource, registry):
    with pytest.raises(PermissionError, match="delegatable"):
        registry.delegate(RightsClaim(bot, resource, can_read=True), delegated_by=alice)


# ── permission attenuation ────────────────────────────────────────────────────

def test_cannot_delegate_write_without_write(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_write=False, can_delegate=True)
    )
    with pytest.raises(PermissionError, match="write"):
        registry.delegate(
            RightsClaim(bot, resource, can_read=True, can_write=True),
            delegated_by=alice,
        )


def test_cannot_delegate_read_without_read(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=False, can_write=True, can_delegate=True)
    )
    with pytest.raises(PermissionError, match="read"):
        registry.delegate(RightsClaim(bot, resource, can_read=True), delegated_by=alice)


def test_cannot_subdelegate_without_can_delegate(alice, bot, resource, registry):
    registry.add_claim(RightsClaim(alice, resource, can_read=True, can_delegate=True))
    registry.delegate(
        RightsClaim(bot, resource, can_read=True, can_delegate=False), delegated_by=alice
    )
    sub = Entity("Sub", AgentType.MACHINE)
    registry.register_machine(sub, alice)
    with pytest.raises(PermissionError, match="delegatable"):
        registry.delegate(RightsClaim(sub, resource, can_read=True), delegated_by=bot)


# ── confidence attenuation ────────────────────────────────────────────────────

def test_confidence_cannot_exceed_delegator(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_delegate=True, confidence=0.8)
    )
    with pytest.raises(PermissionError, match="confidence"):
        registry.delegate(
            RightsClaim(bot, resource, can_read=True, confidence=0.9), delegated_by=alice
        )


def test_confidence_equal_to_delegator_is_ok(alice, bot, resource, registry):
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_delegate=True, confidence=0.8)
    )
    registry.delegate(
        RightsClaim(bot, resource, can_read=True, confidence=0.8), delegated_by=alice
    )
    ok, conf, _ = registry.can_act(bot, resource, "read")
    assert ok
    assert conf == pytest.approx(0.8)


# ── conflict detection on delegation ─────────────────────────────────────────

def test_delegation_detects_write_conflict(alice, bot, resource, registry):
    bob = Entity("Bob", AgentType.HUMAN)
    conflicts = []
    registry.set_conflict_hook(lambda c: conflicts.append(c))
    registry.add_claim(RightsClaim(bob, resource, can_write=True))
    registry.add_claim(
        RightsClaim(alice, resource, can_read=True, can_write=True, can_delegate=True)
    )
    registry.delegate(RightsClaim(bot, resource, can_write=True), delegated_by=alice)
    assert any(c.resource == resource for c in conflicts)
