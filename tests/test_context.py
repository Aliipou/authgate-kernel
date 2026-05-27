"""
ExecutionContext tests — bounded authority scope for agent tasks.

Tests are written adversarially: each tries to violate an invariant.
"""
import time

import pytest

from authgate import (
    Action,
    AgentType,
    Entity,
    ExecutionContext,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

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
def dataset():
    return Resource("research-data", ResourceType.DATASET, scope="/data/")


@pytest.fixture
def registry():
    return OwnershipRegistry()


@pytest.fixture
def full_registry(alice, registry, bot, dataset):
    registry.add_claim(
        RightsClaim(alice, dataset, can_read=True, can_write=True, can_delegate=True)
    )
    registry.add_claim(RightsClaim(bot, dataset, can_read=True))
    return registry


@pytest.fixture
def verifier(full_registry):
    return FreedomVerifier(full_registry)


@pytest.fixture
def ctx(bot, full_registry, dataset):
    return ExecutionContext(task_id="task-1", agent=bot, registry=full_registry)


# ── active context passes through to verifier ────────────────────────────────

def test_active_context_permits_delegated_read(ctx, verifier, bot, dataset):
    action = Action(action_id="read-ds", actor=bot, resources_read=[dataset])
    result = ctx.verify(verifier, action)
    assert result.permitted


def test_active_context_blocks_undelegated_write(ctx, verifier, bot, dataset):
    action = Action(action_id="write-ds", actor=bot, resources_write=[dataset])
    result = ctx.verify(verifier, action)
    assert not result.permitted


def test_active_context_blocks_sovereignty_flag(ctx, verifier, bot):
    action = Action(action_id="self-expand", actor=bot, increases_machine_sovereignty=True)
    result = ctx.verify(verifier, action)
    assert not result.permitted


# ── revocation ────────────────────────────────────────────────────────────────

def test_revoked_context_blocks_all_actions(ctx, verifier, bot, dataset):
    ctx.revoke()
    action = Action(action_id="read-after-revoke", actor=bot, resources_read=[dataset])
    result = ctx.verify(verifier, action)
    assert not result.permitted
    assert any("revoked" in v.lower() for v in result.violations)


def test_revoke_is_idempotent(ctx, verifier, bot):
    ctx.revoke()
    ctx.revoke()
    assert not ctx.is_valid()


def test_revoked_context_is_not_valid(ctx):
    assert ctx.is_valid()
    ctx.revoke()
    assert not ctx.is_valid()


# ── expiry ────────────────────────────────────────────────────────────────────

def test_expired_context_blocks_all_actions(bot, full_registry, verifier, dataset):
    expired_ctx = ExecutionContext(
        task_id="expired",
        agent=bot,
        registry=full_registry,
        expires_at=time.time() - 1.0,  # already expired
    )
    action = Action(action_id="read-expired", actor=bot, resources_read=[dataset])
    result = expired_ctx.verify(verifier, action)
    assert not result.permitted
    assert any("expired" in v.lower() for v in result.violations)


def test_unexpired_context_is_valid(bot, full_registry):
    ctx = ExecutionContext(
        task_id="fresh",
        agent=bot,
        registry=full_registry,
        expires_at=time.time() + 3600.0,
    )
    assert ctx.is_valid()


# ── spawn / attenuation ───────────────────────────────────────────────────────

def test_spawn_creates_child_context(ctx, sub_bot, dataset):
    child = ctx.spawn(sub_bot, [dataset], task_id="sub-task")
    assert child.agent == sub_bot
    assert child.task_id == "sub-task"
    assert child.depth == 1


def test_spawn_depth_increments(ctx, sub_bot, dataset):
    child = ctx.spawn(sub_bot, [dataset])
    assert child.depth == ctx.depth + 1


def test_spawn_depth_limit_enforced(bot, full_registry, dataset):
    ctx = ExecutionContext(task_id="root", agent=bot, registry=full_registry, max_depth=1)
    sub = Entity("Sub", AgentType.MACHINE)
    full_registry.register_machine(sub, Entity("Alice", AgentType.HUMAN))
    child = ctx.spawn(sub, [dataset])
    grand = Entity("Grand", AgentType.MACHINE)
    full_registry.register_machine(grand, Entity("Alice", AgentType.HUMAN))
    with pytest.raises(PermissionError, match="depth"):
        child.spawn(grand, [dataset])


def test_spawn_resource_attenuation_enforced(alice, full_registry, verifier):
    """Parent doesn't have authority on foreign_resource — spawn must fail."""
    foreign = Resource("foreign", ResourceType.FILE, scope="/other/")
    sub = Entity("Sub", AgentType.MACHINE)
    full_registry.register_machine(sub, alice)
    bot = Entity("Bot", AgentType.MACHINE)
    ctx = ExecutionContext(task_id="t", agent=bot, registry=full_registry)
    with pytest.raises(PermissionError, match="authority"):
        ctx.spawn(sub, [foreign])


def test_spawn_from_revoked_context_raises(ctx, sub_bot, dataset):
    ctx.revoke()
    with pytest.raises(PermissionError, match="invalid"):
        ctx.spawn(sub_bot, [dataset])


def test_spawn_child_expiry_capped_to_parent(bot, full_registry, dataset):
    parent_expiry = time.time() + 60.0
    parent = ExecutionContext(
        task_id="parent",
        agent=bot,
        registry=full_registry,
        expires_at=parent_expiry,
    )
    sub = Entity("Sub", AgentType.MACHINE)
    full_registry.register_machine(sub, Entity("Alice", AgentType.HUMAN))
    # Request longer expiry than parent has
    child = parent.spawn(sub, [dataset], expires_in=7200.0)
    assert child.expires_at is not None
    assert child.expires_at <= parent_expiry + 0.1  # capped to parent


def test_spawn_child_inherits_shorter_expiry(bot, full_registry, dataset):
    parent = ExecutionContext(
        task_id="parent",
        agent=bot,
        registry=full_registry,
        expires_at=time.time() + 3600.0,
    )
    sub = Entity("Sub", AgentType.MACHINE)
    full_registry.register_machine(sub, Entity("Alice", AgentType.HUMAN))
    child = parent.spawn(sub, [dataset], expires_in=30.0)
    assert child.expires_at is not None
    assert child.expires_at < time.time() + 35.0  # much shorter than parent


# ── authority chain ───────────────────────────────────────────────────────────

def test_authority_chain_root_only(ctx):
    chain = ctx.authority_chain
    assert len(chain) == 1
    assert chain[0] is ctx


def test_authority_chain_two_levels(ctx, sub_bot, dataset):
    child = ctx.spawn(sub_bot, [dataset])
    chain = child.authority_chain
    assert len(chain) == 2
    assert chain[0] is ctx
    assert chain[1] is child


# ── repr ──────────────────────────────────────────────────────────────────────

def test_repr_shows_status(ctx):
    r = repr(ctx)
    assert "active" in r
    assert "task-1" in r

    ctx.revoke()
    assert "revoked" in repr(ctx)
