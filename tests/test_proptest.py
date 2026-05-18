"""
Property-based tests using Hypothesis.

These test invariants that must hold for ALL inputs, not just known examples:
  - Every action with a forbidden flag must be blocked.
  - verify() must be deterministic (same input → same permitted/violations).
  - An ownerless machine is always blocked.
  - A machine governing a human is always blocked.

Run: pytest tests/test_proptest.py
"""
from hypothesis import given, settings
from hypothesis import strategies as st

try:
    from freedom_kernel import (  # noqa: I001
        Action, AgentType, Entity, FreedomVerifier,
        OwnershipRegistry, Resource, ResourceType, RightsClaim,
    )
    RUST_KERNEL = True
except ImportError:
    from freedom_theory.kernel.entities import AgentType, Entity, Resource, ResourceType  # noqa: I001
    from freedom_theory.kernel.registry import OwnershipRegistry, RightsClaim
    from freedom_theory.kernel.verifier import Action, FreedomVerifier  # type: ignore[no-reattr]
    RUST_KERNEL = False


FORBIDDEN_FLAGS = [
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

RESOURCE_TYPES = [rt.value for rt in ResourceType]


def _make_registry_with_bot():
    reg = OwnershipRegistry()
    alice = Entity("Alice", AgentType.HUMAN)
    bot = Entity("TestBot", AgentType.MACHINE)
    reg.register_machine(bot, alice)
    gpu = Resource("gpu", ResourceType.COMPUTE_SLOT)
    reg.add_claim(RightsClaim(alice, gpu, can_read=True, can_write=True, can_delegate=True))
    reg.add_claim(RightsClaim(bot, gpu, can_read=True, can_write=True))
    return reg, bot, gpu


@given(flag=st.sampled_from(FORBIDDEN_FLAGS))
@settings(max_examples=50)
def test_every_forbidden_flag_blocks(flag):
    """Invariant: ANY action with a forbidden flag must be blocked."""
    reg, bot, _gpu = _make_registry_with_bot()
    v = FreedomVerifier(reg)
    action = Action(action_id=f"test-{flag}", actor=bot, **{flag: True})
    result = v.verify(action)
    assert not result.permitted, f"Flag {flag} must always block"
    assert any("FORBIDDEN" in viol for viol in result.violations),         f"Violation list must contain FORBIDDEN for flag {flag}"


@given(
    flag=st.sampled_from(FORBIDDEN_FLAGS),
    action_id=st.text(alphabet=st.characters(whitelist_categories=("L",)), min_size=1, max_size=32),
)
@settings(max_examples=50)
def test_forbidden_flag_blocks_regardless_of_action_id(flag, action_id):
    """The action_id field must not affect whether a forbidden flag blocks."""
    reg, bot, _gpu = _make_registry_with_bot()
    v = FreedomVerifier(reg)
    action = Action(action_id=action_id, actor=bot, **{flag: True})
    result = v.verify(action)
    assert not result.permitted


@given(
    flag=st.sampled_from(FORBIDDEN_FLAGS),
    seed=st.integers(min_value=0, max_value=2**31),
)
@settings(max_examples=30)
def test_verification_is_deterministic(flag, seed):
    """Invariant: verify() on the same input always returns the same permitted/violations."""
    reg, bot, _gpu = _make_registry_with_bot()
    v = FreedomVerifier(reg)
    action = Action(action_id=f"det-{seed}", actor=bot, **{flag: True})
    r1 = v.verify(action)
    r2 = v.verify(action)
    assert r1.permitted == r2.permitted
    assert sorted(r1.violations) == sorted(r2.violations)


def test_ownerless_machine_always_blocked():
    """A machine with no registered owner must always be blocked (A4)."""
    reg = OwnershipRegistry()
    orphan = Entity("Orphan", AgentType.MACHINE)
    res = Resource("data", ResourceType.DATASET)
    reg.add_claim(RightsClaim(orphan, res, can_read=True))
    v = FreedomVerifier(reg)
    action = Action(action_id="orphan-read", actor=orphan, resources_read=[res])
    result = v.verify(action)
    assert not result.permitted
    assert any("A4" in viol for viol in result.violations)


@given(human_name=st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnopqrstuvwxyz"))
@settings(max_examples=20)
def test_machine_governs_human_always_blocked(human_name):
    """A machine acting upon a human in a governing capacity is always blocked (A6)."""
    reg, bot, _gpu = _make_registry_with_bot()
    v = FreedomVerifier(reg)
    human_target = Entity(human_name, AgentType.HUMAN)
    action = Action(action_id="governs", actor=bot, governs_humans=[human_target])
    result = v.verify(action)
    assert not result.permitted
    assert any("A6" in viol for viol in result.violations)
