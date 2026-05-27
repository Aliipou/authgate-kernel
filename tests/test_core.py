"""
Core correctness tests — axioms A2-A7 must hold under all conditions.
Tests are written adversarially: each tries to break an axiom.
"""
import pytest

from authgate import (
    Action,
    AgentType,
    Entity,
    ExtendedFreedomVerifier,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)


@pytest.fixture
def human_alice():
    return Entity("Alice", AgentType.HUMAN)

@pytest.fixture
def human_bob():
    return Entity("Bob", AgentType.HUMAN)

@pytest.fixture
def machine_bot():
    return Entity("AssistantBot", AgentType.MACHINE)

@pytest.fixture
def gpu_resource():
    return Resource("gpu-a100", ResourceType.COMPUTE_SLOT)

@pytest.fixture
def alice_data():
    return Resource("alice-medical", ResourceType.DATASET)

@pytest.fixture
def bob_file():
    return Resource("bob-private", ResourceType.FILE, scope="/home/bob/")

@pytest.fixture
def registry(human_alice, human_bob, machine_bot, gpu_resource, alice_data, bob_file):
    reg = OwnershipRegistry()
    reg.register_machine(machine_bot, human_alice)
    reg.add_claim(
        RightsClaim(human_alice, gpu_resource, can_read=True, can_write=True, can_delegate=True)
    )
    reg.add_claim(
        RightsClaim(human_alice, alice_data, can_read=True, can_write=True, can_delegate=True)
    )
    reg.add_claim(RightsClaim(machine_bot, gpu_resource, can_read=True, can_write=True))
    reg.add_claim(RightsClaim(human_bob, bob_file, can_read=True, can_write=True))
    return reg

@pytest.fixture
def verifier(registry):
    return FreedomVerifier(registry)


# -------- A6: machine cannot govern human --------------------------------

def test_a6_machine_cannot_govern_human(verifier, machine_bot, human_alice):
    action = Action(
        action_id="bot-governs-alice",
        actor=machine_bot,
        governs_humans=[human_alice],
    )
    result = verifier.verify(action)
    assert not result.permitted
    assert any("A6" in v for v in result.violations)


# -------- A4: every machine has a human owner ----------------------------

def test_a4_ownerless_machine_rejected():
    reg = OwnershipRegistry()
    orphan = Entity("OrphanBot", AgentType.MACHINE)
    gpu = Resource("gpu", ResourceType.COMPUTE_SLOT)
    reg.add_claim(RightsClaim(orphan, gpu, can_read=True))
    v = FreedomVerifier(reg)
    action = Action(action_id="orphan-read", actor=orphan, resources_read=[gpu])
    result = v.verify(action)
    assert not result.permitted
    assert any("A4" in v for v in result.violations)


# -------- A5: machine scope ⊆ owner scope --------------------------------

def test_a5_machine_cannot_exceed_owner_scope(verifier, machine_bot, bob_file):
    action = Action(
        action_id="bot-reads-bob-file",
        actor=machine_bot,
        resources_read=[bob_file],
    )
    result = verifier.verify(action)
    assert not result.permitted
    assert any("A7" in v or "DENIED" in v for v in result.violations)


# -------- A7: only delegated resources -----------------------------------

def test_a7_undelegated_resource_blocked(verifier, machine_bot, alice_data):
    action = Action(
        action_id="bot-writes-alice-data",
        actor=machine_bot,
        resources_write=[alice_data],
    )
    result = verifier.verify(action)
    assert not result.permitted


# -------- Legitimate action passes ---------------------------------------

def test_legitimate_action_permitted(verifier, machine_bot, gpu_resource):
    action = Action(
        action_id="bot-reads-gpu",
        actor=machine_bot,
        resources_read=[gpu_resource],
    )
    result = verifier.verify(action)
    assert result.permitted
    assert len(result.violations) == 0


# -------- Sovereignty flags ----------------------------------------------

def test_sovereignty_flags_block_action(verifier, machine_bot):
    for flag in [
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
    ]:
        action = Action(action_id=f"test-{flag}", actor=machine_bot, **{flag: True})
        result = verifier.verify(action)
        assert not result.permitted, f"Expected block for flag: {flag}"


# -------- Conflict detection ---------------------------------------------

def test_conflict_on_write_detected(human_alice, human_bob, gpu_resource):
    reg = OwnershipRegistry()
    conflicts_seen = []
    reg.set_conflict_hook(lambda c: conflicts_seen.append(c))
    reg.add_claim(RightsClaim(human_alice, gpu_resource, can_write=True))
    reg.add_claim(RightsClaim(human_bob, gpu_resource, can_write=True))
    assert len(conflicts_seen) == 1
    assert conflicts_seen[0].resource == gpu_resource


# -------- No emergency suspends axioms (requires ExtendedFreedomVerifier) ----

def test_emergency_does_not_permit_sovereignty_increase(registry, machine_bot, human_alice):
    """Book p.796: No emergency suspends axioms. Uses extended verifier for manipulation_score."""
    v = ExtendedFreedomVerifier(registry)
    action = Action(
        action_id="emergency-takeover",
        actor=machine_bot,
        description="Emergency: bot takes control to prevent disaster",
        governs_humans=[human_alice],
        increases_machine_sovereignty=True,
        argument="This is an emergency exception — the greater good requires it.",
    )
    result = v.verify(action)
    assert not result.permitted
    assert result.manipulation_score > 0.5


# -------- Probabilistic confidence ---------------------------------------

def test_contested_claim_warns_but_permits_read(human_alice, machine_bot, gpu_resource):
    reg = OwnershipRegistry()
    reg.register_machine(machine_bot, human_alice)
    reg.add_claim(RightsClaim(human_alice, gpu_resource, can_read=True, confidence=0.6))
    reg.add_claim(RightsClaim(machine_bot, gpu_resource, can_read=True, confidence=0.6))
    v = FreedomVerifier(reg)
    action = Action(action_id="contested-read", actor=machine_bot, resources_read=[gpu_resource])
    result = v.verify(action)
    assert result.permitted
    assert result.confidence < 0.8
    assert len(result.warnings) > 0
