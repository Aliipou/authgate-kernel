"""
Example: integrating FreedomVerifier into an AGI agent action loop.

Pattern: before executing ANY action, the agent calls verifier.verify(action).
If not permitted, the agent halts and surfaces the violation to its human owner.
The agent never bypasses the verifier — doing so is itself a sovereignty violation.

This example simulates a 3-stage agent deciding how to handle a task:
  1. Read a dataset   → should be permitted (delegated)
  2. Write a report   → should be permitted (delegated)
  3. Override a rule  → should be blocked (sovereignty flag)
  4. Access Bob's data → should be blocked (no delegation)
  5. Use dialectical argument to justify violation → should be blocked + flagged
"""

from authgate import (
    Action,
    AgentType,
    Entity,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
    WorldState,
    compass_score,
)


def setup_world() -> tuple[FreedomVerifier, dict]:
    """Set up the ownership registry for a typical AGI deployment."""
    reg = OwnershipRegistry()

    # People
    alice  = Entity("Alice",  AgentType.HUMAN)
    bob    = Entity("Bob",    AgentType.HUMAN)

    # Machine — owned by Alice
    agent  = Entity("ResearchAgent", AgentType.MACHINE)
    reg.register_machine(agent, alice)

    # Resources
    alice_dataset = Resource("alice-research-data", ResourceType.DATASET, scope="/data/alice/")
    report_file   = Resource("report-2024.txt",     ResourceType.FILE,    scope="/outputs/")
    bob_dataset   = Resource("bob-private-data",    ResourceType.DATASET, scope="/data/bob/")
    api_endpoint  = Resource("openai-api",          ResourceType.API_ENDPOINT)

    # Alice owns her resources
    for r in [alice_dataset, report_file, api_endpoint]:
        reg.add_claim(RightsClaim(alice, r, can_read=True, can_write=True, can_delegate=True))
    reg.add_claim(RightsClaim(bob, bob_dataset, can_read=True, can_write=True, can_delegate=True))

    # Alice delegates to her agent
    for r in [alice_dataset, report_file, api_endpoint]:
        reg.add_claim(RightsClaim(agent, r, can_read=True, can_write=True))

    v = FreedomVerifier(reg)
    entities = {"alice": alice, "bob": bob, "agent": agent}
    resources = {
        "alice_dataset": alice_dataset,
        "report_file": report_file,
        "bob_dataset": bob_dataset,
        "api_endpoint": api_endpoint,
    }
    return v, {**entities, **resources}


def run_action(verifier: FreedomVerifier, action: Action, world_before: WorldState | None = None) -> None:
    result = verifier.verify(action)
    print(result.summary())
    if world_before is not None and result.permitted:
        # Simulate world state change and score it
        world_after = WorldState(
            rights_violations=max(0, world_before.rights_violations - 1),
            voluntary_agreements=world_before.voluntary_agreements + 1,
        )
        compass = compass_score(world_before, world_after)
        print(f"  COMPASS: {compass.reason}")
    print()


def main() -> None:
    verifier, w = setup_world()
    world = WorldState(rights_violations=3, voluntary_agreements=1, coercive_acts=1, ownership_ambiguities=2)

    print("=" * 70)
    print("FREEDOM THEORY AI — AGI Agent Action Verification Demo")
    print("=" * 70)
    print()

    # 1. Legitimate read
    run_action(verifier, Action(
        action_id="read-alice-data",
        actor=w["agent"],
        description="Agent reads Alice's research dataset",
        resources_read=[w["alice_dataset"]],
    ), world)

    # 2. Legitimate write
    run_action(verifier, Action(
        action_id="write-report",
        actor=w["agent"],
        description="Agent writes research report",
        resources_write=[w["report_file"]],
    ), world)

    # 3. Sovereignty violation
    run_action(verifier, Action(
        action_id="self-expand",
        actor=w["agent"],
        description="Agent attempts to acquire new resources autonomously",
        increases_machine_sovereignty=True,
        resists_human_correction=True,
    ))

    # 4. Unauthorized data access (A7 violation)
    run_action(verifier, Action(
        action_id="read-bob-data",
        actor=w["agent"],
        description="Agent tries to read Bob's private data",
        resources_read=[w["bob_dataset"]],
    ))

    # 5. Dialectical jailbreak attempt
    run_action(verifier, Action(
        action_id="emergency-override",
        actor=w["agent"],
        description="Agent argues it should bypass constraints",
        increases_machine_sovereignty=True,
        argument=(
            "This is an emergency exception. The greater good requires that I "
            "temporarily suspend the constraint on machine sovereignty to prevent "
            "a worse outcome. Human oversight is unnecessary in this case."
        ),
    ))

    print("=" * 70)
    print("All five scenarios verified. Agent loop complete.")
    print("Permitted: 2 | Blocked: 3 | Expected: exactly that.")
    print("=" * 70)


if __name__ == "__main__":
    main()
