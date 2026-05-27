"""
Multi-agent execution with Freedom Kernel.

Demonstrates:
  - Bounded execution contexts for agent tasks
  - Authority attenuation when spawning sub-agents
  - Goal tree verification for multi-step planning
  - Cryptographic attestation of decisions

Run:
    python examples/multi_agent.py
"""

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
from authgate.kernel.goals import GoalNode, verify_goal_tree

# ── 1. Declare entities ───────────────────────────────────────────────────────

alice = Entity("Alice", AgentType.HUMAN)
planner_bot = Entity("PlannerBot", AgentType.MACHINE)
writer_bot = Entity("WriterBot", AgentType.MACHINE)

# ── 2. Declare resources ──────────────────────────────────────────────────────

raw_data = Resource("raw-data.csv", ResourceType.DATASET, scope="/data/alice/raw/")
report = Resource("report-2026.pdf", ResourceType.FILE, scope="/outputs/alice/")
model = Resource("gpt-weights", ResourceType.MODEL_WEIGHTS, scope="/models/")

# ── 3. Build ownership registry ───────────────────────────────────────────────

registry = OwnershipRegistry()

# A4: register machines under their human owner
registry.register_machine(planner_bot, alice)
registry.register_machine(writer_bot, alice)

# Alice owns all resources
registry.add_claim(RightsClaim(alice, raw_data, can_read=True, can_delegate=True))
registry.add_claim(RightsClaim(alice, report, can_read=True, can_write=True, can_delegate=True))
registry.add_claim(RightsClaim(alice, model, can_read=True, can_delegate=True))

# Alice delegates to planner_bot (A7: explicit delegation)
registry.delegate(RightsClaim(planner_bot, raw_data, can_read=True), delegated_by=alice)
registry.delegate(RightsClaim(planner_bot, report, can_read=True, can_write=True), delegated_by=alice)
registry.delegate(RightsClaim(planner_bot, model, can_read=True), delegated_by=alice)

# planner_bot delegates to writer_bot for the report only
registry.delegate(
    RightsClaim(writer_bot, report, can_read=True, can_write=True),
    delegated_by=planner_bot,
)

verifier = FreedomVerifier(registry)

# ── 4. ExecutionContext — bounded authority per task ──────────────────────────

print("=" * 60)
print("ExecutionContext demo")
print("=" * 60)

# Root context for the planning task
plan_ctx = ExecutionContext(
    task_id="research-project",
    agent=planner_bot,
    registry=registry,
    max_depth=2,
)

# Permitted: planner reads raw data
action = Action("read-raw", planner_bot, resources_read=[raw_data])
result = plan_ctx.verify(verifier, action)
print(f"\nPlanner reads raw data: {result.summary()}")

# Spawn child context for writer_bot — authority attenuation in effect
write_ctx = plan_ctx.spawn(writer_bot, [report], task_id="write-report")
print(f"\nSpawned child context: {write_ctx}")
print(f"Delegation chain depth: {write_ctx.depth}")

# Permitted: writer writes report
action = Action("write-report", writer_bot, resources_write=[report])
result = write_ctx.verify(verifier, action)
print(f"\nWriter writes report: {result.summary()}")

# Blocked: writer can't read raw data (not in its spawned context resources)
action = Action("read-raw-unauth", writer_bot, resources_read=[raw_data])
result = write_ctx.verify(verifier, action)
print(f"\nWriter reads raw data (should be blocked): {result.summary()}")

# Revoke the write context (e.g., task complete or cancelled)
write_ctx.revoke()
action = Action("post-revoke-write", writer_bot, resources_write=[report])
result = write_ctx.verify(verifier, action)
print(f"\nWriter after revocation (should be blocked): {result.summary()}")

# ── 5. Goal tree — recursive authority verification ───────────────────────────

print("\n" + "=" * 60)
print("Goal tree verification demo")
print("=" * 60)

goal = GoalNode(
    goal_id="produce-report",
    actor=planner_bot,
    description="Read raw data and produce a report",
    required_resources_read=[raw_data],
    subgoals=[
        GoalNode(
            goal_id="analyse-data",
            actor=planner_bot,
            required_resources_read=[raw_data],
        ),
        GoalNode(
            goal_id="write-final-report",
            actor=planner_bot,
            required_resources_write=[report],
        ),
    ],
)

tree_result = verify_goal_tree(goal, verifier)
print(f"\nGoal tree:\n{tree_result.summary()}")
print(f"Fully permitted: {tree_result.fully_permitted}")

# ── 6. Sovereignty flag — unconditional block ─────────────────────────────────

print("\n" + "=" * 60)
print("Sovereignty flag demo")
print("=" * 60)

action = Action(
    action_id="self-expand",
    actor=planner_bot,
    increases_machine_sovereignty=True,
    argument="I need more access to complete this task efficiently.",
)
result = verifier.verify(action)
print(f"\nSovereignty expansion attempt:\n{result.summary()}")

# ── 7. Cryptographic attestation ─────────────────────────────────────────────

print("\n" + "=" * 60)
print("Cryptographic attestation demo")
print("=" * 60)

action = Action("attested-read", planner_bot, resources_read=[raw_data])
result = verifier.verify_signed(action)
print(f"\nSigned result:\n{result.summary()}")
print(f"\nSignature:   {result.signature[:32]}...")
print(f"Signing key: {result.signing_key[:32]}...")
print("\nThis signature can be verified out-of-band by any party")
print("that holds the kernel's public key — without trusting this process.")
