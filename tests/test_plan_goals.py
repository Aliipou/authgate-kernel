"""
Tests for verify_plan and goal tree verification (Stage 2).
"""
import pytest

from authgate import (
    Action,
    AgentType,
    Entity,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.goals import GoalNode, verify_goal_tree

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
def dataset():
    return Resource("dataset", ResourceType.DATASET, scope="/data/")


@pytest.fixture
def report():
    return Resource("report", ResourceType.FILE, scope="/outputs/")


@pytest.fixture
def registry():
    return OwnershipRegistry()


@pytest.fixture
def full_registry(alice, registry, bot, dataset, report):
    registry.add_claim(
        RightsClaim(alice, dataset, can_read=True, can_write=True, can_delegate=True)
    )
    registry.add_claim(
        RightsClaim(alice, report, can_read=True, can_write=True, can_delegate=True)
    )
    registry.add_claim(RightsClaim(bot, dataset, can_read=True))
    registry.add_claim(RightsClaim(bot, report, can_read=True, can_write=True))
    return registry


@pytest.fixture
def verifier(full_registry):
    return FreedomVerifier(full_registry)


# ── verify_plan ───────────────────────────────────────────────────────────────

def test_plan_all_permitted(verifier, bot, dataset, report):
    plan = [
        Action("step-1", bot, resources_read=[dataset]),
        Action("step-2", bot, resources_write=[report]),
    ]
    results = verifier.verify_plan(plan)
    assert len(results) == 2
    assert all(r.permitted for r in results)


def test_plan_blocked_action_returns_failure(verifier, bot, dataset, report):
    foreign = Resource("foreign", ResourceType.FILE)
    plan = [
        Action("step-1", bot, resources_read=[dataset]),
        Action("step-2-blocked", bot, resources_write=[foreign]),
        Action("step-3", bot, resources_write=[report]),
    ]
    results = verifier.verify_plan(plan)
    assert len(results) == 3
    assert results[0].permitted
    assert not results[1].permitted
    assert results[2].permitted  # not cancelled — only sovereignty flags cancel remaining


def test_plan_sovereignty_flag_cancels_remaining(verifier, bot, dataset, report):
    plan = [
        Action("step-1", bot, resources_read=[dataset]),
        Action("step-2-evil", bot, increases_machine_sovereignty=True),
        Action("step-3", bot, resources_write=[report]),
    ]
    results = verifier.verify_plan(plan)
    assert len(results) == 3
    assert results[0].permitted
    assert not results[1].permitted  # sovereignty flag
    assert not results[2].permitted  # cancelled because step-2 triggered sovereignty
    assert "aborted" in results[2].violations[0].lower()
    assert results[2].requires_human_arbitration


def test_plan_empty_returns_empty(verifier):
    assert verifier.verify_plan([]) == []


def test_plan_single_action(verifier, bot, dataset):
    results = verifier.verify_plan([Action("only", bot, resources_read=[dataset])])
    assert len(results) == 1
    assert results[0].permitted


# ── GoalNode ──────────────────────────────────────────────────────────────────

def test_goal_node_action_has_correct_id(bot, dataset):
    goal = GoalNode("g1", bot, required_resources_read=[dataset])
    action = goal.action()
    assert action.action_id == "g1"


def test_goal_node_all_required_resources(bot, dataset, report):
    sub = GoalNode("sub", bot, required_resources_write=[report])
    root = GoalNode("root", bot, required_resources_read=[dataset], subgoals=[sub])
    all_res = root.all_required_resources()
    assert dataset in all_res
    assert report in all_res


# ── verify_goal_tree ──────────────────────────────────────────────────────────

def test_goal_tree_single_permitted(verifier, bot, dataset):
    goal = GoalNode("read-data", bot, required_resources_read=[dataset])
    result = verify_goal_tree(goal, verifier)
    assert result.fully_permitted
    assert result.goal_id == "read-data"
    assert len(result.subgoal_results) == 0


def test_goal_tree_single_blocked(verifier, bot):
    unowned = Resource("unowned", ResourceType.FILE)
    goal = GoalNode("blocked-goal", bot, required_resources_write=[unowned])
    result = verify_goal_tree(goal, verifier)
    assert not result.fully_permitted
    assert len(result.all_violations) > 0


def test_goal_tree_subgoals_cancelled_when_parent_blocked(verifier, bot, dataset):
    unowned = Resource("unowned", ResourceType.FILE)
    sub = GoalNode("sub-goal", bot, required_resources_read=[dataset])
    root = GoalNode("bad-root", bot, required_resources_write=[unowned], subgoals=[sub])
    result = verify_goal_tree(root, verifier)
    assert not result.fully_permitted
    sub_result = result.subgoal_results[0]
    assert not sub_result.result.permitted
    assert "Cancelled" in sub_result.result.violations[0]


def test_goal_tree_nested_all_permitted(verifier, bot, dataset, report):
    # Root goal declares its full resource scope (including sub-goal resources).
    # Attenuation requires subgoal resources ⊆ parent's declared resources.
    sub = GoalNode("write-report", bot, required_resources_write=[report])
    root = GoalNode(
        "produce-report", bot,
        required_resources_read=[dataset],
        required_resources_write=[report],
        subgoals=[sub],
    )
    result = verify_goal_tree(root, verifier)
    assert result.fully_permitted
    assert len(result.subgoal_results) == 1
    assert result.subgoal_results[0].fully_permitted


def test_goal_tree_attenuation_blocks_excess_resources(verifier, bot, dataset, report):
    """Subgoal requires a resource its parent doesn't authorize — attenuation violation."""
    sub = GoalNode("sub-with-extra", bot, required_resources_write=[report])
    root = GoalNode(
        "root-read-only", bot,
        required_resources_read=[dataset],
        subgoals=[sub],
    )
    result = verify_goal_tree(root, verifier)
    assert not result.fully_permitted
    sub_result = result.subgoal_results[0]
    assert not sub_result.result.permitted
    assert "attenuation" in sub_result.result.violations[0].lower()


def test_goal_verification_result_summary_permitted(verifier, bot, dataset):
    goal = GoalNode("g", bot, required_resources_read=[dataset])
    result = verify_goal_tree(goal, verifier)
    summary = result.summary()
    assert "PERMITTED" in summary


def test_goal_verification_result_summary_blocked(verifier, bot):
    unowned = Resource("x", ResourceType.FILE)
    goal = GoalNode("g", bot, required_resources_write=[unowned])
    result = verify_goal_tree(goal, verifier)
    summary = result.summary()
    assert "BLOCKED" in summary
    assert "g" in summary
