"""Integration tests for authgate.runtime.agent — AgentRuntime + build_runtime."""
from __future__ import annotations

import pytest

from authgate.kernel.audit import AuditLog
from authgate.runtime.agent import build_runtime
from authgate.runtime.planner import MockPlanner, PlanStep, ScriptedPlanner


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "a.txt").write_text("FILE CONTENT", encoding="utf-8")
    return tmp_path


# --- granted tool executes -------------------------------------------------

def test_granted_calculator_permits_and_produces_output(sandbox):
    planner = ScriptedPlanner([PlanStep("calculator", {"expression": "2 + 2"})])
    runtime, _ = build_runtime(planner, sandbox)
    result = runtime.run("calc")

    assert result.permitted_count == 1
    assert result.denied_count == 0
    assert result.outputs() == ["4"]
    assert result.stopped_early is False


def test_granted_execution_records_permit_entry_in_run_log(sandbox):
    planner = ScriptedPlanner([PlanStep("calculator", {"expression": "2 + 2"})])
    runtime, _ = build_runtime(planner, sandbox)
    runtime.run("calc")

    entries = runtime.run_log.entries()
    assert len(entries) == 1
    assert entries[0]["decision"] == "permit"
    assert entries[0]["output"] == "4"
    assert entries[0]["tool"] == "calculator"


def test_granted_file_read_returns_real_content(sandbox):
    planner = ScriptedPlanner([PlanStep("file_read", {"filename": "a.txt"})])
    runtime, _ = build_runtime(planner, sandbox)
    result = runtime.run("read a.txt")
    assert result.outputs() == ["FILE CONTENT"]


# --- ungranted tool denied; tool body never runs ---------------------------

def test_ungranted_tool_is_denied_and_body_never_runs(sandbox):
    # file_read NOT granted -> gate denies before the tool fn executes.
    planner = ScriptedPlanner([PlanStep("file_read", {"filename": "a.txt"})])
    runtime, _ = build_runtime(planner, sandbox, granted_tools=["calculator"])
    result = runtime.run("read a.txt")

    outcome = result.outcomes[0]
    assert outcome.permitted is False
    assert outcome.result.output is None  # tool body never produced output
    assert "capability" in outcome.result.denied_reason
    assert result.denied_count == 1


def test_ungranted_denial_logged_with_no_output(sandbox):
    planner = ScriptedPlanner([PlanStep("file_read", {"filename": "a.txt"})])
    runtime, _ = build_runtime(planner, sandbox, granted_tools=["calculator"])
    runtime.run("x")
    entry = runtime.run_log.entries()[0]
    assert entry["decision"] == "deny"
    assert entry["output"] is None


# --- denied step stops execution -------------------------------------------

def test_denied_step_halts_remaining_plan(sandbox):
    plan = [
        PlanStep("calculator", {"expression": "1 + 1"}),  # granted
        PlanStep("file_read", {"filename": "a.txt"}),       # NOT granted -> deny
        PlanStep("web_search", {"query": "authgate"}),      # must never run
    ]
    runtime, _ = build_runtime(
        ScriptedPlanner(plan), sandbox,
        granted_tools=["calculator", "web_search"],
    )
    result = runtime.run("multi")

    assert len(result.outcomes) == 2  # third step never executed
    assert result.stopped_early is True
    assert result.permitted_count == 1
    assert result.denied_count == 1
    # web_search never appears in the run log
    logged_tools = [e["tool"] for e in runtime.run_log.entries()]
    assert "web_search" not in logged_tools


def test_denied_last_step_does_not_set_stopped_early(sandbox):
    plan = [
        PlanStep("calculator", {"expression": "1 + 1"}),  # granted
        PlanStep("file_read", {"filename": "a.txt"}),       # denied, but is last
    ]
    runtime, _ = build_runtime(
        ScriptedPlanner(plan), sandbox, granted_tools=["calculator"]
    )
    result = runtime.run("two")
    assert len(result.outcomes) == 2
    assert result.stopped_early is False  # nothing after the denial


# --- reproducibility -------------------------------------------------------

def test_two_fresh_runtimes_produce_equal_outputs(sandbox):
    intent = "calculate 2 + 2 and search authgate"
    runtime_a, _ = build_runtime(MockPlanner(), sandbox)
    runtime_b, _ = build_runtime(MockPlanner(), sandbox)
    assert runtime_a.run(intent).outputs() == runtime_b.run(intent).outputs()


def test_repeated_run_same_runtime_is_reproducible(sandbox):
    intent = "search authgate"
    runtime, _ = build_runtime(MockPlanner(), sandbox)
    assert runtime.run(intent).outputs() == runtime.run(intent).outputs()


# --- unknown tool ----------------------------------------------------------

def test_unknown_tool_is_denied_without_crash(sandbox):
    planner = ScriptedPlanner([PlanStep("nonexistent_tool", {})])
    runtime, _ = build_runtime(planner, sandbox)
    result = runtime.run("x")

    outcome = result.outcomes[0]
    assert outcome.permitted is False
    assert "unknown tool" in outcome.result.denied_reason
    assert result.denied_count == 1


# --- revocation ------------------------------------------------------------

def test_revocation_flips_permit_to_deny(sandbox):
    planner = ScriptedPlanner([PlanStep("calculator", {"expression": "3 + 3"})])
    runtime, registry = build_runtime(planner, sandbox, freeze=False)

    first = runtime.run("calc")
    assert first.outcomes[0].permitted is True

    registry.revoke_all("agent-1")

    second = runtime.run("calc")
    assert second.outcomes[0].permitted is False


# --- audit -----------------------------------------------------------------

def test_audit_chain_is_valid_after_run(sandbox):
    audit = AuditLog()
    planner = MockPlanner()
    runtime, _ = build_runtime(planner, sandbox, audit_log=audit)
    runtime.run("calculate 2 + 2 and search authgate")

    assert len(audit) > 0
    assert audit.verify_chain() is True


def test_audit_records_one_entry_per_step(sandbox):
    audit = AuditLog()
    plan = [
        PlanStep("calculator", {"expression": "1 + 1"}),
        PlanStep("web_search", {"query": "authgate"}),
    ]
    runtime, _ = build_runtime(ScriptedPlanner(plan), sandbox, audit_log=audit)
    runtime.run("two steps")
    assert len(audit) == 2
    assert audit.verify_chain() is True
