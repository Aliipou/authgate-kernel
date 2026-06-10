"""Unit tests for authgate.runtime.planner — MockPlanner rules and ScriptedPlanner."""
from __future__ import annotations

import pytest

from authgate.runtime.planner import MockPlanner, PlanStep, ScriptedPlanner


@pytest.fixture
def planner():
    return MockPlanner()


def _tools(steps):
    return [s.tool for s in steps]


# --- determinism -----------------------------------------------------------

def test_mock_planner_is_deterministic(planner):
    intent = "calculate 2 + 2 and search authgate and read notes.txt"
    plans = [planner.plan(intent) for _ in range(3)]
    assert plans[0] == plans[1] == plans[2]


# --- arithmetic rule -------------------------------------------------------

def test_arithmetic_keyword_triggers_calculator(planner):
    steps = planner.plan("please compute the result")
    assert _tools(steps) == ["calculator"]


def test_bare_expression_triggers_calculator_and_extracts_it(planner):
    steps = planner.plan("2 + 3 * 4")
    assert steps[0].tool == "calculator"
    assert steps[0].args == {"expression": "2 + 3 * 4"}


def test_arithmetic_keyword_with_expression_extracts_expression(planner):
    steps = planner.plan("calculate 5 * 5")
    assert steps[0].args == {"expression": "5 * 5"}


def test_arithmetic_keyword_without_expression_falls_back_to_zero(planner):
    steps = planner.plan("compute the sum")
    assert steps[0].tool == "calculator"
    assert steps[0].args == {"expression": "0"}


# --- search rule -----------------------------------------------------------

@pytest.mark.parametrize("word", ["search", "find", "look up", "lookup", "what is"])
def test_search_keywords_trigger_web_search(planner, word):
    steps = planner.plan(f"{word} something about cats")
    assert "web_search" in _tools(steps)


def test_search_query_preserves_original_casing(planner):
    intent = "Find AuthGate Documentation"
    steps = planner.plan(intent)
    search = next(s for s in steps if s.tool == "web_search")
    assert search.args == {"query": "Find AuthGate Documentation"}


def test_search_query_is_stripped(planner):
    steps = planner.plan("   search for kernels   ")
    search = next(s for s in steps if s.tool == "web_search")
    assert search.args == {"query": "search for kernels"}


# --- file rule -------------------------------------------------------------

@pytest.mark.parametrize("word", ["read", "open", "file", "cat "])
def test_file_keywords_trigger_file_read(planner, word):
    steps = planner.plan(f"{word} something")
    assert "file_read" in _tools(steps)


def test_filename_extraction_picks_dotted_token(planner):
    steps = planner.plan("read notes.txt now")
    fr = next(s for s in steps if s.tool == "file_read")
    assert fr.args == {"filename": "notes.txt"}


def test_filename_extraction_picks_slashed_token(planner):
    steps = planner.plan("cat data/log.csv")
    fr = next(s for s in steps if s.tool == "file_read")
    assert fr.args == {"filename": "data/log.csv"}


def test_filename_extraction_falls_back_when_no_filename_token(planner):
    steps = planner.plan("open the file")
    fr = next(s for s in steps if s.tool == "file_read")
    assert fr.args == {"filename": "notes.txt"}


# --- multi-rule ordering ---------------------------------------------------

def test_multi_rule_intent_orders_arith_search_file(planner):
    intent = "compute 5*5 and search authgate and read a.txt"
    steps = planner.plan(intent)
    assert _tools(steps) == ["calculator", "web_search", "file_read"]


def test_multi_rule_intent_args_are_correct(planner):
    intent = "compute 5*5 and search authgate and read a.txt"
    steps = planner.plan(intent)
    assert steps[0].args == {"expression": "5*5"}
    assert steps[1].args == {"query": intent}
    assert steps[2].args == {"filename": "a.txt"}


# --- no match --------------------------------------------------------------

def test_no_match_yields_empty_plan(planner):
    assert planner.plan("hello world good morning") == []


# --- ScriptedPlanner -------------------------------------------------------

def test_scripted_planner_returns_equal_but_distinct_list():
    steps = [PlanStep("calculator", {"expression": "1 + 1"})]
    sp = ScriptedPlanner(steps)
    out = sp.plan("ignored intent")
    assert out == steps
    assert out is not steps


def test_scripted_planner_ignores_intent():
    sp = ScriptedPlanner([PlanStep("web_search", {"query": "x"})])
    assert sp.plan("intent A") == sp.plan("completely different intent B")


def test_scripted_planner_mutating_returned_list_does_not_affect_source():
    steps = [PlanStep("calculator", {"expression": "1 + 1"})]
    sp = ScriptedPlanner(steps)
    out = sp.plan("x")
    out.append(PlanStep("web_search", {"query": "extra"}))
    assert len(sp.plan("x")) == 1


def test_scripted_planner_preserves_exact_step_sequence():
    plan = [
        PlanStep("calculator", {"expression": "2+2"}),
        PlanStep("file_read", {"filename": "a.txt"}),
        PlanStep("web_search", {"query": "authgate"}),
    ]
    sp = ScriptedPlanner(plan)
    assert sp.plan("anything") == plan
