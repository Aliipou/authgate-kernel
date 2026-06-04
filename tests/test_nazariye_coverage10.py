"""
Coverage tests (batch 10) added on the `nazariye-azadi` branch.

Targets the LangChain/Anthropic adapter edges, the audit loader blank-line
skip, RightsClaim.covers on an invalid claim, and goal-tree violation
aggregation.
"""
from __future__ import annotations

import pytest

from authgate.adapters.anthropic import AnthropicKernelAdapter
from authgate.adapters.langchain import FreedomTool
from authgate.kernel.audit import AuditLog
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.goals import GoalVerificationResult
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


def _res(name="doc"):
    return Resource(name, ResourceType.FILE)


# --------------------------------------------------------------------------- #
# adapters/langchain.py
# --------------------------------------------------------------------------- #

def test_freedom_tool_without_verifier_is_noop():
    # Subclassing triggers __init_subclass__; langchain_core is absent here so
    # the ImportError branch (lines 148-149) runs. _verify with no verifier
    # early-returns (line 114).
    class MyTool(FreedomTool):
        name = "t"

        def _run(self, x):
            return x * 2

    tool = MyTool()
    assert tool.run(5) == 10


# --------------------------------------------------------------------------- #
# adapters/anthropic.py
# --------------------------------------------------------------------------- #

class _Block:
    type = "tool_use"

    def __init__(self, name, id):
        self.name = name
        self.id = id
        self.input = {}


def test_anthropic_check_block_blocks_unauthorized():
    reg = OwnershipRegistry()
    bot = _machine()
    reg.register_machine(bot, _human())
    adapter = AnthropicKernelAdapter(
        verifier=FreedomVerifier(reg),
        agent=bot,
        resource_map={"write_file": ([], [_res("secret")])},  # bot holds no claim
    )
    with pytest.raises(PermissionError):  # line 71
        adapter.check_block(_Block("write_file", "blk-1"))


# --------------------------------------------------------------------------- #
# kernel/audit.py — loader skips blank lines
# --------------------------------------------------------------------------- #

def test_audit_load_from_file_skips_blank_lines(tmp_path):
    logfile = tmp_path / "log.jsonl"
    log = AuditLog(path=str(logfile))
    log.record(VerificationResult("a1", True, (), (), 1.0, False))
    # Inject a blank line into the JSONL file
    content = logfile.read_text(encoding="utf-8")
    logfile.write_text(content + "\n\n", encoding="utf-8")

    loaded = AuditLog.load_from_file(str(logfile))  # line 242: blank line skipped
    assert len(loaded) == 1


# --------------------------------------------------------------------------- #
# kernel/entities.py — covers() on an invalid (zero-confidence) claim
# --------------------------------------------------------------------------- #

def test_rights_claim_covers_false_when_invalid():
    claim = RightsClaim(_human(), _res(), can_read=True, confidence=0.0)
    assert claim.is_valid() is False
    assert claim.covers("read") is False  # line 169


# --------------------------------------------------------------------------- #
# kernel/goals.py — all_violations aggregates subgoal violations
# --------------------------------------------------------------------------- #

def test_goal_all_violations_includes_subgoals():
    child = GoalVerificationResult(
        goal_id="child",
        result=VerificationResult("child", False, ("subgoal denied",), (), 0.0, False),
        subgoal_results=(),
    )
    parent = GoalVerificationResult(
        goal_id="parent",
        result=VerificationResult("parent", True, (), (), 1.0, False),
        subgoal_results=(child,),
    )
    violations = parent.all_violations  # line 82 extends with child's violations
    assert ("child", "subgoal denied") in violations
    assert parent.fully_permitted is False
