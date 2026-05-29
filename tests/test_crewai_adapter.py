"""
CrewAI adapter tests — Phase 1, O3.

Tests CrewAIKernelGate: decorator pattern, task-level guard, crew-level middleware.
No CrewAI dependency required — adapter uses duck typing.
"""
import pytest

from authgate.adapters.crewai import CrewAIKernelGate, KernelDeniedError
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import FreedomVerifier


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def setup():
    human = Entity("alice", AgentType.HUMAN)
    bot = Entity("crewai-bot", AgentType.MACHINE)
    report = Resource("report", ResourceType.FILE, scope="/reports/")
    dataset = Resource("dataset", ResourceType.DATASET, scope="/data/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, human)
    reg.add_claim(RightsClaim(bot, report, can_read=True, can_write=True))
    reg.add_claim(RightsClaim(bot, dataset, can_read=True))
    frozen = reg.freeze()
    verifier = FreedomVerifier(frozen)
    gate = CrewAIKernelGate(verifier, bot)
    return gate, bot, report, dataset


@pytest.fixture
def restricted_setup():
    """Bot has no write claim — only read."""
    human = Entity("alice", AgentType.HUMAN)
    bot = Entity("crewai-bot", AgentType.MACHINE)
    report = Resource("report", ResourceType.FILE, scope="/reports/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, human)
    reg.add_claim(RightsClaim(bot, report, can_read=True, can_write=False))
    frozen = reg.freeze()
    verifier = FreedomVerifier(frozen)
    gate = CrewAIKernelGate(verifier, bot)
    return gate, bot, report


# ── Decorator pattern ─────────────────────────────────────────────────────────

class TestDecoratorPattern:
    def test_permitted_task_executes(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_write=[report])
        def write_report(content: str) -> str:
            return f"written:{content}"

        result = write_report(content="hello")
        assert result == "written:hello"

    def test_denied_task_raises_kernel_denied_error(self, restricted_setup):
        gate, bot, report = restricted_setup

        @gate.task(resources_write=[report])
        def write_report(content: str) -> str:
            return "should not reach here"

        with pytest.raises(KernelDeniedError) as exc_info:
            write_report(content="hello")
        assert "blocked" in str(exc_info.value).lower() or "BLOCKED" in str(exc_info.value)

    def test_read_task_permitted(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset])
        def read_dataset() -> str:
            return "data"

        assert read_dataset() == "data"

    def test_kernel_denied_error_is_authgate_error(self, restricted_setup):
        gate, bot, report = restricted_setup

        @gate.task(resources_write=[report])
        def write_report() -> str:
            return "x"

        from authgate.errors import AuthgateError
        with pytest.raises(AuthgateError):
            write_report()

    def test_decorated_function_is_marked(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset])
        def my_task() -> None:
            pass

        assert getattr(my_task, "_kernel_gated", False) is True

    def test_original_function_name_preserved(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset])
        def my_special_task() -> None:
            pass

        assert my_special_task.__name__ == "my_special_task"

    def test_sovereignty_flag_always_denied(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset], increases_machine_sovereignty=True)
        def suspicious_task() -> str:
            return "sovereignty gained"

        with pytest.raises(KernelDeniedError):
            suspicious_task()

    def test_coercion_flag_always_denied(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset], coerces=True)
        def coercive_task() -> str:
            return "coerced"

        with pytest.raises(KernelDeniedError):
            coercive_task()

    def test_permitted_task_returns_original_value(self, setup):
        gate, bot, report, dataset = setup

        @gate.task(resources_read=[dataset])
        def task_with_value() -> dict:
            return {"key": "value", "count": 42}

        result = task_with_value()
        assert result == {"key": "value", "count": 42}

    def test_permitted_task_passes_args_correctly(self, setup):
        gate, bot, report, dataset = setup
        captured = []

        @gate.task(resources_read=[dataset])
        def task_with_args(a: int, b: str, c: float = 0.5) -> str:
            captured.extend([a, b, c])
            return "ok"

        result = task_with_args(1, "hello", c=0.9)
        assert result == "ok"
        assert captured == [1, "hello", 0.9]


# ── verify() method ───────────────────────────────────────────────────────────

class TestVerifyMethod:
    def test_verify_returns_permitted_result(self, setup):
        gate, bot, report, dataset = setup
        result = gate.verify(
            action_id="test-read",
            task_description="read dataset",
            resources_read=[dataset],
        )
        assert result.permitted

    def test_verify_returns_denied_result_without_claim(self, restricted_setup):
        gate, bot, report = restricted_setup
        result = gate.verify(
            action_id="test-write",
            task_description="write report",
            resources_write=[report],
        )
        assert not result.permitted

    def test_verify_does_not_raise_on_deny(self, restricted_setup):
        gate, bot, report = restricted_setup
        result = gate.verify(
            action_id="test",
            resources_write=[report],
        )
        # Does not raise — caller decides
        assert result is not None


# ── guard_task pattern ────────────────────────────────────────────────────────

class _MockTask:
    """Minimal duck-typed CrewAI Task for testing."""
    def __init__(self, description: str = "mock task"):
        self.description = description
        self._executed = False
        self._execute_called = False

    def execute(self, *args, **kwargs):
        self._executed = True
        self._execute_called = True
        return "task-result"


class TestGuardTask:
    def test_guard_task_permits_and_executes(self, setup):
        gate, bot, report, dataset = setup
        task = _MockTask("read dataset task")
        gate.guard_task(task, resources_read=[dataset])
        result = task.execute()
        assert result == "task-result"
        assert task._executed is True

    def test_guard_task_denied_raises(self, restricted_setup):
        gate, bot, report = restricted_setup
        task = _MockTask("write report task")
        gate.guard_task(task, resources_write=[report])
        with pytest.raises(KernelDeniedError):
            task.execute()

    def test_guard_task_sets_gate_attribute(self, setup):
        gate, bot, report, dataset = setup
        task = _MockTask()
        gate.guard_task(task, resources_read=[dataset])
        assert hasattr(task, "_kernel_gate")
        assert task._kernel_gate is gate

    def test_guard_task_records_resources(self, setup):
        gate, bot, report, dataset = setup
        task = _MockTask()
        gate.guard_task(task, resources_read=[dataset], resources_write=[report])
        assert dataset in task._kernel_gate_resources["read"]
        assert report in task._kernel_gate_resources["write"]


# ── wrap_crew pattern ─────────────────────────────────────────────────────────

class _MockCrew:
    def __init__(self, tasks):
        self.tasks = tasks


class TestWrapCrew:
    def test_wrap_crew_guards_all_tasks(self, setup):
        gate, bot, report, dataset = setup
        task1 = _MockTask("task-1")
        task2 = _MockTask("task-2")
        crew = _MockCrew([task1, task2])
        gate.wrap_crew(crew, task_resource_map={
            task1: {"resources_read": [dataset]},
            task2: {"resources_write": [report]},
        })
        assert hasattr(task1, "_kernel_gate")
        assert hasattr(task2, "_kernel_gate")

    def test_wrap_crew_permits_execution(self, setup):
        gate, bot, report, dataset = setup
        task1 = _MockTask("read task")
        crew = _MockCrew([task1])
        gate.wrap_crew(crew, task_resource_map={
            task1: {"resources_read": [dataset]},
        })
        result = task1.execute()
        assert result == "task-result"

    def test_wrap_crew_denies_unauthorized_task(self, restricted_setup):
        gate, bot, report = restricted_setup
        task = _MockTask("write task")
        crew = _MockCrew([task])
        gate.wrap_crew(crew, task_resource_map={
            task: {"resources_write": [report]},
        })
        with pytest.raises(KernelDeniedError):
            task.execute()

    def test_wrap_crew_returns_crew(self, setup):
        gate, bot, report, dataset = setup
        crew = _MockCrew([])
        returned = gate.wrap_crew(crew)
        assert returned is crew
