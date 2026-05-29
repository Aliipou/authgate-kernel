"""Tests for DSPy adapter — Phase 1/O3 (remaining)."""
import pytest

from authgate.adapters.dspy_adapter import DSPyKernelGate, KernelDeniedError
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource() -> Resource:
    return Resource("llm", ResourceType.MODEL_WEIGHTS, scope="/models/")


def _setup(allowed: bool = True):
    alice = _human()
    bot = _machine()
    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    if allowed:
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True))
    verifier = FreedomVerifier(reg, freeze=True)
    gate = DSPyKernelGate(verifier, actor=bot, resource=_resource())
    return gate, bot, alice


class _FakeModule:
    """Minimal duck-type DSPy Module."""
    def __init__(self, return_val="result"):
        self.return_val = return_val

    def forward(self, question: str = "") -> str:
        return self.return_val

    def __call__(self, question: str = "") -> str:
        return self.return_val


class TestDSPyKernelGate:
    def test_permitted_call_executes(self):
        gate, _, _ = _setup(allowed=True)
        module = _FakeModule("answer")
        guarded = gate.guard(module)
        result = guarded(question="What is 2+2?")
        assert result == "answer"

    def test_permitted_forward_executes(self):
        gate, _, _ = _setup(allowed=True)
        module = _FakeModule("fwd-result")
        guarded = gate.guard(module)
        result = guarded.forward(question="x")
        assert result == "fwd-result"

    def test_blocked_actor_raises(self):
        # Bot with sovereignty flag → denied
        alice = _human()
        bot = _machine()
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True))
        verifier = FreedomVerifier(reg, freeze=True)
        # Create a gate but call verify with a blocked action — test by overriding
        gate = DSPyKernelGate(verifier, actor=bot, resource=_resource())
        module = _FakeModule()
        guarded = gate.guard(module)
        # Directly test verify_invocation with a blocked actor (no claim in fresh reg)
        reg2 = OwnershipRegistry()
        reg2.register_machine(bot, alice)
        # No claim → ownerless-resource → blocked
        verifier2 = FreedomVerifier(reg2, freeze=True)
        gate2 = DSPyKernelGate(verifier2, actor=bot, resource=_resource())
        guarded2 = gate2.guard(module)
        with pytest.raises(KernelDeniedError):
            guarded2(question="x")

    def test_attribute_delegation(self):
        gate, _, _ = _setup(allowed=True)
        module = _FakeModule()
        module.custom_attr = "hello"
        guarded = gate.guard(module)
        assert guarded.custom_attr == "hello"

    def test_setattr_delegated(self):
        gate, _, _ = _setup(allowed=True)
        module = _FakeModule()
        guarded = gate.guard(module)
        guarded.custom_attr = "world"
        assert module.custom_attr == "world"

    def test_gate_custom_prefix(self):
        alice = _human()
        bot = _machine()
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(bot, _resource(), can_read=True))
        verifier = FreedomVerifier(reg, freeze=True)
        gate = DSPyKernelGate(verifier, actor=bot, resource=_resource(), action_prefix="my-prefix")
        # Should not raise (prefix affects action_id only)
        gate.verify_invocation("test-action")

    def test_kernel_denied_error_message(self):
        alice = _human()
        bot = _machine()
        reg = OwnershipRegistry()
        reg.register_machine(bot, alice)
        # No model claim → will fail on resource check
        verifier = FreedomVerifier(reg, freeze=True)
        gate = DSPyKernelGate(verifier, actor=bot, resource=_resource())
        with pytest.raises(KernelDeniedError, match="denied by authgate"):
            gate.verify_invocation("bad-op")
