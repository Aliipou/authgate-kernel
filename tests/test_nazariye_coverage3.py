"""
Coverage tests (batch 3) added on the `nazariye-azadi` branch.

Targets the CallGate execution pipeline, the registry revocation/expiry and
delegation-chain attenuation paths, and the verifier's tracer + contested-write
+ summary branches.
"""
from __future__ import annotations

import time

from authgate.kernel.call_gate import CallGate, GateResult
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.tracing import TraceCollector
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


def _res(name, rtype=ResourceType.FILE, scope=""):
    return Resource(name, rtype, scope=scope)


# --------------------------------------------------------------------------- #
# call_gate.py
# --------------------------------------------------------------------------- #

class _StubVerify:
    def __init__(self, permitted, violations=()):
        self.permitted = permitted
        self.violations = list(violations)


class _StubVerifier:
    def __init__(self, permitted, violations=()):
        self._r = _StubVerify(permitted, violations)

    def verify(self, action):
        return self._r


class _StubABI:
    def __init__(self, valid, reason=""):
        self.valid = valid
        self.reason = reason
        self.seen_rights = None

    def validate_call(self, tool_name, args, rights_held, caller_scope=""):
        self.seen_rights = rights_held
        return self  # acts as its own validation result (has .valid / .reason)


def test_gate_result_predicates():
    ok = GateResult(permitted=True, output=1, tool_name="t")
    assert ok.is_executed() is True and ok.is_denied() is False
    denied = GateResult(permitted=False, denied_reason="x", tool_name="t")
    assert denied.is_denied() is True and denied.is_executed() is False


def test_callgate_permit_executes_tool():
    gate = CallGate(_StubVerifier(True))
    tool = gate.register("echo", lambda value: value)
    # both call forms
    r1 = gate.execute(_dummy_action(), "echo", {"value": 7})
    assert r1.permitted and r1.output == 7
    r2 = tool(_dummy_action(), value=9)
    assert r2.output == 9
    assert "echo" in gate.registered_tools()
    assert repr(tool).startswith("GatedTool(") and tool.name == "echo"


def test_callgate_denied_by_verifier():
    gate = CallGate(_StubVerifier(False, ["FORBIDDEN (x)"]))
    gate.register("t", lambda: 1)
    r = gate.execute(_dummy_action(), "t")
    assert r.permitted is False
    assert "capability gate denied" in r.denied_reason


def test_callgate_denied_with_no_violations_message():
    gate = CallGate(_StubVerifier(False, []))
    gate.register("t", lambda: 1)
    r = gate.execute(_dummy_action(), "t")
    assert "denied" in r.denied_reason


def test_callgate_abi_rejects():
    gate = CallGate(_StubVerifier(True), abi_registry=_StubABI(valid=False, reason="missing right"))
    gate.register("t", lambda: 1)
    r = gate.execute(_dummy_action(), "t")
    assert r.permitted is False
    assert "ABI validation failed" in r.denied_reason


def test_callgate_abi_pass_extracts_rights():
    abi = _StubABI(valid=True)
    gate = CallGate(_StubVerifier(True), abi_registry=abi)
    gate.register("t", lambda **k: "done")
    action = Action(
        "a1", _machine(),
        resources_read=[_res("net", ResourceType.NETWORK_ENDPOINT)],
        resources_write=[_res("w", ResourceType.MODEL_WEIGHTS)],
        resources_delegate=[_res("d")],
    )
    r = gate.execute(action, "t")
    assert r.permitted is True
    # _extract_rights walked read/write/delegate + the typed-resource branches
    assert {"read", "write", "delegate", "network", "model_invoke"} <= abi.seen_rights


def test_callgate_unregistered_tool_raises_keyerror():
    gate = CallGate(_StubVerifier(True))
    try:
        gate.execute(_dummy_action(), "ghost")
        assert False, "expected KeyError"
    except KeyError as e:
        assert "ghost" in str(e)


def test_callgate_tool_exception_becomes_denied():
    gate = CallGate(_StubVerifier(True))

    def boom():
        raise RuntimeError("kaboom")

    gate.register("boom", boom)
    r = gate.execute(_dummy_action(), "boom")
    assert r.permitted is False
    assert "tool execution error" in r.denied_reason


def _dummy_action():
    return Action("dummy", _machine())


# --------------------------------------------------------------------------- #
# registry.py — revoke_on_resource, expire_stale, cascading, chain attenuation
# --------------------------------------------------------------------------- #

def test_revoke_on_resource():
    reg = OwnershipRegistry()
    alice = _human()
    a = _res("a")
    b = _res("b")
    reg.add_claim(RightsClaim(alice, a))
    reg.add_claim(RightsClaim(alice, b))
    removed = reg.revoke_on_resource("Alice", "a")
    assert removed == 1
    assert reg.can_act(alice, a, "read")[0] is False
    assert reg.can_act(alice, b, "read")[0] is True


def test_expire_stale_removes_expired():
    reg = OwnershipRegistry()
    alice = _human()
    res = _res("doc")
    reg.add_claim(RightsClaim(alice, res, expires_at=time.time() - 1))  # already expired
    reg.add_claim(RightsClaim(alice, _res("live"), expires_at=time.time() + 1000))
    removed = reg.expire_stale()
    assert removed == 1


def test_revoke_cascading_root_claim():
    reg = OwnershipRegistry()
    alice = _human()
    bot = _machine()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, _res("root"), can_delegate=True))  # delegated_by None -> 405
    total = reg.revoke_cascading("Alice")
    assert total >= 1


def test_delegation_chain_attenuation_read_and_confidence():
    reg = OwnershipRegistry()
    alice = _human()
    bot = _machine()
    res = _res("doc")

    # Parent grants delegate but NOT read; child claims read -> chain invalid (line 281)
    reg.add_claim(RightsClaim(alice, res, can_read=False, can_write=True, can_delegate=True))
    child_read = RightsClaim(bot, res, can_read=True, can_write=False)
    child_read.delegated_by = alice
    reg.add_claim(child_read)
    assert reg.can_act(bot, res, "read")[0] is False

    # Parent confidence 0.5, child confidence 0.9 -> anti-monotonicity fail (line 289)
    reg2 = OwnershipRegistry()
    res2 = _res("ledger")
    reg2.add_claim(RightsClaim(alice, res2, can_read=True, can_delegate=True, confidence=0.5))
    child_hi = RightsClaim(bot, res2, can_read=True, confidence=0.9)
    child_hi.delegated_by = alice
    reg2.add_claim(child_hi)
    assert reg2.can_act(bot, res2, "read")[0] is False


# --------------------------------------------------------------------------- #
# verifier.py — summary arbitration line, tracer path, contested write + conflict
# --------------------------------------------------------------------------- #

def test_verification_result_summary_with_arbitration():
    r = VerificationResult(
        action_id="a1",
        permitted=False,
        violations=("READ DENIED on x",),
        warnings=("contested",),
        confidence=0.4,
        requires_human_arbitration=True,
    )
    s = r.summary()
    assert "Human arbitration required" in s
    assert "VIOLATION" in s and "WARNING" in s


def test_verifier_with_tracer_records_guards():
    reg = OwnershipRegistry()
    alice = _human()
    bot = _machine()
    reg.register_machine(bot, alice)
    res = _res("doc")
    reg.add_claim(RightsClaim(bot, res, can_read=True))
    tracer = TraceCollector()
    verifier = FreedomVerifier(reg, tracer=tracer)
    result = verifier.verify(Action("a", bot, resources_read=[res]))
    assert result.permitted is True
    trace = tracer.last()
    assert trace is not None and len(trace.guards) >= 1


def test_verifier_contested_write_requires_arbitration():
    reg = OwnershipRegistry()
    alice = _human()
    bob = _human("Bob")
    bot = _machine()
    reg.register_machine(bot, alice)
    res = _res("shared")

    # Two human writers create a conflict on the resource
    reg.add_claim(RightsClaim(alice, res, can_write=True, confidence=1.0))
    reg.add_claim(RightsClaim(bob, res, can_write=True, confidence=1.0))
    # The acting machine holds a low-confidence write claim (contested, < 0.8)
    reg.add_claim(RightsClaim(bot, res, can_write=True, confidence=0.6))

    verifier = FreedomVerifier(reg)
    result = verifier.verify(Action("w", bot, resources_write=[res]))
    # permitted (holds a write claim) but contested -> warning + arbitration flagged
    assert result.permitted is True
    assert result.requires_human_arbitration is True
    assert any("contested" in w for w in result.warnings)
