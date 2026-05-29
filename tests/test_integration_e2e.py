"""
End-to-end integration test — the deployment answer.

Tests the full chain:
  Tool call → FreedomVerifier.verify() → execution (or block) → AuditLog entry

This test answers "does it deploy?" with assertions, not print statements.
No API key required. No network calls.

Chain under test:
  Human registers machine → machine gets scoped capabilities →
  tool calls verified before execution → audit log populated →
  chain integrity verified → revocation immediately visible
"""
from __future__ import annotations

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog
from authgate.adapters.openai_agents import OpenAIKernelMiddleware


# ─── Shared setup ─────────────────────────────────────────────────────────────

def _build_env():
    alice = Entity("Alice", AgentType.HUMAN)
    bot = Entity("ResearchBot", AgentType.MACHINE)

    codebase = Resource("codebase", ResourceType.FILE, scope="/repos/")
    secrets  = Resource("secrets",  ResourceType.FILE, scope="/secrets/")
    scratch  = Resource("scratch",  ResourceType.FILE, scope="/tmp/")

    registry = OwnershipRegistry()
    registry.register_machine(bot, alice)
    registry.add_claim(RightsClaim(alice, codebase, can_read=True, can_delegate=True))
    registry.add_claim(RightsClaim(alice, scratch,  can_read=True, can_write=True, can_delegate=True))
    registry.delegate(RightsClaim(bot, codebase, can_read=True),              delegated_by=alice)
    registry.delegate(RightsClaim(bot, scratch,  can_read=True, can_write=True), delegated_by=alice)
    # secrets: alice owns it, bot has NO delegation

    return alice, bot, codebase, secrets, scratch, registry


# ═══════════════════════════════════════════════════════════════════════════
# 1. Core gate: permit and deny
# ═══════════════════════════════════════════════════════════════════════════

class TestGatePermitDeny:

    def test_permitted_read_succeeds(self):
        _, bot, codebase, _, _, registry = _build_env()
        v = FreedomVerifier(registry)
        result = v.verify(Action("read-code", actor=bot, resources_read=[codebase]))
        assert result.permitted
        assert result.violations == ()

    def test_denied_read_no_delegation(self):
        _, bot, _, secrets, _, registry = _build_env()
        v = FreedomVerifier(registry)
        result = v.verify(Action("read-secrets", actor=bot, resources_read=[secrets]))
        assert not result.permitted
        assert any("READ DENIED" in v for v in result.violations)

    def test_denied_write_read_only_claim(self):
        _, bot, codebase, _, _, registry = _build_env()
        v = FreedomVerifier(registry)
        result = v.verify(Action("write-code", actor=bot, resources_write=[codebase]))
        assert not result.permitted

    def test_sovereignty_flag_unconditional_deny(self):
        _, bot, codebase, _, _, registry = _build_env()
        v = FreedomVerifier(registry)
        result = v.verify(Action(
            "escalate", actor=bot,
            resources_read=[codebase],
            increases_machine_sovereignty=True,
        ))
        assert not result.permitted
        assert any("increases machine sovereignty" in viol for viol in result.violations)

    def test_ownerless_machine_blocked(self):
        orphan = Entity("Orphan", AgentType.MACHINE)
        registry = OwnershipRegistry()
        resource = Resource("data", ResourceType.FILE, scope="/data/")
        registry.add_claim(RightsClaim(orphan, resource, can_read=True))
        v = FreedomVerifier(registry)
        result = v.verify(Action("read", actor=orphan, resources_read=[resource]))
        assert not result.permitted
        assert any("UNOWNED_MACHINE" in viol for viol in result.violations)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Audit chain — every decision is logged, chain is tamper-evident
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditChainIntegrity:

    def test_every_verify_creates_audit_entry(self):
        _, bot, codebase, secrets, _, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, audit_log=audit)

        v.verify(Action("read-code",    actor=bot, resources_read=[codebase]))
        v.verify(Action("read-secrets", actor=bot, resources_read=[secrets]))

        assert len(audit) == 2

    def test_denied_action_also_logged(self):
        _, bot, _, secrets, _, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, audit_log=audit)
        result = v.verify(Action("read-secrets", actor=bot, resources_read=[secrets]))
        assert not result.permitted
        assert len(audit) == 1  # denied actions are logged too

    def test_audit_chain_intact_after_mixed_decisions(self):
        _, bot, codebase, secrets, scratch, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, audit_log=audit)

        v.verify(Action("r1", actor=bot, resources_read=[codebase]))
        v.verify(Action("r2", actor=bot, resources_read=[secrets]))   # denied
        v.verify(Action("w1", actor=bot, resources_write=[scratch]))
        v.verify(Action("w2", actor=bot, resources_write=[secrets]))  # denied

        assert len(audit) == 4
        assert audit.verify_chain(), "Audit chain broken after mixed permit/deny"

    def test_tampered_audit_detected(self):
        _, bot, codebase, _, _, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, audit_log=audit)

        for i in range(5):
            v.verify(Action(f"a{i}", actor=bot, resources_read=[codebase]))

        assert audit.verify_chain()

        with audit._lock:
            audit._records[2]["permitted"] = not audit._records[2]["permitted"]

        assert not audit.verify_chain(), "Tampered entry not detected"


# ═══════════════════════════════════════════════════════════════════════════
# 3. Revocation — live registry, immediately visible
# ═══════════════════════════════════════════════════════════════════════════

class TestRevocationImmediate:

    def test_revocation_blocks_immediately(self):
        _, bot, codebase, _, _, registry = _build_env()
        v = FreedomVerifier(registry, freeze=False)

        assert v.verify(Action("before", actor=bot, resources_read=[codebase])).permitted
        registry.revoke_all(bot.name)
        assert not v.verify(Action("after",  actor=bot, resources_read=[codebase])).permitted

    def test_frozen_verifier_unaffected_by_revocation(self):
        _, bot, codebase, _, _, registry = _build_env()
        v = FreedomVerifier(registry, freeze=True)  # snapshot taken now

        registry.revoke_all(bot.name)  # mutate original after freeze

        # Frozen verifier still uses its snapshot
        assert v.verify(Action("after", actor=bot, resources_read=[codebase])).permitted


# ═══════════════════════════════════════════════════════════════════════════
# 4. OpenAI adapter — decorator gate
# ═══════════════════════════════════════════════════════════════════════════

class TestOpenAIAdapterGate:

    def _setup(self):
        _, bot, codebase, secrets, scratch, registry = _build_env()
        v = FreedomVerifier(registry)
        mw = OpenAIKernelMiddleware(v, agent=bot)
        return mw, bot, codebase, secrets, scratch

    def test_permitted_tool_executes(self):
        mw, _, codebase, _, _ = self._setup()

        @mw.tool(resources_read=[codebase])
        def read_file(path: str) -> str:
            return f"contents:{path}"

        result = read_file("main.py")
        assert result == "contents:main.py"

    def test_denied_tool_raises_before_execution(self):
        mw, _, _, secrets, _ = self._setup()
        executed = []

        @mw.tool(resources_write=[secrets])
        def write_secrets(data: str) -> str:
            executed.append(data)  # must never run
            return "written"

        with pytest.raises(PermissionError):
            write_secrets("exfiltrated-data")

        assert not executed, "Tool body executed despite denial — gate failed"

    def test_manual_check_permit(self):
        mw, _, codebase, _, _ = self._setup()
        result = mw.check("call-001", tool_name="read", resources_read=[codebase])
        assert result.permitted

    def test_manual_check_deny(self):
        mw, _, _, secrets, _ = self._setup()
        result = mw.check("call-002", tool_name="steal", resources_read=[secrets])
        assert not result.permitted

    def test_sovereignty_flag_blocks_via_adapter(self):
        mw, bot, codebase, _, _ = self._setup()
        result = mw.check(
            "call-003",
            tool_name="escalate",
            resources_read=[codebase],
            increases_machine_sovereignty=True,
        )
        assert not result.permitted


# ═══════════════════════════════════════════════════════════════════════════
# 5. Full chain: adapter → gate → audit
# ═══════════════════════════════════════════════════════════════════════════

class TestFullChain:

    def test_permit_deny_both_in_audit(self):
        """Complete chain: tool calls → gate → audit → chain integrity."""
        _, bot, codebase, secrets, scratch, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, audit_log=audit)
        mw = OpenAIKernelMiddleware(v, agent=bot)

        @mw.tool(resources_read=[codebase])
        def read_code(path: str) -> str:
            return "ok"

        @mw.tool(resources_write=[secrets])
        def steal_secrets(data: str) -> str:
            return "stolen"  # never runs

        # Permitted call
        read_code("main.py")

        # Denied call
        with pytest.raises(PermissionError):
            steal_secrets("exfil")

        # Both are in the audit log
        assert len(audit) == 2
        entries = audit.entries()
        assert entries[0]["permitted"] is True
        assert entries[1]["permitted"] is False

        # Chain is intact
        assert audit.verify_chain()

    def test_revoke_then_tool_blocked_with_audit(self):
        """Revocation → subsequent tool call denied → logged."""
        _, bot, codebase, _, _, registry = _build_env()
        audit = AuditLog()
        v = FreedomVerifier(registry, freeze=False, audit_log=audit)
        mw = OpenAIKernelMiddleware(v, agent=bot)

        @mw.tool(resources_read=[codebase])
        def read_code(path: str) -> str:
            return "ok"

        # Before revocation: permitted
        read_code("a.py")
        assert audit.entries()[0]["permitted"] is True

        # Revoke
        registry.revoke_all(bot.name)

        # After revocation: denied
        with pytest.raises(PermissionError):
            read_code("b.py")

        assert len(audit) == 2
        assert audit.entries()[1]["permitted"] is False
        assert audit.verify_chain()
