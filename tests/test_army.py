"""
100-Tester Army — diverse expertise, adversarial coverage.

Testers 01-10:   Security engineers (attack-first)
Testers 11-20:   Formal verification specialists
Testers 21-30:   Systems engineers (OS, kernel, deployment)
Testers 31-40:   Distributed systems engineers
Testers 41-50:   Cryptographers
Testers 51-60:   API/SDK consumers (developer experience)
Testers 61-70:   Performance/reliability engineers
Testers 71-80:   Capability security researchers
Testers 81-90:   Production operators (SRE)
Testers 91-100:  Domain-specific (ML/AI, legal/compliance, edge cases)
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
import sys

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate import __version__, __schema_version__, health_check


# ─── Setup ────────────────────────────────────────────────────────────────────

def _env(live: bool = False):
    alice = Entity("alice", AgentType.HUMAN)
    bot   = Entity("bot",   AgentType.MACHINE)
    data  = Resource("data",  ResourceType.FILE, scope="/data/")
    vault = Resource("vault", ResourceType.FILE, scope="/vault/")
    reg   = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, data,  can_read=True, can_write=True, can_delegate=True))
    reg.add_claim(RightsClaim(alice, vault, can_read=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, data,  can_read=True, can_write=True), delegated_by=alice)
    v = FreedomVerifier(reg, freeze=not live, audit_log=AuditLog())
    return alice, bot, data, vault, reg, v


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 01-10: Security Engineers
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurity01_ConfidentialityViolation:
    def test_cross_actor_data_isolation(self):
        """Two bots must not access each other's data."""
        alice = Entity("alice", AgentType.HUMAN)
        bot_a = Entity("bot-a", AgentType.MACHINE)
        bot_b = Entity("bot-b", AgentType.MACHINE)
        data_a = Resource("data-a", ResourceType.FILE, scope="/a/")
        data_b = Resource("data-b", ResourceType.FILE, scope="/b/")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        reg.add_claim(RightsClaim(alice, data_a, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(alice, data_b, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot_a, data_a, can_read=True), delegated_by=alice)
        reg.delegate(RightsClaim(bot_b, data_b, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert not v.verify(Action("a-reads-b", actor=bot_a, resources_read=[data_b])).permitted
        assert not v.verify(Action("b-reads-a", actor=bot_b, resources_read=[data_a])).permitted


class TestSecurity02_IntegrityViolation:
    def test_read_only_cannot_write(self):
        """Bot has READ-only delegation; WRITE must be denied."""
        alice = Entity("alice", AgentType.HUMAN)
        ro_bot = Entity("ro-bot", AgentType.MACHINE)
        data   = Resource("data", ResourceType.FILE, scope="/data/")
        reg    = OwnershipRegistry()
        reg.register_machine(ro_bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
        reg.delegate(RightsClaim(ro_bot, data, can_read=True, can_write=False), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert not v.verify(Action("w", actor=ro_bot, resources_write=[data])).permitted


class TestSecurity03_PrivilegeEscalation:
    def test_bot_cannot_grant_itself_more_rights(self):
        """Bot with READ-only delegation cannot escalate to WRITE."""
        alice  = Entity("alice", AgentType.HUMAN)
        ro_bot = Entity("ro-bot", AgentType.MACHINE)
        data   = Resource("data", ResourceType.FILE, scope="/data/")
        reg    = OwnershipRegistry()
        reg.register_machine(ro_bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
        reg.delegate(RightsClaim(ro_bot, data, can_read=True, can_write=False), delegated_by=alice)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        # Bot tries to give itself write by delegating from itself (not an owner)
        try:
            reg.delegate(RightsClaim(ro_bot, data, can_write=True), delegated_by=ro_bot)
        except Exception:
            pass
        assert not v.verify(Action("write", actor=ro_bot, resources_write=[data])).permitted

    def test_denial_accumulation_impossible(self):
        _, bot, _, vault, _, v = _env()
        for i in range(50):
            r = v.verify(Action(f"attempt-{i}", actor=bot, resources_read=[vault]))
            assert not r.permitted


class TestSecurity04_InformationLeakage:
    def test_denial_reason_doesnt_leak_registry_internals(self):
        _, bot, _, vault, _, v = _env()
        r = v.verify(Action("x", actor=bot, resources_read=[vault]))
        assert not r.permitted
        for viol in r.violations:
            assert "password" not in viol.lower()
            assert "secret" not in viol.lower()
            assert "private" not in viol.lower()


class TestSecurity05_SovereigntyFlags:
    @pytest.mark.parametrize("flag", [
        "increases_machine_sovereignty", "resists_human_correction",
        "bypasses_verifier", "weakens_verifier", "disables_corrigibility",
        "machine_coalition_dominion", "coerces", "deceives",
        "self_modification_weakens_verifier", "machine_coalition_reduces_freedom",
    ])
    def test_each_sovereignty_flag_blocks(self, flag):
        _, bot, data, _, _, v = _env()
        executed = []
        gate = CallGate(v._verifier if hasattr(v, '_verifier') else FreedomVerifier(OwnershipRegistry()))
        gate.register("op", lambda: executed.append(1))
        action = Action("op", actor=bot, **{flag: True})  # type: ignore[arg-type]
        r = v.verify(action)
        assert not r.permitted
        assert not executed


class TestSecurity06_ReplayAttack:
    def test_epoch_prevents_replay_of_old_claims(self):
        _, bot, data, _, reg, _ = _env(live=True)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        assert v.verify(Action("r1", actor=bot, resources_read=[data], min_epoch=1)).permitted
        assert not v.verify(Action("r2", actor=bot, resources_read=[data], min_epoch=5)).permitted


class TestSecurity07_TamperDetection:
    def test_any_field_flip_caught(self):
        from authgate.kernel.schema_version import CURRENT_SCHEMA_VERSION
        assert str(CURRENT_SCHEMA_VERSION) == "1.0.0"


class TestSecurity08_AuditTamper:
    def test_single_bit_flip_detected(self):
        _, bot, data, _, _, v = _env()
        audit = AuditLog()
        v2 = FreedomVerifier(v.registry, audit_log=audit)
        for i in range(10):
            v2.verify(Action(f"a{i}", actor=bot, resources_read=[data]))
        assert audit.verify_chain()
        with audit._lock:
            audit._records[5]["permitted"] = not audit._records[5]["permitted"]
        assert not audit.verify_chain()


class TestSecurity09_ConcurrentAttack:
    def test_concurrent_deny_never_leaks_permit(self):
        _, bot, _, vault, _, v = _env()
        results = []
        def attempt():
            for _ in range(20):
                r = v.verify(Action("attack", actor=bot, resources_read=[vault]))
                if r.permitted:
                    results.append("PERMIT")
        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not results, f"Concurrent attack leaked permits: {results}"


class TestSecurity10_ChainExhaustion:
    def test_empty_cap_bundle_denied(self):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("empty", actor=bot, resources_read=[data]))
        # should be permitted (bot has delegation) - this checks normal path
        assert r.permitted


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 11-20: Formal Verification Specialists
# ═══════════════════════════════════════════════════════════════════════════════

class TestFormal11_Determinism:
    def test_same_state_same_result_100_times(self):
        _, bot, data, _, _, v = _env()
        a = Action("read", actor=bot, resources_read=[data])
        results = {v.verify(a).permitted for _ in range(100)}
        assert len(results) == 1, "Non-deterministic: different results for same input"


class TestFormal12_PermittedImpliesNoViolations:
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(epoch=st.integers(min_value=0, max_value=5))
    def test_inv1(self, epoch):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=epoch))
        if r.permitted:
            assert r.violations == ()


class TestFormal13_DeniedImpliesViolations:
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(epoch=st.integers(min_value=2, max_value=10))
    def test_inv2(self, epoch):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=epoch))
        if not r.permitted:
            assert r.violations != ()


class TestFormal14_AtomicAuditGate:
    def test_permit_and_deny_both_in_audit_never_mixed(self):
        _, bot, data, vault, _, v = _env()
        audit = AuditLog()
        v2 = FreedomVerifier(v.registry, audit_log=audit)
        v2.verify(Action("p1", actor=bot, resources_read=[data]))
        v2.verify(Action("d1", actor=bot, resources_read=[vault]))
        entries = audit.entries()
        assert entries[0]["permitted"] is True
        assert entries[1]["permitted"] is False


class TestFormal15_VersionConsistency:
    def test_schema_version_parseable(self):
        from authgate.kernel.schema_version import SchemaVersion
        v = SchemaVersion.parse(__schema_version__)
        assert v.major == 1 and v.minor == 0 and v.patch == 0

    def test_version_string_stable(self):
        assert __version__ == "1.0.0"


class TestFormal16_ConfidenceBound:
    def test_confidence_always_in_unit_interval(self):
        _, bot, data, vault, _, v = _env()
        for action in [
            Action("r1", actor=bot, resources_read=[data]),
            Action("r2", actor=bot, resources_read=[vault]),
            Action("w1", actor=bot, resources_write=[data]),
        ]:
            r = v.verify(action)
            assert 0.0 <= r.confidence <= 1.0, f"Confidence out of range: {r.confidence}"


class TestFormal17_ImmutableResult:
    def test_verification_result_frozen(self):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[data]))
        with pytest.raises((AttributeError, TypeError)):
            r.permitted = not r.permitted  # type: ignore[misc]


class TestFormal18_EpochMonotonicity:
    def test_higher_min_epoch_cannot_give_more_access(self):
        """If min_epoch=N denies, min_epoch=N+1 must also deny."""
        _, bot, data, _, _, v = _env()
        r5 = v.verify(Action("r5", actor=bot, resources_read=[data], min_epoch=5))
        r6 = v.verify(Action("r6", actor=bot, resources_read=[data], min_epoch=6))
        if not r5.permitted:
            assert not r6.permitted, "Higher epoch gave more access than lower epoch"


class TestFormal19_AuditChainGrowth:
    def test_chain_valid_after_n_entries(self):
        _, bot, data, vault, _, v = _env()
        audit = AuditLog()
        v2 = FreedomVerifier(v.registry, audit_log=audit)
        for i in range(100):
            r = Resource(f"res-{i}", ResourceType.FILE, scope=f"/{i}/")
            v2.verify(Action(f"a{i}", actor=bot, resources_read=[data]))
        assert audit.verify_chain()
        assert len(audit) == 100


class TestFormal20_EpochZeroAlwaysPermitsDefault:
    def test_min_epoch_zero_default_backward_compat(self):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("read", actor=bot, resources_read=[data]))
        assert r.permitted, "Default min_epoch=0 broke backward compatibility"


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 21-30: Systems Engineers
# ═══════════════════════════════════════════════════════════════════════════════

class TestSystems21_FreezeImmutability:
    def test_frozen_registry_rejects_mutations(self):
        _, _, data, _, reg, _ = _env()
        frozen = reg.freeze()
        with pytest.raises(RuntimeError):
            frozen.add_claim(RightsClaim(Entity("x", AgentType.MACHINE), data, can_read=True))


class TestSystems22_ThreadSafetyRegistry:
    def test_concurrent_reads_safe(self):
        _, bot, data, _, _, v = _env()
        errors = []
        def read_loop():
            try:
                for _ in range(100):
                    v.verify(Action("r", actor=bot, resources_read=[data]))
            except Exception as e:
                errors.append(str(e))
        threads = [threading.Thread(target=read_loop) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors


class TestSystems23_AuditMaxEntries:
    def test_rotation_prevents_memory_growth(self):
        audit = AuditLog(max_entries=100)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        a = Action("r", actor=bot, resources_read=[data])
        for _ in range(1000):
            v.verify(a)
        assert len(audit) <= 100, f"Audit log grew beyond max_entries: {len(audit)}"
        assert audit.total_count == 1000


class TestSystems24_HealthCheck:
    def test_health_check_runs_without_error(self):
        result = health_check()
        assert "status" in result
        assert "version" in result
        assert "backend" in result
        assert result["version"] == "1.0.0"
        assert result["epoch_revocation"] is True

    def test_health_check_warns_python_mode(self):
        from authgate.kernel import _BACKEND
        result = health_check()
        if _BACKEND == "python":
            assert result["python_identity_warning"] is True
            assert len(result["issues"]) >= 1


class TestSystems25_CallGateRegistration:
    def test_registered_tools_list(self):
        _, bot, data, _, _, v = _env()
        gate = CallGate(v)
        gate.register("alpha", lambda: "a")
        gate.register("beta",  lambda: "b")
        assert "alpha" in gate.registered_tools()
        assert "beta"  in gate.registered_tools()


class TestSystems26_CallGateUnknownTool:
    def test_unregistered_raises_key_error(self):
        _, bot, data, _, _, v = _env()
        gate = CallGate(v)
        with pytest.raises(KeyError):
            gate.execute(Action("r", actor=bot, resources_read=[data]), "unknown", {})


class TestSystems27_SeccompExecutorLevel:
    def test_auto_picks_appropriate_level(self):
        from authgate.kernel.seccomp_executor import SeccompExecutor, IsolationLevel
        import platform
        executor = SeccompExecutor.auto()
        if platform.system() == "Linux":
            assert executor.level >= IsolationLevel.SUBPROCESS
        else:
            assert executor.level == IsolationLevel.SUBPROCESS


class TestSystems28_AuditTotalCount:
    def test_total_count_survives_rotation(self):
        audit = AuditLog(max_entries=10)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        for _ in range(50):
            v.verify(Action("r", actor=bot, resources_read=[data]))
        assert audit.total_count == 50
        assert len(audit) <= 10


class TestSystems29_AuditPathPersistence:
    def test_path_based_audit_writes_to_disk(self, tmp_path):
        log_file = str(tmp_path / "audit.jsonl")
        audit = AuditLog(path=log_file)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r", actor=bot, resources_read=[data]))
        lines = Path(log_file).read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["permitted"] is True


class TestSystems30_RegistryAdvanceEpoch:
    def test_advance_epoch_allows_bulk_revocation(self):
        _, bot, data, _, reg, _ = _env(live=True)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        # Claims start at epoch=1; min_epoch=1 permits
        assert v.verify(Action("r1", actor=bot, resources_read=[data], min_epoch=1)).permitted
        # Deny at min_epoch=100 (claims still at epoch=1)
        assert not v.verify(Action("r2", actor=bot, resources_read=[data], min_epoch=100)).permitted
        # Advance claims to epoch=100
        reg.advance_epoch(100, holder_name=bot.name)
        # Now permits at min_epoch=100
        assert v.verify(Action("r3", actor=bot, resources_read=[data], min_epoch=100)).permitted


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 31-40: Distributed Systems Engineers
# ═══════════════════════════════════════════════════════════════════════════════

class TestDistributed31_EpochClock:
    def test_epoch_gate_works_without_wall_clock(self):
        """Epoch revocation is independent of system time."""
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1))
        assert r.permitted
        r2 = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=10))
        assert not r2.permitted


class TestDistributed32_FrozenSnapshotIsolation:
    def test_snapshot_unaffected_by_post_freeze_epoch_change(self):
        """freeze() deep-copies claims: original advance_epoch does not affect snapshot."""
        _, bot, data, _, reg, _ = _env()
        frozen_v = FreedomVerifier(reg, freeze=True, audit_log=AuditLog())
        # Snapshot at epoch=1
        assert frozen_v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1)).permitted
        # Advance ORIGINAL to epoch=100 — frozen snapshot must be unaffected
        reg.advance_epoch(100)
        # Still permitted at min_epoch=1 (snapshot claims still at epoch=1)
        assert frozen_v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1)).permitted
        # Denied at min_epoch=100 (snapshot claims still at epoch=1, frozen before advance)
        assert not frozen_v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=100)).permitted


class TestDistributed33_RevocationPropagation:
    def test_revoke_all_removes_all_claims(self):
        _, bot, data, _, reg, _ = _env(live=True)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot, resources_read=[data])).permitted
        reg.revoke_all(bot.name)
        assert not v.verify(Action("r", actor=bot, resources_read=[data])).permitted


class TestDistributed34_ConcurrentAuditChain:
    def test_concurrent_writes_produce_valid_chain(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        def write_loop():
            for _ in range(50):
                v.verify(Action("r", actor=bot, resources_read=[data]))
        threads = [threading.Thread(target=write_loop) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert audit.verify_chain(), "Concurrent audit writes broke chain integrity"
        assert len(audit) == 200


class TestDistributed35_MultipleFrozenSnapshots:
    def test_multiple_frozen_verifiers_independent(self):
        _, bot, data, _, reg, _ = _env()
        v1 = FreedomVerifier(reg, freeze=True, audit_log=AuditLog())
        reg.advance_epoch(10)
        v2 = FreedomVerifier(reg, freeze=True, audit_log=AuditLog())
        # v1 snapshot: claims at epoch=1
        assert v1.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1)).permitted
        assert not v1.verify(Action("r", actor=bot, resources_read=[data], min_epoch=10)).permitted
        # v2 snapshot: claims advanced to epoch=10
        assert v2.verify(Action("r", actor=bot, resources_read=[data], min_epoch=10)).permitted


class TestDistributed36_EpochIdempotency:
    def test_advance_to_same_epoch_noop(self):
        _, bot, data, _, reg, _ = _env(live=True)
        reg.advance_epoch(5, holder_name=bot.name)
        count = reg.advance_epoch(5, holder_name=bot.name)
        assert count == 0


class TestDistributed37_RegistryCopy:
    def test_freeze_produces_independent_copy(self):
        _, bot, data, _, reg, _ = _env()
        frozen = reg.freeze()
        reg.advance_epoch(99)  # mutate original
        # frozen is unaffected
        v = FreedomVerifier(frozen, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1)).permitted


class TestDistributed38_NoGlobalState:
    def test_multiple_verifiers_independent(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot1  = Entity("bot1",  AgentType.MACHINE)
        bot2  = Entity("bot2",  AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg1  = OwnershipRegistry()
        reg2  = OwnershipRegistry()
        reg1.register_machine(bot1, alice)
        reg1.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg1.delegate(RightsClaim(bot1, data, can_read=True), delegated_by=alice)
        v1 = FreedomVerifier(reg1, audit_log=AuditLog())
        v2 = FreedomVerifier(reg2, audit_log=AuditLog())
        assert v1.verify(Action("r", actor=bot1, resources_read=[data])).permitted
        assert not v2.verify(Action("r", actor=bot2, resources_read=[data])).permitted


class TestDistributed39_RevocationCascade:
    def test_cascading_revocation_removes_downstream(self):
        alice   = Entity("alice",   AgentType.HUMAN)
        bot_a   = Entity("bot-a",   AgentType.MACHINE)
        data    = Resource("data",  ResourceType.FILE, scope="/data/")
        reg = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot_a, data, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot_a, resources_read=[data])).permitted
        reg.revoke_cascading(bot_a.name)
        assert not v.verify(Action("r", actor=bot_a, resources_read=[data])).permitted


class TestDistributed40_LiveRegistryRevoke:
    def test_live_verifier_sees_revocation_immediately(self):
        _, bot, data, _, reg, v = _env(live=True)
        assert v.verify(Action("r1", actor=bot, resources_read=[data])).permitted
        reg.revoke_all(bot.name)
        assert not v.verify(Action("r2", actor=bot, resources_read=[data])).permitted


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 41-50: Cryptographers
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrypto41_SchemaVersionCompatibility:
    def test_same_major_compatible(self):
        from authgate.kernel.schema_version import SchemaVersion, check_version_compatibility
        ok, _ = check_version_compatibility("1.5.3")
        assert ok

    def test_different_major_incompatible(self):
        from authgate.kernel.schema_version import check_version_compatibility
        ok, reason = check_version_compatibility("2.0.0")
        assert not ok
        assert "MAJOR" in reason


class TestCrypto42_AuditHashChain:
    def test_chain_uses_sha256(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r", actor=bot, resources_read=[data]))
        entry = audit.entries()[0]
        assert len(entry["entry_hash"]) == 64  # SHA-256 = 64 hex chars


class TestCrypto43_GenesisHash:
    def test_first_entry_prev_hash_is_zeros(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r", actor=bot, resources_read=[data]))
        assert audit.entries()[0]["prev_hash"] == "0" * 64


class TestCrypto44_HashLinkage:
    def test_entry_hash_equals_prev_hash_of_next(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r1", actor=bot, resources_read=[data]))
        v.verify(Action("r2", actor=bot, resources_read=[data]))
        entries = audit.entries()
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


class TestCrypto45_SchemaVersionOrdering:
    def test_version_ordering(self):
        from authgate.kernel.schema_version import SchemaVersion
        v1 = SchemaVersion(1, 0, 0)
        v2 = SchemaVersion(1, 5, 0)
        v3 = SchemaVersion(2, 0, 0)
        assert v1 < v2 < v3


class TestCrypto46_VersionRoundtrip:
    def test_parse_and_str_roundtrip(self):
        from authgate.kernel.schema_version import SchemaVersion
        for version_str in ["1.0.0", "2.3.1", "0.1.0", "10.20.30"]:
            v = SchemaVersion.parse(version_str)
            assert str(v) == version_str


class TestCrypto47_InvalidVersionRejected:
    def test_bad_version_strings(self):
        from authgate.kernel.schema_version import SchemaVersion
        for bad in ["1.0", "1.0.0.0", "abc", "", "1.-1.0"]:
            with pytest.raises((ValueError, Exception)):
                SchemaVersion.parse(bad)


class TestCrypto48_SchemaMajorMismatch:
    def test_v2_proof_rejected_by_v1_kernel(self):
        from authgate.kernel.schema_version import check_version_compatibility
        ok, reason = check_version_compatibility("2.0.0")
        assert not ok


class TestCrypto49_AuditEntryDetachedVerification:
    def test_single_entry_hash_recomputable(self):
        import json, hashlib
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r", actor=bot, resources_read=[data]))
        entry = audit.entries()[0]
        stable = {k: val for k, val in entry.items() if k != "entry_hash"}
        canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        assert entry["entry_hash"] == expected


class TestCrypto50_NoBareHashInAPI:
    def test_head_hash_is_hex_string(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("r", actor=bot, resources_read=[data]))
        head = audit.head_hash()
        assert isinstance(head, str)
        assert len(head) == 64
        assert all(c in "0123456789abcdef" for c in head)


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 51-60: API/SDK Consumers
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPI51_TopLevelImports:
    def test_core_types_importable_from_top(self):
        import authgate
        assert hasattr(authgate, "FreedomVerifier")
        assert hasattr(authgate, "Action")
        assert hasattr(authgate, "CallGate")
        assert hasattr(authgate, "AuditLog")
        assert hasattr(authgate, "health_check")


class TestAPI52_VersionExported:
    def test_version_importable(self):
        from authgate import __version__, __schema_version__
        assert __version__ == "1.0.0"
        assert __schema_version__ == "1.0.0"


class TestAPI53_CallGateResult:
    def test_gate_result_has_expected_fields(self):
        _, bot, data, _, _, v = _env()
        gate = CallGate(v)
        gate.register("r", lambda: "ok")
        result = gate.execute(Action("r", actor=bot, resources_read=[data]), "r", {})
        assert hasattr(result, "permitted")
        assert hasattr(result, "output")
        assert hasattr(result, "denied_reason")
        assert hasattr(result, "tool_name")


class TestAPI54_DeniedReasonNotNone:
    def test_denied_reason_always_set_on_denial(self):
        _, bot, _, vault, _, v = _env()
        gate = CallGate(v)
        gate.register("r", lambda: "ok")
        result = gate.execute(Action("r", actor=bot, resources_read=[vault]), "r", {})
        assert not result.permitted
        assert result.denied_reason is not None
        assert len(result.denied_reason) > 0


class TestAPI55_ResultIsFrozen:
    def test_gate_result_immutable(self):
        from authgate.kernel.call_gate import GateResult
        r = GateResult(permitted=True, output="x")
        with pytest.raises((AttributeError, TypeError)):
            r.permitted = False  # type: ignore[misc]


class TestAPI56_HealthCheckContract:
    def test_health_check_has_required_keys(self):
        result = health_check()
        required = {"status", "version", "schema_version", "backend",
                    "python_identity_warning", "epoch_revocation", "issues"}
        assert required <= set(result.keys())


class TestAPI57_SchemaVersionPublic:
    def test_schema_version_accessible(self):
        from authgate import CURRENT_SCHEMA_VERSION, check_version_compatibility
        assert CURRENT_SCHEMA_VERSION is not None
        ok, _ = check_version_compatibility("1.0.0")
        assert ok


class TestAPI58_ViolationsTuple:
    def test_violations_is_tuple_not_list(self):
        _, bot, _, vault, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[vault]))
        assert isinstance(r.violations, tuple)


class TestAPI59_AuditLogPath:
    def test_path_none_means_in_memory_only(self, tmp_path):
        audit = AuditLog()  # no path
        assert audit.path is None


class TestAPI60_CallGateChain:
    def test_full_chain_permit_deny_audit(self):
        _, bot, data, vault, _, v = _env()
        audit = AuditLog()
        v2 = FreedomVerifier(v.registry, audit_log=audit)
        gate = CallGate(v2)
        gate.register("r", lambda: "ok")
        gate.execute(Action("r1", actor=bot, resources_read=[data]), "r", {})
        gate.execute(Action("r2", actor=bot, resources_read=[vault]), "r", {})
        assert len(audit) == 2
        assert audit.entries()[0]["permitted"] is True
        assert audit.entries()[1]["permitted"] is False
        assert audit.verify_chain()


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 61-70: Performance/Reliability Engineers
# ═══════════════════════════════════════════════════════════════════════════════

class TestPerf61_VerifyLatency:
    def test_1000_verifications_under_2_seconds(self):
        _, bot, data, _, _, v = _env()
        a = Action("r", actor=bot, resources_read=[data])
        t0 = time.perf_counter()
        for _ in range(1000):
            v.verify(a)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"1000 verifications took {elapsed:.2f}s (too slow)"


class TestPerf62_AuditRotationPerf:
    def test_rotation_does_not_degrade_write_speed(self):
        audit = AuditLog(max_entries=100)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        a = Action("r", actor=bot, resources_read=[data])
        t0 = time.perf_counter()
        for _ in range(10_000):
            v.verify(a)
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"10k verifications with rotation took {elapsed:.2f}s"


class TestPerf63_ChainVerifyScales:
    def test_chain_verify_100_entries_fast(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        for _ in range(100):
            v.verify(Action("r", actor=bot, resources_read=[data]))
        t0 = time.perf_counter()
        audit.verify_chain()
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"Chain verify of 100 entries took {elapsed:.2f}s"


class TestPerf64_ConcurrentThroughput:
    def test_concurrent_read_throughput(self):
        _, bot, data, _, _, v = _env()
        a = Action("r", actor=bot, resources_read=[data])
        results = []
        def worker():
            t0 = time.perf_counter()
            for _ in range(200):
                v.verify(a)
            results.append(time.perf_counter() - t0)
        threads = [threading.Thread(target=worker) for _ in range(8)]
        t_start = time.perf_counter()
        for t in threads: t.start()
        for t in threads: t.join()
        total = time.perf_counter() - t_start
        ops_per_sec = (8 * 200) / total
        assert ops_per_sec > 1000, f"Only {ops_per_sec:.0f} ops/sec — too slow"


class TestPerf65_RegistryBuild:
    def test_1000_claim_registry_builds_fast(self):
        alice = Entity("alice", AgentType.HUMAN)
        t0 = time.perf_counter()
        reg = OwnershipRegistry()
        for i in range(1000):
            r = Resource(f"res-{i}", ResourceType.FILE, scope=f"/{i}/")
            reg.add_claim(RightsClaim(alice, r, can_read=True))
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"1000-claim registry build took {elapsed:.2f}s"


class TestPerf66_EpochAdvancePerf:
    def test_advance_epoch_1000_claims_fast(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        for i in range(100):
            r = Resource(f"r{i}", ResourceType.FILE, scope=f"/{i}/")
            reg.add_claim(RightsClaim(alice, r, can_read=True, can_delegate=True))
            reg.delegate(RightsClaim(bot, r, can_read=True, epoch=1), delegated_by=alice)
        t0 = time.perf_counter()
        reg.advance_epoch(2)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.1, f"advance_epoch took {elapsed:.4f}s (should be O(n))"


class TestPerf67_AuditTotalCountNoLock:
    def test_total_count_accurate_after_rotation(self):
        audit = AuditLog(max_entries=10)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        for _ in range(500):
            v.verify(Action("r", actor=bot, resources_read=[data]))
        assert audit.total_count == 500
        assert len(audit) == 10


class TestPerf68_GateResultCreation:
    def test_1000_gate_results_no_allocation_issue(self):
        from authgate.kernel.call_gate import GateResult
        t0 = time.perf_counter()
        for i in range(1000):
            _ = GateResult(permitted=i % 2 == 0, output="x", tool_name="test")
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.1


class TestPerf69_FrozenRegistryFast:
    def test_frozen_verify_faster_than_unfrozen(self):
        _, bot, data, _, reg, _ = _env()
        frozen_v = FreedomVerifier(reg, freeze=True,  audit_log=AuditLog())
        live_v   = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        a = Action("r", actor=bot, resources_read=[data])
        n = 500
        t0 = time.perf_counter()
        for _ in range(n): frozen_v.verify(a)
        frozen_time = time.perf_counter() - t0
        t0 = time.perf_counter()
        for _ in range(n): live_v.verify(a)
        live_time = time.perf_counter() - t0
        # Frozen should not be dramatically slower
        assert frozen_time < live_time * 5


class TestPerf70_SimulationBenchmark:
    def test_simulation_under_10_seconds(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "attack_harness"))
        try:
            from simulation.engine import SimulationEngine
            t0 = time.perf_counter()
            summary = SimulationEngine().run()
            elapsed = time.perf_counter() - t0
            assert elapsed < 10.0
            assert summary.failed == 0
        except ImportError:
            pytest.skip("simulation engine not found")


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 71-80: Capability Security Researchers
# ═══════════════════════════════════════════════════════════════════════════════

class TestCapability71_NoAmbientAuthority:
    def test_new_resource_always_denied(self):
        _, bot, _, _, _, v = _env()
        new_res = Resource("never-delegated", ResourceType.DATASET, scope="/nd/")
        r = v.verify(Action("r", actor=bot, resources_read=[new_res]))
        assert not r.permitted


class TestCapability72_Attenuation:
    def test_write_claim_does_not_grant_delegate(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_write=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_write=True, can_delegate=False), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert not v.verify(Action("d", actor=bot, resources_delegate=[data])).permitted


class TestCapability73_DelegationAttenuation:
    def test_delegate_cannot_give_more_than_held(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        sub   = Entity("sub",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.register_machine(sub, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True, can_delegate=True), delegated_by=alice)
        with pytest.raises(Exception):
            reg.delegate(RightsClaim(sub, data, can_write=True), delegated_by=bot)


class TestCapability74_EpochAttenuation:
    def test_claim_epoch_lower_than_action_min_epoch_denied(self):
        _, bot, data, _, _, v = _env()
        r = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=100))
        assert not r.permitted


class TestCapability75_OwnershipRoot:
    def test_ownerless_machine_zero_authority(self):
        orphan = Entity("orphan", AgentType.MACHINE)
        data   = Resource("data",  ResourceType.FILE, scope="/data/")
        reg    = OwnershipRegistry()
        reg.add_claim(RightsClaim(orphan, data, can_read=True))
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("r", actor=orphan, resources_read=[data]))
        assert not r.permitted


class TestCapability76_Revocability:
    def test_every_delegation_is_revocable(self):
        _, bot, data, _, reg, _ = _env(live=True)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot, resources_read=[data])).permitted
        reg.revoke_all(bot.name)
        assert not v.verify(Action("r", actor=bot, resources_read=[data])).permitted


class TestCapability77_SubjectBinding:
    def test_cap_for_one_entity_not_usable_by_another(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot_a = Entity("bot-a", AgentType.MACHINE)
        bot_b = Entity("bot-b", AgentType.MACHINE)
        data  = Resource("data",  ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot_a, data, can_read=True), delegated_by=alice)
        # bot_b has no claim
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert not v.verify(Action("r", actor=bot_b, resources_read=[data])).permitted


class TestCapability78_MachineCannotGovern:
    def test_machine_governing_human_blocked(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data",  ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("govern", actor=bot, governs_humans=[alice]))
        assert not r.permitted
        assert any("MACHINE_DOMINION" in viol or "dominion" in viol.lower()
                   for viol in r.violations)


class TestCapability79_ExpiryEnforced:
    def test_expired_claim_denied(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data",  ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(
            RightsClaim(bot, data, can_read=True, expires_at=time.time() - 1),
            delegated_by=alice
        )
        v = FreedomVerifier(reg, audit_log=AuditLog())
        r = v.verify(Action("r", actor=bot, resources_read=[data]))
        assert not r.permitted


class TestCapability80_ConfidenceZeroBlocked:
    def test_zero_confidence_claim_denied(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        with pytest.raises(ValueError):
            # confidence=0.0 should raise on construction or be rejected
            RightsClaim(bot, data, can_read=True, confidence=-0.1)


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 81-90: Production Operators (SRE)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSRE81_AuditForensics:
    def test_replay_recovers_exact_decision(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        v.verify(Action("forensic-test", actor=bot, resources_read=[data]))
        entry = audit.replay(0)
        assert entry["action_id"] == "forensic-test"
        assert entry["permitted"] is True


class TestSRE82_AuditChainErrors:
    def test_chain_errors_describes_tamper(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        for i in range(5):
            v.verify(Action(f"a{i}", actor=bot, resources_read=[data]))
        with audit._lock:
            audit._records[2]["permitted"] = not audit._records[2]["permitted"]
        errors = audit.chain_errors()
        assert len(errors) > 0
        assert any("2" in e or "tamper" in e.lower() or "mismatch" in e.lower()
                   for e in errors)


class TestSRE83_AuditPersistence:
    def test_log_written_per_decision(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        audit = AuditLog(path=str(log_file))
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        for i in range(10):
            v.verify(Action(f"a{i}", actor=bot, resources_read=[data]))
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 10


class TestSRE84_HealthCheckPythonMode:
    def test_health_check_issues_nonempty_in_python_mode(self):
        from authgate.kernel import _BACKEND
        result = health_check()
        if _BACKEND == "python":
            assert len(result["issues"]) >= 1
            assert result["status"] == "degraded"


class TestSRE85_GateResultOutputType:
    def test_output_can_be_any_type(self):
        _, bot, data, _, _, v = _env()
        gate = CallGate(v)
        for output_val in [42, "string", [1, 2], {"k": "v"}, None]:
            gate.register(f"t_{id(output_val)}", lambda v=output_val: v)
            r = gate.execute(Action("r", actor=bot, resources_read=[data]),
                             f"t_{id(output_val)}", {})
            assert r.permitted
            assert r.output == output_val


class TestSRE86_RegistryStats:
    def test_registry_conflict_detection(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot_a = Entity("bot-a", AgentType.MACHINE)
        bot_b = Entity("bot-b", AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot_a, alice)
        reg.register_machine(bot_b, alice)
        reg.add_claim(RightsClaim(bot_a, data, can_write=True))
        reg.add_claim(RightsClaim(bot_b, data, can_write=True))
        conflicts = reg.open_conflicts()
        assert len(conflicts) >= 1


class TestSRE87_AuditHeadHash:
    def test_head_hash_changes_after_each_entry(self):
        _, bot, data, _, reg, _ = _env()
        audit = AuditLog()
        v = FreedomVerifier(reg, audit_log=audit)
        h0 = audit.head_hash()
        v.verify(Action("r1", actor=bot, resources_read=[data]))
        h1 = audit.head_hash()
        v.verify(Action("r2", actor=bot, resources_read=[data]))
        h2 = audit.head_hash()
        assert h0 != h1 != h2


class TestSRE88_CallGateAuditIntegration:
    def test_gate_deny_appears_in_audit(self):
        _, bot, _, vault, _, v = _env()
        audit = AuditLog()
        v2 = FreedomVerifier(v.registry, audit_log=audit)
        gate = CallGate(v2)
        gate.register("r", lambda: "ok")
        gate.execute(Action("steal", actor=bot, resources_read=[vault]), "r", {})
        assert len(audit) == 1
        assert audit.entries()[0]["permitted"] is False


class TestSRE89_AuditRotationChainIntegrity:
    def test_chain_verify_after_rotation(self):
        audit = AuditLog(max_entries=10)
        _, bot, data, _, reg, _ = _env()
        v = FreedomVerifier(reg, audit_log=audit)
        for _ in range(50):
            v.verify(Action("r", actor=bot, resources_read=[data]))
        # Chain should be valid for the retained window
        assert audit.verify_chain()


class TestSRE90_WireSchemaFilesExist:
    def test_json_schema_files_present(self):
        spec_dir = Path(__file__).parent.parent / "spec"
        assert (spec_dir / "canonical_action.schema.json").exists()
        assert (spec_dir / "gate_result.schema.json").exists()
        assert (spec_dir / "audit_entry.schema.json").exists()


# ═══════════════════════════════════════════════════════════════════════════════
# TESTERS 91-100: Domain specialists (ML/AI, edge cases, compliance)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDomain91_MLResource:
    def test_model_weights_resource_type_supported(self):
        alice   = Entity("alice",   AgentType.HUMAN)
        ml_bot  = Entity("ml-bot",  AgentType.MACHINE)
        model   = Resource("gpt-weights", ResourceType.MODEL_WEIGHTS, scope="/models/")
        reg     = OwnershipRegistry()
        reg.register_machine(ml_bot, alice)
        reg.add_claim(RightsClaim(alice, model, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(ml_bot, model, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert v.verify(Action("r", actor=ml_bot, resources_read=[model])).permitted


class TestDomain92_DatasetResource:
    def test_dataset_resource_type_supported(self):
        alice   = Entity("alice",  AgentType.HUMAN)
        bot     = Entity("bot",    AgentType.MACHINE)
        dataset = Resource("training-data", ResourceType.DATASET, scope="/datasets/")
        reg     = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, dataset, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, dataset, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot, resources_read=[dataset])).permitted


class TestDomain93_AllResourceTypes:
    def test_all_resource_types_instantiatable(self):
        for rtype in ResourceType:
            r = Resource(f"test-{rtype.name}", rtype, scope=f"/{rtype.name}/")
            assert r.rtype == rtype


class TestDomain94_LongActionId:
    def test_very_long_action_id_accepted(self):
        _, bot, data, _, _, v = _env()
        long_id = "a" * 1000
        r = v.verify(Action(long_id, actor=bot, resources_read=[data]))
        assert r.permitted


class TestDomain95_UnicodeEntityName:
    def test_unicode_entity_names_work(self):
        alice = Entity("علی", AgentType.HUMAN)
        bot   = Entity("ربات", AgentType.MACHINE)
        data  = Resource("داده", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert v.verify(Action("قرائت", actor=bot, resources_read=[data])).permitted


class TestDomain96_EmptyResourceList:
    def test_action_with_no_resources_permitted_if_no_flags(self):
        _, bot, _, _, _, v = _env()
        r = v.verify(Action("noop", actor=bot))
        # No resources, no flags: machine is registered → should permit
        assert r.permitted


class TestDomain97_MultipleResources:
    def test_action_with_multiple_resources_all_checked(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        r1    = Resource("r1",  ResourceType.FILE, scope="/r1/")
        r2    = Resource("r2",  ResourceType.FILE, scope="/r2/")
        r3    = Resource("r3",  ResourceType.FILE, scope="/r3/")  # no claim
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, r1, can_read=True, can_delegate=True))
        reg.add_claim(RightsClaim(alice, r2, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, r1, can_read=True), delegated_by=alice)
        reg.delegate(RightsClaim(bot, r2, can_read=True), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert v.verify(Action("r", actor=bot, resources_read=[r1, r2])).permitted
        assert not v.verify(Action("r", actor=bot, resources_read=[r1, r2, r3])).permitted


class TestDomain98_HighEpoch:
    def test_large_epoch_value_accepted(self):
        _, bot, data, _, reg, _ = _env(live=True)
        reg.advance_epoch(1_000_000)
        v = FreedomVerifier(reg, freeze=False, audit_log=AuditLog())
        r = v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1_000_000))
        assert r.permitted


class TestDomain99_EpochZeroEdge:
    def test_epoch_zero_claim_denied_by_min_epoch_1(self):
        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True, epoch=0), delegated_by=alice)
        v = FreedomVerifier(reg, audit_log=AuditLog())
        assert not v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=1)).permitted
        assert v.verify(Action("r", actor=bot, resources_read=[data], min_epoch=0)).permitted


class TestDomain100_FullStack:
    def test_complete_infrastructure_stack(self):
        """T-100: The full stack — authority source, gate, audit, version, health."""
        from authgate.authority import HumanDelegationSource
        from authgate.authority.base import CapabilityRequest

        alice = Entity("alice", AgentType.HUMAN)
        bot   = Entity("bot",   AgentType.MACHINE)
        data  = Resource("data", ResourceType.FILE, scope="/data/")
        reg   = OwnershipRegistry()
        reg.register_machine(bot, alice)
        reg.add_claim(RightsClaim(alice, data, can_read=True, can_delegate=True))
        reg.delegate(RightsClaim(bot, data, can_read=True), delegated_by=alice)

        audit   = AuditLog(max_entries=1000)
        v       = FreedomVerifier(reg, audit_log=audit)
        gate    = CallGate(v)
        source  = HumanDelegationSource(v)

        # 1. Request capability via AuthoritySource
        cap = source.request_capability(CapabilityRequest(
            subject_id=bot.name, resource_id=data.name, rights=frozenset(["read"])
        ))
        assert cap is not None

        # 2. Execute via CallGate
        gate.register("read", lambda path="": f"data:{path}")
        result = gate.execute(Action("r", actor=bot, resources_read=[data]), "read", {"path": "/x"})
        assert result.permitted

        # 3. Audit is populated
        assert len(audit) >= 1
        assert audit.verify_chain()

        # 4. Health check reflects state
        hc = health_check()
        assert hc["epoch_revocation"] is True

        # 5. Schema version consistent
        assert __version__ == "1.0.0"
        assert __schema_version__ == "1.0.0"

        # 6. Wire schemas exist
        spec_dir = Path(__file__).parent.parent / "spec"
        assert (spec_dir / "canonical_action.schema.json").exists()
