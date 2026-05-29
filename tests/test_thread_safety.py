"""
Thread safety tests — authgate-kernel MASTER_PLAN Phase 5.1.

Tests that OwnershipRegistry, FreedomVerifier, and AuditLog are safe
under concurrent access without deadlocks or data corruption.

Run: pytest tests/test_thread_safety.py -v
"""

from __future__ import annotations
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.audit import AuditLog


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_base() -> tuple[OwnershipRegistry, Entity, Entity, Resource]:
    human = Entity("owner", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    dataset = Resource("dataset", ResourceType.DATASET, scope="/data/")
    registry = OwnershipRegistry()
    registry.register_machine(bot, human)
    registry.add_claim(RightsClaim(bot, dataset, can_read=True, can_write=True))
    return registry, human, bot, dataset


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConcurrentVerify:
    """Multiple threads calling verify() simultaneously on a frozen registry."""

    def test_50_concurrent_reads_no_corruption(self):
        """50 threads verify the same action simultaneously — all must agree."""
        registry, _, bot, dataset = _build_base()
        frozen = registry.freeze()
        verifier = FreedomVerifier(frozen)
        action = Action("concurrent-read", actor=bot, resources_read=[dataset])

        results = []
        errors = []
        lock = threading.Lock()

        def verify_once():
            try:
                r = verifier.verify(action)
                with lock:
                    results.append(r.permitted)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=verify_once) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent verify: {errors}"
        assert len(results) == 50
        # All decisions must be identical (determinism under concurrency)
        assert all(r == results[0] for r in results), "Inconsistent results across threads"
        assert results[0] is True, "Expected permit"

    def test_concurrent_permit_and_deny_mix(self):
        """Two action types run concurrently — permit and deny must not bleed into each other."""
        registry, _, bot, dataset = _build_base()
        frozen = registry.freeze()
        verifier = FreedomVerifier(frozen)

        permit_action = Action("permit", actor=bot, resources_read=[dataset])
        deny_action   = Action("deny",   actor=bot, resources_read=[dataset],
                               increases_machine_sovereignty=True)

        permits = []
        denies  = []
        lock = threading.Lock()

        def run_permit():
            r = verifier.verify(permit_action)
            with lock:
                permits.append(r.permitted)

        def run_deny():
            r = verifier.verify(deny_action)
            with lock:
                denies.append(r.permitted)

        threads = (
            [threading.Thread(target=run_permit) for _ in range(25)] +
            [threading.Thread(target=run_deny) for _ in range(25)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(permits), "Permit action returned deny under concurrency"
        assert not any(denies), "Deny action returned permit under concurrency"

    def test_threadpool_verify_throughput(self):
        """Verify 1000 actions through a thread pool — no deadlock, no error."""
        registry, _, bot, dataset = _build_base()
        frozen = registry.freeze()
        verifier = FreedomVerifier(frozen)
        action = Action("tp-read", actor=bot, resources_read=[dataset])

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(verifier.verify, action) for _ in range(1000)]
            results = [f.result() for f in as_completed(futures)]

        assert len(results) == 1000
        assert all(r.permitted for r in results)


class TestConcurrentRegistryMutation:
    """Writers mutating a live registry while readers take snapshots."""

    def test_freeze_while_writer_mutates(self):
        """freeze() produces a consistent snapshot even while the original is mutated."""
        registry, human, bot, dataset = _build_base()

        snapshots = []
        errors = []
        stop = threading.Event()
        lock = threading.Lock()

        def writer():
            i = 0
            while not stop.is_set():
                extra = Resource(f"extra_{i}", ResourceType.FILE, scope=f"/extra/{i}/")
                try:
                    registry.add_claim(RightsClaim(bot, extra, can_read=True))
                except RuntimeError:
                    pass  # frozen registry raises; ignore
                i += 1
                time.sleep(0.001)

        def reader():
            for _ in range(10):
                snap = registry.freeze()
                with lock:
                    snapshots.append(len(snap._claims))
                time.sleep(0.002)

        writer_thread = threading.Thread(target=writer, daemon=True)
        reader_threads = [threading.Thread(target=reader) for _ in range(5)]

        writer_thread.start()
        for t in reader_threads:
            t.start()
        for t in reader_threads:
            t.join()
        stop.set()
        writer_thread.join(timeout=1.0)

        assert not errors
        # Snapshots taken at different times should have non-decreasing sizes
        # (writer only adds, never removes)
        assert all(s >= 2 for s in snapshots), "Snapshot lost existing claims"

    def test_frozen_registry_mutation_raises(self):
        """A frozen snapshot must raise RuntimeError on any mutation attempt."""
        registry, human, bot, dataset = _build_base()
        frozen = registry.freeze()

        extra = Resource("extra", ResourceType.FILE, scope="/extra/")
        with pytest.raises(RuntimeError, match="frozen"):
            frozen.add_claim(RightsClaim(bot, extra, can_read=True))

        with pytest.raises(RuntimeError, match="frozen"):
            frozen.register_machine(bot, human)

    def test_snapshot_independent_of_original(self):
        """Mutations to the original registry after freeze() do not affect the snapshot."""
        registry, human, bot, dataset = _build_base()
        frozen = registry.freeze()

        original_claim_count = len(frozen._claims)

        # Add many claims to original
        for i in range(20):
            extra = Resource(f"post_{i}", ResourceType.FILE, scope=f"/post/{i}/")
            registry.add_claim(RightsClaim(bot, extra, can_read=True))

        # Snapshot must be unchanged
        assert len(frozen._claims) == original_claim_count, \
            "Snapshot was mutated by changes to original registry"


class TestAuditLogConcurrency:
    """AuditLog must maintain chain integrity under concurrent appends."""

    def test_concurrent_audit_chain_integrity(self):
        """50 concurrent verify() calls — audit chain must be intact after all complete."""
        registry, _, bot, dataset = _build_base()
        audit = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=audit)
        action = Action("audit-concurrent", actor=bot, resources_read=[dataset])

        threads = [
            threading.Thread(target=verifier.verify, args=(action,))
            for _ in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(audit) == 50
        assert audit.verify_chain(), "Audit chain broken under concurrent appends"

    def test_audit_chain_tamper_detection(self):
        """Modifying one entry must be detected by verify_chain()."""
        registry, _, bot, dataset = _build_base()
        audit = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=audit)

        for i in range(10):
            verifier.verify(Action(f"entry-{i}", actor=bot, resources_read=[dataset]))

        assert audit.verify_chain()

        # Tamper one entry
        entries = audit.entries()
        entries[5]["permitted"] = not entries[5]["permitted"]
        # Replace internal records (bypassing normal API — simulating an attacker)
        with audit._lock:
            audit._records[5] = entries[5]

        assert not audit.verify_chain(), "Tampered entry not detected"

    def test_audit_deletion_detected(self):
        """Removing an entry from the middle breaks the chain."""
        registry, _, bot, dataset = _build_base()
        audit = AuditLog()
        verifier = FreedomVerifier(registry.freeze(), audit_log=audit)

        for i in range(10):
            verifier.verify(Action(f"entry-{i}", actor=bot, resources_read=[dataset]))

        assert audit.verify_chain()

        # Remove middle entry
        with audit._lock:
            del audit._records[4]

        assert not audit.verify_chain(), "Missing entry not detected"


class TestVerifierFreezeOnInit:
    """freeze=True (default) gives a consistent snapshot; freeze=False uses live registry."""

    def test_live_registry_sees_mutations(self):
        """freeze=False: mutations after verifier creation are visible."""
        registry, human, bot, dataset = _build_base()
        verifier = FreedomVerifier(registry, freeze=False)  # explicit live

        r1 = verifier.verify(Action("before", actor=bot, resources_read=[dataset]))
        assert r1.permitted

        # Remove the claim — live verifier sees this immediately
        original_claims = registry._claims[:]
        with registry._lock:
            registry._claims.clear()
            registry._index.clear()

        r2 = verifier.verify(Action("after", actor=bot, resources_read=[dataset]))
        assert not r2.permitted, "Live registry: mutation should be visible immediately"

        # Restore
        with registry._lock:
            registry._claims.extend(original_claims)
            for claim in original_claims:
                registry._index[(claim.holder.name, claim.resource.name)].append(claim)

    def test_frozen_verifier_ignores_mutations(self):
        """freeze=True: mutations after construction do NOT affect verify()."""
        registry, human, bot, dataset = _build_base()
        verifier = FreedomVerifier(registry, freeze=True)

        r1 = verifier.verify(Action("before", actor=bot, resources_read=[dataset]))
        assert r1.permitted

        # Remove all claims from original registry
        with registry._lock:
            registry._claims.clear()
            registry._index.clear()

        # Frozen verifier still uses its snapshot — still permits
        r2 = verifier.verify(Action("after-mutation", actor=bot, resources_read=[dataset]))
        assert r2.permitted, "Frozen verifier must not be affected by post-freeze mutations"
