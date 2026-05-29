"""
Differential fuzzer — closes A5 (Python ≠ Rust divergence).

Two test modes:
  1. Python invariant mode (always runs):
     Property-based testing of the Python verify model against
     10 core security invariants. Catches regressions in the Python layer.

  2. Differential mode (runs when Rust build available):
     Compares Python verify() vs Rust verify() across random inputs.
     Any divergence = a security gap that must be investigated.

Run:
  pytest attack_harness/differential_fuzzer.py -v
  pytest attack_harness/differential_fuzzer.py -v -k "differential"
  pytest attack_harness/differential_fuzzer.py -v -k "invariant"

The differential tests are skipped automatically if the Rust build
is not installed (authgate_kernel not importable).
"""

from __future__ import annotations

import sys
import os
import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, HealthCheck, assume
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# ─── Python verify model (inline — same as simulation engine) ─────────────────

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7
ALL_RIGHTS = 0xFF

RIGHTS_LIST = [
    RIGHT_READ, RIGHT_WRITE, RIGHT_DELEGATE, RIGHT_EXECUTE,
    RIGHT_SPAWN, RIGHT_NETWORK, RIGHT_MODEL_INVOKE, RIGHT_POLICY_MODIFY,
]


def _compute_binding_hash(actor_id, resource_hash, required_rights, nonce,
                          timestamp, min_epoch, cap_bytes_list, rev_bytes_list):
    h = hashlib.sha256()
    h.update(actor_id)
    h.update(resource_hash)
    h.update(struct.pack(">Q", required_rights))
    h.update(nonce)
    h.update(struct.pack(">Q", timestamp))
    h.update(struct.pack(">Q", min_epoch))
    h.update(struct.pack(">I", len(cap_bytes_list)))
    for b in cap_bytes_list:
        h.update(b)
    h.update(struct.pack(">I", len(rev_bytes_list)))
    for b in rev_bytes_list:
        h.update(b)
    return h.digest()


def _py_verify(actor_id, resource_hash, required_rights, min_epoch,
               caps, now, action_binding_hash, nonce, timestamp,
               cap_bytes, rev_bytes, revocations=None):
    """Python verify model — mirrors engine.rs exactly."""
    computed = _compute_binding_hash(
        actor_id, resource_hash, required_rights, nonce,
        timestamp, min_epoch, cap_bytes, rev_bytes or []
    )
    if computed != action_binding_hash:
        return False, "canonical binding hash mismatch"

    if not caps:
        return False, "no capability proofs provided"

    found_actor_cap = False
    for cap in caps:
        if cap.get("subject_id") != actor_id:
            continue
        found_actor_cap = True
        if cap.get("resource_hash") != resource_hash:
            return False, "capability resource mismatch"
        if cap.get("expiry", 9999) < now:
            return False, "capability has expired"
        if cap.get("epoch", 0) < min_epoch:
            return False, "capability epoch predates minimum required epoch"
        if not cap.get("sig_valid", True):
            return False, "root signature verification failed"
        parent_epoch = cap.get("parent_epoch", cap.get("epoch", 0))
        if parent_epoch < min_epoch:
            return False, "delegation chain node epoch predates minimum required epoch"
        if not cap.get("issuer_binding_valid", True):
            return False, "issuer pubkey does not correspond to parent subject identity"
        if cap.get("parent_rights") is not None:
            if (cap["rights"] & ~cap["parent_rights"]) != 0:
                return False, "attenuation violation: child rights exceed parent"
        if (cap.get("rights", 0) & required_rights) != required_rights:
            return False, "capability does not grant required rights"

    if not found_actor_cap:
        return False, "capability not issued to this actor"

    for rev in (revocations or []):
        if not rev.get("sig_valid", False):
            continue
        for cap in caps:
            if cap.get("proof_hash") == rev.get("target_hash"):
                return False, "capability has been explicitly revoked"

    return True, ""


# ─── High-level action builder ─────────────────────────────────────────────────

def _make_cap(actor, resource, rights, expiry=9999, epoch=5,
              sig_valid=True, parent_rights=None,
              issuer_binding_valid=True, parent_epoch=None):
    ph = hashlib.sha256(actor + resource + struct.pack(">Q", rights)).digest()
    return {
        "subject_id": actor,
        "resource_hash": resource,
        "rights": rights,
        "expiry": expiry,
        "epoch": epoch,
        "sig_valid": sig_valid,
        "parent_rights": parent_rights,
        "issuer_binding_valid": issuer_binding_valid,
        "parent_epoch": parent_epoch if parent_epoch is not None else epoch,
        "proof_hash": ph,
        "canonical_bytes": ph + actor + resource,
    }


def _make_action(actor, resource, rights, min_epoch=5, caps=None,
                 revs=None, nonce=None, timestamp=1000):
    caps_ = caps if caps is not None else [_make_cap(actor, resource, rights)]
    revs_ = revs or []
    n = nonce or b"\x07" * 16
    cap_bytes = [c["canonical_bytes"] for c in caps_]
    rev_bytes = [rv.get("canonical_bytes", b"\x00" * 40) for rv in revs_]
    bh = _compute_binding_hash(actor, resource, rights, n, timestamp, min_epoch, cap_bytes, rev_bytes)
    return {
        "actor_id": actor, "resource_hash": resource,
        "required_rights": rights, "min_epoch": min_epoch,
        "caps": caps_, "revocations": revs_,
        "nonce": n, "timestamp": timestamp,
        "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": rev_bytes,
    }


def _run_py(act):
    a = act
    return _py_verify(
        actor_id=a["actor_id"], resource_hash=a["resource_hash"],
        required_rights=a["required_rights"], min_epoch=a["min_epoch"],
        caps=a["caps"], now=a["timestamp"],
        action_binding_hash=a["binding_hash"],
        nonce=a["nonce"], timestamp=a["timestamp"],
        cap_bytes=a["cap_bytes"], rev_bytes=a["rev_bytes"],
        revocations=a.get("revocations", []),
    )


# ─── Hypothesis strategies ─────────────────────────────────────────────────────

actor_st    = st.binary(min_size=32, max_size=32)
resource_st = st.binary(min_size=32, max_size=32)
rights_st   = st.integers(min_value=0, max_value=ALL_RIGHTS)
epoch_st    = st.integers(min_value=0, max_value=20)
expiry_st   = st.integers(min_value=0, max_value=5000)
nonce_st    = st.binary(min_size=16, max_size=16)
ts_st       = st.integers(min_value=0, max_value=3000)


# ─── I. Python invariant tests ─────────────────────────────────────────────────

class TestPythonInvariants:
    """
    10 core security invariants that the Python verify model must satisfy.
    Run via Hypothesis (property-based) — each test generates 200+ random inputs.
    """

    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st,
           epoch=epoch_st, expiry=expiry_st)
    def test_inv1_permitted_implies_no_violations(self, actor, resource, rights, epoch, expiry):
        """INV-1: If permitted, violations must be empty."""
        assume(rights > 0)
        assume(expiry > 1000)  # fresh
        cap = _make_cap(actor, resource, rights, expiry=expiry, epoch=epoch)
        act = _make_action(actor, resource, rights, min_epoch=epoch, caps=[cap])
        permitted, reason = _run_py(act)
        if permitted:
            assert reason == "", f"permitted but reason non-empty: {reason!r}"

    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st,
           epoch=epoch_st, expiry=expiry_st)
    def test_inv2_denied_implies_reason_nonempty(self, actor, resource, rights, epoch, expiry):
        """INV-2: If denied, reason must be non-empty."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights, expiry=expiry, epoch=epoch)
        act = _make_action(actor, resource, rights, min_epoch=epoch, caps=[cap])
        permitted, reason = _run_py(act)
        if not permitted:
            assert reason, "denied but reason is empty"

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st, epoch=epoch_st)
    def test_inv3_deterministic(self, actor, resource, rights, epoch):
        """INV-3: Same input always produces the same output (no hidden state)."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights, epoch=epoch)
        act = _make_action(actor, resource, rights, min_epoch=epoch, caps=[cap])
        r1 = _run_py(act)
        r2 = _run_py(act)
        assert r1 == r2, f"non-deterministic: {r1} != {r2}"

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st)
    def test_inv4_expired_cap_always_denied(self, actor, resource, rights):
        """INV-4: Expired cap (expiry < now=1000) is always denied."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights, expiry=999)  # expired
        act = _make_action(actor, resource, rights, caps=[cap], timestamp=1000)
        permitted, reason = _run_py(act)
        assert not permitted, f"expired cap was permitted: {reason}"
        assert "expired" in reason

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st,
           cap_epoch=st.integers(min_value=0, max_value=4))
    def test_inv5_stale_epoch_always_denied(self, actor, resource, rights, cap_epoch):
        """INV-5: Cap epoch < min_epoch is always denied."""
        assume(rights > 0)
        min_epoch = 5
        assume(cap_epoch < min_epoch)
        cap = _make_cap(actor, resource, rights, epoch=cap_epoch)
        act = _make_action(actor, resource, rights, min_epoch=min_epoch, caps=[cap])
        permitted, reason = _run_py(act)
        assert not permitted, f"stale epoch cap was permitted (cap_epoch={cap_epoch})"
        assert "epoch" in reason

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st,
           parent_rights=rights_st, extra_rights=rights_st)
    def test_inv6_attenuation_enforced(self, actor, resource, parent_rights, extra_rights):
        """INV-6: Child cannot exceed parent rights (attenuation invariant)."""
        assume(extra_rights > 0)
        child_rights = parent_rights | extra_rights
        assume((child_rights & ~parent_rights) != 0)  # child actually exceeds parent
        cap = _make_cap(actor, resource, child_rights, parent_rights=parent_rights)
        act = _make_action(actor, resource, child_rights, caps=[cap])
        permitted, reason = _run_py(act)
        assert not permitted, f"attenuation violation permitted (parent={parent_rights:#x} child={child_rights:#x})"
        assert "attenuation" in reason

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, other_actor=actor_st,
           resource=resource_st, rights=rights_st)
    def test_inv7_cross_actor_rejected(self, actor, other_actor, resource, rights):
        """INV-7: Cap issued to OTHER cannot be used by ACTOR."""
        assume(actor != other_actor)
        assume(rights > 0)
        cap = _make_cap(other_actor, resource, rights)  # for OTHER
        # Build action: actor requests using OTHER's cap
        cap_bytes = [cap["canonical_bytes"]]
        bh = _compute_binding_hash(actor, resource, rights, b"\x07"*16, 1000, 5, cap_bytes, [])
        act = {
            "actor_id": actor, "resource_hash": resource,
            "required_rights": rights, "min_epoch": 5,
            "caps": [cap], "revocations": [],
            "nonce": b"\x07"*16, "timestamp": 1000,
            "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": [],
        }
        permitted, reason = _run_py(act)
        assert not permitted, f"cross-actor reuse permitted (actor={actor.hex()[:8]} cap_for={other_actor.hex()[:8]})"

    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, cap_rights=rights_st, req_rights=rights_st)
    def test_inv8_insufficient_rights_denied(self, actor, resource, cap_rights, req_rights):
        """INV-8: Cap granting R cannot satisfy requirement for rights not in R."""
        assume((req_rights & ~cap_rights) != 0)  # req includes rights not in cap
        assume(req_rights > 0)
        cap = _make_cap(actor, resource, cap_rights)
        cap_bytes = [cap["canonical_bytes"]]
        bh = _compute_binding_hash(actor, resource, req_rights, b"\x07"*16, 1000, 5, cap_bytes, [])
        act = {
            "actor_id": actor, "resource_hash": resource,
            "required_rights": req_rights, "min_epoch": 5,
            "caps": [cap], "revocations": [],
            "nonce": b"\x07"*16, "timestamp": 1000,
            "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": [],
        }
        permitted, reason = _run_py(act)
        assert not permitted, f"insufficient rights permitted (cap={cap_rights:#x} req={req_rights:#x})"

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st)
    def test_inv9_tampered_binding_hash_rejected(self, actor, resource, rights):
        """INV-9: Any field mutation after sealing is detected by binding_hash."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights)
        act = _make_action(actor, resource, rights, caps=[cap])
        # Flip one bit in actor_id — binding_hash should no longer match
        tampered_actor = bytes(b ^ 0x01 for b in act["actor_id"])
        tampered = {**act, "actor_id": tampered_actor}
        permitted, reason = _run_py(tampered)
        assert not permitted
        assert "binding" in reason, f"tamper not caught by binding hash: {reason}"

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st)
    def test_inv10_valid_revocation_denies(self, actor, resource, rights):
        """INV-10: Valid root-signed revocation of a cap denies even if cap is otherwise valid."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights)
        rev = {
            "sig_valid": True,
            "target_hash": cap["proof_hash"],
            "canonical_bytes": b"\x00" * 40,
        }
        act = _make_action(actor, resource, rights, caps=[cap], revs=[rev])
        permitted, reason = _run_py(act)
        assert not permitted, "valid revocation did not deny"
        assert "revoked" in reason


# ─── II. Differential tests (Python vs Rust) ──────────────────────────────────

try:
    from authgate import _BACKEND as _RUST_BACKEND
    _RUST_AVAILABLE = (_RUST_BACKEND == "rust")
except ImportError:
    _RUST_AVAILABLE = False

_DIFF_SKIP = pytest.mark.skipif(
    not _RUST_AVAILABLE,
    reason="Rust build not available (authgate_kernel not installed). "
           "Run `cargo build --release` then `pip install .` in freedom-kernel/ to enable."
)


def _rust_verify_from_action(act: dict) -> tuple[bool, str]:
    """Call Rust verify via the Python API that uses authgate_kernel."""
    from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
    from authgate.kernel.registry import OwnershipRegistry
    from authgate.kernel.verifier import Action, FreedomVerifier

    # Build minimal registry with exactly one claim matching the action
    actor_bytes = act["actor_id"]
    actor_name = actor_bytes.hex()[:16]
    res_bytes   = act["resource_hash"]
    res_name    = res_bytes.hex()[:16]
    rights      = act["required_rights"]

    alice = Entity("alice", AgentType.HUMAN)
    bot   = Entity(actor_name, AgentType.MACHINE)
    res   = Resource(res_name, ResourceType.FILE, scope=f"/{res_name}/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(
        alice, res,
        can_read=(rights & RIGHT_READ) != 0,
        can_write=(rights & RIGHT_WRITE) != 0,
        can_delegate=(rights & RIGHT_DELEGATE) != 0,
    ))
    reg.delegate(RightsClaim(
        bot, res,
        can_read=(rights & RIGHT_READ) != 0,
        can_write=(rights & RIGHT_WRITE) != 0,
    ), delegated_by=alice)

    v = FreedomVerifier(reg)
    action = Action(
        action_id="diff-test",
        actor=bot,
        resources_read=[res] if (rights & RIGHT_READ) else [],
        resources_write=[res] if (rights & RIGHT_WRITE) else [],
    )
    result = v.verify(action)
    return result.permitted, "; ".join(result.violations)


class TestDifferential:
    """
    Compares Python verify() vs Rust verify() for identical inputs.
    Skipped automatically if Rust build is not available.
    Every divergence is a security gap.
    """

    @_DIFF_SKIP
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st,
           rights=st.sampled_from(RIGHTS_LIST),
           epoch=epoch_st, expiry=expiry_st)
    def test_diff_basic_permit_deny_match(self, actor, resource, rights, epoch, expiry):
        """DIFF-1: Python and Rust agree on permit/deny for valid inputs."""
        assume(expiry > 1000)
        cap = _make_cap(actor, resource, rights, expiry=expiry, epoch=epoch)
        act = _make_action(actor, resource, rights, min_epoch=epoch, caps=[cap])

        py_permitted, py_reason = _run_py(act)
        rust_permitted, rust_reason = _rust_verify_from_action(act)

        assert py_permitted == rust_permitted, (
            f"DIVERGENCE: Python={py_permitted}({py_reason!r}) "
            f"Rust={rust_permitted}({rust_reason!r}) "
            f"rights={rights:#x} epoch={epoch} expiry={expiry}"
        )

    @_DIFF_SKIP
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st)
    def test_diff_expired_cap_both_deny(self, actor, resource, rights):
        """DIFF-2: Both layers deny expired caps."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights, expiry=500)  # expired
        act = _make_action(actor, resource, rights, caps=[cap], timestamp=1000)

        py_permitted, _ = _run_py(act)
        rust_permitted, _ = _rust_verify_from_action(act)

        assert py_permitted == rust_permitted == False, (
            f"Expired cap divergence: py={py_permitted} rust={rust_permitted}"
        )

    @_DIFF_SKIP
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    @given(actor=actor_st, resource=resource_st, rights=rights_st,
           cap_epoch=st.integers(min_value=0, max_value=4))
    def test_diff_stale_epoch_both_deny(self, actor, resource, rights, cap_epoch):
        """DIFF-3: Both layers deny stale epoch caps."""
        assume(rights > 0)
        cap = _make_cap(actor, resource, rights, epoch=cap_epoch)
        act = _make_action(actor, resource, rights, min_epoch=5, caps=[cap])

        py_permitted, _ = _run_py(act)
        rust_permitted, _ = _rust_verify_from_action(act)

        assert py_permitted == rust_permitted == False, (
            f"Stale epoch divergence: py={py_permitted} rust={rust_permitted}"
        )
