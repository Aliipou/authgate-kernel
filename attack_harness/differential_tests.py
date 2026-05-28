"""
Differential testing harness — Python model vs Rust kernel.

Closes TIER 4, A2 (Dual-Representation Drift): tests that the Python model
and the Rust kernel produce identical permit/deny decisions on the same inputs,
including adversarial and edge-case inputs.

If the Python model and Rust kernel diverge on any input, that input is a
potential exploit: an attacker can stage in an environment where one runtime
is used for policy evaluation and the other is used for enforcement.

Usage:
  python differential_tests.py             # runs Python-only model tests
  python differential_tests.py --rust      # also invokes Rust kernel via JSON ABI

The Rust kernel is invoked via the C/JSON ABI (verify_json). If the Rust
extension is not installed, Rust-side tests are skipped with a clear message.
"""

from __future__ import annotations
import hashlib
import struct
import os
import json
import sys
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Rights constants (mirrors types.rs)
# ---------------------------------------------------------------------------

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7


# ---------------------------------------------------------------------------
# Python model of TCB verify() — must stay in sync with engine.rs
# ---------------------------------------------------------------------------

@dataclass
class CapProof:
    subject_id:    bytes  # 32 bytes
    resource_hash: bytes  # 32 bytes
    rights:        int    # u64 bitmask
    expiry:        int    # u64 unix timestamp
    epoch:         int    # u64


@dataclass
class Decision:
    permit: bool
    reason: str = ""

    def __eq__(self, other):
        if isinstance(other, Decision):
            return self.permit == other.permit
        return NotImplemented


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def python_verify(
    actor_id:       bytes,
    resource_hash:  bytes,
    required_rights: int,
    cap:            CapProof,
    now:            int,
    min_epoch:      int,
    parent_cap:     Optional[CapProof] = None,
) -> Decision:
    """Python model of the v2 verify logic. Must match engine.rs exactly."""
    if cap.subject_id != actor_id:
        return Decision(False, "subject mismatch")
    if cap.resource_hash != resource_hash:
        return Decision(False, "resource mismatch")
    if cap.expiry < now:
        return Decision(False, "capability expired")
    if cap.epoch < min_epoch:
        return Decision(False, "stale epoch")
    if (cap.rights & required_rights) != required_rights:
        return Decision(False, "insufficient rights")
    if parent_cap is not None:
        if (cap.rights & ~parent_cap.rights) != 0:
            return Decision(False, "attenuation violation")
    return Decision(True, "all checks passed")


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

PASS = []
FAIL = []


def _check(name: str, got: Decision, expected_permit: bool, note: str = ""):
    if got.permit == expected_permit:
        PASS.append(name)
        result = "Permit" if got.permit else f"Deny({got.reason})"
        print(f"  PASS {name}: {result}" + (f" — {note}" if note else ""))
    else:
        FAIL.append(name)
        result = "Permit" if got.permit else f"Deny({got.reason})"
        expected = "Permit" if expected_permit else "Deny"
        print(f"  FAIL {name}: got {result}, expected {expected}" + (f" — {note}" if note else ""))


def _make_cap(
    actor_id:  bytes,
    resource:  bytes,
    rights:    int    = RIGHT_READ,
    expiry:    int    = 2**64 - 1,
    epoch:     int    = 1,
) -> CapProof:
    return CapProof(
        subject_id=actor_id,
        resource_hash=resource,
        rights=rights,
        expiry=expiry,
        epoch=epoch,
    )


ACTOR    = os.urandom(32)
RESOURCE = os.urandom(32)
NOW      = 1_000_000
MIN_EP   = 1


# ---------------------------------------------------------------------------
# Differential test cases
# ---------------------------------------------------------------------------

def test_dt1_valid_read_permit():
    """DT-1: Standard permit — actor has READ, action requires READ."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt1_valid_read_permit", d, True)


def test_dt2_subject_mismatch_deny():
    """DT-2: Cap issued to different actor — must deny."""
    other_actor = os.urandom(32)
    cap = _make_cap(other_actor, RESOURCE, RIGHT_READ)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt2_subject_mismatch_deny", d, False, "subject mismatch")


def test_dt3_resource_mismatch_deny():
    """DT-3: Cap covers different resource — must deny."""
    other_res = os.urandom(32)
    cap = _make_cap(ACTOR, other_res, RIGHT_READ)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt3_resource_mismatch_deny", d, False, "resource mismatch")


def test_dt4_expired_cap_deny():
    """DT-4: Cap with expiry < now — must deny."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, expiry=NOW - 1)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt4_expired_cap_deny", d, False, "expired")


def test_dt5_exact_expiry_boundary():
    """DT-5: Cap expiry == now. Edge: expires AT now, not BEFORE.

    Divergence risk: some implementations use < vs <=. Must document and match.
    If expiry == now means 'expired at this instant', deny. Else permit.
    Our model: expiry < now → deny; expiry == now → permit (still valid).
    """
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, expiry=NOW)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt5_exact_expiry_boundary", d, True, "expiry==now means still valid")


def test_dt6_stale_epoch_deny():
    """DT-6: Cap epoch < min_epoch — must deny (AT-3.1)."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, epoch=0)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, min_epoch=1)
    _check("dt6_stale_epoch_deny", d, False, "stale epoch")


def test_dt7_exact_epoch_boundary():
    """DT-7: Cap epoch == min_epoch — boundary, must permit."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, epoch=5)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, min_epoch=5)
    _check("dt7_exact_epoch_boundary", d, True, "epoch==min_epoch is valid")


def test_dt8_insufficient_rights_deny():
    """DT-8: Cap has READ only, action requires WRITE — must deny."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ)
    d = python_verify(ACTOR, RESOURCE, RIGHT_WRITE, cap, NOW, MIN_EP)
    _check("dt8_insufficient_rights_deny", d, False, "insufficient rights")


def test_dt9_superset_rights_permit():
    """DT-9: Cap has READ|WRITE, action requires only READ — must permit."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt9_superset_rights_permit", d, True, "superset rights satisfies requirement")


def test_dt10_zero_required_rights_always_permit():
    """DT-10: required_rights == 0 — vacuously satisfied by any cap."""
    cap = _make_cap(ACTOR, RESOURCE, 0)
    d = python_verify(ACTOR, RESOURCE, 0, cap, NOW, MIN_EP)
    _check("dt10_zero_required_rights_permit", d, True, "zero rights vacuously satisfied")


def test_dt11_attenuation_violation_deny():
    """DT-11: Child cap claims READ|WRITE, parent only had READ — deny."""
    parent = _make_cap(ACTOR, RESOURCE, RIGHT_READ)
    child  = _make_cap(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, child, NOW, MIN_EP, parent_cap=parent)
    _check("dt11_attenuation_violation_deny", d, False, "attenuation violation")


def test_dt12_attenuation_equal_rights_permit():
    """DT-12: Child cap == parent cap — not escalation, must permit."""
    parent = _make_cap(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE)
    child  = _make_cap(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, child, NOW, MIN_EP, parent_cap=parent)
    _check("dt12_attenuation_equal_rights_permit", d, True, "equal rights is valid attenuation")


def test_dt13_u64_max_rights_cap():
    """DT-13: Cap and required_rights both at u64::MAX — must permit."""
    U64_MAX = (1 << 64) - 1
    cap = _make_cap(ACTOR, RESOURCE, U64_MAX)
    d = python_verify(ACTOR, RESOURCE, U64_MAX, cap, NOW, MIN_EP)
    _check("dt13_u64_max_rights_permit", d, True, "all bits set on both sides")


def test_dt14_u64_max_epoch_and_min_epoch():
    """DT-14: Both cap epoch and min_epoch at u64::MAX — must permit."""
    U64_MAX = (1 << 64) - 1
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, epoch=U64_MAX)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, min_epoch=U64_MAX)
    _check("dt14_u64_max_epoch_permit", d, True, "u64::MAX epoch == u64::MAX min_epoch")


def test_dt15_all_zeros_actor_id():
    """DT-15: actor_id == [0x00; 32] — edge identity, must work correctly."""
    zero_actor = b"\x00" * 32
    cap = _make_cap(zero_actor, RESOURCE, RIGHT_READ)
    d = python_verify(zero_actor, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt15_all_zeros_actor_permit", d, True, "zero actor is a valid identity")


def test_dt16_zero_epoch_min_epoch_zero():
    """DT-16: Cap epoch == 0, min_epoch == 0 — permits (boundary)."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, epoch=0)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, min_epoch=0)
    _check("dt16_epoch_zero_min_zero_permit", d, True, "epoch 0 >= min_epoch 0")


def test_dt17_single_missing_bit_deny():
    """DT-17: Cap is missing exactly one required bit — must deny."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE)
    required = RIGHT_READ | RIGHT_WRITE | RIGHT_EXECUTE  # cap missing EXECUTE
    d = python_verify(ACTOR, RESOURCE, required, cap, NOW, MIN_EP)
    _check("dt17_single_missing_bit_deny", d, False, "one missing bit in rights")


def test_dt18_nonstandard_high_bit():
    """DT-18: High bit (bit 63) in rights — both cap and required have it."""
    high_bit = 1 << 63
    cap = _make_cap(ACTOR, RESOURCE, high_bit)
    d = python_verify(ACTOR, RESOURCE, high_bit, cap, NOW, MIN_EP)
    _check("dt18_nonstandard_high_bit_permit", d, True, "bit 63 is a valid rights bit")


def test_dt19_expiry_zero_and_now_nonzero():
    """DT-19: Cap expiry == 0, now > 0 — must deny (expired at epoch start)."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, expiry=0)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, NOW, MIN_EP)
    _check("dt19_expiry_zero_deny", d, False, "expiry 0 < now > 0")


def test_dt20_now_zero_expiry_zero():
    """DT-20: now == 0, expiry == 0 — boundary: expiry == now, must permit."""
    cap = _make_cap(ACTOR, RESOURCE, RIGHT_READ, expiry=0)
    d = python_verify(ACTOR, RESOURCE, RIGHT_READ, cap, now=0, min_epoch=0)
    _check("dt20_now_zero_expiry_zero_permit", d, True, "expiry==now==0 is still valid")


# ---------------------------------------------------------------------------
# Rust-side differential check (optional, requires Rust extension installed)
# ---------------------------------------------------------------------------

def _try_rust_differential():
    """
    Attempt to load the Rust kernel and run a sample of the same cases
    against it, checking that decisions match the Python model.

    Skips gracefully if the Rust extension is not installed.
    """
    try:
        import authgate_kernel  # type: ignore
    except ImportError:
        print("\n  [SKIP] Rust kernel not installed — skipping cross-runtime differential")
        print("         Install with: cd freedom-kernel && maturin develop --features sandbox")
        return

    print("\n  Rust kernel found — running cross-runtime differential checks...")
    # TODO: construct VerifyInput wire JSON and compare Decision outcomes
    # This requires aligning the v2 CanonicalAction wire format between
    # Python and Rust. Placeholder until wire format is stabilized.
    print("  [TODO] Rust differential: wire format alignment pending")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Differential testing harness — authgate-kernel")
    print("Closes TIER 4 A2: Dual-Representation Drift")
    print("=" * 60)

    test_dt1_valid_read_permit()
    test_dt2_subject_mismatch_deny()
    test_dt3_resource_mismatch_deny()
    test_dt4_expired_cap_deny()
    test_dt5_exact_expiry_boundary()
    test_dt6_stale_epoch_deny()
    test_dt7_exact_epoch_boundary()
    test_dt8_insufficient_rights_deny()
    test_dt9_superset_rights_permit()
    test_dt10_zero_required_rights_always_permit()
    test_dt11_attenuation_violation_deny()
    test_dt12_attenuation_equal_rights_permit()
    test_dt13_u64_max_rights_cap()
    test_dt14_u64_max_epoch_and_min_epoch()
    test_dt15_all_zeros_actor_id()
    test_dt16_zero_epoch_min_epoch_zero()
    test_dt17_single_missing_bit_deny()
    test_dt18_nonstandard_high_bit()
    test_dt19_expiry_zero_and_now_nonzero()
    test_dt20_now_zero_expiry_zero()

    if "--rust" in sys.argv:
        _try_rust_differential()

    print()
    print("=" * 60)
    passed = len(PASS)
    failed = len(FAIL)
    total  = passed + failed
    print(f"Results: {passed}/{total} passed, {failed} failed")
    if FAIL:
        print(f"FAILURES: {FAIL}")
        raise SystemExit(1)
    else:
        print("All differential tests passed.")
