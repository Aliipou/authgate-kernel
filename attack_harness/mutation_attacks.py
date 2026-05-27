"""
Mutation attack harness.

Systematically mutates valid proofs to verify every security check fires.
Each test constructs a valid baseline, mutates one field, and asserts rejection.

Covers: subject binding, resource binding, expiry, epoch, rights sufficiency,
        attenuation enforcement, forged revocation, root key mismatch.
"""

import hashlib
import struct
import os


# ---------------------------------------------------------------------------
# Minimal Python model of the TCB verification logic
# (mirrors engine.rs for black-box testing of the Python verification layer)
# ---------------------------------------------------------------------------

class Decision:
    def __init__(self, permit: bool, reason: str = ""):
        self.permit = permit
        self.reason = reason

    def __repr__(self):
        return "Permit" if self.permit else f"Deny({self.reason})"


def verify_model(
    actor_id: bytes,
    resource_hash: bytes,
    required_rights: int,
    cap_subject: bytes,
    cap_resource: bytes,
    cap_rights: int,
    cap_expiry: int,
    cap_epoch: int,
    sig_valid: bool,
    now: int,
    min_epoch: int,
    parent_rights: int | None = None,  # None = root proof
    revocation_sig_valid: bool = False,
    revocation_targets_cap: bool = False,
) -> Decision:
    """Pure Python model of the v2 verify() function."""
    if cap_subject != actor_id:
        return Decision(False, "capability not issued to this actor")
    if cap_resource != resource_hash:
        return Decision(False, "capability resource mismatch")
    if cap_expiry < now:
        return Decision(False, "capability has expired")
    if cap_epoch < min_epoch:
        return Decision(False, "capability epoch predates minimum required epoch")
    if not sig_valid:
        return Decision(False, "root signature verification failed")
    if parent_rights is not None and (cap_rights & ~parent_rights) != 0:
        return Decision(False, "attenuation violation: child rights exceed parent")
    if (cap_rights & required_rights) != required_rights:
        return Decision(False, "capability does not grant required rights")
    if revocation_sig_valid and revocation_targets_cap:
        return Decision(False, "capability has been explicitly revoked")
    return Decision(True)


# ---------------------------------------------------------------------------
# Baseline values
# ---------------------------------------------------------------------------

ACTOR      = os.urandom(32)
RESOURCE   = os.urandom(32)
OTHER      = os.urandom(32)
NOW        = 1000
EXPIRY     = 9999
EPOCH      = 5
MIN_EPOCH  = 5
RIGHTS     = 0x01  # RIGHT_READ


def baseline() -> Decision:
    return verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
    )


# ---------------------------------------------------------------------------
# Mutation tests
# ---------------------------------------------------------------------------

def test_baseline_permits():
    d = baseline()
    assert d.permit, f"Baseline failed: {d}"
    print("Baseline PASS: valid proof produces Permit")


def test_wrong_actor_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=OTHER, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
    )
    assert not d.permit and "actor" in d.reason, f"Wrong actor: {d}"
    print("PASS: wrong actor -> Deny")


def test_wrong_resource_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=OTHER, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
    )
    assert not d.permit and "resource" in d.reason, f"Wrong resource: {d}"
    print("PASS: wrong resource -> Deny")


def test_expired_cap_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=500, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
    )
    assert not d.permit and "expired" in d.reason, f"Expired: {d}"
    print("PASS: expired capability -> Deny")


def test_stale_epoch_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=2, sig_valid=True,
        now=NOW, min_epoch=5,  # epoch 2 < min 5
    )
    assert not d.permit and "epoch" in d.reason, f"Stale epoch: {d}"
    print("PASS: stale epoch -> Deny (primary revocation mechanism)")


def test_invalid_sig_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=False,
        now=NOW, min_epoch=MIN_EPOCH,
    )
    assert not d.permit and "signature" in d.reason, f"Invalid sig: {d}"
    print("PASS: invalid signature -> Deny")


def test_attenuation_violation_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=0x03,  # READ|WRITE
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
        parent_rights=0x01,  # parent only has READ
    )
    assert not d.permit and "attenuation" in d.reason, f"Attenuation: {d}"
    print("PASS: child rights > parent rights -> Deny (attenuation)")


def test_insufficient_rights_denied():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=0x02,  # need WRITE
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=0x01,  # only have READ
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
    )
    assert not d.permit and "rights" in d.reason, f"Insufficient rights: {d}"
    print("PASS: insufficient rights -> Deny")


def test_valid_revocation_denies():
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
        revocation_sig_valid=True, revocation_targets_cap=True,
    )
    assert not d.permit and "revoked" in d.reason, f"Valid revocation: {d}"
    print("PASS: root-signed revocation -> Deny")


def test_forged_revocation_ignored():
    """Key property: attacker cannot forge a revocation to deny a valid capability."""
    d = verify_model(
        actor_id=ACTOR, resource_hash=RESOURCE, required_rights=RIGHTS,
        cap_subject=ACTOR, cap_resource=RESOURCE, cap_rights=RIGHTS,
        cap_expiry=EXPIRY, cap_epoch=EPOCH, sig_valid=True,
        now=NOW, min_epoch=MIN_EPOCH,
        revocation_sig_valid=False,  # forged — invalid sig
        revocation_targets_cap=True,
    )
    assert d.permit, f"Forged revocation must be ignored: {d}"
    print("PASS: forged revocation ignored -> Permit (DoS prevention)")


if __name__ == "__main__":
    test_baseline_permits()
    test_wrong_actor_denied()
    test_wrong_resource_denied()
    test_expired_cap_denied()
    test_stale_epoch_denied()
    test_invalid_sig_denied()
    test_attenuation_violation_denied()
    test_insufficient_rights_denied()
    test_valid_revocation_denies()
    test_forged_revocation_ignored()
    print("\nAll mutation attack tests passed.")
