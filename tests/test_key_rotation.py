"""
Key rotation protocol tests -- Phase 1 C3.
"""
from __future__ import annotations
import time
import hashlib
import hmac

import pytest

from authgate.key_rotation import (
    ActiveKeySet,
    RotationCertificate,
    issue_rotation,
    verify_rotation,
)


def _fake_sk(seed: bytes):
    def sign(msg: bytes) -> bytes:
        return hmac.new(seed, msg, hashlib.sha256).digest() * 2
    return sign, seed

def _fake_vk(seed: bytes):
    def verify(msg: bytes, sig: bytes) -> bool:
        expected = hmac.new(seed, msg, hashlib.sha256).digest() * 2
        return hmac.compare_digest(sig, expected)
    return verify


OLD_SEED = b"old-root-key-seed-exactly-32byte"
NEW_SEED = b"new-root-key-seed-exactly-32byte"

old_sign, OLD_PUBKEY = _fake_sk(OLD_SEED)
new_sign, NEW_PUBKEY = _fake_sk(NEW_SEED)
old_verify = _fake_vk(OLD_SEED)


class TestRotationCertificate:
    def test_issue_and_verify(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10)
        assert verify_rotation(cert, old_verify)

    def test_wrong_verifier_rejects(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10)
        wrong_verify = _fake_vk(NEW_SEED)
        assert not verify_rotation(cert, wrong_verify)

    def test_wire_roundtrip(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=5, overlap_window_seconds=3600)
        wire = cert.to_wire()
        restored = RotationCertificate.from_wire(wire)
        assert restored.old_pubkey == cert.old_pubkey
        assert restored.new_pubkey == cert.new_pubkey
        assert restored.new_epoch  == cert.new_epoch
        assert restored.signature  == cert.signature

    def test_json_roundtrip(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=7)
        restored = RotationCertificate.from_json(cert.to_json())
        assert restored == cert

    def test_wrong_version_rejected(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=1)
        wire = cert.to_wire()
        wire["version"] = "authgate-rotation-v99"
        with pytest.raises(ValueError, match="Unknown rotation"):
            RotationCertificate.from_wire(wire)

    def test_same_pubkey_rejected(self):
        with pytest.raises(ValueError, match="must differ"):
            issue_rotation(old_sign, OLD_PUBKEY, OLD_PUBKEY, new_epoch=5)

    def test_zero_epoch_rejected(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=0)

    def test_emergency_rotation_zero_overlap(self):
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=5, overlap_window_seconds=0)
        assert cert.overlap_window_seconds == 0
        assert cert.cutover_at == cert.effective_at


class TestGracePeriod:
    def test_in_grace_period(self):
        now = time.time()
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=3600, effective_at=now - 60)
        assert cert.is_in_grace_period(now)
        assert not cert.is_fully_rotated(now)

    def test_after_cutover(self):
        now = time.time()
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=3600, effective_at=now - 7200)
        assert not cert.is_in_grace_period(now)
        assert cert.is_fully_rotated(now)

    def test_before_effective(self):
        now = time.time()
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=3600, effective_at=now + 600)
        assert not cert.is_in_grace_period(now)
        assert not cert.is_fully_rotated(now)


class TestActiveKeySet:
    def test_initial_only_current_key(self):
        ks = ActiveKeySet(OLD_PUBKEY)
        assert ks.accepted_keys() == [OLD_PUBKEY]

    def test_in_grace_period_both_keys_accepted(self):
        now = time.time()
        ks = ActiveKeySet(OLD_PUBKEY)
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=3600, effective_at=now - 60)
        ks.apply_rotation(cert, old_verify)
        keys = ks.accepted_keys(now)
        assert OLD_PUBKEY in keys
        assert NEW_PUBKEY in keys

    def test_after_cutover_only_new_key(self):
        now = time.time()
        ks = ActiveKeySet(OLD_PUBKEY)
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=3600, effective_at=now - 7200)
        ks.apply_rotation(cert, old_verify)
        keys = ks.accepted_keys(now)
        assert keys == [NEW_PUBKEY]
        assert ks.current_pubkey == NEW_PUBKEY

    def test_wrong_old_pubkey_rejected(self):
        ks = ActiveKeySet(NEW_PUBKEY)
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10)
        with pytest.raises(ValueError, match="does not match current"):
            ks.apply_rotation(cert, old_verify)

    def test_invalid_signature_rejected(self):
        ks = ActiveKeySet(OLD_PUBKEY)
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10)
        wrong_verify = _fake_vk(NEW_SEED)
        with pytest.raises(ValueError, match="signature is invalid"):
            ks.apply_rotation(cert, wrong_verify)

    def test_emergency_rotation_immediate_cutover(self):
        now = time.time()
        ks = ActiveKeySet(OLD_PUBKEY)
        cert = issue_rotation(old_sign, OLD_PUBKEY, NEW_PUBKEY, new_epoch=10,
                              overlap_window_seconds=0, effective_at=now - 1)
        ks.apply_rotation(cert, old_verify)
        keys = ks.accepted_keys(now)
        assert keys == [NEW_PUBKEY]
