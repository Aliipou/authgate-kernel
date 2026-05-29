"""
Tests for Phase 1/O4: Signed Audit Export.

AuditLog.export_signed() → signed dict
AuditLog.verify_signed_export() → bool
"""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authgate.kernel.audit import AuditLog


def _make_result(action_id="test-action", permitted=True, violations=(), warnings=(), confidence=1.0):
    from types import SimpleNamespace
    return SimpleNamespace(
        action_id=action_id,
        permitted=permitted,
        violations=violations,
        warnings=warnings,
        confidence=confidence,
    )


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class TestExportSigned:
    def test_export_returns_required_keys(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        assert "head_hash" in export
        assert "entry_count" in export
        assert "export_ts" in export
        assert "signature" in export
        assert "verifying_key" in export

    def test_export_entry_count_matches(self):
        log = AuditLog()
        for i in range(5):
            log.record(_make_result(action_id=f"action-{i}"))
        sk = _private_key()
        export = log.export_signed(sk)
        assert export["entry_count"] == 5

    def test_export_head_hash_matches_log_head(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        assert export["head_hash"] == log.head_hash()

    def test_empty_log_export(self):
        log = AuditLog()
        sk = _private_key()
        export = log.export_signed(sk)
        assert export["entry_count"] == 0
        assert export["head_hash"] == "0" * 64

    def test_wrong_key_type_raises(self):
        log = AuditLog()
        with pytest.raises(TypeError, match="Ed25519PrivateKey"):
            log.export_signed("not-a-key")


class TestVerifySignedExport:
    def test_valid_export_verifies_true(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        assert AuditLog.verify_signed_export(export) is True

    def test_tampered_head_hash_fails(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        export["head_hash"] = "0" * 64  # tamper
        assert AuditLog.verify_signed_export(export) is False

    def test_tampered_entry_count_fails(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        export["entry_count"] = 999
        assert AuditLog.verify_signed_export(export) is False

    def test_tampered_signature_fails(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        export = log.export_signed(sk)
        # Flip last byte of signature
        import base64
        sig = base64.b64decode(export["signature"])
        sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        export["signature"] = base64.b64encode(sig).decode()
        assert AuditLog.verify_signed_export(export) is False

    def test_verify_with_external_key_object(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        vk = sk.public_key()
        export = log.export_signed(sk)
        assert AuditLog.verify_signed_export(export, verifying_key=vk) is True

    def test_verify_with_wrong_key_fails(self):
        log = AuditLog()
        log.record(_make_result())
        sk = _private_key()
        other_sk = _private_key()
        export = log.export_signed(sk)
        assert AuditLog.verify_signed_export(export, verifying_key=other_sk.public_key()) is False

    def test_multiple_records_verify(self):
        log = AuditLog()
        for i in range(10):
            log.record(_make_result(action_id=f"a{i}", permitted=(i % 2 == 0)))
        sk = _private_key()
        export = log.export_signed(sk)
        assert export["entry_count"] == 10
        assert AuditLog.verify_signed_export(export) is True
