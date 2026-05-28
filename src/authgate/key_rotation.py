"""
Key rotation protocol — authgate-kernel Phase 1 / MASTER_PLAN C3.

Root key compromise without rotation = permanent system compromise.
Epoch-based revocation handles capability cohort invalidation.
This module handles the root key itself.

Rotation procedure:
  1. Generate new root keypair (outside this module — use ed25519 library)
  2. Call rotate(old_sk, new_sk, new_epoch) → RotationCertificate
  3. Distribute the certificate to all verifiers
  4. Verifiers call verify_rotation(cert, old_vk) to confirm legitimacy
  5. All new capability proofs are signed with new_sk
  6. Set min_epoch = new_epoch on all actions to invalidate old-epoch caps

Grace period:
  During overlap_window_seconds, both old and new root keys are accepted.
  After the window, only the new key is valid.
  Emergency rotation: overlap_window_seconds = 0 (immediate cutover).

Wire format (JSON):
  {
    "old_pubkey":             hex string (32 bytes = 64 hex chars),
    "new_pubkey":             hex string,
    "new_epoch":              int (u64),
    "effective_at":           float (Unix timestamp),
    "overlap_window_seconds": int,
    "signature":              hex string (64 bytes = 128 hex chars),
    "version":                "authgate-rotation-v1"
  }

The signature covers all fields except itself:
  SHA-256(old_pubkey || new_pubkey || new_epoch_be8 || effective_at_be8 || overlap_be4)
  signed with old_sk (proves the old key holder authorized this rotation).
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
from dataclasses import dataclass


ROTATION_VERSION = "authgate-rotation-v1"


@dataclass(frozen=True)
class RotationCertificate:
    """A signed root key rotation certificate."""
    old_pubkey:             bytes  # 32 bytes
    new_pubkey:             bytes  # 32 bytes
    new_epoch:              int    # all caps with epoch < new_epoch are invalid after cutover
    effective_at:           float  # Unix timestamp when rotation becomes active
    overlap_window_seconds: int    # 0 = emergency (immediate), >0 = grace period
    signature:              bytes  # 64 bytes, ed25519 sig by old_sk

    @property
    def cutover_at(self) -> float:
        """Timestamp after which only new_pubkey is accepted."""
        return self.effective_at + self.overlap_window_seconds

    def is_in_grace_period(self, now: float | None = None) -> bool:
        """True if we are within the overlap window (both keys valid)."""
        t = now if now is not None else time.time()
        return self.effective_at <= t < self.cutover_at

    def is_fully_rotated(self, now: float | None = None) -> bool:
        """True if the grace period has passed — only new_pubkey valid."""
        t = now if now is not None else time.time()
        return t >= self.cutover_at

    def signing_message(self) -> bytes:
        """Canonical byte string that the old_sk signs."""
        return (
            self.old_pubkey
            + self.new_pubkey
            + struct.pack(">Q", self.new_epoch)
            + struct.pack(">d", self.effective_at)
            + struct.pack(">I", self.overlap_window_seconds)
        )

    def to_wire(self) -> dict:
        return {
            "version":                ROTATION_VERSION,
            "old_pubkey":             self.old_pubkey.hex(),
            "new_pubkey":             self.new_pubkey.hex(),
            "new_epoch":              self.new_epoch,
            "effective_at":           self.effective_at,
            "overlap_window_seconds": self.overlap_window_seconds,
            "signature":              self.signature.hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_wire(), separators=(",", ":"))

    @classmethod
    def from_wire(cls, data: dict) -> "RotationCertificate":
        if data.get("version") != ROTATION_VERSION:
            raise ValueError(
                f"Unknown rotation certificate version: {data.get('version')!r}. "
                f"Expected {ROTATION_VERSION!r}."
            )
        return cls(
            old_pubkey=             bytes.fromhex(data["old_pubkey"]),
            new_pubkey=             bytes.fromhex(data["new_pubkey"]),
            new_epoch=              int(data["new_epoch"]),
            effective_at=           float(data["effective_at"]),
            overlap_window_seconds= int(data["overlap_window_seconds"]),
            signature=              bytes.fromhex(data["signature"]),
        )

    @classmethod
    def from_json(cls, raw: str) -> "RotationCertificate":
        return cls.from_wire(json.loads(raw))


def issue_rotation(
    old_sk_sign,        # callable: bytes → bytes (ed25519 sign with old key)
    old_pubkey: bytes,  # 32-byte verifying key
    new_pubkey: bytes,  # 32-byte verifying key
    new_epoch: int,
    overlap_window_seconds: int = 3600,
    effective_at: float | None = None,
) -> RotationCertificate:
    """
    Issue a root key rotation certificate signed by the old key.

    old_sk_sign: a callable that takes bytes and returns a 64-byte ed25519
                 signature. This keeps the private key out of this module.
                 Example:
                   from ed25519_dalek import SigningKey
                   issue_rotation(lambda msg: sk.sign(msg).to_bytes(), ...)

    new_epoch: all capability proofs with epoch < new_epoch are invalidated
               after the grace period. Choose new_epoch > max(existing cap epochs).

    overlap_window_seconds: how long both keys are accepted simultaneously.
                            0 = emergency rotation (immediate cutover).
    """
    if len(old_pubkey) != 32:
        raise ValueError(f"old_pubkey must be 32 bytes, got {len(old_pubkey)}")
    if len(new_pubkey) != 32:
        raise ValueError(f"new_pubkey must be 32 bytes, got {len(new_pubkey)}")
    if old_pubkey == new_pubkey:
        raise ValueError("new_pubkey must differ from old_pubkey")
    if new_epoch < 1:
        raise ValueError("new_epoch must be >= 1 (epoch 0 is reserved for genesis)")
    if overlap_window_seconds < 0:
        raise ValueError("overlap_window_seconds must be >= 0")

    eff = effective_at if effective_at is not None else time.time()

    # Build the cert (without signature) to get the signing message
    proto = RotationCertificate(
        old_pubkey=old_pubkey,
        new_pubkey=new_pubkey,
        new_epoch=new_epoch,
        effective_at=eff,
        overlap_window_seconds=overlap_window_seconds,
        signature=b"\x00" * 64,
    )
    msg = proto.signing_message()
    sig = old_sk_sign(msg)
    if len(sig) != 64:
        raise ValueError(f"old_sk_sign must return 64-byte signature, got {len(sig)}")

    return RotationCertificate(
        old_pubkey=old_pubkey,
        new_pubkey=new_pubkey,
        new_epoch=new_epoch,
        effective_at=eff,
        overlap_window_seconds=overlap_window_seconds,
        signature=sig,
    )


def verify_rotation(
    cert: RotationCertificate,
    old_vk_verify,  # callable: (bytes, bytes) → bool (message, signature)
) -> bool:
    """
    Verify that a rotation certificate was legitimately issued by old_sk.

    old_vk_verify: callable(message: bytes, signature: bytes) -> bool.
    Returns True if the signature is valid, False otherwise.
    Never raises — verification failures are returned as False.
    """
    try:
        msg = cert.signing_message()
        return bool(old_vk_verify(msg, cert.signature))
    except Exception:
        return False


class ActiveKeySet:
    """
    Tracks which root public keys are currently accepted.

    During grace period: both old and new keys are accepted.
    After cutover: only new key is accepted.
    Before rotation: only the original key is accepted.
    """

    def __init__(self, initial_pubkey: bytes) -> None:
        self._current: bytes = initial_pubkey
        self._pending: RotationCertificate | None = None

    def apply_rotation(
        self,
        cert: RotationCertificate,
        old_vk_verify,
    ) -> None:
        """
        Apply a rotation certificate after verification.

        Raises ValueError if the cert is invalid or doesn't match current key.
        """
        if cert.old_pubkey != self._current:
            raise ValueError(
                "Rotation certificate old_pubkey does not match current active key. "
                "This may be a replay of a prior rotation or a forged certificate."
            )
        if not verify_rotation(cert, old_vk_verify):
            raise ValueError(
                "Rotation certificate signature is invalid — "
                "not signed by the current root key."
            )
        self._pending = cert

    def accepted_keys(self, now: float | None = None) -> list[bytes]:
        """Return the list of currently-accepted public keys."""
        t = now if now is not None else time.time()
        if self._pending is None:
            return [self._current]
        if t >= self._pending.cutover_at:
            # Grace period over — advance to new key
            self._current = self._pending.new_pubkey
            self._pending = None
            return [self._current]
        if t >= self._pending.effective_at:
            # In grace period — both accepted
            return [self._current, self._pending.new_pubkey]
        # Rotation not yet effective
        return [self._current]

    @property
    def current_pubkey(self) -> bytes:
        return self._current
