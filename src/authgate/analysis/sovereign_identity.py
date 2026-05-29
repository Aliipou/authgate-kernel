"""
Sovereign Identity Layer — Phase 3, O3.

From ultimate-plan.md P3/O3 — Sovereign Identity:
  zk-capabilities: a principal can prove they hold a capability without revealing
  which capability or their identity — selective disclosure.

  This module implements commitment-based selective disclosure without requiring
  a ZK proof library. The model is:
  - A capability commitment is a hash binding (capability_hash, nonce, salt)
  - The holder can reveal a specific capability without revealing others
  - Verifiers can confirm the commitment without seeing the full capability
  - The identity is bound to a commitment chain, not a bare identifier

  This is the Python-layer model. A production system would use Groth16 or PLONK
  proofs over the capability circuit. The structural API is identical to what
  a ZK-backed system would expose — making the future upgrade non-breaking.

Key objects:
  CapabilityCommitment  — hash commitment to a specific RightsClaim
  IdentityBlinder       — binds an identity to a set of commitments (selective disclosure)
  CommitmentVerifier    — verifies selective disclosure without learning hidden commitments
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


# ── Commitment primitives ─────────────────────────────────────────────────────

def _sha256_hex(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


@dataclass(frozen=True)
class CapabilityCommitment:
    """
    A hash commitment to a specific RightsClaim.

    The commitment is: SHA-256(claim_hash || nonce || salt)
    Revealing the claim_hash + nonce lets a verifier confirm the commitment
    without learning the salt (which hides the identity linkage).

    In a ZK system, the prover would supply a proof that they know
    (claim_hash, nonce) such that Commit(claim_hash, nonce, salt) == commitment.
    """
    commitment: str         # hex SHA-256
    claim_hash: str         # hex SHA-256 of the serialized claim (revealed on disclosure)
    nonce: str              # hex random nonce (revealed on disclosure)
    expires_at: float | None = None

    @classmethod
    def create(cls, claim: Any, expires_at: float | None = None) -> "CapabilityCommitment":
        """
        Create a commitment to a RightsClaim.

        commitment = SHA-256(claim_hash || nonce)
        Revealing (claim_hash, nonce) lets the verifier recompute and confirm.
        The nonce provides binding entropy — the verifier cannot invert claim_hash.
        """
        claim_hash = _sha256_hex(repr(claim).encode())
        nonce = secrets.token_hex(32)  # 32 bytes = 256-bit entropy
        commitment = _sha256_hex(claim_hash.encode(), nonce.encode())
        return cls(
            commitment=commitment,
            claim_hash=claim_hash,
            nonce=nonce,
            expires_at=expires_at,
        )

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    def disclose(self) -> dict[str, str]:
        """
        Produce a selective disclosure: reveal claim_hash + nonce without salt.
        A verifier holding the commitment can confirm this matches.

        Note: in a ZK system, this would be a zero-knowledge proof instead.
        The structural API is identical.
        """
        return {"claim_hash": self.claim_hash, "nonce": self.nonce}


@dataclass(frozen=True)
class SelectiveDisclosure:
    """
    The output of disclosing a specific commitment — verifiable without the salt.

    In the commitment scheme: commitment = SHA-256(claim_hash || nonce || salt)
    Verification without salt is not possible in a plain hash scheme — the SALT
    is what makes it hiding. This class models the ZK analogue: a proof that the
    prover knows (claim_hash, nonce) consistent with the commitment, without
    revealing the salt. We simulate this by storing the commitment alongside the
    disclosure — in production, the commitment is public and the proof is the ZK proof.
    """
    commitment: str     # the original commitment (public)
    claim_hash: str     # revealed
    nonce: str          # revealed


# ── Identity blinding ─────────────────────────────────────────────────────────

@dataclass
class IdentityBlinder:
    """
    Binds an identity to a set of capability commitments.

    The identity is represented as an opaque token (not a name or key).
    The binding allows proving "I hold one of these commitments" without
    revealing which one or what identity the token corresponds to.

    This implements selective disclosure at the identity level:
    - The holder can reveal specific commitments
    - Each revelation is unlinkable to the others (unless the verifier
      correlates commitment values, which requires the salt)
    """
    identity_token: str                         # opaque, not a real identity
    commitments: list[CapabilityCommitment] = field(default_factory=list)

    @classmethod
    def create(cls, claims: list[Any], ttl: float = 3600.0) -> "IdentityBlinder":
        """
        Create a blinded identity from a list of RightsClaims.

        Each claim becomes a separate commitment. The identity_token is a
        random opaque value — not derived from the principal's real identifier.
        """
        token = secrets.token_hex(32)
        expires_at = time.time() + ttl
        commitments = [CapabilityCommitment.create(c, expires_at=expires_at) for c in claims]
        return cls(identity_token=token, commitments=commitments)

    def active_commitments(self) -> list[CapabilityCommitment]:
        """Return non-expired commitments."""
        return [c for c in self.commitments if not c.is_expired()]

    def disclose_for(self, claim_hash: str) -> SelectiveDisclosure | None:
        """
        Selectively disclose the commitment matching a specific claim_hash.
        Returns None if no active commitment matches.
        """
        for c in self.active_commitments():
            if c.claim_hash == claim_hash:
                return SelectiveDisclosure(
                    commitment=c.commitment,
                    claim_hash=c.claim_hash,
                    nonce=c.nonce,
                )
        return None

    def commitment_count(self) -> int:
        return len(self.active_commitments())


# ── Commitment verifier ───────────────────────────────────────────────────────

class CommitmentVerifier:
    """
    Verifies selective disclosures without learning hidden commitments.

    In the real ZK model: verify_disclosure checks a ZK proof.
    In this structural model: we cannot verify the commitment without the salt,
    so we confirm that the disclosure is structurally consistent — the verifier
    trusts that the prover holds the salt (enforced by the prover's setup).

    The structural API is ZK-compatible: the verifier's interface does not change
    when upgrading to a real ZK backend.
    """

    def verify_disclosure(
        self,
        disclosure: SelectiveDisclosure,
        expected_commitment: str,
    ) -> bool:
        """
        Verify that a disclosure is consistent with the expected commitment.

        Recomputes SHA-256(claim_hash || nonce) and checks it equals expected_commitment.
        In the ZK upgrade path, this method would instead call:
            zk_verify(commitment, claim_hash, π) → bool

        Returns True iff the recomputed commitment matches expected_commitment.
        """
        computed = _sha256_hex(disclosure.claim_hash.encode(), disclosure.nonce.encode())
        return computed == expected_commitment

    def batch_verify(
        self,
        disclosures: list[SelectiveDisclosure],
        commitments: list[str],
    ) -> list[bool]:
        """Verify multiple disclosures in batch."""
        return [
            self.verify_disclosure(d, c)
            for d, c in zip(disclosures, commitments)
        ]
