"""Tests for Phase 3/O3: Sovereign Identity Layer (commitment-based selective disclosure)."""
import time

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.analysis.sovereign_identity import (
    CapabilityCommitment,
    CommitmentVerifier,
    IdentityBlinder,
    SelectiveDisclosure,
)


def _claim() -> RightsClaim:
    bot = Entity("bot", AgentType.MACHINE)
    res = Resource("data", ResourceType.DATASET, scope="/data/")
    return RightsClaim(bot, res, can_read=True)


class TestCapabilityCommitment:
    def test_create_returns_commitment(self):
        claim = _claim()
        c = CapabilityCommitment.create(claim)
        assert len(c.commitment) == 64  # hex SHA-256
        assert len(c.claim_hash) == 64
        assert len(c.nonce) == 64  # 32 bytes hex

    def test_two_commits_of_same_claim_differ(self):
        claim = _claim()
        c1 = CapabilityCommitment.create(claim)
        c2 = CapabilityCommitment.create(claim)
        assert c1.commitment != c2.commitment  # salt differs

    def test_not_expired_by_default(self):
        claim = _claim()
        c = CapabilityCommitment.create(claim, expires_at=time.time() + 3600)
        assert not c.is_expired()

    def test_expired_past_expiry(self):
        claim = _claim()
        c = CapabilityCommitment.create(claim, expires_at=time.time() - 1)
        assert c.is_expired()

    def test_no_expiry_never_expired(self):
        claim = _claim()
        c = CapabilityCommitment.create(claim)
        assert not c.is_expired()

    def test_disclose_returns_claim_hash_and_nonce(self):
        claim = _claim()
        c = CapabilityCommitment.create(claim)
        d = c.disclose()
        assert d["claim_hash"] == c.claim_hash
        assert d["nonce"] == c.nonce

    def test_claim_hash_is_deterministic_for_same_claim(self):
        claim = _claim()
        c1 = CapabilityCommitment.create(claim)
        c2 = CapabilityCommitment.create(claim)
        assert c1.claim_hash == c2.claim_hash  # same claim → same hash


class TestIdentityBlinder:
    def test_create_from_claims(self):
        claims = [_claim(), _claim()]
        blinder = IdentityBlinder.create(claims)
        assert blinder.commitment_count() == 2
        assert len(blinder.identity_token) == 64  # 32 bytes hex

    def test_identity_token_differs_per_creation(self):
        claims = [_claim()]
        b1 = IdentityBlinder.create(claims)
        b2 = IdentityBlinder.create(claims)
        assert b1.identity_token != b2.identity_token

    def test_active_commitments_excludes_expired(self):
        claims = [_claim()]
        blinder = IdentityBlinder.create(claims, ttl=-1)  # immediately expired
        assert blinder.active_commitments() == []

    def test_disclose_for_known_hash(self):
        claim = _claim()
        blinder = IdentityBlinder.create([claim])
        expected_hash = blinder.active_commitments()[0].claim_hash
        disclosure = blinder.disclose_for(expected_hash)
        assert disclosure is not None
        assert disclosure.claim_hash == expected_hash

    def test_disclose_for_unknown_hash_returns_none(self):
        claim = _claim()
        blinder = IdentityBlinder.create([claim])
        assert blinder.disclose_for("0" * 64) is None

    def test_disclose_for_expired_returns_none(self):
        claim = _claim()
        blinder = IdentityBlinder.create([claim], ttl=-1)
        hash_ = blinder.commitments[0].claim_hash
        assert blinder.disclose_for(hash_) is None

    def test_empty_claims_zero_commitments(self):
        blinder = IdentityBlinder.create([])
        assert blinder.commitment_count() == 0


class TestCommitmentVerifier:
    def _setup(self):
        claim = _claim()
        blinder = IdentityBlinder.create([claim])
        commitment = blinder.active_commitments()[0]
        disclosure = blinder.disclose_for(commitment.claim_hash)
        return commitment, disclosure

    def test_valid_disclosure_verifies(self):
        commitment, disclosure = self._setup()
        verifier = CommitmentVerifier()
        assert verifier.verify_disclosure(disclosure, commitment.commitment)

    def test_wrong_expected_commitment_fails(self):
        _, disclosure = self._setup()
        verifier = CommitmentVerifier()
        assert not verifier.verify_disclosure(disclosure, "0" * 64)

    def test_tampered_disclosure_nonce_fails(self):
        commitment, disclosure = self._setup()
        tampered = SelectiveDisclosure(
            commitment=commitment.commitment,
            claim_hash=disclosure.claim_hash,
            nonce="aa" * 32,   # wrong nonce — recomputed hash will not match
        )
        verifier = CommitmentVerifier()
        # Verifier recomputes SHA-256(claim_hash || nonce) — mismatch detected
        assert not verifier.verify_disclosure(tampered, commitment.commitment)

    def test_batch_verify_all_valid(self):
        verifier = CommitmentVerifier()
        bot = Entity("bot", AgentType.MACHINE)
        # Three DISTINCT claims (different resources) so claim_hashes differ
        claims = [
            RightsClaim(bot, Resource(f"res-{i}", ResourceType.DATASET, scope=f"/d{i}/"), can_read=True)
            for i in range(3)
        ]
        blinder = IdentityBlinder.create(claims)
        comms = blinder.active_commitments()
        disclosures = [blinder.disclose_for(c.claim_hash) for c in comms]
        results = verifier.batch_verify(disclosures, [c.commitment for c in comms])
        assert all(results)

    def test_commitment_matches_stored(self):
        commitment, disclosure = self._setup()
        assert disclosure.commitment == commitment.commitment

    def test_multiple_disclosures_unlinkable(self):
        # Two disclosures from same identity should have different commitment values
        claim1 = _claim()
        claim2 = _claim()
        blinder = IdentityBlinder.create([claim1, claim2])
        comms = blinder.active_commitments()
        assert comms[0].commitment != comms[1].commitment
