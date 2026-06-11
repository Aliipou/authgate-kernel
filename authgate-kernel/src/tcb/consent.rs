#![forbid(unsafe_code)]
//! ConsentRecord — first-class consent in the TCB (Theory_to_Engineering_Plan GAP 1).
//!
//! A `ConsentRecord` is a signed statement by a *grantor* (the party whose
//! resource or person is affected) that a *grantee* (the acting principal)
//! may exercise specific rights over a specific resource. It is the
//! legitimacy counterpart to a `CapabilityProof`: the capability says the
//! actor *can*, the consent says the affected party *agrees*.
//!
//! # Trust assumptions (honest statement)
//!
//! The `requires_consent` flag on `CanonicalAction` is set by the UNTRUSTED
//! adapter layer — exactly the same trust assumption as `required_rights`.
//! The kernel cannot know, from first principles, which actions touch a
//! consent-requiring resource; the adapter (or a policy layer above it)
//! decides that. What the kernel guarantees:
//!
//! - The flag and the consent proofs are folded into the canonical
//!   `binding_hash`, so any tampering AFTER construction (flipping
//!   `requires_consent` off, swapping or stripping consent proofs) is
//!   detected and denied as "canonical binding hash mismatch".
//! - When the flag is set, no Permit is possible without at least one
//!   cryptographically valid, unexpired, unrevoked consent that matches the
//!   actor, the resource, and covers all required rights.
//!
//! An adapter that never sets `requires_consent` simply does not buy this
//! protection — same as an adapter that under-states `required_rights`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::tcb::types::{Bytes16, Bytes32, Bytes64, Rights};

/// A signed consent grant from `grantor` to `grantee` over a resource.
///
/// Identity model matches the rest of the TCB: `grantor` is
/// `SHA-256(grantor_pubkey)`, and the signature is an ed25519 signature by
/// the grantor's key over `signing_message()`.
#[derive(Debug, Clone)]
pub struct ConsentRecord {
    /// Identity hash of the consenting party: SHA-256(grantor_pubkey).
    pub grantor: Bytes32,
    /// Identity hash of the principal the consent is granted to.
    pub grantee: Bytes32,
    /// SHA-256 of the canonical resource descriptor this consent covers.
    pub resource_hash: Bytes32,
    /// Rights bitmask the grantor consents to.
    pub rights: Rights,
    /// Unix seconds after which this consent is void. 0 = never expires.
    pub expires_at: u64,
    /// Whether the grantor may later revoke this consent.
    /// Non-revocable consents ignore revocation proofs targeting them.
    pub revocable: bool,
    /// Random nonce — distinguishes otherwise-identical consent grants.
    pub nonce: Bytes16,
    /// SHA-256(grantor ‖ grantee ‖ resource_hash ‖ rights(be) ‖ nonce).
    /// Stable identifier; revocation proofs target this hash.
    pub consent_id: Bytes32,
    /// ed25519 signature by the grantor's key over `signing_message()`.
    pub signature: Bytes64,
    /// Public key of the grantor (32 bytes, ed25519 compressed point).
    pub grantor_pubkey: Bytes32,
}

impl ConsentRecord {
    /// Canonical bytes over which `signature` is computed.
    /// Field order is fixed — any change is a protocol version bump.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(160);
        msg.extend_from_slice(&self.grantor);
        msg.extend_from_slice(&self.grantee);
        msg.extend_from_slice(&self.resource_hash);
        msg.extend_from_slice(&self.rights.to_be_bytes());
        msg.extend_from_slice(&self.expires_at.to_be_bytes());
        msg.push(self.revocable as u8);
        msg.extend_from_slice(&self.nonce);
        msg.extend_from_slice(&self.consent_id);
        msg.extend_from_slice(&self.grantor_pubkey);
        msg
    }

    /// Canonical bytes for inclusion in `CanonicalAction::compute_hash()`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(224);
        b.extend_from_slice(&self.grantor);
        b.extend_from_slice(&self.grantee);
        b.extend_from_slice(&self.resource_hash);
        b.extend_from_slice(&self.rights.to_be_bytes());
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b.push(self.revocable as u8);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.consent_id);
        b.extend_from_slice(&self.signature);
        b.extend_from_slice(&self.grantor_pubkey);
        b
    }

    /// Recompute the stable consent identifier from the record's fields.
    /// SHA-256(grantor ‖ grantee ‖ resource_hash ‖ rights(be) ‖ nonce).
    pub fn compute_consent_id(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(self.grantor);
        h.update(self.grantee);
        h.update(self.resource_hash);
        h.update(self.rights.to_be_bytes());
        h.update(self.nonce);
        h.finalize().into()
    }
}

/// Verify a single consent record against the requesting action's context.
///
/// Checks, in order:
/// 1. The grantor identity binds to the embedded public key.
/// 2. The consent was granted to the requesting actor.
/// 3. The consent covers the resource being accessed.
/// 4. The consented rights cover every required right.
/// 5. The consent has not expired (expires_at == 0 means never).
/// 6. The consent_id is consistent with the record's fields.
/// 7. The grantor's ed25519 signature is valid (checked last — it is the
///    most expensive step, and the cheap structural checks gate it).
///
/// Revocation is NOT checked here — the engine cross-references root-signed
/// `RevocationProof`s against `consent_id` (see `engine::verify`).
pub(crate) fn verify_consent(
    c: &ConsentRecord,
    actor_id: Bytes32,
    resource_hash: Bytes32,
    required_rights: Rights,
    now: u64,
) -> Result<(), &'static str> {
    let expected_grantor: Bytes32 = Sha256::digest(c.grantor_pubkey).into();
    if c.grantor != expected_grantor {
        return Err("consent grantor identity mismatch");
    }
    if c.grantee != actor_id {
        return Err("consent not granted to this actor");
    }
    if c.resource_hash != resource_hash {
        return Err("consent resource mismatch");
    }
    if (c.rights & required_rights) != required_rights {
        return Err("consent does not cover required rights");
    }
    if c.expires_at != 0 && c.expires_at < now {
        return Err("consent has expired");
    }
    if c.consent_id != c.compute_consent_id() {
        return Err("consent id mismatch");
    }
    let vk = VerifyingKey::from_bytes(&c.grantor_pubkey)
        .map_err(|_| "consent signature invalid")?;
    let sig = Signature::from_bytes(&c.signature);
    vk.verify(&c.signing_message(), &sig)
        .map_err(|_| "consent signature invalid")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcb::engine::verify;
    use crate::tcb::types::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    const NOW: u64 = 1000;

    fn build_root_cap(
        root_sk: &SigningKey,
        subject: Bytes32,
        resource: Bytes32,
        rights: Rights,
    ) -> CapabilityProof {
        let mut p = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id: subject,
            resource_hash: resource,
            rights,
            expiry: u64::MAX,
            epoch: 1,
            issuer: IssuerRef::Root,
            signature: [0u8; 64],
            issuer_pubkey: root_sk.verifying_key().to_bytes(),
        };
        p.signature = root_sk.sign(&p.signing_message()).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    /// Build a fully signed ConsentRecord. grantor = SHA-256(grantor_pubkey).
    fn build_consent(
        grantor_sk: &SigningKey,
        grantee: Bytes32,
        resource_hash: Bytes32,
        rights: Rights,
        expires_at: u64,
        revocable: bool,
    ) -> ConsentRecord {
        let grantor_pubkey = grantor_sk.verifying_key().to_bytes();
        let grantor: Bytes32 = Sha256::digest(grantor_pubkey).into();
        let mut c = ConsentRecord {
            grantor,
            grantee,
            resource_hash,
            rights,
            expires_at,
            revocable,
            nonce: [0x33u8; 16],
            consent_id: [0u8; 32],
            signature: [0u8; 64],
            grantor_pubkey,
        };
        c.consent_id = c.compute_consent_id();
        c.signature = grantor_sk.sign(&c.signing_message()).to_bytes();
        c
    }

    fn seal_action(
        actor_id: Bytes32,
        resource_hash: Bytes32,
        required_rights: Rights,
        caps: Vec<CapabilityProof>,
        requires_consent: bool,
        consent_proofs: Vec<ConsentRecord>,
        revocation_proofs: Vec<RevocationProof>,
    ) -> CanonicalAction {
        let mut a = CanonicalAction {
            actor_id,
            resource_hash,
            required_rights,
            capability_proofs: caps,
            revocation_proofs,
            nonce: [0x77u8; 16],
            timestamp: NOW,
            min_epoch: 1,
            requires_consent,
            consent_proofs,
            binding_hash: [0u8; 32],
        };
        a.binding_hash = a.compute_hash();
        a
    }

    fn make_revocation(root_sk: &SigningKey, target: Bytes32) -> RevocationProof {
        let mut rev = RevocationProof {
            target_proof_hash: target,
            revoked_at: NOW - 1,
            signature: [0u8; 64],
        };
        rev.signature = root_sk.sign(&rev.signing_message()).to_bytes();
        rev
    }

    const ACTOR: Bytes32 = [1u8; 32];
    const RESOURCE: Bytes32 = [2u8; 32];

    #[test]
    fn no_consent_required_unaffected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], false, vec![], vec![]);
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn valid_matching_consent_permits() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn missing_consent_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![], vec![]);
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn wrong_grantee_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        // Consent granted to somebody else, not ACTOR.
        let consent = build_consent(&grantor_sk, [9u8; 32], RESOURCE, RIGHT_READ, 0, true);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn wrong_resource_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, [8u8; 32], RIGHT_READ, 0, true);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn expired_consent_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, true);
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn zero_expiry_means_never_expires() {
        let consent = build_consent(
            &SigningKey::generate(&mut OsRng), ACTOR, RESOURCE, RIGHT_READ, 0, true,
        );
        assert_eq!(
            verify_consent(&consent, ACTOR, RESOURCE, RIGHT_READ, u64::MAX),
            Ok(())
        );
    }

    #[test]
    fn insufficient_rights_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE);
        // Consent covers READ only, but the action requires READ|WRITE.
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        let action = seal_action(
            ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, vec![cap], true, vec![consent], vec![],
        );
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn bad_signature_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let mut consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        consent.signature = [0u8; 64];
        // Sealed AFTER tampering so the binding hash is consistent — the
        // signature check itself must catch this.
        let action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn grantor_identity_mismatch_denied() {
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let mut consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        consent.grantor = [0xAB; 32]; // does not hash-bind to grantor_pubkey
        assert_eq!(
            verify_consent(&consent, ACTOR, RESOURCE, RIGHT_READ, NOW),
            Err("consent grantor identity mismatch")
        );
    }

    #[test]
    fn consent_id_mismatch_denied() {
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let mut consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        consent.consent_id = [0xCD; 32];
        assert_eq!(
            verify_consent(&consent, ACTOR, RESOURCE, RIGHT_READ, NOW),
            Err("consent id mismatch")
        );
    }

    #[test]
    fn revoked_revocable_consent_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        let rev = make_revocation(&root_sk, consent.consent_id);
        let action = seal_action(
            ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![rev],
        );
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "consent required but absent, invalid, or revoked" }
        ));
    }

    #[test]
    fn non_revocable_consent_ignores_revocation() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, false);
        let rev = make_revocation(&root_sk, consent.consent_id);
        let action = seal_action(
            ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![rev],
        );
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn forged_consent_revocation_ignored() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        // Revocation NOT signed by root — must be ignored.
        let fake_rev = RevocationProof {
            target_proof_hash: consent.consent_id,
            revoked_at: NOW - 1,
            signature: [0u8; 64],
        };
        let action = seal_action(
            ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![fake_rev],
        );
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn one_valid_consent_among_invalid_permits() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let expired = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, true);
        let valid = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        let action = seal_action(
            ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![expired, valid], vec![],
        );
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn tampering_consent_proofs_after_sealing_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let grantor_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let consent = build_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
        let mut action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![consent], vec![]);
        // Strip the consent after sealing — binding hash must catch it.
        action.consent_proofs.clear();
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "canonical binding hash mismatch" }
        ));
    }

    #[test]
    fn flipping_requires_consent_after_sealing_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let cap = build_root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
        let mut action = seal_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], true, vec![], vec![]);
        // Adversary flips the flag off after sealing to dodge the consent gate.
        action.requires_consent = false;
        assert!(matches!(
            verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "canonical binding hash mismatch" }
        ));
    }
}
