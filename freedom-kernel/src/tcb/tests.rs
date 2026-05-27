/// Comprehensive test suite for the v2 TCB.
///
/// Coverage target: every security check in engine.rs fires in isolation,
/// every security check is NOT triggered on the happy path, and every
/// possible ordered pair of (single violation, otherwise valid proof) is tested.
///
/// Test naming convention:
///   happy_*        — valid input, expect Permit
///   deny_*         — single mutation, expect Deny with specific reason
///   edge_*         — boundary / corner cases
///   compose_*      — composition (SequenceContext) tests
///   chain_*        — delegation chain tests
#[cfg(test)]
mod tcb_tests {
    use crate::tcb::dag::validate_chain;
    use crate::tcb::engine::verify;
    use crate::tcb::sequence::SequenceContext;
    use crate::tcb::types::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn random_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_root_proof(
        root_sk: &SigningKey,
        subject: [u8; 32],
        resource: [u8; 32],
        rights: Rights,
        expiry: u64,
        epoch: u64,
    ) -> CapabilityProof {
        let issuer_pubkey = root_sk.verifying_key().to_bytes();
        let mut p = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id: subject,
            resource_hash: resource,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Root,
            signature: [0u8; 64],
            issuer_pubkey,
        };
        p.signature = root_sk.sign(&p.signing_message()).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    fn make_delegated_proof(
        delegator_sk: &SigningKey,
        parent: &CapabilityProof,
        subject: [u8; 32],
        resource: [u8; 32],
        rights: Rights,
        expiry: u64,
        epoch: u64,
    ) -> CapabilityProof {
        let issuer_pubkey = delegator_sk.verifying_key().to_bytes();
        let mut p = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id: subject,
            resource_hash: resource,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Delegated { parent_hash: parent.proof_hash },
            signature: [0u8; 64],
            issuer_pubkey,
        };
        p.signature = delegator_sk.sign(&p.signing_message()).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    fn make_action(
        actor_id: [u8; 32],
        resource_hash: [u8; 32],
        required_rights: Rights,
        caps: Vec<CapabilityProof>,
        min_epoch: u64,
    ) -> CanonicalAction {
        let mut a = CanonicalAction {
            actor_id,
            resource_hash,
            required_rights,
            capability_proofs: caps,
            revocation_proofs: vec![],
            nonce: [7u8; 16],
            timestamp: 1000,
            min_epoch,
            binding_hash: [0u8; 32],
        };
        a.binding_hash = a.compute_hash();
        a
    }

    fn make_valid_revocation(
        root_sk: &SigningKey,
        target_hash: [u8; 32],
    ) -> RevocationProof {
        let mut rev = RevocationProof {
            target_proof_hash: target_hash,
            revoked_at: 900,
            signature: [0u8; 64],
        };
        rev.signature = root_sk.sign(&rev.signing_message()).to_bytes();
        rev
    }

    const ACTOR:     [u8; 32] = [0x01; 32];
    const RESOURCE:  [u8; 32] = [0x02; 32];
    const OTHER:     [u8; 32] = [0x09; 32];
    const NOW:       u64       = 1000;
    const EXPIRY:    u64       = 9999;
    const EPOCH:     u64       = 5;
    const MIN_EPOCH: u64       = 5;

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn happy_read_permit() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_write_permit() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_WRITE, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_multiple_rights_permit() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_superset_rights_permit() {
        // Cap grants READ|WRITE, action only requires READ — should Permit
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_expiry_at_exact_now_permit() {
        // expiry == now is valid (not expired): condition is expiry < now
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, NOW, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_epoch_at_exact_min_permit() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, MIN_EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn happy_zero_min_epoch_permits_any_epoch() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, 0);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], 0);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    // ── Canonical gate (Layer 1) ─────────────────────────────────────────────

    #[test]
    fn deny_tampered_required_rights() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.required_rights = RIGHT_WRITE; // tamper after sealing
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn deny_tampered_actor_id() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.actor_id = OTHER;
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn deny_tampered_resource_hash() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.resource_hash = OTHER;
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn deny_tampered_min_epoch() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.min_epoch = 1; // attacker tries to lower min_epoch after sealing
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn deny_empty_capability_proofs() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "no capability proofs provided" }));
    }

    // ── Subject binding (Bug 3) ──────────────────────────────────────────────

    #[test]
    fn deny_wrong_actor() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        // Proof issued to OTHER, but action is by ACTOR
        let cap = make_root_proof(&root_sk, OTHER, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability not issued to this actor" }));
    }

    #[test]
    fn deny_zero_actor_with_nonzero_subject() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, [0x01; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action([0x00; 32], RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability not issued to this actor" }));
    }

    // ── Resource binding (Bug 4) ─────────────────────────────────────────────

    #[test]
    fn deny_wrong_resource() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, OTHER, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability resource mismatch" }));
    }

    // ── Expiry ───────────────────────────────────────────────────────────────

    #[test]
    fn deny_expired_by_one() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability has expired" }));
    }

    #[test]
    fn deny_zero_expiry() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, 0, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability has expired" }));
    }

    // ── Epoch gate (primary revocation) ─────────────────────────────────────

    #[test]
    fn deny_stale_epoch_by_one() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, MIN_EPOCH - 1);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(
            verify(&action, &root_vk, NOW),
            Decision::Deny { reason: "capability epoch predates minimum required epoch" }
        ));
    }

    #[test]
    fn deny_epoch_zero_with_min_epoch_one() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, 0);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], 1);
        assert!(matches!(
            verify(&action, &root_vk, NOW),
            Decision::Deny { reason: "capability epoch predates minimum required epoch" }
        ));
    }

    // ── Chain validation (Bug 2: signatures) ────────────────────────────────

    #[test]
    fn deny_wrong_root_key() {
        let root_sk = random_key();
        let wrong_sk = random_key();
        let wrong_vk = wrong_sk.verifying_key();
        // Proof is signed by root_sk but we verify with wrong_vk
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &wrong_vk, NOW), Decision::Deny { .. }));
    }

    #[test]
    fn deny_zeroed_signature() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let mut cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        cap.signature = [0u8; 64]; // corrupt the signature
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { .. }));
    }

    // ── Attenuation (Bug 5) ──────────────────────────────────────────────────

    #[test]
    fn deny_attenuation_violation() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let delegator_sk = random_key();

        // Parent: READ only
        let parent = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Child claims READ | WRITE — violation
        let child = make_delegated_proof(&delegator_sk, &parent, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child.clone()], MIN_EPOCH);
        let result = verify(&action, &root_vk, NOW);
        assert!(matches!(result, Decision::Deny { reason: "attenuation violation: child rights exceed parent" }));
    }

    #[test]
    fn chain_equal_rights_permitted() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let delegator_sk = random_key();

        let parent = make_root_proof(&root_sk, [0xAA; 32], RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let child = make_delegated_proof(&delegator_sk, &parent, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    // ── Revocation ───────────────────────────────────────────────────────────

    #[test]
    fn deny_valid_revocation() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let cap_hash = cap.proof_hash;
        let rev = make_valid_revocation(&root_sk, cap_hash);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(rev);
        action.binding_hash = action.compute_hash();
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability has been explicitly revoked" }));
    }

    #[test]
    fn permit_forged_revocation_ignored() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let fake_rev = RevocationProof {
            target_proof_hash: cap.proof_hash,
            revoked_at: 999,
            signature: [0u8; 64], // invalid
        };
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(fake_rev);
        action.binding_hash = action.compute_hash();
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn permit_revocation_for_different_proof_ignored() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Valid revocation but targeting a different proof hash
        let rev = make_valid_revocation(&root_sk, [0xFF; 32]);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(rev);
        action.binding_hash = action.compute_hash();
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    // ── Rights sufficiency ───────────────────────────────────────────────────

    #[test]
    fn deny_read_only_cap_for_write_action() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_WRITE, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability does not grant required rights" }));
    }

    #[test]
    fn deny_no_rights_cap() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, 0, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability does not grant required rights" }));
    }

    // ── Composition (SequenceContext) ────────────────────────────────────────

    #[test]
    fn compose_accumulated_rights_are_monotone() {
        let mut ctx = SequenceContext::new();
        ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100);
        let after_read = ctx.accumulated_rights();
        ctx.record(ACTOR, RESOURCE, RIGHT_WRITE, 101);
        let after_write = ctx.accumulated_rights();
        assert!(after_write >= after_read);
        assert!((after_write & RIGHT_READ) != 0);
    }

    #[test]
    fn compose_exceeds_limit_read_only_session() {
        let mut ctx = SequenceContext::new();
        ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100);
        assert!(!ctx.exceeds_limit(RIGHT_READ));
        ctx.record(ACTOR, RESOURCE, RIGHT_WRITE, 101);
        assert!(ctx.exceeds_limit(RIGHT_READ));
    }

    #[test]
    fn compose_zero_limit_rejects_all() {
        let mut ctx = SequenceContext::new();
        ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100);
        assert!(ctx.exceeds_limit(0));
    }

    #[test]
    fn compose_step_count_tracks_all_records() {
        let mut ctx = SequenceContext::new();
        ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100);
        ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100); // replay
        assert_eq!(ctx.step_count(), 2);
    }

    #[test]
    fn compose_empty_context_within_any_limit() {
        let ctx = SequenceContext::new();
        assert!(!ctx.exceeds_limit(0xFFFF_FFFF_FFFF_FFFF));
        assert!(!ctx.exceeds_limit(0));
    }

    // ── DAG chain validation standalone ─────────────────────────────────────

    #[test]
    fn chain_missing_parent_rejected() {
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();
        let delegator_sk = random_key();
        let fake_parent_hash = [0xDE; 32];
        let mut child = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id: ACTOR,
            resource_hash: RESOURCE,
            rights: RIGHT_READ,
            expiry: EXPIRY,
            epoch: EPOCH,
            issuer: IssuerRef::Delegated { parent_hash: fake_parent_hash },
            signature: [0u8; 64],
            issuer_pubkey: delegator_sk.verifying_key().to_bytes(),
        };
        child.signature = delegator_sk.sign(&child.signing_message()).to_bytes();
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();
        // Bundle has no parent matching fake_parent_hash
        let result = validate_chain(&child, &[child.clone()], &root_vk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parent proof not found"));
    }

    #[test]
    fn chain_depth_limit_enforced() {
        // Build a chain of MAX_CHAIN_DEPTH + 1 — should fail
        let root_sk = random_key();
        let root_vk = root_sk.verifying_key();

        let mut all_proofs = Vec::new();
        let mut prev = make_root_proof(&root_sk, [0xA0; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        all_proofs.push(prev.clone());

        for i in 0..17u8 {
            let sk = random_key();
            let next = make_delegated_proof(&sk, &prev, [i; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
            all_proofs.push(next.clone());
            prev = next;
        }

        let result = validate_chain(all_proofs.last().unwrap(), &all_proofs, &root_vk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("depth limit"));
    }
}
