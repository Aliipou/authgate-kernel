/// Hardening tests — real attack paths, malformed inputs, property invariants.
///
/// Each test answers: "what real attack does this make harder?"
/// Tests are grouped by the attack class they cover.
#[cfg(test)]
mod hardening_tests {
    use crate::tcb::dag::validate_chain;
    use crate::tcb::engine::verify;
    use crate::tcb::types::*;
    use ed25519_dalek::{SigningKey, Signer};
    use proptest::prelude::*;
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    const ACTOR:     [u8; 32] = [0xAA; 32];
    const RESOURCE:  [u8; 32] = [0xBB; 32];
    const RESOURCE2: [u8; 32] = [0xCC; 32];
    const NOW:       u64 = 10_000;
    const EXPIRY:    u64 = 99_999;
    const EPOCH:     u64 = 5;
    const MIN_EPOCH: u64 = 5;

    fn rk() -> SigningKey { SigningKey::generate(&mut OsRng) }

    fn sid(sk: &SigningKey) -> [u8; 32] {
        Sha256::digest(sk.verifying_key().to_bytes()).into()
    }

    fn root_cap(sk: &SigningKey, subject: [u8; 32], resource: [u8; 32], rights: Rights, expiry: u64, epoch: u64) -> CapabilityProof {
        let mut p = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: subject,
            resource_hash: resource,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Root,
            signature: [0; 64],
            issuer_pubkey: sk.verifying_key().to_bytes(),
        };
        p.signature = sk.sign(&p.signing_message()).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    fn delegated_cap(del_sk: &SigningKey, parent: &CapabilityProof, subject: [u8; 32], rights: Rights, expiry: u64, epoch: u64) -> CapabilityProof {
        let resource = parent.resource_hash; // same resource as parent (resource propagation)
        let mut p = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: subject,
            resource_hash: resource,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Delegated { parent_hash: parent.proof_hash },
            signature: [0; 64],
            issuer_pubkey: del_sk.verifying_key().to_bytes(),
        };
        p.signature = del_sk.sign(&p.signing_message()).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    fn seal(actor_id: [u8; 32], resource: [u8; 32], rights: Rights, caps: Vec<CapabilityProof>, min_epoch: u64) -> CanonicalAction {
        let mut a = CanonicalAction {
            actor_id,
            resource_hash: resource,
            required_rights: rights,
            capability_proofs: caps,
            revocation_proofs: vec![],
            nonce: [0xDE; 16],
            timestamp: NOW,
            min_epoch,
            binding_hash: [0; 32],
        };
        a.binding_hash = a.compute_hash();
        a
    }

    fn make_revocation(root_sk: &SigningKey, target: [u8; 32]) -> RevocationProof {
        let mut rev = RevocationProof { target_proof_hash: target, revoked_at: NOW - 1, signature: [0; 64] };
        rev.signature = root_sk.sign(&rev.signing_message()).to_bytes();
        rev
    }

    // ── AT-2: Chain resource manipulation ────────────────────────────────────
    // Attack: compromised delegator redirects root-granted authority on R1 to R2.
    // Fix: INV-RESOURCE-PROP enforced in dag.rs.

    #[test]
    fn deny_delegator_redirects_resource() {
        let root_sk = rk();
        let del_sk = rk();
        // Root grants delegator access to RESOURCE.
        let parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Delegator issues child for RESOURCE2 — a different resource.
        let mut child = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: ACTOR,
            resource_hash: RESOURCE2, // attacker substitutes different resource
            rights: RIGHT_READ,
            expiry: EXPIRY,
            epoch: EPOCH,
            issuer: IssuerRef::Delegated { parent_hash: parent.proof_hash },
            signature: [0; 64],
            issuer_pubkey: del_sk.verifying_key().to_bytes(),
        };
        child.signature = del_sk.sign(&child.signing_message()).to_bytes();
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();

        let action = seal(ACTOR, RESOURCE2, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        let result = verify(&action, &root_sk.verifying_key(), NOW);
        assert!(matches!(result, Decision::Deny { reason: "delegation chain resource mismatch" }));
    }

    #[test]
    fn deny_resource_mismatch_in_three_level_chain() {
        let root_sk = rk();
        let del1_sk = rk();
        let del2_sk = rk();
        let p1 = root_cap(&root_sk, sid(&del1_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let p2 = delegated_cap(&del1_sk, &p1, sid(&del2_sk), RIGHT_READ, EXPIRY, EPOCH);
        // del2 issues child on RESOURCE2 instead of RESOURCE
        let mut child = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: ACTOR,
            resource_hash: RESOURCE2,
            rights: RIGHT_READ,
            expiry: EXPIRY,
            epoch: EPOCH,
            issuer: IssuerRef::Delegated { parent_hash: p2.proof_hash },
            signature: [0; 64],
            issuer_pubkey: del2_sk.verifying_key().to_bytes(),
        };
        child.signature = del2_sk.sign(&child.signing_message()).to_bytes();
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();

        let action = seal(ACTOR, RESOURCE2, RIGHT_READ, vec![p1, p2, child], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    // ── AT-6: Malformed crypto inputs ────────────────────────────────────────
    // Attack: inject garbage bytes in signature/pubkey fields to confuse the verifier.

    #[test]
    fn deny_all_zeros_signature_on_root_cap() {
        let root_sk = rk();
        let mut cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        cap.signature = [0u8; 64]; // overwrite with zeros (not a valid signature)
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    #[test]
    fn deny_bit_flipped_signature_on_root_cap() {
        let root_sk = rk();
        let mut cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        cap.signature[31] ^= 0xFF; // flip last byte of S component
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    #[test]
    fn deny_wrong_signing_key_on_root_cap() {
        let root_sk = rk();
        let attacker_sk = rk();
        let root_vk = root_sk.verifying_key();
        // Sign the cap with attacker's key, but claim it's root-signed
        let mut cap = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: ACTOR,
            resource_hash: RESOURCE,
            rights: RIGHT_READ,
            expiry: EXPIRY,
            epoch: EPOCH,
            issuer: IssuerRef::Root,
            signature: [0; 64],
            issuer_pubkey: root_sk.verifying_key().to_bytes(), // claims root pubkey
        };
        cap.signature = attacker_sk.sign(&cap.signing_message()).to_bytes(); // but signed by attacker
        cap.proof_hash = Sha256::digest(cap.to_canonical_bytes()).into();
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { .. }));
    }

    #[test]
    fn deny_invalid_issuer_pubkey_in_delegated_cap() {
        let root_sk = rk();
        let del_sk = rk();
        let parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut child = delegated_cap(&del_sk, &parent, ACTOR, RIGHT_READ, EXPIRY, EPOCH);
        child.issuer_pubkey = [0u8; 32]; // not a valid curve point
        // Re-sign with the del_sk so the signature covers the bad pubkey
        child.signature = del_sk.sign(&child.signing_message()).to_bytes();
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        // VerifyingKey::from_bytes([0;32]) will fail → chain error
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    #[test]
    fn deny_all_ones_signature_on_delegated_cap() {
        let root_sk = rk();
        let del_sk = rk();
        let parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut child = delegated_cap(&del_sk, &parent, ACTOR, RIGHT_READ, EXPIRY, EPOCH);
        child.signature = [0xFF; 64]; // invalid signature bytes
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    // ── AT-2: Bundle manipulation ────────────────────────────────────────────

    #[test]
    fn deny_parent_stripped_from_bundle() {
        let root_sk = rk();
        let del_sk = rk();
        let parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let child = delegated_cap(&del_sk, &parent, ACTOR, RIGHT_READ, EXPIRY, EPOCH);
        // Bundle contains only the child, not the parent → chain traversal fails
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![child], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason: "parent proof not found in bundle" }));
    }

    #[test]
    fn permit_irrelevant_caps_in_bundle_do_not_interfere() {
        let root_sk = rk();
        let other_sk = rk();
        let valid_cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Caps for other actors — filtered by L2 (subject_id != ACTOR)
        let noise1 = root_cap(&root_sk, [0x11; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let noise2 = root_cap(&other_sk, [0x22; 32], RESOURCE, RIGHT_WRITE, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![noise1, valid_cap, noise2], MIN_EPOCH);
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn deny_cap_hash_pointing_to_wrong_parent() {
        let root_sk = rk();
        let del_sk = rk();
        let real_parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Build a decoy parent with different content (different subject)
        let decoy_parent = root_cap(&root_sk, [0xFF; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // Child references decoy_parent's hash but decoy_parent's subject != del_sk's identity
        let mut child = CapabilityProof {
            proof_hash: [0; 32],
            subject_id: ACTOR,
            resource_hash: RESOURCE,
            rights: RIGHT_READ,
            expiry: EXPIRY,
            epoch: EPOCH,
            issuer: IssuerRef::Delegated { parent_hash: decoy_parent.proof_hash },
            signature: [0; 64],
            issuer_pubkey: del_sk.verifying_key().to_bytes(),
        };
        child.signature = del_sk.sign(&child.signing_message()).to_bytes();
        child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();
        // Bundle: real_parent (correct but not referenced), decoy_parent (referenced but wrong subject)
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![real_parent, decoy_parent, child], MIN_EPOCH);
        // AT-5.1: del_sk identity != decoy_parent.subject_id → denied
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { .. }));
    }

    // ── AT-3: Revocation edge cases ──────────────────────────────────────────

    #[test]
    fn permit_revocation_targeting_nonexistent_proof_hash() {
        let root_sk = rk();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let rev = make_revocation(&root_sk, [0x00; 32]); // targets a hash not in bundle
        let mut action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(rev);
        action.binding_hash = action.compute_hash();
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn permit_fifty_forged_revocations_all_ignored() {
        let root_sk = rk();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap.clone()], MIN_EPOCH);
        for i in 0u8..50 {
            action.revocation_proofs.push(RevocationProof {
                target_proof_hash: cap.proof_hash,
                revoked_at: NOW,
                signature: [i; 64], // all invalid
            });
        }
        action.binding_hash = action.compute_hash();
        assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
    }

    #[test]
    fn deny_valid_revocation_among_forged_ones() {
        let root_sk = rk();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let valid_rev = make_revocation(&root_sk, cap.proof_hash);
        let mut action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap.clone()], MIN_EPOCH);
        // 49 forged + 1 valid revocation
        for i in 0u8..49 {
            action.revocation_proofs.push(RevocationProof {
                target_proof_hash: cap.proof_hash,
                revoked_at: NOW,
                signature: [i; 64],
            });
        }
        action.revocation_proofs.push(valid_rev);
        action.binding_hash = action.compute_hash();
        assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW),
            Decision::Deny { reason: "capability has been explicitly revoked" }));
    }

    // ── Chain depth limit ────────────────────────────────────────────────────
    // Attack: infinite-depth chains consuming memory/CPU during traversal.

    fn build_chain(root_sk: &SigningKey, num_delegators: usize) -> (Vec<CapabilityProof>, SigningKey) {
        let mut keys: Vec<SigningKey> = (0..num_delegators).map(|_| rk()).collect();
        let actor_sk = rk();

        let root_subject = if num_delegators > 0 { sid(&keys[0]) } else { ACTOR };
        let mut proofs = vec![root_cap(root_sk, root_subject, RESOURCE, RIGHT_READ, EXPIRY, EPOCH)];

        for i in 0..num_delegators {
            let parent = &proofs[i].clone();
            let subject = if i + 1 < num_delegators { sid(&keys[i + 1]) } else { sid(&actor_sk) };
            let cap = delegated_cap(&keys[i], parent, subject, RIGHT_READ, EXPIRY, EPOCH);
            proofs.push(cap);
        }
        (proofs, actor_sk)
    }

    #[test]
    fn permit_chain_at_max_depth_minus_one() {
        // 16 nodes total (root + 14 delegators + actor_cap) — well within MAX_CHAIN_DEPTH=16
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let (mut proofs, actor_sk) = build_chain(&root_sk, 14);
        let actor_cap_idx = proofs.len() - 1;
        // The last proof's subject is actor_sk's identity; actor sends action using that identity
        let actor_id = proofs[actor_cap_idx].subject_id;
        // Seal action with the full bundle
        let action = seal(actor_id, RESOURCE, RIGHT_READ, proofs.clone(), MIN_EPOCH);
        let _ = actor_sk; // used for identity derivation
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn deny_chain_exceeding_max_depth() {
        // 19 nodes total → iterates 19 times → depth=18 > 16 → error on 19th iteration
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let (proofs, actor_sk) = build_chain(&root_sk, 18);
        let actor_id = proofs[proofs.len() - 1].subject_id;
        let action = seal(actor_id, RESOURCE, RIGHT_READ, proofs, MIN_EPOCH);
        let _ = actor_sk;
        assert!(matches!(verify(&action, &root_vk, NOW),
            Decision::Deny { reason: "delegation chain depth limit exceeded" }));
    }

    // ── Stateless / replay ───────────────────────────────────────────────────
    // The kernel is stateless: replay protection is the orchestration layer's job.
    // These tests verify the stateless contract, not a gap.

    #[test]
    fn same_valid_action_permits_twice() {
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn action_timestamp_is_not_enforced_by_kernel() {
        // timestamp is in the binding hash but not checked for freshness — by design
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        // Recompute with a very old timestamp — still permits (clock is caller's concern)
        action.timestamp = 0;
        action.binding_hash = action.compute_hash();
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    // ── Rights arithmetic edge cases ─────────────────────────────────────────

    #[test]
    fn zero_required_rights_always_permits() {
        // required_rights=0: 0 & cap.rights == 0 == required_rights → always sufficient
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, 0, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn deny_u64_max_required_rights_unless_cap_has_all_bits() {
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, u64::MAX, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability does not grant required rights" }));
    }

    #[test]
    fn permit_u64_max_required_rights_when_cap_has_all_bits() {
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, u64::MAX, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, u64::MAX, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn deny_single_missing_bit_in_rights() {
        // Cap has all bits except bit 7 (POLICY_MODIFY); action requires bit 7
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap_rights = u64::MAX & !RIGHT_POLICY_MODIFY;
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, cap_rights, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, RIGHT_POLICY_MODIFY, vec![cap], MIN_EPOCH);
        assert!(matches!(verify(&action, &root_vk, NOW), Decision::Deny { reason: "capability does not grant required rights" }));
    }

    #[test]
    fn non_standard_high_bit_rights_works() {
        // Rights bitmask is u64; any bit can be used
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let custom_right = 1u64 << 63;
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, custom_right, EXPIRY, EPOCH);
        let action = seal(ACTOR, RESOURCE, custom_right, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    // ── Epoch / expiry boundary precision ───────────────────────────────────

    #[test]
    fn permit_u64_max_min_epoch_when_cap_epoch_is_u64_max() {
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, u64::MAX);
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], u64::MAX);
        assert_eq!(verify(&action, &root_vk, NOW), Decision::Permit);
    }

    #[test]
    fn deny_u64_max_min_epoch_when_cap_epoch_is_finite() {
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, 999);
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], u64::MAX);
        assert!(matches!(verify(&action, &root_vk, NOW),
            Decision::Deny { reason: "capability epoch predates minimum required epoch" }));
    }

    #[test]
    fn permit_now_equals_u64_max_expiry_u64_max() {
        // expiry < now is false when both are u64::MAX → not expired
        let root_sk = rk();
        let root_vk = root_sk.verifying_key();
        let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, u64::MAX, EPOCH);
        let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(verify(&action, &root_vk, u64::MAX), Decision::Permit);
    }

    // ── Proptest: arithmetic invariants ──────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any cap_epoch < min_epoch → Deny (epoch gate is total)
        #[test]
        fn prop_stale_epoch_always_denied(
            cap_epoch in 0u64..500,
            extra    in 1u64..500,
        ) {
            let min_epoch = cap_epoch + extra;
            let root_sk = rk();
            let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, cap_epoch);
            let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], min_epoch);
            prop_assert!(matches!(
                verify(&action, &root_sk.verifying_key(), NOW),
                Decision::Deny { reason: "capability epoch predates minimum required epoch" }
            ));
        }

        /// Any cap.expiry < now → Deny (expiry gate is total)
        #[test]
        fn prop_expired_cap_always_denied(
            expiry in 0u64..9_999,
            extra  in 1u64..1_000,
        ) {
            let now = expiry + extra;
            let root_sk = rk();
            let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, expiry, EPOCH);
            let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
            prop_assert!(matches!(
                verify(&action, &root_sk.verifying_key(), now),
                Decision::Deny { reason: "capability has expired" }
            ));
        }

        /// Any bit in required_rights not present in cap.rights → Deny
        #[test]
        fn prop_missing_right_bit_always_denied(bit_pos in 0u32..64) {
            let missing_bit = 1u64 << bit_pos;
            let cap_rights = !missing_bit; // all bits except the required one
            let required = missing_bit;
            let root_sk = rk();
            let cap = root_cap(&root_sk, ACTOR, RESOURCE, cap_rights, EXPIRY, EPOCH);
            let action = seal(ACTOR, RESOURCE, required, vec![cap], MIN_EPOCH);
            prop_assert!(matches!(
                verify(&action, &root_sk.verifying_key(), NOW),
                Decision::Deny { reason: "capability does not grant required rights" }
            ));
        }

        /// If cap.rights is a superset of required_rights, rights check passes
        #[test]
        fn prop_superset_rights_pass_rights_check(extra_bits in 0u64..u64::MAX) {
            let required = RIGHT_READ | RIGHT_WRITE;
            let cap_rights = required | extra_bits; // required bits + any extras
            let root_sk = rk();
            let cap = root_cap(&root_sk, ACTOR, RESOURCE, cap_rights, EXPIRY, EPOCH);
            let action = seal(ACTOR, RESOURCE, required, vec![cap], MIN_EPOCH);
            prop_assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
        }

        /// Modifying any byte of actor_id or resource_hash after sealing → binding mismatch
        #[test]
        fn prop_tamper_actor_id_byte_denies(byte_idx in 0usize..32, flip in 1u8..=255) {
            let root_sk = rk();
            let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
            let mut action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
            action.actor_id[byte_idx] ^= flip;
            prop_assert!(matches!(
                verify(&action, &root_sk.verifying_key(), NOW),
                Decision::Deny { reason: "canonical binding hash mismatch" }
            ));
        }

        /// Attenuation: child rights superset of parent rights → chain denied
        #[test]
        fn prop_attenuation_violation_always_denied(extra_bit in 0u32..64) {
            let parent_rights = RIGHT_READ;
            let extra = 1u64 << extra_bit;
            prop_assume!(extra & parent_rights == 0); // ensure extra_bit not already in parent
            let child_rights = parent_rights | extra; // superset → violation
            let root_sk = rk();
            let del_sk = rk();
            let parent = root_cap(&root_sk, sid(&del_sk), RESOURCE, parent_rights, EXPIRY, EPOCH);
            let mut child = CapabilityProof {
                proof_hash: [0; 32],
                subject_id: ACTOR,
                resource_hash: RESOURCE,
                rights: child_rights,
                expiry: EXPIRY,
                epoch: EPOCH,
                issuer: IssuerRef::Delegated { parent_hash: parent.proof_hash },
                signature: [0; 64],
                issuer_pubkey: del_sk.verifying_key().to_bytes(),
            };
            child.signature = del_sk.sign(&child.signing_message()).to_bytes();
            child.proof_hash = Sha256::digest(child.to_canonical_bytes()).into();
            let action = seal(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
            prop_assert!(matches!(
                verify(&action, &root_sk.verifying_key(), NOW),
                Decision::Deny { reason: "attenuation violation: child rights exceed parent" }
            ));
        }
    }
}
