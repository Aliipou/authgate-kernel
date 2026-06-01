/// CallGate — the only public entry point into the TCB.
///
/// AT-7.5 structural closure: `engine::verify` is `pub(crate)`, so no code
/// outside this crate can reach it directly. All external callers must go
/// through `CallGate::execute`, which unconditionally invokes verify().
///
/// This means "adapter bypasses verify()" is a compile-time type error, not
/// a runtime policy that can be misconfigured or forgotten.
///
/// # Security contract
/// - `root_key` is the trust anchor. Supply it once at construction time from
///   a secure source (HSM, provisioned secret, etc.). Never update it at runtime.
/// - `now` (Unix seconds) is caller-supplied. Clock integrity is the caller's
///   responsibility. A compromised clock is out-of-scope for this module.
/// - The `action` struct must be sealed (binding_hash computed) by the adapter
///   before calling execute(). Tampering after sealing is detected by Layer 1.
#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use crate::tcb::engine::verify;
use crate::tcb::types::{CanonicalAction, Decision};

/// The sole public gateway into the kernel.
///
/// Construct once with the trust anchor root key. Call `execute` for every
/// action that must be capability-checked.
pub struct CallGate {
    root_key: VerifyingKey,
}

impl CallGate {
    pub fn new(root_key: VerifyingKey) -> Self {
        Self { root_key }
    }

    /// Verify `action` against this gate's root key at time `now`.
    ///
    /// This is the only path that reaches `engine::verify`. No other public
    /// function exists that can invoke kernel verification.
    pub fn execute(&self, action: &CanonicalAction, now: u64) -> Decision {
        verify(action, &self.root_key, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcb::types::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    // ── Helpers (identical to tests.rs helpers; CallGate tests are self-contained) ──

    fn random_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn subject_id_of(sk: &SigningKey) -> [u8; 32] {
        Sha256::digest(sk.verifying_key().to_bytes()).into()
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
            nonce: [0x11u8; 16],
            timestamp: 1000,
            min_epoch,
            binding_hash: [0u8; 32],
        };
        a.binding_hash = a.compute_hash();
        a
    }

    fn make_revocation(root_sk: &SigningKey, target: [u8; 32]) -> RevocationProof {
        let mut rev = RevocationProof {
            target_proof_hash: target,
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
    const EPOCH:     u64       = 3;
    const MIN_EPOCH: u64       = 3;

    // ── AT-7.5: CallGate is the only way into the kernel ────────────────────
    // This cannot be tested at runtime — it's a compile-time guarantee from
    // `pub(crate)` on engine::verify. The test below verifies that the gate
    // itself works correctly; the structural guarantee is enforced by the type
    // system and documented in call_gate.rs doc comments above.

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn gate_permits_valid_read_action() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    #[test]
    fn gate_permits_valid_write_action() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_WRITE, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    #[test]
    fn gate_permits_all_rights_when_cap_covers_all() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let all = RIGHT_READ | RIGHT_WRITE | RIGHT_DELEGATE | RIGHT_EXECUTE
                | RIGHT_SPAWN | RIGHT_NETWORK | RIGHT_MODEL_INVOKE | RIGHT_POLICY_MODIFY;
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, all, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, all, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    #[test]
    fn gate_permits_superset_rights_in_cap() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    // ── Layer 1: tampered IR rejected before any proof processing ──────────

    #[test]
    fn gate_denies_tampered_required_rights() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.required_rights = RIGHT_WRITE; // tamper after sealing
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn gate_denies_tampered_actor_id() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.actor_id = OTHER;
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn gate_denies_tampered_resource_hash() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.resource_hash = OTHER;
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    #[test]
    fn gate_denies_tampered_min_epoch() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.min_epoch = 1; // attacker lowers min_epoch to allow stale caps
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "canonical binding hash mismatch" }));
    }

    // ── Wrong root key (different trust anchor) ──────────────────────────────

    #[test]
    fn gate_denies_when_constructed_with_wrong_root_key() {
        let correct_root_sk = random_key();
        let wrong_root_sk = random_key();
        // Gate uses wrong key — proofs signed by correct key will fail chain validation
        let gate = CallGate::new(wrong_root_sk.verifying_key());
        let cap = make_root_proof(&correct_root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { .. }));
    }

    // ── Subject binding ───────────────────────────────────────────────────────

    #[test]
    fn gate_denies_cap_issued_to_wrong_actor() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, OTHER, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "capability not issued to this actor" }));
    }

    // ── Expiry ────────────────────────────────────────────────────────────────

    #[test]
    fn gate_denies_expired_capability() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "capability has expired" }));
    }

    // ── Epoch gate (primary revocation) ──────────────────────────────────────

    #[test]
    fn gate_denies_stale_epoch() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, 1);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(
            gate.execute(&action, NOW),
            Decision::Deny { reason: "capability epoch predates minimum required epoch" }
        ));
    }

    // ── Resource binding ──────────────────────────────────────────────────────

    #[test]
    fn gate_denies_capability_for_different_resource() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, OTHER, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "capability resource mismatch" }));
    }

    // ── Rights sufficiency ────────────────────────────────────────────────────

    #[test]
    fn gate_denies_insufficient_rights() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_WRITE, vec![cap], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "capability does not grant required rights" }));
    }

    // ── Revocation ───────────────────────────────────────────────────────────

    #[test]
    fn gate_denies_explicitly_revoked_capability() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let rev = make_revocation(&root_sk, cap.proof_hash);
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(rev);
        action.binding_hash = action.compute_hash();
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "capability has been explicitly revoked" }));
    }

    #[test]
    fn gate_permits_when_forged_revocation_is_ignored() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let fake_rev = RevocationProof {
            target_proof_hash: cap.proof_hash,
            revoked_at: 999,
            signature: [0u8; 64], // invalid signature
        };
        let mut action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        action.revocation_proofs.push(fake_rev);
        action.binding_hash = action.compute_hash();
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    // ── Delegation chain through the gate ────────────────────────────────────

    #[test]
    fn gate_permits_valid_two_level_delegation() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let delegator_sk = random_key();
        let parent = make_root_proof(&root_sk, subject_id_of(&delegator_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let child = make_delegated_proof(&delegator_sk, &parent, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), Decision::Permit);
    }

    #[test]
    fn gate_denies_attenuation_violation_in_chain() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let delegator_sk = random_key();
        let parent = make_root_proof(&root_sk, subject_id_of(&delegator_sk), RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        // delegator claims READ|WRITE but only has READ — attenuation violation
        let child = make_delegated_proof(&delegator_sk, &parent, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![parent, child], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { .. }));
    }

    #[test]
    fn gate_denies_delegation_impersonation() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let attacker_sk = random_key();
        // Parent issued to [0xAA;32], not attacker_sk's identity
        let parent = make_root_proof(&root_sk, [0xAA; 32], RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let fake_child = make_delegated_proof(&attacker_sk, &parent, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![parent, fake_child], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { .. }));
    }

    // ── Consistency: gate and raw verify produce identical results ────────────
    // Verifies that CallGate is a thin wrapper with no added logic.

    #[test]
    fn gate_output_matches_direct_verify_on_permit() {
        use crate::tcb::engine::verify;
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, EXPIRY, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), verify(&action, &root_sk.verifying_key(), NOW));
    }

    #[test]
    fn gate_output_matches_direct_verify_on_deny() {
        use crate::tcb::engine::verify;
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let cap = make_root_proof(&root_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, EPOCH);
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![cap], MIN_EPOCH);
        assert_eq!(gate.execute(&action, NOW), verify(&action, &root_sk.verifying_key(), NOW));
    }

    // ── Empty cap bundle ──────────────────────────────────────────────────────

    #[test]
    fn gate_denies_empty_capability_bundle() {
        let root_sk = random_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let action = make_action(ACTOR, RESOURCE, RIGHT_READ, vec![], MIN_EPOCH);
        assert!(matches!(gate.execute(&action, NOW), Decision::Deny { reason: "no capability proofs provided" }));
    }
}
