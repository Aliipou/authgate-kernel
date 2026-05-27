/// v2 stateless verify function — the TCB core.
///
/// Design decisions (settled):
///   - Option B: root key passed as parameter. No global singleton. Caller controls trust anchor.
///   - Epoch-based primary revocation: advancing `min_epoch` in the action invalidates
///     all proofs from prior epochs without distributing explicit revocation lists.
///     This closes the "stale-but-valid resurrection" gap that cryptographic revocation
///     proof checking alone cannot close in distributed/cached deployments.
///   - Revocation proofs: secondary, emergency mechanism for targeted single-proof revocation.
///     Only root-signed revocations are accepted (Bug 1 fix).
///   - Canonical gate checked first: any IR tampering between adapter and kernel
///     is caught before any proof is parsed (Bug 6 fix).
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use crate::v2::types::{CanonicalAction, Decision, RevocationProof};
use crate::v2::dag::validate_chain;

/// Verify an action. Stateless — no global state, no side effects, no allocator beyond
/// what Vec operations require.
///
/// # Arguments
/// - `action` — canonical, tamper-evident action request from the (untrusted) adapter layer.
/// - `root_key` — the trust anchor. Caller is responsible for establishing this securely.
/// - `now` — current Unix seconds. Caller is responsible for clock integrity.
pub fn verify(
    action: &CanonicalAction,
    root_key: &VerifyingKey,
    now: u64,
) -> Decision {
    // ── Layer 1: Canonical gate ──────────────────────────────────────────────
    // Reject tampered IR before touching any proof. Constant-time comparison
    // inside verify_binding() prevents oracle attacks on the hash check.
    if !action.verify_binding() {
        return Decision::Deny { reason: "canonical binding hash mismatch" };
    }

    // A request with no capability proofs cannot possibly be permitted.
    if action.capability_proofs.is_empty() {
        return Decision::Deny { reason: "no capability proofs provided" };
    }

    // ── Layer 2: Capability proof validation ─────────────────────────────────
    for cap in &action.capability_proofs {
        // Bug 3 fix: the proof must have been issued to the requesting actor.
        if cap.subject_id != action.actor_id {
            return Decision::Deny { reason: "capability not issued to this actor" };
        }

        // Bug 4 fix: the proof must cover the resource being accessed.
        if cap.resource_hash != action.resource_hash {
            return Decision::Deny { reason: "capability resource mismatch" };
        }

        // Time-based expiry.
        if cap.expiry < now {
            return Decision::Deny { reason: "capability has expired" };
        }

        // Epoch-based revocation (primary mechanism).
        // Closing the "stale-but-valid resurrection" gap:
        // Even a cryptographically valid, non-expired proof is rejected if it
        // was issued in an epoch prior to what the caller requires. The epoch
        // acts as a lightweight "fresh enough" proof-of-currency.
        if cap.epoch < action.min_epoch {
            return Decision::Deny { reason: "capability epoch predates minimum required epoch" };
        }

        // Bug 2 + Bug 5 fix: full chain with signatures + attenuation enforcement.
        if let Err(reason) = validate_chain(cap, &action.capability_proofs, root_key) {
            return Decision::Deny { reason };
        }

        // Rights sufficiency check.
        if (cap.rights & action.required_rights) != action.required_rights {
            return Decision::Deny { reason: "capability does not grant required rights" };
        }
    }

    // ── Layer 3: Revocation proof processing (secondary, emergency mechanism) ─
    // Bug 1 fix: only root-signed revocations are accepted.
    // An invalid signature is silently ignored — attackers cannot forge a
    // revocation of a valid capability, nor can they deny service by injecting
    // garbage revocation proofs (those are simply skipped).
    for rev in &action.revocation_proofs {
        if !verify_revocation_sig(rev, root_key) {
            continue;
        }
        for cap in &action.capability_proofs {
            if cap.proof_hash == rev.target_proof_hash {
                return Decision::Deny { reason: "capability has been explicitly revoked" };
            }
        }
    }

    Decision::Permit
}

fn verify_revocation_sig(rev: &RevocationProof, root_key: &VerifyingKey) -> bool {
    let Ok(sig) = Signature::from_bytes(&rev.signature) else {
        return false;
    };
    root_key.verify(&rev.signing_message(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::types::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    fn build_root_proof(
        root_sk: &SigningKey,
        subject: Bytes32,
        resource: Bytes32,
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

    fn build_action(
        actor_id: Bytes32,
        resource_hash: Bytes32,
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
            nonce: [0u8; 16],
            timestamp: 1000,
            min_epoch,
            binding_hash: [0u8; 32],
        };
        a.binding_hash = a.compute_hash();
        a
    }

    #[test]
    fn happy_path_permit() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let actor = [1u8; 32];
        let resource = [2u8; 32];
        let cap = build_root_proof(&root_sk, actor, resource, RIGHT_READ, u64::MAX, 1);
        let action = build_action(actor, resource, RIGHT_READ, vec![cap], 1);
        assert_eq!(verify(&action, &root_vk, 1000), Decision::Permit);
    }

    #[test]
    fn wrong_actor_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let alice = [1u8; 32];
        let bob = [9u8; 32];
        let resource = [2u8; 32];
        let cap = build_root_proof(&root_sk, alice, resource, RIGHT_READ, u64::MAX, 1);
        // Bob uses Alice's proof
        let action = build_action(bob, resource, RIGHT_READ, vec![cap], 1);
        assert!(matches!(verify(&action, &root_vk, 1000), Decision::Deny { .. }));
    }

    #[test]
    fn expired_capability_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let actor = [1u8; 32];
        let resource = [2u8; 32];
        let cap = build_root_proof(&root_sk, actor, resource, RIGHT_READ, 500, 1);
        let action = build_action(actor, resource, RIGHT_READ, vec![cap], 1);
        assert!(matches!(verify(&action, &root_vk, 1000), Decision::Deny { reason: "capability has expired" }));
    }

    #[test]
    fn stale_epoch_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let actor = [1u8; 32];
        let resource = [2u8; 32];
        // Proof from epoch 1; caller requires epoch 5
        let cap = build_root_proof(&root_sk, actor, resource, RIGHT_READ, u64::MAX, 1);
        let action = build_action(actor, resource, RIGHT_READ, vec![cap], 5);
        assert!(matches!(
            verify(&action, &root_vk, 1000),
            Decision::Deny { reason: "capability epoch predates minimum required epoch" }
        ));
    }

    #[test]
    fn tampered_ir_denied() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let actor = [1u8; 32];
        let resource = [2u8; 32];
        let cap = build_root_proof(&root_sk, actor, resource, RIGHT_READ, u64::MAX, 1);
        let mut action = build_action(actor, resource, RIGHT_READ, vec![cap], 1);
        // Tamper with required_rights after sealing
        action.required_rights = RIGHT_WRITE;
        assert!(matches!(
            verify(&action, &root_vk, 1000),
            Decision::Deny { reason: "canonical binding hash mismatch" }
        ));
    }

    #[test]
    fn forged_revocation_ignored() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let actor = [1u8; 32];
        let resource = [2u8; 32];
        let cap = build_root_proof(&root_sk, actor, resource, RIGHT_READ, u64::MAX, 1);
        let mut action = build_action(actor, resource, RIGHT_READ, vec![cap.clone()], 1);
        // Attacker injects a revocation with garbage signature
        let fake_rev = RevocationProof {
            target_proof_hash: cap.proof_hash,
            revoked_at: 999,
            signature: [0u8; 64],
        };
        action.revocation_proofs.push(fake_rev);
        action.binding_hash = action.compute_hash();
        // Forged revocation must be ignored — action should still Permit
        assert_eq!(verify(&action, &root_vk, 1000), Decision::Permit);
    }
}
