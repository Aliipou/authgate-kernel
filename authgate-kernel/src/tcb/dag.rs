/// Delegation chain validation — the DAG traversal at the heart of v2 security.
///
/// `validate_chain` walks from a leaf capability proof back to the root, verifying:
///   1. Every node's ed25519 signature is cryptographically valid.
///   2. Every node's epoch >= min_epoch (AT-3.1 fix: intermediate delegation nodes
///      issued in a compromised epoch cannot serve as valid chain links).
///   3. Every intermediate node's issuer_pubkey binds to the parent's subject_id
///      via SHA-256 (AT-5.1 fix: closes delegation impersonation gap).
///   4. Child rights ⊆ parent rights (attenuation invariant).
///
/// The root is identified by `IssuerRef::Root` — its signature is verified
/// against the root key passed into verify(). No other node is implicitly trusted.
///
/// Identity model: subject_id = SHA-256(pubkey). This is the invariant that
/// AT-5.1 relies on. All capability issuers must have their pubkey enrolled
/// as SHA-256(pubkey) = subject_id in the granting proof.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};
use crate::tcb::types::{CapabilityProof, IssuerRef};

const MAX_CHAIN_DEPTH: usize = 16;

/// Validate a capability proof chain from `leaf` to a root-signed grant.
///
/// `all_proofs` is the full bundle from `CanonicalAction` — intermediate nodes
/// must be present here. Proofs absent from the bundle cannot be trusted.
///
/// `min_epoch` is the caller's minimum required epoch. Every node in the chain
/// must have `epoch >= min_epoch` (AT-3.1 fix).
///
/// Returns `Ok(())` if the chain is valid; `Err(reason)` otherwise.
pub fn validate_chain(
    leaf: &CapabilityProof,
    all_proofs: &[CapabilityProof],
    root_key: &VerifyingKey,
    min_epoch: u64,
) -> Result<(), &'static str> {
    let mut current = leaf;
    let mut depth = 0usize;

    loop {
        if depth > MAX_CHAIN_DEPTH {
            return Err("delegation chain depth limit exceeded");
        }
        depth += 1;

        // AT-3.1 fix: epoch check on every chain node, not just the leaf.
        // A delegator whose key was compromised in epoch N cannot serve as a
        // valid chain link even if the leaf was reissued in a later epoch.
        if current.epoch < min_epoch {
            return Err("delegation chain node epoch predates minimum required epoch");
        }

        let msg = current.signing_message();
        let sig = Signature::from_bytes(&current.signature)
            .map_err(|_| "malformed signature encoding")?;

        match &current.issuer {
            IssuerRef::Root => {
                root_key
                    .verify(&msg, &sig)
                    .map_err(|_| "root signature verification failed")?;
                return Ok(());
            }

            IssuerRef::Delegated { parent_hash } => {
                let issuer_key = VerifyingKey::from_bytes(&current.issuer_pubkey)
                    .map_err(|_| "malformed issuer pubkey in proof")?;
                issuer_key
                    .verify(&msg, &sig)
                    .map_err(|_| "intermediate signature verification failed")?;

                let parent = all_proofs
                    .iter()
                    .find(|p| p.proof_hash == *parent_hash)
                    .ok_or("parent proof not found in bundle")?;

                // Resource propagation: a delegator may only grant caps for the
                // same resource they were themselves granted. Without this check,
                // a compromised delegator with a root-signed cap for R1 could issue
                // a child cap for R2, redirecting root authority to an unauthorized resource.
                if current.resource_hash != parent.resource_hash {
                    return Err("delegation chain resource mismatch");
                }

                // AT-5.1 fix: the principal this node claims as issuer must be
                // the same principal the parent capability was issued to.
                // Identity model: subject_id = SHA-256(pubkey).
                // Without this, an attacker who knows the parent proof can sign a
                // child with their own key and set parent_hash to the real parent —
                // the chain would traverse correctly despite no key from the parent's
                // subject ever being used.
                let claimed_issuer_id: [u8; 32] = Sha256::digest(&current.issuer_pubkey).into();
                if claimed_issuer_id != parent.subject_id {
                    return Err("issuer pubkey does not correspond to parent subject identity");
                }

                // Attenuation: a delegator cannot grant rights they don't possess.
                if (current.rights & !parent.rights) != 0 {
                    return Err("attenuation violation: child rights exceed parent");
                }

                current = parent;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcb::types::{IssuerRef, RIGHT_READ, RIGHT_WRITE};
    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    fn subject_id_of(sk: &SigningKey) -> [u8; 32] {
        Sha256::digest(sk.verifying_key().to_bytes()).into()
    }

    fn make_root_proof(
        root_sk: &SigningKey,
        subject_id: [u8; 32],
        resource_hash: [u8; 32],
        rights: u64,
        expiry: u64,
        epoch: u64,
    ) -> CapabilityProof {
        let issuer_pubkey = root_sk.verifying_key().to_bytes();
        let mut p = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id,
            resource_hash,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Root,
            signature: [0u8; 64],
            issuer_pubkey,
        };
        let msg = p.signing_message();
        p.signature = root_sk.sign(&msg).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    fn make_delegated_proof(
        delegator_sk: &SigningKey,
        parent: &CapabilityProof,
        subject_id: [u8; 32],
        resource_hash: [u8; 32],
        rights: u64,
        expiry: u64,
        epoch: u64,
    ) -> CapabilityProof {
        let issuer_pubkey = delegator_sk.verifying_key().to_bytes();
        let mut p = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id,
            resource_hash,
            rights,
            expiry,
            epoch,
            issuer: IssuerRef::Delegated { parent_hash: parent.proof_hash },
            signature: [0u8; 64],
            issuer_pubkey,
        };
        let msg = p.signing_message();
        p.signature = delegator_sk.sign(&msg).to_bytes();
        p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
        p
    }

    const RESOURCE: [u8; 32] = [0x02; 32];
    const MIN_EPOCH: u64 = 1;

    #[test]
    fn valid_root_proof_passes() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let proof = make_root_proof(&root_sk, [1u8; 32], RESOURCE, RIGHT_READ, u64::MAX, 1);
        assert!(validate_chain(&proof, &[proof.clone()], &root_vk, MIN_EPOCH).is_ok());
    }

    #[test]
    fn wrong_root_key_fails() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let other_sk = SigningKey::generate(&mut OsRng);
        let other_vk = other_sk.verifying_key();
        let proof = make_root_proof(&root_sk, [1u8; 32], RESOURCE, RIGHT_READ, u64::MAX, 1);
        assert!(validate_chain(&proof, &[proof.clone()], &other_vk, MIN_EPOCH).is_err());
    }

    #[test]
    fn attenuation_violation_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let child_sk = SigningKey::generate(&mut OsRng);
        // Parent grants READ to child_sk's identity.
        let parent = make_root_proof(&root_sk, subject_id_of(&child_sk), RESOURCE, RIGHT_READ, u64::MAX, 1);
        // Child claims READ|WRITE — attenuation violation.
        let child = make_delegated_proof(&child_sk, &parent, [3u8; 32], RESOURCE, RIGHT_READ | RIGHT_WRITE, u64::MAX, 1);
        let result = validate_chain(&child, &[parent.clone(), child.clone()], &root_vk, MIN_EPOCH);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("attenuation"));
    }

    // AT-5.1: attacker with a different key cannot forge delegation from [0xAA;32]
    #[test]
    fn at5_delegation_impersonation_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let attacker_sk = SigningKey::generate(&mut OsRng);
        // Parent issued to [0xAA;32] — NOT to attacker_sk's identity.
        let parent = make_root_proof(&root_sk, [0xAA; 32], RESOURCE, RIGHT_READ, u64::MAX, 1);
        // Attacker signs a child claiming delegation from that parent, using their own key.
        let fake_child = make_delegated_proof(&attacker_sk, &parent, [0x01; 32], RESOURCE, RIGHT_READ, u64::MAX, 1);
        let result = validate_chain(&fake_child, &[parent.clone(), fake_child.clone()], &root_vk, MIN_EPOCH);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("issuer pubkey"));
    }

    // AT-3.1: intermediate node with stale epoch fails even if leaf epoch is fresh
    #[test]
    fn at3_1_intermediate_stale_epoch_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let delegator_sk = SigningKey::generate(&mut OsRng);
        let next_sk = SigningKey::generate(&mut OsRng);
        // Parent issued at epoch 0 (stale).
        let parent = make_root_proof(&root_sk, subject_id_of(&delegator_sk), RESOURCE, RIGHT_READ, u64::MAX, 0);
        // Child at fresh epoch — but its parent node is stale.
        let child = make_delegated_proof(&delegator_sk, &parent, subject_id_of(&next_sk), RESOURCE, RIGHT_READ, u64::MAX, 5);
        let result = validate_chain(&child, &[parent.clone(), child.clone()], &root_vk, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("epoch"));
    }

    // Resource propagation: delegator cannot redirect root-granted R1 authority to R2
    #[test]
    fn resource_mismatch_in_delegation_rejected() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let delegator_sk = SigningKey::generate(&mut OsRng);
        const R1: [u8; 32] = [0x11; 32];
        const R2: [u8; 32] = [0x22; 32]; // different resource
        // Root grants delegator access to R1.
        let parent = make_root_proof(&root_sk, subject_id_of(&delegator_sk), R1, RIGHT_READ, u64::MAX, 1);
        // Delegator issues child for R2 claiming parentage from R1 cap — invalid.
        let child = make_delegated_proof(&delegator_sk, &parent, [0x01; 32], R2, RIGHT_READ, u64::MAX, 1);
        let result = validate_chain(&child, &[parent.clone(), child.clone()], &root_vk, MIN_EPOCH);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("resource mismatch"));
    }

    // Valid two-level chain with proper identity binding
    #[test]
    fn valid_two_level_chain() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_vk = root_sk.verifying_key();
        let delegator_sk = SigningKey::generate(&mut OsRng);
        let actor = [0x01; 32];
        // Parent granted to delegator_sk's identity.
        let parent = make_root_proof(&root_sk, subject_id_of(&delegator_sk), RESOURCE, RIGHT_READ, u64::MAX, 1);
        // delegator_sk issues to actor.
        let child = make_delegated_proof(&delegator_sk, &parent, actor, RESOURCE, RIGHT_READ, u64::MAX, 1);
        let result = validate_chain(&child, &[parent.clone(), child.clone()], &root_vk, MIN_EPOCH);
        assert!(result.is_ok());
    }
}
