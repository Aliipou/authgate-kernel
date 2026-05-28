/// AT-7.5 closure: the only public execution path to the TCB.
///
/// # The Problem It Solves
///
/// Without a call gate, any adapter can call `engine::verify()` directly,
/// ignore its return value, or bypass it entirely (AT-7.5 shadow execution).
/// No TLA+ invariant can capture this — it occurs outside the kernel's
/// state space. The fix is structural: make the bypass architecturally
/// impossible rather than merely forbidden by convention.
///
/// # Structural Guarantee
///
/// `engine::verify()` is `pub(crate)` — not exported from the crate.
/// External adapters receive a `CallGate` handle. The only way to reach
/// `verify()` from outside the crate is through `CallGate::execute()`.
/// There is no type-system-valid way to call `verify()` and discard the
/// result before it reaches the caller, because `execute()` returns the
/// `Decision` directly.
///
/// # What This Does NOT Close
///
/// An adapter that receives `Decision::Permit` and then acts as if it
/// received `Decision::Deny` (or vice versa) is a semantic error, not a
/// capability error. This requires adapter-level attestation (outside TCB).
#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use crate::tcb::engine::verify;
use crate::tcb::types::{CanonicalAction, Decision};

/// The sole public entry point to the TCB verification logic.
///
/// Create once at startup with the trust root, then share the handle to
/// all adapters. Adapters cannot extract the root key or call `verify()`
/// directly.
pub struct CallGate {
    root_key: VerifyingKey,
}

impl CallGate {
    /// Construct a `CallGate` bound to a specific trust root.
    ///
    /// `root_key` is the ed25519 root of trust for this deployment.
    /// It is stored inside the gate and never returned or cloned out.
    /// All capability proof chains must trace back to this key.
    pub fn new(root_key: VerifyingKey) -> Self {
        Self { root_key }
    }

    /// Execute an action through the TCB.
    ///
    /// This is the only path to `verify()`. The return value is the
    /// kernel's decision — the adapter is responsible for acting on it
    /// and must not discard it.
    ///
    /// # Arguments
    /// - `action` — canonical, tamper-evident action IR from the adapter.
    /// - `now`    — caller-provided Unix seconds. The caller is responsible
    ///              for clock integrity (trusted clock assumption).
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

    fn make_root_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn subject_id(sk: &SigningKey) -> Bytes32 {
        Sha256::digest(sk.verifying_key().to_bytes()).into()
    }

    fn build_valid_action(root_sk: &SigningKey) -> CanonicalAction {
        let actor_id = subject_id(root_sk);
        let resource = [1u8; 32];
        let issuer_pubkey = root_sk.verifying_key().to_bytes();
        let mut cap = CapabilityProof {
            proof_hash: [0u8; 32],
            subject_id: actor_id,
            resource_hash: resource,
            rights: RIGHT_READ,
            expiry: u64::MAX,
            epoch: 1,
            issuer: IssuerRef::Root,
            signature: [0u8; 64],
            issuer_pubkey,
        };
        cap.signature = root_sk.sign(&cap.signing_message()).to_bytes();
        cap.proof_hash = Sha256::digest(cap.to_canonical_bytes()).into();

        let mut action = CanonicalAction {
            actor_id,
            resource_hash: resource,
            required_rights: RIGHT_READ,
            nonce: [0u8; 16],
            timestamp: 0,
            min_epoch: 1,
            capability_proofs: vec![cap],
            revocation_proofs: vec![],
            binding_hash: [0u8; 32],
        };
        action.binding_hash = action.compute_hash();
        action
    }

    #[test]
    fn call_gate_permits_valid_action() {
        let root_sk = make_root_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let action = build_valid_action(&root_sk);
        assert_eq!(gate.execute(&action, 0), Decision::Permit);
    }

    #[test]
    fn call_gate_denies_tampered_action() {
        let root_sk = make_root_key();
        let gate = CallGate::new(root_sk.verifying_key());
        let mut action = build_valid_action(&root_sk);
        // Tamper post-seal: escalate rights without recomputing binding_hash
        action.required_rights = RIGHT_WRITE;
        match gate.execute(&action, 0) {
            Decision::Deny { .. } => {}
            Decision::Permit => panic!("tampered action must be denied"),
        }
    }

    #[test]
    fn call_gate_denies_wrong_root_key() {
        let root_sk = make_root_key();
        let wrong_sk = make_root_key();
        // Gate is initialized with wrong_sk — cannot verify root_sk-signed caps
        let gate = CallGate::new(wrong_sk.verifying_key());
        let action = build_valid_action(&root_sk);
        match gate.execute(&action, 0) {
            Decision::Deny { .. } => {}
            Decision::Permit => panic!("wrong root key must deny"),
        }
    }
}
