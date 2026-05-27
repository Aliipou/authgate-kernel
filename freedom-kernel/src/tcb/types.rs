/// v2 TCB types — stateless, proof-chain-based authority model.
///
/// No registry. All authority lives in signed capability proofs.
/// The root key is passed into verify() — no global state, no singleton.
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type Bytes16 = [u8; 16];
pub type Bytes32 = [u8; 32];
pub type Bytes64 = [u8; 64];

/// Rights bitmask. Extend by adding constants — do not reuse bit positions.
pub type Rights = u64;
pub const RIGHT_READ: Rights           = 1 << 0;
pub const RIGHT_WRITE: Rights          = 1 << 1;
pub const RIGHT_DELEGATE: Rights       = 1 << 2;
pub const RIGHT_EXECUTE: Rights        = 1 << 3;
pub const RIGHT_SPAWN: Rights          = 1 << 4;
pub const RIGHT_NETWORK: Rights        = 1 << 5;
pub const RIGHT_MODEL_INVOKE: Rights   = 1 << 6;
pub const RIGHT_POLICY_MODIFY: Rights  = 1 << 7;

/// Who issued this capability proof node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerRef {
    /// Signed directly by the root key (trust anchor).
    Root,
    /// Signed by an intermediate delegator identified by their proof's hash.
    Delegated { parent_hash: Bytes32 },
}

/// One node in a capability delegation chain.
///
/// The chain runs from a root-signed grant down to the leaf (the actor's proof).
/// Each intermediate node is signed by the delegator's own key, and that key's
/// authority must itself be traceable back to the root (via its own proof node).
#[derive(Debug, Clone)]
pub struct CapabilityProof {
    /// SHA-256 of `signing_message()`. Used as this node's identifier.
    pub proof_hash: Bytes32,
    /// The principal this capability was issued to (actor's identity hash).
    pub subject_id: Bytes32,
    /// SHA-256 of the canonical resource descriptor.
    pub resource_hash: Bytes32,
    /// Rights bitmask granted. Child ⊆ parent (enforced by validate_chain).
    pub rights: Rights,
    /// Unix seconds. Proof invalid if `expiry < now`.
    pub expiry: u64,
    /// Epoch this proof was issued in. Proof invalid if `epoch < current_epoch`.
    /// This closes the "stale-but-valid resurrection" gap: advancing the epoch
    /// invalidates all proofs from prior epochs without explicit revocation lists.
    pub epoch: u64,
    pub issuer: IssuerRef,
    /// ed25519 signature over `signing_message()` by the issuer's key.
    pub signature: Bytes64,
    /// Public key of the issuer (32 bytes, ed25519 compressed point).
    pub issuer_pubkey: Bytes32,
}

impl CapabilityProof {
    /// Canonical bytes over which `signature` is computed.
    /// Field order is fixed — any change is a protocol version bump.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&self.subject_id);
        msg.extend_from_slice(&self.resource_hash);
        msg.extend_from_slice(&self.rights.to_be_bytes());
        msg.extend_from_slice(&self.expiry.to_be_bytes());
        msg.extend_from_slice(&self.epoch.to_be_bytes());
        match &self.issuer {
            IssuerRef::Root => msg.push(0x00),
            IssuerRef::Delegated { parent_hash } => {
                msg.push(0x01);
                msg.extend_from_slice(parent_hash);
            }
        }
        msg.extend_from_slice(&self.issuer_pubkey);
        msg
    }

    /// Canonical bytes for inclusion in `CanonicalAction::compute_hash()`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(196);
        b.extend_from_slice(&self.proof_hash);
        b.extend_from_slice(&self.subject_id);
        b.extend_from_slice(&self.resource_hash);
        b.extend_from_slice(&self.rights.to_be_bytes());
        b.extend_from_slice(&self.expiry.to_be_bytes());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.signature);
        b.extend_from_slice(&self.issuer_pubkey);
        b
    }
}

/// A root-signed revocation notice for a single capability proof.
///
/// Revocation proofs are a secondary, emergency mechanism.
/// Primary revocation is epoch advancement — advancing `min_epoch` in the
/// verify call invalidates all proofs from prior epochs without any revocation list.
#[derive(Debug, Clone)]
pub struct RevocationProof {
    /// Proof hash of the capability being revoked.
    pub target_proof_hash: Bytes32,
    /// Unix seconds when this revocation was issued.
    pub revoked_at: u64,
    /// ed25519 signature by root key over `[target_proof_hash || revoked_at(be)]`.
    pub signature: Bytes64,
}

impl RevocationProof {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(104);
        b.extend_from_slice(&self.target_proof_hash);
        b.extend_from_slice(&self.revoked_at.to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&self.target_proof_hash);
        msg.extend_from_slice(&self.revoked_at.to_be_bytes());
        msg
    }
}

/// The canonical, tamper-evident representation of an action request.
///
/// Constructed by the (untrusted) adapter layer.
/// The kernel verifies `binding_hash` before processing any proof —
/// any field modification after construction changes the hash and is rejected.
///
/// This is the Canonicalization Gate (Layer 1 of the non-exploitable boundary).
#[derive(Debug, Clone)]
pub struct CanonicalAction {
    /// Identity hash of the actor requesting the action.
    pub actor_id: Bytes32,
    /// SHA-256 of the canonical resource descriptor.
    pub resource_hash: Bytes32,
    /// Rights the actor claims to need.
    pub required_rights: Rights,
    /// Capability proofs bundled with this request.
    pub capability_proofs: Vec<CapabilityProof>,
    /// Revocation notices (secondary mechanism; see RevocationProof docs).
    pub revocation_proofs: Vec<RevocationProof>,
    /// Random nonce — prevents replay of a prior Permit result.
    pub nonce: Bytes16,
    /// Unix seconds when this action request was constructed.
    pub timestamp: u64,
    /// Minimum epoch required for capability proofs in this request.
    /// Caller sets this to the current epoch known to them.
    /// Proofs with `epoch < min_epoch` are rejected.
    pub min_epoch: u64,
    /// SHA-256 of all fields above, in canonical order.
    /// Kernel recomputes and rejects if mismatched.
    pub binding_hash: Bytes32,
}

impl CanonicalAction {
    /// Compute the canonical hash of all fields except `binding_hash` itself.
    /// Length-prefixes on lists prevent extension attacks.
    pub fn compute_hash(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(self.actor_id);
        h.update(self.resource_hash);
        h.update(self.required_rights.to_be_bytes());
        h.update(self.nonce);
        h.update(self.timestamp.to_be_bytes());
        h.update(self.min_epoch.to_be_bytes());
        h.update((self.capability_proofs.len() as u32).to_be_bytes());
        for cap in &self.capability_proofs {
            h.update(cap.to_canonical_bytes());
        }
        h.update((self.revocation_proofs.len() as u32).to_be_bytes());
        for rev in &self.revocation_proofs {
            h.update(rev.to_canonical_bytes());
        }
        h.finalize().into()
    }

    /// Constant-time comparison to prevent timing attacks on the gate check.
    pub fn verify_binding(&self) -> bool {
        let computed = self.compute_hash();
        computed.ct_eq(&self.binding_hash).into()
    }
}

/// The kernel's decision for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny { reason: &'static str },
}

impl Decision {
    pub fn is_permit(&self) -> bool {
        matches!(self, Decision::Permit)
    }
}
