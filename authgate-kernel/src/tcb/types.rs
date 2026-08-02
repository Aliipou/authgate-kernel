/// v2 TCB types — stateless, proof-chain-based authority model.
///
/// No registry. All authority lives in signed capability proofs.
/// The root key is passed into verify() — no global state, no singleton.
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type Bytes16 = [u8; 16];
pub type Bytes32 = [u8; 32];
pub type Bytes64 = [u8; 64];

// ── Domain separation ───────────────────────────────────────────────────────
//
// Every signed or hashed payload in this protocol begins with a preamble that
// binds THREE things under the signature: a context string naming the message
// type, the signature algorithm, and the schema version.
//
// WHY THIS EXISTS. Before v2, `CapabilityProof::signing_message()` and
// `RevocationProof::signing_message()` were both signed by the root key and
// neither carried a type tag. They could not actually be confused, but only
// because a revocation message is exactly 40 bytes and a capability message is
// at least 121 — an accident of current field sizes, not an enforced property.
// Any future field change could have made a signature over one valid as a
// signature over the other. The preamble makes cross-type confusion
// structurally impossible instead of accidentally impossible.
//
// Binding the ALGORITHM matters for the same reason JWT's `alg` confusion
// matters: when a second scheme is added (post-quantum migration is a *when*),
// a verifier that accepts two schemes must be able to tell which one a
// signature was produced under. That is only sound if the algorithm is inside
// the signed bytes.
//
// Binding the VERSION is what makes the doc comment on `signing_message()`
// true. It previously claimed "any change is a protocol version bump" while the
// version appeared nowhere in the signed bytes, so old signatures stayed valid
// under a new field order.
//
// The context is LENGTH-PREFIXED. Without that, one context string being a
// prefix of another would reintroduce the ambiguity the preamble removes.

/// Signature algorithm identifier, bound under every signature.
/// Add a new constant per scheme; never reuse a value.
pub const ALG_ED25519: u8 = 0x01;

/// Protocol schema version, bound under every signature and every canonical
/// hash. Bumped from v1 (which had no preamble at all) to v2.
/// A v1 signature cannot verify against a v2 payload: the signed bytes differ.
pub const SCHEMA_VERSION: u8 = 0x02;

/// Context: one node of a delegation chain, signed by its issuer.
pub const CTX_CHAIN_LINK: &[u8] = b"authgate/v2/chain-link";
/// Context: a root-signed revocation notice.
pub const CTX_REVOCATION: &[u8] = b"authgate/v2/revocation";
/// Context: the canonical action binding hash (Layer 1 gate).
pub const CTX_ACTION_BINDING: &[u8] = b"authgate/v2/action-binding";
/// Context: capability proof bytes as hashed into `proof_hash`.
pub const CTX_CAP_CANONICAL: &[u8] = b"authgate/v2/cap-canonical";
/// Context: revocation proof bytes as hashed into the action binding.
pub const CTX_REV_CANONICAL: &[u8] = b"authgate/v2/rev-canonical";
/// Context: a signed verification result / audit log entry.
pub const CTX_AUDIT_ENTRY: &[u8] = b"authgate/v2/audit-entry";

/// The preamble prefixed to every signed or hashed payload:
/// `len(ctx) ‖ ctx ‖ alg_id ‖ schema_version`.
///
/// Callers must never construct this by hand — a payload built without it is
/// exactly the pre-v2 format this function exists to retire.
#[inline]
pub fn domain_preamble(ctx: &[u8]) -> Vec<u8> {
    debug_assert!(ctx.len() <= u8::MAX as usize, "context string too long");
    let mut b = Vec::with_capacity(ctx.len() + 3);
    b.push(ctx.len() as u8);
    b.extend_from_slice(ctx);
    b.push(ALG_ED25519);
    b.push(SCHEMA_VERSION);
    b
}

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
    ///
    /// Field order is fixed. The preamble binds the message type, the signature
    /// algorithm and the schema version under the signature, so a change of
    /// field order or of algorithm is a real version bump: pre-v2 signatures
    /// cannot verify against these bytes.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = domain_preamble(CTX_CHAIN_LINK);
        msg.reserve(128);
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

    /// Canonical bytes for inclusion in `CanonicalAction::compute_hash()`,
    /// and the preimage of `proof_hash`. Carries its own context so these bytes
    /// can never be reinterpreted as a signing message.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = domain_preamble(CTX_CAP_CANONICAL);
        b.reserve(196);
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
        let mut b = domain_preamble(CTX_REV_CANONICAL);
        b.reserve(104);
        b.extend_from_slice(&self.target_proof_hash);
        b.extend_from_slice(&self.revoked_at.to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    /// Root-signed revocation notice.
    ///
    /// Pre-v2 this was exactly `target_proof_hash ‖ revoked_at` — 40 bytes with
    /// no type tag, signed by the same root key that signs chain links. It was
    /// safe only because a chain-link message is never 40 bytes long. The
    /// context prefix replaces that accident with a guarantee.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = domain_preamble(CTX_REVOCATION);
        msg.reserve(40);
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
        h.update(domain_preamble(CTX_ACTION_BINDING));
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
