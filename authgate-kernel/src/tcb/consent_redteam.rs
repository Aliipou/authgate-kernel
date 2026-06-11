//! Red-team suite for the ConsentRecord TCB gate (GAP 1 / axiom A3).
//!
//! Every test below is an ATTACK: it constructs a malicious or degenerate
//! input and asserts the kernel denies, ignores the forgery, or behaves
//! exactly as documented. Where a "limitation" is structural (e.g. the
//! stateless TCB cannot know who the *true* resource owner is — L2 malicious
//! trust root), the test asserts the honest current behaviour and says so in
//! a comment rather than pretending the kernel defends against it.

use crate::tcb::consent::{verify_consent, ConsentRecord};
use crate::tcb::engine::verify;
use crate::tcb::types::*;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const NOW: u64 = 1000;
const ACTOR: Bytes32 = [1u8; 32];
const RESOURCE: Bytes32 = [2u8; 32];

fn root_cap(root_sk: &SigningKey, subject: Bytes32, resource: Bytes32, rights: Rights) -> CapabilityProof {
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

/// Build a consent signed by `signer`, but label the grantor identity with
/// `claimed_grantor` / `claimed_pubkey`. For a *legitimate* consent, pass the
/// signer's own pubkey; for forgeries, mismatch them.
#[allow(clippy::too_many_arguments)] // test helper; mirrors the wide ConsentRecord shape
fn consent_signed_by(
    signer: &SigningKey,
    claimed_grantor: Bytes32,
    claimed_pubkey: Bytes32,
    grantee: Bytes32,
    resource_hash: Bytes32,
    rights: Rights,
    expires_at: u64,
    revocable: bool,
) -> ConsentRecord {
    let mut c = ConsentRecord {
        grantor: claimed_grantor,
        grantee,
        resource_hash,
        rights,
        expires_at,
        revocable,
        nonce: [0x5Au8; 16],
        consent_id: [0u8; 32],
        signature: [0u8; 64],
        grantor_pubkey: claimed_pubkey,
    };
    c.consent_id = c.compute_consent_id();
    c.signature = signer.sign(&c.signing_message()).to_bytes();
    c
}

/// Honest, fully valid consent from `grantor_sk`.
fn valid_consent(
    grantor_sk: &SigningKey,
    grantee: Bytes32,
    resource_hash: Bytes32,
    rights: Rights,
    expires_at: u64,
    revocable: bool,
) -> ConsentRecord {
    let pk = grantor_sk.verifying_key().to_bytes();
    let grantor: Bytes32 = Sha256::digest(pk).into();
    consent_signed_by(grantor_sk, grantor, pk, grantee, resource_hash, rights, expires_at, revocable)
}

fn seal(
    required_rights: Rights,
    caps: Vec<CapabilityProof>,
    requires_consent: bool,
    consent_proofs: Vec<ConsentRecord>,
    revocation_proofs: Vec<RevocationProof>,
) -> CanonicalAction {
    let mut a = CanonicalAction {
        actor_id: ACTOR,
        resource_hash: RESOURCE,
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

fn root_revocation(root_sk: &SigningKey, target: Bytes32) -> RevocationProof {
    let mut rev = RevocationProof { target_proof_hash: target, revoked_at: NOW - 1, signature: [0u8; 64] };
    rev.signature = root_sk.sign(&rev.signing_message()).to_bytes();
    rev
}

const DENY_CONSENT: &str = "consent required but absent, invalid, or revoked";
const DENY_BINDING: &str = "canonical binding hash mismatch";

// ── 1. Forged grantor key: attacker signs, claims victim's identity ─────────
#[test]
fn attack_forged_grantor_key_signature_fails() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let victim_sk = SigningKey::generate(&mut OsRng);
    let attacker_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);

    // Claim the victim's pubkey/identity but sign with the attacker's key.
    let victim_pk = victim_sk.verifying_key().to_bytes();
    let victim_id: Bytes32 = Sha256::digest(victim_pk).into();
    let forged = consent_signed_by(&attacker_sk, victim_id, victim_pk, ACTOR, RESOURCE, RIGHT_READ, 0, true);

    let action = seal(RIGHT_READ, vec![cap], true, vec![forged], vec![]);
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_CONSENT));
}

// ── 2. Relabel grantor_pubkey only → identity no longer hash-binds ──────────
#[test]
fn attack_grantor_pubkey_substitution_breaks_identity() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let attacker_sk = SigningKey::generate(&mut OsRng);
    let mut c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    // Swap only the embedded pubkey; grantor field still hashes the old key.
    c.grantor_pubkey = attacker_sk.verifying_key().to_bytes();
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW),
        Err("consent grantor identity mismatch")
    );
}

// ── 3. Resource swap: consent for A, action on B ────────────────────────────
#[test]
fn attack_resource_swap_via_engine() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    // Consent covers a DIFFERENT resource than the action's RESOURCE.
    let other = valid_consent(&grantor_sk, ACTOR, [0xEE; 32], RIGHT_READ, 0, true);
    let action = seal(RIGHT_READ, vec![cap], true, vec![other], vec![]);
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_CONSENT));
}

// ── 4. Rights escalation: consent READ, action needs READ|WRITE ─────────────
#[test]
fn attack_rights_escalation_denied() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    let action = seal(RIGHT_READ | RIGHT_WRITE, vec![cap], true, vec![c], vec![]);
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_CONSENT));
}

// ── 5. consent.rights == 0 cannot cover any nonzero requirement ─────────────
#[test]
fn attack_empty_consent_rights_covers_nothing() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, 0, 0, true);
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW),
        Err("consent does not cover required rights")
    );
}

// ── 6. consent_id forgery: mutate a field without recomputing the id ────────
#[test]
fn attack_consent_id_not_recomputed_after_field_change() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let mut c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    // Widen rights but leave the (now stale) consent_id and signature in place.
    c.rights = RIGHT_READ | RIGHT_WRITE | RIGHT_DELEGATE;
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW),
        Err("consent id mismatch")
    );
}

// ── 7. Recompute id but don't re-sign → signature catches it ────────────────
#[test]
fn attack_recompute_id_without_resigning_fails_signature() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let mut c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    c.rights = RIGHT_READ | RIGHT_WRITE;
    c.consent_id = c.compute_consent_id(); // id now consistent…
    // …but the signature still covers the old message.
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW),
        Err("consent signature invalid")
    );
}

// ── 8. Wrong grantee: consent for someone else ──────────────────────────────
#[test]
fn attack_wrong_grantee_denied() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let c = valid_consent(&grantor_sk, [9u8; 32], RESOURCE, RIGHT_READ, 0, true);
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW),
        Err("consent not granted to this actor")
    );
}

// ── 9. Expiry boundary: expires_at == now is still valid (strict <) ─────────
#[test]
fn attack_expiry_boundary_is_inclusive() {
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, NOW, true);
    // expires_at == now → "expires_at < now" is false → still valid this second.
    assert_eq!(verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW), Ok(()));
    // One second later it is expired.
    assert_eq!(
        verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW + 1),
        Err("consent has expired")
    );
}

// ── 10. Revoke a revocable consent (root-signed revocation of consent_id) ───
#[test]
fn attack_revoked_revocable_consent_denied() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    let rev = root_revocation(&root_sk, c.consent_id);
    let action = seal(RIGHT_READ, vec![cap], true, vec![c], vec![rev]);
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_CONSENT));
}

// ── 11. Non-revocable consent ignores a (valid root) revocation ─────────────
#[test]
fn attack_nonrevocable_consent_survives_revocation() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, false);
    let rev = root_revocation(&root_sk, c.consent_id);
    let action = seal(RIGHT_READ, vec![cap], true, vec![c], vec![rev]);
    assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
}

// ── 12. Forged (non-root) revocation of a consent is ignored ────────────────
#[test]
fn attack_nonroot_consent_revocation_ignored() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let c = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    let fake = RevocationProof { target_proof_hash: c.consent_id, revoked_at: NOW - 1, signature: [0u8; 64] };
    let action = seal(RIGHT_READ, vec![cap], true, vec![c], vec![fake]);
    assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
}

// ── 13. Inject an extra consent after sealing → binding hash mismatch ───────
#[test]
fn attack_inject_consent_after_seal() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let mut action = seal(RIGHT_READ, vec![cap], true, vec![], vec![]);
    action.consent_proofs.push(valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true));
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_BINDING));
}

// ── 14. Reorder consents after sealing → binding hash mismatch ──────────────
#[test]
fn attack_reorder_consents_after_seal() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let a = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    let b = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, 0, true);
    let mut action = seal(RIGHT_READ, vec![cap], true, vec![a, b], vec![]);
    action.consent_proofs.reverse();
    assert!(matches!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Deny { reason } if reason == DENY_BINDING));
}

// ── 15. One valid consent among a pile of broken ones still permits ─────────
#[test]
fn attack_valid_needle_in_invalid_haystack() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let attacker_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);

    let expired = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, true);
    let wrong_actor = valid_consent(&grantor_sk, [7u8; 32], RESOURCE, RIGHT_READ, 0, true);
    let mut forged = valid_consent(&attacker_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    forged.signature = [0u8; 64];
    let good = valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);

    let action = seal(RIGHT_READ, vec![cap], true, vec![expired, wrong_actor, forged, good], vec![]);
    assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
}

// ── 16. requires_consent=false: junk consents are never consulted ───────────
#[test]
fn attack_flag_off_skips_consent_entirely() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    // A garbage consent that would never verify — but the flag is off.
    let mut junk = valid_consent(&SigningKey::generate(&mut OsRng), [0u8; 32], [0u8; 32], 0, 0, true);
    junk.signature = [0xFF; 64];
    let action = seal(RIGHT_READ, vec![cap], false, vec![junk], vec![]);
    assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
}

// ── 17. HONEST LIMITATION (L2): the TCB cannot bind grantor to true owner ───
// A consent signed by *any* keypair is structurally valid. The stateless TCB
// has no ownership registry, so it cannot tell whether the signer is the
// resource's rightful owner — that is the L2 "malicious trust root" boundary,
// explicitly out of scope. This test documents the behaviour rather than
// pretending the kernel defends against it.
#[test]
fn attack_arbitrary_signer_is_structurally_valid_documented_l2() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let stranger_sk = SigningKey::generate(&mut OsRng); // NOT the resource owner
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);
    let c = valid_consent(&stranger_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true);
    let action = seal(RIGHT_READ, vec![cap], true, vec![c], vec![]);
    // Permits: structurally well-formed consent. Binding grantor→owner is the
    // policy layer's job (L2). Documented, not a regression.
    assert_eq!(verify(&action, &root_sk.verifying_key(), NOW), Decision::Permit);
}

// ── 18. INVARIANT: every consent-gated Permit had a valid covering consent ──
#[test]
fn invariant_consent_gated_permit_implies_valid_consent() {
    let root_sk = SigningKey::generate(&mut OsRng);
    let grantor_sk = SigningKey::generate(&mut OsRng);
    let cap = root_cap(&root_sk, ACTOR, RESOURCE, RIGHT_READ);

    // Matrix of consent mutations crossed against the engine decision.
    let cases: Vec<(ConsentRecord, bool /* expected verify_consent ok */)> = vec![
        (valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, 0, true), true),
        (valid_consent(&grantor_sk, [9u8; 32], RESOURCE, RIGHT_READ, 0, true), false),
        (valid_consent(&grantor_sk, ACTOR, [3u8; 32], RIGHT_READ, 0, true), false),
        (valid_consent(&grantor_sk, ACTOR, RESOURCE, 0, 0, true), false),
        (valid_consent(&grantor_sk, ACTOR, RESOURCE, RIGHT_READ, NOW - 1, true), false),
    ];

    for (c, expected_ok) in cases {
        let consent_ok = verify_consent(&c, ACTOR, RESOURCE, RIGHT_READ, NOW).is_ok();
        assert_eq!(consent_ok, expected_ok);
        let action = seal(RIGHT_READ, vec![cap.clone()], true, vec![c], vec![]);
        let permitted = verify(&action, &root_sk.verifying_key(), NOW) == Decision::Permit;
        // The engine permits a consent-required action IFF a covering consent verifies.
        assert_eq!(permitted, expected_ok);
    }
}
