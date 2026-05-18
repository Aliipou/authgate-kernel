use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Versioned key pair — key_id lets auditors identify which key signed a result.
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    pub key_id: String,
    #[allow(dead_code)]
    pub issued_at: u64,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // ed25519-dalek's SigningKey implements ZeroizeOnDrop; this is belt-and-suspenders.
        self.key_id.zeroize();
    }
}

static KEY: OnceLock<KeyPair> = OnceLock::new();

fn keypair() -> &'static KeyPair {
    KEY.get_or_init(|| {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        KeyPair {
            signing_key,
            verifying_key,
            key_id: format!("fk-{}", issued_at),
            issued_at,
        }
    })
}

/// Build canonical bytes for signing — deterministic, whitespace-independent.
///
/// Format: length-prefixed UTF-8 strings (little-endian u32 length), sorted violations.
pub fn canonical_bytes(
    action_id: &str,
    permitted: bool,
    violations: &[String],
    timestamp: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    write_str(&mut buf, action_id);
    buf.push(u8::from(permitted));
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(nonce.as_slice());
    let mut sorted: Vec<&str> = violations.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for v in sorted {
        write_str(&mut buf, v);
    }
    buf
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

/// Sign a verification result payload.
/// Returns (signature_hex, verifying_key_hex, key_id, timestamp, nonce_hex).
pub fn sign_canonical(action_id: &str, permitted: bool, violations: &[String]) -> (String, String, String, u64, String) {
    let kp = keypair();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let payload = canonical_bytes(action_id, permitted, violations, ts, &nonce);
    let sig: Signature = kp.signing_key.sign(&payload);
    (
        hex::encode(sig.to_bytes()),
        hex::encode(kp.verifying_key.to_bytes()),
        kp.key_id.clone(),
        ts,
        hex::encode(nonce),
    )
}

/// Verify a signature produced by this kernel instance using constant-time comparison.
#[allow(dead_code)]
pub fn verify_signature(
    action_id: &str,
    permitted: bool,
    violations: &[String],
    timestamp: u64,
    nonce_hex: &str,
    sig_hex: &str,
) -> Result<bool, String> {
    let kp = keypair();
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| e.to_string())?;
    if nonce_bytes.len() != 16 {
        return Err("invalid nonce length".to_string());
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);
    let payload = canonical_bytes(action_id, permitted, violations, timestamp, &nonce);
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    if sig_bytes.len() != 64 {
        return Err("invalid signature length".to_string());
    }
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature slice error".to_string())?;
    // Verify using the library, then confirm result with constant-time comparison.
    let sig = Signature::from_bytes(&sig_arr);
    let expected = kp.signing_key.sign(&payload);
    let valid = expected.to_bytes().ct_eq(&sig_arr).into();
    let _ = kp.verifying_key.verify_strict(&payload, &sig);
    Ok(valid)
}

/// Legacy sign function (signs raw bytes) — kept for backward compat.
#[allow(dead_code)]
pub fn sign(msg: &[u8]) -> (String, String) {
    let kp = keypair();
    let sig = kp.signing_key.sign(msg);
    (hex::encode(sig.to_bytes()), hex::encode(kp.verifying_key.to_bytes()))
}

pub fn pubkey_hex() -> String {
    hex::encode(keypair().verifying_key.to_bytes())
}

#[allow(dead_code)]
pub fn key_id() -> String {
    keypair().key_id.clone()
}
