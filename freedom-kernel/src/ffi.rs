//! C ABI — call Freedom Kernel from any language via JSON.
//!
//! Go, C, Zig, Java (JNA), Node (ffi-napi) — all use the same .so.
//! No Python runtime required.
use std::os::raw::c_char;

use crate::{crypto, engine};
use crate::wire::{VerificationResultWire, VerifyInput};

/// Hard input size ceiling — prevents memory exhaustion via crafted payloads.
const MAX_INPUT_BYTES: usize = 1 << 20; // 1 MB

/// Verify an action against a registry (JSON in → JSON out, canonically signed).
///
/// `input_buf`  — pointer to UTF-8 JSON bytes (NOT required to be NUL-terminated)
/// `input_len`  — byte length of `input_buf` (must be ≤ FREEDOM_KERNEL_MAX_INPUT)
/// `output_buf` — caller-allocated buffer that receives the result JSON
/// `output_len` — size of `output_buf` in bytes (recommend ≥ FREEDOM_KERNEL_MAX_OUTPUT)
///
/// Returns bytes written on success (> 0), or a negative error code:
///   -1  parse / runtime error  (out_buf contains {"error":"..."})
///   -2  invalid input          (null pointer, oversized, invalid UTF-8)
///
/// # Safety
/// `input_buf` and `output_buf` must be valid for their respective lengths
/// for the duration of this call. They must not overlap.
#[no_mangle]
pub unsafe extern "C" fn freedom_kernel_verify(
    input_buf: *const c_char,
    input_len: usize,
    output_buf: *mut c_char,
    output_len: usize,
) -> i32 {
    // 1. Null pointer guards — must come first before any dereference.
    if input_buf.is_null() || output_buf.is_null() {
        // Can't write error if output_buf is null; just return.
        if !output_buf.is_null() {
            write_buf(output_buf, output_len, r#"{"error":"null pointer"}"#);
        }
        return -2;
    }

    // 2. Size limit — prevents memory exhaustion.
    if input_len > MAX_INPUT_BYTES {
        write_buf(output_buf, output_len, r#"{"error":"input too large"}"#);
        return -2;
    }

    // 3. Bounded UTF-8 decode using caller-supplied length (not NUL search).
    let bytes = unsafe { std::slice::from_raw_parts(input_buf as *const u8, input_len) };
    let input = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            write_buf(output_buf, output_len, r#"{"error":"invalid utf-8 in input"}"#);
            return -2;
        }
    };

    // 4. Verify — with catch_unwind as last-resort net (primary defense: zero-panic engine).
    //    Note: when compiled with panic = "abort" (release profile), catch_unwind is a no-op.
    let outcome = std::panic::catch_unwind(|| -> Result<String, String> {
        let vi: VerifyInput =
            serde_json::from_str(input).map_err(|e| format!("parse: {e}"))?;
        let mut r = engine::verify(&vi.registry, &vi.action);
        attach_signature(&mut r)?;
        serde_json::to_string(&r).map_err(|e| e.to_string())
    });

    match outcome {
        Ok(Ok(json)) => {
            write_buf(output_buf, output_len, &json);
            json.len() as i32
        }
        Ok(Err(e)) => {
            write_buf(output_buf, output_len, &format!(r#"{{"error":"{e}"}}"#));
            -1
        }
        Err(_) => {
            write_buf(output_buf, output_len, r#"{"error":"kernel panic — report as security bug"}"#);
            -1
        }
    }
}

/// Write the kernel's ed25519 verifying key (hex, 64 chars + NUL) into `out_buf`.
///
/// # Safety
/// `out_buf` must be valid and at least `out_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn freedom_kernel_pubkey(out_buf: *mut c_char, out_len: usize) -> i32 {
    if out_buf.is_null() {
        return -2;
    }
    write_buf(out_buf, out_len, &crypto::pubkey_hex());
    0
}

// ─── internal ────────────────────────────────────────────────────────────────

pub(crate) fn attach_signature(r: &mut VerificationResultWire) -> Result<(), String> {
    let (sig, vk, kid, ts, nonce) =
        crypto::sign_canonical(&r.action_id, r.permitted, &r.violations);
    r.signature   = Some(sig);
    r.signing_key = Some(vk);
    r.key_id      = Some(kid);
    r.timestamp   = Some(ts);
    r.nonce       = Some(nonce);
    Ok(())
}

fn write_buf(buf: *mut c_char, len: usize, s: &str) {
    if len == 0 { return; }
    let bytes = s.as_bytes();
    let n = bytes.len().min(len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
}
