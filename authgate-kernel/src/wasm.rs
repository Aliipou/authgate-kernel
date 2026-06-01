/// WebAssembly bindings for the Freedom Kernel engine.
///
/// Build targets:
///   wasm32-unknown-unknown  (browser / Node.js via wasm-bindgen):
///     wasm-pack build --target web   -- --features wasm
///
///   wasm32-wasi (WASI-capable runtimes like Wasmtime, Wasmer):
///     cargo build --target wasm32-wasi --features wasm --no-default-features
///
/// The WASM build uses only `engine.rs` and `wire.rs` — no PyO3, no I/O,
/// no system calls except deterministic verification logic.
///
/// JavaScript usage:
///   ```js
///   import init, { verify_json_wasm, kernel_pubkey_wasm } from './freedom_kernel_bg.wasm';
///   await init();
///   const result = JSON.parse(verify_json_wasm(JSON.stringify({ registry, action })));
///   // result: { permitted, violations, warnings, confidence, signature, ... }
///   ```
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Verify an action against a registry using the JSON wire format.
///
/// Input JSON:  `{"registry": <OwnershipRegistryWire>, "action": <ActionWire>}`
/// Output JSON: `<VerificationResultWire>` (with ed25519 signature when available)
///
/// This is the WASM equivalent of `FreedomVerifier.verify_signed()`.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_json_wasm(input_json: &str) -> Result<String, JsValue> {
    let vi: crate::wire::VerifyInput = serde_json::from_str(input_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut r = crate::engine::verify(&vi.registry, &vi.action);
    // Signature attachment is best-effort in WASM (getrandom may not be available)
    let _ = crate::ffi::attach_signature(&mut r);
    serde_json::to_string(&r).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Return this kernel instance's ed25519 verifying key (hex, 64 chars).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn kernel_pubkey_wasm() -> String {
    crate::crypto::pubkey_hex()
}

/// Pure JSON verification without signatures (no randomness required).
/// Useful for WASM targets where getrandom is unavailable.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_json_unsigned(input_json: &str) -> Result<String, JsValue> {
    let vi: crate::wire::VerifyInput = serde_json::from_str(input_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let r = crate::engine::verify(&vi.registry, &vi.action);
    serde_json::to_string(&r).map_err(|e| JsValue::from_str(&e.to_string()))
}
