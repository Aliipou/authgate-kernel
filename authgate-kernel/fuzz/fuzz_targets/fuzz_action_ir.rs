//! Fuzz target: arbitrary ActionIR JSON → verify() must never panic.
//!
//! Run: cargo fuzz run fuzz_action_ir -- -max_len=65536 -timeout=5
#![no_main]
use libfuzzer_sys::fuzz_target;
use freedom_kernel::wire::{OwnershipRegistryWire, VerifyInput};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(vi) = serde_json::from_str::<VerifyInput>(s) {
            // Must never panic — result value is irrelevant.
            let _ = freedom_kernel::engine::verify(&vi.registry, &vi.action);
        }
    }
});
