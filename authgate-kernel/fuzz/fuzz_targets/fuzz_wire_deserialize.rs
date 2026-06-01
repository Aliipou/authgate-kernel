//! Fuzz target: arbitrary bytes → wire::VerifyInput deserialization must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use freedom_kernel::wire::VerifyInput;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Deserialization must never panic — only return Err at worst.
        let _ = serde_json::from_str::<VerifyInput>(s);
    }
});
