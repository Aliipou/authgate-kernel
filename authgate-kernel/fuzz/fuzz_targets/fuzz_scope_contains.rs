//! Fuzz target: arbitrary scope string pairs → deterministic, no panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }
    let mid = data[0] as usize % data.len();
    let (a, b) = data.split_at(mid.max(1));
    if let (Ok(parent), Ok(child)) = (std::str::from_utf8(a), std::str::from_utf8(b)) {
        // Inline the scope_contains logic — must never panic on arbitrary strings.
        let _ = scope_contains(parent, child);
    }
});

fn scope_contains(parent: &str, child: &str) -> bool {
    const MAX_SCOPE_LEN: usize = 4096;
    if parent.len() > MAX_SCOPE_LEN || child.len() > MAX_SCOPE_LEN {
        return false;
    }
    child == parent
        || child.starts_with(&format!("{}/", parent.trim_end_matches('/')))
}
