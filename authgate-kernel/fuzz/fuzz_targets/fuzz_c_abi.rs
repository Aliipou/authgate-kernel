//! Fuzz target: arbitrary bytes through the C ABI must never cause UB or panic.
//!
//! This verifies the full C ABI input validation path:
//! null guards, size limit, UTF-8 validation, and the engine.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::os::raw::c_char;

extern "C" {
    fn freedom_kernel_verify(
        input_buf: *const c_char,
        input_len: usize,
        output_buf: *mut c_char,
        output_len: usize,
    ) -> i32;
}

fuzz_target!(|data: &[u8]| {
    let mut out = vec![0u8; 65536];
    // Safety: data and out are valid for their lengths; they do not overlap.
    unsafe {
        let _ = freedom_kernel_verify(
            data.as_ptr() as *const c_char,
            data.len(),
            out.as_mut_ptr() as *mut c_char,
            out.len(),
        );
    }
});
