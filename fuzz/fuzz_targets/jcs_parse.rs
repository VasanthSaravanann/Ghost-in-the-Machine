#![no_main]

use libfuzzer_sys::fuzz_target;

// T-JCS-F: no panic and no hang on arbitrary input.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = gate_jcs::canonicalize(text);
    }
});
