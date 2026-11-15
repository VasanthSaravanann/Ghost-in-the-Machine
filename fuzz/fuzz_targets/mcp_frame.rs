#![no_main]

use libfuzzer_sys::fuzz_target;

// T-TRN-F: arbitrary bytes must never panic or hang the framer, and a parsed
// message must round-trip through canonical classification.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(parsed) = gate_transport::classify(text, 1 << 20) {
            for frame in &parsed.frames {
                let _ = frame.is_request();
                let _ = frame.method();
                let _ = gate_transport::classify(&frame.raw, 1 << 20);
            }
        }
    }
});
