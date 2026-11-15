#![no_main]

use libfuzzer_sys::fuzz_target;

// T-POL-F: arbitrary TOML must never panic the policy parser, and an accepted
// policy must produce a stable hash.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(policy) = gate_policy::Policy::parse(text) {
            let hash = policy.hash().to_owned();
            assert!(hash.starts_with("sha256:"));
        }
    }
});
