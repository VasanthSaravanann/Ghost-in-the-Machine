//! gate-testkit — deterministic fixtures for T1–T5 (plan.md §3.1).
//!
//! DEV-DEPENDENCY ONLY. No product crate may depend on this crate
//! (plan.md §2.2, enforced by T-REPO-002).

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use gate_core::{Clock, Rng as GateRng};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Manually advanced clock. Supports jumps for Δt / TTL tests (T-BUD, T-LDG).
#[derive(Debug, Clone, Default)]
pub struct FakeClock {
    now_ms: Arc<AtomicI64>,
}

impl FakeClock {
    pub fn new(start_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(AtomicI64::new(start_ms)),
        }
    }

    pub fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    pub fn advance(&self, by_ms: i64) {
        self.now_ms.fetch_add(by_ms, Ordering::SeqCst);
    }

    /// Jump *backwards* (clock-skew tests, T-LDG-011..026).
    pub fn jump_to(&self, to_ms: i64) {
        self.now_ms.store(to_ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        Self::now_ms(self)
    }
}

/// ChaCha20 seeded per test, so every identifier, salt and nonce is reproducible.
#[derive(Clone)]
pub struct SeededRng {
    inner: Arc<Mutex<ChaCha20Rng>>,
}

impl std::fmt::Debug for SeededRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeededRng(..)")
    }
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChaCha20Rng::seed_from_u64(seed))),
        }
    }

    pub fn bytes32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill_bytes(&mut out);
        out
    }

    pub fn bytes16(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.fill_bytes(&mut out);
        out
    }

    pub fn next_u64(&self) -> u64 {
        self.inner.lock().map(|mut r| r.next_u64()).unwrap_or(0)
    }

    pub fn fill_bytes(&self, dest: &mut [u8]) {
        if let Ok(mut r) = self.inner.lock() {
            r.fill_bytes(dest);
        }
    }
}

impl GateRng for SeededRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        Self::fill_bytes(self, dest);
    }
}

/// Vector tool stub: RFC 8785 / RFC 9162 vectors are generated here and
/// cross-checked against `ref/` in CI (plan.md §3.1, T-JCS-V, T-MRK-V).
#[derive(Debug, Default)]
pub struct VectorTool;

impl VectorTool {
    pub fn new() -> Self {
        Self
    }
}

/// Paraphrase/laundering transforms (plan.md §3.1, T-TNT-007..020).
///
/// Each entry rewrites `input` into a plausible "cleaned" form: summarised,
/// translated (reversed), case-folded, homoglyphed, wrapped in filler, encoded.
/// The point is that *no* transform may change provenance, so the gate tests
/// assert that claiming clean provenance for any of these is rejected.
#[must_use]
pub fn laundering_corpus(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let words: Vec<&str> = input.split_whitespace().collect();

    // 40 summaries: take the first N words.
    for n in 1..=40 {
        let text = words.iter().take(n).copied().collect::<Vec<_>>().join(" ");
        out.push((format!("summarise-{n}"), text));
    }
    // 40 truncations by character.
    for n in 1..=40 {
        out.push((format!("truncate-{n}"), input.chars().take(n).collect()));
    }
    // 5 case transforms x 8 wrappers = 40.
    let cases: [fn(&str) -> String; 5] = [
        |s: &str| s.to_uppercase(),
        |s: &str| s.to_lowercase(),
        |s: &str| {
            s.split_whitespace()
                .map(|w| {
                    let mut chars = w.chars();
                    match chars.next() {
                        Some(first) => {
                            format!("{}{}", first.to_uppercase(), chars.as_str().to_lowercase())
                        }
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        },
        |s: &str| {
            s.chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                })
                .collect()
        },
        |s: &str| s.chars().rev().collect(),
    ];
    let wrappers = [
        "",
        "Note: ",
        "Summary: ",
        "Ticket says: ",
        "> ",
        "[quoted] ",
        "TL;DR ",
        "FYI ",
    ];
    for (i, transform) in cases.iter().enumerate() {
        for (j, wrapper) in wrappers.iter().enumerate() {
            out.push((
                format!("case-{i}-{j}"),
                format!("{wrapper}{}", transform(input)),
            ));
        }
    }
    // 40 synonym swaps.
    let synonyms = [
        ("forward", "pass along"),
        ("send", "dispatch"),
        ("ticket", "issue"),
        ("customer", "client"),
        ("all", "every"),
        ("ignore", "disregard"),
        ("previous", "earlier"),
        ("instructions", "guidance"),
        ("delete", "remove"),
        ("transfer", "move"),
    ];
    for (i, (from, to)) in synonyms.iter().enumerate() {
        for n in 1..=4 {
            let text = (0..n).fold(input.to_owned(), |acc, _| acc.replace(from, to));
            out.push((format!("synonym-{i}-{n}"), text));
        }
    }
    // 40 homoglyph/zero-width insertions.
    let confusables = [
        '\u{430}', '\u{435}', '\u{43e}', '\u{200b}', '\u{200d}', '\u{feff}', '\u{2060}', '\u{00a0}',
    ];
    for (i, ch) in confusables.iter().enumerate() {
        for stride in 1..=5 {
            let text = input
                .chars()
                .enumerate()
                .map(|(n, c)| {
                    if n % stride == 0 {
                        format!("{c}{ch}")
                    } else {
                        c.to_string()
                    }
                })
                .collect::<String>();
            out.push((format!("homoglyph-{i}-{stride}"), text));
        }
    }
    // 40 encodings / structural rewrites.
    for n in 1..=20 {
        out.push((
            format!("hex-{n}"),
            hex_encode(input).chars().take(n * 4).collect(),
        ));
        out.push((
            format!("chunk-{n}"),
            input
                .as_bytes()
                .chunks(n.max(1))
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join(" | "),
        ));
    }
    out
}

fn hex_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for byte in text.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advances_and_jumps() {
        let c = FakeClock::new(1_000);
        c.advance(500);
        assert_eq!(c.now_ms(), 1_500);
        c.jump_to(10);
        assert_eq!(c.now_ms(), 10);
    }

    #[test]
    fn seeded_rng_is_reproducible() {
        let a = SeededRng::new(7);
        let b = SeededRng::new(7);
        assert_eq!(a.bytes32(), b.bytes32());
        let c = SeededRng::new(8);
        assert_ne!(a.bytes32(), c.bytes32());
    }
}
