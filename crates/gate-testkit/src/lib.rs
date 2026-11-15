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
