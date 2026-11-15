//! gate-crypto — approved primitives only (plan.md §2.4).
//!
//! Hash: SHA-256. Signatures: Ed25519 (default) and ECDSA P-256 (FIPS profile).
//! Key custody is behind [`KeyStore`]; `SoftKeyStore` is for tests and
//! development, `HsmKeyStore` is a stub that reports unavailability so the
//! authorisation path fails closed rather than silently using software keys.

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

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gate_core::GateError;

/// Crypto agility (NF-R6): the suite id travels with every signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteId {
    Ed25519,
    P256Sha256,
}

impl SuiteId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256Sha256 => "p256-sha256",
        }
    }

    /// Unknown suites are rejected, never defaulted (T-CRY-005). Under the FIPS
    /// profile Ed25519 is refused outright (M6-T04).
    pub fn parse(s: &str) -> Result<Self, GateError> {
        match s {
            "ed25519" => {
                if cfg!(feature = "fips") {
                    return Err(GateError::Unsupported(
                        "ed25519 disabled in FIPS profile".into(),
                    ));
                }
                Ok(Self::Ed25519)
            }
            "p256-sha256" | "ecdsa-p256-sha256" => Ok(Self::P256Sha256),
            other => Err(GateError::Unsupported(format!("crypto suite {other:?}"))),
        }
    }
}

impl fmt::Display for SuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub suite: SuiteId,
    pub key_id: KeyId,
    /// Raw signature bytes: 64 for Ed25519, 64 (r‖s) for P-256.
    pub bytes: Vec<u8>,
}

pub trait Signer: Send + Sync {
    fn suite(&self) -> SuiteId;
    fn key_id(&self) -> &KeyId;
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Result<Signature, GateError>;
}

pub trait Verifier: Send + Sync {
    fn suite(&self) -> SuiteId;
    fn key_id(&self) -> &KeyId;
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), GateError>;
}

/// Key custody boundary. Production wires PKCS#11; tests wire software keys.
pub trait KeyStore: Send + Sync {
    fn signer(&self, id: &KeyId) -> Result<Box<dyn Signer>, GateError>;
    fn verifier(&self, id: &KeyId) -> Result<Box<dyn Verifier>, GateError>;
}

/// SHA-256, the only hash in the TCB (plan.md §2.4).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// `sha256:<lowercase hex>` — the form used in pins, digests and the log.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// ---------------------------------------------------------------- Ed25519

pub struct Ed25519Signer {
    key_id: KeyId,
    key: Ed25519SigningKey,
}

impl Ed25519Signer {
    /// Seed-based construction: the same seed yields the same key (R6).
    pub fn from_seed(key_id: KeyId, seed: &[u8; 32]) -> Self {
        Self {
            key_id,
            key: Ed25519SigningKey::from_bytes(seed),
        }
    }

    pub fn from_secret_bytes(key_id: KeyId, bytes: &[u8]) -> Result<Self, GateError> {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GateError::InvalidInput("ed25519 secret key must be 32 bytes".into()))?;
        Ok(Self::from_seed(key_id, &seed))
    }

    #[must_use]
    pub fn verifying_key(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key_id: self.key_id.clone(),
            key: self.key.verifying_key(),
        }
    }
}

impl Signer for Ed25519Signer {
    fn suite(&self) -> SuiteId {
        SuiteId::Ed25519
    }

    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, GateError> {
        if cfg!(feature = "fips") {
            // Never silently fall back: the FIPS profile has no Ed25519.
            return Err(GateError::Unsupported(
                "ed25519 disabled in FIPS profile".into(),
            ));
        }
        let sig = ed25519_dalek::Signer::sign(&self.key, message);
        Ok(Signature {
            suite: SuiteId::Ed25519,
            key_id: self.key_id.clone(),
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

pub struct Ed25519Verifier {
    key_id: KeyId,
    key: Ed25519VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_public_bytes(key_id: KeyId, bytes: &[u8]) -> Result<Self, GateError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GateError::InvalidInput("ed25519 public key must be 32 bytes".into()))?;
        let key = Ed25519VerifyingKey::from_bytes(&arr)
            .map_err(|_| GateError::InvalidInput("invalid ed25519 public key".into()))?;
        Ok(Self { key_id, key })
    }
}

impl Verifier for Ed25519Verifier {
    fn suite(&self) -> SuiteId {
        SuiteId::Ed25519
    }

    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), GateError> {
        if cfg!(feature = "fips") {
            return Err(GateError::Unsupported(
                "ed25519 disabled in FIPS profile".into(),
            ));
        }
        if signature.suite != SuiteId::Ed25519 || signature.key_id != self.key_id {
            return Err(GateError::VerificationFailed);
        }
        let arr: [u8; 64] = signature
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| GateError::VerificationFailed)?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        ed25519_dalek::Verifier::verify(&self.key, message, &sig)
            .map_err(|_| GateError::VerificationFailed)
    }
}

// ------------------------------------------------------------------- P-256

pub struct P256Signer {
    key_id: KeyId,
    key: P256SigningKey,
}

impl P256Signer {
    pub fn from_secret_bytes(key_id: KeyId, bytes: &[u8]) -> Result<Self, GateError> {
        let key = P256SigningKey::from_slice(bytes)
            .map_err(|_| GateError::InvalidInput("invalid p256 secret key".into()))?;
        Ok(Self { key_id, key })
    }

    pub fn generate(key_id: KeyId, rng: &dyn gate_core::Rng) -> Result<Self, GateError> {
        // Rejection sampling until the scalar is valid; deterministic under a
        // seeded Rng (R6).
        for _ in 0..64 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Ok(key) = P256SigningKey::from_slice(&bytes) {
                return Ok(Self { key_id, key });
            }
        }
        Err(GateError::SignerUnavailable)
    }

    #[must_use]
    pub fn verifying_key(&self) -> P256Verifier {
        P256Verifier {
            key_id: self.key_id.clone(),
            key: *self.key.verifying_key(),
        }
    }
}

impl Signer for P256Signer {
    fn suite(&self) -> SuiteId {
        SuiteId::P256Sha256
    }

    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, GateError> {
        // RFC 6979 deterministic ECDSA: no RNG in the signing path (R6).
        let sig: P256Signature = self.key.sign(message);
        let sig = sig.normalize_s();
        Ok(Signature {
            suite: SuiteId::P256Sha256,
            key_id: self.key_id.clone(),
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

pub struct P256Verifier {
    key_id: KeyId,
    key: P256VerifyingKey,
}

impl P256Verifier {
    pub fn from_public_bytes(key_id: KeyId, bytes: &[u8]) -> Result<Self, GateError> {
        let key = P256VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| GateError::InvalidInput("invalid p256 public key".into()))?;
        Ok(Self { key_id, key })
    }
}

impl Verifier for P256Verifier {
    fn suite(&self) -> SuiteId {
        SuiteId::P256Sha256
    }

    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), GateError> {
        if signature.suite != SuiteId::P256Sha256 || signature.key_id != self.key_id {
            return Err(GateError::VerificationFailed);
        }
        let sig = P256Signature::from_slice(&signature.bytes)
            .map_err(|_| GateError::VerificationFailed)?;
        // Reject malleable high-S signatures (T-CRY-004): a signature that is
        // not already canonical normalises to different bytes.
        if sig.normalize_s().to_bytes() != sig.to_bytes() {
            return Err(GateError::VerificationFailed);
        }
        self.key
            .verify(message, &sig)
            .map_err(|_| GateError::VerificationFailed)
    }
}

// --------------------------------------------------------------- KeyStore

/// Software key custody: tests and development only.
#[derive(Default)]
pub struct SoftKeyStore {
    ed25519: BTreeMap<KeyId, Ed25519Signer>,
    p256: BTreeMap<KeyId, P256Signer>,
}

impl SoftKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_ed25519(&mut self, signer: Ed25519Signer) -> &mut Self {
        self.ed25519.insert(signer.key_id.clone(), signer);
        self
    }

    pub fn insert_p256(&mut self, signer: P256Signer) -> &mut Self {
        self.p256.insert(signer.key_id.clone(), signer);
        self
    }
}

impl KeyStore for SoftKeyStore {
    fn signer(&self, id: &KeyId) -> Result<Box<dyn Signer>, GateError> {
        if let Some(s) = self.ed25519.get(id) {
            return Ok(Box::new(Ed25519Signer::from_seed(
                id.clone(),
                &s.key.to_bytes(),
            )));
        }
        if let Some(s) = self.p256.get(id) {
            return Ok(Box::new(P256Signer::from_secret_bytes(
                id.clone(),
                &s.key.to_bytes(),
            )?));
        }
        Err(GateError::SignerUnavailable)
    }

    fn verifier(&self, id: &KeyId) -> Result<Box<dyn Verifier>, GateError> {
        if let Some(s) = self.ed25519.get(id) {
            return Ok(Box::new(s.verifying_key()));
        }
        if let Some(s) = self.p256.get(id) {
            return Ok(Box::new(s.verifying_key()));
        }
        Err(GateError::SignerUnavailable)
    }
}

/// PKCS#11 stub. Until an HSM is wired, every operation reports unavailability
/// so the decision path denies (INV-12) instead of falling back to software keys.
#[derive(Debug, Default)]
pub struct HsmKeyStore;

impl HsmKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl KeyStore for HsmKeyStore {
    fn signer(&self, _id: &KeyId) -> Result<Box<dyn Signer>, GateError> {
        Err(GateError::SignerUnavailable)
    }

    fn verifier(&self, _id: &KeyId) -> Result<Box<dyn Verifier>, GateError> {
        Err(GateError::SignerUnavailable)
    }
}
