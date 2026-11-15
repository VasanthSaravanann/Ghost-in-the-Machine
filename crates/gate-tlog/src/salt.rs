//! Salted leaves, encrypted evidence store and crypto-shredding
//! (plan.md M4-T02, P4-R2/R5/R6/R7, INV-10).
//!
//! The log never sees a payload or an unsalted digest: the entry digest is
//! `E = H(salt ‖ JCS(payload))` and the Merkle leaf is `H(0x00 ‖ E)` (INV-10).
//! Salts and payloads live only in the encrypted evidence store; deleting a
//! salt shreds that leaf and nothing else, because every other proof depends on
//! leaf hashes alone (T-SLT-004).

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

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use gate_core::Rng;
use gate_crypto::sha256;
use serde::{Deserialize, Serialize};

use crate::{leaf_hash, Hash};

/// Declared payload-size buckets (P4-R7). Padding hides the true size.
pub const BUCKETS: [usize; 5] = [256, 1024, 4 * 1024, 16 * 1024, 64 * 1024];

pub type Salt = [u8; 32];

/// Pick the smallest bucket that fits `len` (with a 4-byte length prefix).
#[must_use]
pub fn bucket_for(len: usize) -> Option<usize> {
    let needed = len.checked_add(4)?;
    BUCKETS.iter().copied().find(|b| *b >= needed)
}

/// Length-prefixed zero padding to the bucket size.
#[must_use]
pub fn pad(payload: &[u8]) -> Option<(usize, Vec<u8>)> {
    let bucket = bucket_for(payload.len())?;
    let mut out = Vec::with_capacity(bucket);
    let len = u32::try_from(payload.len()).ok()?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(bucket, 0);
    Some((bucket, out))
}

/// Reverse [`pad`]: the length prefix is authoritative.
#[must_use]
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(padded.get(..4)?.try_into().ok()?) as usize;
    padded.get(4..4 + len).map(<[u8]>::to_vec)
}

/// `E = H(salt ‖ payload)` — the entry digest, never logged raw (INV-10).
#[must_use]
pub fn evidence_digest(salt: &Salt, payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + payload.len());
    material.extend_from_slice(salt);
    material.extend_from_slice(payload);
    sha256(&material)
}

/// The Merkle leaf for an entry: `H(0x00 ‖ E)`.
#[must_use]
pub fn salted_leaf(salt: &Salt, payload: &[u8]) -> Hash {
    leaf_hash(&evidence_digest(salt, payload))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub leaf_id: String,
    pub bucket: usize,
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

mod serde_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8; 24], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(nonce)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 24 bytes"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    TooLarge,
    UnknownLeaf(String),
    DecryptFailed,
    Shredded,
    Duplicate(String),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("payload exceeds the largest evidence bucket"),
            Self::UnknownLeaf(id) => write!(f, "unknown evidence leaf {id}"),
            Self::DecryptFailed => f.write_str("AEAD authentication failed"),
            Self::Shredded => f.write_str("evidence was shredded"),
            Self::Duplicate(id) => write!(f, "leaf {id} already stored"),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// XChaCha20-Poly1305 evidence store with a rotatable key and salted leaves.
pub struct EvidenceStore {
    key: [u8; 32],
    salts: BTreeMap<String, Salt>,
    records: BTreeMap<String, EvidenceRecord>,
    shredded: BTreeMap<String, ()>,
}

impl std::fmt::Debug for EvidenceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceStore")
            .field("entries", &self.records.len())
            .field("shredded", &self.shredded.len())
            .finish()
    }
}

impl EvidenceStore {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            salts: BTreeMap::new(),
            records: BTreeMap::new(),
            shredded: BTreeMap::new(),
        }
    }

    /// Store a payload: fresh 32-byte salt, padded, encrypted, AEAD-bound to the
    /// leaf id. Returns the leaf hash to append to the Merkle tree.
    pub fn store(
        &mut self,
        leaf_id: impl Into<String>,
        payload: &[u8],
        rng: &dyn Rng,
    ) -> Result<(Salt, Hash), EvidenceError> {
        let leaf_id = leaf_id.into();
        if self.records.contains_key(&leaf_id) {
            return Err(EvidenceError::Duplicate(leaf_id));
        }
        let (bucket, padded) = pad(payload).ok_or(EvidenceError::TooLarge)?;
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: &padded,
                    aad: leaf_id.as_bytes(),
                },
            )
            .map_err(|_| EvidenceError::DecryptFailed)?;
        let record = EvidenceRecord {
            leaf_id: leaf_id.clone(),
            bucket,
            nonce,
            ciphertext,
        };
        self.salts.insert(leaf_id.clone(), salt);
        self.records.insert(leaf_id, record);
        Ok((salt, salted_leaf(&salt, payload)))
    }

    /// Open an entry (principal-side operation).
    pub fn open(&self, leaf_id: &str) -> Result<Vec<u8>, EvidenceError> {
        if self.shredded.contains_key(leaf_id) {
            return Err(EvidenceError::Shredded);
        }
        let record = self
            .records
            .get(leaf_id)
            .ok_or_else(|| EvidenceError::UnknownLeaf(leaf_id.to_owned()))?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let padded = cipher
            .decrypt(
                &XNonce::from(record.nonce),
                chacha20poly1305::aead::Payload {
                    msg: &record.ciphertext,
                    aad: record.leaf_id.as_bytes(),
                },
            )
            .map_err(|_| EvidenceError::DecryptFailed)?;
        unpad(&padded).ok_or(EvidenceError::DecryptFailed)
    }

    /// Selective disclosure: reveal exactly one salt+payload, enough to
    /// recompute that leaf's `E`, and nothing about any other entry (T-SLT-003).
    pub fn disclose(&self, leaf_id: &str) -> Result<(Salt, Vec<u8>), EvidenceError> {
        if self.shredded.contains_key(leaf_id) {
            return Err(EvidenceError::Shredded);
        }
        let salt = *self
            .salts
            .get(leaf_id)
            .ok_or_else(|| EvidenceError::UnknownLeaf(leaf_id.to_owned()))?;
        let payload = self.open(leaf_id)?;
        Ok((salt, payload))
    }

    /// Crypto-shredding: drop the salt and the ciphertext, record the shred.
    /// Other leaves stay provable (T-SLT-004). Idempotent.
    pub fn shred(&mut self, leaf_id: &str) -> bool {
        let had = self.salts.remove(leaf_id).is_some() | self.records.remove(leaf_id).is_some();
        self.shredded.insert(leaf_id.to_owned(), ());
        had
    }

    #[must_use]
    pub fn is_shredded(&self, leaf_id: &str) -> bool {
        self.shredded.contains_key(leaf_id)
    }

    /// Rotate the evidence key, re-encrypting every live record (T-SLT-006..018).
    pub fn rotate(&mut self, new_key: [u8; 32], rng: &dyn Rng) -> Result<usize, EvidenceError> {
        let ids: Vec<String> = self.records.keys().cloned().collect();
        let mut rewritten = BTreeMap::new();
        for id in &ids {
            let payload = self.open(id)?;
            let salt = *self
                .salts
                .get(id)
                .ok_or_else(|| EvidenceError::UnknownLeaf(id.clone()))?;
            let (bucket, padded) = pad(&payload).ok_or(EvidenceError::TooLarge)?;
            let mut nonce = [0u8; 24];
            rng.fill_bytes(&mut nonce);
            let cipher = XChaCha20Poly1305::new((&new_key).into());
            let ciphertext = cipher
                .encrypt(
                    &XNonce::from(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &padded,
                        aad: id.as_bytes(),
                    },
                )
                .map_err(|_| EvidenceError::DecryptFailed)?;
            rewritten.insert(
                id.clone(),
                EvidenceRecord {
                    leaf_id: id.clone(),
                    bucket,
                    nonce,
                    ciphertext,
                },
            );
            let _ = salt;
        }
        self.key = new_key;
        self.records = rewritten;
        Ok(ids.len())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Every byte the store would persist (ciphertexts + nonces only: salts are
    /// held separately and never serialised into the log).
    #[must_use]
    pub fn persisted_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, record) in &self.records {
            out.extend_from_slice(id.as_bytes());
            out.extend_from_slice(&record.nonce);
            out.extend_from_slice(&record.ciphertext);
        }
        out
    }

    /// Test-only helpers for AEAD binding checks.
    #[doc(hidden)]
    #[must_use]
    pub fn clone_for_test(&self) -> Self {
        Self {
            key: self.key,
            salts: self.salts.clone(),
            records: self.records.clone(),
            shredded: self.shredded.clone(),
        }
    }

    #[doc(hidden)]
    pub fn retag_for_test(&mut self, from: &str, to: &str) {
        if let Some(mut record) = self.records.remove(from) {
            record.leaf_id = to.to_owned();
            self.records.insert(to.to_owned(), record);
        }
    }

    #[must_use]
    pub fn bucket_of(&self, leaf_id: &str) -> Option<usize> {
        self.records.get(leaf_id).map(|r| r.bucket)
    }
}
