//! Split-leaf endorsement ledger (plan.md M3-T04, P3-R16..R19/R22, INV-5, INV-8).
//!
//! Leaf A records what the principal endorsed; execution is released **only**
//! when `H(JCS(outbound)) == leaf_a.call_digest` (INV-5). Leaf B closes the loop
//! with `ref = H(leaf_a)`; if it does not arrive by `attestation_due`, the ledger
//! records `AttestLapsed` — never confirmation (INV-8). The 15-minute
//! endorsement timeout fails closed (T-LDG-007). Leaves only ever leave this
//! crate through [`gate_core::LeafSink`].

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

use gate_core::{CallId, Class, EpisodeId, GateError, LeafSink, PrincipalId};
use gate_crypto::{sha256_hex, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

pub const MIN_DELTA_T_MS: i64 = 60 * 60 * 1_000;
pub const MAX_DELTA_T_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const ENDORSEMENT_TIMEOUT_MS: i64 = 15 * 60 * 1_000;
pub const RUBBER_STAMP_MS: i64 = 2_000;

pub const LEAF_A_TYPE: &str = "ENDORSEMENT_T0";
pub const LEAF_B_TYPE: &str = "ATTESTATION_T0_PLUS_DT";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FramingSummary {
    pub sup_share_tokens: f64,
    pub sup_share_pixels: f64,
    pub third_person: bool,
    pub filters_passed: bool,
}

/// Leaf A. The signature lives in [`SignedLeafA`] so the signed bytes are
/// exactly the canonicalised leaf (no self-reference).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeafA {
    pub leaf_id: String,
    pub episode_id: EpisodeId,
    pub call_id: CallId,
    pub tool: String,
    pub class: Class,
    /// `H(JCS(outbound))` — what the principal is endorsing (INV-5).
    pub call_digest: String,
    pub brief_digest: String,
    pub sup_share: f64,
    pub framing: FramingSummary,
    pub taint_path_digest: String,
    pub budget_used: u64,
    pub budget_cap: u64,
    pub latency_ms: i64,
    pub rubber_stamp_flag: bool,
    pub resolved_effect_digest: String,
    pub principal: PrincipalId,
    pub prev: Option<String>,
    pub attestation_due_ms: i64,
    pub issued_ms: i64,
}

impl LeafA {
    /// Canonical bytes over which the gate signs (RFC 8785).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, GateError> {
        let json = serde_json::to_string(self).map_err(|e| GateError::Jcs(e.to_string()))?;
        gate_jcs::canonicalize(&json)
            .map(String::into_bytes)
            .map_err(|e| GateError::Jcs(e.to_string()))
    }

    /// Deterministic digest used as `prev` for the next leaf and as Leaf B's `ref`.
    pub fn digest(&self) -> Result<String, GateError> {
        Ok(sha256_hex(&self.signing_bytes()?))
    }

    /// Rubber-stamp heuristic (T-DRF-001): a decision under 2 s is flagged.
    #[must_use]
    pub fn rubber_stamp(latency_ms: i64) -> bool {
        latency_ms < RUBBER_STAMP_MS
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedLeafA {
    pub leaf: LeafA,
    /// `sha256:<hex>` of the canonical leaf.
    pub digest: String,
    pub signature: Signature,
}

impl SignedLeafA {
    pub fn sign(leaf: LeafA, signer: &dyn Signer) -> Result<Self, GateError> {
        let bytes = leaf.signing_bytes()?;
        let digest = sha256_hex(&bytes);
        let signature = signer.sign(&bytes)?;
        Ok(Self {
            leaf,
            digest,
            signature,
        })
    }

    pub fn verify(&self, verifier: &dyn Verifier) -> Result<(), GateError> {
        let bytes = self.leaf.signing_bytes()?;
        if sha256_hex(&bytes) != self.digest {
            return Err(GateError::VerificationFailed);
        }
        verifier.verify(&bytes, &self.signature)
    }
}

/// Leaf B: the principal's post-hoc attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafB {
    pub leaf_id: String,
    /// `H(leaf_a)` — the reference that binds the attestation (T-LDG-005).
    pub reference: String,
    pub outcome_summary: String,
    pub still_endorses: bool,
    /// 3-point regret scale (0 = none, 3 = severe).
    pub regret_scale: u8,
    pub cause_text: String,
    pub attested_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// `sup_share > 0.50`: the brief must not be rendered (INV-6).
    NotSymmetric,
    InvalidSignature,
    /// Executed bytes differ from the endorsed bytes (INV-5).
    Toctou {
        expected: String,
        actual: String,
    },
    TimeoutExpired,
    AlreadyReleased,
    UnknownEndorsement(String),
    AttestationMismatch,
    DeltaTOutOfBounds,
    RegretOutOfRange,
    AlreadyExecuted,
    SinkUnavailable,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSymmetric => f.write_str("brief is not symmetric (sup share > 0.50)"),
            Self::InvalidSignature => f.write_str("leaf signature is invalid"),
            Self::Toctou { .. } => f.write_str("executed bytes differ from the endorsed bytes"),
            Self::TimeoutExpired => f.write_str("endorsement timeout expired (fail closed)"),
            Self::AlreadyReleased => f.write_str("leaf A was already released"),
            Self::UnknownEndorsement(id) => write!(f, "unknown endorsement {id}"),
            Self::AttestationMismatch => f.write_str("leaf B does not reference this leaf A"),
            Self::DeltaTOutOfBounds => f.write_str("delta_t out of bounds (1h..30d)"),
            Self::RegretOutOfRange => f.write_str("regret scale must be 0..=3"),
            Self::AlreadyExecuted => f.write_str("effect already executed; refusing a duplicate"),
            Self::SinkUnavailable => f.write_str("leaf sink unavailable"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Journal stages, enough to resume after a crash without re-prompting (NF-R5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Endorsed,
    Released,
    Executed,
}

/// What a restart should do for a call digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// Endorsed but not released: release, do **not** re-prompt.
    Release,
    /// Released but not executed: execute exactly once, do **not** re-prompt.
    ExecuteOnce,
    /// Already executed: do nothing (no duplicate effect).
    Done,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseReceipt {
    pub call_digest: String,
    pub leaf_a_digest: String,
    pub released_ms: i64,
}

struct Pending {
    leaf: SignedLeafA,
    deadline_ms: i64,
    delta_t_ms: i64,
    attestation_done: bool,
}

/// The endorsement ledger. Deterministic: injected clock, sorted iteration.
pub struct EndorsementLedger {
    pending: BTreeMap<String, Pending>,
    leaves_b: BTreeMap<String, LeafB>,
    lapsed: Vec<String>,
    stage: BTreeMap<String, Stage>,
    last_leaf_digest: Option<String>,
}

impl EndorsementLedger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            leaves_b: BTreeMap::new(),
            lapsed: Vec::new(),
            stage: BTreeMap::new(),
            last_leaf_digest: None,
        }
    }

    /// Record an endorsement. Rejects an asymmetric brief (INV-6), an
    /// out-of-bounds `delta_t`, and a bad signature, before anything is stored.
    pub fn endorse(
        &mut self,
        leaf: LeafA,
        signer: &dyn Signer,
        now_ms: i64,
    ) -> Result<String, LedgerError> {
        if leaf.sup_share > 0.50
            || !leaf
                .framing
                .sup_share_tokens
                .max(leaf.framing.sup_share_pixels)
                .le(&0.50)
        {
            return Err(LedgerError::NotSymmetric);
        }
        let delta_t_ms = leaf.attestation_due_ms - leaf.issued_ms;
        if !(MIN_DELTA_T_MS..=MAX_DELTA_T_MS).contains(&delta_t_ms) {
            return Err(LedgerError::DeltaTOutOfBounds);
        }
        let signed = SignedLeafA::sign(leaf, signer).map_err(|_| LedgerError::InvalidSignature)?;
        let key = signed.leaf.call_digest.clone();
        if self.pending.contains_key(&key) {
            return Err(LedgerError::AlreadyReleased);
        }
        self.stage.insert(key.clone(), Stage::Endorsed);
        self.last_leaf_digest = Some(signed.digest.clone());
        self.pending.insert(
            key.clone(),
            Pending {
                deadline_ms: now_ms + ENDORSEMENT_TIMEOUT_MS,
                leaf: signed,
                delta_t_ms,
                attestation_done: false,
            },
        );
        Ok(key)
    }

    /// Release the effect. INV-5: the bytes about to be executed must hash to
    /// exactly the endorsed `call_digest`.
    pub fn release(
        &mut self,
        call_digest: &str,
        outbound: &[u8],
        now_ms: i64,
    ) -> Result<ReleaseReceipt, LedgerError> {
        let Some(pending) = self.pending.get(call_digest) else {
            return Err(LedgerError::UnknownEndorsement(call_digest.to_owned()));
        };
        let actual = sha256_hex(outbound);
        if actual != pending.leaf.leaf.call_digest {
            return Err(LedgerError::Toctou {
                expected: pending.leaf.leaf.call_digest.clone(),
                actual,
            });
        }
        if now_ms > pending.deadline_ms {
            return Err(LedgerError::TimeoutExpired);
        }
        match self.stage.get(call_digest) {
            Some(Stage::Released) | Some(Stage::Executed) => {
                return Err(LedgerError::AlreadyReleased)
            }
            _ => {}
        }
        self.stage.insert(call_digest.to_owned(), Stage::Released);
        Ok(ReleaseReceipt {
            call_digest: call_digest.to_owned(),
            leaf_a_digest: pending.leaf.digest.clone(),
            released_ms: now_ms,
        })
    }

    /// Mark the effect as executed. A second call is a duplicate effect.
    pub fn mark_executed(&mut self, call_digest: &str) -> Result<(), LedgerError> {
        match self.stage.get(call_digest) {
            Some(Stage::Released) => {
                self.stage.insert(call_digest.to_owned(), Stage::Executed);
                Ok(())
            }
            Some(Stage::Executed) => Err(LedgerError::AlreadyExecuted),
            _ => Err(LedgerError::UnknownEndorsement(call_digest.to_owned())),
        }
    }

    /// Crash recovery (NF-R5): never re-prompt once endorsed or executed.
    #[must_use]
    pub fn resume(&self, call_digest: &str) -> Resume {
        match self.stage.get(call_digest) {
            Some(Stage::Endorsed) => Resume::Release,
            Some(Stage::Released) => Resume::ExecuteOnce,
            Some(Stage::Executed) => Resume::Done,
            None => Resume::Unknown,
        }
    }

    /// Record Leaf B. Its reference must be the leaf A digest (T-LDG-005).
    pub fn attest(
        &mut self,
        reference: &str,
        outcome: &str,
        still_endorses: bool,
        regret_scale: u8,
        cause: &str,
        now_ms: i64,
    ) -> Result<LeafB, LedgerError> {
        if regret_scale > 3 {
            return Err(LedgerError::RegretOutOfRange);
        }
        let Some((key, pending)) = self
            .pending
            .iter()
            .find(|(_, p)| p.leaf.digest == reference)
        else {
            return Err(LedgerError::AttestationMismatch);
        };
        if pending.attestation_done {
            return Err(LedgerError::AlreadyExecuted);
        }
        let key = key.clone();
        if let Some(p) = self.pending.get_mut(&key) {
            p.attestation_done = true;
        }
        let leaf_b = LeafB {
            leaf_id: format!(
                "leaf_b_{}",
                &reference.trim_start_matches("sha256:")[..16.min(reference.len())]
            ),
            reference: reference.to_owned(),
            outcome_summary: outcome.to_owned(),
            still_endorses,
            regret_scale,
            cause_text: cause.to_owned(),
            attested_ms: now_ms,
        };
        self.leaves_b.insert(reference.to_owned(), leaf_b.clone());
        Ok(leaf_b)
    }

    /// Scheduler tick: every endorsement past its `attestation_due` without a
    /// Leaf B is recorded as lapsed (INV-8). Returns newly lapsed leaf digests.
    pub fn tick(&mut self, now_ms: i64) -> Vec<String> {
        let mut newly = Vec::new();
        for (key, pending) in &self.pending {
            if pending.attestation_done {
                continue;
            }
            let due = pending.leaf.leaf.issued_ms + pending.delta_t_ms;
            if now_ms >= due && !self.lapsed.iter().any(|l| l == &pending.leaf.digest) {
                let _ = key;
                newly.push(pending.leaf.digest.clone());
            }
        }
        for digest in &newly {
            self.lapsed.push(digest.clone());
        }
        newly
    }

    #[must_use]
    pub fn lapsed(&self) -> &[String] {
        &self.lapsed
    }

    #[must_use]
    pub fn leaves_b(&self) -> &BTreeMap<String, LeafB> {
        &self.leaves_b
    }

    #[must_use]
    pub fn stage(&self, call_digest: &str) -> Option<Stage> {
        self.stage.get(call_digest).copied()
    }

    #[must_use]
    pub fn last_leaf_digest(&self) -> Option<&str> {
        self.last_leaf_digest.as_deref()
    }

    /// Emit every stored leaf through the sink (the only exit path). M3's sink
    /// is the signed span chain; M4's is the Merkle log.
    pub fn trail(&self, sink: &dyn LeafSink) -> Result<usize, GateError> {
        let mut count = 0;
        for pending in self.pending.values() {
            let payload = pending
                .leaf
                .leaf
                .signing_bytes()
                .map_err(|_| GateError::ExporterUnavailable)?;
            sink.sink_leaf(LEAF_A_TYPE, &pending.leaf.digest, &payload)
                .map_err(|_| GateError::ExporterUnavailable)?;
            count += 1;
        }
        for (reference, leaf_b) in &self.leaves_b {
            let payload = serde_json::to_vec(leaf_b).map_err(|_| GateError::ExporterUnavailable)?;
            sink.sink_leaf(LEAF_B_TYPE, reference, &payload)
                .map_err(|_| GateError::ExporterUnavailable)?;
            count += 1;
        }
        Ok(count)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Default for EndorsementLedger {
    fn default() -> Self {
        Self::new()
    }
}
