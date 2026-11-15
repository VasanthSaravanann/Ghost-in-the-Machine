//! Scoped declassification hook (plan.md M2-T06, P2-R9, T-DEC-001..008).
//!
//! A [`DeclassifyRecord`] temporarily narrows a segment's influence for one
//! specific target for one TTL. Two hard rules:
//! * only an out-of-band [`DeclassifyAuthority`] (the endorsement channel, M3-T04)
//!   can mint one — the model channel holds a rejecting authority, so a model
//!   "declassify" is rejected, never ignored;
//! * expiry restores the taint ([`DeclassificationLedger::effective`] returns the
//!   original label once the TTL passes).

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

use gate_core::{Label, PrincipalId, SegmentId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassifyRecord {
    pub id: String,
    pub segment: SegmentId,
    /// The single target this scoping applies to (a namespaced tool, or a
    /// permitted principal).
    pub target: String,
    pub issued_ms: i64,
    pub ttl_ms: i64,
    pub issued_by: PrincipalId,
    pub prev_label: Label,
}

impl DeclassifyRecord {
    /// Stable digest, so the ledger is replayable (`mcp-audit replay`, T-DEC-004..008).
    #[must_use]
    pub fn digest(&self) -> String {
        let mut material = format!(
            "{}|{}|{}|{}|{}",
            self.segment,
            self.target,
            self.issued_ms,
            self.ttl_ms,
            self.prev_label.as_str()
        );
        material.push('|');
        material.push_str(self.issued_by.as_str());
        gate_crypto::sha256_hex(material.as_bytes())
    }

    #[must_use]
    pub fn is_active(&self, now_ms: i64) -> bool {
        now_ms >= self.issued_ms && now_ms <= self.issued_ms + self.ttl_ms
    }
}

/// The only way a declassification can be minted. The endorsement channel (M3)
/// implements this; the agent/model channel holds [`DenyAllAuthority`].
pub trait DeclassifyAuthority: Send + Sync {
    /// `None` means "not authorised": the request is rejected (fail closed).
    fn authorize(&self, segment: &SegmentId, target: &str) -> Option<PrincipalId>;
}

#[derive(Debug, Default)]
pub struct DenyAllAuthority;

impl DeclassifyAuthority for DenyAllAuthority {
    fn authorize(&self, _segment: &SegmentId, _target: &str) -> Option<PrincipalId> {
        None
    }
}

#[derive(Debug, Default)]
pub struct EveryPrincipalAuthority(pub PrincipalId);

impl DeclassifyAuthority for EveryPrincipalAuthority {
    fn authorize(&self, _segment: &SegmentId, _target: &str) -> Option<PrincipalId> {
        Some(self.0.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclassifyError {
    NotAuthorised,
    UnknownSegment(SegmentId),
}

impl std::fmt::Display for DeclassifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthorised => f.write_str("declassification not authorised"),
            Self::UnknownSegment(id) => write!(f, "unknown segment {id}"),
        }
    }
}

impl std::error::Error for DeclassifyError {}

/// Append-only declassification ledger.
#[derive(Clone, Debug, Default)]
pub struct DeclassificationLedger {
    records: std::collections::BTreeMap<SegmentId, Vec<DeclassifyRecord>>,
}

impl DeclassificationLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a record through the authority. A record is scoped to exactly one
    /// `target`; calling this with the agent channel's authority always fails.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        authority: &dyn DeclassifyAuthority,
        segment: &SegmentId,
        target: &str,
        known_segment: bool,
        prev_label: Label,
        issued_ms: i64,
        ttl_ms: i64,
    ) -> Result<DeclassifyRecord, DeclassifyError> {
        let principal = authority
            .authorize(segment, target)
            .ok_or(DeclassifyError::NotAuthorised)?;
        if !known_segment || segment.as_str().is_empty() {
            return Err(DeclassifyError::UnknownSegment(segment.clone()));
        }
        let record = DeclassifyRecord {
            id: crate::SourceRef::new(format!(
                "declass:{}",
                crate::SourceRef::new(segment.as_str()).id
            ))
            .id,
            segment: segment.clone(),
            target: target.to_owned(),
            issued_ms,
            ttl_ms,
            issued_by: principal,
            prev_label,
        };
        self.records
            .entry(segment.clone())
            .or_default()
            .push(record.clone());
        Ok(record)
    }

    /// Effective label of `segment` *for `target`*: if an in-TTL record matches
    /// (same segment, same target), the taint is scoped away; expired records
    /// restore it (T-DEC-003). Anything else falls through to the caller's
    /// provenance label.
    #[must_use]
    pub fn effective(
        &self,
        segment: &SegmentId,
        target: &str,
        _previous: Label,
        now_ms: i64,
    ) -> Label {
        // An in-TTL record for this exact target scopes the *external* influence
        // away: the label for that target is PrincipalDirect while active, and
        // `prev_label` records what returns at expiry (for audit/replay).
        if self
            .records
            .get(segment)
            .into_iter()
            .flatten()
            .any(|r| r.target == target && r.is_active(now_ms))
        {
            Label::PrincipalDirect
        } else {
            Label::ExternalUntrustedData
        }
    }
}
