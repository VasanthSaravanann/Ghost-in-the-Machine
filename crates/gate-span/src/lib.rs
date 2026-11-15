//! gate-span — signed, chained, durably committed spans (plan.md §2.1, §5.3).
//!
//! INV-1: no external side effect without a durably committed, signed
//! authorising span. The commit path therefore writes the record, calls fsync,
//! and only then reports success; the caller releases the effect afterwards.

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
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use gate_core::{CallId, Class, Clock, EpisodeId, GateError, Label, ReasonCode};
use gate_crypto::{sha256_hex, Signature, Signer, SuiteId, Verifier};
use serde::{Deserialize, Serialize};

/// Attribute value types. Floats must be finite so JCS can never fail on a
/// value the gate itself constructed (T-SPAN-010).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    StrArray(Vec<String>),
}

impl AttrValue {
    fn kind(&self) -> AttrKind {
        match self {
            Self::Str(_) => AttrKind::Str,
            Self::Int(_) => AttrKind::Int,
            Self::Float(_) => AttrKind::Float,
            Self::Bool(_) => AttrKind::Bool,
            Self::StrArray(_) => AttrKind::StrArray,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrKind {
    Str,
    Int,
    Float,
    Bool,
    StrArray,
}

/// OTel GenAI / MCP semantic conventions used by the gate, with the type each
/// attribute must have (`T-SPAN-011..014`). Units: token attributes are integer
/// counts, `*_ms` attributes are integer milliseconds, `*_hash` attributes are
/// `sha256:<hex>` strings.
pub const GENAI_ATTRIBUTES: &[(&str, AttrKind)] = &[
    ("gen_ai.system", AttrKind::Str),
    ("gen_ai.operation.name", AttrKind::Str),
    ("gen_ai.request.model", AttrKind::Str),
    ("gen_ai.response.model", AttrKind::Str),
    ("gen_ai.request.max_tokens", AttrKind::Int),
    ("gen_ai.usage.input_tokens", AttrKind::Int),
    ("gen_ai.usage.output_tokens", AttrKind::Int),
    ("gen_ai.response.finish_reasons", AttrKind::StrArray),
    ("mcp.method", AttrKind::Str),
    ("mcp.tool.name", AttrKind::Str),
    ("gate.class", AttrKind::Str),
    ("gate.label", AttrKind::Str),
    ("gate.policy_hash", AttrKind::Str),
    ("gate.server", AttrKind::Str),
    ("gate.episode_id", AttrKind::Str),
    ("gate.call_digest", AttrKind::Str),
    ("gate.duration_ms", AttrKind::Int),
    ("gate.score", AttrKind::Float),
    ("gate.leaf_type", AttrKind::Str),
    ("gate.leaf_digest", AttrKind::Str),
    ("gate.decision", AttrKind::Str),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanStatus {
    Ok,
    Error,
}

/// One mediated request/response (T-SPAN-001). Serialised with JCS before
/// signing, so the signature covers canonical bytes and nothing else.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Span {
    pub span_id: String,
    pub episode_id: EpisodeId,
    pub call_id: Option<CallId>,
    /// Monotonic per-episode sequence number (gap detection, T-SPAN-004).
    pub seq: u64,
    /// Digest of the previous signed span in this episode, if any.
    pub prev: Option<String>,
    pub name: String,
    pub class: Class,
    pub label: Label,
    pub policy_hash: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub status: SpanStatus,
    pub attributes: BTreeMap<String, AttrValue>,
}

/// Everything the gate must supply when opening a span.
#[derive(Clone, Debug)]
pub struct SpanSpec {
    pub span_id: String,
    pub episode_id: EpisodeId,
    pub call_id: Option<CallId>,
    pub seq: u64,
    pub prev: Option<String>,
    pub name: String,
    pub class: Class,
    pub label: Label,
    pub policy_hash: String,
    pub duration_ms: i64,
}

impl SpanSpec {
    #[must_use]
    pub fn new(
        span_id: impl Into<String>,
        episode_id: EpisodeId,
        seq: u64,
        prev: Option<String>,
        name: impl Into<String>,
        class: Class,
        policy_hash: impl Into<String>,
    ) -> Self {
        Self {
            span_id: span_id.into(),
            episode_id,
            call_id: None,
            seq,
            prev,
            name: name.into(),
            class,
            label: Label::PrincipalDirect,
            policy_hash: policy_hash.into(),
            duration_ms: 0,
        }
    }

    #[must_use]
    pub fn with_call_id(mut self, call_id: CallId) -> Self {
        self.call_id = Some(call_id);
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: Label) -> Self {
        self.label = label;
        self
    }

    #[must_use]
    pub fn with_duration_ms(mut self, duration_ms: i64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

impl Span {
    /// Schema check: known attributes must have the declared type, and every
    /// attribute name must be a known one (no free-form smuggling).
    pub fn validate(&self) -> Result<(), GateError> {
        if self.span_id.is_empty() || self.name.is_empty() {
            return Err(GateError::InvalidInput(
                "span_id/name must not be empty".into(),
            ));
        }
        if self.end_ms < self.start_ms {
            return Err(GateError::InvalidInput("end before start".into()));
        }
        if !self.policy_hash.starts_with("sha256:") || self.policy_hash.len() != 71 {
            return Err(GateError::InvalidInput(
                "policy_hash must be sha256:<hex>".into(),
            ));
        }
        for (name, value) in &self.attributes {
            let (_, expected) = GENAI_ATTRIBUTES
                .iter()
                .find(|(known, _)| known == name)
                .ok_or_else(|| GateError::InvalidInput(format!("unknown attribute {name:?}")))?;
            if value.kind() != *expected {
                return Err(GateError::InvalidInput(format!(
                    "attribute {name:?} has type {:?}, expected {:?}",
                    value.kind(),
                    expected
                )));
            }
            if let AttrValue::Float(f) = value {
                if !f.is_finite() {
                    return Err(GateError::Jcs("non-finite attribute".into()));
                }
            }
        }
        for required in ["gate.class", "gate.label", "gate.policy_hash"] {
            if !self.attributes.contains_key(required) {
                return Err(GateError::InvalidInput(format!(
                    "missing attribute {required:?}"
                )));
            }
        }
        Ok(())
    }

    /// Canonical bytes that get signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, GateError> {
        self.validate()?;
        let json = serde_json::to_string(self)
            .map_err(|e| GateError::Jcs(format!("span serialisation: {e}")))?;
        gate_jcs::canonicalize(&json)
            .map(String::into_bytes)
            .map_err(|e| GateError::Jcs(e.to_string()))
    }

    /// Build a span from the pieces the gate always knows, filling the
    /// conventional attributes that must be present on every span.
    #[must_use]
    pub fn build(spec: SpanSpec, clock: &dyn Clock) -> Self {
        let start_ms = clock.now_ms() - spec.duration_ms.max(0);
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "gate.class".to_owned(),
            AttrValue::Str(spec.class.as_str().to_owned()),
        );
        attributes.insert(
            "gate.label".to_owned(),
            AttrValue::Str(spec.label.as_str().to_owned()),
        );
        attributes.insert(
            "gate.policy_hash".to_owned(),
            AttrValue::Str(spec.policy_hash.clone()),
        );
        attributes.insert(
            "gate.duration_ms".to_owned(),
            AttrValue::Int(spec.duration_ms),
        );
        Self {
            span_id: spec.span_id,
            episode_id: spec.episode_id,
            call_id: spec.call_id,
            seq: spec.seq,
            prev: spec.prev,
            name: spec.name,
            class: spec.class,
            label: spec.label,
            policy_hash: spec.policy_hash,
            start_ms,
            end_ms: clock.now_ms(),
            status: SpanStatus::Ok,
            attributes,
        }
    }

    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: AttrValue) -> Self {
        self.attributes.insert(name.into(), value);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedSpan {
    pub span: Span,
    pub signature: Signature,
    /// \`sha256:<hex>\` of the canonical span bytes (this is what chains).
    pub digest: String,
}

impl SignedSpan {
    pub fn sign(span: Span, signer: &dyn Signer) -> Result<Self, GateError> {
        let bytes = span.signing_bytes()?;
        let digest = sha256_hex(&bytes);
        let signature = signer.sign(&bytes)?;
        Ok(Self {
            span,
            signature,
            digest,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GateError> {
        let json = serde_json::to_string(self)
            .map_err(|e| GateError::Jcs(format!("signed span serialisation: {e}")))?;
        gate_jcs::canonicalize(&json)
            .map(String::into_bytes)
            .map_err(|e| GateError::Jcs(e.to_string()))
    }

    pub fn verify_digest(&self) -> Result<(), GateError> {
        let bytes = self.span.signing_bytes()?;
        if sha256_hex(&bytes) != self.digest {
            return Err(GateError::VerificationFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// A sequence number was skipped (span deleted, T-SPAN-004).
    Gap {
        at: usize,
        expected: u64,
        found: u64,
    },
    /// Spans out of order (T-SPAN-005).
    Reorder { at: usize },
    /// \`prev\` does not point at the previous digest.
    BrokenLink { at: usize },
    /// Episode changed mid-chain.
    MixedEpisodes { at: usize },
    /// Signature or digest verification failed.
    BadSignature { at: usize },
    /// The chain was not started at sequence 0.
    BadStart { found: u64 },
}

/// Verify signatures, digests and the hash chain (T-SPAN-003..005).
pub fn verify_chain(spans: &[SignedSpan], verifier: &dyn Verifier) -> Result<(), ChainError> {
    let Some(first) = spans.first() else {
        return Ok(());
    };
    if first.span.seq != 0 {
        return Err(ChainError::BadStart {
            found: first.span.seq,
        });
    }
    let episode = &first.span.episode_id;
    for (i, signed) in spans.iter().enumerate() {
        if signed.span.episode_id != *episode {
            return Err(ChainError::MixedEpisodes { at: i });
        }
        if signed.span.seq != i as u64 {
            return if signed.span.seq < i as u64 {
                Err(ChainError::Reorder { at: i })
            } else {
                Err(ChainError::Gap {
                    at: i,
                    expected: i as u64,
                    found: signed.span.seq,
                })
            };
        }
        let expected_prev = if i == 0 {
            None
        } else {
            Some(spans[i - 1].digest.clone())
        };
        if signed.span.prev != expected_prev {
            return Err(ChainError::BrokenLink { at: i });
        }
        if signed.verify_digest().is_err() {
            return Err(ChainError::BadSignature { at: i });
        }
        let bytes = signed
            .span
            .signing_bytes()
            .map_err(|_| ChainError::BadSignature { at: i })?;
        verifier
            .verify(&bytes, &signed.signature)
            .map_err(|_| ChainError::BadSignature { at: i })?;
    }
    Ok(())
}

// ----------------------------------------------------------- durable commit

/// Injectable fsync so tests can prove the effect is withheld until the commit
/// is durable (T-SPAN-006).
pub trait Fsync: Send + Sync {
    fn sync(&self, file: &File) -> std::io::Result<()>;
}

#[derive(Debug, Default)]
pub struct RealFsync;

impl Fsync for RealFsync {
    fn sync(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
}

/// Receipt returned only after the record is durable. Callers must treat its
/// existence as the precondition for releasing an external side effect (INV-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub span_id: String,
    pub digest: String,
    pub seq: u64,
    pub durable: bool,
}

/// Append-only segment file with length-prefixed records and fsync on commit.
pub struct SegmentLog {
    path: PathBuf,
    file: Mutex<File>,
    fsync: Box<dyn Fsync>,
    next_seq: AtomicU64,
}

impl SegmentLog {
    pub fn open(path: impl AsRef<Path>, fsync: Box<dyn Fsync>) -> Result<Self, GateError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|e| GateError::StoreUnavailable(format!("open {}: {e}", path.display())))?;
        let next_seq = Self::read_all(&path)
            .map(|existing| existing.last().map_or(0, |s| s.span.seq + 1))
            .unwrap_or(0);
        Ok(Self {
            path,
            file: Mutex::new(file),
            fsync,
            next_seq: AtomicU64::new(next_seq),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::SeqCst)
    }

    /// Allocate the next (seq, prev) pair for an episode.
    pub fn allocate(&self, prev: Option<String>) -> (u64, Option<String>) {
        (self.next_seq.fetch_add(1, Ordering::SeqCst), prev)
    }

    /// Write one record and fsync it. Returns only after the fsync succeeded.
    pub fn append(&self, signed: &SignedSpan) -> Result<CommitReceipt, GateError> {
        let payload = signed.canonical_bytes()?;
        let len = u32::try_from(payload.len())
            .map_err(|_| GateError::InvalidInput("span too large".into()))?;
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| GateError::StoreUnavailable("segment lock poisoned".into()))?;
            file.write_all(&len.to_le_bytes())
                .and_then(|()| file.write_all(&payload))
                .map_err(|e| GateError::StoreUnavailable(format!("append: {e}")))?;
            (self.fsync)
                .sync(&file)
                .map_err(|e| GateError::StoreUnavailable(format!("fsync: {e}")))?;
        }
        Ok(CommitReceipt {
            span_id: signed.span.span_id.clone(),
            digest: signed.digest.clone(),
            seq: signed.span.seq,
            durable: true,
        })
    }

    /// Group commit: one fsync for a batch. Every receipt is still returned only
    /// after that fsync (DEC-P01 — pending human sign-off, see STATE.md).
    pub fn append_batch(&self, batch: &[SignedSpan]) -> Result<Vec<CommitReceipt>, GateError> {
        let mut payloads = Vec::with_capacity(batch.len());
        for signed in batch {
            let payload = signed.canonical_bytes()?;
            let len = u32::try_from(payload.len())
                .map_err(|_| GateError::InvalidInput("span too large".into()))?;
            payloads.push((len, payload));
        }
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| GateError::StoreUnavailable("segment lock poisoned".into()))?;
            for (len, payload) in &payloads {
                file.write_all(&len.to_le_bytes())
                    .and_then(|()| file.write_all(payload))
                    .map_err(|e| GateError::StoreUnavailable(format!("append: {e}")))?;
            }
            (self.fsync)
                .sync(&file)
                .map_err(|e| GateError::StoreUnavailable(format!("fsync: {e}")))?;
        }
        Ok(batch
            .iter()
            .map(|s| CommitReceipt {
                span_id: s.span.span_id.clone(),
                digest: s.digest.clone(),
                seq: s.span.seq,
                durable: true,
            })
            .collect())
    }

    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<SignedSpan>, GateError> {
        let mut file = match File::open(path.as_ref()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(GateError::StoreUnavailable(format!(
                    "open {}: {e}",
                    path.as_ref().display()
                )))
            }
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| GateError::StoreUnavailable(format!("read: {e}")))?;
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset + 4 <= buf.len() {
            let len = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            offset += 4;
            let end = offset
                .checked_add(len)
                .ok_or_else(|| GateError::StoreUnavailable("corrupt length".into()))?;
            let payload = buf
                .get(offset..end)
                .ok_or_else(|| GateError::StoreUnavailable("truncated record".into()))?;
            let text = std::str::from_utf8(payload)
                .map_err(|_| GateError::StoreUnavailable("record is not UTF-8".into()))?;
            let signed: SignedSpan = serde_json::from_str(text)
                .map_err(|e| GateError::StoreUnavailable(format!("corrupt record: {e}")))?;
            out.push(signed);
            offset = end;
        }
        if offset != buf.len() {
            return Err(GateError::StoreUnavailable("trailing bytes".into()));
        }
        Ok(out)
    }
}

/// Exporter boundary. In production this is a separate fd/UDS with distinct
/// credentials the agent process cannot reach; loss of the exporter is a
/// fail-closed condition for every class with an external side effect
/// (T-SPAN-007, INV-12).
pub trait Exporter: Send + Sync {
    fn export(&self, signed: &SignedSpan) -> Result<(), GateError>;
}

#[derive(Debug, Default)]
pub struct NullExporter;

impl Exporter for NullExporter {
    fn export(&self, _signed: &SignedSpan) -> Result<(), GateError> {
        Ok(())
    }
}

/// Channel exporter used by tests and the shadow-mode binary.
pub struct ChannelExporter {
    sender: Mutex<std::sync::mpsc::Sender<SignedSpan>>,
}

impl ChannelExporter {
    #[must_use]
    pub fn new(sender: std::sync::mpsc::Sender<SignedSpan>) -> Self {
        Self {
            sender: Mutex::new(sender),
        }
    }
}

impl Exporter for ChannelExporter {
    fn export(&self, signed: &SignedSpan) -> Result<(), GateError> {
        self.sender
            .lock()
            .map_err(|_| GateError::ExporterUnavailable)?
            .send(signed.clone())
            .map_err(|_| GateError::ExporterUnavailable)
    }
}

/// The gate-side commit path: sign → durable commit → export.
///
/// The returned receipt means *durable*; the caller must not release an effect
/// before it exists.
pub struct SpanPipeline<'a> {
    pub signer: &'a dyn Signer,
    pub log: &'a SegmentLog,
    pub exporter: &'a dyn Exporter,
}

impl SpanPipeline<'_> {
    pub fn commit(&self, span: Span) -> Result<CommitReceipt, GateError> {
        let signed = SignedSpan::sign(span, self.signer)?;
        let receipt = self.log.append(&signed)?;
        if !receipt.durable {
            // Unreachable with SegmentLog, but never release an effect on an
            // unproven commit (INV-1).
            return Err(GateError::Internal("commit reported non-durable".into()));
        }
        self.exporter.export(&signed)?;
        Ok(receipt)
    }
}

/// Map an exporter failure through the single fail-closed mapping (T-SPAN-007).
#[must_use]
pub fn exporter_failure_decision(
    class: Class,
    policy: gate_core::failclosed::ExporterLossPolicy,
) -> gate_core::Decision {
    let decision = gate_core::failclosed::map_error(&GateError::ExporterUnavailable, class, policy);
    debug_assert!(
        decision.verdict() == gate_core::Verdict::Deny || class.is_read_only(),
        "exporter loss must deny every class with an external side effect"
    );
    let _ = ReasonCode::DenyFailClosed;
    decision
}

/// Signature suite accepted for spans (crypto agility, NF-R6).
#[must_use]
pub fn span_suite_ok(suite: SuiteId) -> bool {
    matches!(suite, SuiteId::Ed25519 | SuiteId::P256Sha256)
}

/// M3 implementation of [`gate_core::LeafSink`]: every ledger leaf goes through
/// the signed span chain, so it inherits INV-1 (durable commit before release).
pub struct SpanLeafSink {
    signer: std::sync::Arc<dyn Signer>,
    log: std::sync::Arc<SegmentLog>,
    clock: std::sync::Arc<dyn Clock>,
    episode: EpisodeId,
    policy_hash: String,
    seq: std::sync::atomic::AtomicU64,
    prev: std::sync::Mutex<Option<String>>,
}

impl SpanLeafSink {
    #[must_use]
    pub fn new(
        signer: std::sync::Arc<dyn Signer>,
        log: std::sync::Arc<SegmentLog>,
        clock: std::sync::Arc<dyn Clock>,
        episode: EpisodeId,
        policy_hash: impl Into<String>,
    ) -> Self {
        let seq = log.next_seq();
        Self {
            signer,
            log,
            clock,
            episode,
            policy_hash: policy_hash.into(),
            seq: std::sync::atomic::AtomicU64::new(seq),
            prev: std::sync::Mutex::new(None),
        }
    }
}

impl gate_core::LeafSink for SpanLeafSink {
    fn sink_leaf(&self, leaf_type: &str, digest: &str, payload: &[u8]) -> Result<(), GateError> {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let prev = self.prev.lock().map(|p| p.clone()).unwrap_or(None);
        let spec = SpanSpec::new(
            format!("span_{leaf_type}_{seq}"),
            self.episode.clone(),
            seq,
            prev,
            format!("gate.{leaf_type}"),
            Class::ReadOnly,
            self.policy_hash.clone(),
        )
        .with_duration_ms(0);
        let mut span = Span::build(spec, self.clock.as_ref());
        span.attributes.insert(
            "gate.leaf_type".to_owned(),
            AttrValue::Str(leaf_type.to_owned()),
        );
        span.attributes.insert(
            "gate.leaf_digest".to_owned(),
            AttrValue::Str(digest.to_owned()),
        );
        span.attributes.insert(
            "gate.call_digest".to_owned(),
            AttrValue::Str(gate_crypto::sha256_hex(payload)),
        );
        let signed = SignedSpan::sign(span, self.signer.as_ref())?;
        self.log.append(&signed)?;
        if let Ok(mut p) = self.prev.lock() {
            *p = Some(signed.digest.clone());
        }
        Ok(())
    }
}
