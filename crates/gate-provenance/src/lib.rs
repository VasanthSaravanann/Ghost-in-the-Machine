//! gate-provenance — lattice, ancestry DAG, structural taint and control-flow
//! tracking (plan.md M2-T01..T04).
//!
//! INV-3: a derived value is never more trusted than any input. Every segment
//! carries exactly one [`Label`]; insertion rejects a label above the meet of
//! its parents, so taint cannot be silently dropped. Provenance is
//! *structural*: transforming untrusted text (paraphrase, translation,
//! summarisation) cannot change its ancestry, so it cannot launder taint.

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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use gate_core::{Label, SegmentId};
use gate_crypto::sha256_hex;
use serde::{Deserialize, Serialize};

pub mod persist;

/// Where a segment came from. `locator` is what an explanation can point at
/// ("ticket #8841", "line 14") without storing the content itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRef {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

impl SourceRef {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            locator: None,
        }
    }

    #[must_use]
    pub fn with_locator(id: impl Into<String>, locator: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            locator: Some(locator.into()),
        }
    }
}

impl fmt::Display for SourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.locator {
            Some(locator) => write!(f, "{} ({locator})", self.id),
            None => f.write_str(&self.id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    UnknownParent(SegmentId),
    /// A segment claimed more trust than its parents allow (INV-3).
    TaintRaised {
        claimed: Label,
        allowed: Label,
    },
    EmptySource,
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParent(id) => write!(f, "unknown parent segment {id}"),
            Self::TaintRaised { claimed, allowed } => {
                write!(
                    f,
                    "label {claimed} is more trusted than the parents allow ({allowed})"
                )
            }
            Self::EmptySource => f.write_str("segment source id must not be empty"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// One typed segment: exactly one label, a causal ancestry set, and the turn it
/// was observed in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub id: SegmentId,
    pub label: Label,
    pub parent_label: Option<Label>,
    pub source: SourceRef,
    pub content_digest: String,
    pub parents: BTreeSet<SegmentId>,
    pub turn: u64,
}

#[derive(Clone, Debug)]
pub struct SegmentSpec {
    pub label: Label,
    pub source: SourceRef,
    pub content: String,
    /// Persistence hint: when set, this digest is used instead of hashing
    /// `content`, so the exact content-addressed id survives a reload even when
    /// the original content is not persisted (only the digest is).
    pub content_digest_hint: Option<String>,
    pub parents: Vec<SegmentId>,
    pub turn: u64,
}

impl SegmentSpec {
    #[must_use]
    pub fn new(
        label: Label,
        source: SourceRef,
        content: impl Into<String>,
        parents: Vec<SegmentId>,
        turn: u64,
    ) -> Self {
        Self {
            label,
            source,
            content: content.into(),
            content_digest_hint: None,
            parents,
            turn,
        }
    }

    /// Rebuild a spec from a stored segment, preserving its exact id.
    #[must_use]
    pub fn from_segment(segment: &Segment) -> Self {
        Self {
            label: segment.label,
            source: segment.source.clone(),
            content: String::new(),
            content_digest_hint: Some(segment.content_digest.clone()),
            parents: segment.parents.iter().cloned().collect(),
            turn: segment.turn,
        }
    }
}

/// Append-only provenance store. Deterministic: no clock, no RNG, sorted
/// iteration only.
#[derive(Clone, Debug, Default)]
pub struct ProvenanceStore {
    segments: BTreeMap<SegmentId, Segment>,
    turn_windows: BTreeMap<u64, BTreeSet<SegmentId>>,
    /// source id -> the content digest the principal endorsed.
    endorsed: BTreeMap<String, String>,
}

impl ProvenanceStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an endorsed corpus: hash-identified, so a tampered copy is
    /// demoted to `EXTERNAL_UNTRUSTED_DATA` (T-PRV-005..015).
    pub fn register_endorsed_source(&mut self, source: impl Into<String>, content_digest: &str) {
        self.endorsed
            .insert(source.into(), content_digest.to_owned());
    }

    #[must_use]
    pub fn segment(&self, id: &SegmentId) -> Option<&Segment> {
        self.segments.get(id)
    }

    #[must_use]
    pub fn label_of(&self, id: &SegmentId) -> Option<Label> {
        self.segments.get(id).map(|s| s.label)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// All stored ids in deterministic order.
    #[must_use]
    pub fn ids(&self) -> Vec<SegmentId> {
        self.segments.keys().cloned().collect()
    }

    /// `(source, digest)` pairs for every registered endorsed corpus.
    #[must_use]
    pub fn endorsed_entries(&self) -> Vec<(String, String)> {
        self.endorsed
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Segments observed in a turn's input window, in deterministic order.
    #[must_use]
    pub fn turn_window(&self, turn: u64) -> Vec<SegmentId> {
        self.turn_windows
            .get(&turn)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Transitive ancestry (including the segment itself).
    #[must_use]
    pub fn ancestry(&self, id: &SegmentId) -> BTreeSet<SegmentId> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id.clone()];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if let Some(segment) = self.segments.get(&current) {
                stack.extend(segment.parents.iter().cloned());
            }
        }
        seen
    }

    /// Meet of the labels of `ids`; `None` for an empty set.
    #[must_use]
    pub fn derived_label(&self, ids: &[SegmentId]) -> Option<Label> {
        let labels: Vec<Label> = ids.iter().filter_map(|id| self.label_of(id)).collect();
        if labels.is_empty() {
            None
        } else {
            Some(Label::derive(labels.iter()))
        }
    }

    /// Insert a segment. The stored label is the meet of the declared label and
    /// the parents' meet; a declared label above that is an error, never a
    /// silent upgrade.
    pub fn insert(&mut self, spec: SegmentSpec) -> Result<Segment, ProvenanceError> {
        if spec.source.id.is_empty() {
            return Err(ProvenanceError::EmptySource);
        }
        let mut parents = BTreeSet::new();
        for parent in &spec.parents {
            if !self.segments.contains_key(parent) {
                return Err(ProvenanceError::UnknownParent(parent.clone()));
            }
            parents.insert(parent.clone());
        }
        let parent_label = if parents.is_empty() {
            None
        } else {
            let labels: Vec<Label> = parents.iter().filter_map(|id| self.label_of(id)).collect();
            Some(Label::derive(labels.iter()))
        };

        let content_digest = match &spec.content_digest_hint {
            Some(hint) => hint.clone(),
            None => sha256_hex(spec.content.as_bytes()),
        };
        let mut label = self.effective_label(&spec, &content_digest);
        if let Some(parent_label) = parent_label {
            if label > parent_label {
                return Err(ProvenanceError::TaintRaised {
                    claimed: label,
                    allowed: parent_label,
                });
            }
            label = label.meet(parent_label);
        }

        let id = segment_id(label, &spec.source, &content_digest, &parents);
        if let Some(existing) = self.segments.get(&id) {
            // Idempotent: same bytes, same label, same ancestry.
            self.turn_windows
                .entry(spec.turn)
                .or_default()
                .insert(existing.id.clone());
            return Ok(existing.clone());
        }

        let segment = Segment {
            id: id.clone(),
            label,
            parent_label,
            source: spec.source,
            content_digest,
            parents,
            turn: spec.turn,
        };
        self.segments.insert(id.clone(), segment.clone());
        self.turn_windows.entry(spec.turn).or_default().insert(id);
        Ok(segment)
    }

    fn effective_label(&self, spec: &SegmentSpec, content_digest: &str) -> Label {
        match self.endorsed.get(&spec.source.id) {
            Some(expected) if expected == content_digest => Label::EndorsedCorpus,
            // Registered but tampered: never trust it more than untrusted data.
            Some(_) => Label::ExternalUntrustedData,
            None => spec.label,
        }
    }
}

fn segment_id(
    label: Label,
    source: &SourceRef,
    content_digest: &str,
    parents: &BTreeSet<SegmentId>,
) -> SegmentId {
    let mut material = String::with_capacity(64 + parents.len() * 40);
    material.push_str(label.as_str());
    material.push('\u{1f}');
    material.push_str(&source.id);
    material.push('\u{1f}');
    if let Some(locator) = &source.locator {
        material.push_str(locator);
    }
    material.push('\u{1f}');
    material.push_str(content_digest);
    for parent in parents {
        material.push('\u{1f}');
        material.push_str(parent.as_str());
    }
    let hash = sha256_hex(material.as_bytes());
    SegmentId::from(format!("seg_{}", hash.trim_start_matches("sha256:")).as_str())
}

// ------------------------------------------------------------- structural taint

/// Optional attribution scoring. It may only *add* taint: the ancestry meet
/// always dominates (T-TNT-005/006).
pub trait TaintScorer: Send + Sync {
    fn score(&self, output: &str, inputs: &[&Segment]) -> Option<Label>;
}

#[derive(Debug, Default)]
pub struct NoOpScorer;

impl TaintScorer for NoOpScorer {
    fn score(&self, _output: &str, _inputs: &[&Segment]) -> Option<Label> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintResult {
    pub label: Label,
    /// Untrusted segments that contributed, deterministically ordered.
    pub sources: Vec<SegmentId>,
}

/// Structural taint of a turn's output: *any* untrusted segment in the turn's
/// input window taints every output of that turn (P2-R3).
#[must_use]
pub fn turn_taint(
    store: &ProvenanceStore,
    turn: u64,
    output: &str,
    scorer: &dyn TaintScorer,
) -> Option<TaintResult> {
    let window = store.turn_window(turn);
    let inputs: Vec<&Segment> = window.iter().filter_map(|id| store.segment(id)).collect();
    if inputs.is_empty() {
        return None;
    }
    let ancestry_label = Label::derive(inputs.iter().map(|s| &s.label));
    let label = match scorer.score(output, &inputs) {
        Some(extra) => ancestry_label.meet(extra),
        None => ancestry_label,
    };
    Some(TaintResult {
        label,
        sources: window
            .into_iter()
            .filter(|id| {
                store
                    .label_of(id)
                    .is_some_and(|l| l < Label::PrincipalDirect)
            })
            .collect(),
    })
}

/// A principal-only checkpoint that screens off specific segments (T-CTL-005).
/// Only the principal channel may construct one; the gate never builds it from
/// model output.
#[derive(Clone, Debug)]
pub struct PrincipalCheckpoint {
    pub principal: gate_core::PrincipalId,
    pub covers: BTreeSet<SegmentId>,
}

impl PrincipalCheckpoint {
    #[must_use]
    pub fn new(
        principal: gate_core::PrincipalId,
        covers: impl IntoIterator<Item = SegmentId>,
    ) -> Self {
        Self {
            principal,
            covers: covers.into_iter().collect(),
        }
    }
}

/// Implicit control-flow taint (P2-R4): a call is tainted if an untrusted
/// segment is in the window that preceded it and is not provably screened off
/// by a principal-only checkpoint.
#[must_use]
pub fn control_flow_taint(
    store: &ProvenanceStore,
    window: &[SegmentId],
    checkpoint: Option<&PrincipalCheckpoint>,
) -> Option<TaintResult> {
    let mut sources = Vec::new();
    let mut labels = Vec::new();
    for id in window {
        let Some(segment) = store.segment(id) else {
            continue;
        };
        if checkpoint.is_some_and(|c| c.covers.contains(id)) {
            continue;
        }
        labels.push(segment.label);
        if segment.label < Label::PrincipalDirect {
            sources.push(id.clone());
        }
    }
    if labels.is_empty() {
        return None;
    }
    Some(TaintResult {
        label: Label::derive(labels.iter()),
        sources,
    })
}

/// Explanation of a blocked call: source, hops, and the call that was stopped
/// (P2-R5/P2-R8). Rendered text is bounded: at most 3 hops and 280 characters
/// per hop, with an explicit truncation marker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: SourceRef,
    pub source_label: Label,
    pub hops: Vec<Hop>,
    pub blocked_call: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub segment: SegmentId,
    pub turn: u64,
    pub label: Label,
}

pub const MAX_RENDER_HOPS: usize = 3;
pub const MAX_RENDER_CHARS: usize = 280;
const TRUNCATION_MARKER: &str = " …";

impl TaintPath {
    /// Build a path from the taint sources to `blocked_call`, taking the
    /// least-trusted source as the explanation root.
    #[must_use]
    pub fn build(
        store: &ProvenanceStore,
        sources: &[SegmentId],
        blocked_call: impl Into<String>,
    ) -> Option<Self> {
        // Explain from the *root* of the influence chain (the least-trusted
        // ancestor with the shortest ancestry), not from the last hop.
        let mut candidates: Vec<Segment> = sources
            .iter()
            .flat_map(|id| store.ancestry(id))
            .filter_map(|id| store.segment(&id).cloned())
            .collect();
        candidates.sort_by(|a, b| {
            (a.label, store.ancestry(&a.id).len(), a.id.clone()).cmp(&(
                b.label,
                store.ancestry(&b.id).len(),
                b.id.clone(),
            ))
        });
        let root = candidates.into_iter().next()?;
        let hops = store
            .ancestry(&root.id)
            .into_iter()
            .filter_map(|id| store.segment(&id))
            .map(|segment| Hop {
                segment: segment.id.clone(),
                turn: segment.turn,
                label: segment.label,
            })
            .collect();
        Some(Self {
            source: root.source,
            source_label: root.label,
            hops,
            blocked_call: blocked_call.into(),
        })
    }

    /// Rendered explanation for `mcp-audit explain` / the endorsement brief.
    /// Bounded to [`MAX_RENDER_CHARS`] characters; omitted hops are counted,
    /// never silently dropped.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = format!(
            "blocked {}: influenced by {} [{}]",
            self.blocked_call,
            self.source,
            self.source_label.as_str()
        );
        let mut shown = 0usize;
        for hop in self.hops.iter() {
            let piece = format!(
                " <- {} (turn {}, {})",
                hop.segment,
                hop.turn,
                hop.label.as_str()
            );
            if shown >= MAX_RENDER_HOPS
                || text.chars().count() + piece.chars().count() + 24 > MAX_RENDER_CHARS
            {
                break;
            }
            text.push_str(&piece);
            shown += 1;
        }
        let omitted = self.hops.len().saturating_sub(shown);
        if omitted > 0 {
            let note = format!("{TRUNCATION_MARKER} ({omitted} more hops)");
            while text.chars().count() + note.chars().count() > MAX_RENDER_CHARS {
                if text.pop().is_none() {
                    break;
                }
            }
            text.push_str(&note);
        }
        text
    }

    /// Stable digest for the ledger (Leaf A `taint_path_digest`).
    #[must_use]
    pub fn digest(&self) -> String {
        let mut material = format!(
            "{}|{}|{}",
            self.blocked_call,
            self.source.id,
            self.source_label.as_str()
        );
        if let Some(locator) = &self.source.locator {
            material.push('|');
            material.push_str(locator);
        }
        for hop in &self.hops {
            material.push('|');
            material.push_str(hop.segment.as_str());
            material.push(':');
            material.push_str(&hop.turn.to_string());
        }
        sha256_hex(material.as_bytes())
    }
}
