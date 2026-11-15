//! gate-core — the decision vocabulary (plan.md §2.3).
//!
//! Everything in the authorisation path is built from these types. There is
//! exactly one place where an error becomes a verdict: [`failclosed`].

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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub mod failclosed;

/// Provenance label. Ordered: `ExternalUntrustedData < EndorsedCorpus < PrincipalDirect`.
///
/// Derivation uses [`Label::meet`], the greatest lower bound, so a derived
/// value can never be more trusted than any of its inputs (INV-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Label {
    ExternalUntrustedData,
    EndorsedCorpus,
    PrincipalDirect,
}

impl Label {
    /// Lattice meet: the greatest lower bound. Commutative, associative,
    /// idempotent and monotone (T-CORE-001..004, T-PRV-003).
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        self.min(other)
    }

    /// Derive the label of a value computed from `parents` (INV-3).
    #[must_use]
    pub fn derive<'a>(parents: impl IntoIterator<Item = &'a Self>) -> Self {
        parents
            .into_iter()
            .copied()
            .reduce(Self::meet)
            .unwrap_or(Self::ExternalUntrustedData)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExternalUntrustedData => "EXTERNAL_UNTRUSTED_DATA",
            Self::EndorsedCorpus => "ENDORSED_CORPUS",
            Self::PrincipalDirect => "PRINCIPAL_DIRECT",
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Capability class. Ordered by blast radius; `ReadOnly` is the only class that
/// may degrade instead of denying (R4, T-CORE-007).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Class {
    ReadOnly,
    IdempotentWrite,
    ExternalEgress,
    Irreversible,
    PrivilegeGranting,
}

impl Class {
    #[must_use]
    pub fn is_read_only(self) -> bool {
        self == Self::ReadOnly
    }

    /// True for every class that can produce an external side effect, i.e.
    /// every class that may never degrade (P1-R5, R4).
    #[must_use]
    pub fn has_external_side_effect(self) -> bool {
        self != Self::ReadOnly
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "READ_ONLY",
            Self::IdempotentWrite => "IDEMPOTENT_WRITE",
            Self::ExternalEgress => "EXTERNAL_EGRESS",
            Self::Irreversible => "IRREVERSIBLE",
            Self::PrivilegeGranting => "PRIVILEGE_GRANTING",
        }
    }
}

macro_rules! id_type {
    ($name:ident, $prefix:literal) => {
        #[derive(
            Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn prefix() -> &'static str {
                $prefix
            }
        }

        impl From<&str> for $name {
            fn from(v: &str) -> Self {
                Self(v.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(v: String) -> Self {
                Self(v)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(CallId, "call_");
id_type!(EpisodeId, "ep_");
id_type!(SegmentId, "seg_");
id_type!(LeafId, "leaf_");
id_type!(PrincipalId, "prn_");

/// Injected clock (R6). Production wires the OS clock; tests wire [`FakeClock`].
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

/// Injected randomness (R6): salts, nonces, identifiers.
pub trait Rng: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]);
}

/// Deterministic identifier factory (T-CORE-009..012).
#[derive(Clone)]
pub struct IdFactory {
    rng: Arc<dyn Rng>,
    counter: Arc<AtomicU64>,
}

impl fmt::Debug for IdFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdFactory(..)")
    }
}

impl IdFactory {
    #[must_use]
    pub fn new(rng: Arc<dyn Rng>) -> Self {
        Self {
            rng,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn unique(&self, prefix: &str, scope: &str) -> String {
        let mut raw = [0u8; 16];
        self.rng.fill_bytes(&mut raw);
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut out = String::with_capacity(prefix.len() + scope.len() + 34);
        out.push_str(prefix);
        if !scope.is_empty() {
            out.push_str(&sanitise(scope));
            out.push('_');
        }
        out.push_str(&hex(&raw));
        out.push('_');
        out.push_str(&n.to_string());
        out
    }

    #[must_use]
    pub fn call_id(&self, episode: &str) -> CallId {
        CallId(self.unique(CallId::prefix(), episode))
    }

    #[must_use]
    pub fn episode_id(&self) -> EpisodeId {
        EpisodeId(self.unique(EpisodeId::prefix(), ""))
    }

    #[must_use]
    pub fn segment_id(&self) -> SegmentId {
        SegmentId(self.unique(SegmentId::prefix(), ""))
    }

    #[must_use]
    pub fn leaf_id(&self) -> LeafId {
        LeafId(self.unique(LeafId::prefix(), ""))
    }

    #[must_use]
    pub fn principal_id(&self) -> PrincipalId {
        PrincipalId(self.unique(PrincipalId::prefix(), ""))
    }
}

fn sanitise(scope: &str) -> String {
    scope
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// The closed set of reason codes (plan.md §9.3). Extend only with a decision
/// entry; free text never enters a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    // denials
    DenyUnpinned,
    DenyDrift,
    DenyParamNotAllowed,
    DenyParamInvalid,
    DenyTaintPivot,
    DenyBudget,
    DenyRate,
    DenySymmetry,
    DenyFraming,
    DenyToctou,
    DenyEndorsementTimeout,
    DenyTransparencyDegraded,
    DenySignerUnavailable,
    DenyFailClosed,
    // escalation
    EscalateEndorsementRequired,
    // allow
    AllowPolicy,
    // findings (never a verdict on their own)
    MetadataPoisoningSuspected,
    ApprovalSpamSuspected,
    PossibleRubberStamp,
    TransparencyDegraded,
}

impl ReasonCode {
    pub const ALL: [Self; 20] = [
        Self::DenyUnpinned,
        Self::DenyDrift,
        Self::DenyParamNotAllowed,
        Self::DenyParamInvalid,
        Self::DenyTaintPivot,
        Self::DenyBudget,
        Self::DenyRate,
        Self::DenySymmetry,
        Self::DenyFraming,
        Self::DenyToctou,
        Self::DenyEndorsementTimeout,
        Self::DenyTransparencyDegraded,
        Self::DenySignerUnavailable,
        Self::DenyFailClosed,
        Self::EscalateEndorsementRequired,
        Self::AllowPolicy,
        Self::MetadataPoisoningSuspected,
        Self::ApprovalSpamSuspected,
        Self::PossibleRubberStamp,
        Self::TransparencyDegraded,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DenyUnpinned => "DENY_UNPINNED",
            Self::DenyDrift => "DENY_DRIFT",
            Self::DenyParamNotAllowed => "DENY_PARAM_NOT_ALLOWED",
            Self::DenyParamInvalid => "DENY_PARAM_INVALID",
            Self::DenyTaintPivot => "DENY_TAINT_PIVOT",
            Self::DenyBudget => "DENY_BUDGET",
            Self::DenyRate => "DENY_RATE",
            Self::DenySymmetry => "DENY_SYMMETRY",
            Self::DenyFraming => "DENY_FRAMING",
            Self::DenyToctou => "DENY_TOCTOU",
            Self::DenyEndorsementTimeout => "DENY_ENDORSEMENT_TIMEOUT",
            Self::DenyTransparencyDegraded => "DENY_TRANSPARENCY_DEGRADED",
            Self::DenySignerUnavailable => "DENY_SIGNER_UNAVAILABLE",
            Self::DenyFailClosed => "DENY_FAIL_CLOSED",
            Self::EscalateEndorsementRequired => "ESCALATE_ENDORSEMENT_REQUIRED",
            Self::AllowPolicy => "ALLOW_POLICY",
            Self::MetadataPoisoningSuspected => "METADATA_POISONING_SUSPECTED",
            Self::ApprovalSpamSuspected => "APPROVAL_SPAM_SUSPECTED",
            Self::PossibleRubberStamp => "POSSIBLE_RUBBER_STAMP",
            Self::TransparencyDegraded => "TRANSPARENCY_DEGRADED",
        }
    }

    #[must_use]
    pub const fn is_denial(self) -> bool {
        matches!(
            self,
            Self::DenyUnpinned
                | Self::DenyDrift
                | Self::DenyParamNotAllowed
                | Self::DenyParamInvalid
                | Self::DenyTaintPivot
                | Self::DenyBudget
                | Self::DenyRate
                | Self::DenySymmetry
                | Self::DenyFraming
                | Self::DenyToctou
                | Self::DenyEndorsementTimeout
                | Self::DenyTransparencyDegraded
                | Self::DenySignerUnavailable
                | Self::DenyFailClosed
        )
    }

    #[must_use]
    pub const fn is_finding(self) -> bool {
        matches!(
            self,
            Self::MetadataPoisoningSuspected
                | Self::ApprovalSpamSuspected
                | Self::PossibleRubberStamp
                | Self::TransparencyDegraded
        )
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Deny,
    Escalate,
}

/// The deterministic set of `(segment_id, label)` a decision depended on
/// (plan.md §2.3). This is what `mcp-audit explain` prints.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthClosure(BTreeMap<SegmentId, Label>);

impl AuthClosure {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, segment: SegmentId, label: Label) {
        self.0.insert(segment, label);
    }

    #[must_use]
    pub fn get(&self, segment: &SegmentId) -> Option<Label> {
        self.0.get(segment).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SegmentId, &Label)> {
        self.0.iter()
    }

    /// Least-trusted label in the closure, if any.
    #[must_use]
    pub fn weakest(&self) -> Option<Label> {
        self.0.values().copied().min()
    }
}

impl FromIterator<(SegmentId, Label)> for AuthClosure {
    fn from_iter<T: IntoIterator<Item = (SegmentId, Label)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// The only output of `PolicyEngine::decide` (plan.md §2.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    verdict: Verdict,
    reasons: Vec<ReasonCode>,
    closure: AuthClosure,
}

impl Decision {
    #[must_use]
    pub fn new(verdict: Verdict, reasons: Vec<ReasonCode>, closure: AuthClosure) -> Self {
        Self {
            verdict,
            reasons,
            closure,
        }
    }

    #[must_use]
    pub fn allow(reasons: Vec<ReasonCode>, closure: AuthClosure) -> Self {
        Self::new(Verdict::Allow, reasons, closure)
    }

    #[must_use]
    pub fn deny(reason: ReasonCode) -> Self {
        Self::new(Verdict::Deny, vec![reason], AuthClosure::new())
    }

    #[must_use]
    pub fn deny_with(reasons: Vec<ReasonCode>, closure: AuthClosure) -> Self {
        Self::new(Verdict::Deny, reasons, closure)
    }

    #[must_use]
    pub fn escalate(reason: ReasonCode) -> Self {
        Self::new(Verdict::Escalate, vec![reason], AuthClosure::new())
    }

    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    #[must_use]
    pub fn reasons(&self) -> &[ReasonCode] {
        &self.reasons
    }

    #[must_use]
    pub fn closure(&self) -> &AuthClosure {
        &self.closure
    }

    #[must_use]
    pub fn with_closure(mut self, closure: AuthClosure) -> Self {
        self.closure = closure;
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: ReasonCode) -> Self {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
        self
    }
}

/// Every fallible operation in the TCB returns one of these. The `GateError`
/// → `Deny` mapping lives in [`failclosed`] and nowhere else (R4).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error("canonicalisation failed: {0}")]
    Jcs(String),
    #[error("signer unavailable")]
    SignerUnavailable,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("exporter unavailable")]
    ExporterUnavailable,
    #[error("store unavailable: {0}")]
    StoreUnavailable(String),
    #[error("policy missing or unpinned")]
    PolicyMissing,
    #[error("operation timed out")]
    Timeout,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal error: {0}")]
    Internal(String),
}
