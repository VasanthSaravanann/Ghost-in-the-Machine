//! mcp-gate — inline MCP proxy in shadow (observe-only) mode (plan.md M0-T06).
//!
//! The gate evaluates every `tools/call` against the pinned policy and the
//! provenance closure, signs a span for it, and — in shadow mode — always
//! forwards while recording what it *would* have blocked. That report is what
//! lets G-M0 be reasoned about before enforcement is switched on.

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

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gate_core::{AuthClosure, Class, Decision, EpisodeId, GateError, IdFactory, Label, ReasonCode};
use gate_crypto::{Ed25519Signer, KeyId};
use gate_policy::{CallRequest, FsResolver, Policy, PolicyEngine};
use gate_provenance::TaintPath;
use gate_span::{AttrValue, RealFsync, SegmentLog, SignedSpan, Span, SpanSpec};
use gate_transport::{
    ConnectionContext, Direction, Frame, FrameKind, Mediation, Mediator, TransportEvent,
};
use serde::{Deserialize, Serialize};

/// Gate configuration. Deliberately small: policy, span log, mode.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Path to the TOML policy (plan.md §9.1).
    pub policy: PathBuf,
    /// Append-only span segment file.
    pub spans: PathBuf,
    /// Observe-only (true) or enforcing (false).
    #[serde(default = "default_shadow")]
    pub shadow: bool,
    /// Maximum accepted JSON-RPC message size.
    #[serde(default = "default_max_message")]
    pub max_message_bytes: usize,
    /// Dev-only signing seed (hex, 32 bytes). Production must use the KeyStore.
    #[serde(default = "default_seed")]
    pub dev_signing_seed: String,
}

fn default_shadow() -> bool {
    true
}

fn default_max_message() -> usize {
    gate_transport::DEFAULT_MAX_MESSAGE_BYTES
}

fn default_seed() -> String {
    "11".repeat(32)
}

impl Config {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, GateError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| GateError::InvalidInput(format!("config: {e}")))?;
        toml::from_str(&text).map_err(|e| GateError::InvalidInput(format!("config: {e}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WouldBlock {
    pub tool: String,
    pub verdict: String,
    pub reasons: Vec<String>,
    pub at_ms: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub evaluated: u64,
    pub would_block: Vec<WouldBlock>,
    pub shadow: bool,
    pub policy_hash: String,
}

/// The gate: policy engine + span chain + would-have-blocked recorder.
pub struct Gate {
    engine: PolicyEngine,
    policy_hash: String,
    clock: Arc<dyn gate_core::Clock>,
    // Reserved for content-addressed call/span ids once the transport supplies
    // the raw request bytes (M2 wiring).
    #[allow(dead_code)]
    ids: IdFactory,
    signer: Ed25519Signer,
    log: SegmentLog,
    episode: EpisodeId,
    seq: AtomicU64,
    prev: Mutex<Option<String>>,
    shadow: bool,
    evaluated: AtomicU64,
    would_block: Mutex<Vec<WouldBlock>>,
}

impl Gate {
    pub fn new(
        policy_text: &str,
        spans_path: impl AsRef<std::path::Path>,
        shadow: bool,
        seed_hex: &str,
        clock: Arc<dyn gate_core::Clock>,
    ) -> Result<Self, GateError> {
        let policy = Arc::new(
            Policy::parse(policy_text)
                .map_err(|e| GateError::InvalidInput(format!("policy: {e}")))?,
        );
        let policy_hash = policy.hash().to_owned();
        let engine = PolicyEngine::new(Arc::clone(&policy), Arc::new(FsResolver));
        let seed: [u8; 32] = decode_seed(seed_hex)?;
        let signer = Ed25519Signer::from_seed(KeyId::new("gate-dev"), &seed);
        let log = SegmentLog::open(spans_path, Box::new(RealFsync))?;
        let seq = log.next_seq();
        let ids = IdFactory::new(Arc::new(DevRng));
        Ok(Self {
            engine,
            policy_hash,
            clock,
            ids,
            signer,
            log,
            episode: EpisodeId::from("ep_gate"),
            seq: AtomicU64::new(seq),
            prev: Mutex::new(None),
            shadow,
            evaluated: AtomicU64::new(0),
            would_block: Mutex::new(Vec::new()),
        })
    }

    /// Evaluate one `tools/call`. Returns the decision and records a span.
    pub fn evaluate(&self, frame: &Frame) -> Result<Decision, GateError> {
        let (tool, params) = call_arguments(frame)?;
        let closure = AuthClosure::new();
        let request = CallRequest::new(tool.clone(), params).with_closure(closure);
        let decision = self.engine.decide(&request);
        self.evaluated.fetch_add(1, Ordering::SeqCst);
        // Record the would-be block BEFORE the span commit: a span failure must
        // not erase the evidence of the decision (INV-1 still denies in enforce
        // mode because record_span's error propagates below).
        let blocked = decision.verdict() != gate_core::Verdict::Allow;
        if blocked {
            if let Ok(mut list) = self.would_block.lock() {
                list.push(WouldBlock {
                    tool: tool.clone(),
                    verdict: format!("{:?}", decision.verdict()),
                    reasons: decision
                        .reasons()
                        .iter()
                        .map(|r| r.code().to_owned())
                        .collect(),
                    at_ms: self.clock.now_ms(),
                });
            }
        }
        self.record_span(&tool, &decision)?;
        Ok(decision)
    }

    fn record_span(&self, tool: &str, decision: &Decision) -> Result<(), GateError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let prev = self.prev.lock().map(|p| p.clone()).unwrap_or(None);
        let class = self
            .engine
            .policy()
            .tool(tool)
            .map_or(Class::ReadOnly, |t| t.class);
        let label = decision
            .closure()
            .weakest()
            .unwrap_or(Label::PrincipalDirect);
        let mut span = Span::build(
            SpanSpec::new(
                format!("span_{seq}"),
                self.episode.clone(),
                seq,
                prev,
                "mcp.tools/call",
                class,
                self.policy_hash.clone(),
            )
            .with_duration_ms(0),
            self.clock.as_ref(),
        );
        span.attributes.insert(
            "gate.decision".to_owned(),
            AttrValue::Str(format!("{:?}", decision.verdict())),
        );
        span.attributes.insert(
            "gate.reason".to_owned(),
            AttrValue::Str(
                decision
                    .reasons()
                    .iter()
                    .map(|r| r.code())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        );
        span.attributes.insert(
            "gate.label".to_owned(),
            AttrValue::Str(label.as_str().to_owned()),
        );
        let signed = SignedSpan::sign(span, &self.signer)?;
        self.log.append(&signed)?;
        if let Ok(mut p) = self.prev.lock() {
            *p = Some(signed.digest.clone());
        }
        Ok(())
    }

    #[must_use]
    pub fn report(&self) -> Report {
        Report {
            evaluated: self.evaluated.load(Ordering::SeqCst),
            would_block: self
                .would_block
                .lock()
                .map(|b| b.clone())
                .unwrap_or_default(),
            shadow: self.shadow,
            policy_hash: self.policy_hash.clone(),
        }
    }

    #[must_use]
    pub fn shadow(&self) -> bool {
        self.shadow
    }

    /// Attach a taint path to a call (used by the taint pipeline in M2).
    #[must_use]
    pub fn tainted(&self, call: CallRequest, taint: &TaintPath) -> CallRequest {
        call.with_taint(taint.clone())
    }
}

fn decode_seed(hex: &str) -> Result<[u8; 32], GateError> {
    let bytes = gate_transport::frame::hex_decode(hex)
        .ok_or_else(|| GateError::InvalidInput("dev_signing_seed must be 64 hex chars".into()))?;
    bytes
        .try_into()
        .map_err(|_| GateError::InvalidInput("dev_signing_seed must be 32 bytes".into()))
}

#[derive(Debug, Default)]
struct DevRng;

impl gate_core::Rng for DevRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
}

/// Extract `(tool, params)` from a JSON-RPC `tools/call` frame.
pub fn call_arguments(
    frame: &Frame,
) -> Result<(String, serde_json::Map<String, serde_json::Value>), GateError> {
    let value: serde_json::Value = serde_json::from_str(&frame.raw)
        .map_err(|e| GateError::InvalidInput(format!("frame: {e}")))?;
    let params = value
        .get("params")
        .ok_or_else(|| GateError::InvalidInput("missing params".into()))?;
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| GateError::InvalidInput("missing tool name".into()))?;
    let arguments = params
        .get("arguments")
        .and_then(|a| a.as_object())
        .cloned()
        .unwrap_or_default();
    Ok((name.to_owned(), arguments))
}

/// Transport mediator. In shadow mode every call is forwarded; the decision is
/// only recorded. In enforce mode a non-Allow verdict blocks the request.
impl Mediator for Gate {
    fn mediate(&self, _ctx: &ConnectionContext, direction: Direction, frame: &Frame) -> Mediation {
        if direction != Direction::ClientToServer {
            return Mediation::Forward;
        }
        let FrameKind::Request { .. } = frame.kind else {
            return Mediation::Forward;
        };
        if frame.method() != Some("tools/call") {
            return Mediation::Forward;
        }
        match self.evaluate(frame) {
            Ok(decision) if decision.verdict() == gate_core::Verdict::Allow => Mediation::Forward,
            Ok(_) if self.shadow => Mediation::Forward,
            Ok(_) => Mediation::Block {
                reason: "denied by gate",
            },
            Err(_) => {
                if self.shadow {
                    Mediation::Forward
                } else {
                    Mediation::Block {
                        reason: "gate error (fail closed)",
                    }
                }
            }
        }
    }
}

/// Newtype so a shared gate handle can be used as the proxy's mediator
/// (Rust's orphan rules forbid implementing the foreign `Mediator` for `Arc`).
#[derive(Clone)]
pub struct SharedGate(pub Arc<Gate>);

impl Mediator for SharedGate {
    fn mediate(&self, ctx: &ConnectionContext, direction: Direction, frame: &Frame) -> Mediation {
        self.0.mediate(ctx, direction, frame)
    }
}

/// Reason codes seen in a report, for `mcp-audit`/dashboards.
#[must_use]
pub fn reasons_in(report: &Report) -> Vec<ReasonCode> {
    report
        .would_block
        .iter()
        .flat_map(|b| b.reasons.iter())
        .filter_map(|code| ReasonCode::ALL.iter().copied().find(|r| r.code() == code))
        .collect()
}

/// Events are surfaced, never swallowed (transport contract).
#[derive(Debug, Default)]
pub struct CountingSink {
    pub count: AtomicU64,
}

impl gate_transport::EventSink for CountingSink {
    fn emit(&self, _event: TransportEvent) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}
