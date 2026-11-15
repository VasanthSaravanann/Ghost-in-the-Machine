//! T-SPAN-001..014 (plan.md §5.3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use gate_core::failclosed::ExporterLossPolicy;
use gate_core::{CallId, Class, Decision, EpisodeId, GateError, ReasonCode, Verdict};
use gate_crypto::{Ed25519Signer, KeyId, Verifier};
use gate_span::{
    exporter_failure_decision, verify_chain, AttrValue, ChainError, ChannelExporter, CommitReceipt,
    Exporter, Fsync, RealFsync, SegmentLog, SignedSpan, Span, SpanPipeline, SpanSpec, SpanStatus,
};
use gate_testkit::FakeClock;
use tempfile::TempDir;

const POLICY_HASH: &str = "sha256:9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c";

struct Fixture {
    dir: TempDir,
    clock: FakeClock,
    signer: Ed25519Signer,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
            clock: FakeClock::new(1_700_000_000_000),
            signer: Ed25519Signer::from_seed(KeyId::new("span-key"), &[21u8; 32]),
        }
    }

    fn log(&self) -> SegmentLog {
        SegmentLog::open(self.dir.path().join("spans.seg"), Box::new(RealFsync)).unwrap()
    }

    fn span(&self, seq: u64, prev: Option<String>) -> Span {
        self.clock.advance(5);
        Span::build(
            SpanSpec::new(
                format!("span_{seq}"),
                EpisodeId::from("ep_test"),
                seq,
                prev,
                "mcp.tools/call",
                Class::ReadOnly,
                POLICY_HASH,
            )
            .with_call_id(CallId::from(format!("call_{seq}")))
            .with_duration_ms(5),
            &self.clock,
        )
    }

    fn chain(&self, n: u64) -> Vec<SignedSpan> {
        let mut out: Vec<SignedSpan> = Vec::new();
        for seq in 0..n {
            let prev = out.last().map(|s: &SignedSpan| s.digest.clone());
            let signed = SignedSpan::sign(self.span(seq, prev), &self.signer).unwrap();
            out.push(signed);
        }
        out
    }
}

// T-SPAN-001 — one signed span per mediated request/response.
#[test]
fn t_span_001_one_signed_span_per_exchange() {
    let f = Fixture::new();
    let log = f.log();
    let mut prev = None;
    for i in 0..7 {
        let signed = SignedSpan::sign(f.span(i, prev.clone()), &f.signer).unwrap();
        let receipt = log.append(&signed).unwrap();
        assert!(receipt.durable);
        prev = Some(signed.digest.clone());
    }
    let stored = SegmentLog::read_all(log.path()).unwrap();
    assert_eq!(stored.len(), 7);
    for signed in &stored {
        assert_eq!(signed.signature.suite, gate_crypto::SuiteId::Ed25519);
        assert_eq!(signed.signature.key_id.as_str(), "span-key");
    }
}

// T-SPAN-002 — the span is canonicalised before hashing.
#[test]
fn t_span_002_hash_is_over_canonical_bytes() {
    let f = Fixture::new();
    let signed = SignedSpan::sign(f.span(0, None), &f.signer).unwrap();
    let bytes = signed.span.signing_bytes().unwrap();
    assert_eq!(gate_crypto::sha256_hex(&bytes), signed.digest);
    // Canonical: parsing and re-canonicalising yields identical bytes.
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(gate_jcs::canonicalize(text).unwrap(), text);
    // Signature verifies over exactly those bytes.
    signed
        .span
        .signing_bytes()
        .map(|b| f.signer.verifying_key().verify(&b, &signed.signature))
        .unwrap()
        .unwrap();
}

// T-SPAN-003 — chain links.
#[test]
fn t_span_003_hash_chain() {
    let f = Fixture::new();
    let chain = f.chain(5);
    for window in chain.windows(2) {
        assert_eq!(
            window[1].span.prev.as_deref(),
            Some(window[0].digest.as_str())
        );
        assert_eq!(window[1].span.prev, Some(window[0].digest.clone()));
    }
    verify_chain(&chain, &f.signer.verifying_key()).unwrap();
}

// T-SPAN-004 — a deleted span is detected.
#[test]
fn t_span_004_gap_detected() {
    let f = Fixture::new();
    let mut chain = f.chain(5);
    chain.remove(2);
    assert!(matches!(
        verify_chain(&chain, &f.signer.verifying_key()),
        Err(ChainError::Gap { at: 2, .. }) | Err(ChainError::BrokenLink { at: 2 })
    ));
}

// T-SPAN-005 — reordered spans are detected.
#[test]
fn t_span_005_reorder_detected() {
    let f = Fixture::new();
    let mut chain = f.chain(5);
    chain.swap(1, 3);
    let err = verify_chain(&chain, &f.signer.verifying_key()).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::Reorder { .. } | ChainError::BrokenLink { .. } | ChainError::Gap { .. }
        ),
        "unexpected error: {err:?}"
    );
}

struct BlockingFsync {
    entered: mpsc::Sender<()>,
    release: std::sync::Mutex<mpsc::Receiver<()>>,
}

impl Fsync for BlockingFsync {
    fn sync(&self, file: &std::fs::File) -> std::io::Result<()> {
        let _ = self.entered.send(());
        if let Ok(rx) = self.release.lock() {
            let _ = rx.recv_timeout(Duration::from_secs(10));
        }
        file.sync_all()
    }
}

// T-SPAN-006 — the effect is not released until fsync has completed.
#[test]
fn t_span_006_no_effect_before_durable_commit() {
    let f = Fixture::new();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let log = Arc::new(
        SegmentLog::open(
            f.dir.path().join("blocking.seg"),
            Box::new(BlockingFsync {
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
            }),
        )
        .unwrap(),
    );
    let span = f.span(0, None);
    let signer = Arc::new(Ed25519Signer::from_seed(
        KeyId::new("span-key"),
        &[21u8; 32],
    ));
    let released = Arc::new(AtomicBool::new(false));

    let log2 = Arc::clone(&log);
    let released2 = Arc::clone(&released);
    let handle = std::thread::spawn(move || {
        let pipeline = SpanPipeline {
            signer: signer.as_ref(),
            log: log2.as_ref(),
            exporter: &gate_span::NullExporter,
        };
        let receipt: CommitReceipt = pipeline.commit(span).unwrap();
        // Effect release happens here, only after commit returned.
        released2.store(true, Ordering::SeqCst);
        receipt
    });

    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        !released.load(Ordering::SeqCst),
        "effect must not be released while fsync is in flight"
    );
    release_tx.send(()).unwrap();
    let receipt = handle.join().unwrap();
    assert!(receipt.durable);
    assert!(released.load(Ordering::SeqCst));
}

// T-SPAN-007 — exporter loss denies every class with external side effects.
#[test]
fn t_span_007_exporter_loss_denies() {
    let f = Fixture::new();
    let log = f.log();
    let (tx, rx) = mpsc::channel();
    drop(rx);
    let exporter = ChannelExporter::new(tx);
    let pipeline = SpanPipeline {
        signer: &f.signer,
        log: &log,
        exporter: &exporter,
    };
    assert_eq!(
        pipeline.commit(f.span(0, None)).unwrap_err(),
        GateError::ExporterUnavailable
    );

    for class in [
        Class::IdempotentWrite,
        Class::ExternalEgress,
        Class::Irreversible,
        Class::PrivilegeGranting,
    ] {
        let d = exporter_failure_decision(class, ExporterLossPolicy::Allow);
        assert_eq!(d.verdict(), Verdict::Deny, "{class:?}");
    }
    assert_eq!(
        exporter_failure_decision(Class::ReadOnly, ExporterLossPolicy::Allow).verdict(),
        Verdict::Allow
    );
    assert_eq!(
        exporter_failure_decision(Class::ReadOnly, ExporterLossPolicy::Deny).verdict(),
        Verdict::Deny
    );
}

// T-SPAN-008 — the export sink is not inherited by the agent process.
#[test]
fn t_span_008_agent_process_cannot_see_channel() {
    let f = Fixture::new();
    let log = f.log();
    log.append(&SignedSpan::sign(f.span(0, None), &f.signer).unwrap())
        .unwrap();
    let path = log.path().to_string_lossy().into_owned();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("ls -l /dev/fd 2>/dev/null; ls -l /proc/self/fd 2>/dev/null")
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        !listing.contains(&path),
        "child inherited the span sink: {listing}"
    );
}

// T-SPAN-009 — the policy hash travels with every span.
#[test]
fn t_span_009_policy_hash_present() {
    let f = Fixture::new();
    let span = f.span(0, None);
    assert_eq!(
        span.attributes.get("gate.policy_hash"),
        Some(&AttrValue::Str(POLICY_HASH.to_owned()))
    );
    assert_eq!(span.policy_hash, POLICY_HASH);
}

// T-SPAN-010 — a span that cannot be canonicalised denies.
#[test]
fn t_span_010_jcs_failure_denies() {
    let f = Fixture::new();
    let bad = f
        .span(0, None)
        .with_attribute("gate.score", AttrValue::Float(f64::NAN));
    assert!(matches!(
        SignedSpan::sign(bad, &f.signer).unwrap_err(),
        GateError::Jcs(_)
    ));
    let decision = gate_core::failclosed::map_error(
        &GateError::Jcs("non-finite".into()),
        Class::ExternalEgress,
        ExporterLossPolicy::Allow,
    );
    assert_eq!(decision.verdict(), Verdict::Deny);
}

// T-SPAN-011 — the GenAI/MCP attribute schema is enforced.
#[test]
fn t_span_011_attribute_conformance() {
    let f = Fixture::new();
    let mut span = f.span(0, None);
    span.attributes
        .insert("gen_ai.system".into(), AttrValue::Str("openai".into()));
    span.attributes.insert(
        "gen_ai.operation.name".into(),
        AttrValue::Str("execute_tool".into()),
    );
    span.attributes
        .insert("gen_ai.usage.input_tokens".into(), AttrValue::Int(42));
    span.attributes.insert(
        "mcp.tool.name".into(),
        AttrValue::Str("mailer:send_email".into()),
    );
    span.attributes.insert(
        "gen_ai.response.finish_reasons".into(),
        AttrValue::StrArray(vec!["stop".into()]),
    );
    span.validate().unwrap();
    let signed = SignedSpan::sign(span, &f.signer).unwrap();
    let json = String::from_utf8(signed.canonical_bytes().unwrap()).unwrap();
    for expected in [
        "gen_ai.system",
        "gen_ai.usage.input_tokens",
        "mcp.tool.name",
    ] {
        assert!(json.contains(expected), "missing {expected} in {json}");
    }
}

// T-SPAN-012 — unknown attribute names are rejected.
#[test]
fn t_span_012_unknown_attribute_rejected() {
    let f = Fixture::new();
    let span = f
        .span(0, None)
        .with_attribute("not.a.real.attribute", AttrValue::Str("x".into()));
    assert!(matches!(span.validate(), Err(GateError::InvalidInput(_))));
}

// T-SPAN-013 — type confusion on a known attribute is rejected.
#[test]
fn t_span_013_wrong_type_rejected() {
    let f = Fixture::new();
    let span = f
        .span(0, None)
        .with_attribute("gen_ai.usage.input_tokens", AttrValue::Str("42".into()));
    assert!(matches!(span.validate(), Err(GateError::InvalidInput(_))));
    assert_eq!(span.status, SpanStatus::Ok);
}

// T-SPAN-014 — canonical bytes are stable and tamper-evident.
#[test]
fn t_span_014_canonical_stable_and_tamper_evident() {
    let f = Fixture::new();
    let span = f.span(0, None);
    let a = span.signing_bytes().unwrap();
    let b = span.signing_bytes().unwrap();
    assert_eq!(a, b);
    let signed = SignedSpan::sign(span, &f.signer).unwrap();
    let mut tampered = signed.clone();
    tampered.span.name.push('!');
    assert_eq!(
        tampered.verify_digest().unwrap_err(),
        GateError::VerificationFailed
    );
    let _ = ReasonCode::DenyFailClosed;
    let _ = Decision::deny(ReasonCode::DenyFailClosed);
    let _ = Exporter::export(&gate_span::NullExporter, &signed);
}

// Persistence: restart resumes the sequence and the chain.
#[test]
fn segment_log_survives_restart() {
    let f = Fixture::new();
    let log = f.log();
    let chain = f.chain(3);
    for signed in &chain {
        log.append(signed).unwrap();
    }
    drop(log);
    let reopened = f.log();
    assert_eq!(reopened.next_seq(), 3);
    let stored = SegmentLog::read_all(reopened.path()).unwrap();
    assert_eq!(stored, chain);
    verify_chain(&stored, &f.signer.verifying_key()).unwrap();
}

// Group commit still returns durable receipts.
#[test]
fn group_commit_is_durable() {
    let f = Fixture::new();
    let log = f.log();
    let batch = f.chain(4);
    let receipts = log.append_batch(&batch).unwrap();
    assert_eq!(receipts.len(), 4);
    assert!(receipts.iter().all(|r| r.durable));
    let stored = SegmentLog::read_all(log.path()).unwrap();
    assert_eq!(stored, batch);
}

// A truncated record is reported, never silently ignored (fail closed).
#[test]
fn truncated_segment_fails_closed() {
    let f = Fixture::new();
    let log = f.log();
    log.append(&SignedSpan::sign(f.span(0, None), &f.signer).unwrap())
        .unwrap();
    let path = log.path().to_path_buf();
    drop(log);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 3);
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        SegmentLog::read_all(&path),
        Err(GateError::StoreUnavailable(_))
    ));
}
