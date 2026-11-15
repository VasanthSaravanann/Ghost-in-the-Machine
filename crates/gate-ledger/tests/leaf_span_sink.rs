//! T-LDG-016 (second implementation) — the ledger's leaves must flow through the
//! signed span chain in M3 and both sinks must agree on what was emitted.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use gate_core::{CallId, Class, EpisodeId, PrincipalId, VecSink};
use gate_crypto::{sha256_hex, Ed25519Signer, KeyId};
use gate_ledger::leaf::{EndorsementLedger, FramingSummary, LeafA};
use gate_span::{verify_chain, RealFsync, SegmentLog, SpanLeafSink};
use gate_testkit::FakeClock;
use tempfile::TempDir;

const NOW: i64 = 1_700_000_000_000;
const POLICY_HASH: &str = "sha256:9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c";

fn leaf(call_digest: &str) -> LeafA {
    LeafA {
        leaf_id: "leaf_a_span".into(),
        episode_id: EpisodeId::from("ep_span"),
        call_id: CallId::from("call_span"),
        tool: "mailer:send_email".into(),
        class: Class::ExternalEgress,
        call_digest: call_digest.to_owned(),
        brief_digest: sha256_hex(b"brief"),
        sup_share: 0.4,
        framing: FramingSummary {
            sup_share_tokens: 0.4,
            sup_share_pixels: 0.38,
            third_person: true,
            filters_passed: true,
        },
        taint_path_digest: sha256_hex(b"taint"),
        budget_used: 1,
        budget_cap: 5,
        latency_ms: 20_000,
        rubber_stamp_flag: false,
        resolved_effect_digest: sha256_hex(b"effect"),
        principal: PrincipalId::from("prn_alice"),
        prev: None,
        attestation_due_ms: NOW + 24 * 60 * 60 * 1_000,
        issued_ms: NOW,
    }
}

#[test]
fn t_ldg_016b_trail_through_signed_span_chain() {
    let dir = TempDir::new().unwrap();
    let concrete = Ed25519Signer::from_seed(KeyId::new("gate"), &[5u8; 32]);
    let signer: Arc<dyn gate_crypto::Signer> =
        Arc::new(Ed25519Signer::from_seed(KeyId::new("gate"), &[5u8; 32]));
    let log =
        Arc::new(SegmentLog::open(dir.path().join("leaves.seg"), Box::new(RealFsync)).unwrap());
    let clock: Arc<dyn gate_core::Clock> = Arc::new(FakeClock::new(NOW));
    let sink = SpanLeafSink::new(
        Arc::clone(&signer),
        Arc::clone(&log),
        clock,
        EpisodeId::from("ep_span"),
        POLICY_HASH,
    );

    let mut ledger = EndorsementLedger::new();
    let bytes = b"{\"jsonrpc\":\"2.0\",\"id\":\"c\",\"method\":\"tools/call\"}".to_vec();
    let digest = sha256_hex(&bytes);
    let key = ledger.endorse(leaf(&digest), signer.as_ref(), NOW).unwrap();
    let reference = ledger.last_leaf_digest().unwrap().to_owned();
    ledger
        .attest(&reference, "delivered", true, 0, "", NOW + 1_000)
        .unwrap();
    let _ = key;

    // Both sinks receive the same leaf set.
    let memory = VecSink::new();
    assert_eq!(ledger.trail(&memory).unwrap(), 2);
    assert_eq!(ledger.trail(&sink).unwrap(), 2);
    assert_eq!(memory.entries().len(), 2);

    // The span chain is signed, chained and durable.
    let spans = SegmentLog::read_all(log.path()).unwrap();
    assert_eq!(spans.len(), 2);
    verify_chain(&spans, &concrete.verifying_key()).unwrap();
    for span in &spans {
        assert_eq!(span.span.policy_hash, POLICY_HASH);
    }
}
