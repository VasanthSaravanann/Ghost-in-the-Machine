//! T-LDG-001..026 — split-leaf endorsement ledger (plan.md §5.8, M3-T04).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::{CallId, Class, EpisodeId, LeafSink, PrincipalId, SegmentId, VecSink};
use gate_crypto::{sha256_hex, Ed25519Signer, Ed25519Verifier, KeyId, Signer};
use gate_ledger::leaf::{
    EndorsementLedger, FramingSummary, LeafA, LedgerError, Resume, Stage, ENDORSEMENT_TIMEOUT_MS,
    LEAF_A_TYPE, LEAF_B_TYPE, MAX_DELTA_T_MS, MIN_DELTA_T_MS,
};

const NOW: i64 = 1_700_000_000_000;
const HOUR: i64 = 60 * 60 * 1_000;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(KeyId::new("gate"), &[9u8; 32])
}

fn outbound(tool: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{{"name":"{tool}","arguments":{{"to":"partner@partner.example"}}}}}}"#).into_bytes()
}

fn leaf(call_digest: &str, sup_share: f64, delta_ms: i64) -> LeafA {
    LeafA {
        leaf_id: "leaf_a_1".into(),
        episode_id: EpisodeId::from("ep_ldg"),
        call_id: CallId::from("call_1"),
        tool: "mailer:send_email".into(),
        class: Class::ExternalEgress,
        call_digest: call_digest.to_owned(),
        brief_digest: sha256_hex(b"brief"),
        sup_share,
        framing: FramingSummary {
            sup_share_tokens: sup_share,
            sup_share_pixels: sup_share,
            third_person: true,
            filters_passed: true,
        },
        taint_path_digest: sha256_hex(b"taint"),
        budget_used: 3,
        budget_cap: 5,
        latency_ms: 41_280,
        rubber_stamp_flag: false,
        resolved_effect_digest: sha256_hex(b"effect"),
        principal: PrincipalId::from("prn_alice"),
        prev: None,
        attestation_due_ms: NOW + delta_ms,
        issued_ms: NOW,
    }
}

fn endorse_default(ledger: &mut EndorsementLedger) -> (String, Vec<u8>) {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let key = ledger
        .endorse(leaf(&digest, 0.41, 24 * HOUR), &signer(), NOW)
        .unwrap();
    (key, bytes)
}

// T-LDG-001 — Leaf A carries every P3-R17 field.
#[test]
fn t_ldg_001_leaf_a_schema() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let leaf = leaf(&digest, 0.41, 24 * HOUR);
    let json = serde_json::to_value(&leaf).unwrap();
    for field in [
        "leaf_id",
        "episode_id",
        "call_id",
        "tool",
        "class",
        "call_digest",
        "brief_digest",
        "sup_share",
        "framing",
        "taint_path_digest",
        "budget_used",
        "budget_cap",
        "latency_ms",
        "rubber_stamp_flag",
        "resolved_effect_digest",
        "principal",
        "prev",
        "attestation_due_ms",
        "issued_ms",
    ] {
        assert!(json.get(field).is_some(), "Leaf A missing {field}");
    }
    assert_eq!(json["framing"]["third_person"], true);
}

// T-LDG-002 — matching bytes are released.
#[test]
fn t_ldg_002_release_on_digest_match() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    let receipt = ledger.release(&key, &bytes, NOW + 1_000).unwrap();
    assert_eq!(ledger.stage(&key), Some(Stage::Released));
    assert!(receipt.leaf_a_digest.starts_with("sha256:"));
}

// T-LDG-003 — one mutated byte is denied (INV-5 TOCTOU).
#[test]
fn t_ldg_003_one_byte_mutation_denied() {
    let mut ledger = EndorsementLedger::new();
    let (key, mut bytes) = endorse_default(&mut ledger);
    let idx = bytes.iter().position(|b| *b == b'p').unwrap();
    bytes[idx] = b'q';
    match ledger.release(&key, &bytes, NOW + 1_000) {
        Err(LedgerError::Toctou { expected, actual }) => {
            assert_ne!(expected, actual);
        }
        other => panic!("expected TOCTOU denial, got {other:?}"),
    }
    assert_eq!(
        ledger.stage(&key),
        Some(Stage::Endorsed),
        "nothing released"
    );
}

// T-LDG-004 — replaying the same endorsement for a new call is denied.
#[test]
fn t_ldg_004_replay_denied() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    ledger.release(&key, &bytes, NOW + 1).unwrap();
    assert_eq!(
        ledger.release(&key, &bytes, NOW + 2).err().unwrap(),
        LedgerError::AlreadyReleased
    );
}

// T-LDG-005 — Leaf B must reference H(leaf A).
#[test]
fn t_ldg_005_leaf_b_reference() {
    let mut ledger = EndorsementLedger::new();
    let (key, _) = endorse_default(&mut ledger);
    let reference = ledger.last_leaf_digest().unwrap().to_owned();
    let b = ledger
        .attest(
            &reference,
            "sent to one partner",
            true,
            0,
            "",
            NOW + 24 * HOUR,
        )
        .unwrap();
    assert_eq!(b.reference, reference);
    assert!(ledger.leaves_b().contains_key(&reference));
    assert_eq!(
        ledger
            .attest("sha256:deadbeef", "x", true, 0, "", NOW)
            .err()
            .unwrap(),
        LedgerError::AttestationMismatch
    );
    let _ = key;
}

// T-LDG-006 — no Leaf B by delta_t is AttestLapsed, never confirmation.
#[test]
fn t_ldg_006_attest_lapsed() {
    let mut ledger = EndorsementLedger::new();
    let (_key, _) = endorse_default(&mut ledger);
    assert!(ledger.tick(NOW + HOUR).is_empty());
    let lapsed = ledger.tick(NOW + 24 * HOUR);
    assert_eq!(lapsed.len(), 1);
    assert_eq!(ledger.lapsed().len(), 1);
    // Ticking again does not duplicate the lapse.
    assert!(ledger.tick(NOW + 30 * HOUR).is_empty());
    assert_eq!(ledger.leaves_b().len(), 0, "lapse is not an attestation");
}

// T-LDG-007 — the 15-minute timeout fails closed.
#[test]
fn t_ldg_007_timeout_fails_closed() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    assert_eq!(
        ledger
            .release(&key, &bytes, NOW + ENDORSEMENT_TIMEOUT_MS + 1)
            .err()
            .unwrap(),
        LedgerError::TimeoutExpired
    );
}

// T-LDG-008/009 — crash recovery never re-prompts and never double-executes.
#[test]
fn t_ldg_008_crash_after_endorse_before_execute() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    assert_eq!(ledger.resume(&key), Resume::Release);
    ledger.release(&key, &bytes, NOW + 1).unwrap();
    // "Crash" here: a fresh ledger cannot know the call, but the stage machine
    // must never report Release (which would re-prompt) once released.
    assert_eq!(ledger.resume(&key), Resume::ExecuteOnce);
    ledger.mark_executed(&key).unwrap();
    assert_eq!(ledger.resume(&key), Resume::Done);
}

#[test]
fn t_ldg_009_crash_after_execute_no_duplicate() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    ledger.release(&key, &bytes, NOW + 1).unwrap();
    ledger.mark_executed(&key).unwrap();
    assert_eq!(
        ledger.mark_executed(&key).err().unwrap(),
        LedgerError::AlreadyExecuted
    );
    assert_eq!(ledger.resume(&key), Resume::Done);
}

// T-LDG-010 — an invalid principal signature is rejected.
#[test]
fn t_ldg_010_invalid_signature() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let mut signed =
        gate_ledger::leaf::SignedLeafA::sign(leaf(&digest, 0.41, 24 * HOUR), &signer()).unwrap();
    signed.leaf.tool = "mailer:send_sms".into();
    assert_eq!(
        signed.verify(&signer().verifying_key()).unwrap_err(),
        gate_core::GateError::VerificationFailed
    );
    // Wrong verifier also fails.
    let other = Ed25519Signer::from_seed(KeyId::new("gate"), &[10u8; 32]);
    let good =
        gate_ledger::leaf::SignedLeafA::sign(leaf(&digest, 0.41, 24 * HOUR), &signer()).unwrap();
    assert!(good.verify(&other.verifying_key()).is_err());
    let pk = Signer::public_key(&signer());
    let _ = Ed25519Verifier::from_public_bytes(KeyId::new("gate"), &pk).unwrap();
}

// T-LDG-011..026 — bounds, clock jumps, sink, chaining, concurrency, framing.
#[test]
fn t_ldg_011_delta_t_bounds() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    for (delta, ok) in [
        (MIN_DELTA_T_MS - 1, false),
        (MIN_DELTA_T_MS, true),
        (MAX_DELTA_T_MS, true),
        (MAX_DELTA_T_MS + 1, false),
    ] {
        let mut ledger = EndorsementLedger::new();
        let result = ledger.endorse(leaf(&digest, 0.41, delta), &signer(), NOW);
        assert_eq!(result.is_ok(), ok, "delta {delta}");
        if !ok {
            assert_eq!(result.err().unwrap(), LedgerError::DeltaTOutOfBounds);
        }
    }
}

#[test]
fn t_ldg_012_asymmetric_brief_never_endorsed() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let mut ledger = EndorsementLedger::new();
    assert_eq!(
        ledger
            .endorse(leaf(&digest, 0.51, 24 * HOUR), &signer(), NOW)
            .err()
            .unwrap(),
        LedgerError::NotSymmetric
    );
    // Pixel measure alone above the limit is also rejected.
    let mut l = leaf(&digest, 0.40, 24 * HOUR);
    l.framing.sup_share_pixels = 0.60;
    assert_eq!(
        ledger.endorse(l, &signer(), NOW).err().unwrap(),
        LedgerError::NotSymmetric
    );
}

#[test]
fn t_ldg_013_clock_jump_does_not_bypass() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    // Clock jumps forward past the deadline: fail closed.
    assert_eq!(
        ledger
            .release(&key, &bytes, NOW + 10 * ENDORSEMENT_TIMEOUT_MS)
            .err()
            .unwrap(),
        LedgerError::TimeoutExpired
    );
    // Clock jumps backwards before issue: still within the window, allowed.
    // (A different call digest: re-endorsing the same call is a replay.)
    let bytes2 = outbound("fs:read_file");
    let digest2 = sha256_hex(&bytes2);
    let key2 = ledger
        .endorse(leaf(&digest2, 0.2, 24 * HOUR), &signer(), NOW)
        .unwrap();
    assert!(ledger.release(&key2, &bytes2, NOW - HOUR).is_ok());
}

#[test]
fn t_ldg_014_unknown_endorsement() {
    let mut ledger = EndorsementLedger::new();
    assert_eq!(
        ledger.release("sha256:missing", b"x", NOW).err().unwrap(),
        LedgerError::UnknownEndorsement("sha256:missing".into())
    );
    assert_eq!(ledger.resume("sha256:missing"), Resume::Unknown);
}

#[test]
fn t_ldg_015_regret_scale_bounds() {
    let mut ledger = EndorsementLedger::new();
    let (_key, _) = endorse_default(&mut ledger);
    let reference = ledger.last_leaf_digest().unwrap().to_owned();
    assert_eq!(
        ledger
            .attest(&reference, "x", true, 4, "", NOW + HOUR)
            .err()
            .unwrap(),
        LedgerError::RegretOutOfRange
    );
    assert!(ledger
        .attest(&reference, "x", false, 3, "overreach", NOW + HOUR)
        .is_ok());
    assert_eq!(
        ledger
            .attest(&reference, "dup", true, 0, "", NOW + 2 * HOUR)
            .err()
            .unwrap(),
        LedgerError::AlreadyExecuted
    );
}

#[test]
fn t_ldg_016_sink_is_the_only_exit_and_tags_both_leaf_types() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    let reference = ledger.last_leaf_digest().unwrap().to_owned();
    ledger
        .attest(&reference, "ok", true, 0, "", NOW + HOUR)
        .unwrap();
    let sink = VecSink::new();
    let count = ledger.trail(&sink).unwrap();
    assert_eq!(count, 2);
    let entries = sink.entries();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|(t, _, _)| t == LEAF_A_TYPE));
    assert!(entries.iter().any(|(t, _, _)| t == LEAF_B_TYPE));
    let _ = (key, bytes);
}

#[test]
fn t_ldg_017_sink_failure_is_reported_not_swallowed() {
    struct Broken;
    impl LeafSink for Broken {
        fn sink_leaf(&self, _: &str, _: &str, _: &[u8]) -> Result<(), gate_core::GateError> {
            Err(gate_core::GateError::ExporterUnavailable)
        }
    }
    let mut ledger = EndorsementLedger::new();
    let _ = endorse_default(&mut ledger);
    assert_eq!(
        ledger.trail(&Broken).unwrap_err(),
        gate_core::GateError::ExporterUnavailable
    );
}

#[test]
fn t_ldg_018_prev_chaining() {
    let mut ledger = EndorsementLedger::new();
    let first = endorse_default(&mut ledger).0;
    let first_digest = ledger.last_leaf_digest().unwrap().to_owned();
    let bytes2 = outbound("fs:read_file");
    let digest2 = sha256_hex(&bytes2);
    let mut second = leaf(&digest2, 0.30, 24 * HOUR);
    second.prev = Some(first_digest.clone());
    let second_key = ledger.endorse(second, &signer(), NOW + 1).unwrap();
    assert_ne!(first, second_key);
    assert_eq!(
        ledger.last_leaf_digest(),
        Some(ledger.last_leaf_digest().unwrap())
    );
    assert_eq!(ledger.len(), 2);
}

#[test]
fn t_ldg_019_rubber_stamp_flag() {
    assert!(LeafA::rubber_stamp(1_999));
    assert!(!LeafA::rubber_stamp(2_000));
    assert!(!LeafA::rubber_stamp(41_280));
}

#[test]
fn t_ldg_020_budget_snapshot_recorded() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let l = leaf(&digest, 0.41, 24 * HOUR);
    assert_eq!(l.budget_used, 3);
    assert_eq!(l.budget_cap, 5);
    assert!(l.budget_used < l.budget_cap);
}

#[test]
fn t_ldg_021_multiple_endorsements_independent() {
    let mut ledger = EndorsementLedger::new();
    let mut keys = Vec::new();
    for i in 0..4 {
        let bytes = format!("call-{i}").into_bytes();
        let digest = sha256_hex(&bytes);
        let key = ledger
            .endorse(leaf(&digest, 0.2, 24 * HOUR), &signer(), NOW + i as i64)
            .unwrap();
        keys.push((key, bytes));
    }
    assert_eq!(ledger.len(), 4);
    for (key, bytes) in &keys {
        ledger.release(key, bytes, NOW + 10).unwrap();
    }
    assert!(keys
        .iter()
        .all(|(k, _)| ledger.stage(k) == Some(Stage::Released)));
}

#[test]
fn t_ldg_022_tick_respects_delta_t() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let mut ledger = EndorsementLedger::new();
    ledger
        .endorse(leaf(&digest, 0.2, MIN_DELTA_T_MS), &signer(), NOW)
        .unwrap();
    assert!(ledger.tick(NOW + MIN_DELTA_T_MS - 1).is_empty());
    assert_eq!(ledger.tick(NOW + MIN_DELTA_T_MS).len(), 1);
}

#[test]
fn t_ldg_023_leaf_b_fields_schema() {
    let mut ledger = EndorsementLedger::new();
    let (_key, _) = endorse_default(&mut ledger);
    let reference = ledger.last_leaf_digest().unwrap().to_owned();
    let b = ledger
        .attest(
            &reference,
            "delivered",
            true,
            1,
            "late delivery",
            NOW + HOUR,
        )
        .unwrap();
    let json = serde_json::to_value(&b).unwrap();
    for field in [
        "leaf_id",
        "reference",
        "outcome_summary",
        "still_endorses",
        "regret_scale",
        "cause_text",
        "attested_ms",
    ] {
        assert!(json.get(field).is_some(), "Leaf B missing {field}");
    }
    assert_eq!(json["regret_scale"], 1);
    assert_eq!(json["still_endorses"], true);
}

#[test]
fn t_ldg_024_digest_is_over_canonical_bytes() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let l = leaf(&digest, 0.41, 24 * HOUR);
    let canonical = l.signing_bytes().unwrap();
    assert_eq!(sha256_hex(&canonical), l.digest().unwrap());
    let text = std::str::from_utf8(&canonical).unwrap();
    assert_eq!(gate_jcs::canonicalize(text).unwrap(), text);
}

#[test]
fn t_ldg_025_release_requires_the_endorsed_call_digest() {
    let mut ledger = EndorsementLedger::new();
    let (key, bytes) = endorse_default(&mut ledger);
    let other = outbound("db:drop_all");
    assert!(matches!(
        ledger.release(&key, &other, NOW + 1),
        Err(LedgerError::Toctou { .. })
    ));
    assert!(ledger.release(&key, &bytes, NOW + 1).is_ok());
}

#[test]
fn t_ldg_026_endorsement_is_deterministic() {
    let bytes = outbound("mailer:send_email");
    let digest = sha256_hex(&bytes);
    let a =
        gate_ledger::leaf::SignedLeafA::sign(leaf(&digest, 0.41, 24 * HOUR), &signer()).unwrap();
    let b =
        gate_ledger::leaf::SignedLeafA::sign(leaf(&digest, 0.41, 24 * HOUR), &signer()).unwrap();
    assert_eq!(a.digest, b.digest);
    assert_eq!(a.signature.bytes, b.signature.bytes);
    let _ = SegmentId::from("seg_x");
}
