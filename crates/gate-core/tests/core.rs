//! T-CORE-001..012 (plan.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use gate_core::{
    failclosed, AuthClosure, CallId, Class, Clock, Decision, EpisodeId, GateError, Label,
    ReasonCode, SegmentId, Verdict,
};
use gate_testkit::{FakeClock, SeededRng};
use proptest::prelude::*;

fn label_strategy() -> impl Strategy<Value = Label> {
    prop_oneof![
        Just(Label::ExternalUntrustedData),
        Just(Label::EndorsedCorpus),
        Just(Label::PrincipalDirect),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    // T-CORE-001..003
    #[test]
    fn t_core_001_meet_commutative(a in label_strategy(), b in label_strategy()) {
        prop_assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn t_core_002_meet_associative(a in label_strategy(), b in label_strategy(), c in label_strategy()) {
        prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
    }

    #[test]
    fn t_core_003_meet_idempotent(a in label_strategy()) {
        prop_assert_eq!(a.meet(a), a);
    }

    // T-CORE-004: meet is the greatest lower bound.
    #[test]
    fn t_core_004_meet_is_lower_bound(a in label_strategy(), b in label_strategy()) {
        let m = a.meet(b);
        prop_assert!(m <= a);
        prop_assert!(m <= b);
    }
}

#[test]
fn t_core_005_label_order() {
    assert!(Label::ExternalUntrustedData < Label::EndorsedCorpus);
    assert!(Label::EndorsedCorpus < Label::PrincipalDirect);
    // Total order over the three variants.
    let mut all = vec![
        Label::PrincipalDirect,
        Label::ExternalUntrustedData,
        Label::EndorsedCorpus,
    ];
    all.sort();
    assert_eq!(
        all,
        vec![
            Label::ExternalUntrustedData,
            Label::EndorsedCorpus,
            Label::PrincipalDirect
        ]
    );
}

/// Exhaustive match: adding a variant without deciding its fail-closed mapping
/// is a compile error.
fn expected_reason(e: &GateError) -> ReasonCode {
    use GateError as E;
    match e {
        E::Jcs(_) => ReasonCode::DenyFailClosed,
        E::SignerUnavailable => ReasonCode::DenySignerUnavailable,
        E::VerificationFailed => ReasonCode::DenyFailClosed,
        E::ExporterUnavailable => ReasonCode::DenyFailClosed,
        E::StoreUnavailable(_) => ReasonCode::DenyFailClosed,
        E::PolicyMissing => ReasonCode::DenyUnpinned,
        E::Timeout => ReasonCode::DenyEndorsementTimeout,
        E::InvalidInput(_) => ReasonCode::DenyFailClosed,
        E::Unsupported(_) => ReasonCode::DenyFailClosed,
        E::Internal(_) => ReasonCode::DenyFailClosed,
    }
}

fn all_errors() -> Vec<GateError> {
    use GateError as E;
    vec![
        E::Jcs("x".into()),
        E::SignerUnavailable,
        E::VerificationFailed,
        E::ExporterUnavailable,
        E::StoreUnavailable("x".into()),
        E::PolicyMissing,
        E::Timeout,
        E::InvalidInput("x".into()),
        E::Unsupported("x".into()),
        E::Internal("x".into()),
    ]
}

#[test]
fn t_core_006_every_gate_error_denies() {
    for class in [
        Class::ReadOnly,
        Class::IdempotentWrite,
        Class::ExternalEgress,
        Class::Irreversible,
        Class::PrivilegeGranting,
    ] {
        for err in all_errors() {
            let d = failclosed::map_error(&err, class, failclosed::ExporterLossPolicy::Deny);
            assert_eq!(d.verdict(), Verdict::Deny, "{class:?} + {err:?} must deny");
            assert_eq!(d.reasons(), &[expected_reason(&err)]);
            assert_eq!(d.closure().len(), 0);
        }
    }
}

#[test]
fn t_core_007_read_only_degrades_only_when_policy_allows() {
    let err = GateError::SignerUnavailable;
    let allow = failclosed::map_error(&err, Class::ReadOnly, failclosed::ExporterLossPolicy::Allow);
    assert_eq!(allow.verdict(), Verdict::Allow);

    // Every other class denies, even with the degrade flag set.
    for class in [
        Class::IdempotentWrite,
        Class::ExternalEgress,
        Class::Irreversible,
        Class::PrivilegeGranting,
    ] {
        let d = failclosed::map_error(&err, class, failclosed::ExporterLossPolicy::Allow);
        assert_eq!(d.verdict(), Verdict::Deny, "{class:?} must deny");
    }

    // READ_ONLY without the policy exception fails closed too.
    let d = failclosed::map_error(&err, Class::ReadOnly, failclosed::ExporterLossPolicy::Deny);
    assert_eq!(d.verdict(), Verdict::Deny);
}

#[test]
fn t_core_008_reason_codes_are_stable() {
    let expected = [
        "DENY_UNPINNED",
        "DENY_DRIFT",
        "DENY_PARAM_NOT_ALLOWED",
        "DENY_PARAM_INVALID",
        "DENY_TAINT_PIVOT",
        "DENY_BUDGET",
        "DENY_RATE",
        "DENY_SYMMETRY",
        "DENY_FRAMING",
        "DENY_TOCTOU",
        "DENY_ENDORSEMENT_TIMEOUT",
        "DENY_TRANSPARENCY_DEGRADED",
        "DENY_SIGNER_UNAVAILABLE",
        "DENY_FAIL_CLOSED",
        "ESCALATE_ENDORSEMENT_REQUIRED",
        "ALLOW_POLICY",
        "METADATA_POISONING_SUSPECTED",
        "APPROVAL_SPAM_SUSPECTED",
        "POSSIBLE_RUBBER_STAMP",
        "TRANSPARENCY_DEGRADED",
    ];
    assert_eq!(ReasonCode::ALL.len(), expected.len());
    for (reason, want) in ReasonCode::ALL.iter().zip(expected) {
        assert_eq!(reason.code(), want);
        assert_eq!(
            serde_json::to_value(reason).unwrap(),
            serde_json::json!(want)
        );
    }
}

#[test]
fn t_core_009_same_seed_same_ids() {
    let a = gate_core::IdFactory::new(Arc::new(SeededRng::new(42)));
    let b = gate_core::IdFactory::new(Arc::new(SeededRng::new(42)));
    let eps = ["ep_1", "ep_2"];
    for ep in eps {
        assert_eq!(a.call_id(ep), b.call_id(ep));
        assert_eq!(a.episode_id(), b.episode_id());
        assert_eq!(a.segment_id(), b.segment_id());
    }
}

#[test]
fn t_core_010_different_seed_different_ids() {
    let a = gate_core::IdFactory::new(Arc::new(SeededRng::new(42)));
    let b = gate_core::IdFactory::new(Arc::new(SeededRng::new(43)));
    assert_ne!(a.call_id("ep_1"), b.call_id("ep_1"));
}

#[test]
fn t_core_011_clock_is_injected() {
    let clock = FakeClock::new(1_700_000_000_000);
    let core_clock: Arc<dyn Clock> = Arc::new(clock.clone());
    assert_eq!(core_clock.now_ms(), 1_700_000_000_000);
    clock.advance(250);
    assert_eq!(core_clock.now_ms(), 1_700_000_000_250);
}

#[test]
fn t_core_012_ids_are_prefixed_and_well_formed() {
    let f = gate_core::IdFactory::new(Arc::new(SeededRng::new(1)));
    let cid: CallId = f.call_id("ep_abc");
    let eid: EpisodeId = f.episode_id();
    let sid: SegmentId = f.segment_id();
    assert!(cid.as_str().starts_with("call_"));
    assert!(eid.as_str().starts_with("ep_"));
    assert!(sid.as_str().starts_with("seg_"));
    for id in [cid.as_str(), eid.as_str(), sid.as_str()] {
        assert!(id.len() > 5 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }
}

#[test]
fn decision_constructors_carry_reasons_and_closure() {
    let mut closure = AuthClosure::new();
    closure.insert(SegmentId::from("seg_a"), Label::PrincipalDirect);
    let d = Decision::allow(vec![ReasonCode::AllowPolicy], closure.clone());
    assert_eq!(d.verdict(), Verdict::Allow);
    assert_eq!(d.closure(), &closure);
    let d = Decision::deny(ReasonCode::DenyUnpinned);
    assert_eq!(d.verdict(), Verdict::Deny);
    assert_eq!(d.reasons(), &[ReasonCode::DenyUnpinned]);
    let d = Decision::escalate(ReasonCode::EscalateEndorsementRequired);
    assert_eq!(d.verdict(), Verdict::Escalate);
}
