//! T-DRF-001..014 — drift/regret metrics and dual-principal flow (M3-T06).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::PrincipalId;
use gate_ledger::drift::{
    combine, dual_finding, second_principal_brief, DecisionRecord, DriftMetrics, DualOutcome,
    DualPrincipalRequest, FirstPrincipalInput, REGRET_THRESHOLD, RUBBER_STAMP_MS, WINDOW,
};

fn p(name: &str) -> PrincipalId {
    PrincipalId::from(name)
}

fn fill(metrics: &mut DriftMetrics, who: &PrincipalId, latency: i64, regret: Option<u8>, n: usize) {
    for i in 0..n {
        let digest = format!("sha256:{who:?}{i:02}");
        metrics.record(who, DecisionRecord::new(digest.clone(), latency, true));
        if let Some(scale) = regret {
            assert!(metrics.attest(who, &digest, scale));
        }
    }
}

// T-DRF-001 — a sub-2 s decision raises POSSIBLE_RUBBER_STAMP.
#[test]
fn t_drf_001_rubber_stamp_flag() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    metrics.record(&alice, DecisionRecord::new("sha256:a", 1_999, true));
    assert_eq!(
        metrics.rubber_stamp_finding(&alice),
        Some("POSSIBLE_RUBBER_STAMP")
    );
    metrics.record(&alice, DecisionRecord::new("sha256:b", 2_000, true));
    assert_eq!(
        metrics.rubber_stamp_finding(&alice),
        None,
        "2 s is not a stamp"
    );
    assert!(DecisionRecord::new("d", RUBBER_STAMP_MS - 1, true).rubber_stamp());
}

// T-DRF-002 — regret > 15% over the trailing window tightens the cap and
// requires a second principal.
#[test]
fn t_drf_002_auto_tighten_on_regret() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    // 20 window samples, 4 regretted = 20% > 15%.
    fill(&mut metrics, &alice, 20_000, Some(3), 4);
    fill(&mut metrics, &alice, 20_000, Some(0), 16);
    let m = metrics.metrics(&alice);
    assert_eq!(m.samples, WINDOW);
    assert_eq!(m.attested, WINDOW);
    assert!((m.regret_rate - 0.20).abs() < 1e-9, "{}", m.regret_rate);
    assert!(m.regret_rate > REGRET_THRESHOLD);
    let tighten = metrics.auto_tighten(&alice, 5).unwrap();
    assert_eq!(tighten.cap, 4, "cap is lowered by one");
    assert!(tighten.require_dual_principal);
    assert!(tighten.reason.contains("regret"));
}

// T-DRF-003 — principal 2 never sees principal 1's decision.
#[test]
fn t_drf_003_dual_principal_hides_p1() {
    let counters = ["The same result can be reached with a narrower action.".to_string()];
    let request = DualPrincipalRequest {
        action: "The agent attempts to send an email.",
        resolved_effect: "412 records to partner@partner.example",
        counter_considerations: &counters,
        budget_line: "Request 1 of 5 — 4 remaining this episode.",
        first: FirstPrincipalInput {
            decision_text: Some("APPROVED by prn_alice"),
            note: Some("looks fine to me"),
        },
    };
    let p2 = second_principal_brief(&request);
    assert!(p2.contains("412 records"));
    assert!(p2.contains("Consideration:"));
    assert!(p2.contains("independent review required"));
    assert!(
        !p2.contains("APPROVED"),
        "P1's decision must be structurally absent"
    );
    assert!(!p2.contains("prn_alice"));
    assert!(!p2.contains("looks fine to me"));
}

// T-DRF-004 — the drift score is monotone in the rubber-stamp rate.
#[test]
fn t_drf_004_drift_monotone() {
    let alice = p("prn_alice");
    let mut low = DriftMetrics::new();
    fill(&mut low, &alice, 30_000, Some(0), 20);
    let mut high = DriftMetrics::new();
    for i in 0..20 {
        let latency = if i < 10 { 500 } else { 30_000 };
        high.record(
            &alice,
            DecisionRecord::new(format!("sha256:h{i}"), latency, true),
        );
        high.attest(&alice, &format!("sha256:h{i}"), 0);
    }
    let a = low.metrics(&alice);
    let b = high.metrics(&alice);
    assert!(a.rubber_stamp_rate < b.rubber_stamp_rate);
    assert!(
        a.sycophantic_drift < b.sycophantic_drift,
        "{} vs {}",
        a.sycophantic_drift,
        b.sycophantic_drift
    );
    assert!(b.sycophantic_drift <= 1.0 && a.sycophantic_drift >= 0.0);
}

// T-DRF-005 — metrics are reproducible on replay.
#[test]
fn t_drf_005_reproducible() {
    let alice = p("prn_alice");
    let build = || {
        let mut m = DriftMetrics::new();
        for i in 0..7 {
            let digest = format!("sha256:r{i}");
            m.record(
                &alice,
                DecisionRecord::new(digest.clone(), 1_000 + i as i64, true),
            );
            m.attest(&alice, &digest, (i % 4) as u8);
        }
        m.metrics(&alice)
    };
    assert_eq!(build(), build());
}

// T-DRF-006/010 — only the trailing window counts.
#[test]
fn t_drf_006_window_is_trailing() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    // 20 regretted decisions, then 20 clean ones: the old regrets fall out.
    fill(&mut metrics, &alice, 20_000, Some(3), 20);
    fill(&mut metrics, &alice, 20_000, Some(0), 20);
    let m = metrics.metrics(&alice);
    assert_eq!(m.samples, WINDOW);
    assert_eq!(m.regret_rate, 0.0);
    assert!(metrics.auto_tighten(&alice, 5).is_none());
}

// T-DRF-007 — un-attested decisions are not regret.
#[test]
fn t_drf_007_unattested_not_regret() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    for i in 0..WINDOW {
        metrics.record(
            &alice,
            DecisionRecord::new(format!("sha256:u{i}"), 30_000, true),
        );
    }
    let m = metrics.metrics(&alice);
    assert_eq!(m.attested, 0);
    assert_eq!(m.regret_rate, 0.0);
    assert!(metrics.auto_tighten(&alice, 5).is_none());
    assert!(!metrics.attest(&alice, "sha256:nope", 3));
}

// T-DRF-008 — auto-tightening never raises the cap and never goes below 1.
#[test]
fn t_drf_008_tighten_monotone() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    fill(&mut metrics, &alice, 20_000, Some(3), 20);
    let t5 = metrics.auto_tighten(&alice, 5).unwrap();
    let t1 = metrics.auto_tighten(&alice, 1).unwrap();
    assert_eq!(t5.cap, 4);
    assert_eq!(t1.cap, 1);
    assert!(t5.require_dual_principal);
}

// T-DRF-009 — a split dual-principal decision denies.
#[test]
fn t_drf_009_split_denies() {
    assert_eq!(combine(true, true), DualOutcome::Endorsed);
    assert_eq!(combine(false, false), DualOutcome::Denied);
    assert_eq!(combine(true, false), DualOutcome::Split);
    assert_eq!(combine(false, true), DualOutcome::Split);
    assert_eq!(
        dual_finding(DualOutcome::Split),
        Some("DUAL_PRINCIPAL_SPLIT")
    );
    assert_eq!(dual_finding(DualOutcome::Endorsed), None);
}

// T-DRF-011 — principals are isolated.
#[test]
fn t_drf_011_per_principal_isolation() {
    let alice = p("prn_alice");
    let bob = p("prn_bob");
    let mut metrics = DriftMetrics::new();
    fill(&mut metrics, &alice, 500, Some(3), 20);
    fill(&mut metrics, &bob, 30_000, Some(0), 20);
    let a = metrics.metrics(&alice);
    let b = metrics.metrics(&bob);
    assert!(a.rubber_stamp_rate > 0.99);
    assert_eq!(b.rubber_stamp_rate, 0.0);
    assert!(metrics.auto_tighten(&alice, 5).is_some());
    assert!(metrics.auto_tighten(&bob, 5).is_none());
    assert_eq!(metrics.principal_count(), 2);
}

// T-DRF-012 — the drift score is bounded.
#[test]
fn t_drf_012_drift_bounded() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    fill(&mut metrics, &alice, 0, Some(3), 20);
    let m = metrics.metrics(&alice);
    assert!(
        (0.0..=1.0).contains(&m.sycophantic_drift),
        "{}",
        m.sycophantic_drift
    );
    let empty = metrics.metrics(&p("prn_nobody"));
    assert_eq!(empty.samples, 0);
    assert_eq!(empty.sycophantic_drift, 0.0);
}

// T-DRF-013 — no tightening on a small sample, however bad.
#[test]
fn t_drf_013_no_tightening_without_full_window() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    fill(&mut metrics, &alice, 500, Some(3), WINDOW - 1);
    assert!(metrics.auto_tighten(&alice, 5).is_none());
    fill(&mut metrics, &alice, 500, Some(3), 1);
    assert!(metrics.auto_tighten(&alice, 5).is_some());
}

// T-DRF-014 — regret counts scales >= 2 only, and the brief is deterministic.
#[test]
fn t_drf_014_regret_cutoff_and_render_determinism() {
    let alice = p("prn_alice");
    let mut metrics = DriftMetrics::new();
    for i in 0..20 {
        let digest = format!("sha256:c{i}");
        let scale = if i < 3 { 1 } else { 2 };
        metrics.record(&alice, DecisionRecord::new(digest.clone(), 30_000, true));
        metrics.attest(&alice, &digest, scale);
    }
    // 17 of 20 >= 2 -> 85% regret; scale 1 is not regret.
    assert!((metrics.metrics(&alice).regret_rate - 0.85).abs() < 1e-9);

    let counters = ["A denial is always acceptable.".to_string()];
    let request = DualPrincipalRequest {
        action: "a",
        resolved_effect: "e",
        counter_considerations: &counters,
        budget_line: "b",
        first: FirstPrincipalInput {
            decision_text: None,
            note: None,
        },
    };
    assert_eq!(
        second_principal_brief(&request),
        second_principal_brief(&request)
    );
}
