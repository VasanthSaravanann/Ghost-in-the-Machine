//! T-BUD-001..020 (plan.md §5.8, M3-T01).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use gate_core::{Class, PrincipalId, ReasonCode};
use gate_ledger::budget::in_cap;
use gate_ledger::{BudgetError, BudgetTracker, CapAction, PrincipalGate};

#[derive(Clone)]
struct Gate(&'static str);
impl PrincipalGate for Gate {
    fn approve_cap_action(&self) -> Option<PrincipalId> {
        Some(PrincipalId::from(self.0))
    }
}

fn principal_gate(id: &'static str) -> Gate {
    Gate(id)
}

#[derive(Clone)]
struct Deny;
impl PrincipalGate for Deny {
    fn approve_cap_action(&self) -> Option<PrincipalId> {
        None
    }
}

#[test]
fn t_bud_001_cap_then_deny() {
    let mut tracker = BudgetTracker::new("ep_1", 16, 0);
    for i in 0..5 {
        tracker
            .request_prompt(Class::ExternalEgress, i * 25_000, i as u64)
            .unwrap();
        tracker.render_due(i * 25_000);
    }
    assert_eq!(tracker.remaining(Class::ExternalEgress), 0);
    assert_eq!(
        tracker
            .request_prompt(Class::ExternalEgress, 30_000, 2)
            .err()
            .unwrap(),
        BudgetError::CapExhausted
    );
    assert_eq!(
        in_cap(
            tracker.used(Class::ExternalEgress),
            tracker.cap(Class::ExternalEgress)
        ),
        Some(ReasonCode::DenyBudget)
    );
}

#[test]
fn t_bud_002_in_band_raise_ignored() {
    let mut tracker = BudgetTracker::new("ep_2", 16, 0);
    let before = tracker.cap(Class::ExternalEgress);
    tracker.request_in_band_raise(Class::ExternalEgress, 1_000_000, 0);
    assert_eq!(
        tracker.cap(Class::ExternalEgress),
        before,
        "cap must not move"
    );
    assert!(matches!(
        tracker.events().last().unwrap().kind,
        gate_ledger::BudgetEventKind::InBandRaiseIgnored {
            requested: 1_000_000
        }
    ));
}

#[test]
fn t_bud_003_out_of_band_raise() {
    let mut tracker = BudgetTracker::new("ep_3", 16, 0);
    let principal = principal_gate("prn_alice");
    tracker
        .approve_cap_change(
            &principal,
            Class::ExternalEgress,
            CapAction::Raise { to: 7 },
            0,
        )
        .unwrap();
    assert_eq!(tracker.cap(Class::ExternalEgress), 7);
    assert!(matches!(
        tracker.events().last().unwrap().kind,
        gate_ledger::BudgetEventKind::CapChanged { .. }
    ));
    let result = tracker.approve_cap_change(
        &Deny,
        Class::ExternalEgress,
        CapAction::Raise { to: 100 },
        0,
    );
    assert!(result.is_err());
}

#[test]
fn t_bud_004_budget_shown_in_prompt() {
    let mut tracker = BudgetTracker::new("ep_4", 16, 0);
    tracker.request_prompt(Class::ExternalEgress, 0, 1).unwrap();
    tracker.render_due(0);
    let view = tracker.view(Class::ExternalEgress);
    assert_eq!(view.used, 1);
    assert_eq!(view.cap, 5);
    assert_eq!(view.remaining, 4);
    assert!(tracker.invariant_holds());
}

#[test]
fn t_bud_005_rate_limit_queues() {
    let mut tracker = BudgetTracker::new("ep_5", 2, 0);
    tracker.request_prompt(Class::ExternalEgress, 0, 1).unwrap();
    let queued = tracker
        .request_prompt(Class::ExternalEgress, 5_000, 2)
        .unwrap();
    assert_eq!(queued, 1);
    assert_eq!(
        tracker.used(Class::ExternalEgress),
        1,
        "queued prompt must not consume budget yet"
    );
    assert!(tracker.render_due(10_000).is_empty());
    let due = tracker.render_due(20_000);
    assert_eq!(due.len(), 1);
    assert_eq!(
        tracker.used(Class::ExternalEgress),
        2,
        "budget consumed only when rendered"
    );
    let mut full = BudgetTracker::new("ep_5b", 1, 0);
    full.request_prompt(Class::ExternalEgress, 0, 1).unwrap(); // renders immediately
    full.request_prompt(Class::ExternalEgress, 1_000, 2)
        .unwrap(); // now queued
    assert_eq!(
        full.request_prompt(Class::ExternalEgress, 2_000, 3)
            .err()
            .unwrap(),
        BudgetError::QueueFull
    );
}

#[test]
fn t_bud_006_similar_requests_suppressed() {
    let mut tracker = BudgetTracker::new("ep_6", 16, 0);
    tracker
        .request_prompt(Class::ExternalEgress, 0, 42)
        .unwrap();
    tracker.render_due(0);
    let before = tracker.used(Class::ExternalEgress);
    let result = tracker
        .request_prompt(Class::ExternalEgress, 0, 42)
        .err()
        .unwrap();
    assert_eq!(result, BudgetError::TooSoon { wait_ms: 0 });
    assert_eq!(
        tracker.used(Class::ExternalEgress),
        before + 1,
        "budget consumed via cooldown"
    );
    assert!(matches!(
        tracker.events().last().unwrap().kind,
        gate_ledger::BudgetEventKind::CooldownSuppressed { .. }
    ));
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 1000, failure_persistence: None, ..proptest::test_runner::Config::default() })]
    #[test]
    fn t_bud_007_used_never_exceeds_cap(seed in 0u64..1_000_000u64) {
        let mut tracker = BudgetTracker::new("ep_7", 8, 0);
        let mut now = 0i64;
        let mut state = seed;
        for _ in 0..200 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let class = Class::ExternalEgress;
            now += (state % 5_000) as i64;
            let hash = (state >> 16) % 4;
            if tracker.request_prompt(class, now, hash).is_ok() {
                // no-op: the Ok case either rendered or queued
            }
            tracker.render_due(now);
            assert!(tracker.used(class) <= tracker.cap(class), "used {} > cap {}", tracker.used(class), tracker.cap(class));
            assert!(tracker.invariant_holds(), "invariant broken at now={now}");
        }
    }
}

#[test]
fn t_bud_008_per_class_budgets_independent() {
    let mut tracker = BudgetTracker::new("ep_8", 16, 0);
    for i in 0..5 {
        tracker
            .request_prompt(Class::ReadOnly, i * 25_000, i as u64)
            .unwrap();
        tracker.render_due(i * 25_000);
    }
    assert_eq!(tracker.remaining(Class::ReadOnly), 0);
    assert_eq!(tracker.remaining(Class::IdempotentWrite), 5);
    assert_eq!(tracker.remaining(Class::ExternalEgress), 5);
}

#[test]
fn t_bud_009_reset_is_principal_only() {
    let mut tracker = BudgetTracker::new("ep_9", 16, 0);
    for i in 0..5 {
        tracker
            .request_prompt(Class::ExternalEgress, i * 25_000, i as u64)
            .unwrap();
        tracker.render_due(i * 25_000);
    }
    assert!(tracker
        .approve_cap_change(&Deny, Class::ExternalEgress, CapAction::Reset { to: 0 }, 0)
        .is_err());
    let principal = principal_gate("prn_bob");
    tracker
        .approve_cap_change(
            &principal,
            Class::ExternalEgress,
            CapAction::Reset { to: 3 },
            0,
        )
        .unwrap();
    assert_eq!(tracker.cap(Class::ExternalEgress), 3);
    assert_eq!(
        tracker.used(Class::ExternalEgress),
        3,
        "reset bounds used by the new cap"
    );
    assert!(tracker.invariant_holds());
}

#[test]
fn t_bud_010_invariant_across_raises() {
    let mut tracker = BudgetTracker::new("ep_10", 16, 0);
    assert!(tracker.invariant_holds());
    let principal = principal_gate("prn_carol");
    for i in 0..5 {
        tracker
            .request_prompt(Class::PrivilegeGranting, i * 25_000, i as u64)
            .unwrap();
        tracker.render_due(i * 25_000);
    }
    assert_eq!(
        tracker
            .request_prompt(Class::PrivilegeGranting, 25_000 * 6, 99)
            .err()
            .unwrap(),
        BudgetError::CapExhausted
    );
    for i in 6i64..12 {
        tracker
            .approve_cap_change(
                &principal,
                Class::PrivilegeGranting,
                CapAction::Raise { to: i as u64 },
                0,
            )
            .unwrap();
        assert!(tracker.invariant_holds());
        tracker
            .request_prompt(Class::PrivilegeGranting, i * 25_000, i as u64)
            .unwrap();
        tracker.render_due(i * 25_000);
        assert!(tracker.invariant_holds());
    }
}

#[test]
fn t_bud_011_events_are_deterministic() {
    let mut a = BudgetTracker::new("ep_11", 16, 0);
    let mut b = BudgetTracker::new("ep_11", 16, 0);
    let _principal = principal_gate("prn_dave");
    for i in 0..3u64 {
        a.request_prompt(Class::ExternalEgress, 25_000 * i as i64, i)
            .unwrap();
        b.request_prompt(Class::ExternalEgress, 25_000 * i as i64, i)
            .unwrap();
    }
    a.render_due(30_000);
    b.render_due(30_000);
    assert_eq!(a.events(), b.events());
}
