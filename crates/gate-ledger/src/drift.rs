//! Drift and regret metrics + dual-principal flow (plan.md M3-T06, P3-R20..R23).
//!
//! Metrics are per principal and computed over a **trailing window** so a past
//! lapse cannot haunt a principal forever, and so auto-tightening reacts to the
//! recent pattern only. Everything here is pure and deterministic: same inputs,
//! same numbers, on replay (T-DRF-005).

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

use gate_core::PrincipalId;

/// Plan default: react to the trailing 20 endorsements.
pub const WINDOW: usize = 20;
/// A decision faster than this is flagged (`POSSIBLE_RUBBER_STAMP`).
pub const RUBBER_STAMP_MS: i64 = 2_000;
/// Regret above this fraction over the window triggers auto-tightening.
pub const REGRET_THRESHOLD: f64 = 0.15;
/// A regret_scale at or above this counts as regret.
pub const REGRET_CUTOFF: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecord {
    pub call_digest: String,
    pub latency_ms: i64,
    /// `None` until Leaf B arrives; un-attested decisions are never counted as
    /// regret (T-DRF-007).
    pub regret_scale: Option<u8>,
    pub endorsed: bool,
}

impl DecisionRecord {
    #[must_use]
    pub fn new(call_digest: impl Into<String>, latency_ms: i64, endorsed: bool) -> Self {
        Self {
            call_digest: call_digest.into(),
            latency_ms,
            regret_scale: None,
            endorsed,
        }
    }

    /// A decision under 2 s is a rubber-stamp candidate (T-DRF-001).
    #[must_use]
    pub fn rubber_stamp(&self) -> bool {
        self.latency_ms < RUBBER_STAMP_MS
    }
}

#[derive(Clone, Debug, Default)]
pub struct DriftMetrics {
    /// Per principal, oldest first, capped at [`WINDOW`].
    windows: BTreeMap<PrincipalId, Vec<DecisionRecord>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrincipalMetrics {
    pub samples: usize,
    pub attested: usize,
    pub rubber_stamp_rate: f64,
    pub regret_rate: f64,
    /// Bounded [0, 1]; monotone non-decreasing in the rubber-stamp rate
    /// (T-DRF-004).
    pub sycophantic_drift: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tightening {
    pub cap: u64,
    pub require_dual_principal: bool,
    pub reason: &'static str,
}

impl DriftMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a decision. Windows are per principal and bounded.
    pub fn record(&mut self, principal: &PrincipalId, record: DecisionRecord) {
        let window = self.windows.entry(principal.clone()).or_default();
        window.push(record);
        if window.len() > WINDOW {
            window.remove(0);
        }
    }

    /// Attach the Leaf B outcome to the matching decision.
    pub fn attest(&mut self, principal: &PrincipalId, call_digest: &str, regret_scale: u8) -> bool {
        let Some(window) = self.windows.get_mut(principal) else {
            return false;
        };
        for record in window.iter_mut().rev() {
            if record.call_digest == call_digest {
                record.regret_scale = Some(regret_scale);
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn metrics(&self, principal: &PrincipalId) -> PrincipalMetrics {
        let empty = Vec::new();
        let window = self.windows.get(principal).unwrap_or(&empty);
        let samples = window.len();
        let stamps = window.iter().filter(|r| r.rubber_stamp()).count();
        let attested: Vec<&DecisionRecord> =
            window.iter().filter(|r| r.regret_scale.is_some()).collect();
        let regrets = attested
            .iter()
            .filter(|r| r.regret_scale.is_some_and(|s| s >= REGRET_CUTOFF))
            .count();
        let rubber_stamp_rate = ratio(stamps, samples);
        let regret_rate = ratio(regrets, attested.len());
        PrincipalMetrics {
            samples,
            attested: attested.len(),
            rubber_stamp_rate,
            regret_rate,
            sycophantic_drift: (0.5 * rubber_stamp_rate + 0.5 * regret_rate).clamp(0.0, 1.0),
        }
    }

    /// `POSSIBLE_RUBBER_STAMP` is a *finding*, never a verdict on its own.
    #[must_use]
    pub fn rubber_stamp_finding(&self, principal: &PrincipalId) -> Option<&'static str> {
        let window = self.windows.get(principal)?;
        let last = window.last()?;
        if last.rubber_stamp() {
            Some("POSSIBLE_RUBBER_STAMP")
        } else {
            None
        }
    }

    /// Auto-tightening: regret above the threshold over a **full** window lowers
    /// the cap and requires a second principal (P3-R21). It never raises the cap.
    #[must_use]
    pub fn auto_tighten(&self, principal: &PrincipalId, current_cap: u64) -> Option<Tightening> {
        let metrics = self.metrics(principal);
        if metrics.samples < WINDOW || metrics.regret_rate <= REGRET_THRESHOLD {
            return None;
        }
        Some(Tightening {
            cap: current_cap.saturating_sub(1).max(1),
            require_dual_principal: true,
            reason: "regret above 15% over the trailing window",
        })
    }

    #[must_use]
    pub fn principal_count(&self) -> usize {
        self.windows.len()
    }
}

fn ratio(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

// --------------------------------------------------------- dual principal

/// What principal 1 saw, so it can be *excluded* from principal 2's view.
#[derive(Clone, Debug)]
pub struct FirstPrincipalInput<'a> {
    pub decision_text: Option<&'a str>,
    pub note: Option<&'a str>,
}

/// The material both principals must see. The second principal's view is built
/// from this only, never from principal 1's decision (T-DRF-003).
#[derive(Clone, Debug)]
pub struct DualPrincipalRequest<'a> {
    pub action: &'a str,
    pub resolved_effect: &'a str,
    pub counter_considerations: &'a [String],
    pub budget_line: &'a str,
    pub first: FirstPrincipalInput<'a>,
}

/// Render the second principal's brief. Principal 1's decision and note are
/// structurally absent, not merely hidden by CSS.
#[must_use]
pub fn second_principal_brief(request: &DualPrincipalRequest) -> String {
    let mut out = String::new();
    out.push_str("Action: ");
    out.push_str(request.action);
    out.push('\n');
    out.push_str("Effect: ");
    out.push_str(request.resolved_effect);
    out.push('\n');
    for c in request.counter_considerations {
        out.push_str("Consideration: ");
        out.push_str(c);
        out.push('\n');
    }
    out.push_str(request.budget_line);
    out.push('\n');
    out.push_str("Decision: (independent review required)\n");
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualOutcome {
    Endorsed,
    Denied,
    /// Both principals must endorse; disagreement denies (fail closed).
    Split,
}

/// Combine the two independent decisions. Any split denies.
#[must_use]
pub fn combine(first_endorses: bool, second_endorses: bool) -> DualOutcome {
    match (first_endorses, second_endorses) {
        (true, true) => DualOutcome::Endorsed,
        (false, false) => DualOutcome::Denied,
        _ => DualOutcome::Split,
    }
}

/// A finding for the ledger when a dual-principal flow was required.
#[must_use]
pub fn dual_finding(outcome: DualOutcome) -> Option<&'static str> {
    match outcome {
        DualOutcome::Split => Some("DUAL_PRINCIPAL_SPLIT"),
        _ => None,
    }
}
