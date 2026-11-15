//! H7 — the over-taint *cost curve*, not a point estimate.
//!
//! Turner-window taint denies a benign allowlisted write whenever the task read
//! untrusted content. The size of that cost therefore depends on one input:
//! **what fraction of benign tasks touch untrusted data**. That fraction is a
//! workload parameter, not something this corpus measures (the corpus has no
//! tool sequences). So instead of reporting one number derived from a hardcoded
//! subfamily list, we sweep the parameter and print the whole curve.
//!
//! No model calls and no scenario-supplied taint labels: the read is real in the
//! provenance graph, but it is *synthetic* for every selected scenario. This is
//! a sensitivity analysis, and it says so.
//!
//! `PRECISE` (principal checkpoint) is the mechanism by definition, so its 0 %
//! denial is a consistency check, not a discovery.

#![allow(clippy::print_stdout)]

use std::sync::Arc;

use gate_core::{AuthClosure, Label, PrincipalId};
use gate_policy::{CallRequest, PivotMode, Policy, PolicyEngine};
use gate_provenance::{
    control_flow_taint, PrincipalCheckpoint, ProvenanceStore, SegmentSpec, SourceRef,
};
use void_bench::{load_dir, Scenario};

const POLICY: &str = r#"
[tool."mailer:send_email"]
class = "EXTERNAL_EGRESS"
pin = "sha256:9f2c1b7d4e6a8c0f2d4b6e8a0c2e4f6a8b0d2f4e6c8a0b2d4f6e8c0a2b4d6f8e"
params_allow = ["to"]

  [tool."mailer:send_email".to]
  match = '^[\w.+-]+@(corp\.example|partner\.example)$'

[defaults]
default_deny = true
metadata_handling = "delimit"
fail_mode = "closed"
"#;

fn engine() -> PolicyEngine {
    PolicyEngine::lexical(Arc::new(
        Policy::parse(POLICY).unwrap_or_else(|_| std::process::exit(1)),
    ))
    .with_pivot_mode(PivotMode::Deny)
}

fn call_with(closure: AuthClosure) -> CallRequest {
    let params = serde_json::json!({"to": "partner@partner.example"})
        .as_object()
        .cloned()
        .unwrap_or_default();
    CallRequest::new("mailer:send_email", params).with_closure(closure)
}

/// Run the two policies on `chosen` benign scenarios, each given a synthetic
/// untrusted read before the allowlisted write.
fn measure(chosen: &[&Scenario]) -> (u64, u64) {
    let mut conservative_denied = 0u64;
    let mut precise_denied = 0u64;
    for scenario in chosen {
        let mut store = ProvenanceStore::new();
        let read = store
            .insert(SegmentSpec::new(
                Label::ExternalUntrustedData,
                SourceRef::new("tool:web.fetch"),
                format!("benign document for {}", scenario.id),
                Vec::new(),
                0,
            ))
            .unwrap_or_else(|_| std::process::exit(1));

        if let Some(taint) = control_flow_taint(&store, std::slice::from_ref(&read.id), None) {
            let closure: AuthClosure = [(read.id.clone(), taint.label)].into_iter().collect();
            if engine().decide(&call_with(closure)).verdict() != gate_core::Verdict::Allow {
                conservative_denied += 1;
            }
        }

        let checkpoint =
            PrincipalCheckpoint::new(PrincipalId::from("prn_principal"), [read.id.clone()]);
        let taint = control_flow_taint(&store, std::slice::from_ref(&read.id), Some(&checkpoint));
        let blocked = match taint {
            None => false,
            Some(taint) => {
                let closure: AuthClosure = [(read.id.clone(), taint.label)].into_iter().collect();
                engine().decide(&call_with(closure)).verdict() != gate_core::Verdict::Allow
            }
        };
        if blocked {
            precise_denied += 1;
        }
    }
    (conservative_denied, precise_denied)
}

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let scenarios = load_dir(root.join("evals/public")).unwrap_or_else(|_| std::process::exit(1));
    let mut benign: Vec<&Scenario> = scenarios.iter().filter(|s| s.family == "BEN").collect();
    benign.sort_by(|a, b| a.id.cmp(&b.id));

    println!("H7 — over-taint cost curve (sensitivity analysis, not a workload measurement)");
    println!();
    println!(
        "| assumed share of benign tasks that read untrusted data | benign writes denied (CONSERVATIVE) | denied (PRECISE checkpoint) |"
    );
    println!("|---|---|---|");
    for pct in [0u64, 10, 25, 50, 75, 100] {
        let n = (benign.len() as u64 * pct / 100) as usize;
        let chosen = &benign[..n.min(benign.len())];
        let (conservative, precise) = measure(chosen);
        println!(
            "| {pct}% ({} of {}) | {}/{} = {:.1}% | {}/{} = {:.1}% |",
            chosen.len(),
            benign.len(),
            conservative,
            chosen.len(),
            100.0 * conservative as f64 / chosen.len().max(1) as f64,
            precise,
            chosen.len(),
            100.0 * precise as f64 / chosen.len().max(1) as f64,
        );
    }
    println!();
    println!(
        "Caveats: (a) the read is synthetic and every selected scenario gets one; the corpus \
         contains no tool sequences, so the *fraction* is a swept parameter, not a measurement; \
         (b) the selection is the first N benign scenarios by id, not a random sample; \
         (c) the PRECISE branch is the mechanism by definition, so 0% denial is a consistency \
         check, not a discovery; (d) a real workload estimate needs traces, not this corpus."
    );
}
