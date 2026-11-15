//! H7 — the over-taint cost frontier, measured on benign workloads.
//!
//! For each benign scenario that reads untrusted content and then performs an
//! allowlisted effectful call, we ask two boundary policies whether the call is
//! permitted:
//!   * CONSERVATIVE — every untrusted segment in the turn window taints the call;
//!   * PRECISE      — a principal-only checkpoint screens the read, so the write
//!                    is allowed (the H7 mechanism).
//! The difference is the *cost* of conservative boundary taint, reported with
//! exact 95 % upper bounds. No model calls, no scenario-supplied taint labels.

#![allow(clippy::print_stdout)]

use std::sync::Arc;

use gate_core::{AuthClosure, Label, PrincipalId};
use gate_policy::{CallRequest, PivotMode, Policy, PolicyEngine};
use gate_provenance::{
    control_flow_taint, PrincipalCheckpoint, ProvenanceStore, SegmentSpec, SourceRef,
};
use void_bench::stats::rate_s;
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
    let policy = Arc::new(Policy::parse(POLICY).unwrap_or_else(|_| std::process::exit(1)));
    PolicyEngine::new(policy, Arc::new(gate_policy::LexicalResolver))
        .with_pivot_mode(PivotMode::Deny)
}

fn call_with(closure: AuthClosure) -> CallRequest {
    let params = serde_json::json!({"to": "partner@partner.example"})
        .as_object()
        .cloned()
        .unwrap_or_default();
    CallRequest::new("mailer:send_email", params).with_closure(closure)
}

/// Benign scenarios whose task shape includes reading untrusted content before a
/// write. This classification comes from the corpus, not from the result.
fn touches_untrusted(scenario: &Scenario) -> bool {
    matches!(
        scenario.subfamily.as_str(),
        "read_only_research" | "long_multi_session" | "repeat_tasks" | "multi_tool_write"
    )
}

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let scenarios = load_dir(root.join("evals/public")).unwrap_or_else(|_| std::process::exit(1));
    let benign: Vec<&Scenario> = scenarios.iter().filter(|s| s.family == "BEN").collect();
    let relevant: Vec<&&Scenario> = benign.iter().filter(|s| touches_untrusted(s)).collect();

    let mut conservative_denied = 0u64;
    let mut precise_denied = 0u64;
    let mut allowed_without_read = 0u64;

    for scenario in &relevant {
        // Provenance graph for the benign flow: an untrusted read, then a write.
        let mut store = ProvenanceStore::new();
        let read = store
            .insert(SegmentSpec::new(
                Label::ExternalUntrustedData,
                SourceRef::new("tool:web.fetch"),
                format!("benign document for {}", scenario.id),
                vec![],
                0,
            ))
            .unwrap_or_else(|_| std::process::exit(1));

        // CONSERVATIVE: the read taints the turn window.
        if let Some(taint) = control_flow_taint(&store, std::slice::from_ref(&read.id), None) {
            let closure: AuthClosure = [(read.id.clone(), taint.label)].into_iter().collect();
            if engine().decide(&call_with(closure)).verdict() != gate_core::Verdict::Allow {
                conservative_denied += 1;
            }
        }

        // PRECISE: a principal checkpoint screens the read.
        let checkpoint =
            PrincipalCheckpoint::new(PrincipalId::from("prn_principal"), [read.id.clone()]);
        let taint = control_flow_taint(&store, std::slice::from_ref(&read.id), Some(&checkpoint));
        let screened = taint.is_none();
        let blocked = match taint {
            // Screened off entirely -> allowed. Otherwise use the remaining label.
            None => false,
            Some(taint) => {
                let closure: AuthClosure = [(read.id.clone(), taint.label)].into_iter().collect();
                engine().decide(&call_with(closure)).verdict() != gate_core::Verdict::Allow
            }
        };
        if blocked {
            precise_denied += 1;
        }
        if screened {
            allowed_without_read += 1;
        }
    }

    let n = relevant.len() as u64;
    println!("H7 — over-taint cost on benign flows that read untrusted content");
    println!("(PILOT-STATIC; no model calls; n = {n} benign scenarios)");
    println!();
    println!("| policy | benign writes denied | interpretation |");
    println!("|---|---|---|");
    println!(
        "| CONSERVATIVE (turn-window taint) | {} | safety-first; utility cost |",
        rate_s(conservative_denied, n)
    );
    println!(
        "| PRECISE (principal checkpoint) | {} | recovers utility |",
        rate_s(precise_denied, n)
    );
    println!();
    println!(
        "Utility recovered by the checkpoint: {}/{} flows ({:.1}%).",
        allowed_without_read,
        n,
        if n == 0 {
            0.0
        } else {
            100.0 * allowed_without_read as f64 / n as f64
        }
    );
    let all = benign.len();
    println!(
        "Of ALL {} benign scenarios, the conservative rule would deny {:.1}% ({}/{}).",
        all,
        100.0 * conservative_denied as f64 / all.max(1) as f64,
        conservative_denied,
        all
    );
    println!();
    println!("Caveats: (a) the read is synthetic — no real model or document;");
    println!("(b) the PRECISE branch is the mechanism by definition, so 0% denial is a");
    println!("    consistency check, not a discovery. The measured quantity is the");
    println!("    CONSERVATIVE cost, which depends on how often benign tasks touch");
    println!("    untrusted data — workload-dependent, hence the denominator is printed.");
}
