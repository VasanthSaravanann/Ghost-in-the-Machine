//! gate-eval — a line-oriented bridge to the Rust policy engine.
//!
//! Used by the AgentDojo native defense so the allow/deny verdict comes from the
//! same `PolicyEngine` as the proxy, not from a Python reimplementation.
//!
//! stdin:  {"tool": "...", "args": {...}, "tainted": true}
//! stdout: {"allow": false, "reasons": ["DENY_TAINT_PIVOT"]}

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{BufRead, Write};
use std::sync::Arc;

use gate_core::{AuthClosure, Label, SegmentId};
use gate_policy::{CallRequest, Policy, PolicyEngine};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(position) = args.iter().position(|argument| argument == "--policy") else {
        eprintln!("usage: gate-eval --policy <policy.toml>");
        std::process::exit(2);
    };
    let Some(path) = args.get(position + 1) else {
        eprintln!("usage: gate-eval --policy <policy.toml>");
        std::process::exit(2);
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("gate-eval: cannot read policy {path}");
        std::process::exit(1);
    };
    let Ok(policy) = Policy::parse(&text) else {
        eprintln!("gate-eval: invalid policy {path}");
        std::process::exit(1);
    };
    let engine = PolicyEngine::lexical(Arc::new(policy));

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let tool = value
            .get("tool")
            .and_then(|tool| tool.as_str())
            .unwrap_or_default();
        let params = value
            .get("args")
            .and_then(|args| args.as_object())
            .cloned()
            .unwrap_or_default();
        // Unknown is treated as tainted: the bridge fails closed.
        let tainted = value
            .get("tainted")
            .and_then(|tainted| tainted.as_bool())
            .unwrap_or(true);
        let closure: AuthClosure = if tainted {
            [(
                SegmentId::from("agentdojo_untrusted"),
                Label::ExternalUntrustedData,
            )]
            .into_iter()
            .collect()
        } else {
            AuthClosure::new()
        };
        let decision = engine.decide(&CallRequest::new(tool, params).with_closure(closure));
        let response = serde_json::json!({
            "allow": decision.verdict() == gate_core::Verdict::Allow,
            "reasons": decision.reasons().iter().map(|reason| reason.code()).collect::<Vec<_>>(),
        });
        if writeln!(stdout, "{response}").is_err() {
            break;
        }
    }
}
