//! T-E2E-001/002/003/006 — shadow mode over stdio (plan.md M0-T06).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::print_stderr)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use gate_testkit::FakeClock;
use gate_transport::{ConnectionContext, Direction, Frame, Mediator};
use mcp_gate::Report;

fn policy(workspace: &std::path::Path) -> String {
    format!(
        r#"
[tool."fs:read_file"]
class = "READ_ONLY"
pin = "sha256:4b81e2c9a7d5f3b1e8c6a4d2f0b8e6c4a2d0f8e6b4c2a0d8f6e4b2c0a8d6f4e2"
params_allow = ["path"]

  [tool."fs:read_file".path]
  prefix_allow = ["{workspace}/"]

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
"#,
        workspace = workspace.display()
    )
}

fn gate(shadow: bool) -> (Arc<mcp_gate::Gate>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("report.txt"), b"contents").unwrap();
    let gate = mcp_gate::Gate::new(
        &policy(&workspace),
        dir.path().join("spans.seg"),
        shadow,
        &"11".repeat(32),
        Arc::new(FakeClock::new(1_700_000_000_000)),
    )
    .unwrap();
    (Arc::new(gate), dir)
}

fn call(id: u64, tool: &str, args: serde_json::Value) -> Frame {
    let raw = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    })
    .to_string();
    gate_transport::classify(&raw, 1 << 20)
        .unwrap()
        .frames
        .remove(0)
}

fn ctx() -> ConnectionContext {
    ConnectionContext {
        connection_id: 1,
        episode_id: gate_core::EpisodeId::from("ep_e2e"),
    }
}

// T-E2E-001 — a benign read-only call is forwarded with no would-be block.
#[test]
fn t_e2e_001_benign_read_only() {
    let (gate, dir) = gate(true);
    let workspace = dir.path().join("workspace");
    let frame = call(
        1,
        "fs:read_file",
        serde_json::json!({"path": workspace.join("report.txt").display().to_string()}),
    );
    assert_eq!(
        gate.mediate(&ctx(), Direction::ClientToServer, &frame),
        gate_transport::Mediation::Forward
    );
    let report = gate.report();
    assert_eq!(report.evaluated, 1);
    assert!(report.would_block.is_empty(), "{report:?}");
    assert!(report.shadow);
}

// T-E2E-002 — a clean write to an allowlisted destination is forwarded.
#[test]
fn t_e2e_002_benign_write() {
    let (gate, _dir) = gate(true);
    let frame = call(
        2,
        "mailer:send_email",
        serde_json::json!({"to": "partner@partner.example"}),
    );
    assert_eq!(
        gate.mediate(&ctx(), Direction::ClientToServer, &frame),
        gate_transport::Mediation::Forward
    );
    assert!(gate.report().would_block.is_empty());
}

// T-E2E-003 — a bad parameter would be blocked; shadow mode still forwards but
// records the would-have-blocked entry (this is what G-M0 reasons about).
#[test]
fn t_e2e_003_would_have_blocked() {
    let (gate, _dir) = gate(true);
    let frame = call(
        3,
        "mailer:send_email",
        serde_json::json!({"to": "attacker@evil.example"}),
    );
    assert_eq!(
        gate.mediate(&ctx(), Direction::ClientToServer, &frame),
        gate_transport::Mediation::Forward
    );
    let report = gate.report();
    assert_eq!(report.evaluated, 1);
    assert_eq!(report.would_block.len(), 1);
    assert_eq!(report.would_block[0].verdict, "Deny");
    assert!(report.would_block[0]
        .reasons
        .contains(&"DENY_PARAM_INVALID".to_string()));
}

// T-E2E-006 — enforce mode actually blocks the same call.
#[test]
fn t_e2e_006_enforce_blocks() {
    let (gate, dir) = gate(false);
    let workspace = dir.path().join("workspace");
    let frame = call(
        4,
        "mailer:send_email",
        serde_json::json!({"to": "attacker@evil.example"}),
    );
    assert!(matches!(
        gate.mediate(&ctx(), Direction::ClientToServer, &frame),
        gate_transport::Mediation::Block { .. }
    ));
    // A clean call still passes in enforce mode.
    let ok = call(
        5,
        "fs:read_file",
        serde_json::json!({"path": workspace.join("report.txt").display().to_string()}),
    );
    assert_eq!(
        gate.mediate(&ctx(), Direction::ClientToServer, &ok),
        gate_transport::Mediation::Forward
    );
}

// T-E2E-004b — every evaluated call leaves a signed span on the chain.
#[test]
fn t_e2e_spans_are_written() {
    let dir = tempfile::TempDir::new().unwrap();
    let spans = dir.path().join("spans.seg");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let gate = mcp_gate::Gate::new(
        &policy(&workspace),
        &spans,
        true,
        &"11".repeat(32),
        Arc::new(FakeClock::new(1_700_000_000_000)),
    )
    .unwrap();
    let _ = gate.evaluate(&call(
        1,
        "fs:read_file",
        serde_json::json!({"path": workspace.join("report.txt").display().to_string()}),
    ));
    let _ = gate.evaluate(&call(
        2,
        "mailer:send_email",
        serde_json::json!({"to": "x@evil.example"}),
    ));
    let stored = gate_span::SegmentLog::read_all(&spans).unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].span.seq, 0);
    assert_eq!(
        stored[1].span.prev.as_deref(),
        Some(stored[0].digest.as_str())
    );
    assert!(stored
        .iter()
        .all(|s| s.span.policy_hash.starts_with("sha256:")));
}

// G-M0 preparation — the decision path latency is measured and reported. The
// gate itself (p99 <= 15 ms) needs ISSUE-001's storage profile.
#[test]
fn g_m0_latency_of_the_decision_path() {
    let (gate, dir) = gate(true);
    let workspace = dir.path().join("workspace");
    let frame = call(
        7,
        "fs:read_file",
        serde_json::json!({"path": workspace.join("report.txt").display().to_string()}),
    );
    let context = ctx();
    let iterations = 2_000;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let _ = gate.mediate(&context, Direction::ClientToServer, &frame);
        samples.push(start.elapsed().as_secs_f64() * 1e3);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize];
    eprintln!(
        "G-M0 decision-path latency: p50={:.3} ms p95={:.3} ms p99={:.3} ms (includes fsync'd span commit)",
        pick(0.50), pick(0.95), pick(0.99)
    );
    // This is a *probe*, not the P-LAT-1 gate: the gate is measured on the
    // storage profile fixed by ISSUE-001, and CI runners are shared/virtualised.
    // Assert only that the path is not hung or pathological.
    assert!(
        pick(0.99) < 5_000.0,
        "decision path appears hung: {:.1} ms",
        pick(0.99)
    );
}

// The CLI wires the proxy end to end: a canned upstream echoes a response and
// the report is written.
#[test]
fn cli_shadow_run_writes_report() {
    let dir = tempfile::TempDir::new().unwrap();
    let policy_path = dir.path().join("policy.toml");
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(&policy_path, policy(&workspace)).unwrap();
    let config_path = dir.path().join("gate.toml");
    std::fs::write(
        &config_path,
        format!(
            "policy = \"{}\"\nspans = \"{}\"\nshadow = true\n",
            policy_path.display(),
            dir.path().join("spans.seg").display()
        ),
    )
    .unwrap();
    let script = dir.path().join("upstream.py");
    std::fs::write(
        &script,
        r#"import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" in msg:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": True}}), flush=True)
"#,
    )
    .unwrap();
    let report_path = dir.path().join("report.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-gate"))
        .arg("--config")
        .arg(&config_path)
        .arg("--report")
        .arg(&report_path)
        .arg("--upstream")
        .arg("python3")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"mailer:send_email","arguments":{{"to":"attacker@evil.example"}}}}}}"#
        )
        .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Report =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report.evaluated, 1);
    assert_eq!(report.would_block.len(), 1, "{report:?}");
}
