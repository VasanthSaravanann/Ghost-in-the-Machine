//! mcp-gate CLI: shadow-mode proxy between a client (stdio) and an upstream MCP
//! server command (plan.md M0-T06).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use gate_core::Clock;
use gate_transport::{ConnectionContext, StdioProxy};

/// Locks the shared client writer only for the duration of one write, so the two
/// pumps never hold the mutex across a blocking read (that deadlocks).
struct LockedWriter(Arc<Mutex<std::io::Stdout>>);

impl std::io::Write for LockedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.flush()
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: mcp-gate --config <gate.toml> --upstream <command...> [--report <path>] [--enforce]"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = None;
    let mut upstream: Vec<String> = Vec::new();
    let mut report_path = None;
    let mut enforce = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = args.get(i).cloned();
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).cloned();
            }
            "--enforce" => enforce = true,
            "--upstream" => {
                i += 1;
                upstream = args.get(i..).unwrap_or_default().to_vec();
                break;
            }
            _ => usage(),
        }
        i += 1;
    }
    let Some(config_path) = config_path else {
        usage()
    };
    if upstream.is_empty() {
        usage();
    }

    let config = match mcp_gate::Config::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("mcp-gate: {e}");
            std::process::exit(1);
        }
    };
    let policy_text = match std::fs::read_to_string(&config.policy) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("mcp-gate: policy: {e}");
            std::process::exit(1);
        }
    };
    let shadow = config.shadow && !enforce;
    let gate = match mcp_gate::Gate::new(
        &policy_text,
        &config.spans,
        shadow,
        &config.dev_signing_seed,
        Arc::new(SystemClock),
    ) {
        Ok(gate) => Arc::new(
            gate.with_trust_tool_results(config.trust_tool_results)
                .with_trusted_tools(config.trusted_tools.clone()),
        ),
        Err(e) => {
            eprintln!("mcp-gate: {e}");
            std::process::exit(1);
        }
    };

    let mut child = match Command::new(&upstream[0])
        .args(&upstream[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("mcp-gate: cannot spawn upstream: {e}");
            std::process::exit(1);
        }
    };
    let (Some(child_stdin), Some(child_stdout)) = (child.stdin.take(), child.stdout.take()) else {
        eprintln!("mcp-gate: upstream was spawned without piped stdio");
        std::process::exit(1);
    };

    // Two pumps, with ownership arranged so the upstream sees EOF when the
    // client closes: thread A owns the child's stdin and drops it on EOF.
    let client_out = Arc::new(Mutex::new(std::io::stdout()));
    let tracker = Arc::new(Mutex::new(gate_transport::FrameTracker::new()));
    let ctx = ConnectionContext {
        connection_id: 1,
        episode_id: gate_core::EpisodeId::from("ep_gate"),
    };
    let proxy = StdioProxy::new(
        mcp_gate::SharedGate(Arc::clone(&gate)),
        mcp_gate::CountingSink::default(),
        config.max_message_bytes,
    );
    let proxy = Arc::new(proxy);
    let client_out_a = Arc::clone(&client_out);
    let client_out_b = Arc::clone(&client_out);
    let tracker_a = Arc::clone(&tracker);
    let tracker_b = Arc::clone(&tracker);
    let ctx_a = ctx.clone();
    let ctx_b = ctx.clone();
    let proxy_a = Arc::clone(&proxy);
    let proxy_b = Arc::clone(&proxy);
    let (to_upstream, to_client) = std::thread::scope(|scope| {
        let a = scope.spawn(move || {
            let mut reader = std::io::BufReader::new(std::io::stdin());
            let mut out = LockedWriter(Arc::clone(&client_out_a));
            let mut upstream = child_stdin; // owned here: dropped at EOF
            proxy_a
                .pump_client_to_server(&ctx_a, &mut reader, &mut out, &mut upstream, &tracker_a)
                .map(|_| ())
        });
        let b = scope.spawn(move || {
            let mut reader = std::io::BufReader::new(child_stdout);
            let mut out = LockedWriter(Arc::clone(&client_out_b));
            // Upstream-bound error responses (blocked server requests) are not
            // produced by this mediator; a sink keeps the signature honest.
            let mut sink = std::io::sink();
            proxy_b
                .pump_server_to_client(&ctx_b, &mut reader, &mut out, &mut sink, &tracker_b)
                .map(|_| ())
        });
        (a.join(), b.join())
    });
    let _ = (to_upstream, to_client);
    let _ = child.wait();
    let report = gate.report();
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into());
    if let Some(path) = report_path {
        let _ = std::fs::write(&path, &json);
    }
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{json}");
}
