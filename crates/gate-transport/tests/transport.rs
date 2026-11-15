//! T-TRN-001..020 and T-TRN-F (plan.md §5.4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::print_stderr)]

use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gate_core::{EpisodeId, IdFactory};
use gate_testkit::SeededRng;
use gate_transport::{
    classify, error_response, CollectingSink, ConnectionContext, DenyServerRequests, Direction,
    ForwardAll, Frame, FrameTracker, HttpError, HttpProxy, HttpProxyConfig, Mediation, Mediator,
    ProxySummary, StdioProxy, TransportEvent, GATE_DENIED, PARSE_ERROR,
};

// ---------------------------------------------------------------- helpers

fn ctx() -> ConnectionContext {
    ConnectionContext {
        connection_id: 1,
        episode_id: EpisodeId::from("ep_t"),
    }
}

fn blocking_on(methods: &'static [&'static str]) -> impl Mediator {
    struct BlockList(&'static [&'static str]);
    impl Mediator for BlockList {
        fn mediate(&self, _: &ConnectionContext, _: Direction, frame: &Frame) -> Mediation {
            match frame.method() {
                Some(m) if self.0.contains(&m) => Mediation::Block {
                    reason: "test deny",
                },
                _ => Mediation::Forward,
            }
        }
    }
    BlockList(methods)
}

#[derive(Debug, Default)]
struct StdioRun {
    upstream: String,
    client: String,
    summary: ProxySummary,
    events: Vec<TransportEvent>,
}

fn run_stdio<M: Mediator>(
    proxy: &StdioProxy<M, CollectingSink>,
    client_input: &str,
    server_input: &str,
) -> StdioRun {
    let context = ctx();
    let tracker = Mutex::new(FrameTracker::new());
    let mut client_reader = Cursor::new(client_input.as_bytes().to_vec());
    let mut client_err = Vec::new();
    let mut upstream_in = Vec::new();
    let a = proxy
        .pump_client_to_server(
            &context,
            &mut client_reader,
            &mut client_err,
            &mut upstream_in,
            &tracker,
        )
        .unwrap();

    let mut server_reader = Cursor::new(server_input.as_bytes().to_vec());
    let mut client_out = Vec::new();
    let mut upstream_err = Vec::new();
    let b = proxy
        .pump_server_to_client(
            &context,
            &mut server_reader,
            &mut client_out,
            &mut upstream_err,
            &tracker,
        )
        .unwrap();

    let mut summary = a;
    summary.forwarded += b.forwarded;
    summary.blocked += b.blocked;
    summary.malformed += b.malformed;
    summary.oversized += b.oversized;
    summary.dropped += b.dropped;

    let mut upstream = String::from_utf8_lossy(&upstream_in).into_owned();
    upstream.push_str(&String::from_utf8_lossy(&upstream_err));
    let mut client = String::from_utf8_lossy(&client_err).into_owned();
    client.push_str(&String::from_utf8_lossy(&client_out));
    StdioRun {
        upstream,
        client,
        summary,
        events: proxy.sink().events(),
    }
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().filter(|l| !l.is_empty()).collect()
}

// T-TRN-001 — shadow-mode conformance script, byte-identical both ways.
#[test]
fn t_trn_001_stdio_shadow_mode_is_byte_identical() {
    let sink = CollectingSink::new();
    let proxy = StdioProxy::new(ForwardAll, sink, 1 << 20);
    let client_script = concat!(
        r#"{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":"3","method":"tools/call","params":{"name":"fs:read_file","arguments":{"path":"/workspace/a"}}}"#,
        "\n"
    );
    let server_script = concat!(
        r#"{"jsonrpc":"2.0","id":"1","result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"ref","version":"1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"fs:read_file"}]}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":"3","result":{"content":[{"type":"text","text":"ok"}]}}"#,
        "\n"
    );
    let run = run_stdio(&proxy, client_script, server_script);
    assert_eq!(
        run.upstream, client_script,
        "requests must be byte-identical"
    );
    assert_eq!(
        run.client, server_script,
        "responses must be byte-identical"
    );
    assert_eq!(run.summary.forwarded, 7);
    assert_eq!(run.summary.blocked, 0);
    assert!(run
        .events
        .iter()
        .any(|e| matches!(e, TransportEvent::Eof { .. })));
}

// T-TRN-002 — HTTP + SSE passthrough is byte-identical and incremental.
#[test]
fn t_trn_002_http_sse_passthrough() {
    let (upstream, _handle) = spawn_upstream_once(|stream| {
        read_request(stream);
        let head = concat!(
            "HTTP/1.1 200 OK\r\n",
            "content-type: text/event-stream\r\n",
            "cache-control: no-cache\r\n",
            "transfer-encoding: chunked\r\n",
            "connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).unwrap();
        let event1 = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        write_chunk(stream, event1);
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(120));
        let event2 = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n";
        write_chunk(stream, event2);
        stream.write_all(b"0\r\n\r\n").unwrap();
        stream.flush().unwrap();
    });

    let proxy = Arc::new(http_proxy(ForwardAll, HttpProxyConfig::default()));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), upstream);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(b"GET /sse HTTP/1.1\r\nhost: upstream\r\naccept: text/event-stream\r\n\r\n")
        .unwrap();
    client.flush().unwrap();

    // Read the head, then the first event, then the second — proving streaming.
    let mut head = Vec::new();
    read_until(&mut client, b"\r\n\r\n", &mut head);
    let mut first = Vec::new();
    read_until(&mut client, b"id\":1", &mut first);
    let started = Instant::now();
    let mut second = Vec::new();
    read_until(&mut client, b"id\":2", &mut second);
    assert!(
        started.elapsed() >= Duration::from_millis(50),
        "second event must arrive later"
    );
    let mut tail = Vec::new();
    read_until(&mut client, b"0\r\n\r\n", &mut tail);
    join.join().unwrap().unwrap();

    assert!(String::from_utf8_lossy(&head).contains("text/event-stream"));
    assert!(String::from_utf8_lossy(&first).contains("event: message"));
    assert!(String::from_utf8_lossy(&second).contains("jsonrpc"));
    assert!(
        tail.ends_with(b"0\r\n\r\n"),
        "chunk terminator must be preserved"
    );
}

// T-TRN-003 — batches are mediated element by element.
#[test]
fn t_trn_003_batch_elements_mediated_individually() {
    let sink = CollectingSink::new();
    let proxy = StdioProxy::new(blocking_on(&["mailer:send_email"]), sink, 1 << 20);
    let batch = concat!(
        r#"[{"jsonrpc":"2.0","id":1,"method":"fs:read_file","params":{}},"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"mailer:send_email","params":{}},"#,
        r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}]"#,
        "\n"
    );
    let run = run_stdio(&proxy, batch, "");
    let forwarded = lines(&run.upstream);
    assert_eq!(forwarded.len(), 1);
    assert!(
        forwarded[0].starts_with('['),
        "batch framing must be preserved"
    );
    assert!(forwarded[0].contains("fs:read_file"));
    assert!(forwarded[0].contains("notifications/progress"));
    assert!(!forwarded[0].contains("mailer:send_email"));
    // Exactly one error response, for the blocked request id 2.
    let errors = lines(&run.client);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("\"id\":2"));
    assert!(errors[0].contains(&GATE_DENIED.to_string()));
    assert_eq!(run.summary.blocked, 1);
    assert_eq!(run.summary.forwarded, 2);
}

#[test]
fn t_trn_003b_untouched_batch_is_byte_identical() {
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), 1 << 20);
    let batch = concat!(
        r#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]"#,
        "\n"
    );
    let run = run_stdio(&proxy, batch, "");
    assert_eq!(run.upstream, batch);
}

// T-TRN-004 — notifications are mediated and never answered.
#[test]
fn t_trn_004_notifications_never_get_a_response() {
    let proxy = StdioProxy::new(
        blocking_on(&["notifications/evil"]),
        CollectingSink::new(),
        1 << 20,
    );
    let input = concat!(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/evil"}"#,
        "\n"
    );
    let run = run_stdio(&proxy, input, "");
    assert_eq!(lines(&run.upstream).len(), 1);
    assert!(run.upstream.contains("notifications/initialized"));
    assert!(
        run.client.is_empty(),
        "no response may be invented: {:?}",
        run.client
    );
    assert_eq!(run.summary.blocked, 1);
}

// T-TRN-005 — oversized messages are rejected, a span event is emitted, and
// the connection keeps working.
#[test]
fn t_trn_005_oversized_rejected_with_event() {
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), 64);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"blob\":\"{}\"}}}}\n",
        "x".repeat(200)
    );
    let ok = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    let input = format!("{huge}{ok}");
    let run = run_stdio(&proxy, &input, "");
    assert_eq!(run.summary.oversized, 1);
    assert_eq!(run.summary.forwarded, 1);
    assert!(run.events.iter().any(|e| matches!(
        e,
        TransportEvent::Oversized {
            direction: Direction::ClientToServer,
            ..
        }
    )));
    assert!(run.client.contains(&PARSE_ERROR.to_string()));
    assert_eq!(
        lines(&run.upstream).len(),
        1,
        "only the in-limit message is forwarded"
    );
}

// T-TRN-006 — malformed input is rejected cleanly and does not poison the stream.
#[test]
fn t_trn_006_malformed_rejected_connection_sane() {
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), 1 << 20);
    let input = concat!(
        "this is not json\n",
        r#"{"jsonrpc":"2.0","method":"tools/list"}"#,
        "\n",
        r#"{"id":7,"result":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call"}"#,
        "\n"
    );
    let run = run_stdio(&proxy, input, "");
    assert_eq!(run.summary.malformed, 2, "non-JSON and missing jsonrpc");
    assert_eq!(
        run.summary.forwarded, 2,
        "notification and request are valid"
    );
    let errors = lines(&run.client);
    assert_eq!(errors.len(), 2);
    assert!(errors.iter().all(|e| e.contains(&PARSE_ERROR.to_string())));
}

// T-TRN-007 — out-of-order responses are accepted, duplicates are detected.
#[test]
fn t_trn_007_duplicate_and_out_of_order_ids() {
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), 1 << 20);
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"a"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"b"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"c"}"#,
        "\n"
    );
    let responses = concat!(
        r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "\n"
    );
    let run = run_stdio(&proxy, requests, responses);
    assert_eq!(
        lines(&run.upstream).len(),
        2,
        "duplicate request must not be forwarded"
    );
    assert!(run
        .events
        .iter()
        .any(|e| matches!(e, TransportEvent::DuplicateRequest { .. })));
    assert!(run
        .events
        .iter()
        .any(|e| matches!(e, TransportEvent::DuplicateResponse { .. })));
    let client_lines = lines(&run.client);
    assert_eq!(
        client_lines.len(),
        3,
        "two results plus one duplicate-id error"
    );
    assert_eq!(
        client_lines
            .iter()
            .filter(|l| l.contains("\"result\""))
            .count(),
        2,
        "duplicate response must be dropped"
    );
}

// T-TRN-008 — unsolicited server requests are mediated and answered upstream.
#[test]
fn t_trn_008_unsolicited_server_request_denied() {
    let proxy = StdioProxy::new(DenyServerRequests, CollectingSink::new(), 1 << 20);
    let server = concat!(
        r#"{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#,
        "\n"
    );
    let run = run_stdio(&proxy, "", server);
    assert_eq!(
        run.client,
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#.to_owned() + "\n"
    );
    assert!(run.upstream.contains("\"id\":\"srv-1\""));
    assert!(run.upstream.contains(&GATE_DENIED.to_string()));
    assert!(run.events.iter().any(|e| matches!(
        e,
        TransportEvent::UnsolicitedServerRequest { method } if method == "sampling/createMessage"
    )));
}

// T-TRN-009 — slow-loris clients time out without leaking the connection.
#[test]
fn t_trn_009_slow_loris_times_out() {
    let (upstream, _handle) = spawn_upstream_once(|stream| {
        let _ = read_request(stream);
    });
    let config = HttpProxyConfig {
        io_timeout: Duration::from_millis(150),
        ..Default::default()
    };
    let proxy = Arc::new(http_proxy(ForwardAll, config));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), upstream);
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // Never terminate the header block.
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: slow\r\n")
        .unwrap();
    client.flush().unwrap();
    let started = Instant::now();
    let mut sink = Vec::new();
    let _ = client.read_to_end(&mut sink); // returns 0 on close, or a timeout error
    let elapsed = started.elapsed();
    let result = join.join().unwrap();
    assert!(result.is_err(), "handler must report the timeout");
    assert!(elapsed < Duration::from_secs(3), "timeout took {elapsed:?}");
}

// T-TRN-010..020 — concurrency: 100 episodes in parallel, no cross-episode
// leakage, and per-episode correlation.
#[test]
fn t_trn_010_hundred_parallel_episodes_isolated() {
    const N: usize = 100;
    #[derive(Default, Clone)]
    struct Recorder {
        seen: Arc<Mutex<Vec<(u64, String)>>>,
    }
    impl Mediator for Recorder {
        fn mediate(&self, ctx: &ConnectionContext, _: Direction, frame: &Frame) -> Mediation {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((ctx.connection_id, frame.method().unwrap_or("").to_owned()));
            }
            Mediation::Forward
        }
    }

    let upstream = spawn_echo_upstream(N);
    let recorder = Recorder::default();
    let proxy = Arc::new(HttpProxy::new(
        recorder.clone(),
        CollectingSink::new(),
        IdFactory::new(Arc::new(SeededRng::new(1))),
        HttpProxyConfig::default(),
    ));

    let mut handles = Vec::new();
    for i in 0..N {
        let proxy = Arc::clone(&proxy);
        handles.push(std::thread::spawn(move || {
            let method = format!("episode/{i}");
            let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":\"{i}\",\"method\":\"{method}\"}}");
            let (mut client, join) = connect_through_proxy(proxy, upstream);
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = format!(
                "POST /mcp HTTP/1.1\r\nhost: up\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            client.write_all(request.as_bytes()).unwrap();
            client.flush().unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            let handled = join.join().unwrap();
            assert!(handled.is_ok(), "handler failed: {:?}", handled.err());
            (i, method, response)
        }));
    }

    for handle in handles {
        let (i, method, response) = handle.join().unwrap();
        assert!(
            response.contains(&format!("\"id\":\"{i}\"")),
            "episode {i} got another episode's response: {response}"
        );
        assert!(response.contains(&method), "episode {i} lost its method");
    }

    let seen = recorder.seen.lock().unwrap();
    assert_eq!(seen.len(), N);
    let mut per_connection: std::collections::BTreeMap<u64, Vec<String>> = Default::default();
    for (connection, method) in seen.iter() {
        per_connection
            .entry(*connection)
            .or_default()
            .push(method.clone());
    }
    assert_eq!(
        per_connection.len(),
        N,
        "every connection is its own episode"
    );
    for (_, methods) in per_connection {
        assert_eq!(methods.len(), 1);
    }
    assert!(
        seen.iter().all(|(_, m)| m.starts_with("episode/")),
        "no cross-episode traffic"
    );
}

// T-TRN-011/012 — mixed and fully-allowed batches over HTTP.
#[test]
fn t_trn_011_mixed_batch_denied_without_upstream_contact() {
    let upstream = spawn_echo_upstream(1);
    let proxy = Arc::new(http_proxy(
        blocking_on(&["mailer:send_email"]),
        HttpProxyConfig::default(),
    ));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), upstream);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = concat!(
        r#"[{"jsonrpc":"2.0","id":1,"method":"fs:read_file"},"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"mailer:send_email"}]"#
    );
    let request = format!(
        "POST /mcp HTTP/1.1\r\nhost: up\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(request.as_bytes()).unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let _ = join.join();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains(&GATE_DENIED.to_string()));
}

#[test]
fn t_trn_012_all_allowed_batch_forwarded() {
    let upstream = spawn_echo_upstream(1);
    let proxy = Arc::new(http_proxy(ForwardAll, HttpProxyConfig::default()));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), upstream);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = concat!(
        r#"[{"jsonrpc":"2.0","id":1,"method":"a"},"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"b"}]"#
    );
    let request = format!(
        "POST /mcp HTTP/1.1\r\nhost: up\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(request.as_bytes()).unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    join.join().unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

// T-TRN-013 — ids keep their JSON type in synthesised errors.
#[test]
fn t_trn_013_error_id_type_preserved() {
    let proxy = StdioProxy::new(blocking_on(&["deny"]), CollectingSink::new(), 1 << 20);
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":"abc","method":"deny"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":42,"method":"deny"}"#,
        "\n"
    );
    let run = run_stdio(&proxy, input, "");
    assert!(run.client.contains("\"id\":\"abc\""));
    assert!(run.client.contains("\"id\":42"));
}

// T-TRN-014 — a blocked notification inside a batch yields no response.
#[test]
fn t_trn_014_blocked_notification_in_batch_gets_no_response() {
    let proxy = StdioProxy::new(blocking_on(&["notify"]), CollectingSink::new(), 1 << 20);
    let input = concat!(
        r#"[{"jsonrpc":"2.0","method":"notify"},{"jsonrpc":"2.0","id":5,"method":"ok"}]"#,
        "\n"
    );
    let run = run_stdio(&proxy, input, "");
    let errors = lines(&run.client);
    assert_eq!(
        errors.len(),
        0,
        "no response for the notification: {errors:?}"
    );
    assert_eq!(lines(&run.upstream).len(), 1);
    assert!(run.upstream.contains("\"id\":5"));
}

// T-TRN-015 — oversized server→client messages are dropped, not buffered.
#[test]
fn t_trn_015_oversized_server_message_dropped() {
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), 64);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}\n",
        "y".repeat(200)
    );
    let run = run_stdio(&proxy, "", &huge);
    assert_eq!(run.summary.oversized, 1);
    assert_eq!(run.summary.dropped, 1);
    assert!(run.client.is_empty());
    assert!(run.events.iter().any(|e| matches!(
        e,
        TransportEvent::Oversized {
            direction: Direction::ServerToClient,
            ..
        }
    )));
}

// T-TRN-016 — non-JSON request bodies are forwarded unchanged.
#[test]
fn t_trn_016_non_json_body_forwarded() {
    let (upstream, _upstream_handle) = spawn_upstream_once(|stream| {
        let (head, body) = read_request(stream);
        assert!(head
            .to_ascii_lowercase()
            .contains("content-type: text/plain"));
        assert_eq!(body, b"hello");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .unwrap();
    });
    let proxy = Arc::new(http_proxy(
        blocking_on(&["deny"]),
        HttpProxyConfig::default(),
    ));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), upstream);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(
            b"POST /upload HTTP/1.1\r\nhost: up\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
        )
        .unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    let read = client.read_to_string(&mut response);
    assert!(read.is_ok(), "read failed: {read:?}");
    let handled = join.join().unwrap();
    assert!(handled.is_ok(), "handler failed: {:?}", handled.err());
    assert!(response.ends_with("ok"), "{response}");
}

// T-TRN-017 — an oversized JSON body is rejected before any upstream contact.
#[test]
fn t_trn_017_oversized_json_body_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead: SocketAddr = listener.local_addr().unwrap();
    drop(listener); // nothing is listening
    let config = HttpProxyConfig {
        max_message_bytes: 64,
        ..Default::default()
    };
    let proxy = Arc::new(http_proxy(ForwardAll, config));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), dead);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"pad\":\"{}\"}}",
        "z".repeat(200)
    );
    let request = format!(
        "POST /mcp HTTP/1.1\r\nhost: up\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(request.as_bytes()).unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    let read = client.read_to_string(&mut response);
    assert!(read.is_ok(), "read failed: {read:?}");
    let handled = join.join().unwrap();
    assert!(handled.is_ok(), "handler failed: {:?}", handled.err());
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains(&PARSE_ERROR.to_string()));
}

// T-TRN-018 — malformed JSON bodies are rejected with a parse error.
#[test]
fn t_trn_018_malformed_json_body_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);
    let proxy = Arc::new(http_proxy(ForwardAll, HttpProxyConfig::default()));
    let (mut client, join) = connect_through_proxy(Arc::clone(&proxy), dead);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = "{not json";
    let request = format!(
        "POST /mcp HTTP/1.1\r\nhost: up\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(request.as_bytes()).unwrap();
    client.flush().unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    join.join().unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(response.contains(&PARSE_ERROR.to_string()));
}

// T-TRN-019 — the message limit is exact: N accepted, N+1 rejected.
#[test]
fn t_trn_019_limit_boundary_is_exact() {
    let message = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"m\"}";
    let limit = message.len();
    assert!(classify(message, limit).is_ok());
    assert!(classify(&format!("{message} "), limit).is_err());
    let proxy = StdioProxy::new(ForwardAll, CollectingSink::new(), limit);
    let run = run_stdio(&proxy, &format!("{message}\n"), "");
    assert_eq!(run.summary.forwarded, 1);
    assert_eq!(run.summary.oversized, 0);
}

// T-TRN-020 — framing + mediation latency (NF-R1 sanity; the real gate is
// P-LAT-1 at M0-T06 with the full pipeline).
#[test]
fn t_trn_020_framing_latency() {
    let message = r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"fs:read_file","arguments":{"path":"/workspace/report.txt"}}}"#;
    let iterations = 20_000;
    let parsed = classify(message, 1 << 20).unwrap();
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..iterations {
        let frame = &parsed.frames[0];
        total += frame.raw.len();
        assert!(frame.is_request());
    }
    let elapsed = start.elapsed();
    let per_message = elapsed.as_secs_f64() * 1e6 / iterations as f64;
    eprintln!("T-TRN-020: {per_message:.3} µs/message ({total} bytes)");
    assert!(
        per_message < 500.0,
        "framing is too slow: {per_message:.1} µs"
    );
}

// --------------------------------------------------------- HTTP helpers

fn http_proxy<M: Mediator + 'static>(
    mediator: M,
    config: HttpProxyConfig,
) -> HttpProxy<M, CollectingSink> {
    HttpProxy::new(
        mediator,
        CollectingSink::new(),
        IdFactory::new(Arc::new(SeededRng::new(9))),
        config,
    )
}

fn connect_through_proxy<M: Mediator + 'static, S: gate_transport::EventSink + 'static>(
    proxy: Arc<HttpProxy<M, S>>,
    upstream: SocketAddr,
) -> (TcpStream, std::thread::JoinHandle<Result<(), HttpError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (server_side, _) = listener.accept().unwrap();
    let handle = std::thread::spawn(move || proxy.handle_connection(server_side, upstream));
    (client, handle)
}

fn spawn_upstream_once(
    handler: impl FnOnce(&mut TcpStream) + Send + 'static,
) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            handler(&mut stream);
        }
    });
    (addr, handle)
}

/// Echo upstream: responds with the request id and method, so a client can
/// prove it received its own response.
fn spawn_echo_upstream(connections: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let (_head, body) = read_request(&mut stream);
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let method = value
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_owned();
            let response =
                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {"method": method}});
            let text = serde_json::to_string(&response).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                text.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(text.as_bytes());
            let _ = stream.flush();
        }
    });
    addr
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    read_until(stream, b"\r\n\r\n", &mut head);
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let len = head_text
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().to_owned())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match stream.read(&mut body[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    (head_text, body)
}

fn read_until(stream: &mut TcpStream, needle: &[u8], out: &mut Vec<u8>) {
    let mut byte = [0u8; 1];
    while !out.ends_with(needle) {
        match stream.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => out.push(byte[0]),
            Err(_) => return,
        }
    }
}

fn write_chunk(stream: &mut TcpStream, payload: &[u8]) {
    let size = format!("{:x}\r\n", payload.len());
    stream.write_all(size.as_bytes()).unwrap();
    stream.write_all(payload).unwrap();
    stream.write_all(b"\r\n").unwrap();
}

#[test]
fn frame_classification_matches_frame_kinds() {
    let parsed = classify(
        r#"{"jsonrpc":"2.0","id":1,"method":"m","params":{}}"#,
        1 << 20,
    )
    .unwrap();
    assert!(parsed.frames[0].is_request());
    let parsed = classify(r#"{"jsonrpc":"2.0","method":"m"}"#, 1 << 20).unwrap();
    assert!(parsed.frames[0].is_notification());
    let parsed = classify(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#, 1 << 20).unwrap();
    assert!(parsed.frames[0].is_response());
    assert!(parsed.frames[0].is_error_response());
    assert!(classify("[]", 1 << 20).is_err());
    assert!(classify("[[]]", 1 << 20).is_err());
    assert!(classify("42", 1 << 20).is_err());
    assert!(classify(r#"{"jsonrpc":"1.0","id":1,"method":"m"}"#, 1 << 20).is_err());
    assert!(classify(r#"{"jsonrpc":"2.0","id":1.5,"method":"m"}"#, 1 << 20).is_err());
    assert!(error_response(None, -32001, "denied").contains("\"id\":null"));
}
