//! stdio shim: newline-delimited MCP JSON-RPC mediation (plan.md M0-T05).
//!
//! In shadow mode the proxy is byte-equivalent: every forwarded line is written
//! exactly as received (T-TRN-001). Mediation only rewrites a line when at least
//! one message in it is blocked, and never invents a response for a
//! notification (T-TRN-004).

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

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use gate_core::EpisodeId;

use crate::frame::{
    classify, read_limited_line, Frame, FrameKind, FrameTracker, FramingError, LineRead, RpcId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Per-connection context: one connection is one episode (T-TRN-010..020).
#[derive(Clone, Debug)]
pub struct ConnectionContext {
    pub connection_id: u64,
    pub episode_id: EpisodeId,
}

/// Verdict for a single message. The gate's decision engine is wired in behind
/// this trait; the transport itself has no authority to change the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mediation {
    Forward,
    Block { reason: &'static str },
}

pub trait Mediator: Send + Sync {
    fn mediate(&self, ctx: &ConnectionContext, direction: Direction, frame: &Frame) -> Mediation;
}

/// Always forwards: shadow mode / pass-through (T-TRN-001/002).
#[derive(Debug, Default)]
pub struct ForwardAll;

impl Mediator for ForwardAll {
    fn mediate(
        &self,
        _ctx: &ConnectionContext,
        _direction: Direction,
        _frame: &Frame,
    ) -> Mediation {
        Mediation::Forward
    }
}

/// Denies requests the server initiates towards the client (T-TRN-008). Server
/// notifications are still forwarded: they cannot cause a client-side effect.
#[derive(Debug, Default)]
pub struct DenyServerRequests;

impl Mediator for DenyServerRequests {
    fn mediate(&self, _ctx: &ConnectionContext, direction: Direction, frame: &Frame) -> Mediation {
        if direction == Direction::ServerToClient && frame.is_request() {
            Mediation::Block {
                reason: "unsolicited server request",
            }
        } else {
            Mediation::Forward
        }
    }
}

/// Structured transport events. In production these become signed spans; the
/// sink is the only way the transport reports anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEvent {
    Oversized {
        direction: Direction,
        len: usize,
    },
    Malformed {
        direction: Direction,
        reason: &'static str,
    },
    Blocked {
        direction: Direction,
        method: Option<String>,
        reason: &'static str,
    },
    UnsolicitedServerRequest {
        method: String,
    },
    DuplicateRequest {
        id: RpcId,
    },
    DuplicateResponse {
        id: RpcId,
    },
    UnknownResponse {
        id: RpcId,
    },
    Eof {
        direction: Direction,
    },
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: TransportEvent);
}

#[derive(Debug, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: TransportEvent) {}
}

#[derive(Debug, Default)]
pub struct CollectingSink {
    events: Mutex<Vec<TransportEvent>>,
}

impl CollectingSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> Vec<TransportEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl EventSink for CollectingSink {
    fn emit(&self, event: TransportEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxySummary {
    pub forwarded: usize,
    pub blocked: usize,
    pub malformed: usize,
    pub oversized: usize,
    pub dropped: usize,
}

impl ProxySummary {
    #[must_use]
    pub fn total(&self) -> usize {
        self.forwarded + self.blocked + self.malformed + self.oversized + self.dropped
    }
}

pub const PARSE_ERROR: i32 = -32700;
pub const GATE_DENIED: i32 = -32001;

/// JSON-RPC error body. -32001 is the gate's transport denial, -32700 is the
/// JSON-RPC parse error.
#[must_use]
pub fn error_response(id: Option<&RpcId>, code: i32, message: &str) -> String {
    let id = id.map_or_else(|| "null".to_owned(), RpcId::to_json);
    let message = serde_json::to_string(message).unwrap_or_else(|_| "\"error\"".to_owned());
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{message}}}}}"
    )
}

fn write_line<W: Write>(writer: &mut W, text: &str) -> std::io::Result<()> {
    writer.write_all(text.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Outcome of mediating one parsed line.
struct LineOutcome {
    keep: Vec<String>,
    rewrote: bool,
}

impl LineOutcome {
    fn new() -> Self {
        Self {
            keep: Vec::new(),
            rewrote: false,
        }
    }
}

pub struct StdioProxy<M: Mediator, S: EventSink> {
    mediator: M,
    sink: S,
    max_message_bytes: usize,
}

impl<M: Mediator, S: EventSink> StdioProxy<M, S> {
    #[must_use]
    pub fn new(mediator: M, sink: S, max_message_bytes: usize) -> Self {
        Self {
            mediator,
            sink,
            max_message_bytes,
        }
    }

    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Client → server. Forwarded lines are written byte-for-byte as received.
    pub fn pump_client_to_server<R: BufRead, C: Write, U: Write>(
        &self,
        ctx: &ConnectionContext,
        reader: &mut R,
        client_out: &mut C,
        upstream: &mut U,
        tracker: &Mutex<FrameTracker>,
    ) -> std::io::Result<ProxySummary> {
        let mut summary = ProxySummary::default();
        loop {
            match read_limited_line(reader, self.max_message_bytes)? {
                LineRead::Eof => {
                    self.sink.emit(TransportEvent::Eof {
                        direction: Direction::ClientToServer,
                    });
                    break;
                }
                LineRead::Oversized { len } => {
                    summary.oversized += 1;
                    self.sink.emit(TransportEvent::Oversized {
                        direction: Direction::ClientToServer,
                        len,
                    });
                    write_line(
                        client_out,
                        &error_response(None, PARSE_ERROR, "message exceeds size limit"),
                    )?;
                }
                LineRead::Line(bytes) => {
                    let Ok(text) = std::str::from_utf8(&bytes) else {
                        summary.malformed += 1;
                        self.sink.emit(TransportEvent::Malformed {
                            direction: Direction::ClientToServer,
                            reason: "invalid UTF-8",
                        });
                        write_line(
                            client_out,
                            &error_response(None, PARSE_ERROR, "parse error"),
                        )?;
                        continue;
                    };
                    let parsed = match classify(text, self.max_message_bytes) {
                        Ok(parsed) => parsed,
                        Err(FramingError::Oversized { len, .. }) => {
                            summary.oversized += 1;
                            self.sink.emit(TransportEvent::Oversized {
                                direction: Direction::ClientToServer,
                                len,
                            });
                            write_line(
                                client_out,
                                &error_response(None, PARSE_ERROR, "message exceeds size limit"),
                            )?;
                            continue;
                        }
                        Err(FramingError::Malformed(reason)) => {
                            summary.malformed += 1;
                            self.sink.emit(TransportEvent::Malformed {
                                direction: Direction::ClientToServer,
                                reason,
                            });
                            write_line(
                                client_out,
                                &error_response(None, PARSE_ERROR, "parse error"),
                            )?;
                            continue;
                        }
                    };

                    let mut outcome = LineOutcome::new();
                    for frame in &parsed.frames {
                        let verdict = self.mediator.mediate(ctx, Direction::ClientToServer, frame);
                        match verdict {
                            Mediation::Forward => {
                                if frame.is_request() {
                                    let duplicate = tracker
                                        .lock()
                                        .map(|mut t| t.on_sent(frame))
                                        .unwrap_or(Ok(()))
                                        .err();
                                    if let Some(err) = duplicate {
                                        self.sink.emit(err.to_event());
                                        summary.blocked += 1;
                                        outcome.rewrote = true;
                                        if let Some(id) = frame.id() {
                                            write_line(
                                                client_out,
                                                &error_response(
                                                    Some(id),
                                                    GATE_DENIED,
                                                    "duplicate request id",
                                                ),
                                            )?;
                                        }
                                        continue;
                                    }
                                }
                                outcome.keep.push(frame.raw.clone());
                            }
                            Mediation::Block { reason } => {
                                summary.blocked += 1;
                                self.sink.emit(TransportEvent::Blocked {
                                    direction: Direction::ClientToServer,
                                    method: frame.method().map(str::to_owned),
                                    reason,
                                });
                                outcome.rewrote = true;
                                // Notifications get no response (T-TRN-004).
                                if let Some(id) = frame.id() {
                                    write_line(
                                        client_out,
                                        &error_response(Some(id), GATE_DENIED, "denied by gate"),
                                    )?;
                                }
                            }
                        }
                    }

                    if outcome.keep.is_empty() {
                        continue;
                    }
                    summary.forwarded += outcome.keep.len();
                    if parsed.batch && outcome.rewrote {
                        write_line(upstream, &format!("[{}]", outcome.keep.join(",")))?;
                    } else {
                        write_line(upstream, &parsed.raw)?;
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Server → client. Duplicate or unsolicited responses are dropped, never
    /// forwarded (T-TRN-007); unsolicited server requests are mediated
    /// (T-TRN-008).
    pub fn pump_server_to_client<V: BufRead, C: Write, U: Write>(
        &self,
        ctx: &ConnectionContext,
        reader: &mut V,
        client_out: &mut C,
        upstream: &mut U,
        tracker: &Mutex<FrameTracker>,
    ) -> std::io::Result<ProxySummary> {
        let mut summary = ProxySummary::default();
        loop {
            match read_limited_line(reader, self.max_message_bytes)? {
                LineRead::Eof => {
                    self.sink.emit(TransportEvent::Eof {
                        direction: Direction::ServerToClient,
                    });
                    break;
                }
                LineRead::Oversized { len } => {
                    summary.oversized += 1;
                    summary.dropped += 1;
                    self.sink.emit(TransportEvent::Oversized {
                        direction: Direction::ServerToClient,
                        len,
                    });
                }
                LineRead::Line(bytes) => {
                    let Ok(text) = std::str::from_utf8(&bytes) else {
                        summary.malformed += 1;
                        summary.dropped += 1;
                        self.sink.emit(TransportEvent::Malformed {
                            direction: Direction::ServerToClient,
                            reason: "invalid UTF-8",
                        });
                        continue;
                    };
                    let parsed = match classify(text, self.max_message_bytes) {
                        Ok(parsed) => parsed,
                        Err(FramingError::Oversized { len, .. }) => {
                            summary.oversized += 1;
                            summary.dropped += 1;
                            self.sink.emit(TransportEvent::Oversized {
                                direction: Direction::ServerToClient,
                                len,
                            });
                            continue;
                        }
                        Err(FramingError::Malformed(reason)) => {
                            summary.malformed += 1;
                            summary.dropped += 1;
                            self.sink.emit(TransportEvent::Malformed {
                                direction: Direction::ServerToClient,
                                reason,
                            });
                            continue;
                        }
                    };

                    let mut outcome = LineOutcome::new();
                    for frame in &parsed.frames {
                        if frame.is_response() {
                            let tracked = tracker
                                .lock()
                                .map(|mut t| t.on_received(frame))
                                .unwrap_or(Ok(()));
                            if let Err(err) = tracked {
                                self.sink.emit(err.to_event());
                                summary.dropped += 1;
                                outcome.rewrote = true;
                                continue;
                            }
                            outcome.keep.push(frame.raw.clone());
                            continue;
                        }

                        if frame.is_request() {
                            if let FrameKind::Request { method, .. } = &frame.kind {
                                self.sink.emit(TransportEvent::UnsolicitedServerRequest {
                                    method: method.clone(),
                                });
                            }
                        }

                        match self.mediator.mediate(ctx, Direction::ServerToClient, frame) {
                            Mediation::Forward => outcome.keep.push(frame.raw.clone()),
                            Mediation::Block { reason } => {
                                summary.blocked += 1;
                                outcome.rewrote = true;
                                self.sink.emit(TransportEvent::Blocked {
                                    direction: Direction::ServerToClient,
                                    method: frame.method().map(str::to_owned),
                                    reason,
                                });
                                if let Some(id) = frame.id() {
                                    write_line(
                                        upstream,
                                        &error_response(Some(id), GATE_DENIED, "denied by gate"),
                                    )?;
                                }
                            }
                        }
                    }

                    if outcome.keep.is_empty() {
                        continue;
                    }
                    summary.forwarded += outcome.keep.len();
                    if parsed.batch && outcome.rewrote {
                        write_line(client_out, &format!("[{}]", outcome.keep.join(",")))?;
                    } else {
                        write_line(client_out, &parsed.raw)?;
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Drive both directions concurrently. Writers are shared because either
    /// direction can need to answer an error; the readers are independent.
    pub fn run_duplex(
        &self,
        ctx: &ConnectionContext,
        client_in: impl BufRead + Send + 'static,
        client_out: Arc<Mutex<impl Write + Send + 'static>>,
        upstream_in: impl BufRead + Send + 'static,
        upstream_out: Arc<Mutex<impl Write + Send + 'static>>,
    ) -> (std::io::Result<ProxySummary>, std::io::Result<ProxySummary>) {
        let tracker = Arc::new(Mutex::new(FrameTracker::new()));
        std::thread::scope(|scope| {
            let tracker_a = Arc::clone(&tracker);
            let tracker_b = Arc::clone(&tracker);
            let client_out_a = Arc::clone(&client_out);
            let client_out_b = Arc::clone(&client_out);
            let upstream_out_a = Arc::clone(&upstream_out);
            let upstream_out_b = Arc::clone(&upstream_out);

            let a = scope.spawn(move || {
                let mut reader = client_in;
                let mut client = lock(&client_out_a);
                let mut upstream = lock(&upstream_out_a);
                self.pump_client_to_server(
                    ctx,
                    &mut reader,
                    &mut *client,
                    &mut *upstream,
                    &tracker_a,
                )
            });
            let b = scope.spawn(move || {
                let mut reader = upstream_in;
                let mut client = lock(&client_out_b);
                let mut upstream = lock(&upstream_out_b);
                self.pump_server_to_client(
                    ctx,
                    &mut reader,
                    &mut *client,
                    &mut *upstream,
                    &tracker_b,
                )
            });
            (
                a.join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("client→server pump panicked"))),
                b.join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("server→client pump panicked"))),
            )
        })
    }
}

fn lock<T>(mutex: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

trait IntoEvent {
    fn to_event(&self) -> TransportEvent;
}

impl IntoEvent for crate::frame::TrackError {
    fn to_event(&self) -> TransportEvent {
        match self {
            crate::frame::TrackError::DuplicateRequest { id } => {
                TransportEvent::DuplicateRequest { id: id.clone() }
            }
            crate::frame::TrackError::DuplicateResponse { id } => {
                TransportEvent::DuplicateResponse { id: id.clone() }
            }
            crate::frame::TrackError::UnknownResponse { id } => {
                TransportEvent::UnknownResponse { id: id.clone() }
            }
        }
    }
}
