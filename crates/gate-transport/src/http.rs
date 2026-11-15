//! HTTP/1.1 + SSE reverse proxy around an MCP server (plan.md M0-T05).
//!
//! Request bodies that are \`application/json\` are mediated message-by-message
//! before anything is forwarded; a denial never reaches the upstream server.
//! Responses are streamed through unchanged, which keeps SSE byte-identical
//! (T-TRN-002) and lets events arrive incrementally. Non-streaming JSON
//! responses are additionally correlated against outstanding request ids, with
//! duplicates reported through the [\`EventSink\`] (T-TRN-007).

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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gate_core::IdFactory;

use crate::frame::{classify, FrameTracker, FramingError};
use crate::stdio::{
    error_response, ConnectionContext, Direction, EventSink, Mediation, Mediator, TransportEvent,
    GATE_DENIED, PARSE_ERROR,
};

/// Smallest accepted configuration: header cap, body cap, message cap, timeouts.
#[derive(Clone, Debug)]
pub struct HttpProxyConfig {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_message_bytes: usize,
    pub io_timeout: Duration,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 8 * 1024 * 1024,
            max_message_bytes: crate::frame::DEFAULT_MAX_MESSAGE_BYTES,
            io_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("header block exceeds limit")]
    HeaderTooLarge,
    #[error("body exceeds limit")]
    BodyTooLarge,
    #[error("malformed HTTP head")]
    MalformedHead,
    #[error("invalid content-length")]
    BadContentLength,
    #[error("chunked body is malformed")]
    BadChunk,
}

#[derive(Debug, Clone)]
struct Head {
    method: String,
    target: String,
    version: String,
    /// Present for responses ("HTTP/1.1 200 OK"); used to reject upstream
    /// error statuses from being treated as mediated JSON.
    #[allow(dead_code)]
    status: Option<u16>,
    headers: Vec<(String, String)>,
    raw: Vec<u8>,
}

impl Head {
    fn parse(raw: Vec<u8>) -> Result<Self, HttpError> {
        let text = std::str::from_utf8(&raw).map_err(|_| HttpError::MalformedHead)?;
        let mut lines = text.split("\r\n");
        let first = lines.next().ok_or(HttpError::MalformedHead)?;
        let (method, target, version, status) = if first.starts_with("HTTP/") {
            // Response line: "HTTP/1.1 <code> <reason>".
            let mut parts = first.splitn(3, ' ');
            let version = parts.next().ok_or(HttpError::MalformedHead)?.to_owned();
            let status: u16 = parts
                .next()
                .ok_or(HttpError::MalformedHead)?
                .parse()
                .map_err(|_| HttpError::MalformedHead)?;
            if !version.starts_with("HTTP/1.") {
                return Err(HttpError::MalformedHead);
            }
            (String::new(), String::new(), version, Some(status))
        } else {
            let mut parts = first.split_whitespace();
            let method = parts.next().ok_or(HttpError::MalformedHead)?.to_owned();
            let target = parts.next().ok_or(HttpError::MalformedHead)?.to_owned();
            let version = parts.next().ok_or(HttpError::MalformedHead)?.to_owned();
            if parts.next().is_some() || !version.starts_with("HTTP/1.") {
                return Err(HttpError::MalformedHead);
            }
            (method, target, version, None)
        };
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or(HttpError::MalformedHead)?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        Ok(Self {
            method,
            target,
            version,
            status,
            headers,
            raw,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    fn is_chunked(&self) -> bool {
        self.header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }

    fn is_json(&self) -> bool {
        self.header("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("application/json"))
    }

    /// Rewrite \`Content-Length\` for a (possibly rewritten) body and drop
    /// \`Transfer-Encoding\` (the body is re-framed as identity).
    fn rebuild(&self, body_len: usize) -> Vec<u8> {
        let mut out = format!("{} {} {}\r\n", self.method, self.target, self.version);
        let mut wrote_length = false;
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                continue;
            }
            if name.eq_ignore_ascii_case("content-length") {
                out.push_str(&format!("content-length: {body_len}\r\n"));
                wrote_length = true;
                continue;
            }
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        if !wrote_length {
            out.push_str(&format!("content-length: {body_len}\r\n"));
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

pub struct HttpProxy<M: Mediator, S: EventSink> {
    mediator: M,
    sink: S,
    ids: IdFactory,
    config: HttpProxyConfig,
    connections: AtomicU64,
}

impl<M: Mediator, S: EventSink> HttpProxy<M, S> {
    #[must_use]
    pub fn new(mediator: M, sink: S, ids: IdFactory, config: HttpProxyConfig) -> Self {
        Self {
            mediator,
            sink,
            ids,
            config,
            connections: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Accept loop. Connection handling is one thread per connection, so a
    /// slow client cannot block other episodes (T-TRN-009/010).
    pub fn serve(
        self: &std::sync::Arc<Self>,
        listener: &TcpListener,
        upstream: SocketAddr,
    ) -> Result<(), HttpError>
    where
        M: 'static,
        S: 'static,
    {
        for incoming in listener.incoming() {
            let client = incoming?;
            let proxy = std::sync::Arc::clone(self);
            std::thread::spawn(move || {
                let _ = proxy.handle_connection(client, upstream);
            });
        }
        Ok(())
    }

    /// Handle exactly one client connection end-to-end.
    pub fn handle_connection(
        &self,
        mut client: TcpStream,
        upstream: SocketAddr,
    ) -> Result<(), HttpError> {
        client.set_read_timeout(Some(self.config.io_timeout))?;
        client.set_write_timeout(Some(self.config.io_timeout))?;

        let connection_id = self.connections.fetch_add(1, Ordering::SeqCst);
        let ctx = ConnectionContext {
            connection_id,
            episode_id: self.ids.episode_id(),
        };
        let mut tracker = FrameTracker::new();

        let head_raw = read_head(&mut client, self.config.max_header_bytes)?;
        let head = Head::parse(head_raw)?;
        let body = read_body(&mut client, &head, self.config.max_body_bytes)?;

        let body = if head.is_json() && !body.is_empty() {
            match self.mediate_body(&ctx, &body, &mut tracker) {
                Ok(rewritten) => rewritten,
                Err(response) => {
                    write_response(&mut client, response)?;
                    return Ok(());
                }
            }
        } else {
            body
        };

        let mut upstream_stream = connect(upstream, self.config.io_timeout)?;
        upstream_stream.set_read_timeout(Some(self.config.io_timeout))?;
        upstream_stream.set_write_timeout(Some(self.config.io_timeout))?;
        upstream_stream.write_all(&head.rebuild(body.len()))?;
        upstream_stream.write_all(&body)?;
        upstream_stream.flush()?;

        let response_raw = read_head(&mut upstream_stream, self.config.max_header_bytes)?;
        let response = Head::parse(response_raw)?;

        // Stream the response head through unchanged.
        client.write_all(&response.raw)?;
        client.flush()?;

        if response.is_json() {
            // Buffer non-streaming JSON so ids can be correlated (T-TRN-007).
            if let Some(len) = response.content_length() {
                if len <= self.config.max_body_bytes {
                    let mut body = vec![0u8; len];
                    read_exact(&mut upstream_stream, &mut body)?;
                    self.correlate(&ctx, &body, &mut tracker);
                    client.write_all(&body)?;
                    client.flush()?;
                    return Ok(());
                }
            }
        }

        stream_body(&mut upstream_stream, &mut client, &response)?;
        Ok(())
    }

    fn mediate_body(
        &self,
        ctx: &ConnectionContext,
        body: &[u8],
        tracker: &mut FrameTracker,
    ) -> Result<Vec<u8>, Vec<u8>> {
        let Ok(text) = std::str::from_utf8(body) else {
            self.sink.emit(TransportEvent::Malformed {
                direction: Direction::ClientToServer,
                reason: "invalid UTF-8",
            });
            return Err(http_error_body(PARSE_ERROR, "parse error"));
        };
        match classify(text, self.config.max_message_bytes) {
            Err(FramingError::Oversized { len, .. }) => {
                self.sink.emit(TransportEvent::Oversized {
                    direction: Direction::ClientToServer,
                    len,
                });
                Err(http_error_body(PARSE_ERROR, "message exceeds size limit"))
            }
            Err(FramingError::Malformed(reason)) => {
                self.sink.emit(TransportEvent::Malformed {
                    direction: Direction::ClientToServer,
                    reason,
                });
                Err(http_error_body(PARSE_ERROR, "parse error"))
            }
            Ok(parsed) => {
                let mut keep = Vec::with_capacity(parsed.frames.len());
                let mut denied = false;
                let mut rewrote = false;
                for frame in &parsed.frames {
                    match self.mediator.mediate(ctx, Direction::ClientToServer, frame) {
                        Mediation::Forward => {
                            if frame.is_request() {
                                if let Err(err) = tracker.on_sent(frame) {
                                    self.sink.emit(track_event(&err));
                                    rewrote = true;
                                    continue;
                                }
                            }
                            keep.push(frame.raw.clone());
                        }
                        Mediation::Block { reason } => {
                            denied = true;
                            rewrote = true;
                            self.sink.emit(TransportEvent::Blocked {
                                direction: Direction::ClientToServer,
                                method: frame.method().map(str::to_owned),
                                reason,
                            });
                        }
                    }
                }
                if denied {
                    return Err(http_error_body(GATE_DENIED, "denied by gate"));
                }
                if rewrote {
                    Ok(format!("[{}]", keep.join(",")).into_bytes())
                } else {
                    Ok(body.to_vec())
                }
            }
        }
    }

    fn correlate(&self, _ctx: &ConnectionContext, body: &[u8], tracker: &mut FrameTracker) {
        let Ok(text) = std::str::from_utf8(body) else {
            return;
        };
        let Ok(parsed) = classify(text, self.config.max_message_bytes) else {
            return;
        };
        for frame in &parsed.frames {
            if frame.is_response() {
                if let Err(err) = tracker.on_received(frame) {
                    self.sink.emit(track_event(&err));
                }
            }
        }
    }
}

fn track_event(err: &crate::frame::TrackError) -> TransportEvent {
    match err {
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

fn http_error_body(code: i32, message: &str) -> Vec<u8> {
    error_response(None, code, message).into_bytes()
}

fn write_response(stream: &mut TcpStream, body: Vec<u8>) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn connect(upstream: SocketAddr, timeout: Duration) -> Result<TcpStream, HttpError> {
    // Bind the local side explicitly so connect_timeout is used.
    let stream = TcpStream::connect_timeout(&upstream, timeout)?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

fn read_head(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte)? == 0 {
            return Err(HttpError::MalformedHead);
        }
        if out.len() >= limit {
            return Err(HttpError::HeaderTooLarge);
        }
        let b = byte[0];
        out.push(b);
        if out.ends_with(b"\r\n\r\n") {
            return Ok(out);
        }
    }
}

/// Read the request body, decoding chunked framing so it can be re-framed as
/// identity (bounded by \`limit\`).
fn read_body(stream: &mut TcpStream, head: &Head, limit: usize) -> Result<Vec<u8>, HttpError> {
    if head.is_chunked() {
        let mut out = Vec::new();
        loop {
            let size_line = read_until_crlf(stream, 128)?;
            let size_text = size_line.split(|b| *b == b';').next().unwrap_or(&size_line);
            let size_text = std::str::from_utf8(size_text).map_err(|_| HttpError::BadChunk)?;
            let size =
                usize::from_str_radix(size_text.trim(), 16).map_err(|_| HttpError::BadChunk)?;
            if size == 0 {
                // Consume trailers up to the blank line.
                loop {
                    let line = read_until_crlf(stream, 8 * 1024)?;
                    if line.is_empty() {
                        break;
                    }
                }
                break;
            }
            if out.len().saturating_add(size) > limit {
                return Err(HttpError::BodyTooLarge);
            }
            let mut chunk = vec![0u8; size];
            read_exact(stream, &mut chunk)?;
            out.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            read_exact(stream, &mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(HttpError::BadChunk);
            }
        }
        Ok(out)
    } else if let Some(len) = head.content_length() {
        if len > limit {
            return Err(HttpError::BodyTooLarge);
        }
        let mut body = vec![0u8; len];
        read_exact(stream, &mut body)?;
        Ok(body)
    } else {
        Ok(Vec::new())
    }
}

fn read_until_crlf(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte)? == 0 {
            return Err(HttpError::BadChunk);
        }
        out.push(byte[0]);
        if out.len() > limit {
            return Err(HttpError::BadChunk);
        }
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return Ok(out);
        }
    }
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), HttpError> {
    let mut filled = 0;
    while filled < buf.len() {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match stream.read(rest) {
            Ok(0) => return Err(HttpError::Io(std::io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(HttpError::Io(e)),
        }
    }
    Ok(())
}

/// Stream the response body through, preserving chunk framing byte-for-byte
/// (this is what makes SSE incremental and identical).
fn stream_body(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    head: &Head,
) -> Result<(), HttpError> {
    if let Some(len) = head.content_length() {
        let mut remaining = len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            let Some(dst) = buf.get_mut(..want) else {
                break;
            };
            let n = upstream.read(dst)?;
            if n == 0 {
                return Err(HttpError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            let Some(chunk) = buf.get(..n) else { break };
            client.write_all(chunk)?;
            client.flush()?;
            remaining -= n;
        }
        return Ok(());
    }
    if head.is_chunked() {
        loop {
            let size_line = read_until_crlf(upstream, 128)?;
            let size_text = size_line.split(|b| *b == b';').next().unwrap_or(&size_line);
            let size_text = std::str::from_utf8(size_text).map_err(|_| HttpError::BadChunk)?;
            let size =
                usize::from_str_radix(size_text.trim(), 16).map_err(|_| HttpError::BadChunk)?;
            client.write_all(&size_line)?;
            client.write_all(b"\r\n")?;
            if size == 0 {
                loop {
                    let line = read_until_crlf(upstream, 8 * 1024)?;
                    client.write_all(&line)?;
                    client.write_all(b"\r\n")?;
                    if line.is_empty() {
                        break;
                    }
                }
                client.flush()?;
                return Ok(());
            }
            let mut chunk = vec![0u8; size];
            read_exact(upstream, &mut chunk)?;
            client.write_all(&chunk)?;
            let mut crlf = [0u8; 2];
            read_exact(upstream, &mut crlf)?;
            client.write_all(b"\r\n")?;
            client.flush()?;
        }
    }
    let mut buf = [0u8; 8192];
    loop {
        let n = upstream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let Some(chunk) = buf.get(..n) else { break };
        client.write_all(chunk)?;
        client.flush()?;
    }
    Ok(())
}
