//! MCP JSON-RPC framing (plan.md M0-T05).
//!
//! The framer is deliberately strict: a message that does not parse as a
//! JSON-RPC 2.0 object (or a batch of them) is a protocol error and must not
//! reach the upstream server. Size limits and line reading are bounded so
//! adversarial input cannot force unbounded allocation (T-TRN-005/006/009).

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

use std::fmt;
use std::io::BufRead;

use serde_json::Value;

/// Default cap on one JSON-RPC message (1 MiB).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// A JSON-RPC id. MCP uses string ids in practice; numbers are accepted and
/// preserved exactly.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpcId {
    Number(i64),
    Str(String),
}

impl RpcId {
    #[must_use]
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Number(n) => n.as_i64().map(Self::Number),
            Value::String(s) => Some(Self::Str(s.clone())),
            _ => None,
        }
    }

    /// JSON literal for this id, preserving type.
    #[must_use]
    pub fn to_json(&self) -> String {
        match self {
            Self::Number(n) => n.to_string(),
            Self::Str(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned()),
        }
    }
}

impl fmt::Display for RpcId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Request { id: RpcId, method: String },
    Notification { method: String },
    Response { id: RpcId, is_error: bool },
}

/// One JSON-RPC message plus its exact wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Bytes as received (batch elements are re-serialised by the framer).
    pub raw: String,
    pub kind: FrameKind,
}

impl Frame {
    #[must_use]
    pub fn id(&self) -> Option<&RpcId> {
        match &self.kind {
            FrameKind::Request { id, .. } | FrameKind::Response { id, .. } => Some(id),
            FrameKind::Notification { .. } => None,
        }
    }

    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match &self.kind {
            FrameKind::Request { method, .. } | FrameKind::Notification { method } => Some(method),
            FrameKind::Response { .. } => None,
        }
    }

    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self.kind, FrameKind::Request { .. })
    }

    #[must_use]
    pub fn is_notification(&self) -> bool {
        matches!(self.kind, FrameKind::Notification { .. })
    }

    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(self.kind, FrameKind::Response { .. })
    }

    #[must_use]
    pub fn is_error_response(&self) -> bool {
        matches!(self.kind, FrameKind::Response { is_error: true, .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramingError {
    Oversized { len: usize, limit: usize },
    Malformed(&'static str),
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized { len, limit } => {
                write!(f, "message of {len} bytes exceeds limit {limit}")
            }
            Self::Malformed(reason) => write!(f, "malformed message: {reason}"),
        }
    }
}

impl std::error::Error for FramingError {}

/// A parsed line: either one message or a batch of them (T-TRN-003).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedLine {
    pub raw: String,
    pub batch: bool,
    pub frames: Vec<Frame>,
}

/// Parse one newline-delimited message.
pub fn classify(raw: &str, limit: usize) -> Result<ParsedLine, FramingError> {
    if raw.len() > limit {
        return Err(FramingError::Oversized {
            len: raw.len(),
            limit,
        });
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FramingError::Malformed("empty message"));
    }
    let value: Value =
        serde_json::from_str(trimmed).map_err(|_| FramingError::Malformed("invalid JSON"))?;
    match &value {
        Value::Array(items) => {
            if items.is_empty() {
                return Err(FramingError::Malformed("empty batch"));
            }
            let mut frames = Vec::with_capacity(items.len());
            for item in items {
                if item.is_array() {
                    return Err(FramingError::Malformed("nested batch"));
                }
                frames.push(classify_value(item)?);
            }
            Ok(ParsedLine {
                raw: raw.to_owned(),
                batch: true,
                frames,
            })
        }
        other => Ok(ParsedLine {
            raw: raw.to_owned(),
            batch: false,
            frames: vec![classify_value(other)?],
        }),
    }
}

fn classify_value(value: &Value) -> Result<Frame, FramingError> {
    let object = value
        .as_object()
        .ok_or(FramingError::Malformed("message must be an object"))?;
    match object.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        _ => return Err(FramingError::Malformed("jsonrpc must be \"2.0\"")),
    }
    let raw = serde_json::to_string(value)
        .map_err(|_| FramingError::Malformed("message is not serialisable"))?;

    if let Some(method) = object.get("method") {
        let method = method
            .as_str()
            .ok_or(FramingError::Malformed("method must be a string"))?
            .to_owned();
        return match object.get("id") {
            Some(id) => {
                let id = RpcId::from_value(id).ok_or(FramingError::Malformed("invalid id"))?;
                Ok(Frame {
                    raw,
                    kind: FrameKind::Request { id, method },
                })
            }
            None => Ok(Frame {
                raw,
                kind: FrameKind::Notification { method },
            }),
        };
    }

    let id = object
        .get("id")
        .ok_or(FramingError::Malformed("message has neither method nor id"))?;
    let id = RpcId::from_value(id).ok_or(FramingError::Malformed("invalid id"))?;
    Ok(Frame {
        raw,
        kind: FrameKind::Response {
            id,
            is_error: object.contains_key("error"),
        },
    })
}

/// Result of a bounded line read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineRead {
    Line(Vec<u8>),
    /// The line exceeded the limit; the excess was discarded, not buffered.
    Oversized {
        len: usize,
    },
    Eof,
}

/// Read one \`\\n\`-terminated line with a hard memory bound.
pub fn read_limited_line<R: BufRead>(reader: &mut R, limit: usize) -> std::io::Result<LineRead> {
    let mut buf = Vec::new();
    let mut total = 0usize;
    let mut oversized = false;
    loop {
        let mut byte = [0u8; 1];
        let read = reader.read(&mut byte)?;
        if read == 0 {
            return Ok(if total == 0 {
                LineRead::Eof
            } else if oversized {
                LineRead::Oversized { len: total }
            } else {
                LineRead::Line(buf)
            });
        }
        total += 1;
        // \`byte[0]\` is safe: read() == 1 was just checked.
        let b = *byte.first().unwrap_or(&0);
        if b == b'\n' {
            break;
        }
        if !oversized {
            if buf.len() >= limit {
                oversized = true;
                buf.clear();
                buf.shrink_to_fit();
            } else {
                buf.push(b);
            }
        }
    }
    if oversized {
        Ok(LineRead::Oversized { len: total })
    } else {
        Ok(LineRead::Line(buf))
    }
}

/// Request/response correlation (T-TRN-007).
#[derive(Debug, Default)]
pub struct FrameTracker {
    pending: std::collections::BTreeMap<RpcId, ()>,
    completed: std::collections::BTreeSet<RpcId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackError {
    DuplicateRequest { id: RpcId },
    DuplicateResponse { id: RpcId },
    UnknownResponse { id: RpcId },
}

impl FrameTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request sent towards the server.
    pub fn on_sent(&mut self, frame: &Frame) -> Result<(), TrackError> {
        if let FrameKind::Request { id, .. } = &frame.kind {
            if self.pending.contains_key(id) || self.completed.contains(id) {
                return Err(TrackError::DuplicateRequest { id: id.clone() });
            }
            self.pending.insert(id.clone(), ());
        }
        Ok(())
    }

    /// Record a message received from the server. Out-of-order responses are
    /// fine; duplicates and unsolicited responses are not.
    pub fn on_received(&mut self, frame: &Frame) -> Result<(), TrackError> {
        if let FrameKind::Response { id, .. } = &frame.kind {
            if self.pending.remove(id).is_some() {
                self.completed.insert(id.clone());
                return Ok(());
            }
            if self.completed.contains(id) {
                return Err(TrackError::DuplicateResponse { id: id.clone() });
            }
            return Err(TrackError::UnknownResponse { id: id.clone() });
        }
        Ok(())
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn completed(&self) -> usize {
        self.completed.len()
    }
}
