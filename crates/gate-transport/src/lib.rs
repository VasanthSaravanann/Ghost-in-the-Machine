//! gate-transport — MCP JSON-RPC framing, stdio shim, HTTP/SSE proxy
//! (plan.md §2.1, M0-T05).
//!
//! The transport has no authority: it asks a [\`stdio::Mediator\`] what to do with
//! each message and reports everything it does through an [\`stdio::EventSink\`].

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

pub mod frame;
pub mod http;
pub mod stdio;

pub use frame::{
    classify, read_limited_line, Frame, FrameKind, FrameTracker, FramingError, LineRead,
    ParsedLine, RpcId, TrackError, DEFAULT_MAX_MESSAGE_BYTES,
};
pub use http::{HttpError, HttpProxy, HttpProxyConfig};
pub use stdio::CollectingSink;
pub use stdio::{
    error_response, ConnectionContext, DenyServerRequests, Direction, EventSink, ForwardAll,
    Mediation, Mediator, NullSink, ProxySummary, StdioProxy, TransportEvent, GATE_DENIED,
    PARSE_ERROR,
};
