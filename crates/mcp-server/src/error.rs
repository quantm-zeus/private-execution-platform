//! Redacted, payload-free dispatch errors.
//!
//! Each variant maps to a static JSON-RPC error message; no variant carries
//! request data.

use thiserror::Error;

/// Fail-closed classification for a JSON-RPC frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum McpError {
    /// The frame was not well-formed JSON (`-32700`).
    #[error("malformed request")]
    ParseError,

    /// The frame was not a valid JSON-RPC 2.0 request object (`-32600`).
    #[error("invalid request")]
    InvalidRequest,

    /// The method's params were missing or not an object (`-32602`).
    #[error("invalid params")]
    InvalidParams,

    /// The method is not part of the served surface (`-32601`).
    #[error("unknown method")]
    MethodNotFound,
}

impl McpError {
    /// JSON-RPC error code for this classification.
    pub fn code(self) -> i64 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::InvalidParams => -32602,
            Self::MethodNotFound => -32601,
        }
    }
}
