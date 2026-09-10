//! Structured, fail-closed adapter errors.
//!
//! Invariants:
//! - No error variant, Display implementation, or Debug implementation may disclose
//!   endpoints, bearer tokens, credentials, raw request payloads, or raw response bodies.
//! - Field names and service identities are safe closed vocabularies.

use std::fmt;
use thiserror::Error;

use crate::transport::McpServiceId;

#[derive(Clone, PartialEq, Eq, Error)]
pub enum McpAdapterError {
    #[error("invalid argument: {field}")]
    InvalidArgument { field: &'static str },

    #[error("unsupported tool: {tool}")]
    UnsupportedTool { tool: &'static str },

    #[error("disallowed operation: read-only boundary violation")]
    DisallowedOperation,

    #[error("mcp service unavailable: {service}")]
    ServiceUnavailable { service: McpServiceId },

    #[error("mcp transport failure: {service}")]
    TransportFailure { service: McpServiceId },

    #[error("oversized mcp response: {service}")]
    OversizedResponse { service: McpServiceId },

    #[error("malformed mcp response: {service}")]
    MalformedResponse { service: McpServiceId },

    #[error("tool execution failed: {service}")]
    ToolExecutionFailed { service: McpServiceId },
}

impl fmt::Debug for McpAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted, safe debug output that preserves invariant: zero secret,
        // credential, raw payload, or raw response body disclosure.
        write!(f, "McpAdapterError({self})")
    }
}
