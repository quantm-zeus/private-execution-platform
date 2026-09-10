//! Narrow injected/mockable MCP service transport boundary.
//!
//! Enforces:
//! - Typed service identity (`McpServiceId::Fomo` | `McpServiceId::Gmgn`).
//! - No generic arbitrary-tool string escape hatches.
//! - Redacted Debug implementations for request arguments and response payloads.
//! - Strict bounded payload validation (fail-closed on oversized or malformed data).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

use crate::error::McpAdapterError;

/// Maximum payload size allowed for MCP tool responses (1 MiB default limit).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Strongly typed MCP service identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpServiceId {
    Fomo,
    Gmgn,
}

impl McpServiceId {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fomo => "fomo",
            Self::Gmgn => "gmgn",
        }
    }
}

impl fmt::Display for McpServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for McpServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "McpServiceId({})", self.as_str())
    }
}

/// A validated logical MCP tool call sent to the transport.
#[derive(Clone, PartialEq, Eq)]
pub struct McpToolCall {
    pub service: McpServiceId,
    pub tool_name: String,
    pub arguments: Value,
}

impl fmt::Debug for McpToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted debug representation: never leak request payload or arguments.
        f.debug_struct("McpToolCall")
            .field("service", &self.service)
            .field("tool_name", &self.tool_name)
            .field("arguments", &"[REDACTED]")
            .finish()
    }
}

/// Raw tool response returned from transport before adapter unpacking.
#[derive(Clone, PartialEq, Eq)]
pub struct McpToolResponse {
    pub is_error: bool,
    pub payload: Value,
}

impl McpToolResponse {
    /// Creates a success response with a structured JSON payload.
    pub fn success(payload: Value) -> Self {
        Self {
            is_error: false,
            payload,
        }
    }

    /// Creates an error response.
    pub fn error(payload: Value) -> Self {
        Self {
            is_error: true,
            payload,
        }
    }
}

impl fmt::Debug for McpToolResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted debug representation: never leak response payload.
        f.debug_struct("McpToolResponse")
            .field("is_error", &self.is_error)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Low-level transport errors that map fail-closed to `McpAdapterError`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum McpTransportError {
    Unavailable,
    Failed,
    Timeout,
}

impl fmt::Display for McpTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "mcp transport unavailable"),
            Self::Failed => write!(f, "mcp transport call failed"),
            Self::Timeout => write!(f, "mcp transport timed out"),
        }
    }
}

impl fmt::Debug for McpTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "McpTransportError({self})")
    }
}

impl McpTransportError {
    pub fn into_adapter_error(self, service: McpServiceId) -> McpAdapterError {
        match self {
            Self::Unavailable => McpAdapterError::ServiceUnavailable { service },
            Self::Failed | Self::Timeout => McpAdapterError::TransportFailure { service },
        }
    }
}

/// Injected mockable MCP service transport trait.
#[async_trait::async_trait]
pub trait McpTransport: Send + Sync {
    /// Dispatches a validated MCP tool call to the underlying service.
    ///
    /// Implementations must execute at most one physical call per invocation
    /// with no automatic retry.
    async fn call_tool(&self, call: McpToolCall) -> Result<McpToolResponse, McpTransportError>;
}

/// Unpacks and validates a response payload with strict bounds and schema checks.
pub fn unpack_mcp_response(
    response: McpToolResponse,
    service: McpServiceId,
    max_bytes: usize,
) -> Result<Value, McpAdapterError> {
    if response.is_error {
        return Err(McpAdapterError::ToolExecutionFailed { service });
    }

    // Inspect if payload is wrapped in MCP content blocks: {"content": [{"type": "text", "text": "..."}]}
    let extracted_value =
        if let Some(content_array) = response.payload.get("content").and_then(Value::as_array) {
            let mut combined_text = String::new();
            for block in content_array {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    combined_text.push_str(text);
                }
            }
            if combined_text.is_empty() {
                // Check if there's a structured block or fallback to raw payload
                if let Some(structured) = response.payload.get("structured") {
                    structured.clone()
                } else {
                    response.payload
                }
            } else {
                if combined_text.len() > max_bytes {
                    return Err(McpAdapterError::OversizedResponse { service });
                }
                serde_json::from_str::<Value>(&combined_text)
                    .map_err(|_| McpAdapterError::MalformedResponse { service })?
            }
        } else if let Some(structured) = response.payload.get("structured") {
            structured.clone()
        } else {
            response.payload
        };

    // Verify response size bounds on the extracted JSON
    let serialized_len = serde_json::to_vec(&extracted_value)
        .map_err(|_| McpAdapterError::MalformedResponse { service })?
        .len();
    if serialized_len > max_bytes {
        return Err(McpAdapterError::OversizedResponse { service });
    }

    // Detect server-side structured failures embedded in 200/normal results
    if let Some(obj) = extracted_value.as_object() {
        if obj.get("isError").and_then(Value::as_bool) == Some(true)
            || obj.get("is_error").and_then(Value::as_bool) == Some(true)
            || obj.get("ok").and_then(Value::as_bool) == Some(false)
        {
            return Err(McpAdapterError::ToolExecutionFailed { service });
        }
    }

    Ok(extracted_value)
}
