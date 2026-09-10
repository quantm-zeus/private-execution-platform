//! Thin, read-only MCP adapter for the FOMO intelligence service.
//!
//! Enforces:
//! - Exact-name allowlist mapping (`fomo_capabilities`, `fomo_search_tokens`,
//!   `fomo_get_token`, `fomo_get_trending_tokens`, `fomo_get_recent_events`).
//! - Boundary argument validation before transport invocation.
//! - Single transport call per logical request with zero retries.
//! - Fail-closed error mapping with no leak of secrets or payloads.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::allowlist::{AllowedTool, FomoTool};
use crate::error::McpAdapterError;
use crate::transport::{
    unpack_mcp_response, McpServiceId, McpToolCall, McpTransport, DEFAULT_MAX_RESPONSE_BYTES,
};

// ------------------------------------------------------------------ //
// CONTRACT RESPONSE SCHEMAS
// ------------------------------------------------------------------ //

/// Standard envelope returned by all FOMO data tools.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FomoEnvelope {
    pub data: Value,
    #[serde(default)]
    pub source: Option<Value>,
    #[serde(default)]
    pub freshness: Option<Value>,
    #[serde(default)]
    pub coverage: Option<Value>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Response returned by `fomo_capabilities`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FomoCapabilitiesResponse {
    pub tools: Vec<Value>,
    #[serde(default)]
    pub note: Option<String>,
}

// ------------------------------------------------------------------ //
// REQUEST SCHEMAS WITH BOUNDARY VALIDATION
// ------------------------------------------------------------------ //

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FomoSearchTokensRequest {
    pub query: String,
}

impl FomoSearchTokensRequest {
    pub fn validate(&self) -> Result<String, McpAdapterError> {
        let trimmed = self.query.trim();
        if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
            return Err(McpAdapterError::InvalidArgument { field: "query" });
        }
        Ok(trimmed.to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FomoGetTokenRequest {
    pub network_id: i64,
    pub token_address: String,
}

impl FomoGetTokenRequest {
    pub fn validate(&self) -> Result<(i64, String), McpAdapterError> {
        let network_id = validate_network_id(self.network_id)?;
        let address = validate_token_address(&self.token_address)?;
        Ok((network_id, address))
    }
}

/// Documented FOMO trending lists: trendingTokens, mostHeld, graduatedTokens, cryptoTokens, verifiedTokens.
pub const FOMO_TRENDING_LISTS: &[&str] = &[
    "trendingTokens",
    "mostHeld",
    "graduatedTokens",
    "cryptoTokens",
    "verifiedTokens",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FomoTrendingTokensRequest {
    pub list: String,
}

impl FomoTrendingTokensRequest {
    pub fn validate(&self) -> Result<String, McpAdapterError> {
        let trimmed = self.list.trim();
        if !FOMO_TRENDING_LISTS.contains(&trimmed) {
            return Err(McpAdapterError::InvalidArgument { field: "list" });
        }
        Ok(trimmed.to_owned())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FomoRecentEventsRequest {
    pub since_minutes: Option<i64>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub action: Option<String>,
    pub user_handle: Option<String>,
    pub user_id: Option<String>,
    pub network_id: Option<i64>,
    pub token_address: Option<String>,
    pub min_usd: Option<f64>,
    pub limit: Option<i64>,
}

impl FomoRecentEventsRequest {
    pub fn validate(&self) -> Result<Value, McpAdapterError> {
        let mut map = serde_json::Map::new();

        if let Some(m) = self.since_minutes {
            if m <= 0 || m > 10080 {
                return Err(McpAdapterError::InvalidArgument {
                    field: "since_minutes",
                });
            }
            map.insert("sinceMinutes".into(), json!(m));
        }

        if let Some(s) = &self.since {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed.len() > 64 {
                return Err(McpAdapterError::InvalidArgument { field: "since" });
            }
            map.insert("since".into(), json!(trimmed));
        }

        if let Some(u) = &self.until {
            let trimmed = u.trim();
            if trimmed.is_empty() || trimmed.len() > 64 {
                return Err(McpAdapterError::InvalidArgument { field: "until" });
            }
            map.insert("until".into(), json!(trimmed));
        }

        if let Some(a) = &self.action {
            let trimmed = a.trim();
            if trimmed.is_empty() || trimmed.len() > 32 {
                return Err(McpAdapterError::InvalidArgument { field: "action" });
            }
            map.insert("action".into(), json!(trimmed));
        }

        if let Some(h) = &self.user_handle {
            let handle = validate_handle(h)?;
            map.insert("userHandle".into(), json!(handle));
        }

        if let Some(uid) = &self.user_id {
            let trimmed = uid.trim();
            if trimmed.is_empty() || trimmed.len() > 64 {
                return Err(McpAdapterError::InvalidArgument { field: "user_id" });
            }
            map.insert("userId".into(), json!(trimmed));
        }

        if let Some(nid) = self.network_id {
            let valid_nid = validate_network_id(nid)?;
            map.insert("networkId".into(), json!(valid_nid));
        }

        if let Some(addr) = &self.token_address {
            let valid_addr = validate_token_address(addr)?;
            map.insert("tokenAddress".into(), json!(valid_addr));
        }

        if let Some(usd) = self.min_usd {
            if !usd.is_finite() || usd < 0.0 {
                return Err(McpAdapterError::InvalidArgument { field: "min_usd" });
            }
            map.insert("minUsd".into(), json!(usd));
        }

        if let Some(lim) = self.limit {
            if !(1..=100).contains(&lim) {
                return Err(McpAdapterError::InvalidArgument { field: "limit" });
            }
            map.insert("limit".into(), json!(lim));
        }

        Ok(Value::Object(map))
    }
}

// ------------------------------------------------------------------ //
// BOUNDARY VALIDATION HELPERS (matching FOMO contract)
// ------------------------------------------------------------------ //

pub fn validate_network_id(network_id: i64) -> Result<i64, McpAdapterError> {
    if network_id > 0 && network_id < i64::from(u32::MAX) {
        Ok(network_id)
    } else {
        Err(McpAdapterError::InvalidArgument {
            field: "network_id",
        })
    }
}

pub fn validate_token_address(address: &str) -> Result<String, McpAdapterError> {
    let trimmed = address.trim();
    let is_evm = trimmed.starts_with("0x")
        && trimmed.len() == 42
        && trimmed[2..].chars().all(|c| c.is_ascii_hexdigit());
    let is_base58 = (32..=44).contains(&trimmed.len())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'));
    if is_evm || is_base58 {
        Ok(trimmed.to_owned())
    } else {
        Err(McpAdapterError::InvalidArgument {
            field: "token_address",
        })
    }
}

pub fn validate_handle(handle: &str) -> Result<String, McpAdapterError> {
    let trimmed = handle.trim().trim_start_matches('@');
    if trimmed.is_empty()
        || trimmed.len() > 32
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(McpAdapterError::InvalidArgument {
            field: "user_handle",
        });
    }
    Ok(trimmed.to_owned())
}

// ------------------------------------------------------------------ //
// FOMO ADAPTER
// ------------------------------------------------------------------ //

pub struct FomoAdapter<T: McpTransport> {
    transport: Arc<T>,
    max_response_bytes: usize,
}

impl<T: McpTransport> FomoAdapter<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            transport,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn with_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_bytes = max_bytes;
        self
    }

    /// Calls `fomo_capabilities`. Exactly one transport call, zero retries.
    pub async fn capabilities(&self) -> Result<FomoCapabilitiesResponse, McpAdapterError> {
        let call = McpToolCall::new(AllowedTool::Fomo(FomoTool::Capabilities), json!({}));

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Fomo))?;

        let value = unpack_mcp_response(response, McpServiceId::Fomo, self.max_response_bytes)?;
        serde_json::from_value::<FomoCapabilitiesResponse>(value).map_err(|_| {
            McpAdapterError::MalformedResponse {
                service: McpServiceId::Fomo,
            }
        })
    }

    /// Calls `fomo_search_tokens`. Boundary validated before transport call.
    pub async fn search_tokens(
        &self,
        req: FomoSearchTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        let query = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Fomo(FomoTool::SearchTokens),
            json!({ "query": query }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Fomo))?;

        let value = unpack_mcp_response(response, McpServiceId::Fomo, self.max_response_bytes)?;
        serde_json::from_value::<FomoEnvelope>(value).map_err(|_| {
            McpAdapterError::MalformedResponse {
                service: McpServiceId::Fomo,
            }
        })
    }

    /// Calls `fomo_get_token`. Boundary validated before transport call.
    pub async fn get_token(
        &self,
        req: FomoGetTokenRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        let (network_id, address) = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Fomo(FomoTool::GetToken),
            json!({
                "networkId": network_id,
                "tokenAddress": address,
            }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Fomo))?;

        let value = unpack_mcp_response(response, McpServiceId::Fomo, self.max_response_bytes)?;
        serde_json::from_value::<FomoEnvelope>(value).map_err(|_| {
            McpAdapterError::MalformedResponse {
                service: McpServiceId::Fomo,
            }
        })
    }

    /// Calls `fomo_get_trending_tokens`. Boundary validated before transport call.
    pub async fn get_trending_tokens(
        &self,
        req: FomoTrendingTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        let list = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Fomo(FomoTool::GetTrendingTokens),
            json!({ "list": list }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Fomo))?;

        let value = unpack_mcp_response(response, McpServiceId::Fomo, self.max_response_bytes)?;
        serde_json::from_value::<FomoEnvelope>(value).map_err(|_| {
            McpAdapterError::MalformedResponse {
                service: McpServiceId::Fomo,
            }
        })
    }

    /// Calls `fomo_get_recent_events`. Boundary validated before transport call.
    pub async fn get_recent_events(
        &self,
        req: FomoRecentEventsRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        let arguments = req.validate()?;
        let call = McpToolCall::new(AllowedTool::Fomo(FomoTool::GetRecentEvents), arguments);

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Fomo))?;

        let value = unpack_mcp_response(response, McpServiceId::Fomo, self.max_response_bytes)?;
        serde_json::from_value::<FomoEnvelope>(value).map_err(|_| {
            McpAdapterError::MalformedResponse {
                service: McpServiceId::Fomo,
            }
        })
    }
}
