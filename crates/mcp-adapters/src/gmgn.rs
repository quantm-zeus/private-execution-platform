//! Thin, read-only MCP adapter for the GMGN intelligence gateway.
//!
//! Enforces:
//! - Exact-name allowlist mapping (`gmgn_trending`, `gmgn_search`,
//!   `gmgn_token_info`, `gmgn_token_security`, `gmgn_top_holders`, `gmgn_kline`).
//! - Boundary argument validation before transport invocation (official chains only,
//!   bounded limits, strict enums, no query injection).
//! - Single transport call per logical request with zero retries.
//! - Fail-closed error mapping with no leak of secrets or payloads.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::allowlist::{AllowedTool, GmgnTool, GMGN_OFFICIAL_CHAINS};
use crate::error::McpAdapterError;
use crate::transport::{
    unpack_mcp_response, McpServiceId, McpToolCall, McpTransport, DEFAULT_MAX_RESPONSE_BYTES,
};

// ------------------------------------------------------------------ //
// CONTRACT RESPONSE SCHEMAS
// ------------------------------------------------------------------ //

/// Metadata extracted from GMGN `_gmgn_meta` header/field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GmgnMeta {
    #[serde(default)]
    pub cache: Option<String>,
    #[serde(default)]
    pub upstream_request_sent: Option<bool>,
    #[serde(default)]
    pub upstream_status: Option<u16>,
    #[serde(default)]
    pub upstream_latency_ms: Option<u64>,
}

/// Standard response returned by GMGN read-only tools.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GmgnResponse {
    pub payload: Value,
    pub meta: Option<GmgnMeta>,
}

impl GmgnResponse {
    pub fn from_value(mut val: Value) -> Self {
        let meta = if let Some(obj) = val.as_object_mut() {
            obj.remove("_gmgn_meta")
                .and_then(|m| serde_json::from_value::<GmgnMeta>(m).ok())
        } else {
            None
        };
        Self { payload: val, meta }
    }
}

// ------------------------------------------------------------------ //
// REQUEST SCHEMAS WITH BOUNDARY VALIDATION
// ------------------------------------------------------------------ //

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmgnTrendingRequest {
    pub chain: String,
    pub interval: String,
    pub limit: i64,
}

impl GmgnTrendingRequest {
    pub const ALLOWED_INTERVALS: &'static [&'static str] = &["1m", "5m", "1h", "6h", "24h"];

    pub fn validate(&self) -> Result<(String, String, i64), McpAdapterError> {
        let chain = validate_chain(&self.chain)?;
        let interval = self.interval.trim();
        if !Self::ALLOWED_INTERVALS.contains(&interval) {
            return Err(McpAdapterError::InvalidArgument { field: "interval" });
        }
        if !(1..=100).contains(&self.limit) {
            return Err(McpAdapterError::InvalidArgument { field: "limit" });
        }
        Ok((chain, interval.to_owned(), self.limit))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmgnSearchRequest {
    pub query: String,
    pub chain: Option<String>,
}

impl GmgnSearchRequest {
    pub fn validate(&self) -> Result<(String, Option<String>), McpAdapterError> {
        let query = validate_query_str(&self.query, "query")?;
        let chain = match &self.chain {
            Some(c) => Some(validate_chain(c)?),
            None => None,
        };
        Ok((query, chain))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmgnTokenRequest {
    pub chain: String,
    pub address: String,
}

impl GmgnTokenRequest {
    pub fn validate(&self) -> Result<(String, String), McpAdapterError> {
        let chain = validate_chain(&self.chain)?;
        let address = validate_address_str(&self.address)?;
        Ok((chain, address))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmgnTopHoldersRequest {
    pub chain: String,
    pub address: String,
    pub limit: i64,
    pub order_by: Option<String>,
}

impl GmgnTopHoldersRequest {
    pub const ALLOWED_ORDER_BY: &'static [&'static str] = &[
        "amount_percentage",
        "profit",
        "unrealized_profit",
        "buy_volume_cur",
        "sell_volume_cur",
    ];

    pub fn validate(&self) -> Result<(String, String, i64, Option<String>), McpAdapterError> {
        let chain = validate_chain(&self.chain)?;
        let address = validate_address_str(&self.address)?;
        if !(1..=100).contains(&self.limit) {
            return Err(McpAdapterError::InvalidArgument { field: "limit" });
        }
        let order_by = match &self.order_by {
            Some(ob) => {
                let trimmed = ob.trim();
                if !Self::ALLOWED_ORDER_BY.contains(&trimmed) {
                    return Err(McpAdapterError::InvalidArgument { field: "order_by" });
                }
                Some(trimmed.to_owned())
            }
            None => None,
        };
        Ok((chain, address, self.limit, order_by))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GmgnKlineRequest {
    pub chain: String,
    pub address: String,
    pub resolution: String,
    pub from: Option<i64>,
    pub to: Option<i64>,
}
/// Validated parameters for a GMGN Kline request: `(chain, address, resolution, from, to)`.
pub type ValidatedKlineParams = (String, String, String, Option<i64>, Option<i64>);

impl GmgnKlineRequest {
    pub const ALLOWED_RESOLUTIONS: &'static [&'static str] =
        &["30s", "1m", "5m", "15m", "1h", "4h", "1d"];

    pub fn validate(&self) -> Result<ValidatedKlineParams, McpAdapterError> {
        let chain = validate_chain(&self.chain)?;
        let address = validate_address_str(&self.address)?;
        let res = self.resolution.trim();
        if !Self::ALLOWED_RESOLUTIONS.contains(&res) {
            return Err(McpAdapterError::InvalidArgument {
                field: "resolution",
            });
        }
        if let Some(f) = self.from {
            if f <= 0 {
                return Err(McpAdapterError::InvalidArgument { field: "from" });
            }
        }
        if let Some(t) = self.to {
            if t <= 0 {
                return Err(McpAdapterError::InvalidArgument { field: "to" });
            }
            if let Some(f) = self.from {
                if t < f {
                    return Err(McpAdapterError::InvalidArgument { field: "to" });
                }
            }
        }
        Ok((chain, address, res.to_owned(), self.from, self.to))
    }
}

// ------------------------------------------------------------------ //
// VALIDATION HELPERS
// ------------------------------------------------------------------ //

fn validate_chain(chain: &str) -> Result<String, McpAdapterError> {
    let trimmed = chain.trim();
    if GMGN_OFFICIAL_CHAINS.contains(&trimmed) {
        Ok(trimmed.to_owned())
    } else {
        Err(McpAdapterError::InvalidArgument { field: "chain" })
    }
}

fn validate_query_str(query: &str, field: &'static str) -> Result<String, McpAdapterError> {
    let trimmed = query.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
        return Err(McpAdapterError::InvalidArgument { field });
    }
    Ok(trimmed.to_owned())
}

fn validate_address_str(address: &str) -> Result<String, McpAdapterError> {
    let trimmed = address.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '&' | '/' | '?' | '#' | '='))
    {
        return Err(McpAdapterError::InvalidArgument { field: "address" });
    }
    Ok(trimmed.to_owned())
}

// ------------------------------------------------------------------ //
// GMGN ADAPTER
// ------------------------------------------------------------------ //

pub struct GmgnAdapter<T: McpTransport> {
    transport: Arc<T>,
    max_response_bytes: usize,
}

impl<T: McpTransport> GmgnAdapter<T> {
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

    /// Calls `gmgn_trending`. Boundary validated before transport call.
    pub async fn trending(
        &self,
        req: GmgnTrendingRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        let (chain, interval, limit) = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Gmgn(GmgnTool::Trending),
            json!({
                "chain": chain,
                "interval": interval,
                "limit": limit,
            }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }

    /// Calls `gmgn_search`. Boundary validated before transport call.
    pub async fn search(&self, req: GmgnSearchRequest) -> Result<GmgnResponse, McpAdapterError> {
        let (query, chain) = req.validate()?;
        let mut map = serde_json::Map::new();
        map.insert("query".into(), json!(query));
        if let Some(c) = chain {
            map.insert("chain".into(), json!(c));
        }

        let call = McpToolCall::new(AllowedTool::Gmgn(GmgnTool::Search), Value::Object(map));

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }

    /// Calls `gmgn_token_info`. Boundary validated before transport call.
    pub async fn token_info(&self, req: GmgnTokenRequest) -> Result<GmgnResponse, McpAdapterError> {
        let (chain, address) = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Gmgn(GmgnTool::TokenInfo),
            json!({
                "chain": chain,
                "address": address,
            }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }

    /// Calls `gmgn_token_security`. Boundary validated before transport call.
    pub async fn token_security(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        let (chain, address) = req.validate()?;
        let call = McpToolCall::new(
            AllowedTool::Gmgn(GmgnTool::TokenSecurity),
            json!({
                "chain": chain,
                "address": address,
            }),
        );

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }

    /// Calls `gmgn_top_holders`. Boundary validated before transport call.
    pub async fn top_holders(
        &self,
        req: GmgnTopHoldersRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        let (chain, address, limit, order_by) = req.validate()?;
        let mut map = serde_json::Map::new();
        map.insert("chain".into(), json!(chain));
        map.insert("address".into(), json!(address));
        map.insert("limit".into(), json!(limit));
        if let Some(ob) = order_by {
            map.insert("order_by".into(), json!(ob));
        }

        let call = McpToolCall::new(AllowedTool::Gmgn(GmgnTool::TopHolders), Value::Object(map));

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }

    /// Calls `gmgn_kline`. Boundary validated before transport call.
    pub async fn kline(&self, req: GmgnKlineRequest) -> Result<GmgnResponse, McpAdapterError> {
        let (chain, address, resolution, from, to) = req.validate()?;
        let mut map = serde_json::Map::new();
        map.insert("chain".into(), json!(chain));
        map.insert("address".into(), json!(address));
        map.insert("resolution".into(), json!(resolution));
        if let Some(f) = from {
            map.insert("from".into(), json!(f));
        }
        if let Some(t) = to {
            map.insert("to".into(), json!(t));
        }

        let call = McpToolCall::new(AllowedTool::Gmgn(GmgnTool::Kline), Value::Object(map));

        let response = self
            .transport
            .call_tool(call)
            .await
            .map_err(|e| e.into_adapter_error(McpServiceId::Gmgn))?;

        let value = unpack_mcp_response(response, McpServiceId::Gmgn, self.max_response_bytes)?;
        Ok(GmgnResponse::from_value(value))
    }
}
