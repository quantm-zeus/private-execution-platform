//! # Thin Read-Only FOMO / GMGN MCP Adapters
//!
//! Internal adapter boundary connecting the platform to the existing, read-only
//! FOMO and GMGN MCP services.
//!
//! ## Architectural Boundaries
//! - Strictly calls an injected [`McpTransport`].
//! - Zero external networking, HTTP client, WebSocket client, or direct upstream code.
//! - Exact-name allowlist mapping for declared read-only operations.
//! - Defense-in-depth argument validation at the adapter boundary before transport invocation.
//! - Fail-closed error taxonomy ensuring zero secret, endpoint, credential, or raw payload leakage.
//! - At most one transport call per logical request; no automatic retries.
//! - Global trading capability is strictly disabled (`TRADING_ENABLED = false`).

pub mod allowlist;
pub mod error;
pub mod fomo;
pub mod gmgn;
pub mod transport;

pub use allowlist::{
    is_disallowed_operation, validate_tool_allowlist, AllowedTool, FomoTool, GmgnTool,
    FOMO_TOOL_CAPABILITIES, FOMO_TOOL_GET_RECENT_EVENTS, FOMO_TOOL_GET_TOKEN,
    FOMO_TOOL_GET_TRENDING_TOKENS, FOMO_TOOL_SEARCH_TOKENS, GMGN_OFFICIAL_CHAINS, GMGN_TOOL_KLINE,
    GMGN_TOOL_SEARCH, GMGN_TOOL_TOKEN_INFO, GMGN_TOOL_TOKEN_SECURITY, GMGN_TOOL_TOP_HOLDERS,
    GMGN_TOOL_TRENDING,
};
pub use error::McpAdapterError;
pub use fomo::{
    FomoAdapter, FomoCapabilitiesResponse, FomoEnvelope, FomoGetTokenRequest,
    FomoRecentEventsRequest, FomoSearchTokensRequest, FomoTrendingTokensRequest,
    FOMO_TRENDING_LISTS,
};
pub use gmgn::{
    GmgnAdapter, GmgnKlineRequest, GmgnMeta, GmgnResponse, GmgnSearchRequest, GmgnTokenRequest,
    GmgnTopHoldersRequest, GmgnTrendingRequest,
};
pub use transport::{
    McpServiceId, McpToolCall, McpToolResponse, McpTransport, McpTransportError,
    DEFAULT_MAX_RESPONSE_BYTES,
};

/// Global fail-closed invariant: this adapter boundary never possesses or permits trading capabilities.
pub const TRADING_ENABLED: bool = false;
