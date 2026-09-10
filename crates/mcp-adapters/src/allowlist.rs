//! Exact declared service tool allowlist mapping.
//!
//! Exposes ONLY the intentionally narrow, read-only subset documented by the
//! committed contracts. Prohibits any diagnostics, probe, mutation, trade,
//! signing, credential, or configuration operations.

use crate::error::McpAdapterError;
use crate::transport::McpServiceId;

// ------------------------------------------------------------------ //
// EXACT DECLARED WIRE TOOL NAMES
// ------------------------------------------------------------------ //

pub const FOMO_TOOL_CAPABILITIES: &str = "fomo_capabilities";
pub const FOMO_TOOL_SEARCH_TOKENS: &str = "fomo_search_tokens";
pub const FOMO_TOOL_GET_TOKEN: &str = "fomo_get_token";
pub const FOMO_TOOL_GET_TRENDING_TOKENS: &str = "fomo_get_trending_tokens";
pub const FOMO_TOOL_GET_RECENT_EVENTS: &str = "fomo_get_recent_events";

pub const GMGN_TOOL_TRENDING: &str = "gmgn_trending";
pub const GMGN_TOOL_SEARCH: &str = "gmgn_search";
pub const GMGN_TOOL_TOKEN_INFO: &str = "gmgn_token_info";
pub const GMGN_TOOL_TOKEN_SECURITY: &str = "gmgn_token_security";
pub const GMGN_TOOL_TOP_HOLDERS: &str = "gmgn_top_holders";
pub const GMGN_TOOL_KLINE: &str = "gmgn_kline";

/// The official supported GMGN chains. Case-sensitive, no aliases.
pub const GMGN_OFFICIAL_CHAINS: &[&str] =
    &["sol", "bsc", "base", "eth", "robinhood", "arc", "stable"];

/// Enumeration of permitted FOMO tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FomoTool {
    Capabilities,
    SearchTokens,
    GetToken,
    GetTrendingTokens,
    GetRecentEvents,
}

impl FomoTool {
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Capabilities => FOMO_TOOL_CAPABILITIES,
            Self::SearchTokens => FOMO_TOOL_SEARCH_TOKENS,
            Self::GetToken => FOMO_TOOL_GET_TOKEN,
            Self::GetTrendingTokens => FOMO_TOOL_GET_TRENDING_TOKENS,
            Self::GetRecentEvents => FOMO_TOOL_GET_RECENT_EVENTS,
        }
    }
}

/// Enumeration of permitted GMGN tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GmgnTool {
    Trending,
    Search,
    TokenInfo,
    TokenSecurity,
    TopHolders,
    Kline,
}

impl GmgnTool {
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Trending => GMGN_TOOL_TRENDING,
            Self::Search => GMGN_TOOL_SEARCH,
            Self::TokenInfo => GMGN_TOOL_TOKEN_INFO,
            Self::TokenSecurity => GMGN_TOOL_TOKEN_SECURITY,
            Self::TopHolders => GMGN_TOOL_TOP_HOLDERS,
            Self::Kline => GMGN_TOOL_KLINE,
        }
    }
}

/// Unified allowlisted tool descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllowedTool {
    Fomo(FomoTool),
    Gmgn(GmgnTool),
}

impl AllowedTool {
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Fomo(tool) => tool.wire_name(),
            Self::Gmgn(tool) => tool.wire_name(),
        }
    }

    pub const fn service(&self) -> McpServiceId {
        match self {
            Self::Fomo(_) => McpServiceId::Fomo,
            Self::Gmgn(_) => McpServiceId::Gmgn,
        }
    }

    /// Validates an untrusted tool name against the declared allowlist for the service.
    pub fn try_from_name(service: McpServiceId, tool_name: &str) -> Result<Self, McpAdapterError> {
        validate_tool_allowlist(service, tool_name)
    }
}

/// Checks if an operation string indicates a mutation, trade, probe, or disallowed capability.
pub fn is_disallowed_operation(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    // Prohibit probes/diagnostics, trading, mutations, signing, and credentials
    lower.contains("diagnostic")
        || lower.contains("probe")
        || lower.contains("trade")
        || lower.contains("buy")
        || lower.contains("sell")
        || lower.contains("swap")
        || lower.contains("sign")
        || lower.contains("wallet_resolve")
        || lower.contains("resolve_wallet")
        || lower.contains("transfer")
        || lower.contains("mutate")
        || lower.contains("write")
        || lower.contains("delete")
        || lower.contains("config")
        || lower.contains("auth")
        || lower.contains("secret")
        || lower.contains("token_key")
        || lower.contains("admin")
}

/// Validates that the requested tool name is in the exact declared allowlist for the given service.
pub fn validate_tool_allowlist(
    service: McpServiceId,
    tool_name: &str,
) -> Result<AllowedTool, McpAdapterError> {
    if is_disallowed_operation(tool_name) {
        return Err(McpAdapterError::DisallowedOperation);
    }

    match service {
        McpServiceId::Fomo => match tool_name {
            FOMO_TOOL_CAPABILITIES => Ok(AllowedTool::Fomo(FomoTool::Capabilities)),
            FOMO_TOOL_SEARCH_TOKENS => Ok(AllowedTool::Fomo(FomoTool::SearchTokens)),
            FOMO_TOOL_GET_TOKEN => Ok(AllowedTool::Fomo(FomoTool::GetToken)),
            FOMO_TOOL_GET_TRENDING_TOKENS => Ok(AllowedTool::Fomo(FomoTool::GetTrendingTokens)),
            FOMO_TOOL_GET_RECENT_EVENTS => Ok(AllowedTool::Fomo(FomoTool::GetRecentEvents)),
            _ => Err(McpAdapterError::UnsupportedTool {
                tool: "unsupported fomo tool",
            }),
        },
        McpServiceId::Gmgn => match tool_name {
            GMGN_TOOL_TRENDING => Ok(AllowedTool::Gmgn(GmgnTool::Trending)),
            GMGN_TOOL_SEARCH => Ok(AllowedTool::Gmgn(GmgnTool::Search)),
            GMGN_TOOL_TOKEN_INFO => Ok(AllowedTool::Gmgn(GmgnTool::TokenInfo)),
            GMGN_TOOL_TOKEN_SECURITY => Ok(AllowedTool::Gmgn(GmgnTool::TokenSecurity)),
            GMGN_TOOL_TOP_HOLDERS => Ok(AllowedTool::Gmgn(GmgnTool::TopHolders)),
            GMGN_TOOL_KLINE => Ok(AllowedTool::Gmgn(GmgnTool::Kline)),
            _ => Err(McpAdapterError::UnsupportedTool {
                tool: "unsupported gmgn tool",
            }),
        },
    }
}
