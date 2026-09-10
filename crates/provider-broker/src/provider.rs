//! Injected typed provider trait and bridge to typed `mcp-adapters`.
//!
//! Enforces:
//! - Exclusive reliance on typed adapter methods.
//! - Read-only allowlist preservation.
//! - Exactly zero generic tool call strings or unvalidated transport calls.
//! - Exactly one transport invocation per logical call; zero automatic retries.

use std::sync::Arc;

use mcp_adapters::{
    FomoAdapter, FomoCapabilitiesResponse, FomoEnvelope, FomoGetTokenRequest,
    FomoRecentEventsRequest, FomoSearchTokensRequest, FomoTrendingTokensRequest, GmgnAdapter,
    GmgnKlineRequest, GmgnResponse, GmgnSearchRequest, GmgnTokenRequest, GmgnTopHoldersRequest,
    GmgnTrendingRequest, McpAdapterError, McpTransport,
};

/// Abstract typed provider boundary for intelligence queries.
#[async_trait::async_trait]
pub trait IntelligenceProvider: Send + Sync + 'static {
    // FOMO methods
    async fn fomo_capabilities(&self) -> Result<FomoCapabilitiesResponse, McpAdapterError>;
    async fn fomo_search_tokens(
        &self,
        req: FomoSearchTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError>;
    async fn fomo_get_token(
        &self,
        req: FomoGetTokenRequest,
    ) -> Result<FomoEnvelope, McpAdapterError>;
    async fn fomo_get_trending_tokens(
        &self,
        req: FomoTrendingTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError>;
    async fn fomo_get_recent_events(
        &self,
        req: FomoRecentEventsRequest,
    ) -> Result<FomoEnvelope, McpAdapterError>;

    // GMGN methods
    async fn gmgn_trending(
        &self,
        req: GmgnTrendingRequest,
    ) -> Result<GmgnResponse, McpAdapterError>;
    async fn gmgn_search(&self, req: GmgnSearchRequest) -> Result<GmgnResponse, McpAdapterError>;
    async fn gmgn_token_info(&self, req: GmgnTokenRequest)
        -> Result<GmgnResponse, McpAdapterError>;
    async fn gmgn_token_security(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError>;
    async fn gmgn_top_holders(
        &self,
        req: GmgnTopHoldersRequest,
    ) -> Result<GmgnResponse, McpAdapterError>;
    async fn gmgn_kline(&self, req: GmgnKlineRequest) -> Result<GmgnResponse, McpAdapterError>;
}

/// Typed bridge connecting `IntelligenceProvider` to landed `mcp-adapters`.
///
/// Strictly routes through public typed methods of [`FomoAdapter`] and [`GmgnAdapter`],
/// preserving argument validation, schema enforcement, and zero-retry invariants.
pub struct McpAdapterBridge<T: McpTransport> {
    fomo: FomoAdapter<T>,
    gmgn: GmgnAdapter<T>,
}

impl<T: McpTransport> McpAdapterBridge<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            fomo: FomoAdapter::new(transport.clone()),
            gmgn: GmgnAdapter::new(transport),
        }
    }

    pub fn with_max_response_bytes(transport: Arc<T>, max_bytes: usize) -> Self {
        Self {
            fomo: FomoAdapter::new(transport.clone()).with_max_response_bytes(max_bytes),
            gmgn: GmgnAdapter::new(transport).with_max_response_bytes(max_bytes),
        }
    }
}

#[async_trait::async_trait]
impl<T: McpTransport + 'static> IntelligenceProvider for McpAdapterBridge<T> {
    async fn fomo_capabilities(&self) -> Result<FomoCapabilitiesResponse, McpAdapterError> {
        self.fomo.capabilities().await
    }

    async fn fomo_search_tokens(
        &self,
        req: FomoSearchTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.fomo.search_tokens(req).await
    }

    async fn fomo_get_token(
        &self,
        req: FomoGetTokenRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.fomo.get_token(req).await
    }

    async fn fomo_get_trending_tokens(
        &self,
        req: FomoTrendingTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.fomo.get_trending_tokens(req).await
    }

    async fn fomo_get_recent_events(
        &self,
        req: FomoRecentEventsRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.fomo.get_recent_events(req).await
    }

    async fn gmgn_trending(
        &self,
        req: GmgnTrendingRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.trending(req).await
    }

    async fn gmgn_search(&self, req: GmgnSearchRequest) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.search(req).await
    }

    async fn gmgn_token_info(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.token_info(req).await
    }

    async fn gmgn_token_security(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.token_security(req).await
    }

    async fn gmgn_top_holders(
        &self,
        req: GmgnTopHoldersRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.top_holders(req).await
    }

    async fn gmgn_kline(&self, req: GmgnKlineRequest) -> Result<GmgnResponse, McpAdapterError> {
        self.gmgn.kline(req).await
    }
}
