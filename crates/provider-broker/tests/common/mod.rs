use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use mcp_adapters::{
    FomoCapabilitiesResponse, FomoEnvelope, FomoGetTokenRequest, FomoRecentEventsRequest,
    FomoSearchTokensRequest, FomoTrendingTokensRequest, GmgnKlineRequest, GmgnMeta, GmgnResponse,
    GmgnSearchRequest, GmgnTokenRequest, GmgnTopHoldersRequest, GmgnTrendingRequest,
    McpAdapterError,
};
use provider_broker::IntelligenceProvider;

#[allow(dead_code)]
#[derive(Default)]
pub struct FakeIntelligenceProvider {
    pub call_count: AtomicUsize,
    pub fomo_search_count: AtomicUsize,
    pub gmgn_trending_count: AtomicUsize,
    pub gmgn_top_holders_count: AtomicUsize,
    pub should_fail: Mutex<Option<McpAdapterError>>,
    pub dynamic_response_seq: AtomicUsize,
}

#[allow(dead_code)]
impl FakeIntelligenceProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_failure(&self, err: McpAdapterError) {
        *self.should_fail.lock().unwrap() = Some(err);
    }

    pub fn clear_failure(&self) {
        *self.should_fail.lock().unwrap() = None;
    }
}

#[async_trait::async_trait]
impl IntelligenceProvider for FakeIntelligenceProvider {
    async fn fomo_capabilities(&self) -> Result<FomoCapabilitiesResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(FomoCapabilitiesResponse {
            tools: vec![json!({"tool": "fomo_capabilities"})],
            note: Some("verified".into()),
        })
    }

    async fn fomo_search_tokens(
        &self,
        req: FomoSearchTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.fomo_search_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        let seq = self.dynamic_response_seq.fetch_add(1, Ordering::SeqCst);
        Ok(FomoEnvelope {
            data: json!({"query": req.query, "seq": seq}),
            source: Some(json!({"provider": "fomo"})),
            freshness: None,
            coverage: None,
            warnings: vec![],
        })
    }

    async fn fomo_get_token(
        &self,
        req: FomoGetTokenRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(FomoEnvelope {
            data: json!({"address": req.token_address, "network": req.network_id}),
            source: Some(json!({"provider": "fomo"})),
            freshness: None,
            coverage: None,
            warnings: vec![],
        })
    }

    async fn fomo_get_trending_tokens(
        &self,
        req: FomoTrendingTokensRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(FomoEnvelope {
            data: json!({"list": req.list}),
            source: None,
            freshness: None,
            coverage: None,
            warnings: vec![],
        })
    }

    async fn fomo_get_recent_events(
        &self,
        _req: FomoRecentEventsRequest,
    ) -> Result<FomoEnvelope, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(FomoEnvelope {
            data: json!({"events": []}),
            source: None,
            freshness: None,
            coverage: None,
            warnings: vec![],
        })
    }

    async fn gmgn_trending(
        &self,
        req: GmgnTrendingRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.gmgn_trending_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        let seq = self.dynamic_response_seq.fetch_add(1, Ordering::SeqCst);
        Ok(GmgnResponse {
            payload: json!({
                "chain": req.chain,
                "interval": req.interval,
                "seq": seq,
            }),
            meta: Some(GmgnMeta {
                cache: Some("fresh".into()),
                upstream_request_sent: Some(true),
                upstream_status: Some(200),
                upstream_latency_ms: Some(25),
            }),
        })
    }

    async fn gmgn_search(&self, req: GmgnSearchRequest) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(GmgnResponse {
            payload: json!({"query": req.query, "chain": req.chain}),
            meta: None,
        })
    }

    async fn gmgn_token_info(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(GmgnResponse {
            payload: json!({"address": req.address, "chain": req.chain}),
            meta: None,
        })
    }

    async fn gmgn_token_security(
        &self,
        req: GmgnTokenRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(GmgnResponse {
            payload: json!({"security": "ok", "address": req.address}),
            meta: None,
        })
    }

    async fn gmgn_top_holders(
        &self,
        req: GmgnTopHoldersRequest,
    ) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.gmgn_top_holders_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(GmgnResponse {
            payload: json!({"holders": [], "address": req.address, "chain": req.chain}),
            meta: None,
        })
    }

    async fn gmgn_kline(&self, req: GmgnKlineRequest) -> Result<GmgnResponse, McpAdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self.should_fail.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(GmgnResponse {
            payload: json!({"resolution": req.resolution, "address": req.address}),
            meta: None,
        })
    }
}
