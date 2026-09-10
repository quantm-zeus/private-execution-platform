use std::sync::{Arc, Mutex};

use mcp_adapters::{
    FomoAdapter, FomoGetTokenRequest, FomoRecentEventsRequest, FomoSearchTokensRequest,
    FomoTrendingTokensRequest, GmgnAdapter, GmgnKlineRequest, GmgnSearchRequest, GmgnTokenRequest,
    GmgnTopHoldersRequest, GmgnTrendingRequest, McpServiceId, McpToolCall, McpToolResponse,
    McpTransport, McpTransportError,
};
use serde_json::json;

#[derive(Default)]
struct MockTransport {
    recorded_calls: Mutex<Vec<McpToolCall>>,
}

#[async_trait::async_trait]
impl McpTransport for MockTransport {
    async fn call_tool(&self, call: McpToolCall) -> Result<McpToolResponse, McpTransportError> {
        self.recorded_calls.lock().unwrap().push(call.clone());

        // Return a valid mock payload matching the requested tool
        let payload = match (call.service, call.tool_name.as_str()) {
            (McpServiceId::Fomo, "fomo_capabilities") => {
                json!({
                    "tools": [
                        {"tool": "fomo_capabilities", "status": "verified"},
                        {"tool": "fomo_search_tokens", "status": "verified"}
                    ],
                    "note": "verified capabilities"
                })
            }
            (McpServiceId::Fomo, _) => {
                json!({
                    "data": {"result": "fomo_ok"},
                    "source": {"provider": "fomo", "transport": "rest"},
                    "freshness": {"fetchedAt": "2026-09-10T06:00:00Z"},
                    "coverage": null,
                    "warnings": []
                })
            }
            (McpServiceId::Gmgn, _) => {
                json!({
                    "code": 0,
                    "data": {"result": "gmgn_ok"},
                    "_gmgn_meta": {
                        "cache": "fresh",
                        "upstream_request_sent": true,
                        "upstream_status": 200,
                        "upstream_latency_ms": 42
                    }
                })
            }
        };

        Ok(McpToolResponse::success(payload))
    }
}

#[tokio::test]
async fn test_fomo_capabilities_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let res = adapter
        .capabilities()
        .await
        .expect("capabilities call failed");
    assert_eq!(res.tools.len(), 2);
    assert_eq!(res.note.as_deref(), Some("verified capabilities"));

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Fomo);
    assert_eq!(calls[0].tool_name, "fomo_capabilities");
    assert_eq!(calls[0].arguments, json!({}));
}

#[tokio::test]
async fn test_fomo_search_tokens_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoSearchTokensRequest {
        query: "PEPE".to_string(),
    };
    let res = adapter
        .search_tokens(req)
        .await
        .expect("search_tokens call failed");
    assert_eq!(res.data["result"], "fomo_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Fomo);
    assert_eq!(calls[0].tool_name, "fomo_search_tokens");
    assert_eq!(calls[0].arguments, json!({"query": "PEPE"}));
}

#[tokio::test]
async fn test_fomo_get_token_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoGetTokenRequest {
        network_id: 8453,
        token_address: "0x020bfc650a365f8bb26819deaabf3e21291018b4".to_string(),
    };
    let res = adapter.get_token(req).await.expect("get_token call failed");
    assert_eq!(res.data["result"], "fomo_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Fomo);
    assert_eq!(calls[0].tool_name, "fomo_get_token");
    assert_eq!(
        calls[0].arguments,
        json!({
            "networkId": 8453,
            "tokenAddress": "0x020bfc650a365f8bb26819deaabf3e21291018b4"
        })
    );
}

#[tokio::test]
async fn test_fomo_get_trending_tokens_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoTrendingTokensRequest {
        category: Some("trending".to_string()),
        limit: Some(25),
    };
    let res = adapter
        .get_trending_tokens(req)
        .await
        .expect("get_trending_tokens call failed");
    assert_eq!(res.data["result"], "fomo_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Fomo);
    assert_eq!(calls[0].tool_name, "fomo_get_trending_tokens");
    assert_eq!(
        calls[0].arguments,
        json!({
            "category": "trending",
            "limit": 25
        })
    );
}

#[tokio::test]
async fn test_fomo_get_recent_events_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoRecentEventsRequest {
        since_minutes: Some(60),
        limit: Some(15),
        network_id: Some(1399811149),
        action: Some("buy".to_string()),
        ..Default::default()
    };
    let res = adapter
        .get_recent_events(req)
        .await
        .expect("get_recent_events call failed");
    assert_eq!(res.data["result"], "fomo_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Fomo);
    assert_eq!(calls[0].tool_name, "fomo_get_recent_events");
    assert_eq!(
        calls[0].arguments,
        json!({
            "sinceMinutes": 60,
            "limit": 15,
            "networkId": 1399811149,
            "action": "buy"
        })
    );
}

#[tokio::test]
async fn test_gmgn_trending_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnTrendingRequest {
        chain: "sol".to_string(),
        interval: "1h".to_string(),
        limit: 10,
    };
    let res = adapter.trending(req).await.expect("trending call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");
    assert!(res.meta.is_some());
    assert_eq!(res.meta.as_ref().unwrap().upstream_status, Some(200));

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_trending");
    assert_eq!(
        calls[0].arguments,
        json!({
            "chain": "sol",
            "interval": "1h",
            "limit": 10
        })
    );
}

#[tokio::test]
async fn test_gmgn_search_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnSearchRequest {
        query: "bonk".to_string(),
        chain: Some("sol".to_string()),
    };
    let res = adapter.search(req).await.expect("search call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_search");
    assert_eq!(
        calls[0].arguments,
        json!({
            "query": "bonk",
            "chain": "sol"
        })
    );
}

#[tokio::test]
async fn test_gmgn_token_info_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnTokenRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
    };
    let res = adapter
        .token_info(req)
        .await
        .expect("token_info call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_token_info");
    assert_eq!(
        calls[0].arguments,
        json!({
            "chain": "sol",
            "address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        })
    );
}

#[tokio::test]
async fn test_gmgn_token_security_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnTokenRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
    };
    let res = adapter
        .token_security(req)
        .await
        .expect("token_security call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_token_security");
    assert_eq!(
        calls[0].arguments,
        json!({
            "chain": "sol",
            "address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        })
    );
}

#[tokio::test]
async fn test_gmgn_top_holders_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnTopHoldersRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        limit: 20,
        order_by: Some("amount_percentage".to_string()),
    };
    let res = adapter
        .top_holders(req)
        .await
        .expect("top_holders call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_top_holders");
    assert_eq!(
        calls[0].arguments,
        json!({
            "chain": "sol",
            "address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
            "limit": 20,
            "order_by": "amount_percentage"
        })
    );
}

#[tokio::test]
async fn test_gmgn_kline_transport_call() {
    let transport = Arc::new(MockTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnKlineRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        resolution: "1h".to_string(),
        from: Some(1700000000),
        to: Some(1700003600),
    };
    let res = adapter.kline(req).await.expect("kline call failed");
    assert_eq!(res.payload["data"]["result"], "gmgn_ok");

    let calls = transport.recorded_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "must execute exactly one transport call");
    assert_eq!(calls[0].service, McpServiceId::Gmgn);
    assert_eq!(calls[0].tool_name, "gmgn_kline");
    assert_eq!(
        calls[0].arguments,
        json!({
            "chain": "sol",
            "address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
            "resolution": "1h",
            "from": 1700000000,
            "to": 1700003600
        })
    );
}
