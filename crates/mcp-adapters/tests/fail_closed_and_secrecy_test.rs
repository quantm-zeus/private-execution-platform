use std::sync::Arc;

use mcp_adapters::{
    FomoAdapter, FomoSearchTokensRequest, GmgnAdapter, GmgnSearchRequest, McpAdapterError,
    McpServiceId, McpToolCall, McpToolResponse, McpTransport, McpTransportError,
};
use serde_json::json;

struct DynamicTransport {
    response: Result<McpToolResponse, McpTransportError>,
}

#[async_trait::async_trait]
impl McpTransport for DynamicTransport {
    async fn call_tool(&self, _call: McpToolCall) -> Result<McpToolResponse, McpTransportError> {
        self.response.clone()
    }
}

#[tokio::test]
async fn test_transport_unavailable_maps_to_service_unavailable() {
    let transport = Arc::new(DynamicTransport {
        response: Err(McpTransportError::Unavailable),
    });
    let adapter = FomoAdapter::new(transport);

    let err = adapter
        .search_tokens(FomoSearchTokensRequest {
            query: "TOKEN".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::ServiceUnavailable {
            service: McpServiceId::Fomo
        }
    );
}

#[tokio::test]
async fn test_transport_failure_maps_to_transport_failure() {
    let transport = Arc::new(DynamicTransport {
        response: Err(McpTransportError::Failed),
    });
    let adapter = GmgnAdapter::new(transport);

    let err = adapter
        .search(GmgnSearchRequest {
            query: "TOKEN".to_string(),
            chain: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::TransportFailure {
            service: McpServiceId::Gmgn
        }
    );
}

#[tokio::test]
async fn test_tool_is_error_flag_maps_to_tool_execution_failed() {
    let transport = Arc::new(DynamicTransport {
        response: Ok(McpToolResponse::error(json!({
            "error_detail": "sensitive internal exception in upstream service"
        }))),
    });
    let adapter = FomoAdapter::new(transport);

    let err = adapter
        .search_tokens(FomoSearchTokensRequest {
            query: "TOKEN".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::ToolExecutionFailed {
            service: McpServiceId::Fomo
        }
    );
}

#[tokio::test]
async fn test_tool_embedded_failure_maps_to_tool_execution_failed() {
    let transport = Arc::new(DynamicTransport {
        response: Ok(McpToolResponse::success(json!({
            "ok": false,
            "kind": "rate_limited",
            "message": "upstream rate limit exceeded"
        }))),
    });
    let adapter = GmgnAdapter::new(transport);

    let err = adapter
        .search(GmgnSearchRequest {
            query: "TOKEN".to_string(),
            chain: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::ToolExecutionFailed {
            service: McpServiceId::Gmgn
        }
    );
}

#[tokio::test]
async fn test_malformed_response_maps_to_malformed_response_error() {
    let transport = Arc::new(DynamicTransport {
        // Unexpected shape where envelope `data` is missing or invalid structure
        response: Ok(McpToolResponse::success(json!("not an object"))),
    });
    let adapter = FomoAdapter::new(transport);

    let err = adapter
        .search_tokens(FomoSearchTokensRequest {
            query: "TOKEN".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::MalformedResponse {
            service: McpServiceId::Fomo
        }
    );
}

#[tokio::test]
async fn test_oversized_response_rejected_fail_closed() {
    // Large payload that exceeds the configured max bytes
    let large_string = "x".repeat(500);
    let transport = Arc::new(DynamicTransport {
        response: Ok(McpToolResponse::success(json!({
            "data": large_string,
            "source": null,
            "freshness": null,
            "coverage": null,
            "warnings": []
        }))),
    });

    let adapter = FomoAdapter::new(transport).with_max_response_bytes(200);

    let err = adapter
        .search_tokens(FomoSearchTokensRequest {
            query: "TOKEN".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        McpAdapterError::OversizedResponse {
            service: McpServiceId::Fomo
        }
    );
}

#[test]
fn test_zero_secret_and_payload_leakage_regression() {
    let secret_token = "bearer-secret-token-xyz-12345";
    let internal_endpoint = "https://internal-cluster.local:8443/mcp/stream";
    let raw_payload = "{\"private_wallet_key\":\"0x123456789abcdef\"}";

    // Verify all error variants never disclose secrets or raw payloads in Display or Debug
    let errors = [
        McpAdapterError::InvalidArgument { field: "query" },
        McpAdapterError::UnsupportedTool {
            tool: "unsupported fomo tool",
        },
        McpAdapterError::DisallowedOperation,
        McpAdapterError::ServiceUnavailable {
            service: McpServiceId::Fomo,
        },
        McpAdapterError::TransportFailure {
            service: McpServiceId::Gmgn,
        },
        McpAdapterError::OversizedResponse {
            service: McpServiceId::Fomo,
        },
        McpAdapterError::MalformedResponse {
            service: McpServiceId::Gmgn,
        },
        McpAdapterError::ToolExecutionFailed {
            service: McpServiceId::Fomo,
        },
    ];

    for err in &errors {
        let display_str = format!("{err}");
        let debug_str = format!("{err:?}");

        assert!(
            !display_str.contains(secret_token),
            "Display leaked secret: {display_str}"
        );
        assert!(
            !display_str.contains(internal_endpoint),
            "Display leaked endpoint: {display_str}"
        );
        assert!(
            !display_str.contains(raw_payload),
            "Display leaked payload: {display_str}"
        );

        assert!(
            !debug_str.contains(secret_token),
            "Debug leaked secret: {debug_str}"
        );
        assert!(
            !debug_str.contains(internal_endpoint),
            "Debug leaked endpoint: {debug_str}"
        );
        assert!(
            !debug_str.contains(raw_payload),
            "Debug leaked payload: {debug_str}"
        );
    }

    // Verify McpToolCall debug representation redacts arguments
    let call = McpToolCall {
        service: McpServiceId::Fomo,
        tool_name: "fomo_search_tokens".into(),
        arguments: json!({ "secret": secret_token, "data": raw_payload }),
    };
    let call_debug = format!("{call:?}");
    assert!(
        !call_debug.contains(secret_token),
        "ToolCall Debug leaked arguments"
    );
    assert!(
        !call_debug.contains(raw_payload),
        "ToolCall Debug leaked arguments"
    );
    assert!(
        call_debug.contains("[REDACTED]"),
        "ToolCall Debug must redact arguments"
    );

    // Verify McpToolResponse debug representation redacts payload
    let response = McpToolResponse::success(json!({
        "secret": secret_token,
        "raw": raw_payload,
    }));
    let res_debug = format!("{response:?}");
    assert!(
        !res_debug.contains(secret_token),
        "ToolResponse Debug leaked payload"
    );
    assert!(
        !res_debug.contains(raw_payload),
        "ToolResponse Debug leaked payload"
    );
    assert!(
        res_debug.contains("[REDACTED]"),
        "ToolResponse Debug must redact payload"
    );
}
