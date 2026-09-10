use std::sync::{Arc, Mutex};

use mcp_adapters::{
    validate_tool_allowlist, FomoAdapter, FomoGetTokenRequest, FomoRecentEventsRequest,
    FomoSearchTokensRequest, FomoTrendingTokensRequest, GmgnAdapter, GmgnKlineRequest,
    GmgnSearchRequest, GmgnTokenRequest, GmgnTopHoldersRequest, GmgnTrendingRequest,
    McpAdapterError, McpServiceId, McpToolCall, McpToolResponse, McpTransport, McpTransportError,
};

#[derive(Default)]
struct FailOnCallTransport {
    calls: Mutex<usize>,
}

#[async_trait::async_trait]
impl McpTransport for FailOnCallTransport {
    async fn call_tool(&self, _call: McpToolCall) -> Result<McpToolResponse, McpTransportError> {
        *self.calls.lock().unwrap() += 1;
        panic!("transport must NOT be invoked when validation fails");
    }
}

#[tokio::test]
async fn test_fomo_search_tokens_empty_query_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoSearchTokensRequest {
        query: "   ".to_string(),
    };
    let err = adapter.search_tokens(req).await.unwrap_err();
    assert_eq!(err, McpAdapterError::InvalidArgument { field: "query" });
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_fomo_search_tokens_oversized_query_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoSearchTokensRequest {
        query: "a".repeat(257),
    };
    let err = adapter.search_tokens(req).await.unwrap_err();
    assert_eq!(err, McpAdapterError::InvalidArgument { field: "query" });
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_fomo_get_token_invalid_network_id_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoGetTokenRequest {
        network_id: 0,
        token_address: "0x020bfc650a365f8bb26819deaabf3e21291018b4".to_string(),
    };
    let err = adapter.get_token(req).await.unwrap_err();
    assert_eq!(
        err,
        McpAdapterError::InvalidArgument {
            field: "network_id"
        }
    );
    assert_eq!(*transport.calls.lock().unwrap(), 0);

    let req2 = FomoGetTokenRequest {
        network_id: -10,
        token_address: "0x020bfc650a365f8bb26819deaabf3e21291018b4".to_string(),
    };
    let err2 = adapter.get_token(req2).await.unwrap_err();
    assert_eq!(
        err2,
        McpAdapterError::InvalidArgument {
            field: "network_id"
        }
    );
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_fomo_get_token_invalid_address_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoGetTokenRequest {
        network_id: 8453,
        token_address: "invalid_address_string".to_string(),
    };
    let err = adapter.get_token(req).await.unwrap_err();
    assert_eq!(
        err,
        McpAdapterError::InvalidArgument {
            field: "token_address"
        }
    );
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_fomo_get_trending_tokens_invalid_list_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    // Only exact documented lists: trendingTokens, mostHeld, graduatedTokens, cryptoTokens, verifiedTokens
    for bad_list in ["", "   ", "trending", "most_held", "randomList", "category"] {
        let req = FomoTrendingTokensRequest {
            list: bad_list.to_string(),
        };
        let err = adapter.get_trending_tokens(req).await.unwrap_err();
        assert_eq!(err, McpAdapterError::InvalidArgument { field: "list" });
    }
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_fomo_get_recent_events_invalid_minutes_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = FomoAdapter::new(transport.clone());

    let req = FomoRecentEventsRequest {
        since_minutes: Some(-5),
        ..Default::default()
    };
    let err = adapter.get_recent_events(req).await.unwrap_err();
    assert_eq!(
        err,
        McpAdapterError::InvalidArgument {
            field: "since_minutes"
        }
    );
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_trending_invalid_chain_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    // Case-sensitive "SOL" or alias "solana" must be rejected
    for bad_chain in ["SOL", "solana", "arbitrum", "polygon", "", "avalanche"] {
        let req = GmgnTrendingRequest {
            chain: bad_chain.to_string(),
            interval: "1h".to_string(),
            limit: 10,
        };
        let err = adapter.trending(req).await.unwrap_err();
        assert_eq!(err, McpAdapterError::InvalidArgument { field: "chain" });
    }
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_trending_invalid_interval_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    for bad_interval in ["2h", "10m", "30d", "daily"] {
        let req = GmgnTrendingRequest {
            chain: "sol".to_string(),
            interval: bad_interval.to_string(),
            limit: 10,
        };
        let err = adapter.trending(req).await.unwrap_err();
        assert_eq!(err, McpAdapterError::InvalidArgument { field: "interval" });
    }
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_search_empty_query_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnSearchRequest {
        query: "".to_string(),
        chain: None,
    };
    let err = adapter.search(req).await.unwrap_err();
    assert_eq!(err, McpAdapterError::InvalidArgument { field: "query" });
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_token_address_injection_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    for bad_address in [
        "addr&param=inject",
        "addr/path/traversal",
        "addr?query=test",
        "addr#fragment",
        "addr\0nullbyte",
    ] {
        let req = GmgnTokenRequest {
            chain: "sol".to_string(),
            address: bad_address.to_string(),
        };
        let err = adapter.token_info(req).await.unwrap_err();
        assert_eq!(err, McpAdapterError::InvalidArgument { field: "address" });
    }
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_kline_invalid_resolution_and_range_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnKlineRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        resolution: "10m".to_string(),
        from: None,
        to: None,
    };
    let err = adapter.kline(req).await.unwrap_err();
    assert_eq!(
        err,
        McpAdapterError::InvalidArgument {
            field: "resolution"
        }
    );
    assert_eq!(*transport.calls.lock().unwrap(), 0);

    // Range where to < from
    let req2 = GmgnKlineRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        resolution: "1h".to_string(),
        from: Some(1700005000),
        to: Some(1700001000),
    };
    let err2 = adapter.kline(req2).await.unwrap_err();
    assert_eq!(err2, McpAdapterError::InvalidArgument { field: "to" });
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn test_gmgn_top_holders_invalid_order_by_rejected_before_transport() {
    let transport = Arc::new(FailOnCallTransport::default());
    let adapter = GmgnAdapter::new(transport.clone());

    let req = GmgnTopHoldersRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        limit: 10,
        order_by: Some("invalid_order".to_string()),
    };
    let err = adapter.top_holders(req).await.unwrap_err();
    assert_eq!(err, McpAdapterError::InvalidArgument { field: "order_by" });
    assert_eq!(*transport.calls.lock().unwrap(), 0);
}

#[test]
fn test_allowlist_blocks_mutation_and_probe_operations() {
    // Prohibited operations
    let disallowed = [
        "gmgn_diagnostics",
        "gmgn_probe",
        "fomo_resolve_wallet",
        "wallet_resolve",
        "trade_token",
        "buy_token",
        "sell_order",
        "swap_tokens",
        "sign_transaction",
        "transfer_asset",
        "fomo_auth_status",
        "configure_system",
    ];

    for name in disallowed {
        let fomo_check = validate_tool_allowlist(McpServiceId::Fomo, name);
        assert_eq!(
            fomo_check,
            Err(McpAdapterError::DisallowedOperation),
            "tool {name} must be disallowed"
        );

        let gmgn_check = validate_tool_allowlist(McpServiceId::Gmgn, name);
        assert_eq!(
            gmgn_check,
            Err(McpAdapterError::DisallowedOperation),
            "tool {name} must be disallowed"
        );
    }
}

#[test]
fn test_allowlist_blocks_unsupported_documented_tools_in_first_slice() {
    // Tools that are documented read-only queries but deliberately excluded in this slice
    let unsupported_fomo = [
        "fomo_search_users",
        "fomo_get_profile",
        "fomo_get_following",
        "fomo_get_followers",
        "fomo_get_user_holdings",
        "fomo_get_feed",
        "fomo_get_leaderboard",
        "fomo_get_watchlist",
    ];

    for tool in unsupported_fomo {
        assert_eq!(
            validate_tool_allowlist(McpServiceId::Fomo, tool),
            Err(McpAdapterError::UnsupportedTool {
                tool: "unsupported fomo tool"
            })
        );
    }

    // User swaps has "swap" in name so it is blocked as a disallowed operation
    assert_eq!(
        validate_tool_allowlist(McpServiceId::Fomo, "fomo_get_user_swaps"),
        Err(McpAdapterError::DisallowedOperation)
    );

    let unsupported_gmgn = [
        "gmgn_smart_money",
        "gmgn_kol",
        "gmgn_trenches",
        "gmgn_hot_searches",
        "gmgn_wallet_score",
    ];

    for tool in unsupported_gmgn {
        assert_eq!(
            validate_tool_allowlist(McpServiceId::Gmgn, tool),
            Err(McpAdapterError::UnsupportedTool {
                tool: "unsupported gmgn tool"
            })
        );
    }
}

#[test]
fn test_unsupported_names_cannot_enter_call_construction_path() {
    use serde_json::json;

    // Direct construction of McpToolCall from an untrusted name must fail closed
    let disallowed_attempts = [
        (McpServiceId::Gmgn, "gmgn_diagnostics"),
        (McpServiceId::Gmgn, "gmgn_trade"),
        (McpServiceId::Gmgn, "gmgn_buy_token"),
        (McpServiceId::Fomo, "fomo_resolve_wallet"),
        (McpServiceId::Fomo, "fomo_sign_tx"),
        (McpServiceId::Fomo, "fomo_auth_status"),
    ];

    for (service, tool) in disallowed_attempts {
        let res = McpToolCall::try_from_untrusted(service, tool, json!({}));
        assert_eq!(
            res,
            Err(McpAdapterError::DisallowedOperation),
            "disallowed tool '{tool}' must fail closed before call construction"
        );
    }

    let unsupported_attempts = [
        (McpServiceId::Fomo, "fomo_search_users"),
        (McpServiceId::Fomo, "fomo_get_profile"),
        (McpServiceId::Gmgn, "gmgn_smart_money"),
        (McpServiceId::Gmgn, "gmgn_kol"),
        (McpServiceId::Gmgn, "arbitrary_custom_tool"),
        (McpServiceId::Fomo, "gmgn_trending"),
        (McpServiceId::Gmgn, "fomo_search_tokens"),
    ];

    for (service, tool) in unsupported_attempts {
        let res = McpToolCall::try_from_untrusted(service, tool, json!({}));
        assert!(
            matches!(res, Err(McpAdapterError::UnsupportedTool { .. })),
            "unsupported tool '{tool}' must fail closed before call construction"
        );
    }
}
