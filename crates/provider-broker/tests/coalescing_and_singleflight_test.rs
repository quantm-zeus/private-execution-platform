mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{FomoSearchTokensRequest, McpAdapterError, McpServiceId};
use provider_broker::{BrokerConfig, ManualClock, ProviderBroker, RequestContext};
use std::sync::Arc;

#[tokio::test]
async fn test_concurrent_identical_requests_coalesce_to_single_adapter_call() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    let broker = ProviderBroker::new(clock, fake_provider.clone(), BrokerConfig::default());
    let ctx = RequestContext::default();

    let concurrency = 25;
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let b = broker.clone();
        let c = ctx.clone();
        handles.push(tokio::spawn(async move {
            b.fomo_search_tokens(
                FomoSearchTokensRequest {
                    query: "COALESCE_ME".to_string(),
                },
                &c,
            )
            .await
        }));
    }

    let mut results = Vec::with_capacity(concurrency);
    for h in handles {
        let res = h.await.expect("task join failed");
        results.push(res.expect("search tokens should succeed"));
    }

    // Assert that exactly 1 adapter call was made across all concurrent identical requests
    let total_calls = fake_provider
        .fomo_search_count
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        total_calls, 1,
        "concurrent identical requests must coalesce to at most 1 adapter call"
    );

    // Assert that all callers received the exact same data
    let first_val = &results[0].value;
    for r in &results[1..] {
        assert_eq!(&r.value, first_val);
    }
}

#[tokio::test]
async fn test_concurrent_failure_coalesces_without_retry() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    fake_provider.set_failure(McpAdapterError::ServiceUnavailable {
        service: McpServiceId::Fomo,
    });

    let broker = ProviderBroker::new(clock, fake_provider.clone(), BrokerConfig::default());
    let ctx = RequestContext::default();

    let concurrency = 10;
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let b = broker.clone();
        let c = ctx.clone();
        handles.push(tokio::spawn(async move {
            b.fomo_search_tokens(
                FomoSearchTokensRequest {
                    query: "FAIL_CONCURRENT".to_string(),
                },
                &c,
            )
            .await
        }));
    }

    for h in handles {
        let res = h.await.expect("task join failed");
        assert!(res.is_err(), "all concurrent callers must receive error");
    }

    // Exactly 1 adapter call was made; no automatic retries
    let total_calls = fake_provider
        .fomo_search_count
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        total_calls, 1,
        "failed call must not be retried automatically across concurrent requests"
    );
}
