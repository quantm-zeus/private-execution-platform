mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{FomoSearchTokensRequest, McpAdapterError, McpServiceId};
use provider_broker::{
    BrokerConfig, BrokerError, ManualClock, ProviderBroker, ProviderId, ProviderPolicy,
    RequestContext,
};
use std::sync::Arc;

#[tokio::test]
async fn test_concurrent_identical_requests_coalesce_to_single_adapter_call_and_single_budget_charge(
) {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());

    // Disable refill so budget changes are strictly from request charges
    let config = BrokerConfig {
        fomo: ProviderPolicy {
            budget_refill_per_sec: 0,
            ..ProviderPolicy::default_fomo()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock, fake_provider.clone(), config);
    let ctx = RequestContext::default();

    let initial_budget = broker.health(ProviderId::Fomo).available_budget;

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

    // Assert that budget was charged exactly once (1 operation weight)
    let final_budget = broker.health(ProviderId::Fomo).available_budget;
    assert_eq!(
        initial_budget - final_budget,
        1,
        "25 concurrent requests must decrease budget by exactly 1 operation weight, not 25x"
    );

    // Assert that all callers received the exact same data
    let first_val = &results[0].value;
    for r in &results[1..] {
        assert_eq!(&r.value, first_val);
    }
}

#[tokio::test]
async fn test_concurrent_failure_coalesces_without_retry_and_single_budget_charge() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    fake_provider.set_failure(McpAdapterError::ServiceUnavailable {
        service: McpServiceId::Fomo,
    });

    // Disable refill so budget changes are strictly from request charges
    let config = BrokerConfig {
        fomo: ProviderPolicy {
            budget_refill_per_sec: 0,
            ..ProviderPolicy::default_fomo()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock.clone(), fake_provider.clone(), config);
    let ctx = RequestContext::default();

    let initial_budget = broker.health(ProviderId::Fomo).available_budget;

    let concurrency = 25;
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

    // Exactly one budget charge was deducted for the single leader attempt; no double charge
    let final_budget = broker.health(ProviderId::Fomo).available_budget;
    assert_eq!(
        initial_budget - final_budget,
        1,
        "25 concurrent failing requests must charge budget exactly once, not 25x or double charged"
    );

    // Negative cache remains fail-closed and makes zero additional adapter calls
    clock.advance_ms(1_000);
    let neg_res = broker
        .fomo_search_tokens(
            FomoSearchTokensRequest {
                query: "FAIL_CONCURRENT".to_string(),
            },
            &ctx,
        )
        .await;
    match neg_res {
        Err(BrokerError::NegativeCached { provider, .. }) => {
            assert_eq!(provider, McpServiceId::Fomo);
        }
        other => panic!("expected NegativeCached, got {:?}", other),
    }

    // Call count and budget must remain unchanged
    assert_eq!(
        fake_provider
            .fomo_search_count
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "negative cache hit must make zero adapter calls"
    );
    assert_eq!(
        broker.health(ProviderId::Fomo).available_budget,
        final_budget,
        "negative cache hit must consume zero budget"
    );
}
