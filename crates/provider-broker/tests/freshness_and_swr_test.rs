mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{GmgnTrendingRequest, McpAdapterError, McpServiceId};
use provider_broker::{
    BrokerConfig, BrokerError, CacheState, ManualClock, OpaqueFailureKind, ProviderBroker,
    RequestContext,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn test_fresh_hit_returns_immediately_without_adapter_call() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    let broker = ProviderBroker::new(
        clock.clone(),
        fake_provider.clone(),
        BrokerConfig::default(),
    );
    let ctx = RequestContext::default();

    let req = GmgnTrendingRequest {
        chain: "sol".to_string(),
        interval: "1h".to_string(),
        limit: 10,
    };

    // 1. Initial request -> Cache Miss -> invokes adapter (call count = 1)
    let res1 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("req1 failed");
    assert_eq!(res1.meta.cache_state, CacheState::Miss);
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);

    // 2. Advance clock by 5s (well within GMGN fresh TTL of 10s)
    clock.advance_ms(5_000);

    // 3. Second request -> Cache Fresh Hit -> zero adapter call (call count remains 1)
    let res2 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("req2 failed");
    assert_eq!(res2.meta.cache_state, CacheState::FreshHit);
    assert_eq!(res2.meta.freshness_ms, Some(5_000));
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_stale_while_revalidate_and_bounded_single_refresh() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());

    // Disable refill so budget tracking is exact
    let config = BrokerConfig {
        gmgn: provider_broker::ProviderPolicy {
            budget_refill_per_sec: 0,
            ..provider_broker::ProviderPolicy::default_gmgn()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock.clone(), fake_provider.clone(), config);
    let ctx = RequestContext::default();

    let req = GmgnTrendingRequest {
        chain: "sol".to_string(),
        interval: "1h".to_string(),
        limit: 10,
    };

    let initial_budget = broker.health(McpServiceId::Gmgn).available_budget;

    // Initial request at t = 1,000 (seq = 0) -> consumes 1 budget unit
    let res1 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("req1 failed");
    assert_eq!(res1.meta.cache_state, CacheState::Miss);
    assert_eq!(res1.value.payload["seq"], 0);
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        initial_budget - broker.health(McpServiceId::Gmgn).available_budget,
        1,
        "initial miss must charge exactly 1 operation weight"
    );

    // Advance clock to t = 15,000 (age 14,000 > fresh TTL 10,000, but < stale grace 40,000)
    clock.set_ms(15_000);

    // Multiple rapid requests during stale window (none of which consume budget directly)
    let res_stale1 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("stale1 failed");
    let res_stale2 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("stale2 failed");
    let res_stale3 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("stale3 failed");

    // All return stale data immediately
    assert_eq!(res_stale1.meta.cache_state, CacheState::StaleServed);
    assert_eq!(res_stale2.meta.cache_state, CacheState::StaleServed);
    assert_eq!(res_stale3.meta.cache_state, CacheState::StaleServed);
    assert_eq!(res_stale1.value.payload["seq"], 0);

    // Drive background SWR refresh to completion deterministically without wall-clock sleep
    broker.flush_swr().await;

    // Verify exactly ONE refresh was scheduled and executed
    let total_calls = fake_provider.gmgn_trending_count.load(Ordering::SeqCst);
    assert_eq!(
        total_calls, 2,
        "SWR must schedule at most one bounded refresh across multiple stale requests"
    );

    // SWR refresh must charge exactly one operation weight
    assert_eq!(
        initial_budget - broker.health(McpServiceId::Gmgn).available_budget,
        2,
        "SWR refresh must charge exactly one operation weight"
    );

    // Next request at same timestamp now hits fresh updated cache (seq = 1)
    let res_fresh = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("fresh after SWR failed");
    assert_eq!(res_fresh.meta.cache_state, CacheState::FreshHit);
    assert_eq!(res_fresh.value.payload["seq"], 1);
    // Zero additional adapter calls and zero additional budget charge
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        initial_budget - broker.health(McpServiceId::Gmgn).available_budget,
        2
    );
}

#[tokio::test]
async fn test_negative_cache_and_bounded_ttl() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    // Simulate service failure
    fake_provider.set_failure(McpAdapterError::ServiceUnavailable {
        service: McpServiceId::Gmgn,
    });

    let broker = ProviderBroker::new(
        clock.clone(),
        fake_provider.clone(),
        BrokerConfig::default(),
    );
    let ctx = RequestContext::default();

    let req = GmgnTrendingRequest {
        chain: "sol".to_string(),
        interval: "1h".to_string(),
        limit: 10,
    };

    // 1. Initial failed request at t = 1,000 -> adapter call count = 1
    let err1 = broker.gmgn_trending(req.clone(), &ctx).await.unwrap_err();
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);
    assert!(matches!(err1, BrokerError::Adapter { .. }));

    // 2. Immediate second request at t = 1,500 (within GMGN negative TTL 3,000 ms)
    clock.set_ms(1_500);
    let err2 = broker.gmgn_trending(req.clone(), &ctx).await.unwrap_err();
    match err2 {
        BrokerError::NegativeCached {
            provider,
            kind,
            meta,
        } => {
            assert_eq!(provider, McpServiceId::Gmgn);
            assert_eq!(kind, OpaqueFailureKind::ServiceUnavailable);
            assert_eq!(meta.cache_state, CacheState::NegativeHit);
        }
        other => panic!("expected NegativeCached, got {:?}", other),
    }
    // No new adapter call!
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);

    // 3. Clear upstream failure and advance clock past negative TTL (t = 5,000 > 1,000 + 3,000)
    fake_provider.clear_failure();
    clock.set_ms(5_000);

    // 4. Request now bypasses expired negative cache and successfully calls adapter
    let res3 = broker
        .gmgn_trending(req.clone(), &ctx)
        .await
        .expect("retry should succeed");
    assert_eq!(res3.meta.cache_state, CacheState::Miss);
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 2);
}
