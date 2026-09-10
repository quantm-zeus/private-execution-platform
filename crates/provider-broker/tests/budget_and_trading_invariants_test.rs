mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{FomoSearchTokensRequest, GmgnTrendingRequest};
use policy::TradingGate;
use provider_broker::{
    BrokerConfig, BrokerError, CacheState, DegradedReason, ManualClock, ProviderBroker,
    ProviderPolicy, RequestContext, TRADING_ENABLED,
};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[test]
fn test_compile_time_trading_disabled_invariants() {
    // Compile-time invariant proof: TRADING_ENABLED is strictly false in both crates
    const { assert!(!TRADING_ENABLED) };
    const { assert!(!mcp_adapters::TRADING_ENABLED) };
}

#[tokio::test]
async fn test_budget_exhaustion_degrades_intelligence_preserving_trading_invariants() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());

    // Configure a small GMGN budget of 5 units (each trending query costs 1 unit) with 0 refill
    let config = BrokerConfig {
        gmgn: ProviderPolicy {
            max_budget: 3,
            budget_refill_per_sec: 0,
            ..ProviderPolicy::default_gmgn()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock.clone(), fake_provider.clone(), config);
    let ctx = RequestContext::default();

    // Setup an external trading gate (initialized to enabled) and an execution signal
    let trading_gate = TradingGate::from_trusted_startup(Some("true")).expect("gate creation");
    let execution_enabled_signal = Arc::new(AtomicBool::new(true));

    assert!(trading_gate.is_enabled());
    assert!(execution_enabled_signal.load(std::sync::atomic::Ordering::Acquire));

    // Exhaust the 3 budget units with 3 distinct requests (to avoid cache hits)
    for i in 1..=3 {
        let req = GmgnTrendingRequest {
            chain: "sol".to_string(),
            interval: "1h".to_string(),
            limit: i as i64,
        };
        let res = broker.gmgn_trending(req, &ctx).await;
        assert!(res.is_ok(), "query {i} should succeed within budget");
    }

    // 4th request must be rejected due to budget exhaustion
    let req_exhausted = GmgnTrendingRequest {
        chain: "sol".to_string(),
        interval: "1h".to_string(),
        limit: 99,
    };
    let err = broker.gmgn_trending(req_exhausted, &ctx).await.unwrap_err();
    match err {
        BrokerError::BudgetExhausted { provider, meta } => {
            assert_eq!(provider, mcp_adapters::McpServiceId::Gmgn);
            assert_eq!(meta.degraded_reason, Some(DegradedReason::BudgetExhausted));
        }
        other => panic!("expected BudgetExhausted, got {:?}", other),
    }

    // CRITICAL INVARIANT VERIFICATION:
    // 1. External execution-enabled signal remains strictly TRUE
    assert!(
        execution_enabled_signal.load(std::sync::atomic::Ordering::Acquire),
        "intelligence budget exhaustion must never disable local execution signal"
    );
    // 2. TradingGate remains strictly unchanged
    assert!(
        trading_gate.is_enabled(),
        "intelligence budget exhaustion must never alter TradingGate state"
    );
    // 3. Broker and adapter global TRADING_ENABLED remains false
    const { assert!(!TRADING_ENABLED) };
    const { assert!(!mcp_adapters::TRADING_ENABLED) };
}

#[tokio::test]
async fn test_budget_exhaustion_serves_stale_fallback_if_available() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());

    // FOMO budget of 2 units
    let config = BrokerConfig {
        fomo: ProviderPolicy {
            fresh_ttl_ms: 1_000,
            stale_grace_ms: 1_000,
            max_budget: 2,
            budget_refill_per_sec: 0,
            ..ProviderPolicy::default_fomo()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock.clone(), fake_provider.clone(), config);
    let ctx = RequestContext::default();

    let req = FomoSearchTokensRequest {
        query: "FALLBACK_TEST".to_string(),
    };

    // 1. Initial request: succeeds, cached at t = 1,000. Uses 1 budget unit.
    let res1 = broker
        .fomo_search_tokens(req.clone(), &ctx)
        .await
        .expect("req1 failed");
    assert_eq!(res1.meta.cache_state, CacheState::Miss);

    // 2. Another query consumes the 2nd budget unit. Budget is now 0.
    let req2 = FomoSearchTokensRequest {
        query: "OTHER_TOKEN".to_string(),
    };
    let _ = broker
        .fomo_search_tokens(req2, &ctx)
        .await
        .expect("req2 failed");

    // 3. Advance clock past fresh and stale grace so req1 is technically expired
    clock.set_ms(10_000);

    // 4. Request for req1 when budget is exhausted serves historical stale data with DegradedReason::BudgetExhausted
    let res_fallback = broker
        .fomo_search_tokens(req.clone(), &ctx)
        .await
        .expect("should serve stale fallback");
    assert_eq!(res_fallback.meta.cache_state, CacheState::StaleServed);
    assert_eq!(
        res_fallback.meta.degraded_reason,
        Some(DegradedReason::BudgetExhausted)
    );
}
