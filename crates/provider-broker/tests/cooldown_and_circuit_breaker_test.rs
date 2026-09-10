mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{GmgnTrendingRequest, McpAdapterError, McpServiceId};
use provider_broker::{
    BrokerConfig, BrokerError, DegradedReason, ManualClock, ProviderBroker, ProviderHealthState,
    ProviderPolicy, RequestContext,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn test_consecutive_failures_enter_cooldown_and_prevent_hammering() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());

    // Configure 3 consecutive failures threshold, 10,000 ms cooldown
    let config = BrokerConfig {
        gmgn: ProviderPolicy {
            failure_threshold: 3,
            cooldown_duration_ms: 10_000,
            ..ProviderPolicy::default_gmgn()
        },
        ..Default::default()
    };

    let broker = ProviderBroker::new(clock.clone(), fake_provider.clone(), config);
    let ctx = RequestContext::default();

    // Inject failure
    fake_provider.set_failure(McpAdapterError::ServiceUnavailable {
        service: McpServiceId::Gmgn,
    });

    // 1. Failure 1
    let req1 = GmgnTrendingRequest {
        chain: "sol".into(),
        interval: "1h".into(),
        limit: 1,
    };
    let _ = broker.gmgn_trending(req1, &ctx).await.unwrap_err();
    assert_eq!(
        broker.health(McpServiceId::Gmgn).state,
        ProviderHealthState::Degraded
    );
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 1);

    // 2. Failure 2
    clock.advance_ms(500);
    let req2 = GmgnTrendingRequest {
        chain: "sol".into(),
        interval: "1h".into(),
        limit: 2,
    };
    let _ = broker.gmgn_trending(req2, &ctx).await.unwrap_err();
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 2);

    // 3. Failure 3 -> trips circuit into CircuitOpen / Cooldown
    clock.advance_ms(500);
    let req3 = GmgnTrendingRequest {
        chain: "sol".into(),
        interval: "1h".into(),
        limit: 3,
    };
    let _ = broker.gmgn_trending(req3, &ctx).await.unwrap_err();
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 3);
    assert_eq!(
        broker.health(McpServiceId::Gmgn).state,
        ProviderHealthState::CircuitOpen
    );

    // 4. Repeated requests during cooldown (t = 2,500 < 2,000 + 10,000 = 12,000)
    // Must be rejected immediately WITHOUT hammering the adapter!
    clock.set_ms(2_500);
    for i in 4..=10 {
        let req = GmgnTrendingRequest {
            chain: "sol".into(),
            interval: "1h".into(),
            limit: i,
        };
        let err = broker.gmgn_trending(req, &ctx).await.unwrap_err();
        match err {
            BrokerError::CooldownActive { provider, meta } => {
                assert_eq!(provider, McpServiceId::Gmgn);
                assert_eq!(meta.degraded_reason, Some(DegradedReason::CooldownActive));
            }
            other => panic!("expected CooldownActive, got {:?}", other),
        }
    }

    // Call count MUST remain exactly 3; zero adapter hammering!
    assert_eq!(
        fake_provider.gmgn_trending_count.load(Ordering::SeqCst),
        3,
        "cooldown period must prevent adapter hammering"
    );

    // 5. Advance clock past cooldown (t = 12,500 > 12,000)
    clock.set_ms(12_500);
    fake_provider.clear_failure();

    // 6. Half-open probe request is allowed
    let probe_req = GmgnTrendingRequest {
        chain: "sol".into(),
        interval: "1h".into(),
        limit: 50,
    };
    let res = broker
        .gmgn_trending(probe_req, &ctx)
        .await
        .expect("probe should succeed");
    assert!(res.value.payload["chain"] == "sol");

    // Adapter was called for the probe
    assert_eq!(fake_provider.gmgn_trending_count.load(Ordering::SeqCst), 4);

    // Circuit is now restored to Healthy
    assert_eq!(
        broker.health(McpServiceId::Gmgn).state,
        ProviderHealthState::Healthy
    );
    assert_eq!(broker.health(McpServiceId::Gmgn).consecutive_failures, 0);
}
