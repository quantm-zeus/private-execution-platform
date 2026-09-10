mod common;

use common::FakeIntelligenceProvider;
use mcp_adapters::{GmgnTokenRequest, GmgnTopHoldersRequest};
use provider_broker::{
    BrokerConfig, BrokerError, CacheState, CandidateContext, DegradedReason, ManualClock,
    PositionContext, ProviderBroker, RequestContext,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn test_expensive_enrichment_without_candidate_eligibility_makes_zero_adapter_calls() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    let broker = ProviderBroker::new(clock, fake_provider.clone(), BrokerConfig::default());

    let req = GmgnTopHoldersRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
        limit: 20,
        order_by: Some("amount_percentage".to_string()),
    };

    // Case 1: No candidate context provided
    let ctx_none = RequestContext::default();
    let err1 = broker
        .gmgn_top_holders(req.clone(), &ctx_none)
        .await
        .unwrap_err();
    match err1 {
        BrokerError::CandidateNotEligible { candidate_id, meta } => {
            assert_eq!(candidate_id, "none");
            assert_eq!(
                meta.degraded_reason,
                Some(DegradedReason::CandidateGatingRejected)
            );
        }
        other => panic!("expected CandidateNotEligible, got {:?}", other),
    }
    assert_eq!(
        fake_provider.gmgn_top_holders_count.load(Ordering::SeqCst),
        0
    );

    // Case 2: Candidate context provided, but score (40) < threshold (70)
    let ctx_ineligible =
        RequestContext::default().with_candidate(CandidateContext::new("candidate_weak", 40, 70));
    let err2 = broker
        .gmgn_top_holders(req.clone(), &ctx_ineligible)
        .await
        .unwrap_err();
    match err2 {
        BrokerError::CandidateNotEligible { candidate_id, meta } => {
            assert_eq!(candidate_id, "candidate_weak");
            assert_eq!(
                meta.degraded_reason,
                Some(DegradedReason::CandidateGatingRejected)
            );
        }
        other => panic!("expected CandidateNotEligible, got {:?}", other),
    }
    // Zero adapter calls made!
    assert_eq!(
        fake_provider.gmgn_top_holders_count.load(Ordering::SeqCst),
        0
    );

    // Case 3: Candidate context provided and score (85) >= threshold (70)
    let ctx_eligible =
        RequestContext::default().with_candidate(CandidateContext::new("candidate_strong", 85, 70));
    let res3 = broker
        .gmgn_top_holders(req.clone(), &ctx_eligible)
        .await
        .expect("eligible candidate should succeed");
    assert_eq!(res3.meta.cache_state, CacheState::Miss);
    // Exactly 1 adapter call executed now
    assert_eq!(
        fake_provider.gmgn_top_holders_count.load(Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn test_position_context_is_part_of_cache_key_preventing_leakage() {
    let clock = Arc::new(ManualClock::new(1_000));
    let fake_provider = Arc::new(FakeIntelligenceProvider::new());
    let broker = ProviderBroker::new(clock, fake_provider.clone(), BrokerConfig::default());

    let req = GmgnTokenRequest {
        chain: "sol".to_string(),
        address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263".to_string(),
    };

    let ctx_pos1 = RequestContext::default().with_position(PositionContext::new("pos_wallet_A"));
    let ctx_pos2 = RequestContext::default().with_position(PositionContext::new("pos_wallet_B"));
    let ctx_global = RequestContext::default();

    // 1. Request for Position 1 -> Miss -> Call 1
    let res1 = broker
        .gmgn_token_info(req.clone(), &ctx_pos1)
        .await
        .expect("pos1 failed");
    assert_eq!(res1.meta.cache_state, CacheState::Miss);
    assert_eq!(fake_provider.call_count.load(Ordering::SeqCst), 1);

    // 2. Second request for Position 1 -> Fresh Hit -> Call count remains 1
    let res1_repeat = broker
        .gmgn_token_info(req.clone(), &ctx_pos1)
        .await
        .expect("pos1 repeat failed");
    assert_eq!(res1_repeat.meta.cache_state, CacheState::FreshHit);
    assert_eq!(fake_provider.call_count.load(Ordering::SeqCst), 1);

    // 3. Request for Position 2 -> Miss (MUST NOT hit Position 1's cache) -> Call 2
    let res2 = broker
        .gmgn_token_info(req.clone(), &ctx_pos2)
        .await
        .expect("pos2 failed");
    assert_eq!(res2.meta.cache_state, CacheState::Miss);
    assert_eq!(fake_provider.call_count.load(Ordering::SeqCst), 2);

    // 4. Request without position context -> Miss (MUST NOT hit Position 1 or 2's cache) -> Call 3
    let res_global = broker
        .gmgn_token_info(req.clone(), &ctx_global)
        .await
        .expect("global failed");
    assert_eq!(res_global.meta.cache_state, CacheState::Miss);
    assert_eq!(fake_provider.call_count.load(Ordering::SeqCst), 3);
}
