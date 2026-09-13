//! P60: budget/candidate gating, cache/SWR, negative cache, and redaction.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use provider_broker::{CacheState, CandidateContext, DegradedReason, PositionContext};
use social_intel::{
    SocialIntelService, SocialPolicy, SocialPriority, SocialProvider, SocialProviderError,
    SocialRequest, SocialSignal, SocialSignalKind, SocialSnapshot, UnavailableSocialProvider,
};

#[derive(Clone)]
struct FakeProvider {
    calls: Arc<AtomicU32>,
    result: Arc<Mutex<Result<SocialSnapshot, SocialProviderError>>>,
}

#[async_trait]
impl SocialProvider for FakeProvider {
    async fn fetch(&self, _request: &SocialRequest) -> Result<SocialSnapshot, SocialProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.lock().expect("lock").clone()
    }
}

type Shared = Arc<Mutex<Result<SocialSnapshot, SocialProviderError>>>;

fn fake(
    result: Result<SocialSnapshot, SocialProviderError>,
) -> (FakeProvider, Arc<AtomicU32>, Shared) {
    let calls = Arc::new(AtomicU32::new(0));
    let shared = Arc::new(Mutex::new(result));
    (
        FakeProvider {
            calls: calls.clone(),
            result: shared.clone(),
        },
        calls,
        shared,
    )
}

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn snapshot(token: &str) -> SocialSnapshot {
    SocialSnapshot {
        chain: ChainId::Base,
        token: asset(token),
        signals: vec![SocialSignal {
            kind: SocialSignalKind::Catalyst,
            weight_bps: 5_000,
            observed_at_ms: 10,
        }],
        observed_at_ms: 10,
    }
}

fn policy() -> SocialPolicy {
    SocialPolicy {
        budget_capacity: 100,
        budget_refill_per_sec: 0,
        fresh_ttl_ms: 100,
        stale_grace_ms: 1_000,
        negative_ttl_ms: 1_000,
    }
}

fn candidate_request(
    token: &str,
    priority: SocialPriority,
    score: u32,
    threshold: u32,
) -> SocialRequest {
    SocialRequest::for_candidate(
        ChainId::Base,
        asset(token),
        priority,
        CandidateContext::new("cand-1", score, threshold),
    )
}

#[tokio::test]
async fn fresh_fetch_is_cached_and_not_refetched() {
    let (provider, calls, _) = fake(Ok(snapshot("TOKEN")));
    let mut service = SocialIntelService::new(provider, policy(), 0);
    let request = candidate_request("TOKEN", SocialPriority::PromisingCandidate, 80, 75);

    let first = service.get_intelligence(request.clone(), 0).await;
    assert_eq!(first.meta.cache_state, CacheState::Miss);
    assert_eq!(first.value.signals.len(), 1);

    let second = service.get_intelligence(request, 10).await;
    assert_eq!(second.meta.cache_state, CacheState::FreshHit);
    assert_eq!(second.meta.freshness_ms, Some(10));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn budget_exhaustion_degrades_without_calling_the_provider() {
    let (provider, calls, _) = fake(Ok(snapshot("TOKEN")));
    let tight = SocialPolicy {
        budget_capacity: 1,
        ..policy()
    };
    let mut service = SocialIntelService::new(provider, tight, 0);

    let first = service
        .get_intelligence(
            candidate_request("TOKEN", SocialPriority::PromisingCandidate, 80, 75),
            0,
        )
        .await;
    assert_eq!(first.meta.cache_state, CacheState::Miss);

    let second = service
        .get_intelligence(
            candidate_request("OTHER", SocialPriority::PromisingCandidate, 80, 75),
            0,
        )
        .await;
    assert_eq!(
        second.meta.degraded_reason,
        Some(DegradedReason::BudgetExhausted)
    );
    assert!(second.value.signals.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn candidate_and_position_gating_reject_before_any_work() {
    let (provider, calls, _) = fake(Ok(snapshot("TOKEN")));
    let mut service = SocialIntelService::new(provider, policy(), 0);

    // Ineligible candidate.
    let gated = service
        .get_intelligence(
            candidate_request("TOKEN", SocialPriority::PromisingCandidate, 50, 75),
            0,
        )
        .await;
    assert_eq!(
        gated.meta.degraded_reason,
        Some(DegradedReason::CandidateGatingRejected)
    );

    // Pre-trade priority with no candidate at all.
    let no_candidate = service
        .get_intelligence(
            SocialRequest {
                chain: ChainId::Base,
                token: asset("TOKEN"),
                priority: SocialPriority::HighConvictionPreTrade,
                candidate: None,
                position: None,
            },
            0,
        )
        .await;
    assert_eq!(
        no_candidate.meta.degraded_reason,
        Some(DegradedReason::CandidateGatingRejected)
    );

    // Active-position risk with no position.
    let no_position = service
        .get_intelligence(
            SocialRequest {
                chain: ChainId::Base,
                token: asset("TOKEN"),
                priority: SocialPriority::ActivePositionRisk,
                candidate: None,
                position: None,
            },
            0,
        )
        .await;
    assert_eq!(
        no_position.meta.degraded_reason,
        Some(DegradedReason::CandidateGatingRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // An eligible candidate proceeds.
    let ok = service
        .get_intelligence(
            candidate_request("TOKEN", SocialPriority::HighConvictionPreTrade, 80, 75),
            0,
        )
        .await;
    assert_eq!(ok.meta.cache_state, CacheState::Miss);

    // An active position proceeds.
    let position = service
        .get_intelligence(
            SocialRequest::for_position(
                ChainId::Base,
                asset("OTHER"),
                PositionContext::new("pos-1"),
            ),
            1,
        )
        .await;
    assert_eq!(position.meta.cache_state, CacheState::Miss);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn provider_failure_is_negatively_cached() {
    let (provider, calls, _) = fake(Err(SocialProviderError::Unavailable));
    let mut service = SocialIntelService::new(provider, policy(), 0);
    let request = candidate_request("TOKEN", SocialPriority::PromisingCandidate, 80, 75);

    let first = service.get_intelligence(request.clone(), 0).await;
    assert_eq!(
        first.meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert!(first.value.signals.is_empty());

    let second = service.get_intelligence(request, 10).await;
    assert_eq!(second.meta.cache_state, CacheState::NegativeHit);
    assert_eq!(
        second.meta.degraded_reason,
        Some(DegradedReason::NegativeCached)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stale_fallback_is_served_when_the_provider_fails() {
    let (provider, calls, shared) = fake(Ok(snapshot("TOKEN")));
    let mut service = SocialIntelService::new(provider, policy(), 0);
    let request = candidate_request("TOKEN", SocialPriority::PromisingCandidate, 80, 75);

    let first = service.get_intelligence(request.clone(), 0).await;
    assert_eq!(first.meta.cache_state, CacheState::Miss);

    *shared.lock().expect("lock") = Err(SocialProviderError::Unavailable);
    let stale = service.get_intelligence(request, 200).await;
    assert_eq!(stale.meta.cache_state, CacheState::StaleServed);
    assert_eq!(
        stale.meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(stale.value.signals.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_default_provider_fails_closed() {
    let mut service = SocialIntelService::new(UnavailableSocialProvider::new(), policy(), 0);
    let response = service
        .get_intelligence(
            candidate_request("TOKEN", SocialPriority::PromisingCandidate, 80, 75),
            0,
        )
        .await;
    assert_eq!(
        response.meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert!(response.value.signals.is_empty());
}

#[tokio::test]
async fn request_and_snapshot_debug_are_redacted() {
    let request = SocialRequest::for_position(
        ChainId::Base,
        asset("SECRETTOKEN"),
        PositionContext::new("secret-position"),
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("SECRETTOKEN"));
    assert!(!debug.contains("secret-position"));

    let debug = format!("{:?}", snapshot("SECRETTOKEN"));
    assert!(!debug.contains("SECRETTOKEN"));
}
