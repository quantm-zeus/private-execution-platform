//! Focused tests for the budgeted provider-route benchmark service.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chain_types::{AssetId, ChainId};
use market_types::Bps;
use provider_benchmark::{
    BenchmarkMeta, BenchmarkOutcome, BenchmarkRequest, BenchmarkServicePolicy, BenchmarkSkipReason,
    ProviderBenchmarkService, ProviderQuoteRequest, ProviderQuoteSource, ProviderQuoteSourceError,
    UnavailableProviderQuoteSource, TRADING_ENABLED,
};
use provider_broker::{CacheState, CandidateContext, DegradedReason, RequestPriority};
use routing::{
    BenchmarkDirection, BenchmarkPolicy, BenchmarkSource, BenchmarkVerdict, LocalRouteQuote,
    ProviderQuote,
};

const BASE_MS: i64 = 1_000;

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid base asset")
}

fn weth() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000002")
}

fn usdc() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000001")
}

fn label(value: &str) -> BenchmarkSource {
    BenchmarkSource::new(value).expect("valid source label")
}

fn bps(value: u16) -> Bps {
    Bps::new(value).expect("valid bps")
}

fn local_at(amount_in: u128, amount_out: u128, observed_at_ms: i64) -> LocalRouteQuote {
    LocalRouteQuote::new(
        ChainId::Base,
        weth(),
        usdc(),
        amount_in,
        amount_out,
        observed_at_ms,
    )
}

fn candidate(score: u32, threshold: u32) -> CandidateContext {
    CandidateContext::new("candidate-1", score, threshold)
}

fn request_at(amount_in: u128, amount_out: u128, observed_at_ms: i64) -> BenchmarkRequest {
    BenchmarkRequest {
        local: local_at(amount_in, amount_out, observed_at_ms),
        candidate: candidate(100, 50),
        priority: RequestPriority::Normal,
    }
}

#[allow(clippy::too_many_arguments)]
fn policy_with(
    source: BenchmarkSource,
    request_cost: u32,
    budget_capacity: u32,
    budget_refill_per_sec: u32,
    fresh_ttl_ms: u64,
    stale_grace_ms: u64,
    negative_ttl_ms: u64,
    failure_threshold: u32,
    cooldown_duration_ms: u64,
    min_input_atomic: u128,
) -> BenchmarkServicePolicy {
    let benchmark = BenchmarkPolicy::new(bps(50), 5_000, 2_000, min_input_atomic);
    BenchmarkServicePolicy::new(
        source,
        benchmark,
        request_cost,
        budget_capacity,
        budget_refill_per_sec,
        fresh_ttl_ms,
        stale_grace_ms,
        negative_ttl_ms,
        failure_threshold,
        cooldown_duration_ms,
    )
    .expect("valid policy")
}

/// Conventional test policy: fresh 2s, provider age 5s, stale 30s, negative 5s.
fn policy(source: BenchmarkSource) -> BenchmarkServicePolicy {
    policy_with(source, 3, 30, 5, 2_000, 30_000, 5_000, 3, 15_000, 1)
}

/// Scripted provider-quote source with a call counter.
struct ScriptedSource {
    label: BenchmarkSource,
    amount_out: u128,
    fail: bool,
    fail_basis: Option<u128>,
    fail_from_call: Option<usize>,
    hang_on_call: Option<usize>,
    mismatch_amount: bool,
    future: bool,
    calls: AtomicUsize,
}

impl ScriptedSource {
    fn quoting(label: BenchmarkSource, amount_out: u128) -> Self {
        Self {
            label,
            amount_out,
            fail: false,
            fail_basis: None,
            fail_from_call: None,
            hang_on_call: None,
            mismatch_amount: false,
            future: false,
            calls: AtomicUsize::new(0),
        }
    }

    fn failing(label: BenchmarkSource, fail_basis: Option<u128>) -> Self {
        Self {
            fail: true,
            fail_basis,
            ..Self::quoting(label, 10_000)
        }
    }

    /// Succeeds for the first `fail_from_call - 1` calls, then fails.
    fn failing_after(label: BenchmarkSource, amount_out: u128, fail_from_call: usize) -> Self {
        Self {
            fail_from_call: Some(fail_from_call),
            ..Self::quoting(label, amount_out)
        }
    }

    /// Fails on `fail_basis` and hangs forever on the `hang_on_call`-th call.
    fn failing_then_hanging(
        label: BenchmarkSource,
        fail_basis: Option<u128>,
        hang_on_call: usize,
    ) -> Self {
        Self {
            hang_on_call: Some(hang_on_call),
            ..Self::failing(label, fail_basis)
        }
    }

    fn mismatching_amount(label: BenchmarkSource, amount_out: u128) -> Self {
        Self {
            mismatch_amount: true,
            ..Self::quoting(label, amount_out)
        }
    }

    fn from_the_future(label: BenchmarkSource, amount_out: u128) -> Self {
        Self {
            future: true,
            ..Self::quoting(label, amount_out)
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ProviderQuoteSource for ScriptedSource {
    async fn fetch_quote(
        &self,
        request: &ProviderQuoteRequest,
    ) -> Result<ProviderQuote, ProviderQuoteSourceError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let basis_fail = self.fail
            && self
                .fail_basis
                .is_none_or(|basis| basis == request.amount_in);
        let call_fail = self.fail_from_call.is_some_and(|from| call >= from);
        if basis_fail || call_fail {
            return Err(ProviderQuoteSourceError::Unavailable);
        }
        if self.hang_on_call == Some(call) {
            // Cancellation bait: never yields, so the caller can drop the
            // future (time out) while the probe is in flight.
            std::future::pending::<()>().await;
        }
        let amount_in = if self.mismatch_amount {
            request.amount_in.saturating_add(1)
        } else {
            request.amount_in
        };
        let observed_at_ms = if self.future {
            request.observed_at_ms.saturating_add(60_000)
        } else {
            request.observed_at_ms
        };
        ProviderQuote::new(
            self.label.clone(),
            request.chain.clone(),
            request.token_in.clone(),
            request.token_out.clone(),
            amount_in,
            self.amount_out,
            observed_at_ms,
            "opaque-reference",
        )
        .map_err(|_| ProviderQuoteSourceError::Rejected)
    }
}

fn compared(outcome: &BenchmarkOutcome) -> (&BenchmarkVerdict, &BenchmarkMeta) {
    match outcome {
        BenchmarkOutcome::Compared { verdict, meta, .. } => (verdict, meta),
        other => panic!("expected Compared, got {other:?}"),
    }
}

fn skip_reason(outcome: &BenchmarkOutcome) -> BenchmarkSkipReason {
    match outcome {
        BenchmarkOutcome::Skipped { reason, .. } => *reason,
        other => panic!("expected Skipped, got {other:?}"),
    }
}

async fn run(
    source: Arc<ScriptedSource>,
    policy: BenchmarkServicePolicy,
    request: &BenchmarkRequest,
    now_ms: i64,
) -> BenchmarkOutcome {
    let mut service =
        ProviderBenchmarkService::new(source, policy, BASE_MS as u64).expect("service builds");
    service.benchmark(request, now_ms).await
}

#[tokio::test]
async fn exact_vectors_match_the_comparator() {
    let cases = [
        (
            10_100u128,
            BenchmarkVerdict::Disagree {
                deviation_bps: 100,
                direction: BenchmarkDirection::LocalBetter,
            },
        ),
        (
            9_900,
            BenchmarkVerdict::Disagree {
                deviation_bps: 100,
                direction: BenchmarkDirection::ProviderBetter,
            },
        ),
        (
            10_000,
            BenchmarkVerdict::Agree {
                deviation_bps: 0,
                direction: BenchmarkDirection::LocalBetter,
            },
        ),
    ];
    for (local_out, expected) in cases {
        let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
        let outcome = run(
            source.clone(),
            policy(label("okx")),
            &request_at(1_000, local_out, BASE_MS),
            BASE_MS,
        )
        .await;
        let (verdict, meta) = compared(&outcome);
        assert_eq!(*verdict, expected);
        assert_eq!(meta.cache_state, CacheState::Miss);
        assert_eq!(meta.request_cost, 3);
        assert_eq!(source.calls(), 1);
    }
}

#[tokio::test]
async fn budget_exhaustion_skips_without_touching_the_provider() {
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 1, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));
    assert_eq!(source.calls(), 1);

    // A fresh cache hit never charges budget.
    let hit = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    let (_, meta) = compared(&hit);
    assert_eq!(meta.cache_state, CacheState::FreshHit);
    assert_eq!(meta.request_cost, 0);
    assert_eq!(source.calls(), 1);

    // A miss with an exhausted budget degrades and never calls the provider.
    let denied = service
        .benchmark(&request_at(2_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&denied),
        BenchmarkSkipReason::Degraded(DegradedReason::BudgetExhausted)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn open_circuit_degrades_and_negative_caches() {
    let source = Arc::new(ScriptedSource::failing(label("okx"), None));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 1, 10_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);

    // A different basis sees the open circuit (cooldown) without a fetch.
    let second = service
        .benchmark(&request_at(2_000, 10_000, BASE_MS + 1_000), BASE_MS + 1_000)
        .await;
    assert_eq!(
        skip_reason(&second),
        BenchmarkSkipReason::Degraded(DegradedReason::CooldownActive)
    );
    assert_eq!(source.calls(), 1);

    // The failed basis is negatively cached.
    let third = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 1_000), BASE_MS + 1_000)
        .await;
    assert_eq!(
        skip_reason(&third),
        BenchmarkSkipReason::Degraded(DegradedReason::NegativeCached)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn stale_cache_serves_a_fallback_under_outage() {
    let source = Arc::new(ScriptedSource::failing_after(label("okx"), 10_000, 2));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));

    // Reuse the same cached entry under a failing source at a stale age beyond
    // the comparator's provider max age: a real (skipped-verdict) comparison is
    // still produced from the fallback.
    let stale = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 7_000), BASE_MS + 7_000)
        .await;
    let (verdict, meta) = compared(&stale);
    assert_eq!(
        *verdict,
        BenchmarkVerdict::Skipped(routing::BenchmarkSkip::ProviderStale)
    );
    assert_eq!(meta.cache_state, CacheState::StaleServed);
    assert_eq!(
        meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 2);
}

#[tokio::test]
async fn budget_denied_refresh_serves_an_in_age_fallback() {
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
    // Capacity 1: the first fetch exhausts it, so the refresh is budget-denied.
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 1, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));

    // Age 2001ms is stale but still within the 5s provider age, so the fallback
    // produces a real verdict degraded by BudgetExhausted.
    let degraded = service
        .benchmark(&request_at(1_000, 9_000, BASE_MS + 2_001), BASE_MS + 2_001)
        .await;
    let (verdict, meta) = compared(&degraded);
    assert!(matches!(
        verdict,
        BenchmarkVerdict::Disagree { .. } | BenchmarkVerdict::Agree { .. }
    ));
    assert_eq!(meta.cache_state, CacheState::StaleServed);
    assert_eq!(meta.degraded_reason, Some(DegradedReason::BudgetExhausted));
    assert_eq!(meta.request_cost, 0);
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn candidate_and_large_order_gates_precede_any_spend() {
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(
            label("okx"),
            1,
            10,
            5,
            2_000,
            30_000,
            5_000,
            3,
            15_000,
            1_000_000,
        ),
        BASE_MS as u64,
    )
    .expect("service builds");

    // Ineligible candidate.
    let ineligible = BenchmarkRequest {
        local: local_at(2_000_000, 10_000, BASE_MS),
        candidate: candidate(10, 100),
        priority: RequestPriority::Normal,
    };
    let outcome = service.benchmark(&ineligible, BASE_MS).await;
    assert_eq!(
        skip_reason(&outcome),
        BenchmarkSkipReason::CandidateNotEligible
    );
    assert_eq!(source.calls(), 0);

    // Below the large-order threshold.
    let small = service
        .benchmark(&request_at(999_999, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&small),
        BenchmarkSkipReason::BelowLargeOrderThreshold
    );
    assert_eq!(source.calls(), 0);

    // Structurally invalid bases.
    for invalid in [
        request_at(0, 10_000, BASE_MS),
        request_at(2_000_000, 0, BASE_MS),
    ] {
        let outcome = service.benchmark(&invalid, BASE_MS).await;
        assert_eq!(
            skip_reason(&outcome),
            BenchmarkSkipReason::ComparatorRejected
        );
    }
    assert_eq!(source.calls(), 0);
}

#[tokio::test]
async fn unavailable_source_default_degrades_then_negative_caches() {
    let source = Arc::new(UnavailableProviderQuoteSource);
    let mut service = ProviderBenchmarkService::new(source, policy(label("okx")), BASE_MS as u64)
        .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    let second = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&second),
        BenchmarkSkipReason::Degraded(DegradedReason::NegativeCached)
    );
}

#[tokio::test]
async fn cache_hit_bypasses_an_open_circuit() {
    let source = Arc::new(ScriptedSource::failing(label("okx"), Some(2_000)));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 1, 10_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    // Cache basis A, then trip the circuit via basis B.
    let cached = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(cached, BenchmarkOutcome::Compared { .. }));
    let trip = service
        .benchmark(&request_at(2_000, 10_000, BASE_MS + 1_000), BASE_MS + 1_000)
        .await;
    assert_eq!(
        skip_reason(&trip),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );

    // A fresh hit on A is still served despite the open circuit.
    let hit = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 1_500), BASE_MS + 1_500)
        .await;
    let (_, meta) = compared(&hit);
    assert_eq!(meta.cache_state, CacheState::FreshHit);
    assert_eq!(source.calls(), 2);
}

#[tokio::test]
async fn low_priority_is_shed_under_pressure() {
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 1, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    // Exhaust the single budget unit.
    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));

    let low = BenchmarkRequest {
        local: local_at(2_000, 10_000, BASE_MS + 1_000),
        candidate: candidate(100, 50),
        priority: RequestPriority::Low,
    };
    let shed = service.benchmark(&low, BASE_MS + 1_000).await;
    assert_eq!(
        skip_reason(&shed),
        BenchmarkSkipReason::Degraded(DegradedReason::LowPriorityShed)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn unbound_quotes_are_negatively_cached() {
    let source = Arc::new(ScriptedSource::mismatching_amount(label("okx"), 10_000));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    let second = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&second),
        BenchmarkSkipReason::Degraded(DegradedReason::NegativeCached)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn future_quotes_are_unbound() {
    let source = Arc::new(ScriptedSource::from_the_future(label("okx"), 10_000));
    let outcome = run(
        source.clone(),
        policy(label("okx")),
        &request_at(1_000, 10_000, BASE_MS),
        BASE_MS,
    )
    .await;
    assert_eq!(
        skip_reason(&outcome),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn budget_denied_before_probe_does_not_strand_the_circuit() {
    // request_cost=1, capacity=1, refill=1/s, threshold=1, cooldown=10ms.
    let source = Arc::new(ScriptedSource::failing(label("okx"), Some(1)));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 1, 1, 2_000, 30_000, 5_000, 1, 10, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    // t=1000: the basis-1 fetch fails, tripping the circuit and consuming the
    // single budget unit.
    let first = service
        .benchmark(&request_at(1, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);

    // t=1010: the cooldown has elapsed (health is Degraded) but the budget has
    // not refilled. Budget must be denied BEFORE the half-open probe is taken.
    let denied = service
        .benchmark(&request_at(2, 10_000, BASE_MS + 10), BASE_MS + 10)
        .await;
    assert_eq!(
        denied,
        BenchmarkOutcome::Skipped {
            reason: BenchmarkSkipReason::Degraded(DegradedReason::BudgetExhausted),
            meta: BenchmarkMeta {
                cache_state: CacheState::Miss,
                degraded_reason: Some(DegradedReason::BudgetExhausted),
                request_cost: 0,
            },
        }
    );
    assert_eq!(
        source.calls(),
        1,
        "a budget-denied request must not reach the provider"
    );

    // t=2500: the budget has refilled; if the probe had been stranded at t=1010
    // this would be CooldownActive instead of a real comparison.
    let recovered = service
        .benchmark(&request_at(3, 10_000, BASE_MS + 1_500), BASE_MS + 1_500)
        .await;
    assert!(
        matches!(recovered, BenchmarkOutcome::Compared { .. }),
        "budget-denied probe was stranded; outcome = {recovered:?}"
    );
    assert_eq!(source.calls(), 2);
}

#[tokio::test]
async fn bound_but_comparator_rejected_quote_is_negatively_cached() {
    // The quote binds the basis exactly but has zero output, which the
    // comparator structurally rejects.
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 0));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);

    // A malformed quote cached positively would be a fresh hit here; it must be
    // a negative-cache hit with no refetch.
    let second = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&second),
        BenchmarkSkipReason::Degraded(DegradedReason::NegativeCached)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn negative_reference_time_skips_without_calling_the_source() {
    let source = Arc::new(ScriptedSource::quoting(label("okx"), 10_000));
    let outcome = run(
        source.clone(),
        policy(label("okx")),
        &request_at(1_000, 10_000, BASE_MS),
        -1,
    )
    .await;
    assert_eq!(
        skip_reason(&outcome),
        BenchmarkSkipReason::InvalidReferenceTime
    );
    assert_eq!(source.calls(), 0);
}

#[tokio::test]
async fn negative_entry_prefers_a_stale_fallback() {
    // Call 1 succeeds; call 2 (a stale-age refresh) fails and negative-caches
    // the key while the positive data entry is still present.
    let source = Arc::new(ScriptedSource::failing_after(label("okx"), 10_000, 2));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));

    let refresh_failed = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 2_001), BASE_MS + 2_001)
        .await;
    let (_, meta) = compared(&refresh_failed);
    assert_eq!(meta.cache_state, CacheState::StaleServed);
    assert_eq!(
        meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 2);

    // The key now has an active negative entry alongside the positive data: the
    // negative hit must still serve the present stale fallback without a fetch.
    let stale_served = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 2_500), BASE_MS + 2_500)
        .await;
    let (_, meta) = compared(&stale_served);
    assert_eq!(meta.cache_state, CacheState::StaleServed);
    assert_eq!(meta.degraded_reason, Some(DegradedReason::NegativeCached));
    assert_eq!(meta.request_cost, 0);
    assert_eq!(source.calls(), 2);
}

#[tokio::test]
async fn expired_entry_refreshes_with_fallback() {
    // fresh_ttl=2s, stale_grace=3s: an age beyond 5s is Expired, not a hit.
    let source = Arc::new(ScriptedSource::failing_after(label("okx"), 10_000, 2));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 3_000, 5_000, 3, 15_000, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    let first = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS), BASE_MS)
        .await;
    assert!(matches!(first, BenchmarkOutcome::Compared { .. }));

    // Age 5_001ms > fresh_ttl + stale_grace (5_000): Expired -> refresh, and the
    // failed refresh serves the expired entry as a degraded fallback.
    let expired = service
        .benchmark(&request_at(1_000, 10_000, BASE_MS + 5_001), BASE_MS + 5_001)
        .await;
    let (verdict, meta) = compared(&expired);
    assert_eq!(
        *verdict,
        BenchmarkVerdict::Skipped(routing::BenchmarkSkip::ProviderStale)
    );
    assert_eq!(meta.cache_state, CacheState::StaleServed);
    assert_eq!(
        meta.degraded_reason,
        Some(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 2);
}

#[tokio::test]
async fn quote_with_a_different_source_label_is_unbound() {
    // The quote binds chain/pair/amount but reports another source label, so it
    // must be rejected rather than compared against the configured source.
    let source = Arc::new(ScriptedSource::quoting(label("other"), 10_000));
    let outcome = run(
        source.clone(),
        policy(label("okx")),
        &request_at(1_000, 10_000, BASE_MS),
        BASE_MS,
    )
    .await;
    assert_eq!(
        skip_reason(&outcome),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn cancelled_fetch_releases_the_half_open_probe() {
    use std::time::Duration;

    // Fails basis 1 on call 1, hangs on call 2, then quotes normally.
    let source = Arc::new(ScriptedSource::failing_then_hanging(
        label("okx"),
        Some(1),
        2,
    ));
    let mut service = ProviderBenchmarkService::new(
        source.clone(),
        policy_with(label("okx"), 1, 10, 0, 2_000, 30_000, 5_000, 1, 10, 1),
        BASE_MS as u64,
    )
    .expect("service builds");

    // t=1000: basis 1 fails, tripping the circuit open until t=1010.
    let first = service
        .benchmark(&request_at(1, 10_000, BASE_MS), BASE_MS)
        .await;
    assert_eq!(
        skip_reason(&first),
        BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable)
    );
    assert_eq!(source.calls(), 1);

    // t=1010: the half-open probe hangs; the caller times out, dropping (and
    // thus cancelling) the benchmark future mid-fetch.
    let timed_out = tokio::time::timeout(
        Duration::from_millis(20),
        service.benchmark(&request_at(2, 10_000, BASE_MS + 10), BASE_MS + 10),
    )
    .await;
    assert!(timed_out.is_err(), "the hanging fetch should time out");

    // t=1030: the cancelled probe must have been recorded as a failure, so a
    // fresh basis can take the next probe and recover.
    let recovered = service
        .benchmark(&request_at(3, 10_000, BASE_MS + 30), BASE_MS + 30)
        .await;
    assert!(
        matches!(recovered, BenchmarkOutcome::Compared { .. }),
        "cancelled probe was stranded; outcome = {recovered:?}"
    );
    assert_eq!(source.calls(), 3);
}

#[tokio::test]
async fn identical_inputs_produce_identical_outcomes() {
    let first = run(
        Arc::new(ScriptedSource::quoting(label("okx"), 10_000)),
        policy(label("okx")),
        &request_at(1_000, 10_000, BASE_MS),
        BASE_MS,
    )
    .await;
    let second = run(
        Arc::new(ScriptedSource::quoting(label("okx"), 10_000)),
        policy(label("okx")),
        &request_at(1_000, 10_000, BASE_MS),
        BASE_MS,
    )
    .await;
    assert_eq!(first, second);
}

#[test]
fn debug_output_is_redacted() {
    let sentinel_amount = 987_654_321u128;
    let sentinel_reference = "deadbeefdeadbeef";
    let quote = ProviderQuote::new(
        label("okx"),
        ChainId::Base,
        weth(),
        usdc(),
        1_000,
        10_000,
        BASE_MS,
        sentinel_reference,
    )
    .expect("valid quote");
    let request = BenchmarkRequest {
        local: local_at(sentinel_amount, 10_000, BASE_MS),
        candidate: candidate(100, 50),
        priority: RequestPriority::Normal,
    };
    let outcome = BenchmarkOutcome::Compared {
        verdict: BenchmarkVerdict::Agree {
            deviation_bps: 0,
            direction: BenchmarkDirection::LocalBetter,
        },
        record: routing::RouteComparisonRecord::new(
            &local_at(sentinel_amount, 10_000, BASE_MS),
            &quote,
            BenchmarkVerdict::Agree {
                deviation_bps: 0,
                direction: BenchmarkDirection::LocalBetter,
            },
        ),
        meta: BenchmarkMeta {
            cache_state: CacheState::Miss,
            degraded_reason: None,
            request_cost: 3,
        },
    };
    let provider_request = ProviderQuoteRequest {
        chain: ChainId::Base,
        token_in: weth(),
        token_out: usdc(),
        amount_in: sentinel_amount,
        observed_at_ms: BASE_MS,
    };
    let rendered = format!(
        "{request:?} {outcome:?} {provider_request:?} {:?} {:?}",
        ProviderQuoteSourceError::Unavailable,
        BenchmarkSkipReason::ComparatorRejected,
    );
    for sentinel in ["987654321", sentinel_reference] {
        assert!(
            !rendered.contains(sentinel),
            "redacted Debug leaked {sentinel}: {rendered}"
        );
    }
}

#[test]
fn trading_is_disabled() {
    const { assert!(!TRADING_ENABLED) };
}
