//! P93 provider-benchmark loop tests.
//!
//! These exercise the observational seam in isolation: a scripted port, a
//! scripted request source, and a recording sink. They prove the loop records
//! only real comparisons, is bounded, is inert with no work, never touches the
//! execution path, and is not built when the composition seams are absent.

mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_backend::FixedClock;
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::RoutePlan;
use execution_preview::NetDelta;
use provider_benchmark::{BenchmarkMeta, BenchmarkOutcome, BenchmarkRequest, BenchmarkSkipReason};
use provider_broker::{CacheState, CandidateContext, RequestPriority};
use routing::{
    BenchmarkDirection, BenchmarkSource, BenchmarkVerdict, LocalRouteQuote, ProviderQuote,
    RouteComparisonRecord, RouteQuote,
};
use trading_core::benchmark::{
    benchmark_request_from_preview, BenchmarkRequestSource, EmptyBenchmarkRequestSource,
    NoopRouteComparisonRecordSink, ProviderBenchmarkLoop, ProviderBenchmarkPort,
    RouteComparisonRecordSink, MAX_BENCHMARK_REQUESTS_PER_PASS,
};
use trading_core::composition::{TradingCore, TradingCoreSeams};

use support::{
    amount_of, asset_id, config, disabled_policy, freshness, lock, FixedOrderKeys,
    InMemoryOpaqueStore, NOW,
};

fn token_in() -> AssetId {
    asset_id("USDC")
}

fn token_out() -> AssetId {
    asset_id("TOKEN")
}

fn local_basis(now_ms: i64) -> LocalRouteQuote {
    LocalRouteQuote::new(ChainId::Base, token_in(), token_out(), 1_000, 200, now_ms)
}

fn provider_quote() -> ProviderQuote {
    ProviderQuote::new(
        BenchmarkSource::new("okx").expect("source"),
        ChainId::Base,
        token_in(),
        token_out(),
        1_000,
        190,
        NOW,
        "okx-quote-ref",
    )
    .expect("provider quote")
}

fn compared_outcome(deviation_bps: u16) -> BenchmarkOutcome {
    let local = local_basis(NOW);
    let provider = provider_quote();
    let verdict = BenchmarkVerdict::Agree {
        deviation_bps,
        direction: BenchmarkDirection::LocalBetter,
    };
    let record = RouteComparisonRecord::new(&local, &provider, verdict);
    BenchmarkOutcome::Compared {
        verdict,
        record,
        meta: BenchmarkMeta {
            cache_state: CacheState::Miss,
            degraded_reason: None,
            request_cost: 1,
        },
    }
}

fn skipped_outcome() -> BenchmarkOutcome {
    BenchmarkOutcome::Skipped {
        reason: BenchmarkSkipReason::CandidateNotEligible,
        meta: BenchmarkMeta {
            cache_state: CacheState::Miss,
            degraded_reason: None,
            request_cost: 0,
        },
    }
}

fn request(now_ms: i64) -> BenchmarkRequest {
    BenchmarkRequest {
        local: local_basis(now_ms),
        candidate: CandidateContext::new("candidate-1", 10, 5),
        priority: RequestPriority::High,
    }
}

/// Scripted port: pops one outcome per call and counts calls.
struct ScriptedPort {
    outcomes: Mutex<VecDeque<BenchmarkOutcome>>,
    calls: AtomicUsize,
}

impl ScriptedPort {
    fn new(outcomes: Vec<BenchmarkOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from(outcomes)),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ProviderBenchmarkPort for ScriptedPort {
    async fn evaluate(&self, _request: BenchmarkRequest, _now_ms: i64) -> BenchmarkOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.outcomes).pop_front().expect("scripted outcome")
    }
}

/// Port that panics if it is ever asked to evaluate.
struct PanickingPort;

#[async_trait]
impl ProviderBenchmarkPort for PanickingPort {
    async fn evaluate(&self, _request: BenchmarkRequest, _now_ms: i64) -> BenchmarkOutcome {
        panic!("the benchmark port must not be called")
    }
}

/// Source that ignores the per-pass bound, to prove the loop truncates.
struct FixedCountSource {
    count: usize,
}

impl BenchmarkRequestSource for FixedCountSource {
    fn next_requests(&self, now_ms: i64, _max: usize) -> Vec<BenchmarkRequest> {
        (0..self.count).map(|_| request(now_ms)).collect()
    }
}

/// Sink that records the deviation of every comparison it is handed.
struct RecordingSink {
    deviations: Mutex<Vec<u16>>,
}

impl RecordingSink {
    fn new() -> Self {
        Self {
            deviations: Mutex::new(Vec::new()),
        }
    }
}

impl RouteComparisonRecordSink for RecordingSink {
    fn record(&self, record: RouteComparisonRecord) {
        lock(&self.deviations).push(record.deviation_bps());
    }
}

fn build_quote() -> RouteQuote {
    let token_in = token_in();
    let token_out = token_out();
    RouteQuote {
        plan: RoutePlan {
            legs: Vec::new(),
            expected_net_output: amount_of(token_out.clone(), 200),
            state: freshness(),
        },
        net_delta: NetDelta {
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            net_input: amount_of(token_in, 1_000),
            gross_output: amount_of(token_out.clone(), 250),
            net_output: amount_of(token_out.clone(), 200),
            dex_fee: None,
            tax_cost: None,
        },
        hop_quotes: Vec::new(),
        gross_output: amount_of(token_out.clone(), 250),
        net_output: amount_of(token_out, 200),
        tax_cost: None,
        route_impact_bps: None,
    }
}

#[tokio::test]
async fn pass_records_compared_and_counts_skipped() {
    let port = Arc::new(ScriptedPort::new(vec![
        compared_outcome(7),
        skipped_outcome(),
    ]));
    let sink = Arc::new(RecordingSink::new());
    let loop_ = ProviderBenchmarkLoop::new(
        port.clone(),
        sink.clone(),
        Arc::new(FixedCountSource { count: 2 }),
        MAX_BENCHMARK_REQUESTS_PER_PASS,
    );

    let report = loop_.run_pass(NOW).await;

    assert_eq!(report.requested, 2);
    assert_eq!(report.compared, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(port.calls(), 2);
    assert_eq!(*lock(&sink.deviations), vec![7]);
}

#[tokio::test]
async fn empty_source_never_calls_the_port() {
    let port = Arc::new(PanickingPort);
    let sink = Arc::new(RecordingSink::new());
    let loop_ = ProviderBenchmarkLoop::new(
        port,
        sink.clone(),
        Arc::new(EmptyBenchmarkRequestSource),
        MAX_BENCHMARK_REQUESTS_PER_PASS,
    );

    let report = loop_.run_pass(NOW).await;

    assert_eq!(report, Default::default());
    assert!(lock(&sink.deviations).is_empty());
}

#[tokio::test]
async fn a_misbehaving_source_is_truncated_to_the_per_pass_bound() {
    let port = Arc::new(ScriptedPort::new(vec![
        compared_outcome(1),
        compared_outcome(2),
    ]));
    let sink = Arc::new(RecordingSink::new());
    let loop_ = ProviderBenchmarkLoop::new(
        port.clone(),
        sink,
        Arc::new(FixedCountSource { count: 10 }),
        2,
    );

    let report = loop_.run_pass(NOW).await;

    assert_eq!(report.requested, 2);
    assert_eq!(port.calls(), 2);
}

#[test]
fn zero_per_pass_uses_the_hard_cap() {
    let loop_ = ProviderBenchmarkLoop::new(
        Arc::new(PanickingPort),
        Arc::new(NoopRouteComparisonRecordSink),
        Arc::new(EmptyBenchmarkRequestSource),
        0,
    );
    assert_eq!(loop_.max_per_pass(), MAX_BENCHMARK_REQUESTS_PER_PASS);

    let clamped = ProviderBenchmarkLoop::new(
        Arc::new(PanickingPort),
        Arc::new(NoopRouteComparisonRecordSink),
        Arc::new(EmptyBenchmarkRequestSource),
        MAX_BENCHMARK_REQUESTS_PER_PASS + 1_000,
    );
    assert_eq!(clamped.max_per_pass(), MAX_BENCHMARK_REQUESTS_PER_PASS);
}

#[test]
fn benchmark_request_binds_the_exact_net_basis() {
    let quote = build_quote();
    let candidate = CandidateContext::new("candidate-9", 42, 10);
    let request =
        benchmark_request_from_preview(&quote, candidate.clone(), RequestPriority::High, 5_000);

    assert_eq!(request.local.chain, ChainId::Base);
    assert_eq!(request.local.token_in, token_in());
    assert_eq!(request.local.token_out, token_out());
    assert_eq!(request.local.amount_in, 1_000);
    assert_eq!(request.local.amount_out, 200);
    assert_eq!(request.local.observed_at_ms, 5_000);
    assert_eq!(request.candidate, candidate);
    assert_eq!(request.priority, RequestPriority::High);
}

#[test]
fn loop_debug_renders_no_payload() {
    let loop_ = ProviderBenchmarkLoop::new(
        Arc::new(PanickingPort),
        Arc::new(NoopRouteComparisonRecordSink),
        Arc::new(FixedCountSource { count: 1 }),
        3,
    );
    let debug = format!("{loop_:?}");
    assert!(debug.starts_with("ProviderBenchmarkLoop"));
    assert!(debug.contains("max_per_pass: 3"));
    assert!(!debug.contains("USDC"));
    assert!(!debug.contains("TOKEN"));
    assert!(!debug.contains('1'), "no local amounts render: {debug}");
}

#[tokio::test]
async fn absent_seams_build_no_loop() {
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    assert!(core.provider_benchmark_loop().is_none());
}

#[tokio::test]
async fn wired_seams_build_a_loop_that_records() {
    let port = Arc::new(ScriptedPort::new(vec![compared_outcome(3)]));
    let sink = Arc::new(RecordingSink::new());
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            provider_benchmark: Some(port.clone()),
            provider_benchmark_sink: Some(sink.clone()),
            provider_benchmark_requests: Some(Arc::new(FixedCountSource { count: 1 })),
            ..Default::default()
        },
    );

    let loop_ = core.provider_benchmark_loop().expect("loop is wired");
    let report = loop_.run_pass(NOW).await;

    assert_eq!(report.compared, 1);
    assert_eq!(port.calls(), 1);
    assert_eq!(*lock(&sink.deviations), vec![3]);
}

/// A port-only seam (no request source) must not build a loop.
#[tokio::test]
async fn port_without_a_source_builds_no_loop() {
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            provider_benchmark: Some(Arc::new(PanickingPort)),
            ..Default::default()
        },
    );
    assert!(core.provider_benchmark_loop().is_none());
}

/// A source-only seam (no evaluator) must not build a loop.
#[tokio::test]
async fn source_without_a_port_builds_no_loop() {
    let core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            provider_benchmark_requests: Some(Arc::new(FixedCountSource { count: 1 })),
            ..Default::default()
        },
    );
    assert!(core.provider_benchmark_loop().is_none());
}

/// The benchmark path is observational: constructing a core with a wired loop
/// must leave reading/execution behavior identical to the default core.
#[tokio::test]
async fn wiring_the_benchmark_does_not_change_the_capabilities() {
    let default_core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams::default(),
    );
    let wired_core = TradingCore::new(
        config(),
        disabled_policy(),
        Arc::new(InMemoryOpaqueStore::new()),
        Arc::new(FixedOrderKeys),
        Arc::new(FixedClock(NOW)),
        TradingCoreSeams {
            provider_benchmark: Some(Arc::new(PanickingPort)),
            provider_benchmark_requests: Some(Arc::new(FixedCountSource { count: 1 })),
            ..Default::default()
        },
    );

    assert_eq!(
        default_core.trading_enabled_at_startup(),
        wired_core.trading_enabled_at_startup()
    );
    assert_eq!(
        format!("{:?}", default_core.capabilities()),
        format!("{:?}", wired_core.capabilities())
    );
}
