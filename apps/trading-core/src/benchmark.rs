//! P93 provider-benchmark evaluation seam for the composed Trading Core.
//!
//! This module wires the P87 [`ProviderBenchmarkService`] — and, through it,
//! the P80 comparator and the P92 OKX-backed quote source — into the runnable
//! composition root. It is the "record our route vs provider route" KPI path
//! described by `docs/PRD.md`:
//!
//! > Record our route vs provider route vs actual execution to discover missing
//! > direct adapters statistically.
//!
//! # Execution-independent (observational only)
//!
//! The benchmark loop is **never** on the execution path. It holds no signing,
//! relay, or market-execution dependency; it only evaluates provider quotes
//! against a local basis and hands the resulting [`RouteComparisonRecord`] to a
//! sink. A provider outage, budget exhaustion, an open circuit, or a sink that
//! does nothing can never fail a trade or change an outcome.
//!
//! # Bounded
//!
//! [`ProviderBenchmarkLoop::run_pass`] asks the injected
//! [`BenchmarkRequestSource`] for at most [`ProviderBenchmarkLoop::max_per_pass`]
//! requests, and additionally truncates a source that returns more. The request
//! count is capped by [`MAX_BENCHMARK_REQUESTS_PER_PASS`], so a misconfigured
//! interval cannot fan out an unbounded provider burst in one pass.
//!
//! # Fail-closed defaults and additivity
//!
//! [`TradingCoreSeams`](crate::composition::TradingCoreSeams) gains an optional
//! port and request source; when either is absent the composition root builds no
//! loop and behavior is byte-identical to the pre-P93 service. The default sink
//! is [`NoopRouteComparisonRecordSink`] and the default source is
//! [`EmptyBenchmarkRequestSource`].
//!
//! `#![forbid(unsafe_code)]`; no logging, no serialization, and payload-free
//! `Debug` on every wrapper. `TRADING_ENABLED` is unaffected.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use provider_benchmark::{BenchmarkOutcome, BenchmarkRequest, ProviderBenchmarkService};
use provider_broker::{CandidateContext, RequestPriority};
use routing::{LocalRouteQuote, RouteComparisonRecord, RouteQuote};

use crate::composition::ReconcileTick;

/// Hard cap on provider-benchmark requests evaluated in a single pass.
///
/// This is the only fan-out bound the loop applies: a source can never cause an
/// unbounded provider burst, regardless of the configured interval.
pub const MAX_BENCHMARK_REQUESTS_PER_PASS: usize = 16;

/// Async port over a provider-benchmark evaluator.
///
/// The default production adapter is [`SharedProviderBenchmark`]; tests inject
/// scripted implementations. An implementation must never panic and must return
/// a [`BenchmarkOutcome`] for every request (the P87 service always does).
#[async_trait]
pub trait ProviderBenchmarkPort: Send + Sync {
    /// Evaluates one benchmark request at `now_ms`.
    async fn evaluate(&self, request: BenchmarkRequest, now_ms: i64) -> BenchmarkOutcome;
}

/// Shared, serialized adapter over the P87 [`ProviderBenchmarkService`].
///
/// The service needs `&mut self`; this wrapper serializes access behind an async
/// mutex so one handle can be shared by the loop (and, if desired, other
/// observers) without a data race. `Debug` is payload-free.
pub struct SharedProviderBenchmark {
    service: tokio::sync::Mutex<ProviderBenchmarkService>,
}

impl SharedProviderBenchmark {
    /// Wraps a benchmark service for concurrent shared use.
    pub fn new(service: ProviderBenchmarkService) -> Self {
        Self {
            service: tokio::sync::Mutex::new(service),
        }
    }
}

impl fmt::Debug for SharedProviderBenchmark {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedProviderBenchmark")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ProviderBenchmarkPort for SharedProviderBenchmark {
    async fn evaluate(&self, request: BenchmarkRequest, now_ms: i64) -> BenchmarkOutcome {
        let mut service = self.service.lock().await;
        service.benchmark(&request, now_ms).await
    }
}

/// Consumer of "our route vs provider route" comparison records.
///
/// A sink persists or forwards records; it must be observational and must never
/// feed a result back into an execution decision.
pub trait RouteComparisonRecordSink: Send + Sync {
    /// Records one comparison. Amounts and assets stay private to the sink.
    fn record(&self, record: RouteComparisonRecord);
}

/// Fail-safe default: discards every record.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRouteComparisonRecordSink;

impl RouteComparisonRecordSink for NoopRouteComparisonRecordSink {
    fn record(&self, _record: RouteComparisonRecord) {}
}

/// Source of the bounded benchmark requests examined in one pass.
///
/// The source supplies the local comparison basis and the candidate gate; the
/// loop supplies the reference instant and the per-pass bound. Returning more
/// than the requested `max` is harmless: the loop truncates.
pub trait BenchmarkRequestSource: Send + Sync {
    /// Returns at most `max` requests to evaluate at `now_ms`.
    fn next_requests(&self, now_ms: i64, max: usize) -> Vec<BenchmarkRequest>;
}

/// Fail-safe default: yields no work, so a wired-but-empty loop is inert.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyBenchmarkRequestSource;

impl BenchmarkRequestSource for EmptyBenchmarkRequestSource {
    fn next_requests(&self, _now_ms: i64, _max: usize) -> Vec<BenchmarkRequest> {
        Vec::new()
    }
}

/// Builds the exact bound benchmark request for a local route preview.
///
/// The local basis is taken verbatim from the locked `RouteQuote`: the
/// wallet-debit net input and net output come from its `net_delta`, and the
/// local observation instant is the quote's own `plan.state.observed_at_ms` —
/// the same freshness timestamp the execution path derives its state age from.
/// The caller's comparison reference instant is supplied separately to
/// [`ProviderBenchmarkLoop::run_pass`], so the P80 local-state-staleness guard
/// stays live for a re-used or stale preview instead of being pinned to zero.
///
/// This is a pure constructor: no clock, network, or provider access.
pub fn benchmark_request_from_preview(
    quote: &RouteQuote,
    candidate: CandidateContext,
    priority: RequestPriority,
) -> BenchmarkRequest {
    let net = &quote.net_delta;
    let local = LocalRouteQuote::new(
        net.token_in.chain.clone(),
        net.token_in.clone(),
        net.token_out.clone(),
        net.net_input.amount.get(),
        net.net_output.amount.get(),
        quote.plan.state.observed_at_ms,
    );
    BenchmarkRequest {
        local,
        candidate,
        priority,
    }
}

/// Bounded provider-benchmark loop over an injected port, sink, and source.
pub struct ProviderBenchmarkLoop {
    port: Arc<dyn ProviderBenchmarkPort>,
    sink: Arc<dyn RouteComparisonRecordSink>,
    source: Arc<dyn BenchmarkRequestSource>,
    max_per_pass: usize,
}

impl ProviderBenchmarkLoop {
    /// Wires a loop from its observational ports.
    ///
    /// `max_per_pass == 0` selects [`MAX_BENCHMARK_REQUESTS_PER_PASS`]; any
    /// larger value is clamped to that cap, so the loop can never evaluate more
    /// than the cap in one pass.
    pub fn new(
        port: Arc<dyn ProviderBenchmarkPort>,
        sink: Arc<dyn RouteComparisonRecordSink>,
        source: Arc<dyn BenchmarkRequestSource>,
        max_per_pass: usize,
    ) -> Self {
        let max_per_pass = if max_per_pass == 0 {
            MAX_BENCHMARK_REQUESTS_PER_PASS
        } else {
            max_per_pass.min(MAX_BENCHMARK_REQUESTS_PER_PASS)
        };
        Self {
            port,
            sink,
            source,
            max_per_pass,
        }
    }

    /// The effective per-pass request bound (`1..=MAX_BENCHMARK_REQUESTS_PER_PASS`).
    pub fn max_per_pass(&self) -> usize {
        self.max_per_pass
    }

    /// Runs one bounded, observational pass at `now_ms`.
    ///
    /// Exactly one benchmark evaluation is issued per returned request, in
    /// order. A `Compared` outcome is handed to the sink; a `Skipped` outcome is
    /// counted and never recorded. The loop never calls `execute`, signs,
    /// submits, reserves, or mutates market state.
    pub async fn run_pass(&self, now_ms: i64) -> ProviderBenchmarkPassReport {
        let requests = self.source.next_requests(now_ms, self.max_per_pass);
        let mut report = ProviderBenchmarkPassReport::default();
        for request in requests.into_iter().take(self.max_per_pass) {
            report.requested += 1;
            match self.port.evaluate(request, now_ms).await {
                BenchmarkOutcome::Compared { record, .. } => {
                    report.compared += 1;
                    self.sink.record(record);
                }
                BenchmarkOutcome::Skipped { .. } => {
                    report.skipped += 1;
                }
            }
        }
        report
    }
}

impl fmt::Debug for ProviderBenchmarkLoop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: the port/sink/source payloads and any local basis stay
        // hidden; only the non-secret bound renders.
        formatter
            .debug_struct("ProviderBenchmarkLoop")
            .field("max_per_pass", &self.max_per_pass)
            .finish_non_exhaustive()
    }
}

/// Counts for one benchmark pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderBenchmarkPassReport {
    /// Requests returned by the source and evaluated.
    pub requested: u64,
    /// Evaluations that produced a comparison record.
    pub compared: u64,
    /// Evaluations that were skipped (gated, degraded, or budget-exhausted).
    pub skipped: u64,
}

/// Accumulated counts across a benchmark run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderBenchmarkRunReport {
    /// Number of completed passes.
    pub passes: u64,
    /// Total requests evaluated.
    pub requested: u64,
    /// Total comparisons recorded.
    pub compared: u64,
    /// Total evaluations skipped.
    pub skipped: u64,
}

impl ProviderBenchmarkRunReport {
    /// Folds one pass into the accumulated report.
    pub fn absorb(&mut self, pass: ProviderBenchmarkPassReport) {
        self.passes += 1;
        self.requested += pass.requested;
        self.compared += pass.compared;
        self.skipped += pass.skipped;
    }
}

/// Runs benchmark passes until the tick is exhausted.
///
/// The tick owns the stop condition (for example a graceful shutdown watch), so
/// the run is unbounded in pass count but bounded in work per pass. The loop is
/// observational: stopping it never affects execution.
pub async fn run_provider_benchmark_loop<K: ReconcileTick + ?Sized>(
    benchmark: &ProviderBenchmarkLoop,
    tick: &mut K,
) -> ProviderBenchmarkRunReport {
    let mut report = ProviderBenchmarkRunReport::default();
    while let Some(now_ms) = tick.next_tick().await {
        report.absorb(benchmark.run_pass(now_ms).await);
    }
    report
}
