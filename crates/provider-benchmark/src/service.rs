//! The budgeted, candidate-gated provider-route benchmark service.

use std::fmt;
use std::sync::Arc;

use provider_broker::{
    CacheLookup, CacheState, CandidateContext, CircuitBreaker, DegradedReason, LogicalCache,
    LogicalRequestKey, OpaqueFailureKind, ProviderBudget, ProviderHealthState, ProviderId,
    RequestContext, RequestPriority,
};
use routing::{
    compare_route, BenchmarkError, BenchmarkVerdict, LocalRouteQuote, ProviderQuote,
    RouteComparisonRecord,
};

use crate::policy::{BenchmarkPolicyError, BenchmarkServicePolicy};
use crate::provider::{ProviderQuoteRequest, ProviderQuoteSource};

/// Canonical cache operation name; isolates benchmark entries from every other
/// broker operation sharing the cache namespace.
const BENCHMARK_OPERATION: &str = "provider_benchmark";

/// Prune the cache every this many calls (bounded housekeeping).
const PRUNE_INTERVAL_CALLS: u64 = 256;

/// One candidate-gated benchmark request against the exact local route basis.
pub struct BenchmarkRequest {
    /// Exact local route economics for the comparison basis.
    pub local: LocalRouteQuote,
    /// Candidate identity/score that gates the expensive provider call.
    pub candidate: CandidateContext,
    /// Request priority for pressure shedding.
    pub priority: RequestPriority,
}

impl fmt::Debug for BenchmarkRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: the local basis and candidate identity are private
        // execution economics.
        formatter
            .debug_struct("BenchmarkRequest")
            .finish_non_exhaustive()
    }
}

/// Why a benchmark was skipped without a comparison verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkSkipReason {
    /// The candidate did not meet its minimum score threshold.
    CandidateNotEligible,
    /// The input is below the configured large-order threshold.
    BelowLargeOrderThreshold,
    /// The comparison basis was structurally invalid for the comparator.
    ComparatorRejected,
    /// The caller supplied a negative reference time.
    InvalidReferenceTime,
    /// The service degraded for a budget/cache/circuit/provider reason.
    Degraded(DegradedReason),
}

/// Bounded, redacted metadata attached to every benchmark outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkMeta {
    /// How the request was served (or that it was not cached).
    pub cache_state: CacheState,
    /// Why the result is degraded, if it is.
    pub degraded_reason: Option<DegradedReason>,
    /// Cost charged to the budget; non-zero only after an actual provider fetch.
    pub request_cost: u32,
}

/// Result of one benchmark attempt.
///
/// The service always returns an outcome: a gated, budget-exhausted, or degraded
/// call yields [`BenchmarkOutcome::Skipped`] rather than an error, so a provider
/// outage can never fail a caller or an execution path. Deliberately not
/// `Serialize`/`Deserialize`.
#[derive(Clone, PartialEq, Eq)]
pub enum BenchmarkOutcome {
    /// The local and provider quotes were compared.
    Compared {
        /// Exact comparator verdict.
        verdict: BenchmarkVerdict,
        /// Redacted analytics record for "our route vs provider route".
        record: RouteComparisonRecord,
        /// Bounded metadata.
        meta: BenchmarkMeta,
    },
    /// No comparison was produced; see [`BenchmarkSkipReason`].
    Skipped {
        /// Why the comparison was skipped.
        reason: BenchmarkSkipReason,
        /// Bounded metadata.
        meta: BenchmarkMeta,
    },
}

impl fmt::Debug for BenchmarkOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: the record and metadata never render amounts/assets.
        match self {
            Self::Compared { verdict, meta, .. } => formatter
                .debug_struct("BenchmarkOutcome::Compared")
                .field("verdict", verdict)
                .field("meta", meta)
                .finish_non_exhaustive(),
            Self::Skipped { reason, meta } => formatter
                .debug_struct("BenchmarkOutcome::Skipped")
                .field("reason", reason)
                .field("meta", meta)
                .finish_non_exhaustive(),
        }
    }
}

/// Budgeted, candidate-gated provider-route benchmark service.
///
/// # Invariants
/// - **No execution effect.** The service holds no signing/relay/execution
///   dependency and only returns an analytics outcome.
/// - **Never fabricate.** A verdict is only the output of
///   [`routing::compare_route`]; a served quote must bind the exact requested
///   basis and must not be from the future.
/// - **Candidate/large-order gating precedes any spend.** An ineligible
///   candidate or a below-threshold input touches no cache, budget, circuit, or
///   provider.
/// - **Cache hits never charge.** The circuit is only consulted on a refresh
///   path; a fresh/stale hit never consumes a half-open probe.
pub struct ProviderBenchmarkService {
    source: Arc<dyn ProviderQuoteSource>,
    policy: BenchmarkServicePolicy,
    budget: ProviderBudget,
    circuit: CircuitBreaker,
    cache: LogicalCache,
    calls: u64,
}

impl ProviderBenchmarkService {
    /// Builds a service, validating the policy before any state is created.
    pub fn new(
        source: Arc<dyn ProviderQuoteSource>,
        policy: BenchmarkServicePolicy,
        start_ms: u64,
    ) -> Result<Self, BenchmarkPolicyError> {
        policy.validate()?;
        let budget = ProviderBudget::new(
            policy.budget_capacity,
            policy.budget_refill_per_sec,
            start_ms,
        );
        // The broker's circuit state machine is provider-agnostic in practice
        // (the label is only read by `snapshot`, which this service never calls),
        // so the audited `social-intel` private-namespace token is reused instead
        // of widening the shared `McpServiceId` contract with a non-MCP provider.
        let circuit = CircuitBreaker::new(
            ProviderId::Fomo,
            policy.failure_threshold,
            policy.cooldown_duration_ms,
        );
        Ok(Self {
            source,
            policy,
            budget,
            circuit,
            cache: LogicalCache::new(),
            calls: 0,
        })
    }

    /// Benchmarks one local basis against the injected provider quote source.
    ///
    /// Never returns an error: every failure mode degrades to a
    /// [`BenchmarkOutcome::Skipped`].
    pub async fn benchmark(&mut self, request: &BenchmarkRequest, now_ms: i64) -> BenchmarkOutcome {
        if now_ms < 0 {
            return skipped(
                BenchmarkSkipReason::InvalidReferenceTime,
                CacheState::Miss,
                None,
                0,
            );
        }
        let now = now_ms as u64;

        // Candidate gating before any cache/budget/provider work.
        if !request.candidate.is_eligible() {
            return skipped(
                BenchmarkSkipReason::CandidateNotEligible,
                CacheState::Miss,
                Some(DegradedReason::CandidateGatingRejected),
                0,
            );
        }
        // Large-order / structurally invalid basis gating, also before any spend.
        if request.local.amount_in == 0 || request.local.amount_out == 0 {
            return skipped(
                BenchmarkSkipReason::ComparatorRejected,
                CacheState::Miss,
                None,
                0,
            );
        }
        if request.local.amount_in < self.policy.benchmark.min_input_atomic {
            return skipped(
                BenchmarkSkipReason::BelowLargeOrderThreshold,
                CacheState::Miss,
                None,
                0,
            );
        }
        // A local basis from the future is a caller-side comparator error. Gate
        // it before any spend so a bad caller basis can never be misattributed
        // to the provider (circuit failure + negative cache).
        if request.local.observed_at_ms > now_ms {
            return skipped(
                BenchmarkSkipReason::ComparatorRejected,
                CacheState::Miss,
                None,
                0,
            );
        }

        self.calls = self.calls.wrapping_add(1);
        if self.calls % PRUNE_INTERVAL_CALLS == 0 {
            self.cache
                .prune_expired(now, self.policy.fresh_ttl_ms, self.policy.stale_grace_ms);
        }

        let key = match cache_key(&self.policy, request) {
            Ok(key) => key,
            // The basis cannot be canonically encoded: fail closed rather than
            // sharing a collapsed cache key across distinct requests.
            Err(()) => {
                return skipped(
                    BenchmarkSkipReason::Degraded(DegradedReason::ProviderUnavailable),
                    CacheState::Miss,
                    Some(DegradedReason::ProviderUnavailable),
                    0,
                )
            }
        };

        match self.cache.lookup::<ProviderQuote>(
            &key,
            now,
            self.policy.fresh_ttl_ms,
            self.policy.stale_grace_ms,
        ) {
            // A fresh hit is served and never charges budget or a circuit probe.
            CacheLookup::Fresh { value, .. } => self.compare_outcome(
                &request.local,
                value.as_ref(),
                now_ms,
                CacheState::FreshHit,
                None,
                0,
            ),
            // A negative entry must not hide still-usable stale data.
            CacheLookup::Negative(_) => {
                match self.cache.get_stale_fallback::<ProviderQuote>(&key) {
                    Some(value) => self.compare_outcome(
                        &request.local,
                        value.as_ref(),
                        now_ms,
                        CacheState::StaleServed,
                        Some(DegradedReason::NegativeCached),
                        0,
                    ),
                    None => skipped(
                        BenchmarkSkipReason::Degraded(DegradedReason::NegativeCached),
                        CacheState::NegativeHit,
                        Some(DegradedReason::NegativeCached),
                        0,
                    ),
                }
            }
            CacheLookup::Stale { value, .. } | CacheLookup::Expired(Some(value)) => {
                self.refresh_or_fallback(request, key, Some(value), now_ms, now)
                    .await
            }
            CacheLookup::Expired(None) | CacheLookup::Miss => {
                self.refresh_or_fallback(request, key, None, now_ms, now)
                    .await
            }
        }
    }

    /// Refreshes from the provider within budget, serving `fallback` when the
    /// refresh is denied or the provider fails.
    async fn refresh_or_fallback(
        &mut self,
        request: &BenchmarkRequest,
        key: LogicalRequestKey,
        fallback: Option<Arc<ProviderQuote>>,
        now_ms: i64,
        now: u64,
    ) -> BenchmarkOutcome {
        // A definitely open/cooldown circuit denies without consuming a probe.
        if matches!(
            self.circuit.health_state(now),
            ProviderHealthState::Cooldown | ProviderHealthState::CircuitOpen
        ) {
            return self.fallback_or_degraded(
                &request.local,
                fallback,
                DegradedReason::CooldownActive,
                now_ms,
                0,
            );
        }
        // Low-priority shedding under budget pressure or a degraded circuit.
        if request.priority == RequestPriority::Low
            && (self.budget.is_under_pressure(now)
                || self.circuit.health_state(now) != ProviderHealthState::Healthy)
        {
            return self.fallback_or_degraded(
                &request.local,
                fallback,
                DegradedReason::LowPriorityShed,
                now_ms,
                0,
            );
        }
        // Consume budget before the half-open probe so a denied fetch can never
        // strand the circuit's single in-flight probe.
        if let Err(reason) = self.budget.try_consume(now, self.policy.request_cost) {
            return self.fallback_or_degraded(&request.local, fallback, reason, now_ms, 0);
        }
        let cost = self.policy.request_cost;
        if let Err(reason) = self.circuit.check_allowed(now) {
            return self.fallback_or_degraded(&request.local, fallback, reason, now_ms, cost);
        }

        let quote_request = ProviderQuoteRequest {
            chain: request.local.chain.clone(),
            token_in: request.local.token_in.clone(),
            token_out: request.local.token_out.clone(),
            amount_in: request.local.amount_in,
            observed_at_ms: now_ms,
        };
        let source = Arc::clone(&self.source);

        // The half-open probe is wrapped in an RAII guard and the fetch runs in
        // its own block, so the guard is dropped (and the probe resolved) before
        // any cache/comparison work. If this future is cancelled or times out
        // mid-`await`, the guard's `Drop` records a failure instead of leaving
        // `probe_in_flight` set forever.
        let fetch_result = {
            let mut guard = ProbeGuard::new(&mut self.circuit, now);
            match source.fetch_quote(&quote_request).await {
                Ok(quote) if binds(&self.policy, &request.local, &quote, now_ms) => {
                    match compare_route(&request.local, &quote, &self.policy.benchmark, now_ms) {
                        // A zero provider output is a provider contract
                        // violation: fail the probe and negatively cache it.
                        Err(BenchmarkError::ZeroProviderOutput) => {
                            guard.fail();
                            Err(FetchFailure::Unbound)
                        }
                        // The quote binds and is structurally valid. Any other
                        // comparator error (for example arithmetic overflow) is
                        // caller-side, so it must not be charged to the provider
                        // circuit or negative cache; `compare_outcome` surfaces
                        // the comparator's own rejection later.
                        _ => {
                            guard.succeed();
                            Ok(quote)
                        }
                    }
                }
                Ok(_) => {
                    // A quote that does not bind the requested basis is a
                    // provider contract violation: fail closed.
                    guard.fail();
                    Err(FetchFailure::Unbound)
                }
                Err(_) => {
                    guard.fail();
                    Err(FetchFailure::Unavailable)
                }
            }
        };

        match fetch_result {
            Ok(quote) => {
                self.cache.insert_success(key, Arc::new(quote.clone()), now);
                self.compare_outcome(&request.local, &quote, now_ms, CacheState::Miss, None, cost)
            }
            Err(FetchFailure::Unbound) => {
                let until = now.saturating_add(self.policy.negative_ttl_ms);
                self.cache
                    .insert_negative(key, OpaqueFailureKind::MalformedResponse, until);
                self.fallback_or_degraded(
                    &request.local,
                    fallback,
                    DegradedReason::ProviderUnavailable,
                    now_ms,
                    cost,
                )
            }
            Err(FetchFailure::Unavailable) => {
                let until = now.saturating_add(self.policy.negative_ttl_ms);
                self.cache
                    .insert_negative(key, OpaqueFailureKind::ServiceUnavailable, until);
                self.fallback_or_degraded(
                    &request.local,
                    fallback,
                    DegradedReason::ProviderUnavailable,
                    now_ms,
                    cost,
                )
            }
        }
    }

    /// Compares a served quote, never fabricating a verdict.
    fn compare_outcome(
        &self,
        local: &LocalRouteQuote,
        quote: &ProviderQuote,
        now_ms: i64,
        cache_state: CacheState,
        degraded_reason: Option<DegradedReason>,
        request_cost: u32,
    ) -> BenchmarkOutcome {
        match compare_route(local, quote, &self.policy.benchmark, now_ms) {
            Ok(verdict) => BenchmarkOutcome::Compared {
                verdict,
                record: RouteComparisonRecord::new(local, quote, verdict),
                meta: BenchmarkMeta {
                    cache_state,
                    degraded_reason,
                    request_cost,
                },
            },
            Err(_) => skipped(
                BenchmarkSkipReason::ComparatorRejected,
                cache_state,
                degraded_reason,
                request_cost,
            ),
        }
    }

    /// Serves `fallback` when present, otherwise reports the degradation.
    fn fallback_or_degraded(
        &self,
        local: &LocalRouteQuote,
        fallback: Option<Arc<ProviderQuote>>,
        reason: DegradedReason,
        now_ms: i64,
        request_cost: u32,
    ) -> BenchmarkOutcome {
        match fallback {
            Some(quote) => self.compare_outcome(
                local,
                quote.as_ref(),
                now_ms,
                CacheState::StaleServed,
                Some(reason),
                request_cost,
            ),
            None => skipped(
                BenchmarkSkipReason::Degraded(reason),
                CacheState::Miss,
                Some(reason),
                request_cost,
            ),
        }
    }
}

/// Why the probe's fetch did not yield a comparable quote.
///
/// Fieldless so no provider payload, endpoint, or credential can be carried.
enum FetchFailure {
    /// The response did not bind the requested basis, or the comparator
    /// structurally rejected the bound quote.
    Unbound,
    /// The source returned an error (transport or structural rejection).
    Unavailable,
}

/// RAII owner of the circuit's single half-open probe.
///
/// `succeed`/`fail` resolve the probe explicitly; if neither runs because the
/// owning future is dropped mid-fetch, `Drop` records a failure so
/// `probe_in_flight` can never stay set forever.
struct ProbeGuard<'a> {
    circuit: &'a mut CircuitBreaker,
    now_ms: u64,
    armed: bool,
}

impl<'a> ProbeGuard<'a> {
    fn new(circuit: &'a mut CircuitBreaker, now_ms: u64) -> Self {
        Self {
            circuit,
            now_ms,
            armed: true,
        }
    }

    fn succeed(&mut self) {
        self.circuit.record_success();
        self.armed = false;
    }

    fn fail(&mut self) {
        self.circuit.record_failure(self.now_ms);
        self.armed = false;
    }
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.circuit.record_failure(self.now_ms);
        }
    }
}

/// Binds a served quote to the configured source and the requested basis.
fn binds(
    policy: &BenchmarkServicePolicy,
    local: &LocalRouteQuote,
    quote: &ProviderQuote,
    now_ms: i64,
) -> bool {
    quote.source == policy.source
        && quote.chain == local.chain
        && quote.token_in == local.token_in
        && quote.token_out == local.token_out
        && quote.amount_in == local.amount_in
        && quote.observed_at_ms <= now_ms
}

/// Builds a skip outcome.
fn skipped(
    reason: BenchmarkSkipReason,
    cache_state: CacheState,
    degraded_reason: Option<DegradedReason>,
    request_cost: u32,
) -> BenchmarkOutcome {
    BenchmarkOutcome::Skipped {
        reason,
        meta: BenchmarkMeta {
            cache_state,
            degraded_reason,
            request_cost,
        },
    }
}

/// Canonical cache key for a benchmark basis.
///
/// The candidate identity is intentionally excluded: the quote is basis-only, so
/// two candidates that share a basis share the comparison (and its cache entry).
/// Returns `Err(())` when the basis cannot be canonically encoded, so the caller
/// fails closed instead of sharing a collapsed key.
fn cache_key(
    policy: &BenchmarkServicePolicy,
    request: &BenchmarkRequest,
) -> Result<LogicalRequestKey, ()> {
    let context = RequestContext {
        candidate: None,
        position: None,
        priority: request.priority,
    };
    let local = &request.local;
    let args = serde_json::to_string(&(
        policy.source.as_str(),
        &local.chain,
        &local.token_in,
        &local.token_out,
        local.amount_in,
    ))
    .map_err(|_| ())?;
    Ok(LogicalRequestKey::new(
        ProviderId::Fomo,
        BENCHMARK_OPERATION,
        args,
        &context,
    ))
}
