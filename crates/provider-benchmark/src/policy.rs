//! Budget/cache/circuit policy for the benchmark service.

use routing::{BenchmarkPolicy, BenchmarkSource};

/// Default provider label used by [`BenchmarkServicePolicy::okx`].
pub const DEFAULT_SOURCE_LABEL: &str = "okx";

/// Request cost units charged to the provider budget per actual fetch.
pub const DEFAULT_REQUEST_COST: u32 = 3;
/// Default provider budget capacity (in request-cost units).
pub const DEFAULT_BUDGET_CAPACITY: u32 = 30;
/// Default provider budget refill rate (units per second).
pub const DEFAULT_BUDGET_REFILL_PER_SEC: u32 = 5;
/// Default fresh-cache TTL in milliseconds.
pub const DEFAULT_FRESH_TTL_MS: u64 = 2_000;
/// Default stale-grace window in milliseconds.
pub const DEFAULT_STALE_GRACE_MS: u64 = 30_000;
/// Default negative-cache TTL in milliseconds.
pub const DEFAULT_NEGATIVE_TTL_MS: u64 = 5_000;
/// Default consecutive-failure threshold that trips the circuit.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
/// Default circuit cooldown in milliseconds.
pub const DEFAULT_COOLDOWN_MS: u64 = 15_000;
/// Default large-order threshold in input atomic units.
pub const DEFAULT_MIN_INPUT_ATOMIC: u128 = 1;

/// Structural policy failures, all resolved before the service is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BenchmarkPolicyError {
    /// The provider source label failed its structural contract.
    #[error("invalid benchmark source")]
    InvalidSource,
    /// `request_cost` must be at least one so a fetch is never free.
    #[error("benchmark request cost must be non-zero")]
    ZeroRequestCost,
    /// The provider budget must hold at least one request.
    #[error("benchmark budget capacity must be non-zero")]
    ZeroBudgetCapacity,
    /// A zero failure threshold would trip the circuit on any call.
    #[error("benchmark failure threshold must be non-zero")]
    ZeroFailureThreshold,
    /// A "fresh" cache hit must not be older than the comparator's provider age.
    #[error("fresh TTL exceeds the provider maximum age")]
    FreshTtlExceedsProviderAge,
}

/// Budget, cache, circuit, and comparison policy for one benchmark service.
#[derive(Clone, Debug)]
pub struct BenchmarkServicePolicy {
    /// Validated provider/aggregator label bound onto every fetched quote.
    pub source: BenchmarkSource,
    /// Exact comparator thresholds.
    pub benchmark: BenchmarkPolicy,
    /// Cost units charged per actual provider fetch.
    pub request_cost: u32,
    /// Provider budget capacity in request-cost units.
    pub budget_capacity: u32,
    /// Provider budget refill rate in units per second.
    pub budget_refill_per_sec: u32,
    /// Fresh-cache TTL in milliseconds (must not exceed
    /// [`BenchmarkPolicy::max_provider_age_ms`]).
    pub fresh_ttl_ms: u64,
    /// Stale-grace window in milliseconds.
    pub stale_grace_ms: u64,
    /// Negative-cache TTL in milliseconds.
    pub negative_ttl_ms: u64,
    /// Consecutive failures that trip the circuit.
    pub failure_threshold: u32,
    /// Circuit cooldown in milliseconds.
    pub cooldown_duration_ms: u64,
}

impl BenchmarkServicePolicy {
    /// Constructs and validates a policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: BenchmarkSource,
        benchmark: BenchmarkPolicy,
        request_cost: u32,
        budget_capacity: u32,
        budget_refill_per_sec: u32,
        fresh_ttl_ms: u64,
        stale_grace_ms: u64,
        negative_ttl_ms: u64,
        failure_threshold: u32,
        cooldown_duration_ms: u64,
    ) -> Result<Self, BenchmarkPolicyError> {
        let policy = Self {
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
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Conventional OKX benchmark policy.
    pub fn okx() -> Result<Self, BenchmarkPolicyError> {
        let source = BenchmarkSource::new(DEFAULT_SOURCE_LABEL)
            .map_err(|_| BenchmarkPolicyError::InvalidSource)?;
        let benchmark = BenchmarkPolicy {
            min_input_atomic: DEFAULT_MIN_INPUT_ATOMIC,
            ..BenchmarkPolicy::default()
        };
        Self::new(
            source,
            benchmark,
            DEFAULT_REQUEST_COST,
            DEFAULT_BUDGET_CAPACITY,
            DEFAULT_BUDGET_REFILL_PER_SEC,
            DEFAULT_FRESH_TTL_MS,
            DEFAULT_STALE_GRACE_MS,
            DEFAULT_NEGATIVE_TTL_MS,
            DEFAULT_FAILURE_THRESHOLD,
            DEFAULT_COOLDOWN_MS,
        )
    }

    /// Validates the cross-field policy invariants.
    pub fn validate(&self) -> Result<(), BenchmarkPolicyError> {
        if self.request_cost == 0 {
            return Err(BenchmarkPolicyError::ZeroRequestCost);
        }
        if self.budget_capacity == 0 {
            return Err(BenchmarkPolicyError::ZeroBudgetCapacity);
        }
        if self.failure_threshold == 0 {
            return Err(BenchmarkPolicyError::ZeroFailureThreshold);
        }
        if self.fresh_ttl_ms > self.benchmark.max_provider_age_ms {
            return Err(BenchmarkPolicyError::FreshTtlExceedsProviderAge);
        }
        Ok(())
    }
}
