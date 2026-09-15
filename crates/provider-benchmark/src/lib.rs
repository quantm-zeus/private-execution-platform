//! Budgeted, candidate-gated provider-route benchmark service (Phase 4).
//!
//! This crate wires the pure [`routing::benchmark`] comparator into a service
//! that reuses the Provider Intelligence Broker's budget, cache, and circuit
//! primitives. It is the "provider quote deviation" KPI path described by the
//! PRD: an OKX (or other provider) route quote is compared against the exact
//! local route economics for the same basis, and the result is recorded as a
//! [`routing::RouteComparisonRecord`].
//!
//! # Invariants
//! - **Execution-independent.** The service has no signing, relay, or execution
//!   dependency and can never affect a trade. [`TRADING_ENABLED`] is `false`.
//! - **Fail-open toward "skip".** A gated, degraded, budget-exhausted, or
//!   circuit-open call yields a [`BenchmarkOutcome::Skipped`]; a provider outage
//!   can never fail a caller or transitively an execution path.
//! - **Never fabricate.** A verdict is only ever the direct output of
//!   [`routing::compare_route`], and a served provider quote must bind the exact
//!   requested chain, pair, and input amount, and must not be from the future.
//! - **Candidate/large-order gated.** A non-eligible candidate or an input below
//!   [`routing::BenchmarkPolicy::min_input_atomic`] spends no budget and touches
//!   no provider.
//! - **Redacted.** No type is `Serialize`/`Deserialize`, and no `Debug` renders
//!   amounts, assets, or the opaque provider reference.
//!
//! ```no_run
//! // `serde_json` is available to these doctests; the benchmark outcome types
//! // deliberately are not serializable.
//! let _ = serde_json::to_string(&("probe", 1u8));
//! ```
//!
//! ```compile_fail
//! // A `BenchmarkOutcome` must never cross a serialization boundary.
//! let _ = serde_json::to_string(&provider_benchmark::BenchmarkOutcome::Skipped {
//!     reason: provider_benchmark::BenchmarkSkipReason::InvalidReferenceTime,
//!     meta: provider_benchmark::BenchmarkMeta {
//!         cache_state: provider_broker::CacheState::Miss,
//!         degraded_reason: None,
//!         request_cost: 0,
//!     },
//! });
//! ```

#![forbid(unsafe_code)]

pub mod policy;
pub mod provider;
pub mod service;

pub use policy::{BenchmarkPolicyError, BenchmarkServicePolicy};
pub use provider::{
    ProviderQuoteRequest, ProviderQuoteSource, ProviderQuoteSourceError,
    UnavailableProviderQuoteSource,
};
pub use service::{
    BenchmarkMeta, BenchmarkOutcome, BenchmarkRequest, BenchmarkSkipReason,
    ProviderBenchmarkService,
};

/// Global fail-closed invariant: this service never affects trading execution.
pub const TRADING_ENABLED: bool = false;
