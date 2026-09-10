//! Bounded safe metadata for provider health, reliability, and freshness.
//!
//! Invariants:
//! - Records provider identity, cache state/freshness, degradation reason, and reliability counters.
//! - Zero endpoints, credentials, raw request payloads, or raw response errors exposed.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::key::ProviderId;

/// Cache status of a fulfilled broker request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheState {
    /// Satisfied from fresh cache within the provider-specific fresh TTL.
    FreshHit,
    /// Satisfied from stale cache within stale grace while asynchronous SWR refresh was scheduled.
    StaleServed,
    /// Cache miss: fresh data retrieved from the provider adapter.
    Miss,
    /// Satisfied from negative cache (bounded recent failure).
    NegativeHit,
}

/// Structured reason why intelligence is degraded or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    /// Request budget for this provider has been temporarily exhausted.
    BudgetExhausted,
    /// Circuit breaker is open due to consecutive failures.
    CircuitBreakerOpen,
    /// Provider is in cooldown following repeated adapter failures.
    CooldownActive,
    /// Lower-priority request shed under provider pressure.
    LowPriorityShed,
    /// Candidate gating criteria were not met for expensive enrichment.
    CandidateGatingRejected,
    /// Upstream adapter is unavailable or failed; serving fallback if available.
    ProviderUnavailable,
    /// Request blocked by active negative cache.
    NegativeCached,
}

impl fmt::Display for DegradedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted => write!(f, "budget exhausted"),
            Self::CircuitBreakerOpen => write!(f, "circuit breaker open"),
            Self::CooldownActive => write!(f, "cooldown active"),
            Self::LowPriorityShed => write!(f, "low priority shed"),
            Self::CandidateGatingRejected => write!(f, "candidate gating rejected"),
            Self::ProviderUnavailable => write!(f, "provider unavailable"),
            Self::NegativeCached => write!(f, "negative cached"),
        }
    }
}

/// Bounded provider health status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealthState {
    /// Fully healthy and operating within normal parameters.
    Healthy,
    /// Operating under degraded conditions (partial budget, pressure, or minor failures).
    Degraded,
    /// In cooldown after repeated failures; fail-closed against adapter hammering.
    Cooldown,
    /// Circuit breaker is open.
    CircuitOpen,
}

impl fmt::Display for ProviderHealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Cooldown => write!(f, "cooldown"),
            Self::CircuitOpen => write!(f, "circuit_open"),
        }
    }
}

/// Bounded safe response metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseMeta {
    pub provider: ProviderId,
    pub cache_state: CacheState,
    pub freshness_ms: Option<u64>,
    pub degraded_reason: Option<DegradedReason>,
    pub health_state: ProviderHealthState,
    pub consecutive_failures: u32,
    pub request_cost: u32,
}

impl ResponseMeta {
    pub fn is_degraded(&self) -> bool {
        self.degraded_reason.is_some() || self.cache_state == CacheState::StaleServed
    }
}

impl fmt::Display for ResponseMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ResponseMeta(provider={}, cache={:?}, health={}, cost={})",
            self.provider, self.cache_state, self.health_state, self.request_cost
        )
    }
}

/// Structured response wrapping data and bounded metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerResponse<T> {
    pub value: T,
    pub meta: ResponseMeta,
}

impl<T> BrokerResponse<T> {
    pub fn new(value: T, meta: ResponseMeta) -> Self {
        Self { value, meta }
    }
}

/// Safe aggregate provider health snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub provider: ProviderId,
    pub state: ProviderHealthState,
    pub consecutive_failures: u32,
    pub total_requests: u64,
    pub total_failures: u64,
    pub circuit_trips: u32,
    pub available_budget: u32,
}

impl fmt::Display for ProviderHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProviderHealth(provider={}, state={}, failures={}, trips={})",
            self.provider, self.state, self.consecutive_failures, self.circuit_trips
        )
    }
}
