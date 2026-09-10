//! Policy configuration for Provider Intelligence Broker.
//!
//! Enforces:
//! - Distinct freshness, stale grace, negative cache, and budget policies for FOMO and GMGN.
//! - Operation classifications (Standard vs ExpensiveEnrichment).
//! - Deterministic operation weight mapping.

use serde::{Deserialize, Serialize};

use crate::key::ProviderId;

/// Classification of intelligence operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClassification {
    /// Standard lightweight or medium intelligence query.
    Standard,
    /// Expensive enrichment query (e.g. top holders or deep audit) requiring candidate gating.
    ExpensiveEnrichment,
}

impl OperationClassification {
    pub fn is_expensive(&self) -> bool {
        matches!(self, Self::ExpensiveEnrichment)
    }
}

/// Bounded provider-specific policy configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPolicy {
    /// Time in milliseconds during which a cached response is considered completely fresh.
    pub fresh_ttl_ms: u64,
    /// Grace period in milliseconds after `fresh_ttl_ms` during which stale data can be served while SWR is scheduled.
    pub stale_grace_ms: u64,
    /// Bounded negative cache TTL in milliseconds for opaque failures.
    pub negative_ttl_ms: u64,
    /// Maximum cost capacity for the request budget.
    pub max_budget: u32,
    /// Replenishment rate of budget units per second.
    pub budget_refill_per_sec: u32,
    /// Number of consecutive failures before entering cooldown / opening circuit breaker.
    pub failure_threshold: u32,
    /// Duration of cooldown / circuit breaker open period in milliseconds.
    pub cooldown_duration_ms: u64,
}

impl ProviderPolicy {
    /// Default policy tailored for FOMO intelligence service.
    pub fn default_fomo() -> Self {
        Self {
            fresh_ttl_ms: 30_000,         // 30 seconds
            stale_grace_ms: 60_000,       // 60 seconds grace
            negative_ttl_ms: 5_000,       // 5 seconds negative TTL
            max_budget: 100,              // 100 budget units
            budget_refill_per_sec: 10,    // 10 units/sec refill
            failure_threshold: 3,         // 3 consecutive failures
            cooldown_duration_ms: 10_000, // 10 seconds cooldown
        }
    }

    /// Default policy tailored for GMGN intelligence gateway.
    pub fn default_gmgn() -> Self {
        Self {
            fresh_ttl_ms: 10_000,         // 10 seconds
            stale_grace_ms: 30_000,       // 30 seconds grace
            negative_ttl_ms: 3_000,       // 3 seconds negative TTL
            max_budget: 60,               // 60 budget units
            budget_refill_per_sec: 5,     // 5 units/sec refill
            failure_threshold: 3,         // 3 consecutive failures
            cooldown_duration_ms: 15_000, // 15 seconds cooldown
        }
    }
}

/// Global broker configuration containing policies for all supported providers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerConfig {
    pub fomo: ProviderPolicy,
    pub gmgn: ProviderPolicy,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            fomo: ProviderPolicy::default_fomo(),
            gmgn: ProviderPolicy::default_gmgn(),
        }
    }
}

impl BrokerConfig {
    pub fn policy_for(&self, provider: ProviderId) -> &ProviderPolicy {
        match provider {
            ProviderId::Fomo => &self.fomo,
            ProviderId::Gmgn => &self.gmgn,
        }
    }
}

/// Standard wire operation definitions, weights, and classifications.
pub struct OperationProfile {
    pub name: &'static str,
    pub weight: u32,
    pub classification: OperationClassification,
}

impl OperationProfile {
    pub const fn new(
        name: &'static str,
        weight: u32,
        classification: OperationClassification,
    ) -> Self {
        Self {
            name,
            weight,
            classification,
        }
    }
}

// FOMO operations
pub const OP_FOMO_CAPABILITIES: OperationProfile =
    OperationProfile::new("fomo_capabilities", 1, OperationClassification::Standard);
pub const OP_FOMO_SEARCH_TOKENS: OperationProfile =
    OperationProfile::new("fomo_search_tokens", 1, OperationClassification::Standard);
pub const OP_FOMO_GET_TOKEN: OperationProfile =
    OperationProfile::new("fomo_get_token", 1, OperationClassification::Standard);
pub const OP_FOMO_GET_TRENDING_TOKENS: OperationProfile = OperationProfile::new(
    "fomo_get_trending_tokens",
    1,
    OperationClassification::Standard,
);
pub const OP_FOMO_GET_RECENT_EVENTS: OperationProfile = OperationProfile::new(
    "fomo_get_recent_events",
    2,
    OperationClassification::Standard,
);

// GMGN operations
pub const OP_GMGN_TRENDING: OperationProfile =
    OperationProfile::new("gmgn_trending", 1, OperationClassification::Standard);
pub const OP_GMGN_SEARCH: OperationProfile =
    OperationProfile::new("gmgn_search", 1, OperationClassification::Standard);
pub const OP_GMGN_TOKEN_INFO: OperationProfile =
    OperationProfile::new("gmgn_token_info", 1, OperationClassification::Standard);
pub const OP_GMGN_TOKEN_SECURITY: OperationProfile =
    OperationProfile::new("gmgn_token_security", 2, OperationClassification::Standard);
pub const OP_GMGN_TOP_HOLDERS: OperationProfile = OperationProfile::new(
    "gmgn_top_holders",
    5,
    OperationClassification::ExpensiveEnrichment,
);
pub const OP_GMGN_KLINE: OperationProfile =
    OperationProfile::new("gmgn_kline", 3, OperationClassification::Standard);
