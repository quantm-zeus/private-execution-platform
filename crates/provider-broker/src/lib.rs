//! # Provider Intelligence Broker
//!
//! Deterministic Provider Intelligence Broker coordinating reuse of typed `mcp-adapters`
//! without duplicate service or upstream requests.
//!
//! ## Architectural Invariants
//! - Strict reuse of `mcp-adapters` with zero direct network/upstream/HTTP/WebSocket dependencies.
//! - Singleflight/request coalescing: identical concurrent requests coalesce to <= 1 adapter call.
//! - Distinct freshness policies: configurable fresh TTL, stale-while-revalidate (SWR), and negative cache.
//! - Weighted per-provider budgets with deterministic token-bucket replenishment.
//! - Priority shedding, cooldown periods, and fail-closed circuit breakers preventing adapter hammering.
//! - Candidate/position-aware enrichment: candidate gating for expensive queries and strict position keying.
//! - Zero secret, credential, endpoint, or raw payload leakage in errors and metadata.
//! - Global fail-closed trading invariant (`TRADING_ENABLED = false`).

pub mod broker;
pub mod budget;
pub mod cache;
pub mod circuit;
pub mod clock;
pub mod error;
pub mod key;
pub mod meta;
pub mod policy;
pub mod provider;

pub use broker::ProviderBroker;
pub use budget::ProviderBudget;
pub use cache::{CacheLookup, LogicalCache};
pub use circuit::CircuitBreaker;
pub use clock::{Clock, ManualClock, SystemClock};
pub use error::{BrokerError, OpaqueFailureKind};
pub use key::{
    CandidateContext, LogicalRequestKey, PositionContext, ProviderId, RequestContext,
    RequestPriority,
};
pub use meta::{
    BrokerResponse, CacheState, DegradedReason, ProviderHealth, ProviderHealthState, ResponseMeta,
};
pub use policy::{
    BrokerConfig, OperationClassification, OperationProfile, ProviderPolicy, OP_FOMO_CAPABILITIES,
    OP_FOMO_GET_RECENT_EVENTS, OP_FOMO_GET_TOKEN, OP_FOMO_GET_TRENDING_TOKENS,
    OP_FOMO_SEARCH_TOKENS, OP_GMGN_KLINE, OP_GMGN_SEARCH, OP_GMGN_TOKEN_INFO,
    OP_GMGN_TOKEN_SECURITY, OP_GMGN_TOP_HOLDERS, OP_GMGN_TRENDING,
};
pub use provider::{IntelligenceProvider, McpAdapterBridge};

/// Global fail-closed invariant: this broker never possesses, activates, or alters trading capabilities.
pub const TRADING_ENABLED: bool = false;
