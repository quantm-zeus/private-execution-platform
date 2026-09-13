//! Budget, priority, and candidate-gating policy for paid social intelligence.

/// The only request priorities the service accepts.
///
/// There is deliberately **no** broad-discovery or "explore everything" variant:
/// paid social intelligence is spent on an active-position risk, a high-conviction
/// pre-trade candidate, or (budget permitting) a promising candidate — never on
/// broad discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocialPriority {
    /// Highest priority: verify risk on a position the wallet already holds.
    ActivePositionRisk,
    /// A high-conviction pre-trade candidate.
    HighConvictionPreTrade,
    /// A promising candidate, enriched only if budget permits.
    PromisingCandidate,
}

impl SocialPriority {
    /// Weighted budget units one request of this priority costs.
    pub const fn cost_units(self) -> u32 {
        match self {
            Self::ActivePositionRisk => 4,
            Self::HighConvictionPreTrade => 2,
            Self::PromisingCandidate => 1,
        }
    }
}

/// Freshness/budget policy for the social intelligence cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocialPolicy {
    /// Maximum token-bucket capacity.
    pub budget_capacity: u32,
    /// Budget units refilled per second.
    pub budget_refill_per_sec: u32,
    /// Fresh cache TTL.
    pub fresh_ttl_ms: u64,
    /// Stale-while-revalidate grace after the fresh TTL.
    pub stale_grace_ms: u64,
    /// How long a provider failure is negatively cached.
    pub negative_ttl_ms: u64,
}

impl SocialPolicy {
    /// A conservative default: a small budget, minute-scale freshness, and a
    /// short negative cache.
    pub const fn default_policy() -> Self {
        Self {
            budget_capacity: 20,
            budget_refill_per_sec: 1,
            fresh_ttl_ms: 60_000,
            stale_grace_ms: 300_000,
            negative_ttl_ms: 30_000,
        }
    }
}

impl Default for SocialPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}
