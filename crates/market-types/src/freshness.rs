//! Deterministic freshness policy and safe status metadata.

use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::primitives::Sequence;
use crate::sequence::SequencedStreamTracker;

pub const MIN_POLICY_STALENESS_MS: u64 = 1;
pub const MAX_POLICY_STALENESS_MS: u64 = 86_400_000; // 24 hours
pub const MAX_POLICY_FUTURE_SKEW_MS: u64 = 300_000; // 5 minutes
pub const DEFAULT_MAX_STALENESS_MS: u64 = 10_000; // 10 seconds
pub const DEFAULT_MAX_FUTURE_SKEW_MS: u64 = 2_000; // 2 seconds

/// Safe categorization of data freshness without raw error or payload leakage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Fresh,
    Stale,
    ResyncRequired,
}

/// Deterministic policy defining staleness and clock skew boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    pub max_staleness_ms: u64,
    pub max_future_skew_ms: u64,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            max_staleness_ms: DEFAULT_MAX_STALENESS_MS,
            max_future_skew_ms: DEFAULT_MAX_FUTURE_SKEW_MS,
        }
    }
}

impl FreshnessPolicy {
    pub fn new(max_staleness_ms: u64, max_future_skew_ms: u64) -> Result<Self, MarketTypeError> {
        if !(MIN_POLICY_STALENESS_MS..=MAX_POLICY_STALENESS_MS).contains(&max_staleness_ms) {
            return Err(MarketTypeError::PolicyStalenessOutOfRange(max_staleness_ms));
        }
        if max_future_skew_ms > MAX_POLICY_FUTURE_SKEW_MS {
            return Err(MarketTypeError::PolicySkewOutOfRange(max_future_skew_ms));
        }
        Ok(Self {
            max_staleness_ms,
            max_future_skew_ms,
        })
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if !(MIN_POLICY_STALENESS_MS..=MAX_POLICY_STALENESS_MS).contains(&self.max_staleness_ms) {
            return Err(MarketTypeError::PolicyStalenessOutOfRange(
                self.max_staleness_ms,
            ));
        }
        if self.max_future_skew_ms > MAX_POLICY_FUTURE_SKEW_MS {
            return Err(MarketTypeError::PolicySkewOutOfRange(
                self.max_future_skew_ms,
            ));
        }
        Ok(())
    }
}

/// Safe status metadata evaluated deterministically against an explicit reference timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeFreshnessMeta {
    pub status: FreshnessStatus,
    pub observed_at_ms: i64,
    pub evaluated_at_ms: i64,
    pub age_ms: u64,
    pub sequence: Sequence,
}

impl SafeFreshnessMeta {
    pub const fn is_fresh(&self) -> bool {
        matches!(self.status, FreshnessStatus::Fresh)
    }

    pub const fn is_stale(&self) -> bool {
        matches!(self.status, FreshnessStatus::Stale)
    }

    pub const fn is_resync_required(&self) -> bool {
        matches!(self.status, FreshnessStatus::ResyncRequired)
    }
}

/// Evaluates freshness deterministically given bounded timestamps, sequence, and stream gap state.
/// This function is completely free of wall-clock side-effects.
pub fn evaluate_freshness(
    policy: &FreshnessPolicy,
    observed_at_ms: i64,
    evaluated_at_ms: i64,
    sequence: Sequence,
    has_gap_or_resync: bool,
) -> Result<SafeFreshnessMeta, MarketTypeError> {
    policy.validate()?;
    if observed_at_ms <= 0 {
        return Err(MarketTypeError::InvalidTimestamp(observed_at_ms));
    }
    if evaluated_at_ms <= 0 {
        return Err(MarketTypeError::InvalidTimestamp(evaluated_at_ms));
    }

    let age_ms = if evaluated_at_ms >= observed_at_ms {
        (evaluated_at_ms - observed_at_ms) as u64
    } else {
        0
    };

    if has_gap_or_resync {
        return Ok(SafeFreshnessMeta {
            status: FreshnessStatus::ResyncRequired,
            observed_at_ms,
            evaluated_at_ms,
            age_ms,
            sequence,
        });
    }

    if observed_at_ms > evaluated_at_ms {
        let future_skew = (observed_at_ms - evaluated_at_ms) as u64;
        if future_skew > policy.max_future_skew_ms {
            return Ok(SafeFreshnessMeta {
                status: FreshnessStatus::ResyncRequired,
                observed_at_ms,
                evaluated_at_ms,
                age_ms: 0,
                sequence,
            });
        }
        return Ok(SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms,
            evaluated_at_ms,
            age_ms: 0,
            sequence,
        });
    }

    let status = if age_ms > policy.max_staleness_ms {
        FreshnessStatus::Stale
    } else {
        FreshnessStatus::Fresh
    };

    Ok(SafeFreshnessMeta {
        status,
        observed_at_ms,
        evaluated_at_ms,
        age_ms,
        sequence,
    })
}

impl SequencedStreamTracker {
    /// Deterministically evaluate the freshness of this tracker at a reference timestamp `evaluated_at_ms`.
    pub fn evaluate_freshness(
        &self,
        policy: &FreshnessPolicy,
        evaluated_at_ms: i64,
    ) -> Result<SafeFreshnessMeta, MarketTypeError> {
        let seq = self.current_sequence().unwrap_or(Sequence::ZERO);
        let observed_ms = self.last_timestamp_ms().unwrap_or(evaluated_at_ms);
        let has_gap = self.is_resync_required() || self.current_sequence().is_none();
        evaluate_freshness(policy, observed_ms, evaluated_at_ms, seq, has_gap)
    }
}
