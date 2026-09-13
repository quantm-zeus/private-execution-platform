//! Deterministic per-chain health breaker.
//!
//! Mirrors the provider-broker circuit breaker but is keyed by [`ChainId`] and
//! driven entirely by explicit `i64 now_ms`; there is no wall clock. The
//! breaker opens after `failure_threshold` consecutive failures, blocks for
//! `cooldown_ms`, then admits exactly one half-open probe. A probe success
//! closes the breaker; a probe failure re-opens it with a fresh cooldown.

use std::collections::HashMap;
use std::sync::Mutex;

use chain_types::ChainId;
use serde::{Deserialize, Serialize};

/// Coarse chain health reported by a submission adapter or derived from the
/// breaker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainHealth {
    /// The chain is fully available.
    #[default]
    Healthy,
    /// The chain is degraded but requests are still admitted.
    Degraded,
    /// The chain is unavailable; requests are blocked until the cooldown.
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
struct BreakerEntry {
    consecutive_failures: u32,
    state: ChainHealth,
    cooldown_until_ms: i64,
    probe_in_flight: bool,
}

impl Default for BreakerEntry {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: ChainHealth::Healthy,
            cooldown_until_ms: 0,
            probe_in_flight: false,
        }
    }
}

/// Deterministic health breaker with one state machine per chain.
pub struct ChainHealthBreaker {
    failure_threshold: u32,
    cooldown_ms: i64,
    states: Mutex<HashMap<ChainId, BreakerEntry>>,
}

impl ChainHealthBreaker {
    /// Builds a breaker. A zero threshold is treated as one; a negative
    /// cooldown is treated as zero.
    pub fn new(failure_threshold: u32, cooldown_ms: i64) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown_ms: cooldown_ms.max(0),
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Returns whether a request is admitted for `chain` at `now_ms`.
    ///
    /// A healthy or (pre-trip) degraded chain is admitted. An unavailable chain
    /// is blocked until its cooldown elapses; the first call at/after that point
    /// transitions to a single half-open probe.
    pub fn check_allowed(&self, chain: &ChainId, now_ms: i64) -> bool {
        let mut states = crate::lock(&self.states);
        let entry = states.entry(chain.clone()).or_default();
        match entry.state {
            ChainHealth::Healthy => true,
            ChainHealth::Degraded => !entry.probe_in_flight,
            ChainHealth::Unavailable => {
                if now_ms < entry.cooldown_until_ms {
                    false
                } else {
                    entry.state = ChainHealth::Degraded;
                    entry.probe_in_flight = true;
                    true
                }
            }
        }
    }

    /// Records a successful chain interaction and closes the breaker.
    pub fn record_success(&self, chain: &ChainId) {
        let mut states = crate::lock(&self.states);
        let entry = states.entry(chain.clone()).or_default();
        entry.consecutive_failures = 0;
        entry.state = ChainHealth::Healthy;
        entry.probe_in_flight = false;
    }

    /// Records a failed chain interaction, opening the breaker at threshold.
    pub fn record_failure(&self, chain: &ChainId, now_ms: i64) {
        let mut states = crate::lock(&self.states);
        let entry = states.entry(chain.clone()).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.probe_in_flight = false;
        if entry.consecutive_failures >= self.failure_threshold {
            entry.state = ChainHealth::Unavailable;
            entry.cooldown_until_ms = now_ms.saturating_add(self.cooldown_ms);
        } else {
            entry.state = ChainHealth::Degraded;
        }
    }

    /// Feeds an injected adapter health reading into the breaker.
    ///
    /// A healthy reading is a no-op (so a healthy adapter cannot mask real
    /// submission failures); degraded or unavailable readings count as failures.
    pub fn observe(&self, chain: &ChainId, health: ChainHealth, now_ms: i64) {
        match health {
            ChainHealth::Healthy => {}
            ChainHealth::Degraded | ChainHealth::Unavailable => {
                self.record_failure(chain, now_ms);
            }
        }
    }

    /// Reports the current breaker health at `now_ms`.
    pub fn health(&self, chain: &ChainId, now_ms: i64) -> ChainHealth {
        let states = crate::lock(&self.states);
        match states.get(chain) {
            Some(entry)
                if entry.state == ChainHealth::Unavailable && now_ms >= entry.cooldown_until_ms =>
            {
                ChainHealth::Degraded
            }
            Some(entry) => entry.state,
            None => ChainHealth::Healthy,
        }
    }
}

impl Default for ChainHealthBreaker {
    fn default() -> Self {
        Self::new(1, 0)
    }
}

impl std::fmt::Debug for ChainHealthBreaker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChainHealthBreaker")
            .field("failure_threshold", &self.failure_threshold)
            .field("cooldown_ms", &self.cooldown_ms)
            .finish_non_exhaustive()
    }
}
