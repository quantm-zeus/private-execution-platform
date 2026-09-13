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

    /// Read-only gate: returns whether a request is admitted for `chain` at
    /// `now_ms` *without* consuming a half-open probe.
    ///
    /// A healthy chain is always admitted. A degraded chain is admitted while no
    /// probe is in flight. An unavailable chain is admitted only once its
    /// cooldown has elapsed, i.e. when a half-open probe would be admissible.
    ///
    /// This method never mutates the breaker. The caller must subsequently call
    /// [`Self::admit_probe`] immediately before submitting so that a pre-submit
    /// failure cannot strand a half-open probe.
    pub fn check_allowed(&self, chain: &ChainId, now_ms: i64) -> bool {
        let states = crate::lock(&self.states);
        match states.get(chain) {
            None => true,
            Some(entry) => match entry.state {
                ChainHealth::Healthy => true,
                ChainHealth::Degraded => !entry.probe_in_flight,
                ChainHealth::Unavailable => {
                    now_ms >= entry.cooldown_until_ms && !entry.probe_in_flight
                }
            },
        }
    }

    /// Atomically consumes a submission admission for `chain` at `now_ms`.
    ///
    /// Call this immediately before `adapter.submit`: it is the only method that
    /// sets `probe_in_flight`, so any earlier failure returns before a probe is
    /// consumed. A healthy chain is admitted without consuming a probe; an
    /// unavailable chain whose cooldown has elapsed transitions to a single
    /// half-open probe; a degraded chain admits while no probe is in flight.
    /// Returns `None` when no admission is currently available.
    ///
    /// The returned [`ProbeGuard`] must be explicitly resolved with
    /// [`ProbeGuard::success`] or [`ProbeGuard::failure`] once the submission
    /// returns. Dropping it unresolved (for example because the awaiting
    /// `execute` future was cancelled) releases the half-open probe as a
    /// failure, so `probe_in_flight` can never be stranded.
    pub fn admit_probe(&self, chain: &ChainId, now_ms: i64) -> Option<ProbeGuard<'_>> {
        let consumed_probe = {
            let mut states = crate::lock(&self.states);
            let entry = states.entry(chain.clone()).or_default();
            match entry.state {
                ChainHealth::Healthy => false,
                ChainHealth::Degraded => {
                    if entry.probe_in_flight {
                        return None;
                    }
                    entry.probe_in_flight = true;
                    true
                }
                ChainHealth::Unavailable => {
                    if now_ms < entry.cooldown_until_ms || entry.probe_in_flight {
                        return None;
                    }
                    entry.state = ChainHealth::Degraded;
                    entry.probe_in_flight = true;
                    true
                }
            }
        };
        Some(ProbeGuard {
            breaker: self,
            chain: chain.clone(),
            admitted_at_ms: now_ms,
            consumed_probe,
            resolved: false,
        })
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

/// RAII admission guard returned by [`ChainHealthBreaker::admit_probe`].
///
/// While alive it owns the chain's half-open probe (when one was consumed). The
/// caller must resolve it explicitly with [`ProbeGuard::success`] (closes the
/// breaker) or [`ProbeGuard::failure`] (re-opens it with a fresh cooldown).
///
/// If the guard is dropped before either method runs it is resolved as a
/// failure at the admission time. This makes the half-open probe
/// cancellation-safe: dropping an in-flight `execute` future releases the probe
/// instead of stranding `probe_in_flight` forever and permanently blocking a
/// chain whose adapter reports [`ChainHealth::Healthy`].
pub struct ProbeGuard<'a> {
    breaker: &'a ChainHealthBreaker,
    chain: ChainId,
    admitted_at_ms: i64,
    consumed_probe: bool,
    resolved: bool,
}

impl ProbeGuard<'_> {
    /// Resolves the admission as a success, closing the breaker.
    pub fn success(mut self) {
        self.resolved = true;
        self.breaker.record_success(&self.chain);
    }

    /// Resolves the admission as a failure at `now_ms`.
    pub fn failure(mut self, now_ms: i64) {
        self.resolved = true;
        self.breaker.record_failure(&self.chain, now_ms);
    }
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.consumed_probe && !self.resolved {
            // The admission was never resolved (cancellation or a dropped
            // caller): release the probe as a failure so the breaker re-opens
            // with a fresh cooldown rather than blocking forever.
            self.breaker
                .record_failure(&self.chain, self.admitted_at_ms);
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
