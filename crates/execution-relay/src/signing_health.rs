//! Deterministic signing-failure circuit breaker.
//!
//! Mirrors the chain-health breaker in [`crate::health`] but gates the signing
//! boundary rather than a specific chain: there is exactly one state machine per
//! relay, driven entirely by explicit `i64 now_ms` with no wall clock. The
//! breaker opens after `failure_threshold` consecutive signing failures, blocks
//! new execution for `cooldown_ms`, then admits exactly one half-open probe. A
//! probe success closes the breaker; a probe failure re-opens it with a fresh
//! cooldown.
//!
//! This is additive to, and independent of, [`crate::health::ChainHealthBreaker`]:
//! the relay still checks the kill switch and chain health first, so a signing
//! outage can only ever *halt* execution, never bypass those gates.
//!
//! # Concurrency
//!
//! There is a single state machine per relay (unlike the chain breaker's
//! per-chain map), shared by all concurrent signing attempts. It reproduces the
//! chain breaker's exact concurrency semantics, including that a healthy
//! admission reserves no probe and a success clears any in-flight probe. Once
//! the first failure puts the breaker in `Degraded`, signing admissions are
//! serialized to one in-flight attempt at a time.

use std::sync::Mutex;

/// Coarse signing-boundary health derived from the breaker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SigningHealth {
    /// Signing is fully available.
    #[default]
    Healthy,
    /// Signing has recorded failures but is still admitting attempts.
    Degraded,
    /// Signing is unavailable; new execution is halted until the cooldown.
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    consecutive_failures: u32,
    state: SigningHealth,
    cooldown_until_ms: i64,
    probe_in_flight: bool,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: SigningHealth::Healthy,
            cooldown_until_ms: 0,
            probe_in_flight: false,
        }
    }
}

/// Deterministic signing-failure breaker with a single state machine.
pub struct SigningFailureBreaker {
    failure_threshold: u32,
    cooldown_ms: i64,
    inner: Mutex<Entry>,
}

impl SigningFailureBreaker {
    /// Builds a breaker. A zero threshold is treated as one; a negative
    /// cooldown is treated as zero.
    pub fn new(failure_threshold: u32, cooldown_ms: i64) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown_ms: cooldown_ms.max(0),
            inner: Mutex::new(Entry::default()),
        }
    }

    /// The default production policy: three consecutive signing failures open
    /// the breaker for a thirty-second cooldown.
    pub fn default_policy() -> Self {
        Self::new(3, 30_000)
    }

    /// Read-only gate: returns whether signing is admitted at `now_ms` *without*
    /// consuming a half-open probe.
    ///
    /// A healthy breaker is always admitted. A degraded breaker is admitted
    /// while no probe is in flight. An unavailable breaker is admitted only once
    /// its cooldown has elapsed. This method never mutates the breaker; the
    /// caller must subsequently call [`Self::admit_probe`] immediately before
    /// signing so that a pre-signing failure cannot strand a half-open probe.
    pub fn check_allowed(&self, now_ms: i64) -> bool {
        let entry = crate::lock(&self.inner);
        match entry.state {
            SigningHealth::Healthy => true,
            SigningHealth::Degraded => !entry.probe_in_flight,
            SigningHealth::Unavailable => {
                now_ms >= entry.cooldown_until_ms && !entry.probe_in_flight
            }
        }
    }

    /// Atomically consumes a signing admission at `now_ms`.
    ///
    /// Call this immediately before `sign`: it is the only method that sets
    /// `probe_in_flight`, so any earlier failure returns before a probe is
    /// consumed. A healthy breaker is admitted without consuming a probe; an
    /// unavailable breaker whose cooldown has elapsed transitions to a single
    /// half-open probe; a degraded breaker admits while no probe is in flight.
    /// Returns `None` when no admission is currently available.
    ///
    /// The returned [`SigningProbeGuard`] must be explicitly resolved with
    /// [`SigningProbeGuard::success`] or [`SigningProbeGuard::failure`] once
    /// signing returns. Dropping it unresolved (for example because the awaiting
    /// `execute` future was cancelled) releases the half-open probe as a
    /// failure, so `probe_in_flight` can never be stranded.
    pub fn admit_probe(&self, now_ms: i64) -> Option<SigningProbeGuard<'_>> {
        let consumed_probe = {
            let mut entry = crate::lock(&self.inner);
            match entry.state {
                SigningHealth::Healthy => false,
                SigningHealth::Degraded => {
                    if entry.probe_in_flight {
                        return None;
                    }
                    entry.probe_in_flight = true;
                    true
                }
                SigningHealth::Unavailable => {
                    if now_ms < entry.cooldown_until_ms || entry.probe_in_flight {
                        return None;
                    }
                    entry.state = SigningHealth::Degraded;
                    entry.probe_in_flight = true;
                    true
                }
            }
        };
        Some(SigningProbeGuard {
            breaker: self,
            admitted_at_ms: now_ms,
            consumed_probe,
            resolved: false,
        })
    }

    /// Records a successful signing interaction and closes the breaker.
    pub fn record_success(&self) {
        let mut entry = crate::lock(&self.inner);
        entry.consecutive_failures = 0;
        entry.state = SigningHealth::Healthy;
        entry.probe_in_flight = false;
    }

    /// Records a failed signing interaction, opening the breaker at threshold.
    pub fn record_failure(&self, now_ms: i64) {
        let mut entry = crate::lock(&self.inner);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.probe_in_flight = false;
        if entry.consecutive_failures >= self.failure_threshold {
            entry.state = SigningHealth::Unavailable;
            entry.cooldown_until_ms = now_ms.saturating_add(self.cooldown_ms);
        } else {
            entry.state = SigningHealth::Degraded;
        }
    }

    /// Reports the current breaker health at `now_ms`.
    pub fn state(&self, now_ms: i64) -> SigningHealth {
        let entry = crate::lock(&self.inner);
        if entry.state == SigningHealth::Unavailable && now_ms >= entry.cooldown_until_ms {
            SigningHealth::Degraded
        } else {
            entry.state
        }
    }
}

/// RAII admission guard returned by [`SigningFailureBreaker::admit_probe`].
///
/// While alive it owns the half-open probe (when one was consumed). The caller
/// must resolve it explicitly with [`SigningProbeGuard::success`] (closes the
/// breaker) or [`SigningProbeGuard::failure`] (re-opens it with a fresh
/// cooldown).
///
/// If the guard is dropped before either method runs it is resolved as a
/// failure at the admission time. This makes the half-open probe
/// cancellation-safe: dropping an in-flight `execute` future releases the probe
/// instead of stranding `probe_in_flight` forever and permanently halting
/// signing even after the outage ends.
pub struct SigningProbeGuard<'a> {
    breaker: &'a SigningFailureBreaker,
    admitted_at_ms: i64,
    consumed_probe: bool,
    resolved: bool,
}

impl SigningProbeGuard<'_> {
    /// Resolves the admission as a success, closing the breaker.
    pub fn success(mut self) {
        self.resolved = true;
        self.breaker.record_success();
    }

    /// Resolves the admission as a failure at `now_ms`.
    pub fn failure(mut self, now_ms: i64) {
        self.resolved = true;
        self.breaker.record_failure(now_ms);
    }
}

impl Drop for SigningProbeGuard<'_> {
    fn drop(&mut self) {
        if self.consumed_probe && !self.resolved {
            // The admission was never resolved (cancellation or a dropped
            // caller): release the probe as a failure so the breaker re-opens
            // with a fresh cooldown rather than blocking forever.
            self.breaker.record_failure(self.admitted_at_ms);
        }
    }
}

impl std::fmt::Debug for SigningFailureBreaker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningFailureBreaker")
            .field("failure_threshold", &self.failure_threshold)
            .field("cooldown_ms", &self.cooldown_ms)
            .finish_non_exhaustive()
    }
}
