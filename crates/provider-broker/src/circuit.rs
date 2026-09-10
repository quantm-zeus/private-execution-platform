//! Circuit breaker and cooldown state machine for provider adapters.
//!
//! Enforces:
//! - Consecutive failure tracking without automatic retries.
//! - Cooldown/open-circuit period upon reaching failure threshold.
//! - Rejection of adapter requests during cooldown to prevent hammering.
//! - Deterministic, bounded single-probe half-open recovery that cannot fan out.
//! - Bounded reliability metrics tracking.

use crate::key::ProviderId;
use crate::meta::{DegradedReason, ProviderHealth, ProviderHealthState};

#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    provider: ProviderId,
    failure_threshold: u32,
    cooldown_duration_ms: u64,
    consecutive_failures: u32,
    total_failures: u64,
    total_requests: u64,
    circuit_trips: u32,
    state: ProviderHealthState,
    cooldown_until_ms: u64,
    probe_in_flight: bool,
}

impl CircuitBreaker {
    pub fn new(provider: ProviderId, failure_threshold: u32, cooldown_duration_ms: u64) -> Self {
        Self {
            provider,
            failure_threshold,
            cooldown_duration_ms,
            consecutive_failures: 0,
            total_failures: 0,
            total_requests: 0,
            circuit_trips: 0,
            state: ProviderHealthState::Healthy,
            cooldown_until_ms: 0,
            probe_in_flight: false,
        }
    }

    /// Checks if a request is allowed to invoke the adapter under current circuit breaker state.
    ///
    /// If in active cooldown, returns `Err(DegradedReason::CooldownActive)` or `Err(DegradedReason::CircuitBreakerOpen)`.
    /// If cooldown has elapsed, permits exactly one half-open probe request.
    pub fn check_allowed(&mut self, now_ms: u64) -> Result<(), DegradedReason> {
        match self.state {
            ProviderHealthState::Healthy => Ok(()),
            ProviderHealthState::Degraded => {
                if self.probe_in_flight {
                    // A single probe is currently executing; reject additional concurrent probes to avoid fan out
                    Err(DegradedReason::CooldownActive)
                } else {
                    Ok(())
                }
            }
            ProviderHealthState::Cooldown | ProviderHealthState::CircuitOpen => {
                if now_ms < self.cooldown_until_ms {
                    Err(DegradedReason::CooldownActive)
                } else {
                    // Cooldown has expired: transition to half-open probe
                    self.state = ProviderHealthState::Degraded;
                    self.probe_in_flight = true;
                    Ok(())
                }
            }
        }
    }

    /// Records a successful adapter invocation.
    /// Resets consecutive failures and closes the circuit.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = ProviderHealthState::Healthy;
        self.probe_in_flight = false;
        self.total_requests = self.total_requests.saturating_add(1);
    }

    /// Records a failed adapter invocation.
    /// Increments consecutive failures and potentially trips the circuit into cooldown.
    pub fn record_failure(&mut self, now_ms: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.total_failures = self.total_failures.saturating_add(1);
        self.total_requests = self.total_requests.saturating_add(1);
        self.probe_in_flight = false;

        if self.consecutive_failures >= self.failure_threshold {
            self.state = ProviderHealthState::CircuitOpen;
            self.cooldown_until_ms = now_ms + self.cooldown_duration_ms;
            self.circuit_trips = self.circuit_trips.saturating_add(1);
        } else {
            self.state = ProviderHealthState::Degraded;
        }
    }

    /// Returns the current health state.
    pub fn health_state(&self, now_ms: u64) -> ProviderHealthState {
        if matches!(
            self.state,
            ProviderHealthState::CircuitOpen | ProviderHealthState::Cooldown
        ) && now_ms >= self.cooldown_until_ms
        {
            ProviderHealthState::Degraded // Eligible for probe
        } else {
            self.state
        }
    }

    /// Returns consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns a safe health snapshot.
    pub fn snapshot(&self, now_ms: u64, available_budget: u32) -> ProviderHealth {
        ProviderHealth {
            provider: self.provider,
            state: self.health_state(now_ms),
            consecutive_failures: self.consecutive_failures,
            total_requests: self.total_requests,
            total_failures: self.total_failures,
            circuit_trips: self.circuit_trips,
            available_budget,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_trips_after_threshold_and_recovers_via_probe() {
        let mut cb = CircuitBreaker::new(ProviderId::Fomo, 3, 5_000);
        assert_eq!(cb.health_state(0), ProviderHealthState::Healthy);
        assert!(cb.check_allowed(0).is_ok());

        // 1st failure
        cb.record_failure(100);
        assert_eq!(cb.health_state(100), ProviderHealthState::Degraded);
        assert!(cb.check_allowed(100).is_ok());

        // 2nd failure
        cb.record_failure(200);
        assert_eq!(cb.health_state(200), ProviderHealthState::Degraded);
        assert!(cb.check_allowed(200).is_ok());

        // 3rd failure -> trips circuit into CircuitOpen
        cb.record_failure(300);
        assert_eq!(cb.health_state(300), ProviderHealthState::CircuitOpen);

        // During cooldown (cooldown_until = 300 + 5,000 = 5,300)
        assert_eq!(cb.check_allowed(1_000), Err(DegradedReason::CooldownActive));
        assert_eq!(cb.check_allowed(5_299), Err(DegradedReason::CooldownActive));

        // After cooldown expires at t = 5,300 -> half-open probe allowed
        assert!(cb.check_allowed(5_300).is_ok());
        // Second concurrent request during probe in flight is blocked
        assert_eq!(cb.check_allowed(5_300), Err(DegradedReason::CooldownActive));

        // Probe succeeds -> recovers to Healthy
        cb.record_success();
        assert_eq!(cb.health_state(5_301), ProviderHealthState::Healthy);
        assert_eq!(cb.consecutive_failures(), 0);
        assert!(cb.check_allowed(5_301).is_ok());
    }

    #[test]
    fn test_probe_failure_re_opens_circuit() {
        let mut cb = CircuitBreaker::new(ProviderId::Gmgn, 2, 4_000);
        cb.record_failure(100);
        cb.record_failure(200);
        assert_eq!(cb.health_state(200), ProviderHealthState::CircuitOpen);

        // Advance past cooldown
        assert!(cb.check_allowed(4_300).is_ok());

        // Probe fails
        cb.record_failure(4_350);
        // Circuit opens again until 4_350 + 4_000 = 8_350
        assert_eq!(cb.health_state(4_350), ProviderHealthState::CircuitOpen);
        assert_eq!(cb.check_allowed(5_000), Err(DegradedReason::CooldownActive));
    }
}
