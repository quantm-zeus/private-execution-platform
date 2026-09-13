//! The deterministic adaptive-TWAP chunk engine.
//!
//! Given a plan, the running state, and a market observation, [`AdaptiveTwap`]
//! returns the next safe chunk (or completion/halt). It is pure: no clock, no
//! I/O, no randomness. The caller supplies `now_ms`.

use market_types::AtomicAmount;

use crate::plan::{MarketObservation, TwapPlan, TwapPolicy, TwapState};

/// Why a chunk has the size it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkReason {
    /// On-schedule time-weighted slice.
    Schedule,
    /// Enlarged after observed liquidity recovery.
    Accelerated,
    /// Shrunk after deterioration/volatility/high slippage.
    Slowed,
    /// The final slice consumes the whole remaining input.
    Final,
    /// Fixed cron interval because observations were missing or stale.
    FallbackCron,
}

/// Why the plan halted without a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltReason {
    /// Realized slippage exceeded the caller's hard maximum.
    SlippageExceeded,
}

/// The engine's decision for one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwapDecision {
    /// Execute `chunk` (leaving `remaining_after`), then wait until `next_at_ms`.
    Execute {
        /// Input to execute now.
        chunk: AtomicAmount,
        /// Input that will remain after this chunk.
        remaining_after: AtomicAmount,
        /// Earliest time the next slice may run.
        next_at_ms: i64,
        /// Why this chunk size was chosen.
        reason: ChunkReason,
    },
    /// The plan has no input left.
    Complete,
    /// The plan halted before consuming the remainder.
    Halt {
        /// Why the halt happened.
        reason: HaltReason,
    },
}

/// Deterministic adaptive-TWAP chunker with an explicit tuning policy.
pub struct AdaptiveTwap {
    policy: TwapPolicy,
}

impl AdaptiveTwap {
    /// Builds the engine with `policy`.
    pub fn new(policy: TwapPolicy) -> Self {
        Self { policy }
    }

    /// Computes the next step.
    ///
    /// Precedence: completion, then the hard slippage halt, then (when
    /// observations are fresh) deceleration, acceleration, or the schedule; a
    /// missing/stale observation falls back to fixed cron timing. The chunk is
    /// always clamped to `[min_chunk, max_chunk]` and never exceeds the
    /// remaining input; a final slice always consumes all of it.
    pub fn next(
        &self,
        plan: &TwapPlan,
        state: &TwapState,
        observation: &MarketObservation,
        now_ms: i64,
    ) -> TwapDecision {
        let remaining = state.remaining_input.get();
        if remaining == 0 {
            return TwapDecision::Complete;
        }

        // The caller's hard slippage maximum is absolute: never trade through it.
        if let Some(slippage) = observation.last_slippage_bps {
            if slippage > plan.max_slippage_bps {
                return TwapDecision::Halt {
                    reason: HaltReason::SlippageExceeded,
                };
            }
        }

        let remaining_slices = plan.slices.saturating_sub(state.slices_done).max(1);
        let base = (remaining / remaining_slices as u128).max(1);

        let fallback = observation.is_empty()
            || observation.is_stale(now_ms, self.policy.observation_stale_ms);

        let (mut chunk, mut reason, interval) = if fallback {
            (
                base,
                ChunkReason::FallbackCron,
                plan.fallback_interval_ms.max(0),
            )
        } else {
            // `slices` is a public field and a caller may mutate it to 0 after
            // construction; floor the divisor as the schedule arithmetic above
            // already does.
            let base_interval = plan.duration_ms / plan.slices.max(1) as i64;
            let volatility_high = observation
                .volatility_bps
                .is_some_and(|value| value >= self.policy.high_volatility_bps);
            let recovery_low = observation
                .liquidity_recovery_bps
                .is_some_and(|value| value <= self.policy.decelerate_recovery_bps);
            let slippage_near_cap = plan.max_slippage_bps > 0
                && observation.last_slippage_bps.is_some_and(|slippage| {
                    (slippage as u64) * 10_000
                        >= (plan.max_slippage_bps as u64)
                            * (self.policy.high_slippage_fraction_of_cap_bps as u64)
                });
            let recovery_high = observation
                .liquidity_recovery_bps
                .is_some_and(|value| value >= self.policy.accelerate_recovery_bps);

            if volatility_high || recovery_low || slippage_near_cap {
                (
                    (base / 2).max(1),
                    ChunkReason::Slowed,
                    base_interval.saturating_mul(2),
                )
            } else if recovery_high {
                (
                    base.saturating_mul(2),
                    ChunkReason::Accelerated,
                    (base_interval / 2).max(0),
                )
            } else {
                (base, ChunkReason::Schedule, base_interval)
            }
        };

        // Final slice: a single remaining slice, or a remainder at/below the
        // minimum non-final chunk, consumes everything.
        let lo = plan.min_chunk.get().max(1);
        let hi = plan.max_chunk.get().max(lo);
        if remaining_slices <= 1 || remaining <= lo {
            chunk = remaining;
            reason = ChunkReason::Final;
        } else {
            // `min`/`max` avoid `u128::clamp`'s panic when a caller builds an
            // inverted plan by mutating the public fields directly.
            chunk = chunk.min(hi).max(lo).min(remaining);
            if chunk >= remaining {
                chunk = remaining;
                reason = ChunkReason::Final;
            }
        }
        // Defensive: never emit a zero chunk while input remains.
        if chunk == 0 {
            chunk = remaining.min(lo);
        }

        let remaining_after = remaining.saturating_sub(chunk);
        TwapDecision::Execute {
            chunk: AtomicAmount::new(chunk),
            remaining_after: AtomicAmount::new(remaining_after),
            next_at_ms: now_ms.saturating_add(interval.max(0)),
            reason,
        }
    }
}

impl std::fmt::Debug for AdaptiveTwap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdaptiveTwap")
            .field("policy", &self.policy)
            .finish()
    }
}
