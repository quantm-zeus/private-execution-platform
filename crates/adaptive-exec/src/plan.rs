//! Adaptive TWAP plan, state, market observation, and tuning policy.

use market_types::AtomicAmount;

/// A durable TWAP execution plan for one large order.
///
/// All bounds are explicit and caller-supplied; the engine never invents a
/// chunk larger than `max_chunk`, smaller than `min_chunk` (except a final
/// remainder), or beyond the hard `max_slippage_bps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapPlan {
    /// Total input to execute over the plan.
    pub total_input: AtomicAmount,
    /// Target number of slices.
    pub slices: u32,
    /// Smallest non-final slice.
    pub min_chunk: AtomicAmount,
    /// Largest slice.
    pub max_chunk: AtomicAmount,
    /// Nominal plan duration.
    pub duration_ms: i64,
    /// Fixed cron interval used when observations are missing/stale.
    pub fallback_interval_ms: i64,
    /// Hard slippage cap in bps; exceeding it halts the plan.
    pub max_slippage_bps: u16,
}

impl TwapPlan {
    /// Builds a plan, normalizing an empty/inverted bound set.
    ///
    /// `min_chunk` is floored at 1 atomic unit and `max_chunk` at `min_chunk`;
    /// `slices` is floored at 1. The plan does not validate `total_input` beyond
    /// that (a zero total simply completes immediately).
    pub fn new(
        total_input: AtomicAmount,
        slices: u32,
        min_chunk: AtomicAmount,
        max_chunk: AtomicAmount,
        duration_ms: i64,
        fallback_interval_ms: i64,
        max_slippage_bps: u16,
    ) -> Self {
        let min = AtomicAmount::new(min_chunk.get().max(1));
        let max = AtomicAmount::new(max_chunk.get().max(min.get()));
        Self {
            total_input,
            slices: slices.max(1),
            min_chunk: min,
            max_chunk: max,
            duration_ms: duration_ms.max(0),
            fallback_interval_ms: fallback_interval_ms.max(0),
            max_slippage_bps,
        }
    }
}

/// Mutable progress of a running TWAP plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapState {
    /// Input not yet executed.
    pub remaining_input: AtomicAmount,
    /// Slices already executed.
    pub slices_done: u32,
    /// Time the last slice executed, if any.
    pub last_chunk_at_ms: Option<i64>,
    /// Size of the last executed slice, if any.
    pub last_chunk: Option<AtomicAmount>,
}

impl TwapState {
    /// Starts a plan with `total_input` remaining.
    pub fn new(total_input: AtomicAmount) -> Self {
        Self {
            remaining_input: total_input,
            slices_done: 0,
            last_chunk_at_ms: None,
            last_chunk: None,
        }
    }

    /// Records an executed slice, saturating on malformed over-consumption.
    pub fn record(&self, chunk: AtomicAmount, at_ms: i64) -> Self {
        let remaining = self.remaining_input.get().saturating_sub(chunk.get());
        Self {
            remaining_input: AtomicAmount::new(remaining),
            slices_done: self.slices_done.saturating_add(1),
            last_chunk_at_ms: Some(at_ms),
            last_chunk: Some(chunk),
        }
    }
}

/// Market feedback observed since the last slice.
///
/// Every field is optional: a missing/stale observation makes the engine fall
/// back to fixed cron timing rather than guessing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarketObservation {
    /// When the observation was taken.
    pub observed_at_ms: i64,
    /// Realized slippage of the last slice in bps.
    pub last_slippage_bps: Option<u16>,
    /// Liquidity recovery versus the last slice: positive is improvement.
    pub liquidity_recovery_bps: Option<i16>,
    /// Short-horizon volatility in bps.
    pub volatility_bps: Option<u16>,
}

impl MarketObservation {
    /// Whether no signal at all was observed.
    pub fn is_empty(&self) -> bool {
        self.last_slippage_bps.is_none()
            && self.liquidity_recovery_bps.is_none()
            && self.volatility_bps.is_none()
    }

    /// Whether the observation is older than `max_age_ms` at `now_ms`.
    pub fn is_stale(&self, now_ms: i64, max_age_ms: i64) -> bool {
        now_ms.saturating_sub(self.observed_at_ms) > max_age_ms
    }
}

/// Tuning thresholds for adaptive chunking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapPolicy {
    /// Recovery at/above this accelerates the schedule.
    pub accelerate_recovery_bps: i16,
    /// Recovery at/below this decelerates the schedule.
    pub decelerate_recovery_bps: i16,
    /// Volatility at/above this decelerates the schedule.
    pub high_volatility_bps: u16,
    /// Slippage at/above this fraction of `max_slippage_bps` (in bps of the cap,
    /// where 10_000 = the whole cap) decelerates the schedule.
    pub high_slippage_fraction_of_cap_bps: u16,
    /// An observation older than this falls back to fixed cron timing.
    pub observation_stale_ms: i64,
}

impl TwapPolicy {
    /// Conservative defaults for a first adaptive implementation.
    pub const fn default_policy() -> Self {
        Self {
            accelerate_recovery_bps: 500,
            decelerate_recovery_bps: -500,
            high_volatility_bps: 300,
            high_slippage_fraction_of_cap_bps: 5_000,
            observation_stale_ms: 30_000,
        }
    }
}

impl Default for TwapPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}
