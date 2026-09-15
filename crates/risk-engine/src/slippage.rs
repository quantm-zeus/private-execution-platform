//! Pure, deterministic dynamic slippage recommendation.
//!
//! The recommender turns four caller-supplied risk signals and a validated
//! policy into a single slippage bound that is guaranteed to lie in
//! `[0, hard_max]`. It is the P89 core described by `docs/PRD.md`:
//!
//! > Dynamic slippage recommendation may consider volatility, state latency,
//! > route uncertainty and confirmation latency but never exceeds a user hard
//! > maximum.
//!
//! # Model
//!
//! 1. The two latency fields are summed with a saturating `u64` add, so an
//!    extreme pair cannot wrap or abort.
//! 2. The latency contribution is
//!    `ceil(latency_ms * drift_bps_per_sec / 1000)`: a whole-second drift rate
//!    is prorated by wall-clock latency and rounded **up** to the next whole
//!    basis point, so any non-zero latency cost is represented.
//! 3. The raw recommendation is
//!    `base_bps + volatility_bps + route_uncertainty_bps + latency_bps`,
//!    computed in `u128` with checked adds.
//! 4. The result is `min(raw, hard_max)`.
//!
//! Every step is integer-only and deterministic. There is no clock, no
//! randomness, and no I/O, so the same inputs always produce the same output.
//!
//! # Overflow
//!
//! The checked operations fail closed with [`RiskError::ArithmeticOverflow`].
//! With the current field widths that branch is unreachable: `latency_ms` is at
//! most `u64::MAX`, `drift_bps_per_sec` is a [`Bps`] (at most
//! [`Bps::MAX`]), so the product is at most `u64::MAX * 10_000`, which fits
//! comfortably in `u128`; the subsequent adds are bounded by the same scale.
//! The checks are kept anyway so a future widening of the inputs cannot turn
//! into a wrapping or aborting recommendation.

use core::fmt;

use market_types::Bps;

/// Deterministic, caller-supplied risk signals for one execution.
///
/// `Debug` is intentionally redacted: it renders the type name only and never
/// the signal values.
pub struct SlippageSignals {
    /// Recent realized volatility, in basis points.
    pub volatility_bps: Bps,
    /// Uncertainty of the selected route, in basis points.
    pub route_uncertainty_bps: Bps,
    /// Age of the state snapshot the recommendation is based on, in
    /// milliseconds.
    pub state_latency_ms: u64,
    /// Expected confirmation latency of the execution, in milliseconds.
    pub confirmation_latency_ms: u64,
}

impl fmt::Debug for SlippageSignals {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlippageSignals { .. }")
    }
}

/// Validated policy: a base allowance plus a per-second latency drift.
///
/// `Debug` is intentionally redacted: it renders the type name only and never
/// the policy values.
pub struct SlippagePolicy {
    /// Base slippage allowance granted before any risk signal, in basis points.
    pub base_bps: Bps,
    /// Additional slippage allowed per full second of latency, in basis points.
    pub drift_bps_per_sec: Bps,
}

impl fmt::Debug for SlippagePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlippagePolicy { .. }")
    }
}

/// Redacted, fieldless failure taxonomy.
///
/// The variant carries no payload, so neither `Display` nor `Debug` can leak a
/// signal, a policy value, or any execution data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RiskError {
    /// A checked arithmetic step would overflow; the recommendation fails
    /// closed rather than returning a wrapped value.
    #[error("slippage recommendation arithmetic overflowed")]
    ArithmeticOverflow,
}

/// Returns a deterministic recommendation in `[0, hard_max]`, never above it.
///
/// The result is monotone non-decreasing in each signal and in both policy
/// values, and depends on nothing but the arguments.
pub fn recommend_slippage(
    signals: &SlippageSignals,
    policy: &SlippagePolicy,
    hard_max: Bps,
) -> Result<Bps, RiskError> {
    let latency_ms =
        saturating_latency_ms(signals.state_latency_ms, signals.confirmation_latency_ms);
    let latency_bps = ceil_latency_bps(latency_ms, policy.drift_bps_per_sec.get())?;

    let raw = (policy.base_bps.get() as u128)
        .checked_add(signals.volatility_bps.get() as u128)
        .and_then(|sum| sum.checked_add(signals.route_uncertainty_bps.get() as u128))
        .and_then(|sum| sum.checked_add(latency_bps))
        .ok_or(RiskError::ArithmeticOverflow)?;

    let capped = raw.min(hard_max.get() as u128);
    let capped_u16 = u16::try_from(capped).map_err(|_| RiskError::ArithmeticOverflow)?;
    Bps::new(capped_u16).map_err(|_| RiskError::ArithmeticOverflow)
}

/// Saturating sum of the two latency fields.
///
/// `u64::MAX + u64::MAX` saturates to `u64::MAX` instead of wrapping.
fn saturating_latency_ms(state_latency_ms: u64, confirmation_latency_ms: u64) -> u64 {
    state_latency_ms.saturating_add(confirmation_latency_ms)
}

/// `ceil(latency_ms * drift_bps_per_sec / 1000)` using checked arithmetic.
///
/// Rounds up so any non-zero latency cost is charged at least one basis point.
fn ceil_latency_bps(latency_ms: u64, drift_bps_per_sec: u16) -> Result<u128, RiskError> {
    let product = (latency_ms as u128)
        .checked_mul(drift_bps_per_sec as u128)
        .ok_or(RiskError::ArithmeticOverflow)?;
    let rounded = product
        .checked_add(999)
        .ok_or(RiskError::ArithmeticOverflow)?;
    Ok(rounded / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_rounds_up_to_whole_bps() {
        assert_eq!(ceil_latency_bps(1, 1), Ok(1));
        assert_eq!(ceil_latency_bps(1000, 5), Ok(5));
    }

    #[test]
    fn latency_rounds_partial_bps_up() {
        assert_eq!(ceil_latency_bps(1001, 1), Ok(2));
        assert_eq!(ceil_latency_bps(1, 3), Ok(1));
        assert_eq!(ceil_latency_bps(0, 10_000), Ok(0));
    }

    #[test]
    fn latency_sum_saturates_instead_of_wrapping() {
        assert_eq!(saturating_latency_ms(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(saturating_latency_ms(500, 700), 1200);
    }

    #[test]
    fn extreme_latency_and_drift_stay_in_range() {
        // The checked operations cannot fail with the current field widths:
        // u64::MAX * 10_000 still fits in u128. This pins the saturating path
        // as the one that is reached, not the fail-closed path.
        let expected = ((u64::MAX as u128) * 10_000).div_ceil(1000);
        assert_eq!(ceil_latency_bps(u64::MAX, Bps::MAX), Ok(expected));
    }
}
