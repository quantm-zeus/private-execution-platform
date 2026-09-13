//! Exact, fee-excluded price-impact projection.
//!
//! CPMM impact is computed exactly from the simulation kernel's own post-fee
//! effective input and resulting reserve, using 256-bit products so it cannot
//! overflow for any `u128` reserves. CLMM/Bin pools have no exact closed-form
//! impact in this slice; the caller may supply
//! [`crate::PoolDescriptor::impact_override_bps`], otherwise the impact is
//! unavailable and the candidate fails closed when a cap is configured.

use market_types::Bps;
use simulation::{div_u256_by_u128_floor, mul_u128_wide};

/// Exact CPMM fee-excluded price impact in basis points.
///
/// `impact_bps = floor(10_000 * effective_input / (reserve_in + effective_input))`
/// where `reserve_in` is the pre-swap input reserve derived from the kernel's
/// `resulting_reserve_in` minus the full input amount.
///
/// Returns `None` when the reserve is inconsistent, the denominator overflows,
/// or the result is not representable as a valid [`Bps`].
pub(crate) fn cpmm_impact_bps(
    effective_input: u128,
    resulting_reserve_in: u128,
    amount_in: u128,
) -> Option<Bps> {
    let reserve_in = resulting_reserve_in.checked_sub(amount_in)?;
    let denominator = reserve_in.checked_add(effective_input)?;
    if denominator == 0 || effective_input == 0 {
        return None;
    }
    let (hi, lo) = mul_u128_wide(10_000, effective_input);
    let value = div_u256_by_u128_floor(hi, lo, denominator)?;
    let value = u16::try_from(value).ok()?;
    Bps::new(value).ok()
}

/// Combines per-hop impacts into a route impact.
///
/// Returns `None` if any hop impact is unavailable, so a missing CLMM/Bin model
/// cannot be silently treated as zero.
pub(crate) fn combine_impacts(impacts: &[Option<Bps>]) -> Option<Bps> {
    let mut maximum: Option<Bps> = None;
    for impact in impacts {
        let impact = (*impact)?;
        maximum = Some(match maximum {
            Some(current) if current.get() >= impact.get() => current,
            _ => impact,
        });
    }
    maximum
}
