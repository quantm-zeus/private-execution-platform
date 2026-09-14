//! Exact, deterministic depth profiling for concentrated-liquidity (CLMM) and
//! bin/DLMM pools.
//!
//! "Depth near N bps" is the exact atomic input a pool absorbs before its own
//! spot price moves more than `N` basis points, without leaving the pool's
//! initialized tick/bin range. It is computed by bounded integer traversal of
//! the landed exact-input kernels: no floating point, no clock, no RNG, and no
//! re-implemented tick/bin math. Comparison of a post-trade price against the
//! pre-trade spot price is done with exact 256-bit cross-multiplication, so the
//! profile is a pure function of the canonical pool state.
//!
//! Depth is only defined for [`PoolKindState::Clmm`] and [`PoolKindState::Bin`];
//! CPMM price impact is already exact through
//! [`crate::impact::cpmm_impact_bps`], so a CPMM state returns
//! [`RoutingError::UnsupportedPoolKind`]. Every individual target that the pool
//! cannot reach is reported as an explicit `None` coverage entry rather than a
//! guessed number; only a structurally unusable state fails the whole call.
//!
//! [`RoutingError::UnsupportedPoolKind`]: crate::error::RoutingError::UnsupportedPoolKind
//! [`crate::impact::cpmm_impact_bps`]: crate::impact::cpmm_impact_bps

use std::cmp::Ordering;
use std::fmt;

use chain_types::AssetId;
use market_types::{AtomicAmount, BinPoolState, Bps, ClmmPoolState, PoolKindState};
use simulation::{
    cmp_u128_products, simulate_bin_exact_input, simulate_clmm_exact_input, BinExactInputRequest,
    ClmmExactInputRequest,
};

use crate::error::RoutingError;

/// Conventional, operator-facing price-band depth targets in basis points.
///
/// Callers opt into depth-aware ranking by passing these (or any other bounded
/// target list) as [`crate::RouteRequest::depth_targets`]; an empty slice keeps
/// the pre-depth behavior byte-identical.
pub const DEPTH_TARGETS_BPS: [u16; 5] = [10, 25, 50, 100, 250];

/// Hard bound on the input-doubling steps used to bracket a pool's exact range
/// capacity. Inputs are `u128`, so 128 doublings cover the full domain.
const MAX_DEPTH_DOUBLINGS: u32 = 128;

/// One price-band depth level.
///
/// `absorbed_in` is the largest exact atomic input the pool absorbs within
/// `target_bps` without leaving its initialized range. `None` means the pool
/// cannot be traversed at all, or even a one-unit input already leaves the band,
/// so no coverage can be honestly asserted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DepthLevel {
    /// Target band in basis points, exactly as supplied by the caller.
    pub target_bps: Bps,
    /// Exact absorbed input, or `None` when the band is unreachable.
    pub absorbed_in: Option<AtomicAmount>,
}

impl fmt::Debug for DepthLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: never render the absorbed amount.
        f.debug_struct("DepthLevel")
            .field("target_bps", &self.target_bps.get())
            .field("covered", &self.absorbed_in.is_some())
            .finish()
    }
}

/// Exact depth profile of one CLMM/Bin pool for one trade size.
#[derive(Clone, PartialEq, Eq)]
pub struct DepthProfile {
    /// One entry per caller-supplied target, in the caller's order.
    pub levels: Vec<DepthLevel>,
    /// Whole-basis-point ceiling of the profiled trade-size impact, `None` when
    /// the pool cannot quote it or the impact exceeds `Bps::MAX`.
    pub trade_impact_bps: Option<Bps>,
}

impl DepthProfile {
    /// Largest target band that fully absorbs `amount_in`, or `0` when none does.
    ///
    /// A larger score means a deeper pool for this trade size. The value is a
    /// target from the profile (or `0`), never a synthesized number.
    pub fn score_bps(&self, amount_in: AtomicAmount) -> u16 {
        let mut score = 0u16;
        for level in &self.levels {
            if level.target_bps.get() <= score {
                continue;
            }
            if level
                .absorbed_in
                .is_some_and(|absorbed| absorbed.get() >= amount_in.get())
            {
                score = level.target_bps.get();
            }
        }
        score
    }
}

impl fmt::Debug for DepthProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: levels and their coverage only, no amounts.
        f.debug_struct("DepthProfile")
            .field("levels", &self.levels)
            .field("trade_impact_bps", &self.trade_impact_bps.map(Bps::get))
            .finish()
    }
}

/// Compact depth ranking key derived from a [`DepthProfile`].
///
/// `levels` is sorted by `target_bps` **descending**, so the first entry is the
/// widest band. Ranking compares absorbed capacity from the widest band down and
/// only then the exact trade impact, so a pool that can absorb more before a
/// given move is preferred even when the current trade fits both pools equally.
/// `impact_bps` is the weakest key (`None` sorts last).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepthRank {
    /// Depth levels sorted by descending target band.
    pub levels: Vec<DepthLevel>,
    /// Whole-basis-point ceiling of the trade impact, when quotable.
    pub impact_bps: Option<Bps>,
}

/// Computes the exact depth profile of `state` for `amount_in`.
///
/// `targets` is evaluated exactly as supplied (order and duplicates preserved).
/// Only a structurally unusable pool (wrong chain, unknown input asset, CPMM)
/// returns an error; an individual unreachable target is an explicit `None`
/// entry.
pub fn depth_at_bps(
    state: &PoolKindState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    targets: &[Bps],
) -> Result<DepthProfile, RoutingError> {
    match state {
        PoolKindState::Clmm(pool) => clmm_profile(pool, token_in, amount_in, targets),
        PoolKindState::Bin(pool) => bin_profile(pool, token_in, amount_in, targets),
        PoolKindState::Cpmm(_) => Err(RoutingError::UnsupportedPoolKind),
    }
}

/// Computes a compact [`DepthRank`] for ranking without exposing raw amounts.
///
/// The returned levels are sorted by target band descending so callers can
/// compare depth deterministically from the widest band down.
pub fn depth_rank(
    state: &PoolKindState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    targets: &[Bps],
) -> Result<DepthRank, RoutingError> {
    let mut profile = depth_at_bps(state, token_in, amount_in, targets)?;
    profile
        .levels
        .sort_by_key(|level| std::cmp::Reverse(level.target_bps.get()));
    Ok(DepthRank {
        levels: profile.levels,
        impact_bps: profile.trade_impact_bps,
    })
}

/// Whole-basis-point ceiling of the exact CLMM impact from the pre-trade spot
/// sqrt price.
///
/// `impact = ceil_bps(10_000 * |r^2 - s^2| / s^2)` computed by exact cross
/// multiplication (never a division of 256-bit squares). Returns `None` when
/// the impact exceeds [`Bps::MAX`] or an input is zero.
pub(crate) fn clmm_impact_bps(pool_sqrt: u128, resulting_sqrt: u128) -> Option<Bps> {
    if pool_sqrt == 0 || resulting_sqrt == 0 {
        return None;
    }
    if !clmm_within(pool_sqrt, resulting_sqrt, Bps::MAX) {
        return None;
    }
    // `within(b)` is monotone in `b`; the smallest satisfying band is the
    // whole-basis-point ceiling of the exact impact.
    let mut lo = 0u16;
    let mut hi = Bps::MAX;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if clmm_within(pool_sqrt, resulting_sqrt, mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Bps::new(lo).ok()
}

/// Whole-basis-point ceiling of the exact Bin/DLMM impact from the post-trade
/// active bin.
///
/// The bin price is `((10_000 + bin_step) / 10_000) ^ bin_id`; the relative
/// move is compared by exact cross multiplication. Returns `None` when the move
/// exceeds [`Bps::MAX`] or an exact power overflows `u128` (which itself implies
/// a move far beyond any representable band).
pub(crate) fn bin_impact_bps(
    bin_step: u16,
    active_bin_id: i32,
    resulting_bin_id: i32,
) -> Option<Bps> {
    if !bin_within(bin_step, active_bin_id, resulting_bin_id, Bps::MAX) {
        return None;
    }
    // `within(b)` is monotone in `b`; the smallest satisfying band is the
    // whole-basis-point ceiling of the exact impact.
    let mut lo = 0u16;
    let mut hi = Bps::MAX;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if bin_within(bin_step, active_bin_id, resulting_bin_id, mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Bps::new(lo).ok()
}

/// Exact predicate: is the CLMM price move within `target_bps`?
fn clmm_within(pool_sqrt: u128, resulting_sqrt: u128, target_bps: u16) -> bool {
    if resulting_sqrt == pool_sqrt {
        return true;
    }
    let t = target_bps as u128;
    if resulting_sqrt < pool_sqrt {
        // Price fell: impact <= t  <=>  (10_000 - t) * s^2 <= 10_000 * r^2.
        let lhs = (10_000u128 - t) * pool_sqrt;
        let rhs = 10_000u128 * resulting_sqrt;
        cmp_u128_products(lhs, pool_sqrt, rhs, resulting_sqrt) != Ordering::Greater
    } else {
        // Price rose: impact <= t  <=>  10_000 * r^2 <= (10_000 + t) * s^2.
        let lhs = 10_000u128 * resulting_sqrt;
        let rhs = (10_000u128 + t) * pool_sqrt;
        cmp_u128_products(lhs, resulting_sqrt, rhs, pool_sqrt) != Ordering::Greater
    }
}

/// Exact predicate: is the Bin price move within `target_bps`?
fn bin_within(bin_step: u16, active_bin_id: i32, resulting_bin_id: i32, target_bps: u16) -> bool {
    let diff = resulting_bin_id as i64 - active_bin_id as i64;
    if diff == 0 {
        return true;
    }
    let (base_num, base_den) = bin_base(bin_step);
    let exponent = diff.unsigned_abs() as u32;
    let t = target_bps as u128;

    if diff > 0 {
        // Price rose: impact <= t <=> num^d * 10_000 <= (10_000 + t) * den^d.
        let (Some(np), Some(dp)) = (
            base_num.checked_pow(exponent),
            base_den.checked_pow(exponent),
        ) else {
            return false;
        };
        cmp_u128_products(np, 10_000, 10_000 + t, dp) != Ordering::Greater
    } else {
        // Price fell: impact <= t <=> den^d * 10_000 >= (10_000 - t) * num^d.
        let (Some(np), Some(dp)) = (
            base_num.checked_pow(exponent),
            base_den.checked_pow(exponent),
        ) else {
            return false;
        };
        cmp_u128_products(dp, 10_000, 10_000 - t, np) != Ordering::Less
    }
}

fn bin_base(bin_step: u16) -> (u128, u128) {
    let num = 10_000u128 + bin_step as u128;
    let den = 10_000u128;
    let g = gcd_u128(num, den);
    (num / g, den / g)
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn clmm_quote_sqrt(pool: &ClmmPoolState, token_in: &AssetId, amount: u128) -> Option<u128> {
    let request = ClmmExactInputRequest {
        token_in: token_in.clone(),
        amount_in: AtomicAmount::new(amount),
        token_out: None,
    };
    simulate_clmm_exact_input(pool, &request)
        .ok()
        .map(|quote| quote.resulting_sqrt_price_x64)
}

fn bin_quote_id(pool: &BinPoolState, token_in: &AssetId, amount: u128) -> Option<i32> {
    let request = BinExactInputRequest::new(token_in.clone(), AtomicAmount::new(amount));
    simulate_bin_exact_input(pool, &request)
        .ok()
        .map(|quote| quote.resulting_active_bin_id)
}

/// Largest input the kernel accepts, found by bounded doubling + bisection.
///
/// Returns `None` when even a one-unit input fails. The predicate must be
/// monotone (true below the capacity, false above it), which the exact-input
/// kernels guarantee within the initialized range.
fn max_traversable(probe_ok: impl Fn(u128) -> bool) -> Option<u128> {
    if !probe_ok(1) {
        return None;
    }
    let mut lo: u128 = 1;
    let mut hi: u128 = 1;
    let mut bracketed = false;
    for _ in 0..MAX_DEPTH_DOUBLINGS {
        match hi.checked_mul(2) {
            Some(next) => {
                if probe_ok(next) {
                    lo = next;
                    hi = next;
                } else {
                    hi = next;
                    bracketed = true;
                    break;
                }
            }
            None => return Some(lo),
        }
    }
    if !bracketed {
        // The entire representable domain is traversable; `lo` is the floor.
        return Some(lo);
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if probe_ok(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

/// Largest input in `[1, cap]` satisfying `within`, or `None` when none does.
fn max_within(cap: u128, within: impl Fn(u128) -> bool) -> Option<u128> {
    if cap == 0 {
        return None;
    }
    if within(cap) {
        return Some(cap);
    }
    let mut lo: u128 = 0;
    let mut hi: u128 = cap;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if within(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        None
    } else {
        Some(lo)
    }
}

fn clmm_profile(
    pool: &ClmmPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    targets: &[Bps],
) -> Result<DepthProfile, RoutingError> {
    if token_in.chain != pool.token_0.chain {
        return Err(RoutingError::PoolChainMismatch);
    }
    if token_in != &pool.token_0 && token_in != &pool.token_1 {
        return Err(RoutingError::UnsupportedPoolKind);
    }
    let cap = max_traversable(|amount| clmm_quote_sqrt(pool, token_in, amount).is_some())
        .ok_or(RoutingError::UnsupportedPoolKind)?;

    let trade_impact_bps = clmm_quote_sqrt(pool, token_in, amount_in.get())
        .and_then(|resulting| clmm_impact_bps(pool.sqrt_price_x64, resulting));

    let mut levels = Vec::with_capacity(targets.len());
    for target in targets {
        let target_bps = target.get();
        let absorbed = max_within(cap, |amount| {
            clmm_quote_sqrt(pool, token_in, amount)
                .map(|resulting| clmm_within(pool.sqrt_price_x64, resulting, target_bps))
                .unwrap_or(false)
        });
        levels.push(DepthLevel {
            target_bps: *target,
            absorbed_in: absorbed.map(AtomicAmount::new),
        });
    }

    Ok(DepthProfile {
        levels,
        trade_impact_bps,
    })
}

fn bin_profile(
    pool: &BinPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    targets: &[Bps],
) -> Result<DepthProfile, RoutingError> {
    if token_in.chain != pool.token_0.chain {
        return Err(RoutingError::PoolChainMismatch);
    }
    if token_in != &pool.token_0 && token_in != &pool.token_1 {
        return Err(RoutingError::UnsupportedPoolKind);
    }
    let cap = max_traversable(|amount| bin_quote_id(pool, token_in, amount).is_some())
        .ok_or(RoutingError::UnsupportedPoolKind)?;

    let trade_impact_bps = bin_quote_id(pool, token_in, amount_in.get())
        .and_then(|resulting| bin_impact_bps(pool.bin_step, pool.active_bin_id, resulting));

    let mut levels = Vec::with_capacity(targets.len());
    for target in targets {
        let target_bps = target.get();
        let absorbed = max_within(cap, |amount| {
            bin_quote_id(pool, token_in, amount)
                .map(|resulting| {
                    bin_within(pool.bin_step, pool.active_bin_id, resulting, target_bps)
                })
                .unwrap_or(false)
        });
        levels.push(DepthLevel {
            target_bps: *target,
            absorbed_in: absorbed.map(AtomicAmount::new),
        });
    }

    Ok(DepthProfile {
        levels,
        trade_impact_bps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clmm_impact_is_a_ceiling_and_fails_closed_above_max() {
        // No move is exactly zero.
        assert_eq!(clmm_impact_bps(100, 100), Bps::new(0).ok());
        // A sub-basis-point move is reported as a one-bp ceiling, never zero.
        assert_eq!(clmm_impact_bps(1_000_000, 999_999), Bps::new(1).ok());
        // A tripling price move exceeds `Bps::MAX` and stays unrepresentable.
        assert_eq!(clmm_impact_bps(100, 300), None);
    }

    #[test]
    fn bin_impact_is_a_ceiling_and_fails_closed_above_max() {
        assert_eq!(bin_impact_bps(100, 1, 1), Bps::new(0).ok());
        // (101/100) down is 99.01 bps, reported as its whole-bp ceiling of 100.
        assert_eq!(bin_impact_bps(100, 1, 0), Bps::new(100).ok());
        // (1.1)^6 ~ 1.77x is representable...
        assert_eq!(bin_impact_bps(1_000, 0, 6), Bps::new(7_716).ok());
        // ...while (1.1)^8 ~ 2.14x exceeds `Bps::MAX`.
        assert_eq!(bin_impact_bps(1_000, 0, 8), None);
    }
}
