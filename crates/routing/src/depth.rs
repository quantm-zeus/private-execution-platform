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
    atomic_bin_price, cmp_u128_products, mul_u128_wide, simulate_bin_exact_input,
    simulate_clmm_exact_input, BinExactInputRequest, ClmmExactInputRequest,
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
/// Prices are compared through the kernel's own reduced per-bin prices
/// ([`atomic_bin_price`]), so a far-from-zero active bin never overflows: the
/// ratio between two bins is compared by exact cross multiplication instead of
/// materialising `base^|diff|`. Returns `None` when the move exceeds
/// [`Bps::MAX`] or a per-bin price is not representable.
pub(crate) fn bin_impact_bps(
    bin_step: u16,
    decimals_0: u8,
    decimals_1: u8,
    active_bin_id: i32,
    resulting_bin_id: i32,
) -> Option<Bps> {
    if !bin_within(
        bin_step,
        decimals_0,
        decimals_1,
        active_bin_id,
        resulting_bin_id,
        Bps::MAX,
    ) {
        return None;
    }
    // `within(b)` is monotone in `b`; the smallest satisfying band is the
    // whole-basis-point ceiling of the exact impact.
    let mut lo = 0u16;
    let mut hi = Bps::MAX;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if bin_within(
            bin_step,
            decimals_0,
            decimals_1,
            active_bin_id,
            resulting_bin_id,
            mid,
        ) {
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
///
/// Prefers the kernel's reduced per-bin prices (exact even when `|diff|` is large
/// relative to `|bin_id|`). If an endpoint price is not representable — the kernel
/// can still quote by skipping a zero-reserve active bin — it falls back to the
/// signed-exponent ratio `base^|diff|`, compared exactly with a small bignum so a
/// near-one ratio never fails closed merely because its individual powers overflow
/// `u128`.
fn bin_within(
    bin_step: u16,
    decimals_0: u8,
    decimals_1: u8,
    active_bin_id: i32,
    resulting_bin_id: i32,
    target_bps: u16,
) -> bool {
    if resulting_bin_id == active_bin_id {
        return true;
    }
    if let (Ok(before), Ok(after)) = (
        atomic_bin_price(bin_step, decimals_0, decimals_1, active_bin_id),
        atomic_bin_price(bin_step, decimals_0, decimals_1, resulting_bin_id),
    ) {
        return bin_price_within(before, after, resulting_bin_id > active_bin_id, target_bps);
    }
    bin_exponent_within(bin_step, active_bin_id, resulting_bin_id, target_bps)
}

/// Fallback predicate for an unrepresentable endpoint price, using the signed
/// exponent of the reduced bin base.
///
/// The ratio is compared exactly by a small bignum rather than by materialising
/// `base^|diff|` in `u128`: for a near-one ratio (small `bin_step`) both powers can
/// overflow while the exact move is still only a few basis points.
fn bin_exponent_within(
    bin_step: u16,
    active_bin_id: i32,
    resulting_bin_id: i32,
    target_bps: u16,
) -> bool {
    let diff = resulting_bin_id as i64 - active_bin_id as i64;
    if diff == 0 {
        return true;
    }
    let (base_num, base_den) = bin_base(bin_step);
    let exponent = diff.unsigned_abs() as u32;
    let t = target_bps as u64;
    if diff > 0 {
        // `(base_num/base_den)^e <= (10_000 + t)/10_000`
        //   <=>  `10_000 * base_num^e <= (10_000 + t) * base_den^e`.
        bin_pow_cmp(base_num, base_den, exponent, 10_000, 10_000 + t) != Ordering::Greater
    } else {
        // `(base_den/base_num)^e >= (10_000 - t)/10_000`
        //   <=>  `(10_000 - t) * base_num^e <= 10_000 * base_den^e`.
        bin_pow_cmp(base_num, base_den, exponent, 10_000 - t, 10_000) != Ordering::Greater
    }
}

/// Little-endian `u64` bignum limbs.
type Big = Vec<u64>;

/// Exact comparison of `lhs_scale * base_num^exponent` against
/// `rhs_scale * base_den^exponent`.
///
/// `base_num`/`base_den` come from [`bin_base`] (at most `11_000`/`10_000`) and the
/// exponent is bounded by the kernel's bin-crossing budget, so the exact powers fit
/// comfortably in a small little-endian bignum. This is the only way to compare a
/// near-one ratio whose individual powers overflow `u128`.
fn bin_pow_cmp(
    base_num: u128,
    base_den: u128,
    exponent: u32,
    lhs_scale: u64,
    rhs_scale: u64,
) -> Ordering {
    let lhs = mul_big_small(&pow_big(base_num as u64, exponent), lhs_scale);
    let rhs = mul_big_small(&pow_big(base_den as u64, exponent), rhs_scale);
    cmp_big(&lhs, &rhs)
}

/// `base^exponent` as a little-endian `u64` bignum (repeated small multiplication).
fn pow_big(base: u64, exponent: u32) -> Big {
    let mut result: Big = vec![1];
    for _ in 0..exponent {
        result = mul_big_small(&result, base);
    }
    result
}

/// `value * factor` as a bignum.
fn mul_big_small(value: &[u64], factor: u64) -> Big {
    let mut out = Vec::with_capacity(value.len() + 1);
    let mut carry: u128 = 0;
    for &limb in value {
        let acc = limb as u128 * factor as u128 + carry;
        out.push(acc as u64);
        carry = acc >> 64;
    }
    if carry != 0 {
        out.push(carry as u64);
    }
    trim_big(out)
}

/// Drops high-order zero limbs.
fn trim_big(mut value: Big) -> Big {
    while value.len() > 1 && value.last() == Some(&0) {
        value.pop();
    }
    value
}

/// Compares two little-endian bignums.
fn cmp_big(left: &[u64], right: &[u64]) -> Ordering {
    if left.len() != right.len() {
        return left.len().cmp(&right.len());
    }
    left.iter().rev().cmp(right.iter().rev())
}

/// Reduced bin price base `((10_000 + bin_step) / 10_000)`.
fn bin_base(bin_step: u16) -> (u128, u128) {
    let num = 10_000u128 + bin_step as u128;
    let den = 10_000u128;
    let divisor = gcd_u128(num, den);
    (num / divisor, den / divisor)
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

/// Exact predicate: is `after / before` within `target_bps` of one?
///
/// `before`/`after` are reduced `(numerator, denominator)` bin prices; the
/// relative move is compared by exact 256-bit cross multiplication, so it never
/// materialises a large power (which would overflow for a far-from-zero active
/// bin even when both per-bin prices are representable).
fn bin_price_within(
    before: (u128, u128),
    after: (u128, u128),
    rose: bool,
    target_bps: u16,
) -> bool {
    let numerator = mul_u128_wide(after.0, before.1);
    let denominator = mul_u128_wide(after.1, before.0);
    let target = target_bps as u128;
    if rose {
        // ratio <= (10_000 + t) / 10_000.
        cmp_scaled_u256(numerator, 10_000, denominator, 10_000 + target) != Ordering::Greater
    } else {
        // ratio >= (10_000 - t) / 10_000.
        cmp_scaled_u256(numerator, 10_000, denominator, 10_000 - target) != Ordering::Less
    }
}

/// Exact comparison of `a * scale_a` against `b * scale_b`, where the operands
/// are 256-bit products of two `u128`s and the scales are small.
fn cmp_scaled_u256(a: (u128, u128), scale_a: u128, b: (u128, u128), scale_b: u128) -> Ordering {
    scale_u256(a, scale_a).cmp(&scale_u256(b, scale_b))
}

/// Multiplies a 256-bit `(hi, lo)` by a small scalar into three `u128` limbs.
fn scale_u256(value: (u128, u128), scalar: u128) -> (u128, u128, u128) {
    let (low_carry, low) = mul_u128_wide(value.1, scalar);
    let (high_carry, high) = mul_u128_wide(value.0, scalar);
    let (mid, carry) = high.overflowing_add(low_carry);
    let top = high_carry.wrapping_add(carry as u128);
    (top, mid, low)
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
/// A deep pool can reject a one-unit probe (an exact quote that rounds to zero
/// price movement reports `InvariantViolated`) while accepting a slightly larger
/// input, so the search first finds *any* accepted power-of-two input and only
/// then brackets the capacity above it. Returns `None` when no probed input is
/// accepted. The predicate must be monotone above the accepted start, which the
/// exact-input kernels guarantee within the initialized range.
fn max_traversable(probe_ok: impl Fn(u128) -> bool) -> Option<u128> {
    let mut start: u128 = 1;
    let mut found = false;
    for _ in 0..MAX_DEPTH_DOUBLINGS {
        if probe_ok(start) {
            found = true;
            break;
        }
        start = start.checked_mul(2)?;
    }
    if !found {
        return None;
    }
    let mut lo: u128 = start;
    let mut hi: u128 = start;
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

    let trade_impact_bps = bin_quote_id(pool, token_in, amount_in.get()).and_then(|resulting| {
        bin_impact_bps(
            pool.bin_step,
            pool.decimals_0,
            pool.decimals_1,
            pool.active_bin_id,
            resulting,
        )
    });

    let mut levels = Vec::with_capacity(targets.len());
    for target in targets {
        let target_bps = target.get();
        let absorbed = max_within(cap, |amount| {
            bin_quote_id(pool, token_in, amount)
                .map(|resulting| {
                    bin_within(
                        pool.bin_step,
                        pool.decimals_0,
                        pool.decimals_1,
                        pool.active_bin_id,
                        resulting,
                        target_bps,
                    )
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
        assert_eq!(bin_impact_bps(100, 0, 0, 1, 1), Bps::new(0).ok());
        // (101/100) down is 99.01 bps, reported as its whole-bp ceiling of 100.
        assert_eq!(bin_impact_bps(100, 0, 0, 1, 0), Bps::new(100).ok());
        // (1.1)^6 ~ 1.77x is representable...
        assert_eq!(bin_impact_bps(1_000, 0, 0, 0, 6), Bps::new(7_716).ok());
        // ...while (1.1)^8 ~ 2.14x exceeds `Bps::MAX`.
        assert_eq!(bin_impact_bps(1_000, 0, 0, 0, 8), None);
    }

    #[test]
    fn bin_impact_reuses_representable_per_bin_prices() {
        // A far-from-zero active bin: `|diff| = 18` overflows `base^|diff|`, but
        // every per-bin price is representable, so the ratio is still exact.
        // (10001/10000)^18 - 1 = 18.0153 bps -> ceiling 19.
        assert_eq!(bin_impact_bps(1, 0, 0, -9, 9), Bps::new(19).ok());
        // (10001/10000)^10 - 1 = 10.0045 bps -> ceiling 11 (previously `None`).
        assert_eq!(bin_impact_bps(1, 0, 0, -9, 1), Bps::new(11).ok());
    }

    #[test]
    fn scale_u256_matches_wide_multiplication() {
        // Low-limb scaling.
        assert_eq!(scale_u256((0, 7), 10_000), (0, 0, 70_000));
        // Low-limb carry into the middle limb: 2^127 * 2 = 2^128.
        assert_eq!(scale_u256((0, 1u128 << 127), 2), (0, 1, 0));
        // High-limb carry into the top limb.
        assert_eq!(scale_u256((u128::MAX, 0), 2), (1, u128::MAX - 1, 0));
        // Middle-limb carry into the top limb (independently recomputed).
        assert_eq!(
            scale_u256(
                (
                    226_854_911_280_625_642_308_916_404_954_512_140_970u128,
                    u128::MAX
                ),
                3
            ),
            (2, 0, u128::MAX - 2)
        );
    }

    #[test]
    fn bin_within_falls_back_when_an_endpoint_price_overflows() {
        // The active bin 38 is unrepresentable while the adjacent bin 37 is not:
        // the kernel can still quote by skipping the empty active bin, so the
        // predicate must fall back to the signed-exponent ratio.
        assert!(atomic_bin_price(1_000, 0, 0, 38).is_err());
        assert!(atomic_bin_price(1_000, 0, 0, 37).is_ok());
        // One bin below active is a 10/11 move: 909.09 bps -> within 910, not 909.
        assert!(bin_within(1_000, 0, 0, 38, 37, 910));
        assert!(!bin_within(1_000, 0, 0, 38, 37, 909));
    }

    #[test]
    fn bin_exponent_within_is_exact_when_a_per_bin_price_overflows() {
        // `bin_step = 1`: `10001^10` overflows `u128`, so `atomic_bin_price` fails
        // for bin 10, yet the exact ratio over ten bins is only ~9.995 bps (fall)
        // and ~10.005 bps (rise). The bignum fallback must decide exactly.
        assert!(atomic_bin_price(1, 0, 0, 10).is_err());
        assert!(bin_within(1, 0, 0, 10, 0, 10));
        assert!(!bin_within(1, 0, 0, 10, 0, 9));
        assert!(bin_within(1, 0, 0, 0, 10, 11));
        assert!(!bin_within(1, 0, 0, 0, 10, 10));
        // A far move is correctly rejected.
        assert!(!bin_within(1, 0, 0, 10, 0, 1));
    }

    #[test]
    fn bignum_pow_and_compare_are_exact() {
        // `2^64` carries into a second limb.
        assert_eq!(pow_big(2, 64), [0, 1]);
        // `mul_big_small` carry propagation: 2 * (2^64 - 1) = 2^65 - 2.
        assert_eq!(mul_big_small(&[u64::MAX], 2), [u64::MAX - 1, 1]);
        // Exact comparison, including the `lhs_scale`/`rhs_scale` factors.
        assert_eq!(bin_pow_cmp(3, 2, 5, 1, 1), Ordering::Greater);
        assert_eq!(bin_pow_cmp(2, 3, 4, 100, 1), Ordering::Greater);
        assert_eq!(bin_pow_cmp(2, 3, 4, 1, 100), Ordering::Less);
        assert_eq!(bin_pow_cmp(7, 7, 3, 5, 5), Ordering::Equal);
        assert_eq!(cmp_big(&[0], &[0]), Ordering::Equal);
        assert_eq!(cmp_big(&[u64::MAX, 1], &[0, 2]), Ordering::Less);
    }
}
