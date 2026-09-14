//! Pure deterministic Concentrated Liquidity Market Maker (CLMM) exact-input simulation.
//!
//! Part of Phase-3 bounded local exact simulation. Operates directly over canonical
//! [`market_types::ClmmPoolState`] within its current active liquidity range.
//! Fails closed before producing a quote if price movement would reach or cross
//! an initialized tick boundary.

use chain_types::AssetId;
use market_types::{AssetAmount, AtomicAmount, Bps, ClmmPoolState};
use serde::{Deserialize, Serialize};

use crate::cpmm::mul_u128_wide;
use crate::error::ClmmSimulationError;

pub const MIN_TICK: i32 = -887_272;
pub const MAX_TICK: i32 = 887_272;
pub const MIN_SQRT_PRICE_X64: u128 = 4_295_048_016;
pub const MAX_SQRT_PRICE_X64: u128 = 79_226_673_515_401_279_992_447_579_055;

const LOG_B_2_X32: i128 = 59_543_866_431_248i128;
const BIT_PRECISION: u32 = 14;
const LOG_B_P_ERR_MARGIN_LOWER_X64: i128 = 184_467_440_737_095_516i128;
const LOG_B_P_ERR_MARGIN_UPPER_X64: i128 = 15_793_534_762_490_258_745i128;

/// Request parameters for an exact-input direct CLMM swap simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmExactInputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Exact atomic input amount to swap.
    pub amount_in: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

/// Deterministic quote produced by CLMM single-range exact-input simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmSimulationQuote {
    /// Exact input asset and atomic amount.
    pub input: AssetAmount,
    /// Exact gross simulated output asset and atomic amount.
    pub output: AssetAmount,
    /// Explicit pool fee taken from input, denominated in input asset.
    pub fee: AssetAmount,
    /// Effective post-fee input amount entering CLMM price calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Resulting sqrt price in Q64.64 after simulated swap.
    pub resulting_sqrt_price_x64: u128,
    /// Resulting price tick after simulated swap.
    pub resulting_tick: i32,
    /// Resulting active liquidity after simulated swap.
    pub resulting_liquidity: u128,
}

/// Request parameters for an exact-output direct CLMM swap simulation.
///
/// The caller asks for a desired output amount and receives the **minimal** gross
/// input whose exact-input traversal yields at least that output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmExactOutputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Desired output amount from the pool.
    pub amount_out: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

impl ClmmExactOutputRequest {
    /// Creates an exact-output request with inferred output asset.
    pub const fn new(token_in: AssetId, amount_out: AtomicAmount) -> Self {
        Self {
            token_in,
            amount_out,
            token_out: None,
        }
    }

    /// Creates an exact-output request with caller-asserted output asset.
    pub const fn new_directed(
        token_in: AssetId,
        amount_out: AtomicAmount,
        token_out: AssetId,
    ) -> Self {
        Self {
            token_in,
            amount_out,
            token_out: Some(token_out),
        }
    }

    /// Simulates this request against the given pool state.
    pub fn simulate(
        &self,
        pool: &ClmmPoolState,
    ) -> Result<ClmmExactOutputQuote, ClmmSimulationError> {
        simulate_clmm_exact_output(pool, self)
    }
}

/// Deterministic quote produced by CLMM exact-output simulation.
///
/// `input` is the minimal gross input whose exact-input output is `>= requested_output`.
/// Because integer floor rounding makes an exact hit rare, the realized `output`
/// may exceed the requested amount by a bounded rounding remainder; `input - 1`
/// is proven insufficient fail-closed before returning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmExactOutputQuote {
    /// Minimal gross input, denominated in the input asset.
    pub input: AssetAmount,
    /// Requested output, denominated in the output asset.
    pub requested_output: AssetAmount,
    /// Realized output of `input`, denominated in the output asset (`>= requested_output`).
    pub output: AssetAmount,
    /// Pool fee taken from `input`, denominated in the input asset.
    pub fee: AssetAmount,
    /// Effective post-fee input entering the CLMM price calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Resulting sqrt price in Q64.64 after the required swap.
    pub resulting_sqrt_price_x64: u128,
    /// Resulting price tick after the required swap.
    pub resulting_tick: i32,
    /// Resulting active liquidity after the required swap.
    pub resulting_liquidity: u128,
}

impl ClmmExactOutputQuote {
    /// The realized rounding overshoot (`output - requested_output`), never negative.
    pub fn output_overshoot(&self) -> AtomicAmount {
        AtomicAmount::new(
            self.output
                .amount
                .get()
                .saturating_sub(self.requested_output.amount.get()),
        )
    }
}

/// Classification of an exact-input oracle failure for the bounded search.
///
/// The feasibility lemma partitions failures into a contiguous low end
/// (`ZeroOutputAmount`/`ZeroEffectiveInput`/`InvariantViolated`), a contiguous high
/// end (`TickCrossingExceeded`/`BinCrossingExceeded`/`ArithmeticOverflow`), and
/// everything else, which must abort the search fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeClass {
    /// Low-end failure: the input is below the feasible interval.
    Low,
    /// High-end failure: the input is above the feasible ceiling.
    High,
    /// A non-terminal hole in the feasible region: the exact-input kernel
    /// rejected an input that sits *between* `Ok` inputs (for example a
    /// mid-interval `InvariantViolated` rounding artifact). A hole is tolerated
    /// only before any `Ok` input has been observed; once the feasible region has
    /// begun, a hole contradicts monotonicity and the search fails closed rather
    /// than risk returning a non-minimal input.
    Hole,
    /// Any other failure: abort the search fail-closed.
    Unexpected,
}

/// Resolution of the bounded minimal gross-input search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MinimalInputSearch {
    /// The minimal gross input whose exact-input output covers the target.
    Found(u128),
    /// No representable gross input can cover the target.
    Unreachable,
    /// The feasibility-interval lemma was contradicted; fail closed.
    Invariant,
}

/// Finds the minimal gross input `g >= 1` whose exact-input output `f(g)` is
/// `>= target`, using `f` as the only output oracle.
///
/// **Lemma.** For a fixed valid pool and direction, the exact-input output `f(g)`
/// is non-decreasing over the inputs for which the kernel returns `Ok`, and that
/// `Ok` set is a contiguous interval `[g_min, g_max]` (possibly empty). Low-end
/// failures are `ZeroOutputAmount`/`ZeroEffectiveInput`/`InvariantViolated`;
/// high-end failures are `TickCrossingExceeded`/`BinCrossingExceeded`/
/// `ArithmeticOverflow`. Non-monotonicity is never assumed where the algorithm
/// refuses to return.
///
/// The ceiling is located by doubling and, on the first high-end failure, by
/// binary-searching the **smallest** high-error input (the high predicate is
/// monotone, unlike `Ok`, which is followed by high errors). The minimal input is
/// then binary-searched for on `[1, hi]`, and `g - 1` is re-probed to prove
/// minimality before returning. `f` is never called with `g == 0`.
pub(crate) fn find_min_gross_input<E>(
    target: u128,
    mut f: impl FnMut(u128) -> Result<u128, E>,
    classify: impl Fn(&E) -> ProbeClass,
) -> Result<MinimalInputSearch, E> {
    // --- 1. Locate a covering upper bound `hi`. ---
    //
    // `seen_ok` records whether any probe has succeeded. A `Hole` is only
    // tolerated while `!seen_ok`; afterwards it is a monotonicity contradiction
    // and the search fails closed.
    let mut seen_ok = false;
    let mut prev: u128 = 0;
    let mut g: u128 = 1;
    let hi: u128 = loop {
        match f(g) {
            Ok(out) => {
                seen_ok = true;
                if out >= target {
                    break g;
                }
                prev = g;
            }
            Err(err) => match classify(&err) {
                ProbeClass::Low => prev = g,
                ProbeClass::Hole => {
                    if seen_ok {
                        return Err(err);
                    }
                    prev = g;
                }
                ProbeClass::High => {
                    // `g` is above the ceiling while `prev` is not: binary-search
                    // the smallest high-error input `x` in `(prev, g]`.
                    let mut lo = prev;
                    let mut high = g;
                    while high - lo > 1 {
                        // `high >= lo + 2`, so `mid >= lo + 1 >= 1`: never zero.
                        let mid = lo + (high - lo) / 2;
                        match f(mid) {
                            Ok(_) => {
                                seen_ok = true;
                                lo = mid;
                            }
                            Err(inner) => match classify(&inner) {
                                ProbeClass::High => high = mid,
                                ProbeClass::Low => lo = mid,
                                ProbeClass::Hole => {
                                    if seen_ok {
                                        return Err(inner);
                                    }
                                    lo = mid;
                                }
                                ProbeClass::Unexpected => return Err(inner),
                            },
                        }
                    }
                    let x = high;
                    // `x >= 1`, so `x - 1` is a legal probe. If it is zero the
                    // feasible interval is empty (`f(1)` already failed high).
                    let g_max = x - 1;
                    if g_max == 0 {
                        return Ok(MinimalInputSearch::Unreachable);
                    }
                    match f(g_max) {
                        Ok(out) => {
                            if out >= target {
                                break g_max;
                            }
                            return Ok(MinimalInputSearch::Unreachable);
                        }
                        Err(inner) => match classify(&inner) {
                            ProbeClass::Low => return Ok(MinimalInputSearch::Unreachable),
                            ProbeClass::Hole => {
                                if seen_ok {
                                    return Err(inner);
                                }
                                return Ok(MinimalInputSearch::Unreachable);
                            }
                            ProbeClass::High => return Ok(MinimalInputSearch::Invariant),
                            ProbeClass::Unexpected => return Err(inner),
                        },
                    }
                }
                ProbeClass::Unexpected => return Err(err),
            },
        }

        // Advance the doubling probe without ever calling `f(0)` or overflowing.
        if g == u128::MAX {
            return Ok(MinimalInputSearch::Unreachable);
        }
        if g > u128::MAX / 2 {
            g = u128::MAX;
        } else {
            g *= 2;
        }
    };

    // --- 2. Minimal covering input in `[1, hi]` (predicate is monotone here). ---
    let mut lo: u128 = 1;
    let mut bound: u128 = hi;
    while lo < bound {
        let mid = lo + (bound - lo) / 2;
        let covers = match f(mid) {
            Ok(out) => out >= target,
            // A hole, ceiling, or unexpected failure inside `[1, hi]` means the
            // predicate is no longer monotone, so fail closed instead of risking a
            // non-minimal result. A genuine low-end failure is a legitimate "no".
            Err(err) => match classify(&err) {
                ProbeClass::Low => false,
                ProbeClass::Hole | ProbeClass::High | ProbeClass::Unexpected => return Err(err),
            },
        };
        if covers {
            bound = mid;
        } else {
            lo = mid + 1;
        }
    }
    let g_star = lo;

    // --- 3. Realize and prove minimality. ---
    match f(g_star) {
        Ok(out) if out >= target => {}
        _ => return Ok(MinimalInputSearch::Invariant),
    }
    if g_star > 1 {
        match f(g_star - 1) {
            Ok(previous) => {
                if previous >= target {
                    return Ok(MinimalInputSearch::Invariant);
                }
            }
            Err(err) => match classify(&err) {
                ProbeClass::Low => {}
                ProbeClass::Hole | ProbeClass::High | ProbeClass::Unexpected => return Err(err),
            },
        }
    }

    Ok(MinimalInputSearch::Found(g_star))
}

/// Classifies a CLMM exact-input failure for the minimal-input search.
fn clmm_probe_class(err: &ClmmSimulationError) -> ProbeClass {
    match err {
        ClmmSimulationError::ZeroOutputAmount | ClmmSimulationError::ZeroEffectiveInput => {
            ProbeClass::Low
        }
        ClmmSimulationError::InvariantViolated => ProbeClass::Hole,
        ClmmSimulationError::TickCrossingExceeded | ClmmSimulationError::ArithmeticOverflow => {
            ProbeClass::High
        }
        _ => ProbeClass::Unexpected,
    }
}

/// 512-bit unsigned integer represented as four 128-bit limbs in little-endian order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U512([u128; 4]);

impl U512 {
    const ZERO: Self = Self([0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0]);

    #[inline]
    const fn from_u128(val: u128) -> Self {
        Self([val, 0, 0, 0])
    }

    #[inline]
    const fn from_u256(lo: u128, hi: u128) -> Self {
        Self([lo, hi, 0, 0])
    }

    #[inline]
    fn mul_u128(a: u128, b: u128) -> Self {
        let (hi, lo) = mul_u128_wide(a, b);
        Self::from_u256(lo, hi)
    }

    #[inline]
    fn shl_64(&self) -> Option<Self> {
        if self.0[3] >> 64 != 0 {
            return None;
        }
        let w0 = self.0[0] << 64;
        let w1 = (self.0[1] << 64) | (self.0[0] >> 64);
        let w2 = (self.0[2] << 64) | (self.0[1] >> 64);
        let w3 = (self.0[3] << 64) | (self.0[2] >> 64);
        Some(Self([w0, w1, w2, w3]))
    }

    #[inline]
    fn shl_1(&self) -> Option<Self> {
        if (self.0[3] >> 127) != 0 {
            return None;
        }
        let w0 = self.0[0] << 1;
        let w1 = (self.0[1] << 1) | (self.0[0] >> 127);
        let w2 = (self.0[2] << 1) | (self.0[1] >> 127);
        let w3 = (self.0[3] << 1) | (self.0[2] >> 127);
        Some(Self([w0, w1, w2, w3]))
    }

    #[inline]
    fn shr_1(&self) -> Self {
        let w0 = (self.0[0] >> 1) | (self.0[1] << 127);
        let w1 = (self.0[1] >> 1) | (self.0[2] << 127);
        let w2 = (self.0[2] >> 1) | (self.0[3] << 127);
        let w3 = self.0[3] >> 1;
        Self([w0, w1, w2, w3])
    }

    #[inline]
    fn add(&self, other: &Self) -> Option<Self> {
        let mut result = [0u128; 4];
        let mut carry = false;
        let mut i = 0;
        while i < 4 {
            let (sum1, c1) = self.0[i].overflowing_add(other.0[i]);
            let (sum2, c2) = sum1.overflowing_add(if carry { 1 } else { 0 });
            result[i] = sum2;
            carry = c1 || c2;
            i += 1;
        }
        if carry {
            None
        } else {
            Some(Self(result))
        }
    }

    #[inline]
    fn sub(&self, other: &Self) -> Option<Self> {
        let mut result = [0u128; 4];
        let mut borrow = false;
        let mut i = 0;
        while i < 4 {
            let (diff1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (diff2, b2) = diff1.overflowing_sub(if borrow { 1 } else { 0 });
            result[i] = diff2;
            borrow = b1 || b2;
            i += 1;
        }
        if borrow {
            None
        } else {
            Some(Self(result))
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    #[inline]
    fn bits(&self) -> u32 {
        if self.0[3] != 0 {
            512 - self.0[3].leading_zeros()
        } else if self.0[2] != 0 {
            384 - self.0[2].leading_zeros()
        } else if self.0[1] != 0 {
            256 - self.0[1].leading_zeros()
        } else if self.0[0] != 0 {
            128 - self.0[0].leading_zeros()
        } else {
            0
        }
    }

    /// Divides `self` by `den`, returning `(quotient, remainder)`.
    fn div_rem(&self, den: &Self) -> Option<(Self, Self)> {
        if den.is_zero() {
            return None;
        }
        if self < den {
            return Some((Self::ZERO, *self));
        }
        if self == den {
            return Some((Self::ONE, Self::ZERO));
        }

        let num_bits = self.bits();
        let den_bits = den.bits();
        let shift = num_bits.saturating_sub(den_bits);

        let mut current_den = *den;
        for _ in 0..shift {
            current_den = current_den.shl_1()?;
        }

        let mut rem = *self;
        let mut quot = Self::ZERO;

        for i in (0..=shift).rev() {
            if rem >= current_den {
                rem = rem.sub(&current_den)?;
                let limb = (i / 128) as usize;
                let bit = i % 128;
                quot.0[limb] |= 1u128 << bit;
            }
            current_den = current_den.shr_1();
        }

        Some((quot, rem))
    }

    #[inline]
    fn div_floor(&self, den: &Self) -> Option<Self> {
        let (quot, _) = self.div_rem(den)?;
        Some(quot)
    }

    #[inline]
    fn div_ceil(&self, den: &Self) -> Option<Self> {
        let (quot, rem) = self.div_rem(den)?;
        if !rem.is_zero() {
            quot.add(&Self::ONE)
        } else {
            Some(quot)
        }
    }

    #[inline]
    fn as_u128(&self) -> Option<u128> {
        if self.0[1] != 0 || self.0[2] != 0 || self.0[3] != 0 {
            None
        } else {
            Some(self.0[0])
        }
    }
}

impl Ord for U512 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0[3]
            .cmp(&other.0[3])
            .then_with(|| self.0[2].cmp(&other.0[2]))
            .then_with(|| self.0[1].cmp(&other.0[1]))
            .then_with(|| self.0[0].cmp(&other.0[0]))
    }
}

impl PartialOrd for U512 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[inline]
fn mul_shift_96(n0: u128, n1: u128) -> u128 {
    let (hi, lo) = mul_u128_wide(n0, n1);
    (lo >> 96) | (hi << 32)
}

/// Derives sqrt-price in Q64.64 from a tick index.
pub fn sqrt_price_from_tick_index(tick: i32) -> Result<u128, ClmmSimulationError> {
    if !(MIN_TICK..=MAX_TICK).contains(&tick) {
        return Err(ClmmSimulationError::InvalidTick);
    }
    if tick >= 0 {
        Ok(get_sqrt_price_positive_tick(tick))
    } else {
        Ok(get_sqrt_price_negative_tick(tick))
    }
}

fn get_sqrt_price_positive_tick(tick: i32) -> u128 {
    let mut ratio: u128 = if tick & 1 != 0 {
        79_232_123_823_359_799_118_286_999_567
    } else {
        79_228_162_514_264_337_593_543_950_336
    };

    if tick & 2 != 0 {
        ratio = mul_shift_96(ratio, 79_236_085_330_515_764_027_303_304_731);
    }
    if tick & 4 != 0 {
        ratio = mul_shift_96(ratio, 79_244_008_939_048_815_603_706_035_061);
    }
    if tick & 8 != 0 {
        ratio = mul_shift_96(ratio, 79_259_858_533_276_714_757_314_932_305);
    }
    if tick & 16 != 0 {
        ratio = mul_shift_96(ratio, 79_291_567_232_598_584_799_939_703_904);
    }
    if tick & 32 != 0 {
        ratio = mul_shift_96(ratio, 79_355_022_692_464_371_645_785_046_466);
    }
    if tick & 64 != 0 {
        ratio = mul_shift_96(ratio, 79_482_085_999_252_804_386_437_311_141);
    }
    if tick & 128 != 0 {
        ratio = mul_shift_96(ratio, 79_736_823_300_114_093_921_829_183_326);
    }
    if tick & 256 != 0 {
        ratio = mul_shift_96(ratio, 80_248_749_790_819_932_309_965_073_892);
    }
    if tick & 512 != 0 {
        ratio = mul_shift_96(ratio, 81_282_483_887_344_747_381_513_967_011);
    }
    if tick & 1024 != 0 {
        ratio = mul_shift_96(ratio, 83_390_072_131_320_151_908_154_831_281);
    }
    if tick & 2048 != 0 {
        ratio = mul_shift_96(ratio, 87_770_609_709_833_776_024_991_924_138);
    }
    if tick & 4096 != 0 {
        ratio = mul_shift_96(ratio, 97_234_110_755_111_693_312_479_820_773);
    }
    if tick & 8192 != 0 {
        ratio = mul_shift_96(ratio, 119_332_217_159_966_728_226_237_229_890);
    }
    if tick & 16384 != 0 {
        ratio = mul_shift_96(ratio, 179_736_315_981_702_064_433_883_588_727);
    }
    if tick & 32768 != 0 {
        ratio = mul_shift_96(ratio, 407_748_233_172_238_350_107_850_275_304);
    }
    if tick & 65536 != 0 {
        ratio = mul_shift_96(ratio, 2_098_478_828_474_011_932_436_660_412_517);
    }
    if tick & 131072 != 0 {
        ratio = mul_shift_96(ratio, 55_581_415_166_113_811_149_459_800_483_533);
    }
    if tick & 262144 != 0 {
        ratio = mul_shift_96(ratio, 389_923_685_446_031_399_322_330_549_999_935_511);
    }

    ratio >> 32
}

fn get_sqrt_price_negative_tick(tick: i32) -> u128 {
    let abs_tick = tick.unsigned_abs() as i32;

    let mut ratio: u128 = if abs_tick & 1 != 0 {
        18_445_821_805_675_392_311
    } else {
        18_446_744_073_709_551_616
    };

    if abs_tick & 2 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_444_899_583_751_176_498);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 4 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_443_055_278_223_354_162);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 8 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_439_367_220_385_604_838);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 16 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_431_993_317_065_449_817);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 32 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_417_254_355_718_160_513);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 64 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_387_811_781_193_591_352);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 128 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_329_067_761_203_520_168);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 256 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 18_212_142_134_806_087_854);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 512 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 17_980_523_815_641_551_639);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 1024 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 17_526_086_738_831_147_013);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 2048 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 16_651_378_430_235_024_244);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 4096 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 15_030_750_278_693_429_944);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 8192 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 12_247_334_978_882_834_399);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 16384 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 8_131_365_268_884_726_200);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 32768 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 3_584_323_654_723_342_297);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 65536 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 696_457_651_847_595_233);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 131072 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 26_294_789_957_452_057);
        ratio = (lo >> 64) | (hi << 64);
    }
    if abs_tick & 262144 != 0 {
        let (hi, lo) = mul_u128_wide(ratio, 37_481_735_321_082);
        ratio = (lo >> 64) | (hi << 64);
    }

    ratio
}

/// Derives tick index from a sqrt-price in Q64.64.
pub fn tick_index_from_sqrt_price(sqrt_price_x64: u128) -> Result<i32, ClmmSimulationError> {
    if !(MIN_SQRT_PRICE_X64..=MAX_SQRT_PRICE_X64).contains(&sqrt_price_x64) {
        return Err(ClmmSimulationError::InvalidPrice);
    }

    let msb: u32 = 128 - sqrt_price_x64.leading_zeros() - 1;
    let log2p_integer_x32 = (msb as i128 - 64) << 32;

    let mut bit: i128 = 0x8000_0000_0000_0000i128;
    let mut precision = 0;
    let mut log2p_fraction_x64: i128 = 0;

    let mut r = if msb >= 64 {
        sqrt_price_x64 >> (msb - 63)
    } else {
        sqrt_price_x64 << (63 - msb)
    };

    while bit > 0 && precision < BIT_PRECISION {
        r = r.wrapping_mul(r);
        let is_r_more_than_two = r >> 127_u32;
        r >>= 63 + is_r_more_than_two;
        log2p_fraction_x64 += bit * (is_r_more_than_two as i128);
        bit >>= 1;
        precision += 1;
    }

    let log2p_fraction_x32 = log2p_fraction_x64 >> 32;
    let log2p_x32 = log2p_integer_x32 + log2p_fraction_x32;

    let logbp_x64 = log2p_x32.wrapping_mul(LOG_B_2_X32);

    let tick_low: i32 = ((logbp_x64 - LOG_B_P_ERR_MARGIN_LOWER_X64) >> 64) as i32;
    let tick_high: i32 = ((logbp_x64 + LOG_B_P_ERR_MARGIN_UPPER_X64) >> 64) as i32;

    let tick_cand = if tick_low == tick_high {
        tick_low
    } else {
        let actual_tick_high_sqrt_price_x64 = sqrt_price_from_tick_index(tick_high)?;
        if actual_tick_high_sqrt_price_x64 <= sqrt_price_x64 {
            tick_high
        } else {
            tick_low
        }
    };

    Ok(tick_cand.clamp(MIN_TICK, MAX_TICK))
}

/// Hard cap on the maximum number of initialized tick boundaries that can be crossed in a single simulation.
pub const MAX_CLMM_TICK_CROSSES: usize = 32;

#[inline]
fn checked_add_net(liquidity: u128, net: i128) -> Result<u128, ClmmSimulationError> {
    let new_liq = if net >= 0 {
        liquidity
            .checked_add(net as u128)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
    } else {
        liquidity
            .checked_sub(net.unsigned_abs())
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
    };
    if new_liq == 0 {
        return Err(ClmmSimulationError::InvalidLiquidity);
    }
    Ok(new_liq)
}

#[inline]
fn checked_sub_net(liquidity: u128, net: i128) -> Result<u128, ClmmSimulationError> {
    let new_liq = if net >= 0 {
        liquidity
            .checked_sub(net as u128)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
    } else {
        liquidity
            .checked_add(net.unsigned_abs())
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
    };
    if new_liq == 0 {
        return Err(ClmmSimulationError::InvalidLiquidity);
    }
    Ok(new_liq)
}

/// Simulates a direct exact-input swap over a CLMM pool state across bounded initialized tick ranges.
///
/// Deterministically traverses represented initialized ticks in [`market_types::ClmmPoolState`],
/// applying one-time input fee accounting and checked signed net-liquidity transitions.
/// Fails closed before producing a quote if traversal requires crossing beyond represented ticks,
/// exceeds [`MAX_CLMM_TICK_CROSSES`], encounters zero or overflowing liquidity, or violates invariants.
pub fn simulate_clmm_exact_input(
    pool: &ClmmPoolState,
    request: &ClmmExactInputRequest,
) -> Result<ClmmSimulationQuote, ClmmSimulationError> {
    // 1. Validate pool contract invariants
    pool.validate().map_err(ClmmSimulationError::from)?;

    // 2. Reject zero input amount
    if request.amount_in.is_zero() {
        return Err(ClmmSimulationError::ZeroInputAmount);
    }

    // 3. Reject zero or invalid liquidity
    if pool.liquidity == 0 {
        return Err(ClmmSimulationError::InvalidLiquidity);
    }

    // 4. Validate sqrt price bounds
    if pool.sqrt_price_x64 == 0
        || !(MIN_SQRT_PRICE_X64..=MAX_SQRT_PRICE_X64).contains(&pool.sqrt_price_x64)
    {
        return Err(ClmmSimulationError::InvalidPrice);
    }

    // 5. Validate tick range
    if !(MIN_TICK..=MAX_TICK).contains(&pool.current_tick) {
        return Err(ClmmSimulationError::InvalidTick);
    }

    // 6. Validate fee bounds
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(ClmmSimulationError::InvalidFee);
    }

    // 7. Validate chain binding
    if request.token_in.chain != pool.token_0.chain {
        return Err(ClmmSimulationError::ChainMismatch);
    }

    // 8. Determine swap direction
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(ClmmSimulationError::InvalidAssetDirection);
    };

    let expected_out = if is_token_0_in {
        &pool.token_1
    } else {
        &pool.token_0
    };

    // 9. Validate caller-asserted output asset if provided
    if let Some(ref caller_out) = request.token_out {
        if caller_out.chain != pool.token_0.chain {
            return Err(ClmmSimulationError::ChainMismatch);
        }
        if caller_out == &request.token_in {
            return Err(ClmmSimulationError::InvalidAssetDirection);
        }
        if caller_out != expected_out {
            return Err(ClmmSimulationError::OutputAssetMismatch);
        }
    }

    // 10. Validate canonical coherence between current tick and sqrt price
    let recovered_tick = tick_index_from_sqrt_price(pool.sqrt_price_x64)?;
    if recovered_tick != pool.current_tick {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // 11. Find active range bounded by initialized ticks
    // Initialized ticks in pool.ticks must have at least 2 ticks to form a valid active range.
    if pool.ticks.len() < 2 {
        return Err(ClmmSimulationError::InvalidRange);
    }

    let min_init_tick = pool.ticks[0].index;
    let max_init_tick = pool.ticks[pool.ticks.len() - 1].index;
    if pool.current_tick < min_init_tick || pool.current_tick >= max_init_tick {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // Locate the unique initialized interval [t_lower, t_upper) containing current_tick
    let mut lower_tick_idx = None;
    for i in 0..(pool.ticks.len() - 1) {
        if pool.ticks[i].index <= pool.current_tick && pool.current_tick < pool.ticks[i + 1].index {
            lower_tick_idx = Some(i);
            break;
        }
    }

    let mut current_range_idx = lower_tick_idx.ok_or(ClmmSimulationError::InvalidRange)?;
    let t_lower = pool.ticks[current_range_idx].index;
    let t_upper = pool.ticks[current_range_idx + 1].index;

    let s_lower = sqrt_price_from_tick_index(t_lower)?;
    let s_upper = sqrt_price_from_tick_index(t_upper)?;

    if s_lower >= s_upper {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // Price must lie within active range bounds [s_lower, s_upper)
    if pool.sqrt_price_x64 < s_lower || pool.sqrt_price_x64 >= s_upper {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // 12. Apply pool fee exactly once before price movement calculation
    let amount_in_val = request.amount_in.get();
    let (fee_hi, fee_lo) = mul_u128_wide(amount_in_val, fee_bps_val as u128);
    let fee_val = crate::cpmm::div_u256_by_u128_floor(fee_hi, fee_lo, 10_000)
        .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
    let effective_input_val = amount_in_val
        .checked_sub(fee_val)
        .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

    if effective_input_val == 0 {
        return Err(ClmmSimulationError::ZeroEffectiveInput);
    }

    // 13. Initialize simulation traversal state
    let mut current_s = pool.sqrt_price_x64;
    let mut current_tick = pool.current_tick;
    let mut current_liquidity = pool.liquidity;
    let mut remaining_input = effective_input_val;
    let mut total_output: u128 = 0;
    let mut tick_crosses: usize = 0;

    // 14. Bounded tick traversal loop
    while remaining_input > 0 {
        if is_token_0_in {
            // Direction: Token 0 in -> Token 1 out. Price moves DOWN towards lower ticks.
            let range_lower_tick = pool.ticks[current_range_idx].index;
            let mut s_lower = sqrt_price_from_tick_index(range_lower_tick)?;

            // If already at lower boundary of this range, cross into the range below
            if current_s == s_lower {
                if current_range_idx == 0 {
                    return Err(ClmmSimulationError::TickCrossingExceeded);
                }
                if tick_crosses >= MAX_CLMM_TICK_CROSSES {
                    return Err(ClmmSimulationError::TickCrossingExceeded);
                }
                let net = pool.ticks[current_range_idx].liquidity_net;
                current_liquidity = checked_sub_net(current_liquidity, net)?;
                tick_crosses += 1;
                current_range_idx -= 1;
                s_lower = sqrt_price_from_tick_index(pool.ticks[current_range_idx].index)?;
            }

            if current_s <= s_lower {
                return Err(ClmmSimulationError::InvariantViolated);
            }

            // Max token 0 input to reach lower boundary:
            // delta_x_max = ceil( (L * 2^64 * (current_s - s_lower)) / (current_s * s_lower) )
            let delta_s = current_s - s_lower;
            let num_delta = U512::mul_u128(current_liquidity, delta_s)
                .shl_64()
                .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
            let den_delta = U512::mul_u128(current_s, s_lower);
            let delta_x_max = num_delta
                .div_ceil(&den_delta)
                .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

            if U512::from_u128(remaining_input) < delta_x_max {
                // Next price: s_next = ceil( (L * 2^64 * current_s) / (L * 2^64 + remaining_input * current_s) )
                let num_price = U512::mul_u128(current_liquidity, current_s)
                    .shl_64()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
                let l_x64 = U512::from_u128(current_liquidity)
                    .shl_64()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
                let in_times_s = U512::mul_u128(remaining_input, current_s);
                let den_price = l_x64
                    .add(&in_times_s)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let s_next = num_price
                    .div_ceil(&den_price)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                if s_next <= s_lower || s_next >= current_s {
                    return Err(ClmmSimulationError::InvariantViolated);
                }

                // Output token 1: delta_y = floor( (L * (current_s - s_next)) / 2^64 )
                let delta_s_out = current_s - s_next;
                let (num_y_hi, num_y_lo) = mul_u128_wide(current_liquidity, delta_s_out);
                let out_y = (num_y_lo >> 64) | (num_y_hi << 64);
                if num_y_hi >> 64 != 0 {
                    return Err(ClmmSimulationError::ArithmeticOverflow);
                }
                if out_y == 0 && total_output == 0 {
                    return Err(ClmmSimulationError::ZeroOutputAmount);
                }

                total_output = total_output
                    .checked_add(out_y)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let res_tick = tick_index_from_sqrt_price(s_next)?;
                if res_tick < pool.ticks[current_range_idx].index {
                    return Err(ClmmSimulationError::InvariantViolated);
                }

                current_s = s_next;
                current_tick = res_tick;
                break;
            } else {
                // Input is sufficient to reach lower boundary s_lower
                if U512::from_u128(remaining_input) > delta_x_max {
                    if current_range_idx == 0 {
                        return Err(ClmmSimulationError::TickCrossingExceeded);
                    }
                    if tick_crosses >= MAX_CLMM_TICK_CROSSES {
                        return Err(ClmmSimulationError::TickCrossingExceeded);
                    }
                }

                let input_step = delta_x_max
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let delta_s_out = current_s - s_lower;
                let (num_y_hi, num_y_lo) = mul_u128_wide(current_liquidity, delta_s_out);
                let out_y = (num_y_lo >> 64) | (num_y_hi << 64);
                if num_y_hi >> 64 != 0 {
                    return Err(ClmmSimulationError::ArithmeticOverflow);
                }

                total_output = total_output
                    .checked_add(out_y)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                remaining_input = remaining_input
                    .checked_sub(input_step)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                current_s = s_lower;
                current_tick = pool.ticks[current_range_idx].index;
            }
        } else {
            // Direction: Token 1 in -> Token 0 out. Price moves UP towards upper ticks.
            let range_upper_tick = pool.ticks[current_range_idx + 1].index;
            let s_upper = sqrt_price_from_tick_index(range_upper_tick)?;

            if current_s >= s_upper {
                return Err(ClmmSimulationError::InvariantViolated);
            }

            // Max token 1 input to reach upper boundary:
            // delta_y_max = ceil( (L * (s_upper - current_s)) / 2^64 )
            let delta_s = s_upper - current_s;
            let num_delta = U512::mul_u128(current_liquidity, delta_s);
            let den_x64 = U512::ONE
                .shl_64()
                .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
            let delta_y_max = num_delta
                .div_ceil(&den_x64)
                .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

            if U512::from_u128(remaining_input) < delta_y_max {
                // Next price: delta_s = floor( (remaining_input * 2^64) / L )
                // s_next = current_s + delta_s
                let num_price = U512::from_u128(remaining_input)
                    .shl_64()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
                let den_l = U512::from_u128(current_liquidity);
                let delta_s_add = num_price
                    .div_floor(&den_l)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let s_next = current_s
                    .checked_add(delta_s_add)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                if s_next >= s_upper || s_next <= current_s {
                    return Err(ClmmSimulationError::InvariantViolated);
                }

                // Output token 0: delta_x = floor( (L * 2^64 * (s_next - current_s)) / (current_s * s_next) )
                let delta_s_out = s_next - current_s;
                let num_x = U512::mul_u128(current_liquidity, delta_s_out)
                    .shl_64()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
                let den_x = U512::mul_u128(current_s, s_next);
                let out_x = num_x
                    .div_floor(&den_x)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                if out_x == 0 && total_output == 0 {
                    return Err(ClmmSimulationError::ZeroOutputAmount);
                }

                total_output = total_output
                    .checked_add(out_x)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let res_tick = tick_index_from_sqrt_price(s_next)?;
                if res_tick >= pool.ticks[current_range_idx + 1].index {
                    return Err(ClmmSimulationError::InvariantViolated);
                }

                current_s = s_next;
                current_tick = res_tick;
                break;
            } else {
                // Input is sufficient to reach upper boundary s_upper
                if current_range_idx + 1 >= pool.ticks.len() - 1 {
                    return Err(ClmmSimulationError::TickCrossingExceeded);
                }
                if tick_crosses >= MAX_CLMM_TICK_CROSSES {
                    return Err(ClmmSimulationError::TickCrossingExceeded);
                }

                let input_step = delta_y_max
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                let delta_s_out = s_upper - current_s;
                let num_x = U512::mul_u128(current_liquidity, delta_s_out)
                    .shl_64()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
                let den_x = U512::mul_u128(current_s, s_upper);
                let out_x = num_x
                    .div_floor(&den_x)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?
                    .as_u128()
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                total_output = total_output
                    .checked_add(out_x)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                remaining_input = remaining_input
                    .checked_sub(input_step)
                    .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

                current_s = s_upper;
                current_tick = pool.ticks[current_range_idx + 1].index;

                let net = pool.ticks[current_range_idx + 1].liquidity_net;
                current_liquidity = checked_add_net(current_liquidity, net)?;
                tick_crosses += 1;
                current_range_idx += 1;
            }
        }
    }

    if total_output == 0 {
        return Err(ClmmSimulationError::ZeroOutputAmount);
    }

    Ok(ClmmSimulationQuote {
        input: AssetAmount {
            asset: request.token_in.clone(),
            amount: request.amount_in,
        },
        output: AssetAmount {
            asset: expected_out.clone(),
            amount: AtomicAmount::new(total_output),
        },
        fee: AssetAmount {
            asset: request.token_in.clone(),
            amount: AtomicAmount::new(fee_val),
        },
        effective_input: AssetAmount {
            asset: request.token_in.clone(),
            amount: AtomicAmount::new(effective_input_val),
        },
        fee_bps: pool.fee_bps,
        resulting_sqrt_price_x64: current_s,
        resulting_tick: current_tick,
        resulting_liquidity: current_liquidity,
    })
}

/// Simulates a direct exact-output swap over a CLMM pool state.
///
/// Returns the **minimal** gross input whose exact-input traversal yields at
/// least the requested output. The inverse is realized entirely through
/// [`simulate_clmm_exact_input`] (the single authoritative kernel) with a
/// bounded exact integer search: the covering ceiling is located by doubling and
/// a smallest-high-error binary search, the minimal covering input is
/// binary-searched, and `input - 1` is proven insufficient before returning.
///
/// Validates pool state, requested output, direction, caller-asserted output,
/// and fee bounds fail-closed. A target above the pool's reachable output returns
/// [`ClmmSimulationError::OutputUnreachable`]. Never mutates the supplied pool.
pub fn simulate_clmm_exact_output(
    pool: &ClmmPoolState,
    request: &ClmmExactOutputRequest,
) -> Result<ClmmExactOutputQuote, ClmmSimulationError> {
    // 1. Validate pool contract invariants.
    pool.validate().map_err(ClmmSimulationError::from)?;

    // 2. Reject a zero requested output (mirrors the exact-input zero-input guard).
    if request.amount_out.is_zero() {
        return Err(ClmmSimulationError::ZeroOutputAmount);
    }

    // 3. Reject zero or invalid liquidity.
    if pool.liquidity == 0 {
        return Err(ClmmSimulationError::InvalidLiquidity);
    }

    // 4. Validate sqrt price bounds.
    if pool.sqrt_price_x64 == 0
        || !(MIN_SQRT_PRICE_X64..=MAX_SQRT_PRICE_X64).contains(&pool.sqrt_price_x64)
    {
        return Err(ClmmSimulationError::InvalidPrice);
    }

    // 5. Validate tick range.
    if !(MIN_TICK..=MAX_TICK).contains(&pool.current_tick) {
        return Err(ClmmSimulationError::InvalidTick);
    }

    // 6. Validate fee bounds.
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(ClmmSimulationError::InvalidFee);
    }

    // 7. Validate chain binding.
    if request.token_in.chain != pool.token_0.chain {
        return Err(ClmmSimulationError::ChainMismatch);
    }

    // 8. Determine the swap direction and expected counter-asset.
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(ClmmSimulationError::InvalidAssetDirection);
    };
    let expected_out = if is_token_0_in {
        pool.token_1.clone()
    } else {
        pool.token_0.clone()
    };

    // 9. Validate caller-asserted output asset if provided.
    if let Some(ref caller_out) = request.token_out {
        if caller_out.chain != pool.token_0.chain {
            return Err(ClmmSimulationError::ChainMismatch);
        }
        if caller_out == &request.token_in {
            return Err(ClmmSimulationError::InvalidAssetDirection);
        }
        if caller_out != &expected_out {
            return Err(ClmmSimulationError::OutputAssetMismatch);
        }
    }

    // 10. The remaining pool range/coherence validation is enforced by the
    //     exact-input oracle on the first probe and propagates fail-closed.

    let requested_out = request.amount_out.get();
    let token_in = request.token_in.clone();

    // 11. Bounded minimal gross-input search, with the exact-input kernel as the
    //     only output oracle.
    let outcome = find_min_gross_input(
        requested_out,
        |g| {
            simulate_clmm_exact_input(
                pool,
                &ClmmExactInputRequest {
                    token_in: token_in.clone(),
                    amount_in: AtomicAmount::new(g),
                    token_out: None,
                },
            )
            .map(|quote| quote.output.amount.get())
        },
        clmm_probe_class,
    )?;

    let minimal_in = match outcome {
        MinimalInputSearch::Found(g) => g,
        MinimalInputSearch::Unreachable => {
            return Err(ClmmSimulationError::OutputUnreachable);
        }
        MinimalInputSearch::Invariant => return Err(ClmmSimulationError::InvariantViolated),
    };

    // 12. Realize the authoritative exact-input quote at the proven-minimal input.
    let realized = simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in,
            amount_in: AtomicAmount::new(minimal_in),
            token_out: None,
        },
    )?;
    if realized.output.amount.get() < requested_out {
        return Err(ClmmSimulationError::InvariantViolated);
    }

    Ok(ClmmExactOutputQuote {
        input: realized.input,
        requested_output: AssetAmount {
            asset: expected_out,
            amount: request.amount_out,
        },
        output: realized.output,
        fee: realized.fee,
        effective_input: realized.effective_input,
        fee_bps: realized.fee_bps,
        resulting_sqrt_price_x64: realized.resulting_sqrt_price_x64,
        resulting_tick: realized.resulting_tick,
        resulting_liquidity: realized.resulting_liquidity,
    })
}
