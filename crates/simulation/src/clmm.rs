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

/// Simulates a direct exact-input swap over a CLMM pool state within its current active range.
///
/// Preflights active range and fails closed without producing a quote if price movement
/// would reach or cross the next initialized tick/range boundary.
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

    // 10. Find active range bounded by initialized ticks
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

    let lower_idx = lower_tick_idx.ok_or(ClmmSimulationError::InvalidRange)?;
    let t_lower = pool.ticks[lower_idx].index;
    let t_upper = pool.ticks[lower_idx + 1].index;

    let s_lower = sqrt_price_from_tick_index(t_lower)?;
    let s_upper = sqrt_price_from_tick_index(t_upper)?;

    if s_lower >= s_upper {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // Price must lie within active range bounds [s_lower, s_upper]
    if !(s_lower..=s_upper).contains(&pool.sqrt_price_x64) {
        return Err(ClmmSimulationError::InvalidRange);
    }

    // 11. Apply pool fee exactly once before price movement calculation
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

    let current_s = pool.sqrt_price_x64;
    let liquidity = pool.liquidity;

    // 12. Preflight active range and calculate exact output & resulting state
    let (amount_out_val, resulting_s, resulting_tick) = if is_token_0_in {
        // Token 0 in -> Token 1 out. Price moves down towards s_lower.
        if current_s <= s_lower {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        // Max token 0 input to reach lower boundary:
        // delta_x_max = ceil( (L * 2^64 * (current_s - s_lower)) / (current_s * s_lower) )
        let delta_s = current_s - s_lower;
        let num_delta = U512::mul_u128(liquidity, delta_s)
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let den_delta = U512::mul_u128(current_s, s_lower);
        let delta_x_max = num_delta
            .div_ceil(&den_delta)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        if U512::from_u128(effective_input_val) >= delta_x_max {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        // Next price: s_next = ceil( (L * 2^64 * current_s) / (L * 2^64 + effective_input * current_s) )
        let num_price = U512::mul_u128(liquidity, current_s)
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let l_x64 = U512::from_u128(liquidity)
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let in_times_s = U512::mul_u128(effective_input_val, current_s);
        let den_price = l_x64
            .add(&in_times_s)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        let s_next = num_price
            .div_ceil(&den_price)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
            .as_u128()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        if s_next <= s_lower {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }
        if s_next >= current_s {
            return Err(ClmmSimulationError::InvariantViolated);
        }

        // Output token 1: delta_y = floor( (L * (current_s - s_next)) / 2^64 )
        let delta_s_out = current_s - s_next;
        let (num_y_hi, num_y_lo) = mul_u128_wide(liquidity, delta_s_out);
        let out_y = (num_y_lo >> 64) | (num_y_hi << 64);
        if num_y_hi >> 64 != 0 {
            return Err(ClmmSimulationError::ArithmeticOverflow);
        }
        if out_y == 0 {
            return Err(ClmmSimulationError::ZeroOutputAmount);
        }

        let res_tick = tick_index_from_sqrt_price(s_next)?;
        if res_tick < t_lower {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        (out_y, s_next, res_tick)
    } else {
        // Token 1 in -> Token 0 out. Price moves up towards s_upper.
        if current_s >= s_upper {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        // Max token 1 input to reach upper boundary:
        // delta_y_max = ceil( (L * (s_upper - current_s)) / 2^64 )
        let delta_s = s_upper - current_s;
        let num_delta = U512::mul_u128(liquidity, delta_s);
        let den_x64 = U512::ONE
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let delta_y_max = num_delta
            .div_ceil(&den_x64)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        if U512::from_u128(effective_input_val) >= delta_y_max {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        // Next price: delta_s = floor( (effective_input * 2^64) / L )
        // s_next = current_s + delta_s
        let num_price = U512::from_u128(effective_input_val)
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let den_l = U512::from_u128(liquidity);
        let delta_s_add = num_price
            .div_floor(&den_l)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
            .as_u128()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        let s_next = current_s
            .checked_add(delta_s_add)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        if s_next >= s_upper {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }
        if s_next <= current_s {
            return Err(ClmmSimulationError::InvariantViolated);
        }

        // Output token 0: delta_x = floor( (L * 2^64 * (s_next - current_s)) / (current_s * s_next) )
        let delta_s_out = s_next - current_s;
        let num_x = U512::mul_u128(liquidity, delta_s_out)
            .shl_64()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;
        let den_x = U512::mul_u128(current_s, s_next);
        let out_x = num_x
            .div_floor(&den_x)
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?
            .as_u128()
            .ok_or(ClmmSimulationError::ArithmeticOverflow)?;

        if out_x == 0 {
            return Err(ClmmSimulationError::ZeroOutputAmount);
        }

        let res_tick = tick_index_from_sqrt_price(s_next)?;
        if res_tick >= t_upper {
            return Err(ClmmSimulationError::TickCrossingExceeded);
        }

        (out_x, s_next, res_tick)
    };

    Ok(ClmmSimulationQuote {
        input: AssetAmount {
            asset: request.token_in.clone(),
            amount: request.amount_in,
        },
        output: AssetAmount {
            asset: expected_out.clone(),
            amount: AtomicAmount::new(amount_out_val),
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
        resulting_sqrt_price_x64: resulting_s,
        resulting_tick,
        resulting_liquidity: pool.liquidity,
    })
}
