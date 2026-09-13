//! Pure, deterministic Constant Product Market Maker (CPMM) simulation kernel.
//!
//! Implements exact-input quote calculation over [`CpmmPoolState`] using integer/fixed-point
//! arithmetic with explicit floor rounding.

use chain_types::AssetId;
use market_types::{AssetAmount, AtomicAmount, Bps, CpmmPoolState, PriceRatio};
use serde::{Deserialize, Serialize};
use tax_engine::TaxAssessment;

use crate::buy_tax::{simulate_tax_aware_cpmm_buy_exact_input, TaxAwareCpmmBuyQuote};
use crate::error::{SimulationError, TaxAwareSimulationError};

/// Exact 256-bit multiplication of two `u128` values: `a * b -> (hi_128, lo_128)`.
/// Free of floating point, wall clock, or external dependencies.
#[inline]
pub const fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64 as u128;
    let a_hi = a >> 64;
    let b_lo = b as u64 as u128;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let p0_hi = p0 >> 64;
    let mid1 = p1 + p0_hi;
    let (mid, carry) = mid1.overflowing_add(p2);

    let lo = (p0 as u64 as u128) | ((mid as u64 as u128) << 64);
    let carry_term = if carry { 1u128 << 64 } else { 0 };
    let hi = p3 + (mid >> 64) + carry_term;
    (hi, lo)
}

/// Exact comparison of `a * b` vs `c * d` for four `u128` values using 256-bit arithmetic.
#[inline]
pub fn cmp_u128_products(a: u128, b: u128, c: u128, d: u128) -> std::cmp::Ordering {
    let (hi1, lo1) = mul_u128_wide(a, b);
    let (hi2, lo2) = mul_u128_wide(c, d);
    hi1.cmp(&hi2).then_with(|| lo1.cmp(&lo2))
}

/// Divides a 256-bit integer `(hi, lo)` by a 128-bit denominator `den` with explicit floor rounding.
/// Returns `None` if `den == 0` or if the quotient exceeds `u128::MAX`.
pub fn div_u256_by_u128_floor(hi: u128, lo: u128, den: u128) -> Option<u128> {
    if den == 0 {
        return None;
    }
    if hi >= den {
        return None;
    }
    if hi == 0 {
        return Some(lo / den);
    }

    let mut rem = hi;
    let mut quot = 0u128;
    for i in (0..128).rev() {
        let bit = (lo >> i) & 1;
        let rem_hi = rem >> 127;
        rem = (rem << 1) | bit;
        if rem_hi != 0 || rem >= den {
            rem = rem.wrapping_sub(den);
            quot |= 1 << i;
        }
    }
    Some(quot)
}

/// Divides a 256-bit integer `(hi, lo)` by a 128-bit denominator `den` with explicit
/// ceiling rounding.
///
/// Returns `None` if `den == 0`, if the quotient exceeds `u128::MAX`, or if the
/// ceiling itself would exceed `u128::MAX`. For an exact multiple the floor
/// quotient is returned unchanged.
pub fn div_u256_by_u128_ceil(hi: u128, lo: u128, den: u128) -> Option<u128> {
    let quotient = div_u256_by_u128_floor(hi, lo, den)?;
    let (product_hi, product_lo) = mul_u128_wide(quotient, den);
    // `quotient == floor((hi, lo) / den)`, so `quotient * den <= (hi, lo)`: a
    // 256-bit product compare detects a non-zero remainder without a 256-bit
    // subtraction.
    if product_hi != hi || product_lo != lo {
        quotient.checked_add(1)
    } else {
        Some(quotient)
    }
}

/// Request parameters for an exact-input direct CPMM swap simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmExactInputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Exact atomic input amount to swap.
    pub amount_in: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

impl CpmmExactInputRequest {
    /// Creates an exact-input request with inferred output asset.
    pub const fn new(token_in: AssetId, amount_in: AtomicAmount) -> Self {
        Self {
            token_in,
            amount_in,
            token_out: None,
        }
    }

    /// Creates an exact-input request with caller-asserted output asset.
    pub const fn new_directed(
        token_in: AssetId,
        amount_in: AtomicAmount,
        token_out: AssetId,
    ) -> Self {
        Self {
            token_in,
            amount_in,
            token_out: Some(token_out),
        }
    }

    /// Simulates this request against the given pool state.
    pub fn simulate(&self, pool: &CpmmPoolState) -> Result<CpmmSimulationQuote, SimulationError> {
        simulate_cpmm_exact_input(pool, self)
    }

    /// Simulates this request against the given pool state with buy-side tax deduction.
    pub fn simulate_with_buy_tax(
        &self,
        pool: &CpmmPoolState,
        assessment: &TaxAssessment,
    ) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
        simulate_tax_aware_cpmm_buy_exact_input(pool, self, assessment)
    }
}

/// Deterministic quote produced by CPMM exact-input simulation.
///
/// Contains explicit economics designed to feed subsequent execution preview construction:
/// - Exact input asset and amount
/// - Exact output asset and amount
/// - Explicit pool fee taken from input
/// - Effective post-fee input
/// - Resulting reserves in both directions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmSimulationQuote {
    /// Exact input asset and atomic amount.
    pub input: AssetAmount,
    /// Exact gross simulated output asset and atomic amount.
    pub output: AssetAmount,
    /// Explicit pool fee taken from the input, denominated in input asset.
    pub pool_fee: AssetAmount,
    /// Effective post-fee input amount entering the constant-product calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Resulting reserve for pool token_0 after the simulated swap.
    pub resulting_reserve_0: AtomicAmount,
    /// Resulting reserve for pool token_1 after the simulated swap.
    pub resulting_reserve_1: AtomicAmount,
    /// Resulting reserve for the input token.
    pub resulting_reserve_in: AtomicAmount,
    /// Resulting reserve for the output token.
    pub resulting_reserve_out: AtomicAmount,
}

pub type CpmmQuote = CpmmSimulationQuote;

impl CpmmSimulationQuote {
    #[inline]
    pub fn input(&self) -> &AssetAmount {
        &self.input
    }

    #[inline]
    pub fn output(&self) -> &AssetAmount {
        &self.output
    }

    #[inline]
    pub fn pool_fee(&self) -> &AssetAmount {
        &self.pool_fee
    }

    #[inline]
    pub fn effective_input(&self) -> &AssetAmount {
        &self.effective_input
    }

    #[inline]
    pub fn fee_bps(&self) -> Bps {
        self.fee_bps
    }

    #[inline]
    pub fn resulting_reserve_0(&self) -> AtomicAmount {
        self.resulting_reserve_0
    }

    #[inline]
    pub fn resulting_reserve_1(&self) -> AtomicAmount {
        self.resulting_reserve_1
    }

    #[inline]
    pub fn resulting_reserve_in(&self) -> AtomicAmount {
        self.resulting_reserve_in
    }

    #[inline]
    pub fn resulting_reserve_out(&self) -> AtomicAmount {
        self.resulting_reserve_out
    }

    /// Computes the gross quote price ratio (output_atomic / input_atomic).
    pub fn quote_price_ratio(&self) -> Result<PriceRatio, SimulationError> {
        PriceRatio::new(self.output.amount.get(), self.input.amount.get())
            .map_err(|_| SimulationError::ZeroOutputAmount)
    }
}

/// Request parameters for an exact-output direct CPMM swap simulation.
///
/// The caller asks for a desired pre-tax output amount and receives the
/// **minimal** gross input that yields at least that output under the exact-input
/// kernel's floor semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmExactOutputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Desired pre-tax output amount from the pool.
    pub amount_out: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

impl CpmmExactOutputRequest {
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
    pub fn simulate(&self, pool: &CpmmPoolState) -> Result<CpmmExactOutputQuote, SimulationError> {
        simulate_cpmm_exact_output(pool, self)
    }
}

/// Deterministic quote produced by CPMM exact-output simulation.
///
/// `input` is the minimal gross input whose exact-input output is `>= requested_output`.
/// Because integer floor rounding makes an exact hit rare, the realized `output`
/// may exceed the requested amount by a bounded rounding remainder; `input - 1`
/// is insufficient (the function proves this fail-closed before returning).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmExactOutputQuote {
    /// Minimal gross input, denominated in the input asset.
    pub input: AssetAmount,
    /// Requested output, denominated in the output asset.
    pub requested_output: AssetAmount,
    /// Realized output of `input`, denominated in the output asset (`>= requested_output`).
    pub output: AssetAmount,
    /// Pool fee taken from `input`, denominated in the input asset.
    pub pool_fee: AssetAmount,
    /// Effective post-fee input entering the constant-product calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Resulting reserve for pool token_0 after the required swap.
    pub resulting_reserve_0: AtomicAmount,
    /// Resulting reserve for pool token_1 after the required swap.
    pub resulting_reserve_1: AtomicAmount,
    /// Resulting reserve for the input token.
    pub resulting_reserve_in: AtomicAmount,
    /// Resulting reserve for the output token.
    pub resulting_reserve_out: AtomicAmount,
}

impl CpmmExactOutputQuote {
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

/// Pure simulation kernel for CPMM swaps.
pub struct CpmmSimulationKernel;

impl CpmmSimulationKernel {
    /// Simulates a direct exact-input swap over the supplied CPMM pool state.
    pub fn simulate_exact_input(
        pool: &CpmmPoolState,
        request: &CpmmExactInputRequest,
    ) -> Result<CpmmSimulationQuote, SimulationError> {
        simulate_cpmm_exact_input(pool, request)
    }

    /// Simulates a direct exact-output swap over the supplied CPMM pool state.
    pub fn simulate_exact_output(
        pool: &CpmmPoolState,
        request: &CpmmExactOutputRequest,
    ) -> Result<CpmmExactOutputQuote, SimulationError> {
        simulate_cpmm_exact_output(pool, request)
    }

    /// Simulates a direct exact-input swap over the supplied CPMM pool state with buy-side tax.
    pub fn simulate_tax_aware_buy_exact_input(
        pool: &CpmmPoolState,
        request: &CpmmExactInputRequest,
        assessment: &TaxAssessment,
    ) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
        simulate_tax_aware_cpmm_buy_exact_input(pool, request, assessment)
    }
}

/// Simulates a direct exact-input swap over a CPMM pool state.
///
/// Validates pool state, reserves, inputs, and fee bounds fail-closed.
/// Does not mutate the supplied pool state.
pub fn simulate_cpmm_exact_input(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
) -> Result<CpmmSimulationQuote, SimulationError> {
    // 1. Validate pool internal structure invariants
    pool.validate().map_err(SimulationError::InvalidPoolState)?;

    // 2. Reject zero input amount
    if request.amount_in.is_zero() {
        return Err(SimulationError::ZeroInputAmount);
    }

    // 3. Reject zero reserves
    if pool.reserve_0.is_zero() || pool.reserve_1.is_zero() {
        return Err(SimulationError::ZeroReserve);
    }

    // 4. Validate chain match
    if request.token_in.chain != pool.token_0.chain {
        return Err(SimulationError::ChainMismatch);
    }

    // 5. Determine pool swap direction
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(SimulationError::AssetNotFoundInPool(
            request.token_in.clone(),
        ));
    };

    let (token_out, reserve_in, reserve_out) = if is_token_0_in {
        (
            pool.token_1.clone(),
            pool.reserve_0.get(),
            pool.reserve_1.get(),
        )
    } else {
        (
            pool.token_0.clone(),
            pool.reserve_1.get(),
            pool.reserve_0.get(),
        )
    };

    // 6. Validate caller-asserted output asset if supplied
    if let Some(ref caller_out) = request.token_out {
        if caller_out != &token_out {
            return Err(SimulationError::OutputAssetMismatch {
                expected: token_out,
                received: caller_out.clone(),
            });
        }
    }

    // 7. Validate fee basis points
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(SimulationError::InvalidFeeBps(fee_bps_val));
    }

    // 8. Compute fee and effective input with explicit integer floor
    let amount_in_val = request.amount_in.get();
    let fee_numerator = amount_in_val
        .checked_mul(fee_bps_val as u128)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    let fee_val = fee_numerator / 10_000;
    let effective_input_val = amount_in_val
        .checked_sub(fee_val)
        .ok_or(SimulationError::ArithmeticOverflow)?;

    if effective_input_val == 0 {
        return Err(SimulationError::ZeroEffectiveInput);
    }

    // 9. Canonical constant-product calculation: output = floor( (x_eff * R_out) / (R_in + x_eff) )
    let (num_hi, num_lo) = mul_u128_wide(effective_input_val, reserve_out);
    let denominator = reserve_in
        .checked_add(effective_input_val)
        .ok_or(SimulationError::ArithmeticOverflow)?;

    let amount_out_val = div_u256_by_u128_floor(num_hi, num_lo, denominator)
        .ok_or(SimulationError::ArithmeticOverflow)?;

    // 10. Validate output constraints
    if amount_out_val == 0 {
        return Err(SimulationError::ZeroOutputAmount);
    }
    if amount_out_val >= reserve_out {
        return Err(SimulationError::ImpossibleOutput);
    }

    // 11. Calculate resulting reserves
    let resulting_reserve_in = reserve_in
        .checked_add(amount_in_val)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    let resulting_reserve_out = reserve_out
        .checked_sub(amount_out_val)
        .ok_or(SimulationError::ArithmeticOverflow)?;

    let (resulting_reserve_0, resulting_reserve_1) = if is_token_0_in {
        (resulting_reserve_in, resulting_reserve_out)
    } else {
        (resulting_reserve_out, resulting_reserve_in)
    };

    // 12. Fail-closed constant-product invariant check: k_new >= k_old
    if cmp_u128_products(
        resulting_reserve_in,
        resulting_reserve_out,
        reserve_in,
        reserve_out,
    ) == std::cmp::Ordering::Less
    {
        return Err(SimulationError::InvariantViolated);
    }

    Ok(CpmmSimulationQuote {
        input: AssetAmount {
            asset: request.token_in.clone(),
            amount: request.amount_in,
        },
        output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(amount_out_val),
        },
        pool_fee: AssetAmount {
            asset: request.token_in.clone(),
            amount: AtomicAmount::new(fee_val),
        },
        effective_input: AssetAmount {
            asset: request.token_in.clone(),
            amount: AtomicAmount::new(effective_input_val),
        },
        fee_bps: pool.fee_bps,
        resulting_reserve_0: AtomicAmount::new(resulting_reserve_0),
        resulting_reserve_1: AtomicAmount::new(resulting_reserve_1),
        resulting_reserve_in: AtomicAmount::new(resulting_reserve_in),
        resulting_reserve_out: AtomicAmount::new(resulting_reserve_out),
    })
}

/// Simulates a direct exact-output swap over a CPMM pool state.
///
/// Returns the **minimal** gross input whose exact-input output is at least the
/// requested amount. Inversion is exact and fail-closed:
/// - the required post-fee effective input is
///   `ceil(reserve_in * amount_out / (reserve_out - amount_out))`;
/// - the required gross input is the smallest `a` with
///   `a - floor(a * fee_bps / 10_000) >= effective_min`, solved in closed form;
/// - the realized quote is then produced by the exact-input kernel itself and the
///   result is proven minimal (`input - 1` yields strictly less than the request).
///
/// Validates pool state, reserves, direction, fee bounds, and overflow fail-closed.
/// Does not mutate the supplied pool state.
pub fn simulate_cpmm_exact_output(
    pool: &CpmmPoolState,
    request: &CpmmExactOutputRequest,
) -> Result<CpmmExactOutputQuote, SimulationError> {
    // 1. Validate pool internal structure invariants.
    pool.validate().map_err(SimulationError::InvalidPoolState)?;

    // 2. Reject a zero requested output.
    if request.amount_out.is_zero() {
        return Err(SimulationError::ZeroOutputAmount);
    }

    // 3. Reject zero reserves.
    if pool.reserve_0.is_zero() || pool.reserve_1.is_zero() {
        return Err(SimulationError::ZeroReserve);
    }

    // 4. Validate chain match.
    if request.token_in.chain != pool.token_0.chain {
        return Err(SimulationError::ChainMismatch);
    }

    // 5. Determine pool swap direction.
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(SimulationError::AssetNotFoundInPool(
            request.token_in.clone(),
        ));
    };

    let (token_out, reserve_in, reserve_out) = if is_token_0_in {
        (
            pool.token_1.clone(),
            pool.reserve_0.get(),
            pool.reserve_1.get(),
        )
    } else {
        (
            pool.token_0.clone(),
            pool.reserve_1.get(),
            pool.reserve_0.get(),
        )
    };

    // 6. Validate caller-asserted output asset if supplied.
    if let Some(ref caller_out) = request.token_out {
        if caller_out != &token_out {
            return Err(SimulationError::OutputAssetMismatch {
                expected: token_out,
                received: caller_out.clone(),
            });
        }
    }

    // 7. Validate fee basis points.
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(SimulationError::InvalidFeeBps(fee_bps_val));
    }

    // 8. Requested output must be strictly below the output reserve.
    let requested_out = request.amount_out.get();
    if requested_out >= reserve_out {
        return Err(SimulationError::ImpossibleOutput);
    }

    // 9. Minimum post-fee effective input:
    //    floor(e * reserve_out / (reserve_in + e)) >= requested_out
    //    <=> e * (reserve_out - requested_out) >= requested_out * reserve_in
    //    <=> e >= requested_out * reserve_in / (reserve_out - requested_out).
    let denominator = reserve_out - requested_out;
    let (numerator_hi, numerator_lo) = mul_u128_wide(reserve_in, requested_out);
    let effective_min = div_u256_by_u128_ceil(numerator_hi, numerator_lo, denominator)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    if effective_min == 0 {
        return Err(SimulationError::InvariantViolated);
    }

    // 10. Smallest gross input `a` with `a - floor(a * fee / 10_000) >= effective_min`.
    //     `a - floor(a * fee / 10_000) == ceil(a * (10_000 - fee) / 10_000)`, so
    //     ceil(a * (10_000 - fee) / 10_000) >= effective_min
    //     <=> a * (10_000 - fee) >= 10_000 * (effective_min - 1) + 1.
    let fee_denominator = 10_000u128 - fee_bps_val as u128; // in 1..=10_000
    let (scaled_hi, scaled_lo) = mul_u128_wide(10_000, effective_min - 1);
    // Exact 256-bit `+ 1`. With the fixed multiplier `10_000` the low word is
    // always `0 (mod 16)`, so the carry branch is currently unreachable, but it
    // is kept so the wide increment stays correct if the constant ever changes.
    let (threshold_lo, carry) = scaled_lo.overflowing_add(1);
    let threshold_hi = if carry {
        scaled_hi
            .checked_add(1)
            .ok_or(SimulationError::ArithmeticOverflow)?
    } else {
        scaled_hi
    };
    let amount_in = div_u256_by_u128_ceil(threshold_hi, threshold_lo, fee_denominator)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    if amount_in == 0 {
        return Err(SimulationError::InvariantViolated);
    }

    // 11. Realize the quote through the exact-input kernel itself so fee, effective
    //     input, and resulting reserves come from the single authoritative
    //     implementation.
    let input_request = CpmmExactInputRequest::new_directed(
        request.token_in.clone(),
        AtomicAmount::new(amount_in),
        token_out.clone(),
    );
    let realized = simulate_cpmm_exact_input(pool, &input_request)?;

    // 12. Fail closed unless the realized output covers the request.
    if realized.output.amount.get() < requested_out {
        return Err(SimulationError::InvariantViolated);
    }

    // 13. Prove minimality: one unit less must not cover the request. A zero-input
    //     or zero-effective-input rejection is a sufficient "insufficient" signal.
    if amount_in > 1 {
        let previous_request = CpmmExactInputRequest::new_directed(
            request.token_in.clone(),
            AtomicAmount::new(amount_in - 1),
            token_out.clone(),
        );
        match simulate_cpmm_exact_input(pool, &previous_request) {
            Ok(previous) => {
                if previous.output.amount.get() >= requested_out {
                    return Err(SimulationError::InvariantViolated);
                }
            }
            Err(SimulationError::ZeroOutputAmount | SimulationError::ZeroEffectiveInput) => {}
            Err(other) => return Err(other),
        }
    }

    Ok(CpmmExactOutputQuote {
        input: realized.input,
        requested_output: AssetAmount {
            asset: token_out,
            amount: request.amount_out,
        },
        output: realized.output,
        pool_fee: realized.pool_fee,
        effective_input: realized.effective_input,
        fee_bps: realized.fee_bps,
        resulting_reserve_0: realized.resulting_reserve_0,
        resulting_reserve_1: realized.resulting_reserve_1,
        resulting_reserve_in: realized.resulting_reserve_in,
        resulting_reserve_out: realized.resulting_reserve_out,
    })
}

/// Convenience helper to simulate exact input with inferred output asset.
pub fn simulate_cpmm_swap(
    pool: &CpmmPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
) -> Result<CpmmSimulationQuote, SimulationError> {
    let req = CpmmExactInputRequest::new(token_in.clone(), amount_in);
    simulate_cpmm_exact_input(pool, &req)
}

/// Convenience helper to simulate exact input with caller-asserted output asset.
pub fn simulate_cpmm_swap_directed(
    pool: &CpmmPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    token_out: &AssetId,
) -> Result<CpmmSimulationQuote, SimulationError> {
    let req = CpmmExactInputRequest::new_directed(token_in.clone(), amount_in, token_out.clone());
    simulate_cpmm_exact_input(pool, &req)
}
