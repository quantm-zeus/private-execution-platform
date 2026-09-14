//! Pure deterministic Bin/DLMM (Liquidity Book) exact-input simulation.
//!
//! Part of Phase-3 bounded local exact simulation. Operates directly over canonical
//! [`market_types::BinPoolState`] discrete liquidity bins without floating-point
//! arithmetic, wall-clock time, external dependencies, or side-effects.
//!
//! The kernel traverses represented bins in the direction implied by the input asset,
//! failing closed with [`BinSimulationError::BinCrossingExceeded`] once the bounded
//! [`MAX_BIN_CROSSES`] transition budget is exhausted or the represented bins run out.

use chain_types::AssetId;
use market_types::{AssetAmount, AtomicAmount, BinPoolState, Bps};
use serde::{Deserialize, Serialize};

use crate::clmm::{find_min_gross_input, MinimalInputSearch, ProbeClass};
use crate::cpmm::{cmp_u128_products, div_u256_by_u128_floor, mul_u128_wide};
use crate::error::BinSimulationError;

/// Hard cap on the number of bin-to-bin transitions performed in a single simulation.
///
/// This is a secondary traversal bound, not the primary overflow guard. The exact
/// rational bin price grows as `((10000 + bin_step) / 10000)^b`, so a sufficiently
/// deep traversal can fail closed with [`BinSimulationError::ArithmeticOverflow`]
/// before this cap is reached; the cap still bounds worst-case work for the steps
/// that remain representable.
pub const MAX_BIN_CROSSES: usize = 32;

/// Request parameters for an exact-input direct Bin/DLMM swap simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinExactInputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Exact atomic input amount to swap.
    pub amount_in: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

impl BinExactInputRequest {
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
}

/// Deterministic quote produced by Bin/DLMM exact-input simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinSimulationQuote {
    /// Exact input asset and atomic amount.
    pub input: AssetAmount,
    /// Exact gross simulated output asset and atomic amount.
    pub output: AssetAmount,
    /// Explicit pool fee taken from the input, denominated in the input asset.
    pub fee: AssetAmount,
    /// Effective post-fee input amount entering the bin price calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Id of the last represented bin in which output was produced.
    pub resulting_active_bin_id: i32,
    /// Number of bin-to-bin transitions performed during traversal.
    pub bins_crossed: usize,
}

/// Request parameters for an exact-output direct Bin/DLMM swap simulation.
///
/// The caller asks for a desired output amount and receives the **minimal** gross
/// input whose exact-input bin traversal yields at least that output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinExactOutputRequest {
    /// Asset offered as input to the pool.
    pub token_in: AssetId,
    /// Desired output amount from the pool.
    pub amount_out: AtomicAmount,
    /// Optional caller-asserted target output asset.
    /// If provided, must match the pool's counter-asset direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out: Option<AssetId>,
}

impl BinExactOutputRequest {
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
    pub fn simulate(&self, pool: &BinPoolState) -> Result<BinExactOutputQuote, BinSimulationError> {
        simulate_bin_exact_output(pool, self)
    }
}

/// Deterministic quote produced by Bin/DLMM exact-output simulation.
///
/// `input` is the minimal gross input whose exact-input output is `>= requested_output`.
/// Because integer floor rounding makes an exact hit rare, the realized `output`
/// may exceed the requested amount by a bounded rounding remainder; `input - 1`
/// is proven insufficient fail-closed before returning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinExactOutputQuote {
    /// Minimal gross input, denominated in the input asset.
    pub input: AssetAmount,
    /// Requested output, denominated in the output asset.
    pub requested_output: AssetAmount,
    /// Realized output of `input`, denominated in the output asset (`>= requested_output`).
    pub output: AssetAmount,
    /// Pool fee taken from `input`, denominated in the input asset.
    pub fee: AssetAmount,
    /// Effective post-fee input entering the bin price calculation.
    pub effective_input: AssetAmount,
    /// Fee basis points of the pool.
    pub fee_bps: Bps,
    /// Id of the last represented bin in which output was produced.
    pub resulting_active_bin_id: i32,
    /// Number of bin-to-bin transitions performed during traversal.
    pub bins_crossed: usize,
}

impl BinExactOutputQuote {
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

/// Classifies a Bin exact-input failure for the minimal-input search.
fn bin_probe_class(err: &BinSimulationError) -> ProbeClass {
    match err {
        BinSimulationError::ZeroOutputAmount | BinSimulationError::ZeroEffectiveInput => {
            ProbeClass::Low
        }
        // The Bin kernel does not currently emit `InvariantViolated`, but if it
        // ever does it must be treated as a hole (fail closed once the feasible
        // region has begun), never as a monotonically-low failure.
        BinSimulationError::InvariantViolated => ProbeClass::Hole,
        BinSimulationError::BinCrossingExceeded | BinSimulationError::ArithmeticOverflow => {
            ProbeClass::High
        }
        _ => ProbeClass::Unexpected,
    }
}

/// Greatest common divisor of two positive `u128` values.
#[inline]
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let rem = a % b;
        a = b;
        b = rem;
    }
    a
}

/// Reduces `(num, den)` by their greatest common divisor.
#[inline]
fn reduce_fraction(num: u128, den: u128) -> (u128, u128) {
    let divisor = gcd_u128(num, den);
    if divisor <= 1 {
        (num, den)
    } else {
        (num / divisor, den / divisor)
    }
}

/// Computes the reduced atomic bin price `N / D` for `bin_id`.
///
/// The human bin price is `P(b) = ((10000 + bin_step) / 10000)^b`; the atomic price
/// scales it by `10^(decimals_1 - decimals_0)`. The base fraction is reduced before
/// exponentiation so that representable bin prices do not spuriously overflow.
fn atomic_bin_price(
    bin_step: u16,
    decimals_0: u8,
    decimals_1: u8,
    bin_id: i32,
) -> Result<(u128, u128), BinSimulationError> {
    let base_num = 10_000u128
        .checked_add(bin_step as u128)
        .ok_or(BinSimulationError::ArithmeticOverflow)?;
    let (base_num, base_den) = reduce_fraction(base_num, 10_000);

    let exponent = bin_id.unsigned_abs();
    let (num_raw, den_raw) = if bin_id >= 0 {
        (
            base_num
                .checked_pow(exponent)
                .ok_or(BinSimulationError::ArithmeticOverflow)?,
            base_den
                .checked_pow(exponent)
                .ok_or(BinSimulationError::ArithmeticOverflow)?,
        )
    } else {
        (
            base_den
                .checked_pow(exponent)
                .ok_or(BinSimulationError::ArithmeticOverflow)?,
            base_num
                .checked_pow(exponent)
                .ok_or(BinSimulationError::ArithmeticOverflow)?,
        )
    };

    let decimal_delta = (decimals_1 as i32 - decimals_0 as i32).unsigned_abs();
    let decimal_factor = 10u128
        .checked_pow(decimal_delta)
        .ok_or(BinSimulationError::ArithmeticOverflow)?;

    // Cancel common factors between the raw fraction and `10^delta` before scaling so
    // that representable atomic prices do not spuriously overflow the `u128`
    // intermediates.
    let (num, den) = if decimals_1 >= decimals_0 {
        let cancel = gcd_u128(den_raw, decimal_factor);
        let num = num_raw
            .checked_mul(decimal_factor / cancel)
            .ok_or(BinSimulationError::ArithmeticOverflow)?;
        (num, den_raw / cancel)
    } else {
        let cancel = gcd_u128(num_raw, decimal_factor);
        let den = den_raw
            .checked_mul(decimal_factor / cancel)
            .ok_or(BinSimulationError::ArithmeticOverflow)?;
        (num_raw / cancel, den)
    };

    let (num, den) = reduce_fraction(num, den);
    if num == 0 || den == 0 {
        return Err(BinSimulationError::ArithmeticOverflow);
    }
    Ok((num, den))
}

/// Exact `floor(a * b / c)` using 256-bit intermediate arithmetic.
#[inline]
fn mul_div_floor(a: u128, b: u128, c: u128) -> Result<u128, BinSimulationError> {
    let (hi, lo) = mul_u128_wide(a, b);
    div_u256_by_u128_floor(hi, lo, c).ok_or(BinSimulationError::ArithmeticOverflow)
}

/// Exact `ceil(a * b / c)` using 256-bit intermediate arithmetic.
#[inline]
fn mul_div_ceil(a: u128, b: u128, c: u128) -> Result<u128, BinSimulationError> {
    let quotient = mul_div_floor(a, b, c)?;
    if cmp_u128_products(quotient, c, a, b) == std::cmp::Ordering::Less {
        quotient
            .checked_add(1)
            .ok_or(BinSimulationError::ArithmeticOverflow)
    } else {
        Ok(quotient)
    }
}

/// Steps to the next represented bin in the traversal direction, counting a cross.
fn next_bin_index(
    pool: &BinPoolState,
    current_idx: usize,
    is_token_0_in: bool,
    bins_crossed: &mut usize,
) -> Result<usize, BinSimulationError> {
    if *bins_crossed >= MAX_BIN_CROSSES {
        return Err(BinSimulationError::BinCrossingExceeded);
    }
    if is_token_0_in {
        if current_idx == 0 {
            return Err(BinSimulationError::BinCrossingExceeded);
        }
        *bins_crossed += 1;
        Ok(current_idx - 1)
    } else {
        let next_idx = current_idx
            .checked_add(1)
            .ok_or(BinSimulationError::ArithmeticOverflow)?;
        if next_idx >= pool.bins.len() {
            return Err(BinSimulationError::BinCrossingExceeded);
        }
        *bins_crossed += 1;
        Ok(next_idx)
    }
}

/// Simulates a direct exact-input swap over a Bin/DLMM pool state.
///
/// Validates pool state, inputs, fee bounds, direction, and active-bin presence
/// fail-closed. Traverses represented bins in the price-movement direction and
/// never mutates the supplied pool state.
pub fn simulate_bin_exact_input(
    pool: &BinPoolState,
    request: &BinExactInputRequest,
) -> Result<BinSimulationQuote, BinSimulationError> {
    // 1. Validate pool contract invariants.
    pool.validate().map_err(BinSimulationError::from)?;

    // 2. Reject zero input amount.
    if request.amount_in.is_zero() {
        return Err(BinSimulationError::ZeroInputAmount);
    }

    // 3. Validate chain binding.
    if request.token_in.chain != pool.token_0.chain {
        return Err(BinSimulationError::ChainMismatch);
    }

    // 4. Determine swap direction.
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(BinSimulationError::InvalidAssetDirection);
    };
    let expected_out = if is_token_0_in {
        &pool.token_1
    } else {
        &pool.token_0
    };

    // 5. Validate caller-asserted output asset if provided.
    if let Some(ref caller_out) = request.token_out {
        if caller_out.chain != pool.token_0.chain {
            return Err(BinSimulationError::ChainMismatch);
        }
        if caller_out == &request.token_in {
            return Err(BinSimulationError::InvalidAssetDirection);
        }
        if caller_out != expected_out {
            return Err(BinSimulationError::OutputAssetMismatch);
        }
    }

    // 6. Validate fee bounds.
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(BinSimulationError::InvalidFee);
    }

    // 7. The active bin must be represented.
    let active_idx = pool
        .bins
        .iter()
        .position(|bin| bin.id == pool.active_bin_id)
        .ok_or(BinSimulationError::InvalidRange)?;

    // Apply the pool fee exactly once before price movement calculation.
    let amount_in_val = request.amount_in.get();
    let fee_val = mul_div_floor(amount_in_val, fee_bps_val as u128, 10_000)?;
    let effective_input_val = amount_in_val
        .checked_sub(fee_val)
        .ok_or(BinSimulationError::ArithmeticOverflow)?;
    if effective_input_val == 0 {
        return Err(BinSimulationError::ZeroEffectiveInput);
    }

    let mut current_idx = active_idx;
    let mut remaining_input = effective_input_val;
    let mut total_output: u128 = 0;
    let mut bins_crossed: usize = 0;
    // Ids are recorded as production happens; the active index is only a fallback that
    // is always overwritten because a successful quote requires non-zero total output.
    let mut last_output_idx = active_idx;

    // Bounded bin traversal loop.
    while remaining_input > 0 {
        let bin = &pool.bins[current_idx];
        let available = if is_token_0_in {
            bin.reserve_1.get()
        } else {
            bin.reserve_0.get()
        };

        if available == 0 {
            current_idx = next_bin_index(pool, current_idx, is_token_0_in, &mut bins_crossed)?;
            continue;
        }

        let (n, d) = atomic_bin_price(pool.bin_step, pool.decimals_0, pool.decimals_1, bin.id)?;

        let (need, output_numerator, output_denominator) = if is_token_0_in {
            // Token 0 in -> token 1 out: price moves down. Quote output is
            // floor(dx * N / D); input to exhaust the bin quote reserve is
            // ceil(Y * D / N).
            (mul_div_ceil(available, d, n)?, n, d)
        } else {
            // Token 1 in -> token 0 out: price moves up. Base output is
            // floor(dx * D / N); input to exhaust the bin base reserve is
            // ceil(X * N / D).
            (mul_div_ceil(available, n, d)?, d, n)
        };

        if remaining_input >= need {
            total_output = total_output
                .checked_add(available)
                .ok_or(BinSimulationError::ArithmeticOverflow)?;
            last_output_idx = current_idx;
            remaining_input = remaining_input
                .checked_sub(need)
                .ok_or(BinSimulationError::ArithmeticOverflow)?;
            if remaining_input > 0 {
                current_idx = next_bin_index(pool, current_idx, is_token_0_in, &mut bins_crossed)?;
            }
        } else {
            let partial_output =
                mul_div_floor(remaining_input, output_numerator, output_denominator)?;
            if partial_output > 0 {
                last_output_idx = current_idx;
            }
            total_output = total_output
                .checked_add(partial_output)
                .ok_or(BinSimulationError::ArithmeticOverflow)?;
            remaining_input = 0;
        }
    }

    if total_output == 0 {
        return Err(BinSimulationError::ZeroOutputAmount);
    }

    let resulting_active_bin_id = pool.bins[last_output_idx].id;

    Ok(BinSimulationQuote {
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
        resulting_active_bin_id,
        bins_crossed,
    })
}

/// Simulates a direct exact-output swap over a Bin/DLMM pool state.
///
/// Returns the **minimal** gross input whose exact-input bin traversal yields at
/// least the requested output. The inverse is realized entirely through
/// [`simulate_bin_exact_input`] (the single authoritative kernel) with a bounded
/// exact integer search: the covering ceiling is located by doubling and a
/// smallest-high-error binary search, the minimal covering input is
/// binary-searched, and `input - 1` is proven insufficient before returning.
///
/// Validates pool state, requested output, direction, caller-asserted output,
/// and fee bounds fail-closed. A target above the pool's reachable output returns
/// [`BinSimulationError::OutputUnreachable`]. Never mutates the supplied pool.
pub fn simulate_bin_exact_output(
    pool: &BinPoolState,
    request: &BinExactOutputRequest,
) -> Result<BinExactOutputQuote, BinSimulationError> {
    // 1. Validate pool contract invariants.
    pool.validate().map_err(BinSimulationError::from)?;

    // 2. Reject a zero requested output (mirrors the exact-input zero-input guard).
    if request.amount_out.is_zero() {
        return Err(BinSimulationError::ZeroOutputAmount);
    }

    // 3. Validate chain binding.
    if request.token_in.chain != pool.token_0.chain {
        return Err(BinSimulationError::ChainMismatch);
    }

    // 4. Determine the swap direction and expected counter-asset.
    let is_token_0_in = if request.token_in == pool.token_0 {
        true
    } else if request.token_in == pool.token_1 {
        false
    } else {
        return Err(BinSimulationError::InvalidAssetDirection);
    };
    let expected_out = if is_token_0_in {
        pool.token_1.clone()
    } else {
        pool.token_0.clone()
    };

    // 5. Validate caller-asserted output asset if provided.
    if let Some(ref caller_out) = request.token_out {
        if caller_out.chain != pool.token_0.chain {
            return Err(BinSimulationError::ChainMismatch);
        }
        if caller_out == &request.token_in {
            return Err(BinSimulationError::InvalidAssetDirection);
        }
        if caller_out != &expected_out {
            return Err(BinSimulationError::OutputAssetMismatch);
        }
    }

    // 6. Validate fee bounds.
    let fee_bps_val = pool.fee_bps.get();
    if fee_bps_val >= Bps::MAX {
        return Err(BinSimulationError::InvalidFee);
    }

    // 7. The active-bin/range validation is enforced by the exact-input oracle on
    //    the first probe and propagates fail-closed.

    let requested_out = request.amount_out.get();
    let token_in = request.token_in.clone();

    // 8. Bounded minimal gross-input search, with the exact-input kernel as the
    //    only output oracle.
    let outcome = find_min_gross_input(
        requested_out,
        |g| {
            simulate_bin_exact_input(
                pool,
                &BinExactInputRequest::new(token_in.clone(), AtomicAmount::new(g)),
            )
            .map(|quote| quote.output.amount.get())
        },
        bin_probe_class,
    )?;

    let minimal_in = match outcome {
        MinimalInputSearch::Found(g) => g,
        MinimalInputSearch::Unreachable => return Err(BinSimulationError::OutputUnreachable),
        MinimalInputSearch::Invariant => return Err(BinSimulationError::InvariantViolated),
    };

    // 9. Realize the authoritative exact-input quote at the proven-minimal input.
    let realized = simulate_bin_exact_input(
        pool,
        &BinExactInputRequest::new(token_in, AtomicAmount::new(minimal_in)),
    )?;
    if realized.output.amount.get() < requested_out {
        return Err(BinSimulationError::InvariantViolated);
    }

    Ok(BinExactOutputQuote {
        input: realized.input,
        requested_output: AssetAmount {
            asset: expected_out,
            amount: request.amount_out,
        },
        output: realized.output,
        fee: realized.fee,
        effective_input: realized.effective_input,
        fee_bps: realized.fee_bps,
        resulting_active_bin_id: realized.resulting_active_bin_id,
        bins_crossed: realized.bins_crossed,
    })
}
