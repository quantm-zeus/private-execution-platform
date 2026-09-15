//! Pure, deterministic estimate-vs-realized execution analytics (P84).
//!
//! Given one pre-trade [`ExecutionEstimate`] and one [`RealizedExecution`], the
//! core classifies how the fill actually landed: the output deviation in basis
//! points and the signed input/gas/tax deltas. It never signs, submits, performs
//! I/O, reads a clock, or uses floating point; every ratio is computed with
//! `u128` integer arithmetic and the analysis is a pure function of its inputs.
//!
//! # Redaction
//! Amounts and assets are private execution economics. Manual [`fmt::Debug`]
//! implementations for [`ExecutionEstimate`], [`RealizedExecution`],
//! [`ExecutionAnalytics`], and [`Delta`] never render an amount, asset, or
//! chain; [`ExecutionAnalytics`] renders only the derived bps and directions,
//! and [`Delta`] renders its direction but redacts its magnitude. None of the
//! new types implement `serde`, so an analytics record can never cross a
//! serialization boundary.

use std::fmt;

use chain_types::AssetId;

/// Basis points in one whole unit (the deviation scale).
const BPS_SCALE: u128 = 10_000;

/// A pre-trade estimate for one execution, in atomic units.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionEstimate {
    /// Asset spent.
    pub token_in: AssetId,
    /// Asset received.
    pub token_out: AssetId,
    /// Expected wallet debit, in `token_in` atomic units.
    pub amount_in: u128,
    /// Expected net output, in `token_out` atomic units (> 0).
    pub expected_amount_out: u128,
    /// Expected gas paid, in the chain gas asset's atomic units.
    pub expected_gas: Option<u128>,
    /// Expected tax paid, in `token_out` atomic units.
    pub expected_tax: Option<u128>,
}

impl fmt::Debug for ExecutionEstimate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: assets, chain, and every amount are private economics.
        formatter.write_str("ExecutionEstimate { .. }")
    }
}

/// The amounts actually realized by one execution, in atomic units.
#[derive(Clone, PartialEq, Eq)]
pub struct RealizedExecution {
    /// Asset spent.
    pub token_in: AssetId,
    /// Asset received.
    pub token_out: AssetId,
    /// Net input consumed, in `token_in` atomic units.
    pub amount_in: u128,
    /// Net output received, in `token_out` atomic units.
    pub amount_out: u128,
    /// Gas actually paid, in the chain gas asset's atomic units.
    pub gas_paid: Option<u128>,
    /// Tax actually paid, in `token_out` atomic units.
    pub tax_paid: Option<u128>,
}

impl fmt::Debug for RealizedExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: assets, chain, and every amount are private economics.
        formatter.write_str("RealizedExecution { .. }")
    }
}

/// Whether realized output/input beat the estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaDirection {
    /// Realized is better than expected.
    RealizedBetter,
    /// Realized equals expected.
    Exact,
    /// Realized is worse than expected.
    RealizedWorse,
}

/// Signed-magnitude delta (no `i128` overflow over full-range `u128` inputs).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    /// Which side the realized amount landed on.
    pub direction: DeltaDirection,
    /// Absolute distance between realized and expected, in atomic units.
    pub magnitude: u128,
}

impl fmt::Debug for Delta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: the magnitude is an amount, so only the direction renders.
        formatter
            .debug_struct("Delta")
            .field("direction", &self.direction)
            .field("magnitude", &"<redacted>")
            .finish()
    }
}

/// Exact estimate-vs-realized comparison for one execution.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExecutionAnalytics {
    /// Exact `floor(10_000 * |realized_out - expected_out| / expected_out)`.
    pub output_deviation_bps: u16,
    /// Direction of the realized output versus the expected output.
    pub output_direction: DeltaDirection,
    /// Realized minus expected input (spending more is worse).
    pub input_delta: Delta,
    /// Realized minus expected gas; `None` only when both sides are `None`.
    pub gas_delta: Option<Delta>,
    /// Realized minus expected tax; `None` only when both sides are `None`.
    pub tax_delta: Option<Delta>,
}

impl fmt::Debug for ExecutionAnalytics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: only the derived bps and directions render. [`Delta`]'s own
        // `Debug` redacts the magnitude amount.
        formatter
            .debug_struct("ExecutionAnalytics")
            .field("output_deviation_bps", &self.output_deviation_bps)
            .field("output_direction", &self.output_direction)
            .field("input_delta", &self.input_delta)
            .field("gas_delta", &self.gas_delta)
            .field("tax_delta", &self.tax_delta)
            .finish_non_exhaustive()
    }
}

/// Observational sink for a derived, redacted execution-analytics record.
///
/// Implementations must be cheap, non-blocking, and must never panic: the sink
/// is called on the execution path after a compliant fill has been applied, and
/// nothing it does may fail or alter that result.
pub trait ExecutionAnalyticsSink: Send + Sync {
    /// Records one derived analytics record.
    fn record(&self, analytics: &ExecutionAnalytics);
}

/// A sink that drops every record.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopExecutionAnalyticsSink;

impl ExecutionAnalyticsSink for NoopExecutionAnalyticsSink {
    fn record(&self, _analytics: &ExecutionAnalytics) {}
}

/// A redacted analytics failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnalyticsError {
    /// The two executions are not on the same chain.
    #[error("asset chain mismatch")]
    ChainMismatch,
    /// The two executions do not trade the same asset pair.
    #[error("asset pair mismatch")]
    PairMismatch,
    /// The estimate has no expected output, so no deviation is defined.
    #[error("expected output is zero")]
    ZeroExpectedOutput,
    /// Exactly one side carries a gas baseline.
    #[error("gas baseline presence mismatch")]
    GasBaselineMismatch,
    /// Exactly one side carries a tax baseline.
    #[error("tax baseline presence mismatch")]
    TaxBaselineMismatch,
    /// The deviation arithmetic overflowed `u128` or exceeded `u16`.
    #[error("analytics arithmetic overflow")]
    ArithmeticOverflow,
}

/// Compares `realized` against `estimate`, purely and deterministically.
///
/// Binding is checked first: the chains and both assets must agree. A zero
/// expected output then fails closed without dividing. The output deviation is
/// the exact floored bps with `u128::checked_mul`; an overflowing product or a
/// quotient above [`u16::MAX`] yields [`AnalyticsError::ArithmeticOverflow`].
/// Input uses signed-magnitude `abs_diff` (spending more is worse), and gas/tax
/// require matching presence on both sides.
pub fn analyze(
    estimate: &ExecutionEstimate,
    realized: &RealizedExecution,
) -> Result<ExecutionAnalytics, AnalyticsError> {
    if estimate.token_in.chain != realized.token_in.chain
        || estimate.token_out.chain != realized.token_out.chain
    {
        return Err(AnalyticsError::ChainMismatch);
    }
    if estimate.token_in != realized.token_in || estimate.token_out != realized.token_out {
        return Err(AnalyticsError::PairMismatch);
    }
    let expected_out = estimate.expected_amount_out;
    if expected_out == 0 {
        return Err(AnalyticsError::ZeroExpectedOutput);
    }

    let difference = realized.amount_out.abs_diff(expected_out);
    let scaled = difference
        .checked_mul(BPS_SCALE)
        .ok_or(AnalyticsError::ArithmeticOverflow)?;
    let quotient = scaled / expected_out;
    if quotient > u128::from(u16::MAX) {
        return Err(AnalyticsError::ArithmeticOverflow);
    }
    // `quotient` was range-checked against `u16::MAX` immediately above.
    let output_deviation_bps = quotient as u16;

    let input_delta = delta(realized.amount_in, estimate.amount_in);
    let gas_delta = match (realized.gas_paid, estimate.expected_gas) {
        (None, None) => None,
        (Some(realized), Some(expected)) => Some(delta(realized, expected)),
        _ => return Err(AnalyticsError::GasBaselineMismatch),
    };
    let tax_delta = match (realized.tax_paid, estimate.expected_tax) {
        (None, None) => None,
        (Some(realized), Some(expected)) => Some(delta(realized, expected)),
        _ => return Err(AnalyticsError::TaxBaselineMismatch),
    };

    Ok(ExecutionAnalytics {
        output_deviation_bps,
        output_direction: output_direction(realized.amount_out, expected_out),
        input_delta,
        gas_delta,
        tax_delta,
    })
}

/// Signed-magnitude delta where a larger realized value is worse.
fn delta(realized: u128, expected: u128) -> Delta {
    Delta {
        direction: if realized > expected {
            DeltaDirection::RealizedWorse
        } else if realized < expected {
            DeltaDirection::RealizedBetter
        } else {
            DeltaDirection::Exact
        },
        magnitude: realized.abs_diff(expected),
    }
}

/// Direction of realized output where a larger realized value is better.
fn output_direction(realized: u128, expected: u128) -> DeltaDirection {
    if realized > expected {
        DeltaDirection::RealizedBetter
    } else if realized < expected {
        DeltaDirection::RealizedWorse
    } else {
        DeltaDirection::Exact
    }
}
