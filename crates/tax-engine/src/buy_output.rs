//! Deterministic buy-side output-tax arithmetic.
//!
//! Applies a validated buy-side [`TaxAssessment`] to a gross output [`AssetAmount`],
//! computing exact integer floor-rounded tax cost and net received output amount.
//! Operates without floating-point arithmetic, wall-clock time, external RPCs,
//! credentials, or side-effects.

use market_types::{AssetAmount, AtomicAmount, FreshnessStatus};
use serde::{Deserialize, Serialize};

use crate::assessment::TaxAssessment;
use crate::error::TaxSafetyError;

/// Structured result of applying buy-side tax to a gross output amount.
///
/// Contains explicit gross output, output-denominated tax cost, and net received
/// output. Preserves the asset identifier and chain exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyTaxOutput {
    /// Original gross output amount before tax deduction.
    pub gross_output: AssetAmount,
    /// Output-denominated tax cost deducted on the buy side.
    pub tax_cost: AssetAmount,
    /// Output-denominated net received amount after deducting tax cost.
    pub net_output: AssetAmount,
}

impl BuyTaxOutput {
    /// Constructs a new [`BuyTaxOutput`] record.
    pub const fn new(
        gross_output: AssetAmount,
        tax_cost: AssetAmount,
        net_output: AssetAmount,
    ) -> Self {
        Self {
            gross_output,
            tax_cost,
            net_output,
        }
    }

    /// The original gross output.
    pub fn gross_output(&self) -> &AssetAmount {
        &self.gross_output
    }

    /// The output-denominated tax cost.
    pub fn tax_cost(&self) -> &AssetAmount {
        &self.tax_cost
    }

    /// The output-denominated net received amount.
    pub fn net_output(&self) -> &AssetAmount {
        &self.net_output
    }

    /// Convenience alias for [`net_output`].
    pub fn net_received_output(&self) -> &AssetAmount {
        &self.net_output
    }
}

/// Applies a validated buy-side [`TaxAssessment`] to a gross output [`AssetAmount`].
///
/// # Validation Rules
/// 1. Assessment freshness status must be [`FreshnessStatus::Fresh`]. Fails closed
///    with [`TaxSafetyError::StaleObservation`] if stale, or [`TaxSafetyError::ResyncRequired`].
/// 2. Gross output asset chain must equal the assessment chain. Fails closed with
///    [`TaxSafetyError::ChainMismatch`].
/// 3. Gross output asset must equal the assessed asset. Fails closed with
///    [`TaxSafetyError::AssessedAssetMismatch`].
/// 4. Gross output amount must be non-zero. Fails closed with [`TaxSafetyError::ZeroGrossOutput`].
/// 5. Computes `tax_cost = floor(gross_amount * buy_tax_bps / 10_000)` using exact
///    integer division without floating point and without overflowing on any `u128`
///    gross amount.
/// 6. Computes `net_output = gross_amount - tax_cost` with checked arithmetic.
/// 7. Rejects fail closed if net output is zero with [`TaxSafetyError::ZeroNetOutput`].
/// 8. Returns explicit structured [`BuyTaxOutput`] preserving the asset identifier exactly.
/// 9. Inputs remain immutable on both success and failure.
pub fn apply_buy_tax_to_output(
    assessment: &TaxAssessment,
    gross_output: &AssetAmount,
) -> Result<BuyTaxOutput, TaxSafetyError> {
    // 1. Freshness validation: require assessment freshness status to be Fresh
    match assessment.freshness.status {
        FreshnessStatus::Fresh => {}
        FreshnessStatus::Stale => return Err(TaxSafetyError::StaleObservation),
        FreshnessStatus::ResyncRequired => return Err(TaxSafetyError::ResyncRequired),
    }

    // 2. Chain validation: require gross output asset chain to match assessed chain
    if gross_output.asset.chain != assessment.chain
        || gross_output.asset.chain != assessment.assessed_asset.chain
    {
        return Err(TaxSafetyError::ChainMismatch);
    }

    // 3. Asset validation: require gross output asset to equal assessed asset
    if gross_output.asset != assessment.assessed_asset {
        return Err(TaxSafetyError::AssessedAssetMismatch);
    }

    // 4. Reject zero gross amount
    let gross_val = gross_output.amount.get();
    if gross_val == 0 {
        return Err(TaxSafetyError::ZeroGrossOutput);
    }

    // 5. Compute tax cost = floor(gross_amount * buy_tax_bps / 10_000)
    // Using exact integer arithmetic without float conversion and without u128 overflow.
    // Mathematical identity: for gross = q * 10_000 + r:
    // floor(gross * bps / 10_000) = q * bps + floor(r * bps / 10_000).
    // Because q <= u128::MAX / 10_000 and bps <= 10_000, q * bps <= gross <= u128::MAX.
    // Because r < 10_000 and bps <= 10_000, r * bps < 100_000_000.
    // Hence, intermediate and final results never overflow u128.
    let buy_tax_bps = assessment.buy_tax.get() as u128;
    let q = gross_val / 10_000;
    let r = gross_val % 10_000;
    let q_part = q
        .checked_mul(buy_tax_bps)
        .expect("q * bps cannot overflow u128");
    let r_part = r
        .checked_mul(buy_tax_bps)
        .expect("r * bps cannot overflow u128")
        / 10_000;
    let tax_cost_val = q_part
        .checked_add(r_part)
        .expect("tax_cost cannot overflow u128");

    // 6. Compute net received output = gross_amount - tax_cost with checked arithmetic
    let net_val = gross_val
        .checked_sub(tax_cost_val)
        .expect("tax_cost cannot exceed gross_amount");

    // 7. Fail closed if net output is zero
    if net_val == 0 {
        return Err(TaxSafetyError::ZeroNetOutput);
    }

    // 8. Structured result preserving the asset exactly
    Ok(BuyTaxOutput {
        gross_output: gross_output.clone(),
        tax_cost: AssetAmount {
            asset: gross_output.asset.clone(),
            amount: AtomicAmount::new(tax_cost_val),
        },
        net_output: AssetAmount {
            asset: gross_output.asset.clone(),
            amount: AtomicAmount::new(net_val),
        },
    })
}

/// Convenience alias for [`apply_buy_tax_to_output`].
pub fn apply_buy_tax(
    assessment: &TaxAssessment,
    gross_output: &AssetAmount,
) -> Result<BuyTaxOutput, TaxSafetyError> {
    apply_buy_tax_to_output(assessment, gross_output)
}

/// Convenience alias for [`apply_buy_tax_to_output`].
pub fn calculate_buy_tax_output(
    assessment: &TaxAssessment,
    gross_output: &AssetAmount,
) -> Result<BuyTaxOutput, TaxSafetyError> {
    apply_buy_tax_to_output(assessment, gross_output)
}

/// Type alias for [`BuyTaxOutput`].
pub type BuyOutputTax = BuyTaxOutput;
