//! Deterministic sell-side transfer-tax input arithmetic.
//!
//! Applies a validated sell-side [`TaxAssessment`] to a gross input [`AssetAmount`],
//! computing exact integer floor-rounded tax cost and net transferable input amount.
//! Operates without floating-point arithmetic, wall-clock time, external RPCs,
//! credentials, or side-effects.

use market_types::{AssetAmount, AtomicAmount, FreshnessStatus};
use serde::{Deserialize, Serialize};

use crate::assessment::TaxAssessment;
use crate::error::TaxSafetyError;

/// Structured result of applying sell-side transfer-tax to a gross input amount.
///
/// Contains explicit gross input, input-denominated tax cost, and net transferable
/// input. Preserves the asset identifier and chain exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellTaxInput {
    /// Original gross input amount before tax deduction.
    pub gross_input: AssetAmount,
    /// Input-denominated tax cost deducted on the sell side.
    pub tax_cost: AssetAmount,
    /// Input-denominated net transferable amount after deducting tax cost.
    pub net_transferable_input: AssetAmount,
}

impl SellTaxInput {
    /// Constructs a new [`SellTaxInput`] record.
    pub const fn new(
        gross_input: AssetAmount,
        tax_cost: AssetAmount,
        net_transferable_input: AssetAmount,
    ) -> Self {
        Self {
            gross_input,
            tax_cost,
            net_transferable_input,
        }
    }

    /// The original gross input.
    pub fn gross_input(&self) -> &AssetAmount {
        &self.gross_input
    }

    /// The input-denominated tax cost.
    pub fn tax_cost(&self) -> &AssetAmount {
        &self.tax_cost
    }

    /// The input-denominated net transferable amount.
    pub fn net_transferable_input(&self) -> &AssetAmount {
        &self.net_transferable_input
    }

    /// Convenience alias for [`net_transferable_input`].
    pub fn net_input(&self) -> &AssetAmount {
        &self.net_transferable_input
    }
}

/// Applies a validated sell-side [`TaxAssessment`] to a gross input [`AssetAmount`].
///
/// # Validation Rules
/// 1. Assessment freshness status must be [`FreshnessStatus::Fresh`]. Fails closed
///    with [`TaxSafetyError::StaleObservation`] if stale, or [`TaxSafetyError::ResyncRequired`].
/// 2. Gross input asset chain must equal the assessment chain. Fails closed with
///    [`TaxSafetyError::ChainMismatch`].
/// 3. Gross input asset must equal the assessed asset. Fails closed with
///    [`TaxSafetyError::AssessedAssetMismatch`].
/// 4. Gross input amount must be non-zero. Fails closed with [`TaxSafetyError::ZeroGrossInput`].
/// 5. Computes `tax_cost = floor(gross_amount * sell_tax_bps / 10_000)` using exact
///    integer division without floating point and without overflowing on any `u128`
///    gross amount.
/// 6. Computes `net_transferable_input = gross_amount - tax_cost` with checked arithmetic.
/// 7. Rejects fail closed if net transferable input is zero with [`TaxSafetyError::ZeroNetInput`].
/// 8. Returns explicit structured [`SellTaxInput`] preserving the asset identifier exactly.
/// 9. Inputs remain immutable on both success and failure.
pub fn apply_sell_tax_to_input(
    assessment: &TaxAssessment,
    gross_input: &AssetAmount,
) -> Result<SellTaxInput, TaxSafetyError> {
    // 1. Freshness validation: require assessment freshness status to be Fresh
    match assessment.freshness.status {
        FreshnessStatus::Fresh => {}
        FreshnessStatus::Stale => return Err(TaxSafetyError::StaleObservation),
        FreshnessStatus::ResyncRequired => return Err(TaxSafetyError::ResyncRequired),
    }

    // 2. Chain validation: require gross input asset chain to match assessed chain
    if gross_input.asset.chain != assessment.chain
        || gross_input.asset.chain != assessment.assessed_asset.chain
    {
        return Err(TaxSafetyError::ChainMismatch);
    }

    // 3. Asset validation: require gross input asset to equal assessed asset
    if gross_input.asset != assessment.assessed_asset {
        return Err(TaxSafetyError::AssessedAssetMismatch);
    }

    // 4. Reject zero gross amount
    let gross_val = gross_input.amount.get();
    if gross_val == 0 {
        return Err(TaxSafetyError::ZeroGrossInput);
    }

    // 5. Compute tax cost = floor(gross_amount * sell_tax_bps / 10_000)
    // Using exact integer arithmetic without float conversion and without u128 overflow.
    // Mathematical identity: for gross = q * 10_000 + r:
    // floor(gross * bps / 10_000) = q * bps + floor(r * bps / 10_000).
    // Because q <= u128::MAX / 10_000 and bps <= 10_000, q * bps <= gross <= u128::MAX.
    // Because r < 10_000 and bps <= 10_000, r * bps < 100_000_000.
    // Hence, intermediate and final results never overflow u128.
    let sell_tax_bps = assessment.sell_tax.get() as u128;
    let q = gross_val / 10_000;
    let r = gross_val % 10_000;
    let q_part = q
        .checked_mul(sell_tax_bps)
        .expect("q * bps cannot overflow u128");
    let r_part = r
        .checked_mul(sell_tax_bps)
        .expect("r * bps cannot overflow u128")
        / 10_000;
    let tax_cost_val = q_part
        .checked_add(r_part)
        .expect("tax_cost cannot overflow u128");

    // 6. Compute net transferable input = gross_amount - tax_cost with checked arithmetic
    let net_val = gross_val
        .checked_sub(tax_cost_val)
        .expect("tax_cost cannot exceed gross_amount");

    // 7. Fail closed if net transferable input is zero
    if net_val == 0 {
        return Err(TaxSafetyError::ZeroNetInput);
    }

    // 8. Structured result preserving the asset exactly
    Ok(SellTaxInput {
        gross_input: gross_input.clone(),
        tax_cost: AssetAmount {
            asset: gross_input.asset.clone(),
            amount: AtomicAmount::new(tax_cost_val),
        },
        net_transferable_input: AssetAmount {
            asset: gross_input.asset.clone(),
            amount: AtomicAmount::new(net_val),
        },
    })
}

/// Convenience alias for [`apply_sell_tax_to_input`].
pub fn apply_sell_tax(
    assessment: &TaxAssessment,
    gross_input: &AssetAmount,
) -> Result<SellTaxInput, TaxSafetyError> {
    apply_sell_tax_to_input(assessment, gross_input)
}

/// Convenience alias for [`apply_sell_tax_to_input`].
pub fn calculate_sell_tax_input(
    assessment: &TaxAssessment,
    gross_input: &AssetAmount,
) -> Result<SellTaxInput, TaxSafetyError> {
    apply_sell_tax_to_input(assessment, gross_input)
}

/// Type alias for [`SellTaxInput`].
pub type SellInputTax = SellTaxInput;
