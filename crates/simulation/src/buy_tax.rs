//! Pure, deterministic buy-side tax-aware CPMM simulation composition.
//!
//! Composes the landed pure CPMM exact-input simulation kernel with landed
//! buy-side tax evaluation. Operates without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

use chain_types::AssetId;
use market_types::{AssetAmount, AtomicAmount, CpmmPoolState};
use serde::{Deserialize, Serialize};
use tax_engine::{apply_buy_tax_to_output, BuyTaxOutput, TaxAssessment};

use crate::cpmm::{simulate_cpmm_exact_input, CpmmExactInputRequest, CpmmSimulationQuote};
use crate::error::TaxAwareSimulationError;

/// Explicit typed result of a deterministic buy-side tax-aware CPMM exact-input simulation.
///
/// Encapsulates:
/// - Gross CPMM simulation quote ([`CpmmSimulationQuote`])
/// - Tax-adjusted output economics ([`BuyTaxOutput`])
///
/// Guarantees that `gross_output` is precisely the CPMM quote output, and that
/// `net_output + tax_cost == gross_output` (conservation of output).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareCpmmBuyQuote {
    /// Gross CPMM simulation quote before applying buy tax.
    pub cpmm_quote: CpmmSimulationQuote,
    /// Tax-adjusted buy output economics.
    pub tax_output: BuyTaxOutput,
}

pub type TaxAwareCpmmBuyResult = TaxAwareCpmmBuyQuote;
pub type TaxAwareCpmmSimulationQuote = TaxAwareCpmmBuyQuote;

impl TaxAwareCpmmBuyQuote {
    /// Constructs a new [`TaxAwareCpmmBuyQuote`].
    pub const fn new(cpmm_quote: CpmmSimulationQuote, tax_output: BuyTaxOutput) -> Self {
        Self {
            cpmm_quote,
            tax_output,
        }
    }

    /// Reference to the gross CPMM simulation quote.
    #[inline]
    pub fn cpmm_quote(&self) -> &CpmmSimulationQuote {
        &self.cpmm_quote
    }

    /// Reference to the tax-adjusted buy output economics.
    #[inline]
    pub fn tax_output(&self) -> &BuyTaxOutput {
        &self.tax_output
    }

    /// Exact gross simulated output before buy tax deduction.
    #[inline]
    pub fn gross_output(&self) -> &AssetAmount {
        self.tax_output.gross_output()
    }

    /// Output-denominated tax cost deducted on the buy side.
    #[inline]
    pub fn tax_cost(&self) -> &AssetAmount {
        self.tax_output.tax_cost()
    }

    /// Output-denominated net received output amount after deducting tax cost.
    #[inline]
    pub fn net_output(&self) -> &AssetAmount {
        self.tax_output.net_output()
    }

    /// Convenience alias for [`net_output`](Self::net_output).
    #[inline]
    pub fn net_received_output(&self) -> &AssetAmount {
        self.tax_output.net_received_output()
    }

    /// Exact input asset and amount from the underlying CPMM simulation.
    #[inline]
    pub fn input(&self) -> &AssetAmount {
        self.cpmm_quote.input()
    }

    /// Explicit pool fee taken from the input in the underlying CPMM simulation.
    #[inline]
    pub fn pool_fee(&self) -> &AssetAmount {
        self.cpmm_quote.pool_fee()
    }

    /// Effective post-fee input amount entering the constant-product calculation.
    #[inline]
    pub fn effective_input(&self) -> &AssetAmount {
        self.cpmm_quote.effective_input()
    }
}

/// Simulates a direct exact-input swap over a CPMM pool and applies buy-side tax deduction.
///
/// # Semantics
/// 1. Runs pure local CPMM simulation via [`simulate_cpmm_exact_input`] to obtain gross output.
/// 2. Applies validated buy-side tax via [`apply_buy_tax_to_output`] to that gross output.
/// 3. Validates assessment freshness, chain binding, and asset binding fail-closed.
/// 4. All inputs remain completely immutable across success and every error.
/// 5. Errors are returned as redacted structural classes.
pub fn simulate_tax_aware_cpmm_buy_exact_input(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
    let cpmm_quote = simulate_cpmm_exact_input(pool, request)?;
    let tax_output = apply_buy_tax_to_output(assessment, &cpmm_quote.output)?;

    Ok(TaxAwareCpmmBuyQuote {
        cpmm_quote,
        tax_output,
    })
}

/// Convenience alias for [`simulate_tax_aware_cpmm_buy_exact_input`].
#[inline]
pub fn simulate_tax_aware_cpmm_buy(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
    simulate_tax_aware_cpmm_buy_exact_input(pool, request, assessment)
}

/// Convenience helper to simulate exact input buy swap with inferred output asset.
pub fn simulate_tax_aware_cpmm_buy_swap(
    pool: &CpmmPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
    let req = CpmmExactInputRequest::new(token_in.clone(), amount_in);
    simulate_tax_aware_cpmm_buy_exact_input(pool, &req, assessment)
}

/// Convenience helper to simulate exact input buy swap with caller-asserted output asset.
pub fn simulate_tax_aware_cpmm_buy_directed(
    pool: &CpmmPoolState,
    token_in: &AssetId,
    amount_in: AtomicAmount,
    token_out: &AssetId,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
    let req = CpmmExactInputRequest::new_directed(token_in.clone(), amount_in, token_out.clone());
    simulate_tax_aware_cpmm_buy_exact_input(pool, &req, assessment)
}

/// Convenience alias for [`simulate_tax_aware_cpmm_buy_exact_input`].
#[inline]
pub fn simulate_cpmm_exact_input_buy_tax(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmBuyQuote, TaxAwareSimulationError> {
    simulate_tax_aware_cpmm_buy_exact_input(pool, request, assessment)
}
