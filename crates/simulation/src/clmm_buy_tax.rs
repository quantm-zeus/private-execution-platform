//! Pure, deterministic buy-side tax-aware CLMM simulation composition.
//!
//! Composes the landed pure CLMM exact-input simulation kernel with landed
//! buy-side tax evaluation. Operates without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

use market_types::ClmmPoolState;
use serde::{Deserialize, Serialize};
use tax_engine::{apply_buy_tax_to_output, BuyTaxOutput, TaxAssessment};

use crate::clmm::{simulate_clmm_exact_input, ClmmExactInputRequest, ClmmSimulationQuote};
use crate::error::TaxAwareClmmSimulationError;

/// Explicit typed result of a deterministic buy-side tax-aware CLMM exact-input simulation.
///
/// Encapsulates:
/// - Gross CLMM simulation quote ([`ClmmSimulationQuote`])
/// - Tax-adjusted output economics ([`BuyTaxOutput`])
///
/// Guarantees that `tax_output.gross_output` is precisely the CLMM quote output, and that
/// `net_output + tax_cost == gross_output` (conservation of output).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareClmmBuyQuote {
    /// Gross CLMM simulation quote before applying buy tax.
    pub clmm_quote: ClmmSimulationQuote,
    /// Tax-adjusted buy output economics.
    pub tax_output: BuyTaxOutput,
}

/// Simulates a direct exact-input swap over a CLMM pool and applies buy-side tax deduction.
///
/// # Semantics
/// 1. Runs bounded local CLMM simulation via [`simulate_clmm_exact_input`] to obtain gross output.
/// 2. Applies validated buy-side tax via [`apply_buy_tax_to_output`] to that exact gross output.
/// 3. Validates assessment freshness, chain binding, and asset binding fail-closed.
/// 4. All inputs remain completely immutable across success and every error.
/// 5. Errors are returned as redacted structural classes.
pub fn simulate_tax_aware_clmm_buy_exact_input(
    pool: &ClmmPoolState,
    request: &ClmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareClmmBuyQuote, TaxAwareClmmSimulationError> {
    let clmm_quote = simulate_clmm_exact_input(pool, request)?;
    let tax_output = apply_buy_tax_to_output(assessment, &clmm_quote.output)?;

    Ok(TaxAwareClmmBuyQuote {
        clmm_quote,
        tax_output,
    })
}
