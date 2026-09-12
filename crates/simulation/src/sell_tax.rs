//! Pure, deterministic sell-side tax-aware CPMM simulation composition.
//!
//! Composes landed sell-side tax evaluation with the landed pure CPMM exact-input
//! simulation kernel. Operates without floating-point arithmetic, wall-clock time,
//! external dependencies, or side-effects.

use market_types::{AssetAmount, CpmmPoolState};
use serde::{Deserialize, Serialize};
use tax_engine::{apply_sell_tax_to_input, SellTaxInput, TaxAssessment};

use crate::cpmm::{simulate_cpmm_exact_input, CpmmExactInputRequest, CpmmSimulationQuote};
use crate::error::TaxAwareSimulationError;

/// Explicit typed result of a deterministic sell-side tax-aware CPMM exact-input simulation.
///
/// Encapsulates:
/// - Sell-side tax input economics ([`SellTaxInput`])
/// - Resulting CPMM simulation quote ([`CpmmSimulationQuote`]) executed on the net transferable input
///
/// Guarantees that:
/// - `gross_input` is precisely the original swap input
/// - `tax_cost + net_transferable_input == gross_input` (conservation of input)
/// - `cpmm_quote.input` exactly equals `net_transferable_input`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareCpmmSellQuote {
    /// Resulting CPMM simulation quote executed on the net transferable input.
    pub cpmm_quote: CpmmSimulationQuote,
    /// Tax-adjusted sell input economics.
    pub tax_input: SellTaxInput,
}

/// Simulates a direct exact-input swap over a CPMM pool with sell-side tax deduction applied first.
///
/// # Semantics
/// 1. Builds the gross input [`AssetAmount`] from `request.token_in` and `request.amount_in`.
/// 2. Validates assessment freshness, chain binding, assessed asset binding, non-zero gross input,
///    and non-zero net input via landed [`apply_sell_tax_to_input`]. All tax errors fail closed
///    *before* CPMM simulation.
/// 3. Runs pure local CPMM simulation via [`simulate_cpmm_exact_input`] on the net transferable input,
///    preserving the requested input/output direction (`request.token_out`).
/// 4. All source inputs (`pool`, `request`, `assessment`) remain unchanged on success and every failure.
/// 5. Errors are returned as redacted structural classes via [`TaxAwareSimulationError`].
pub fn simulate_tax_aware_cpmm_sell_exact_input(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmSellQuote, TaxAwareSimulationError> {
    let gross_input = AssetAmount {
        asset: request.token_in.clone(),
        amount: request.amount_in,
    };
    let tax_input = apply_sell_tax_to_input(assessment, &gross_input)?;

    let mut net_request = request.clone();
    net_request.amount_in = tax_input.net_transferable_input.amount;
    let cpmm_quote = simulate_cpmm_exact_input(pool, &net_request)?;
    debug_assert_eq!(cpmm_quote.input, tax_input.net_transferable_input);

    Ok(TaxAwareCpmmSellQuote {
        cpmm_quote,
        tax_input,
    })
}
