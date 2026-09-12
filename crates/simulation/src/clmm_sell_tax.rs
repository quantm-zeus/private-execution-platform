//! Pure, deterministic sell-side tax-aware CLMM simulation composition.
//!
//! Applies landed sell-side transfer-tax input arithmetic first, then feeds only
//! the net transferable input through the landed pure CLMM exact-input kernel.
//! Operates without floating-point arithmetic, wall-clock time, external
//! dependencies, or side-effects.

use market_types::{AssetAmount, ClmmPoolState};
use serde::{Deserialize, Serialize};
use tax_engine::{apply_sell_tax_to_input, SellTaxInput, TaxAssessment};

use crate::clmm::{simulate_clmm_exact_input, ClmmExactInputRequest, ClmmSimulationQuote};
use crate::error::TaxAwareClmmSimulationError;

/// Explicit typed result of a deterministic sell-side tax-aware CLMM exact-input simulation.
///
/// Encapsulates:
/// - Sell-side tax input economics ([`SellTaxInput`])
/// - Resulting CLMM simulation quote ([`ClmmSimulationQuote`]) executed on the net transferable input
///
/// Guarantees that:
/// - `tax_input.gross_input` is precisely the original swap input
/// - `tax_input.tax_cost + tax_input.net_transferable_input == tax_input.gross_input`
/// - `clmm_quote.input` exactly equals `tax_input.net_transferable_input`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareClmmSellQuote {
    /// Resulting CLMM simulation quote executed on the net transferable input.
    pub clmm_quote: ClmmSimulationQuote,
    /// Tax-adjusted sell input economics.
    pub tax_input: SellTaxInput,
}

/// Simulates a direct exact-input swap over a CLMM pool with sell-side tax applied first.
///
/// # Semantics
/// 1. Builds the gross input [`AssetAmount`] from `request.token_in` and `request.amount_in`.
/// 2. Validates assessment freshness, chain binding, assessed asset binding, non-zero gross input,
///    and non-zero net input via landed [`apply_sell_tax_to_input`]. Every tax error fails closed
///    *before* CLMM simulation.
/// 3. Runs bounded local CLMM simulation via [`simulate_clmm_exact_input`] on the net transferable
///    input, preserving the requested input/output direction (`request.token_out`).
/// 4. All source inputs (`pool`, `request`, `assessment`) remain unchanged on success and failure.
/// 5. Errors are returned as redacted structural classes via [`TaxAwareClmmSimulationError`].
pub fn simulate_tax_aware_clmm_sell_exact_input(
    pool: &ClmmPoolState,
    request: &ClmmExactInputRequest,
    assessment: &TaxAssessment,
) -> Result<TaxAwareClmmSellQuote, TaxAwareClmmSimulationError> {
    let gross_input = AssetAmount {
        asset: request.token_in.clone(),
        amount: request.amount_in,
    };
    let tax_input = apply_sell_tax_to_input(assessment, &gross_input)?;

    let mut net_request = request.clone();
    net_request.amount_in = tax_input.net_transferable_input.amount;
    let clmm_quote = simulate_clmm_exact_input(pool, &net_request)?;
    debug_assert_eq!(clmm_quote.input, tax_input.net_transferable_input);

    Ok(TaxAwareClmmSellQuote {
        clmm_quote,
        tax_input,
    })
}
