//! Pure, deterministic tax-aware CPMM buy/sell round-trip simulation composition.
//!
//! Composes landed tax-aware CPMM buy simulation with staged post-buy reserve reconstruction
//! and landed tax-aware CPMM sell simulation. Operates without floating-point arithmetic,
//! wall-clock time, external dependencies, or side-effects.

use market_types::CpmmPoolState;
use serde::{Deserialize, Serialize};
use tax_engine::TaxAssessment;

use crate::buy_tax::{simulate_tax_aware_cpmm_buy_exact_input, TaxAwareCpmmBuyQuote};
use crate::cpmm::CpmmExactInputRequest;
use crate::error::TaxAwareSimulationError;
use crate::sell_tax::{simulate_tax_aware_cpmm_sell_exact_input, TaxAwareCpmmSellQuote};

/// Explicit typed result of a deterministic tax-aware CPMM buy/sell round-trip simulation.
///
/// Encapsulates:
/// - The buy-side tax-aware CPMM simulation quote ([`TaxAwareCpmmBuyQuote`])
/// - The sell-side tax-aware CPMM simulation quote ([`TaxAwareCpmmSellQuote`]) executed
///   against the staged post-buy pool reserves
///
/// Guarantees that:
/// - Buy output economics and sell input economics are strictly conserved
/// - Sell gross input is precisely the buy net acquired output
/// - Staged reserves used in the sell leg reflect the buy swap's resulting reserves
/// - Caller's pool, request, and assessments remain completely immutable
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareCpmmRoundtripQuote {
    /// Buy-side tax-aware CPMM simulation quote.
    pub buy_quote: TaxAwareCpmmBuyQuote,
    /// Sell-side tax-aware CPMM simulation quote executed on the staged post-buy reserves.
    pub sell_quote: TaxAwareCpmmSellQuote,
}

/// Simulates a deterministic direct CPMM buy/sell round-trip with buy and sell taxes applied.
///
/// # Semantics
/// 1. Simulates a caller-provided exact-input buy using [`simulate_tax_aware_cpmm_buy_exact_input`].
/// 2. Reconstructs a local staged post-buy CPMM pool state from the buy quote's resulting
///    reserves plus unchanged pool identity and fee metadata. Never mutates the caller's pool.
/// 3. Simulates selling exactly the actual net acquired buy output using
///    [`simulate_tax_aware_cpmm_sell_exact_input`] against that staged post-buy state,
///    directed back to the original buy input asset.
/// 4. All source inputs (`pool`, `request`, `buy_assessment`, `sell_assessment`) remain
///    completely unchanged across success and every failure.
/// 5. Errors are returned as redacted structural classes via [`TaxAwareSimulationError`].
pub fn simulate_tax_aware_cpmm_roundtrip_exact_input(
    pool: &CpmmPoolState,
    request: &CpmmExactInputRequest,
    buy_assessment: &TaxAssessment,
    sell_assessment: &TaxAssessment,
) -> Result<TaxAwareCpmmRoundtripQuote, TaxAwareSimulationError> {
    // 1. Simulate caller-provided exact-input buy
    let buy_quote = simulate_tax_aware_cpmm_buy_exact_input(pool, request, buy_assessment)?;

    // 2. Reconstruct a local staged post-buy CPMM state from resulting reserves
    let staged_pool = CpmmPoolState {
        token_0: pool.token_0.clone(),
        token_1: pool.token_1.clone(),
        decimals_0: pool.decimals_0,
        decimals_1: pool.decimals_1,
        reserve_0: buy_quote.cpmm_quote.resulting_reserve_0,
        reserve_1: buy_quote.cpmm_quote.resulting_reserve_1,
        total_lp_supply: pool.total_lp_supply,
        fee_bps: pool.fee_bps,
    };

    // 3. Simulate selling exactly the actual net acquired buy output directed back to original input asset
    let sell_request = CpmmExactInputRequest::new_directed(
        buy_quote.tax_output.net_output.asset.clone(),
        buy_quote.tax_output.net_output.amount,
        request.token_in.clone(),
    );

    let sell_quote =
        simulate_tax_aware_cpmm_sell_exact_input(&staged_pool, &sell_request, sell_assessment)?;

    // 4. Return minimal explicit result type containing the two landed tax-aware quotes
    Ok(TaxAwareCpmmRoundtripQuote {
        buy_quote,
        sell_quote,
    })
}
