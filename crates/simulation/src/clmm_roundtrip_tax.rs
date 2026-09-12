//! Pure, deterministic tax-aware CLMM buy/sell round-trip simulation composition.
//!
//! Composes the landed tax-aware CLMM buy simulation with staged post-buy pool-state
//! reconstruction and the landed tax-aware CLMM sell simulation. Operates without
//! floating-point arithmetic, wall-clock time, external dependencies, or side-effects.

use market_types::ClmmPoolState;
use serde::{Deserialize, Serialize};
use tax_engine::TaxAssessment;

use crate::clmm::ClmmExactInputRequest;
use crate::clmm_buy_tax::{simulate_tax_aware_clmm_buy_exact_input, TaxAwareClmmBuyQuote};
use crate::clmm_sell_tax::{simulate_tax_aware_clmm_sell_exact_input, TaxAwareClmmSellQuote};
use crate::error::TaxAwareClmmSimulationError;

/// Explicit typed result of a deterministic tax-aware CLMM buy/sell round-trip simulation.
///
/// Encapsulates:
/// - The buy-side tax-aware CLMM simulation quote ([`TaxAwareClmmBuyQuote`])
/// - The sell-side tax-aware CLMM simulation quote ([`TaxAwareClmmSellQuote`]) executed
///   against the staged post-buy pool state
///
/// Guarantees that:
/// - Buy output economics and sell input economics are strictly conserved
/// - Sell gross input is precisely the buy net acquired output
/// - The staged pool state used in the sell leg reflects the buy swap's resulting
///   sqrt price, tick, and active liquidity
/// - Caller's pool, request, and assessments remain completely immutable
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAwareClmmRoundtripQuote {
    /// Buy-side tax-aware CLMM simulation quote.
    pub buy_quote: TaxAwareClmmBuyQuote,
    /// Sell-side tax-aware CLMM simulation quote executed on the staged post-buy pool state.
    pub sell_quote: TaxAwareClmmSellQuote,
}

/// Simulates a deterministic direct CLMM buy/sell round-trip with buy and sell taxes applied.
///
/// # Semantics
/// 1. Simulates a caller-provided exact-input buy using
///    [`simulate_tax_aware_clmm_buy_exact_input`].
/// 2. Reconstructs a local staged post-buy CLMM pool state from the buy quote's resulting
///    sqrt price, tick, and active liquidity plus the unchanged pool identity, tick set, and fee
///    metadata. Never mutates the caller's pool.
/// 3. Simulates selling exactly the actual net acquired buy output using
///    [`simulate_tax_aware_clmm_sell_exact_input`] against that staged state, directed back to the
///    original buy input asset.
/// 4. All source inputs (`pool`, `request`, `buy_assessment`, `sell_assessment`) remain completely
///    unchanged across success and every failure.
/// 5. Errors are returned as redacted structural classes via [`TaxAwareClmmSimulationError`].
pub fn simulate_tax_aware_clmm_roundtrip_exact_input(
    pool: &ClmmPoolState,
    request: &ClmmExactInputRequest,
    buy_assessment: &TaxAssessment,
    sell_assessment: &TaxAssessment,
) -> Result<TaxAwareClmmRoundtripQuote, TaxAwareClmmSimulationError> {
    // 1. Simulate caller-provided exact-input buy.
    let buy_quote = simulate_tax_aware_clmm_buy_exact_input(pool, request, buy_assessment)?;

    // 2. Reconstruct a local staged post-buy CLMM state from the buy quote's resulting state.
    let staged_pool = ClmmPoolState {
        token_0: pool.token_0.clone(),
        token_1: pool.token_1.clone(),
        decimals_0: pool.decimals_0,
        decimals_1: pool.decimals_1,
        tick_spacing: pool.tick_spacing,
        current_tick: buy_quote.clmm_quote.resulting_tick,
        sqrt_price_x64: buy_quote.clmm_quote.resulting_sqrt_price_x64,
        liquidity: buy_quote.clmm_quote.resulting_liquidity,
        fee_bps: pool.fee_bps,
        ticks: pool.ticks.clone(),
    };

    // 3. Sell exactly the net acquired buy output, directed back to the original input asset.
    let sell_request = ClmmExactInputRequest {
        token_in: buy_quote.tax_output.net_output.asset.clone(),
        amount_in: buy_quote.tax_output.net_output.amount,
        token_out: Some(request.token_in.clone()),
    };
    let sell_quote =
        simulate_tax_aware_clmm_sell_exact_input(&staged_pool, &sell_request, sell_assessment)?;

    Ok(TaxAwareClmmRoundtripQuote {
        buy_quote,
        sell_quote,
    })
}
