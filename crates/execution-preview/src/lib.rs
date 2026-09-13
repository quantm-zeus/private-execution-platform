//! Exact-simulation to execution-preview net-delta bridge.
//!
//! Normalizes exact local simulation quotes (CPMM, CLMM, Bin/DLMM, and their
//! tax-aware compositions) into a canonical [`NetDelta`] in full-wallet-debit
//! semantics, then binds that delta to the locked [`domain::ExecutionPreview`]
//! contract without fabricating routes or prices.
//!
//! # Exact economics
//! - `A_in = request.amount_in` is the full wallet debit.
//! - Pool fee is input-side: `fee = floor(A_in * fee_bps / 10_000)`.
//! - Buy tax is output-side: `tax = floor(gross_out * buy_tax / 10_000)`.
//! - Sell tax is input-side before the swap:
//!   `tax = floor(A_in * sell_tax / 10_000)`, and the pool runs on
//!   `A_in - tax`.
//! - `simulated_net_input = A_in` on both sides, so a sell's net limit price
//!   is never overstated by the tax it must still pay.
//! - Zero fee/tax maps to `None`, never `Some(0)`.
//!
//! No floating point, wall-clock time, external dependency, or side effect is
//! used anywhere in this crate.

use chain_types::AssetId;
use domain::{
    ExecutionCostComponents, ExecutionPreview, RoutePlan, TradeIntent, TradeSide,
    ValidatedExecutionPreview,
};
use market_types::{evaluate_freshness, AssetAmount, FreshnessPolicy, FreshnessStatus};
use serde::{Deserialize, Serialize};
use simulation::{
    BinSimulationQuote, ClmmSimulationQuote, CpmmSimulationQuote, TaxAwareClmmBuyQuote,
    TaxAwareClmmSellQuote, TaxAwareCpmmBuyQuote, TaxAwareCpmmSellQuote,
};
use tax_engine::TaxAssessment;

pub mod error;

pub use error::BridgeError;

/// Returns `Some(amount)` when non-zero, `None` otherwise.
///
/// The execution-preview contract rejects zero-valued cost components, so the
/// bridge must never emit `Some(0)` for a zero pool fee or zero tax.
#[inline]
fn nonzero(amount: AssetAmount) -> Option<AssetAmount> {
    if amount.amount.is_zero() {
        None
    } else {
        Some(amount)
    }
}

/// Exact normalized net balance delta for a single simulated swap.
///
/// All fields are denominated as documented on each field. Build the value
/// through one of the `from_*` constructors, which validate exact conservation
/// before returning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetDelta {
    /// Input asset of the simulated swap.
    pub token_in: AssetId,
    /// Output asset of the simulated swap.
    pub token_out: AssetId,
    /// Full wallet debit in `token_in`, including any sell-side input tax.
    pub net_input: AssetAmount,
    /// Gross simulated output in `token_out`, before any output tax.
    pub gross_output: AssetAmount,
    /// Net simulated output in `token_out`, after any output tax.
    pub net_output: AssetAmount,
    /// Input-side pool fee in `token_in`; `None` when zero.
    pub dex_fee: Option<AssetAmount>,
    /// Tax cost; buy: `token_out`, sell: `token_in`; `None` when zero.
    pub tax_cost: Option<AssetAmount>,
}

impl NetDelta {
    /// Normalizes a plain CPMM exact-input quote.
    pub fn from_cpmm(q: &CpmmSimulationQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.input.asset.clone(),
            token_out: q.output.asset.clone(),
            net_input: q.input.clone(),
            gross_output: q.output.clone(),
            net_output: q.output.clone(),
            dex_fee: nonzero(q.pool_fee.clone()),
            tax_cost: None,
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a plain CLMM exact-input quote.
    pub fn from_clmm(q: &ClmmSimulationQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.input.asset.clone(),
            token_out: q.output.asset.clone(),
            net_input: q.input.clone(),
            gross_output: q.output.clone(),
            net_output: q.output.clone(),
            dex_fee: nonzero(q.fee.clone()),
            tax_cost: None,
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a plain Bin/DLMM exact-input quote.
    pub fn from_bin(q: &BinSimulationQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.input.asset.clone(),
            token_out: q.output.asset.clone(),
            net_input: q.input.clone(),
            gross_output: q.output.clone(),
            net_output: q.output.clone(),
            dex_fee: nonzero(q.fee.clone()),
            tax_cost: None,
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a tax-aware CPMM buy composition (output-side tax).
    pub fn from_tax_aware_cpmm_buy(q: &TaxAwareCpmmBuyQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.cpmm_quote.input.asset.clone(),
            token_out: q.tax_output.gross_output.asset.clone(),
            net_input: q.cpmm_quote.input.clone(),
            gross_output: q.tax_output.gross_output.clone(),
            net_output: q.tax_output.net_output.clone(),
            dex_fee: nonzero(q.cpmm_quote.pool_fee.clone()),
            tax_cost: nonzero(q.tax_output.tax_cost.clone()),
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a tax-aware CPMM sell composition (input-side tax before swap).
    pub fn from_tax_aware_cpmm_sell(q: &TaxAwareCpmmSellQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.tax_input.gross_input.asset.clone(),
            token_out: q.cpmm_quote.output.asset.clone(),
            net_input: q.tax_input.gross_input.clone(),
            gross_output: q.cpmm_quote.output.clone(),
            net_output: q.cpmm_quote.output.clone(),
            dex_fee: nonzero(q.cpmm_quote.pool_fee.clone()),
            tax_cost: nonzero(q.tax_input.tax_cost.clone()),
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a tax-aware CLMM buy composition (output-side tax).
    pub fn from_tax_aware_clmm_buy(q: &TaxAwareClmmBuyQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.clmm_quote.input.asset.clone(),
            token_out: q.tax_output.gross_output.asset.clone(),
            net_input: q.clmm_quote.input.clone(),
            gross_output: q.tax_output.gross_output.clone(),
            net_output: q.tax_output.net_output.clone(),
            dex_fee: nonzero(q.clmm_quote.fee.clone()),
            tax_cost: nonzero(q.tax_output.tax_cost.clone()),
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Normalizes a tax-aware CLMM sell composition (input-side tax before swap).
    pub fn from_tax_aware_clmm_sell(q: &TaxAwareClmmSellQuote) -> Result<Self, BridgeError> {
        let delta = Self {
            token_in: q.tax_input.gross_input.asset.clone(),
            token_out: q.clmm_quote.output.asset.clone(),
            net_input: q.tax_input.gross_input.clone(),
            gross_output: q.clmm_quote.output.clone(),
            net_output: q.clmm_quote.output.clone(),
            dex_fee: nonzero(q.clmm_quote.fee.clone()),
            tax_cost: nonzero(q.tax_input.tax_cost.clone()),
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Validates exact denomination and conservation invariants fail-closed.
    ///
    /// Rules:
    /// - `token_in != token_out` and both share one chain.
    /// - Every amount is non-zero and bound to its documented asset.
    /// - `net_output <= gross_output`.
    /// - Output-denominated tax (buy) satisfies
    ///   `net_output + tax_cost == gross_output`; input-denominated tax (sell)
    ///   satisfies `net_output == gross_output`.
    /// - A present fee/tax is non-zero, shares the pair chain, and is
    ///   denominated in `token_in` or `token_out`.
    /// - Input-side conservation holds: `dex_fee <= net_input`, and for a sell
    ///   `tax_cost <= net_input` with `net_input - tax_cost >= dex_fee`.
    pub fn validate(&self) -> Result<(), BridgeError> {
        if self.token_in == self.token_out {
            return Err(BridgeError::NetDeltaInconsistent(
                "token_in and token_out must differ",
            ));
        }
        if self.token_in.chain != self.token_out.chain {
            return Err(BridgeError::NetDeltaInconsistent(
                "token_in and token_out must share a chain",
            ));
        }
        if self.net_input.asset != self.token_in {
            return Err(BridgeError::NetDeltaInconsistent(
                "net_input must be denominated in token_in",
            ));
        }
        if self.gross_output.asset != self.token_out {
            return Err(BridgeError::NetDeltaInconsistent(
                "gross_output must be denominated in token_out",
            ));
        }
        if self.net_output.asset != self.token_out {
            return Err(BridgeError::NetDeltaInconsistent(
                "net_output must be denominated in token_out",
            ));
        }
        if self.net_input.amount.is_zero() {
            return Err(BridgeError::NetDeltaInconsistent(
                "net_input must be non-zero",
            ));
        }
        if self.gross_output.amount.is_zero() {
            return Err(BridgeError::NetDeltaInconsistent(
                "gross_output must be non-zero",
            ));
        }
        if self.net_output.amount.is_zero() {
            return Err(BridgeError::NetDeltaInconsistent(
                "net_output must be non-zero",
            ));
        }
        if self.net_output.amount > self.gross_output.amount {
            return Err(BridgeError::NetDeltaInconsistent(
                "net_output must not exceed gross_output",
            ));
        }

        if let Some(fee) = &self.dex_fee {
            if fee.amount.is_zero() {
                return Err(BridgeError::NetDeltaInconsistent(
                    "dex_fee must be non-zero when present",
                ));
            }
            if fee.asset.chain != self.token_in.chain {
                return Err(BridgeError::NetDeltaInconsistent(
                    "dex_fee must share the pair chain",
                ));
            }
            if fee.asset != self.token_in && fee.asset != self.token_out {
                return Err(BridgeError::NetDeltaInconsistent(
                    "dex_fee must be denominated in token_in or token_out",
                ));
            }
            if fee.amount > self.net_input.amount {
                return Err(BridgeError::NetDeltaInconsistent(
                    "dex_fee must not exceed net_input",
                ));
            }
        }

        match &self.tax_cost {
            Some(tax) => {
                if tax.amount.is_zero() {
                    return Err(BridgeError::NetDeltaInconsistent(
                        "tax_cost must be non-zero when present",
                    ));
                }
                if tax.asset.chain != self.token_in.chain {
                    return Err(BridgeError::NetDeltaInconsistent(
                        "tax_cost must share the pair chain",
                    ));
                }
                if tax.asset == self.token_out {
                    // Buy side: output tax is deducted from gross output.
                    let total = self
                        .net_output
                        .amount
                        .get()
                        .checked_add(tax.amount.get())
                        .ok_or(BridgeError::NetDeltaInconsistent(
                            "net_output and tax_cost overflow u128",
                        ))?;
                    if total != self.gross_output.amount.get() {
                        return Err(BridgeError::NetDeltaInconsistent(
                            "net_output plus tax_cost must equal gross_output",
                        ));
                    }
                } else if tax.asset == self.token_in {
                    // Sell side: input tax is deducted before the pool swap.
                    if self.net_output.amount != self.gross_output.amount {
                        return Err(BridgeError::NetDeltaInconsistent(
                            "net_output must equal gross_output for sell-side input tax",
                        ));
                    }
                    if tax.amount > self.net_input.amount {
                        return Err(BridgeError::NetDeltaInconsistent(
                            "tax_cost must not exceed net_input",
                        ));
                    }
                    let pool_input = self
                        .net_input
                        .amount
                        .get()
                        .checked_sub(tax.amount.get())
                        .ok_or(BridgeError::NetDeltaInconsistent(
                            "tax_cost must not exceed net_input",
                        ))?;
                    let fee = self.dex_fee.as_ref().map(|f| f.amount.get()).unwrap_or(0);
                    if pool_input < fee {
                        return Err(BridgeError::NetDeltaInconsistent(
                            "net_input after tax must cover dex_fee",
                        ));
                    }
                } else {
                    return Err(BridgeError::NetDeltaInconsistent(
                        "tax_cost must be denominated in token_in or token_out",
                    ));
                }
            }
            None => {
                if self.net_output.amount != self.gross_output.amount {
                    return Err(BridgeError::NetDeltaInconsistent(
                        "net_output must equal gross_output when no tax is present",
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Builds an [`ExecutionPreview`] from a validated net delta and an explicit
/// local-state freshness classification.
///
/// The delta is validated and bound to the intent's chain and asset pair
/// fail-closed before any preview fields are produced.
pub fn build_execution_preview(
    intent: &TradeIntent,
    delta: &NetDelta,
    local_state_freshness: FreshnessStatus,
) -> Result<ExecutionPreview, BridgeError> {
    delta.validate()?;

    if delta.token_in.chain != intent.chain || delta.token_out.chain != intent.chain {
        return Err(BridgeError::ChainMismatch);
    }
    if delta.token_in != intent.token_in {
        return Err(BridgeError::InputAssetMismatch);
    }
    if delta.token_out != intent.token_out {
        return Err(BridgeError::OutputAssetMismatch);
    }

    Ok(ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: intent.chain.clone(),
        token_in: delta.token_in.clone(),
        token_out: delta.token_out.clone(),
        side: intent.side,
        simulated_net_input: delta.net_input.clone(),
        simulated_net_output: delta.net_output.clone(),
        gross_output: delta.gross_output.clone(),
        cost_components: ExecutionCostComponents {
            gas_cost: None,
            dex_fee: delta.dex_fee.clone(),
            provider_fee: None,
            tax_cost: delta.tax_cost.clone(),
        },
        local_state_freshness,
    })
}

/// Validates a net delta against an intent and caller-supplied route.
///
/// Local-state freshness is derived deterministically from `route.state` using
/// [`FreshnessPolicy::default()`] before the locked
/// [`ExecutionPreview::validate`] contract is invoked. An unvalidated preview is
/// never returned.
pub fn validate_delta_preview(
    intent: &TradeIntent,
    route: &RoutePlan,
    delta: &NetDelta,
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, BridgeError> {
    let local_state_freshness = evaluate_freshness(
        &FreshnessPolicy::default(),
        route.state.observed_at_ms,
        now_ms,
        route.state.sequence,
        false,
    )
    .map_err(|_| BridgeError::FreshnessUnavailable)?
    .status;

    let preview = build_execution_preview(intent, delta, local_state_freshness)?;
    let validated = preview.validate(intent, route, now_ms)?;
    Ok(validated)
}

/// Validates a net delta against an intent, route, and tax assessment.
///
/// In addition to [`validate_delta_preview`], this enforces the intent tax caps
/// that the raw tax arithmetic does not apply: the assessment chain must match
/// the intent chain, the assessed asset must bind to `token_out` for a buy and
/// `token_in` for a sell, and the assessed tax must not exceed the intent's
/// corresponding risk cap.
pub fn validate_delta_preview_with_assessment(
    intent: &TradeIntent,
    route: &RoutePlan,
    delta: &NetDelta,
    assessment: &TaxAssessment,
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, BridgeError> {
    if assessment.chain != intent.chain {
        return Err(BridgeError::ChainMismatch);
    }
    match intent.side {
        TradeSide::Buy => {
            if assessment.assessed_asset != intent.token_out {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            if assessment.buy_tax > intent.risk.max_buy_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
        TradeSide::Sell => {
            if assessment.assessed_asset != intent.token_in {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            if assessment.sell_tax > intent.risk.max_sell_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
    }

    validate_delta_preview(intent, route, delta, now_ms)
}
