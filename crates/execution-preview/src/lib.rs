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
    ExecutionCostComponents, ExecutionPreview, RoutePlan, SplitPlan, TradeIntent, TradeSide,
    ValidatedExecutionPreview,
};
use market_types::{
    evaluate_freshness, AssetAmount, AtomicAmount, FreshnessPolicy, FreshnessStatus,
};
use serde::{Deserialize, Serialize};
use simulation::{
    BinSimulationQuote, ClmmSimulationQuote, CpmmSimulationQuote, TaxAwareClmmBuyQuote,
    TaxAwareClmmSellQuote, TaxAwareCpmmBuyQuote, TaxAwareCpmmSellQuote,
};
use tax_engine::TaxAssessment;

pub mod error;
pub mod revalidation;

pub use error::BridgeError;
pub use revalidation::{
    revalidate_pre_sign, revalidate_split_pre_sign, AllowanceObservation, AllowanceState,
    RevalidationInput, RevalidationOutcome, RevalidationReason, RouteBinding, RouteLegRef,
    SplitLegRef, SplitRevalidationInput, SplitRouteBinding, WalletBalance,
};

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

/// Exact `floor(amount * bps / 10_000)` using the same `q`/`r` decomposition as
/// the tax engine, so it cannot overflow for any `u128` amount and any `Bps`.
///
/// For `amount = q * 10_000 + r`:
/// `floor(amount * bps / 10_000) = q * bps + floor(r * bps / 10_000)`.
/// Since `q <= u128::MAX / 10_000` and `bps <= 10_000`, `q * bps <= amount`;
/// since `r < 10_000`, `r * bps < 100_000_000`. No intermediate overflows.
fn floor_bps(amount: u128, bps: u16) -> Result<u128, BridgeError> {
    debug_assert!(bps <= 10_000, "Bps is bounded by construction");
    let bps = bps as u128;
    let q = amount / 10_000;
    let r = amount % 10_000;
    let q_part = q.checked_mul(bps).ok_or(BridgeError::NetDeltaInconsistent(
        "tax amount overflowed u128",
    ))?;
    let r_part = r.checked_mul(bps).ok_or(BridgeError::NetDeltaInconsistent(
        "tax amount overflowed u128",
    ))? / 10_000;
    q_part
        .checked_add(r_part)
        .ok_or(BridgeError::NetDeltaInconsistent(
            "tax amount overflowed u128",
        ))
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
    /// - A present fee/tax is non-zero. `dex_fee` is always denominated in
    ///   `token_in`; `tax_cost` is denominated in `token_in` or `token_out`.
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
            if fee.asset != self.token_in {
                return Err(BridgeError::NetDeltaInconsistent(
                    "dex_fee must be denominated in token_in",
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
                if tax.asset != self.token_in && tax.asset != self.token_out {
                    return Err(BridgeError::NetDeltaInconsistent(
                        "tax_cost must be denominated in token_in or token_out",
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
                } else {
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

    /// Aggregates per-branch exact net deltas into one wallet-level delta.
    ///
    /// Fail-closed: every input delta is independently validated; all branches
    /// must share one `(token_in, token_out)` pair and one tax denomination;
    /// every sum is checked; zero fee/tax stays `None` (never `Some(0)`).
    pub fn aggregate(deltas: &[NetDelta]) -> Result<NetDelta, BridgeError> {
        let first = deltas.first().ok_or(BridgeError::NetDeltaInconsistent(
            "split requires at least one net delta",
        ))?;
        let token_in = first.token_in.clone();
        let token_out = first.token_out.clone();

        let mut net_input: u128 = 0;
        let mut gross_output: u128 = 0;
        let mut net_output: u128 = 0;
        let mut dex_fee: u128 = 0;
        let mut tax_total: u128 = 0;
        let mut tax_asset: Option<AssetId> = None;

        for delta in deltas {
            delta.validate()?;
            if delta.token_in != token_in || delta.token_out != token_out {
                return Err(BridgeError::NetDeltaInconsistent(
                    "split deltas must share one token pair",
                ));
            }
            net_input = net_input.checked_add(delta.net_input.amount.get()).ok_or(
                BridgeError::NetDeltaInconsistent("split net_input sum overflowed u128"),
            )?;
            gross_output = gross_output
                .checked_add(delta.gross_output.amount.get())
                .ok_or(BridgeError::NetDeltaInconsistent(
                    "split gross_output sum overflowed u128",
                ))?;
            net_output = net_output
                .checked_add(delta.net_output.amount.get())
                .ok_or(BridgeError::NetDeltaInconsistent(
                    "split net_output sum overflowed u128",
                ))?;
            if let Some(fee) = &delta.dex_fee {
                // `validate` already guarantees fee.asset == token_in.
                dex_fee = dex_fee.checked_add(fee.amount.get()).ok_or(
                    BridgeError::NetDeltaInconsistent("split dex_fee sum overflowed u128"),
                )?;
            }
            if let Some(tax) = &delta.tax_cost {
                match &tax_asset {
                    Some(asset) if *asset != tax.asset => {
                        return Err(BridgeError::NetDeltaInconsistent(
                            "split deltas mix tax denominations",
                        ));
                    }
                    Some(_) => {}
                    None => tax_asset = Some(tax.asset.clone()),
                }
                tax_total = tax_total.checked_add(tax.amount.get()).ok_or(
                    BridgeError::NetDeltaInconsistent("split tax_cost sum overflowed u128"),
                )?;
            }
        }

        let aggregate = NetDelta {
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            net_input: AssetAmount {
                asset: token_in.clone(),
                amount: AtomicAmount::new(net_input),
            },
            gross_output: AssetAmount {
                asset: token_out.clone(),
                amount: AtomicAmount::new(gross_output),
            },
            net_output: AssetAmount {
                asset: token_out,
                amount: AtomicAmount::new(net_output),
            },
            dex_fee: if dex_fee == 0 {
                None
            } else {
                Some(AssetAmount {
                    asset: token_in,
                    amount: AtomicAmount::new(dex_fee),
                })
            },
            tax_cost: tax_asset.map(|asset| AssetAmount {
                asset,
                amount: AtomicAmount::new(tax_total),
            }),
        };
        aggregate.validate()?;
        Ok(aggregate)
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

    // The tax denomination must agree with the intent direction: a buy pays
    // output-side tax in `token_out`, a sell pays input-side tax in `token_in`.
    if let Some(tax) = &delta.tax_cost {
        let expected_asset = match intent.side {
            TradeSide::Buy => &delta.token_out,
            TradeSide::Sell => &delta.token_in,
        };
        if tax.asset != *expected_asset {
            return Err(BridgeError::DirectionMismatch);
        }
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
/// In addition to [`validate_delta_preview`], this binds the caller-supplied
/// assessment to the *realized* delta before applying the intent tax caps:
/// - The assessment must be [`FreshnessStatus::Fresh`].
/// - The assessment chain must match the intent chain and the assessed asset
///   must bind to `token_out` for a buy and `token_in` for a sell.
/// - The tax implied by the assessment over the realized delta must equal
///   `delta.tax_cost` exactly (buy: output-side tax over `gross_output`; sell:
///   input-side tax over `net_input`), otherwise the assessment is not a valid
///   explanation of the delta.
/// - Finally the assessed tax must not exceed the intent's corresponding risk cap.
pub fn validate_delta_preview_with_assessment(
    intent: &TradeIntent,
    route: &RoutePlan,
    delta: &NetDelta,
    assessment: &TaxAssessment,
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, BridgeError> {
    if assessment.freshness.status != FreshnessStatus::Fresh {
        return Err(BridgeError::FreshnessUnavailable);
    }
    if assessment.chain != intent.chain {
        return Err(BridgeError::ChainMismatch);
    }

    match intent.side {
        TradeSide::Buy => {
            if assessment.assessed_asset != intent.token_out {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            // Buy tax is output-side over the realized gross output.
            let expected = floor_bps(delta.gross_output.amount.get(), assessment.buy_tax.get())?;
            let expected_cost = if expected == 0 {
                None
            } else {
                Some(AssetAmount {
                    asset: intent.token_out.clone(),
                    amount: AtomicAmount::new(expected),
                })
            };
            if delta.tax_cost != expected_cost {
                return Err(BridgeError::AssessmentDeltaMismatch);
            }
            if assessment.buy_tax > intent.risk.max_buy_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
        TradeSide::Sell => {
            if assessment.assessed_asset != intent.token_in {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            // Sell tax is input-side over the full realized wallet debit.
            let expected = floor_bps(delta.net_input.amount.get(), assessment.sell_tax.get())?;
            let expected_cost = if expected == 0 {
                None
            } else {
                Some(AssetAmount {
                    asset: intent.token_in.clone(),
                    amount: AtomicAmount::new(expected),
                })
            };
            if delta.tax_cost != expected_cost {
                return Err(BridgeError::AssessmentDeltaMismatch);
            }
            if assessment.sell_tax > intent.risk.max_sell_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
    }

    validate_delta_preview(intent, route, delta, now_ms)
}

/// Aggregate split bridge: aggregates exact branch deltas, derives freshness from
/// the split state, builds one aggregate [`ExecutionPreview`], and runs the locked
/// split validator. `Valid` is reachable only through domain validation.
pub fn validate_split_delta_preview(
    intent: &TradeIntent,
    split: &SplitPlan,
    branch_deltas: &[NetDelta],
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, BridgeError> {
    if branch_deltas.len() != split.legs.len() {
        return Err(BridgeError::NetDeltaInconsistent(
            "split requires one branch delta per leg",
        ));
    }
    let aggregate = NetDelta::aggregate(branch_deltas)?;
    let local = evaluate_freshness(
        &FreshnessPolicy::default(),
        split.state.observed_at_ms,
        now_ms,
        split.state.sequence,
        false,
    )
    .map_err(|_| BridgeError::FreshnessUnavailable)?
    .status;
    let preview = build_execution_preview(intent, &aggregate, local)?;
    let validated = preview.validate_split(intent, split, now_ms)?;
    Ok(validated)
}

/// Validates an aggregate split delta against an intent, split plan, and a
/// single fresh tax assessment applied to every branch.
///
/// In addition to [`validate_split_delta_preview`], this binds the assessment to
/// every realized branch delta (buy: output-side tax over each branch's gross
/// output; sell: input-side tax over each branch's net input) before the intent
/// tax caps and the locked split validation run. One unassessed branch is enough
/// to reject the whole split.
pub fn validate_split_delta_preview_with_assessment(
    intent: &TradeIntent,
    split: &SplitPlan,
    branch_deltas: &[NetDelta],
    assessment: &TaxAssessment,
    now_ms: i64,
) -> Result<ValidatedExecutionPreview, BridgeError> {
    if assessment.freshness.status != FreshnessStatus::Fresh {
        return Err(BridgeError::FreshnessUnavailable);
    }
    if assessment.chain != intent.chain {
        return Err(BridgeError::ChainMismatch);
    }
    if branch_deltas.len() != split.legs.len() {
        return Err(BridgeError::NetDeltaInconsistent(
            "split requires one branch delta per leg",
        ));
    }

    match intent.side {
        TradeSide::Buy => {
            if assessment.assessed_asset != intent.token_out {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            for delta in branch_deltas {
                let expected =
                    floor_bps(delta.gross_output.amount.get(), assessment.buy_tax.get())?;
                let expected_cost = if expected == 0 {
                    None
                } else {
                    Some(AssetAmount {
                        asset: intent.token_out.clone(),
                        amount: AtomicAmount::new(expected),
                    })
                };
                if delta.tax_cost != expected_cost {
                    return Err(BridgeError::AssessmentDeltaMismatch);
                }
            }
            if assessment.buy_tax > intent.risk.max_buy_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
        TradeSide::Sell => {
            if assessment.assessed_asset != intent.token_in {
                return Err(BridgeError::AssessedAssetMismatch);
            }
            for delta in branch_deltas {
                let expected = floor_bps(delta.net_input.amount.get(), assessment.sell_tax.get())?;
                let expected_cost = if expected == 0 {
                    None
                } else {
                    Some(AssetAmount {
                        asset: intent.token_in.clone(),
                        amount: AtomicAmount::new(expected),
                    })
                };
                if delta.tax_cost != expected_cost {
                    return Err(BridgeError::AssessmentDeltaMismatch);
                }
            }
            if assessment.sell_tax > intent.risk.max_sell_tax {
                return Err(BridgeError::TaxCapExceeded);
            }
        }
    }

    validate_split_delta_preview(intent, split, branch_deltas, now_ms)
}
