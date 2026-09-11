//! Pure, deterministic tax and safety evaluation kernel.

use chain_types::{AssetId, ChainId};
use domain::{TaxObservation, TradeIntent, TradeSide};
use market_types::{
    evaluate_freshness, Bps, FreshnessPolicy, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use serde::{Deserialize, Serialize};

use crate::error::TaxSafetyError;

/// Structured local tax safety assessment result.
///
/// Contains verified tax parameters and freshness metadata needed by downstream
/// route economics. Does NOT contain fabricated tax amounts, gas estimates, quotes,
/// execution previews, or transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxAssessment {
    /// The specific token asset evaluated (`token_out` for Buy, `token_in` for Sell).
    pub assessed_asset: AssetId,
    /// Chain ID where the assessment applies.
    pub chain: ChainId,
    /// Observed buy tax in basis points.
    pub buy_tax: Bps,
    /// Observed sell tax in basis points.
    pub sell_tax: Bps,
    /// Preserved deterministic freshness evaluation result.
    pub freshness: SafeFreshnessMeta,
    /// Block or slot number associated with the tax observation.
    pub block_or_slot: u64,
}

impl TaxAssessment {
    /// Creates a new tax assessment record.
    pub fn new(
        assessed_asset: AssetId,
        chain: ChainId,
        buy_tax: Bps,
        sell_tax: Bps,
        freshness: SafeFreshnessMeta,
        block_or_slot: u64,
    ) -> Self {
        Self {
            assessed_asset,
            chain,
            buy_tax,
            sell_tax,
            freshness,
            block_or_slot,
        }
    }

    /// The evaluated token asset.
    pub fn assessed_asset(&self) -> &AssetId {
        &self.assessed_asset
    }

    /// The chain ID for this assessment.
    pub fn chain(&self) -> ChainId {
        self.chain.clone()
    }

    /// The assessed buy tax in basis points.
    pub fn buy_tax(&self) -> Bps {
        self.buy_tax
    }

    /// The assessed sell tax in basis points.
    pub fn sell_tax(&self) -> Bps {
        self.sell_tax
    }

    /// The preserved deterministic freshness metadata.
    pub fn freshness(&self) -> &SafeFreshnessMeta {
        &self.freshness
    }

    /// The observed block or slot number.
    pub fn block_or_slot(&self) -> u64 {
        self.block_or_slot
    }

    /// Returns `true` if both buy and sell taxes are zero basis points.
    pub fn is_zero_tax(&self) -> bool {
        self.buy_tax.get() == 0 && self.sell_tax.get() == 0
    }

    /// Applies this buy-side assessment to a gross output amount.
    pub fn apply_buy_tax(
        &self,
        gross_output: &market_types::AssetAmount,
    ) -> Result<crate::buy_output::BuyTaxOutput, TaxSafetyError> {
        crate::buy_output::apply_buy_tax_to_output(self, gross_output)
    }
}

/// Returns the expected assessed asset for a trade intent:
/// - `token_out` for Buy intents (the asset being acquired);
/// - `token_in` for Sell intents (the asset being disposed).
pub fn assessed_asset_for_intent(intent: &TradeIntent) -> &AssetId {
    match intent.side {
        TradeSide::Buy => &intent.token_out,
        TradeSide::Sell => &intent.token_in,
    }
}

/// Evaluates a trade intent against an optional tax observation.
///
/// All timing parameters are caller-provided and deterministic; no wall clock
/// or external systems are queried.
///
/// # Validation Rules
/// 1. Validates the `TradeIntent` and supplied `TaxObservation` using their landed
///    validation contracts.
/// 2. A missing observation fails closed with [`TaxSafetyError::MissingObservation`].
/// 3. Binds the observation to the intent chain and to the asset actually being assessed:
///    `token_out` for Buy intents, `token_in` for Sell intents. Mismatch fails closed.
/// 4. Evaluates `observation.observed_at_ms` with caller-provided `evaluation_time_ms`
///    and `freshness_policy`. Accepts only `Fresh`; stale, excessive future-skew, or
///    resync-required status fails closed. The freshness metadata is preserved in the
///    returned [`TaxAssessment`].
/// 5. Requires `buy_succeeds`, `sell_succeeds`, and `sellable` all to be `true`. Any `false`
///    value fails closed.
/// 6. Requires `buy_tax <= intent.risk.max_buy_tax` AND `sell_tax <= intent.risk.max_sell_tax`
///    (equality permitted). Both sides are strictly checked regardless of trade direction.
/// 7. Returns only structured local data needed by route economics without fabricating
///    tax amounts, gas estimates, quotes, previews, or transactions.
pub fn evaluate_tax_safety(
    intent: &TradeIntent,
    observation: Option<&TaxObservation>,
    evaluation_time_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<TaxAssessment, TaxSafetyError> {
    // 1. Validate the TradeIntent using its landed contract
    intent
        .validate(evaluation_time_ms)
        .map_err(TaxSafetyError::InvalidTradeIntent)?;

    // 2. Missing observation fails closed
    let obs = observation.ok_or(TaxSafetyError::MissingObservation)?;

    // Validate the TaxObservation using its landed contract
    obs.validate()
        .map_err(TaxSafetyError::InvalidTaxObservation)?;

    // 3. Bind observation to intent chain
    if obs.chain != intent.chain {
        return Err(TaxSafetyError::ChainMismatch);
    }

    // Bind observation to the asset actually being assessed
    let assessed_asset = assessed_asset_for_intent(intent);
    if obs.token != *assessed_asset {
        return Err(TaxSafetyError::AssessedAssetMismatch);
    }

    // 4. Deterministic freshness evaluation
    let freshness_meta = evaluate_freshness(
        freshness_policy,
        obs.observed_at_ms,
        evaluation_time_ms,
        Sequence::new(obs.block_or_slot),
        false,
    )
    .map_err(|_| TaxSafetyError::FreshnessEvaluationFailed)?;

    match freshness_meta.status {
        FreshnessStatus::Fresh => {}
        FreshnessStatus::Stale => return Err(TaxSafetyError::StaleObservation),
        FreshnessStatus::ResyncRequired => return Err(TaxSafetyError::ResyncRequired),
    }

    // 5. Require buy_succeeds, sellable, and sell_succeeds all true
    if !obs.buy_succeeds {
        return Err(TaxSafetyError::BuySimulationFailed);
    }
    if !obs.sellable {
        return Err(TaxSafetyError::TokenNotSellable);
    }
    if !obs.sell_succeeds {
        return Err(TaxSafetyError::SellSimulationFailed);
    }

    // 6. Enforce tax caps: buy_tax <= max_buy_tax && sell_tax <= max_sell_tax
    if obs.buy_tax > intent.risk.max_buy_tax {
        return Err(TaxSafetyError::BuyTaxExceedsCap);
    }
    if obs.sell_tax > intent.risk.max_sell_tax {
        return Err(TaxSafetyError::SellTaxExceedsCap);
    }

    // 7. Structured local result only
    Ok(TaxAssessment {
        assessed_asset: assessed_asset.clone(),
        chain: intent.chain.clone(),
        buy_tax: obs.buy_tax,
        sell_tax: obs.sell_tax,
        freshness: freshness_meta,
        block_or_slot: obs.block_or_slot,
    })
}

/// Convenience alias for [`evaluate_tax_safety`].
pub fn assess_tax_safety(
    intent: &TradeIntent,
    observation: Option<&TaxObservation>,
    evaluation_time_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<TaxAssessment, TaxSafetyError> {
    evaluate_tax_safety(intent, observation, evaluation_time_ms, freshness_policy)
}

/// Stateless evaluator struct providing namespace convenience.
pub struct TaxSafetyEngine;

impl TaxSafetyEngine {
    /// Evaluates a trade intent against an optional tax observation.
    pub fn evaluate(
        intent: &TradeIntent,
        observation: Option<&TaxObservation>,
        evaluation_time_ms: i64,
        freshness_policy: &FreshnessPolicy,
    ) -> Result<TaxAssessment, TaxSafetyError> {
        evaluate_tax_safety(intent, observation, evaluation_time_ms, freshness_policy)
    }

    /// Applies a buy-side assessment to a gross output amount.
    pub fn apply_buy_tax(
        assessment: &TaxAssessment,
        gross_output: &market_types::AssetAmount,
    ) -> Result<crate::buy_output::BuyTaxOutput, TaxSafetyError> {
        crate::buy_output::apply_buy_tax_to_output(assessment, gross_output)
    }

    /// Applies a buy-side assessment to a gross output amount.
    pub fn apply_buy_tax_to_output(
        assessment: &TaxAssessment,
        gross_output: &market_types::AssetAmount,
    ) -> Result<crate::buy_output::BuyTaxOutput, TaxSafetyError> {
        crate::buy_output::apply_buy_tax_to_output(assessment, gross_output)
    }
}
