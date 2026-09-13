//! Pure, deterministic single-hop leg simulation with exact tax composition.
//!
//! All pool state is injected; there is no RPC, network, wall clock, or
//! randomness. Freshness is evaluated against the caller-supplied `now_ms` and
//! [`FreshnessPolicy`]. Integer arithmetic is exact and every composition step
//! is checked for conservation.

use std::cmp::Ordering;

use chain_types::AssetId;
use domain::{DomainError, TradeIntent, TradeSide};
use market_types::{
    evaluate_freshness, AssetAmount, AtomicAmount, BinPoolState, Bps, ClmmPoolState, CpmmPoolState,
    Freshness, FreshnessPolicy, FreshnessStatus, PoolKindState,
};
use simulation::{
    cmp_u128_products, simulate_bin_exact_input, simulate_clmm_exact_input,
    simulate_cpmm_exact_input, simulate_tax_aware_clmm_buy_exact_input,
    simulate_tax_aware_clmm_sell_exact_input, simulate_tax_aware_cpmm_buy_exact_input,
    simulate_tax_aware_cpmm_sell_exact_input, BinExactInputRequest, BinSimulationError,
    ClmmExactInputRequest, ClmmSimulationError, CpmmExactInputRequest, CpmmSimulationErrorClass,
    TaxAwareClmmSimulationError, TaxAwareSimulationError,
};
use tax_engine::{
    apply_buy_tax_to_output, apply_sell_tax_to_input, assessed_asset_for_intent, TaxAssessment,
    TaxSafetyError,
};

use crate::error::RoutingError;
use crate::types::{EvaluatedLeg, PoolCandidate, SwapDir};

/// Internal, un-denominated leg economics prior to asset tagging.
struct RawLeg {
    /// Exact amount the swap kernel consumed (`token_in`).
    actual_in: AtomicAmount,
    /// Pre-output-tax pool output (`token_out`).
    gross_output: AtomicAmount,
    /// Post-tax output delivered by the leg (`token_out`).
    net_output: AtomicAmount,
    /// Input-side pool fee.
    dex_fee: AtomicAmount,
    /// Assessed tax (output-side for Buy, input-side for Sell).
    tax_cost: AtomicAmount,
}

/// Simulates a single direct leg for a candidate against the supplied intent.
///
/// Validates the pool state, chain binding, and freshness, then composes the
/// appropriate CPMM/CLMM/Bin kernel with exact tax handling. The `amount_in` is
/// the full gross amount supplied by the intent; sell-side tax is applied before
/// the swap and buy-side tax after it.
///
/// The signature extends the slice sketch with `freshness_policy` and `now_ms`
/// because deterministic freshness validation requires both.
pub fn simulate_leg(
    candidate: &PoolCandidate,
    intent: &TradeIntent,
    amount_in: AtomicAmount,
    tax: Option<&TaxAssessment>,
    freshness_policy: &FreshnessPolicy,
    now_ms: i64,
) -> Result<EvaluatedLeg, RoutingError> {
    // Bind the simulated input to the intent exactly. Sell-side tax is checked
    // separately through input conservation, but a Buy leg previously consumed
    // whatever `amount_in` the caller supplied, so this closes that gap
    // symmetrically for every side.
    if amount_in != intent.amount {
        return Err(RoutingError::InputConservationViolated);
    }

    validate_state(&candidate.state)?;

    if candidate.state.token_0().chain != intent.chain
        || candidate.state.token_1().chain != intent.chain
    {
        return Err(RoutingError::Domain(DomainError::ChainMismatch));
    }

    check_freshness(&candidate.freshness, freshness_policy, now_ms)?;

    let dir = swap_dir(&candidate.state, &intent.token_in)?;
    let expected_out = match dir {
        SwapDir::ZeroForOne => candidate.state.token_1(),
        SwapDir::OneForZero => candidate.state.token_0(),
    };
    if expected_out != &intent.token_out {
        return Err(output_asset_mismatch(&candidate.state));
    }

    let bound_tax = match tax {
        Some(assessment) => {
            validate_tax_assessment(intent, assessment, freshness_policy, now_ms)?;
            Some(assessment)
        }
        None => None,
    };

    let raw = match &candidate.state {
        PoolKindState::Cpmm(pool) => simulate_cpmm(pool, intent, amount_in, bound_tax)?,
        PoolKindState::Clmm(pool) => simulate_clmm(pool, intent, amount_in, bound_tax)?,
        PoolKindState::Bin(pool) => simulate_bin(pool, intent, amount_in, bound_tax)?,
    };

    finish_leg(candidate, intent, raw)
}

/// Determines the pool swap direction for `token_in`.
pub fn swap_dir(state: &PoolKindState, token_in: &AssetId) -> Result<SwapDir, RoutingError> {
    if token_in == state.token_0() {
        Ok(SwapDir::ZeroForOne)
    } else if token_in == state.token_1() {
        Ok(SwapDir::OneForZero)
    } else {
        Err(direction_not_found(state))
    }
}

fn validate_state(state: &PoolKindState) -> Result<(), RoutingError> {
    state.validate().map_err(|_| match state {
        PoolKindState::Cpmm(_) => RoutingError::Cpmm(CpmmSimulationErrorClass::InvalidPoolState),
        PoolKindState::Clmm(_) => RoutingError::Clmm(ClmmSimulationError::InvalidPoolState),
        PoolKindState::Bin(_) => RoutingError::Bin(BinSimulationError::InvalidPoolState),
    })
}

fn direction_not_found(state: &PoolKindState) -> RoutingError {
    match state {
        PoolKindState::Cpmm(_) => RoutingError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool),
        PoolKindState::Clmm(_) => RoutingError::Clmm(ClmmSimulationError::InvalidAssetDirection),
        PoolKindState::Bin(_) => RoutingError::Bin(BinSimulationError::InvalidAssetDirection),
    }
}

fn output_asset_mismatch(state: &PoolKindState) -> RoutingError {
    match state {
        PoolKindState::Cpmm(_) => RoutingError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch),
        PoolKindState::Clmm(_) => RoutingError::Clmm(ClmmSimulationError::OutputAssetMismatch),
        PoolKindState::Bin(_) => RoutingError::Bin(BinSimulationError::OutputAssetMismatch),
    }
}

fn check_freshness(
    freshness: &Freshness,
    policy: &FreshnessPolicy,
    now_ms: i64,
) -> Result<(), RoutingError> {
    let meta = evaluate_freshness(
        policy,
        freshness.observed_at_ms,
        now_ms,
        freshness.sequence,
        false,
    )
    .map_err(|_| RoutingError::Internal("freshness evaluation failed"))?;

    match meta.status {
        FreshnessStatus::Fresh => Ok(()),
        FreshnessStatus::Stale => Err(RoutingError::StaleState),
        FreshnessStatus::ResyncRequired => Err(RoutingError::ResyncRequired),
    }
}

/// Validates a supplied tax assessment against the intent, its binding assets,
/// and the caller's freshness policy.
///
/// Binding: `chain` must equal the intent chain and `assessed_asset` must be
/// `token_out` for Buy intents / `token_in` for Sell intents.
///
/// Freshness: the preserved [`FreshnessStatus`] must be usable. Because
/// [`SafeFreshnessMeta`] exposes its `observed_at_ms`, the assessment is also
/// re-evaluated against `now_ms` with the caller's policy, so an assessment that
/// was fresh when it was computed cannot silently remain usable when the
/// planner's reference time is later.
pub(crate) fn validate_tax_assessment(
    intent: &TradeIntent,
    assessment: &TaxAssessment,
    freshness_policy: &FreshnessPolicy,
    now_ms: i64,
) -> Result<(), RoutingError> {
    if assessment.chain != intent.chain {
        return Err(RoutingError::Tax(TaxSafetyError::ChainMismatch));
    }
    if assessment.assessed_asset != *assessed_asset_for_intent(intent) {
        return Err(RoutingError::Tax(TaxSafetyError::AssessedAssetMismatch));
    }

    match assessment.freshness.status {
        FreshnessStatus::Fresh => {}
        FreshnessStatus::Stale => return Err(RoutingError::StaleState),
        FreshnessStatus::ResyncRequired => return Err(RoutingError::ResyncRequired),
    }

    let meta = evaluate_freshness(
        freshness_policy,
        assessment.freshness.observed_at_ms,
        now_ms,
        assessment.freshness.sequence,
        false,
    )
    .map_err(|_| RoutingError::Internal("tax freshness evaluation failed"))?;

    match meta.status {
        FreshnessStatus::Fresh => Ok(()),
        FreshnessStatus::Stale => Err(RoutingError::StaleState),
        FreshnessStatus::ResyncRequired => Err(RoutingError::ResyncRequired),
    }
}

fn side_tax(assessment: &TaxAssessment, side: TradeSide) -> Bps {
    match side {
        TradeSide::Buy => assessment.buy_tax,
        TradeSide::Sell => assessment.sell_tax,
    }
}

fn tax_is_active(assessment: &TaxAssessment, side: TradeSide) -> bool {
    side_tax(assessment, side).get() > 0
}

fn simulate_cpmm(
    pool: &CpmmPoolState,
    intent: &TradeIntent,
    amount_in: AtomicAmount,
    tax: Option<&TaxAssessment>,
) -> Result<RawLeg, RoutingError> {
    let request = CpmmExactInputRequest::new_directed(
        intent.token_in.clone(),
        amount_in,
        intent.token_out.clone(),
    );

    match (intent.side, tax) {
        (TradeSide::Buy, Some(assessment)) if tax_is_active(assessment, TradeSide::Buy) => {
            let quote = simulate_tax_aware_cpmm_buy_exact_input(pool, &request, assessment)
                .map_err(map_tax_aware_cpmm)?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: quote.tax_output.gross_output.amount,
                net_output: quote.tax_output.net_output.amount,
                dex_fee: quote.cpmm_quote.pool_fee.amount,
                tax_cost: quote.tax_output.tax_cost.amount,
            })
        }
        (TradeSide::Sell, Some(assessment)) if tax_is_active(assessment, TradeSide::Sell) => {
            let quote = simulate_tax_aware_cpmm_sell_exact_input(pool, &request, assessment)
                .map_err(map_tax_aware_cpmm)?;
            Ok(RawLeg {
                actual_in: quote.tax_input.net_transferable_input.amount,
                gross_output: quote.cpmm_quote.output.amount,
                net_output: quote.cpmm_quote.output.amount,
                dex_fee: quote.cpmm_quote.pool_fee.amount,
                tax_cost: quote.tax_input.tax_cost.amount,
            })
        }
        _ => {
            let quote = simulate_cpmm_exact_input(pool, &request)
                .map_err(|err| RoutingError::Cpmm(CpmmSimulationErrorClass::from(err)))?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: quote.output.amount,
                net_output: quote.output.amount,
                dex_fee: quote.pool_fee.amount,
                tax_cost: AtomicAmount::ZERO,
            })
        }
    }
}

fn simulate_clmm(
    pool: &ClmmPoolState,
    intent: &TradeIntent,
    amount_in: AtomicAmount,
    tax: Option<&TaxAssessment>,
) -> Result<RawLeg, RoutingError> {
    let request = ClmmExactInputRequest {
        token_in: intent.token_in.clone(),
        amount_in,
        token_out: Some(intent.token_out.clone()),
    };

    match (intent.side, tax) {
        (TradeSide::Buy, Some(assessment)) if tax_is_active(assessment, TradeSide::Buy) => {
            let quote = simulate_tax_aware_clmm_buy_exact_input(pool, &request, assessment)
                .map_err(map_tax_aware_clmm)?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: quote.tax_output.gross_output.amount,
                net_output: quote.tax_output.net_output.amount,
                dex_fee: quote.clmm_quote.fee.amount,
                tax_cost: quote.tax_output.tax_cost.amount,
            })
        }
        (TradeSide::Sell, Some(assessment)) if tax_is_active(assessment, TradeSide::Sell) => {
            let quote = simulate_tax_aware_clmm_sell_exact_input(pool, &request, assessment)
                .map_err(map_tax_aware_clmm)?;
            Ok(RawLeg {
                actual_in: quote.tax_input.net_transferable_input.amount,
                gross_output: quote.clmm_quote.output.amount,
                net_output: quote.clmm_quote.output.amount,
                dex_fee: quote.clmm_quote.fee.amount,
                tax_cost: quote.tax_input.tax_cost.amount,
            })
        }
        _ => {
            let quote = simulate_clmm_exact_input(pool, &request).map_err(RoutingError::Clmm)?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: quote.output.amount,
                net_output: quote.output.amount,
                dex_fee: quote.fee.amount,
                tax_cost: AtomicAmount::ZERO,
            })
        }
    }
}

fn simulate_bin(
    pool: &BinPoolState,
    intent: &TradeIntent,
    amount_in: AtomicAmount,
    tax: Option<&TaxAssessment>,
) -> Result<RawLeg, RoutingError> {
    let request = BinExactInputRequest::new_directed(
        intent.token_in.clone(),
        amount_in,
        intent.token_out.clone(),
    );

    match (intent.side, tax) {
        (TradeSide::Buy, Some(assessment)) if tax_is_active(assessment, TradeSide::Buy) => {
            let quote = simulate_bin_exact_input(pool, &request).map_err(RoutingError::Bin)?;
            let gross_output = AssetAmount {
                asset: intent.token_out.clone(),
                amount: quote.output.amount,
            };
            let taxed =
                apply_buy_tax_to_output(assessment, &gross_output).map_err(RoutingError::Tax)?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: taxed.gross_output.amount,
                net_output: taxed.net_output.amount,
                dex_fee: quote.fee.amount,
                tax_cost: taxed.tax_cost.amount,
            })
        }
        (TradeSide::Sell, Some(assessment)) if tax_is_active(assessment, TradeSide::Sell) => {
            let gross_input = AssetAmount {
                asset: intent.token_in.clone(),
                amount: amount_in,
            };
            let taxed =
                apply_sell_tax_to_input(assessment, &gross_input).map_err(RoutingError::Tax)?;
            let net_in = taxed.net_transferable_input.amount;
            let net_request = BinExactInputRequest::new_directed(
                intent.token_in.clone(),
                net_in,
                intent.token_out.clone(),
            );
            let quote = simulate_bin_exact_input(pool, &net_request).map_err(RoutingError::Bin)?;
            Ok(RawLeg {
                actual_in: net_in,
                gross_output: quote.output.amount,
                net_output: quote.output.amount,
                dex_fee: quote.fee.amount,
                tax_cost: taxed.tax_cost.amount,
            })
        }
        _ => {
            let quote = simulate_bin_exact_input(pool, &request).map_err(RoutingError::Bin)?;
            Ok(RawLeg {
                actual_in: amount_in,
                gross_output: quote.output.amount,
                net_output: quote.output.amount,
                dex_fee: quote.fee.amount,
                tax_cost: AtomicAmount::ZERO,
            })
        }
    }
}

fn finish_leg(
    candidate: &PoolCandidate,
    intent: &TradeIntent,
    raw: RawLeg,
) -> Result<EvaluatedLeg, RoutingError> {
    // Exact conservation: output tax on gross output (Buy) or input tax on gross
    // input (Sell). Both are asserted fail-closed even though the tax engine and
    // kernels construct them exactly.
    match intent.side {
        TradeSide::Buy => {
            let summed = raw
                .net_output
                .get()
                .checked_add(raw.tax_cost.get())
                .ok_or(RoutingError::InputConservationViolated)?;
            if summed != raw.gross_output.get() {
                return Err(RoutingError::InputConservationViolated);
            }
        }
        TradeSide::Sell => {
            let summed = raw
                .actual_in
                .get()
                .checked_add(raw.tax_cost.get())
                .ok_or(RoutingError::InputConservationViolated)?;
            if summed != intent.amount.get() {
                return Err(RoutingError::InputConservationViolated);
            }
        }
    }

    validate_dex_fee(raw.dex_fee, raw.actual_in, candidate.state.fee_bps())?;

    let assessed = assessed_asset_for_intent(intent);

    Ok(EvaluatedLeg {
        venue: candidate.venue.clone(),
        pool_ref: candidate.pool_ref.clone(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        amount_in: raw.actual_in,
        expected_amount_out: raw.net_output,
        gross_output: raw.gross_output,
        net_output: raw.net_output,
        dex_fee: nonzero_amount(&intent.token_in, raw.dex_fee),
        tax_cost: nonzero_amount(assessed, raw.tax_cost),
    })
}

fn nonzero_amount(asset: &AssetId, amount: AtomicAmount) -> Option<AssetAmount> {
    if amount.is_zero() {
        None
    } else {
        Some(AssetAmount {
            asset: asset.clone(),
            amount,
        })
    }
}

/// Checks `dex_fee * 10_000 <= actual_in * fee_bps` using exact 256-bit
/// products. The kernels compute the fee with floor rounding, so this bound must
/// always hold; a violation means the composed economics are inconsistent.
fn validate_dex_fee(
    dex_fee: AtomicAmount,
    actual_in: AtomicAmount,
    fee_bps: Bps,
) -> Result<(), RoutingError> {
    if cmp_u128_products(
        dex_fee.get(),
        10_000,
        actual_in.get(),
        fee_bps.get() as u128,
    ) == Ordering::Greater
    {
        return Err(RoutingError::Internal("dex fee exceeds pool fee bound"));
    }
    Ok(())
}

fn map_tax_aware_cpmm(err: TaxAwareSimulationError) -> RoutingError {
    match err {
        TaxAwareSimulationError::Cpmm(class) => RoutingError::Cpmm(class),
        TaxAwareSimulationError::Tax(tax) => RoutingError::Tax(tax),
    }
}

fn map_tax_aware_clmm(err: TaxAwareClmmSimulationError) -> RoutingError {
    match err {
        TaxAwareClmmSimulationError::Clmm(inner) => RoutingError::Clmm(inner),
        TaxAwareClmmSimulationError::Tax(tax) => RoutingError::Tax(tax),
    }
}
