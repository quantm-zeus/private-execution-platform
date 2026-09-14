//! Gas-aware score assembly, validation, and deterministic total ordering.
//!
//! The primary selection key is simulated **net** output, adjusted downward by an
//! exact, floor-rounded gas conversion when both a gas estimate and a gas price
//! are supplied. Gas can only ever reduce the ranking value, so the conversion is
//! conservative. All comparisons are integer-only and fully deterministic.

use std::cmp::Ordering;

use chain_types::{AssetId, ChainId};
use domain::{RouteScore, TradeIntent};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};
use serde::{Deserialize, Serialize};
use simulation::{div_u256_by_u128_floor, mul_u128_wide};

use crate::depth::DepthRank;
use crate::error::RoutingError;
use crate::quote::RouteQuote;
use crate::{RouteRequest, ScoredRoute};

/// Caller-supplied routing cost/risk inputs not derivable from pool state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringInputs {
    /// Expected slippage in basis points.
    pub expected_slippage_bps: Bps,
    /// MEV exposure in basis points.
    pub mev_risk_bps: Bps,
    /// Failure probability in basis points.
    pub failure_probability_bps: Bps,
    /// Provider reliability in basis points.
    pub provider_reliability_bps: Bps,
    /// Provider latency in milliseconds.
    pub latency_ms: u64,
}

/// Injected, deterministic gas model.
///
/// Implementors must not use wall-clock time, RPC, or randomness; the only
/// inputs are the intent chain and the composed hop count.
pub trait GasEstimator: Send + Sync {
    /// Returns the exact gas cost for `hop_count` hops on `chain`.
    fn estimate_gas(&self, chain: &ChainId, hop_count: usize) -> Result<AssetAmount, RoutingError>;
}

/// Asset-bound gas-asset to route-output conversion.
///
/// [`PriceRatio`] carries no asset identity, so a conversion must name the gas
/// asset it consumes and the route terminal output asset (the numeraire) it
/// prices into. Both bindings are checked before any arithmetic, so a ratio can
/// never be silently applied to the wrong asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasConversion {
    /// Asset the gas estimate is denominated in.
    pub gas_asset: AssetId,
    /// Route terminal output asset the ratio converts into.
    pub output_asset: AssetId,
    /// Exact gas-asset to output-asset price ratio.
    pub ratio: PriceRatio,
}

fn zero_bps() -> Result<Bps, RoutingError> {
    Bps::new(0).map_err(|_| RoutingError::Internal("zero bps invalid"))
}

/// Estimates the gas cost for a route, enforcing chain and asset binding.
///
/// A zero estimate maps to `None`, never `Some(0)`. A chain mismatch fails with
/// [`RoutingError::GasChainMismatch`]; a supplied conversion whose declared gas
/// asset disagrees with the estimate fails with
/// [`RoutingError::GasConversionFailed`]. An estimator failure is propagated as
/// the caller's typed error.
pub(crate) fn estimate_gas_cost(
    req: &RouteRequest<'_>,
    hop_count: usize,
) -> Result<Option<AssetAmount>, RoutingError> {
    match req.gas {
        None => Ok(None),
        Some(estimator) => {
            let estimate = estimator.estimate_gas(&req.intent.chain, hop_count)?;
            if estimate.asset.chain != req.intent.chain {
                return Err(RoutingError::GasChainMismatch);
            }
            if let Some(conversion) = &req.gas_price_in_output {
                if estimate.asset != conversion.gas_asset {
                    return Err(RoutingError::GasConversionFailed);
                }
            }
            if estimate.amount.is_zero() {
                Ok(None)
            } else {
                Ok(Some(estimate))
            }
        }
    }
}

/// Exact gas-asset to output-asset conversion, floor-rounded.
///
/// Returns `None` when no complete gas view is available. The supplied
/// conversion must name the estimate's gas asset and the route's terminal
/// output asset; any other pairing fails closed with
/// [`RoutingError::GasConversionFailed`], as does a conversion overflow.
pub(crate) fn net_after_gas(
    net_output: &AssetAmount,
    gas_cost: Option<&AssetAmount>,
    gas_price_in_output: Option<&GasConversion>,
) -> Result<Option<u128>, RoutingError> {
    match (gas_cost, gas_price_in_output) {
        (Some(gas), Some(conversion)) => {
            if gas.asset != conversion.gas_asset || net_output.asset != conversion.output_asset {
                return Err(RoutingError::GasConversionFailed);
            }
            let (hi, lo) = mul_u128_wide(gas.amount.get(), conversion.ratio.numerator_atomic());
            let converted = div_u256_by_u128_floor(hi, lo, conversion.ratio.denominator_atomic())
                .ok_or(RoutingError::GasConversionFailed)?;
            Ok(Some(net_output.amount.get().saturating_sub(converted)))
        }
        _ => Ok(None),
    }
}

fn validate_pair_cost(
    cost: &Option<AssetAmount>,
    chain: &ChainId,
    token_in: &chain_types::AssetId,
    token_out: &chain_types::AssetId,
    label: &'static str,
) -> Result<(), RoutingError> {
    if let Some(amount) = cost {
        if amount.amount.is_zero() {
            return Err(RoutingError::ScoreInconsistent(label));
        }
        if amount.asset.chain != *chain {
            return Err(RoutingError::ScoreInconsistent(label));
        }
        if amount.asset != *token_in && amount.asset != *token_out {
            return Err(RoutingError::ScoreInconsistent(label));
        }
    }
    Ok(())
}

/// Builds and validates a [`RouteScore`] for a quoted route.
pub(crate) fn build_score(
    intent: &TradeIntent,
    quote: &RouteQuote,
    scoring: &ScoringInputs,
    gas_cost: Option<AssetAmount>,
    now_ms: i64,
) -> Result<RouteScore, RoutingError> {
    let price_impact = match quote.route_impact_bps {
        Some(impact) => impact,
        None => zero_bps()?,
    };
    let state_age_ms = (now_ms - quote.plan.state.observed_at_ms).max(0) as u64;

    let score = RouteScore {
        gross_output: quote.gross_output.clone(),
        simulated_net_output: quote.net_output.clone(),
        tax_cost: quote.tax_cost.clone(),
        dex_fee: quote.net_delta.dex_fee.clone(),
        provider_fee: None,
        gas_cost,
        price_impact,
        expected_slippage: scoring.expected_slippage_bps,
        mev_risk: scoring.mev_risk_bps,
        failure_probability: scoring.failure_probability_bps,
        state_age_ms,
        provider_reliability: scoring.provider_reliability_bps,
        latency_ms: scoring.latency_ms,
    };
    validate_score(intent, &score)?;
    Ok(score)
}

/// Validates internal score consistency and cost denomination.
pub(crate) fn validate_score(intent: &TradeIntent, score: &RouteScore) -> Result<(), RoutingError> {
    if score.simulated_net_output.amount > score.gross_output.amount {
        return Err(RoutingError::ScoreInconsistent(
            "net output exceeds gross output",
        ));
    }
    validate_pair_cost(
        &score.dex_fee,
        &intent.chain,
        &intent.token_in,
        &intent.token_out,
        "dex_fee",
    )?;
    validate_pair_cost(
        &score.tax_cost,
        &intent.chain,
        &intent.token_in,
        &intent.token_out,
        "tax_cost",
    )?;
    validate_pair_cost(
        &score.provider_fee,
        &intent.chain,
        &intent.token_in,
        &intent.token_out,
        "provider_fee",
    )?;
    if let Some(gas) = &score.gas_cost {
        if gas.amount.is_zero() || gas.asset.chain != intent.chain {
            return Err(RoutingError::ScoreInconsistent("gas_cost"));
        }
    }
    Ok(())
}

fn primary_net(net_after_gas: Option<u128>, quote: &RouteQuote) -> u128 {
    match net_after_gas {
        Some(value) => value,
        None => quote.net_output.amount.get(),
    }
}

fn gas_ascending(left: &Option<AssetAmount>, right: &Option<AssetAmount>) -> Ordering {
    match (left, right) {
        (Some(a), Some(b)) if a.asset == b.asset => a.amount.get().cmp(&b.amount.get()),
        _ => Ordering::Equal,
    }
}

fn canonical_key(route: &ScoredRoute) -> Vec<(String, String, String, String)> {
    route
        .quote
        .plan
        .legs
        .iter()
        .map(|leg| {
            (
                leg.venue.clone(),
                leg.pool_ref.clone(),
                leg.token_in.address.clone(),
                leg.token_out.address.clone(),
            )
        })
        .collect()
}

/// Deterministic total order over scored routes: the best route sorts first.
///
/// Keys, in order: gas-adjusted net output descending (or net output when no gas
/// view), simulated net output descending, exact CLMM/Bin depth descending when
/// **both** candidates carry a depth key, gas cost ascending when both costs
/// share an asset, failure probability ascending, hop count ascending, canonical
/// leg key ascending.
///
/// Depth is strictly a tie-break below net output and is a no-op when either
/// candidate lacks a key (CPMM, multi-hop, or depth disabled), so an empty
/// target list reproduces the pre-depth ordering exactly.
pub(crate) fn compare_scored(
    left: &ScoredRoute,
    left_net_after_gas: Option<u128>,
    left_depth: Option<&DepthRank>,
    right: &ScoredRoute,
    right_net_after_gas: Option<u128>,
    right_depth: Option<&DepthRank>,
) -> Ordering {
    let left_primary = primary_net(left_net_after_gas, &left.quote);
    let right_primary = primary_net(right_net_after_gas, &right.quote);

    right_primary
        .cmp(&left_primary)
        .then_with(|| {
            right
                .score
                .simulated_net_output
                .amount
                .get()
                .cmp(&left.score.simulated_net_output.amount.get())
        })
        .then_with(|| depth_ascending(left_depth, right_depth))
        .then_with(|| gas_ascending(&left.score.gas_cost, &right.score.gas_cost))
        .then_with(|| {
            left.score
                .failure_probability
                .get()
                .cmp(&right.score.failure_probability.get())
        })
        .then_with(|| left.quote.plan.legs.len().cmp(&right.quote.plan.legs.len()))
        .then_with(|| canonical_key(left).cmp(&canonical_key(right)))
}

/// Orders depth keys as a lower-priority tie-break: compare absorbed capacity
/// from the widest band down, then lower exact impact. A missing key on either
/// side is neutral.
fn depth_ascending(left: Option<&DepthRank>, right: Option<&DepthRank>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            for (left_level, right_level) in left.levels.iter().zip(right.levels.iter()) {
                let ordering = compare_absorbed(left_level.absorbed_in, right_level.absorbed_in);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            depth_impact_key(left.impact_bps).cmp(&depth_impact_key(right.impact_bps))
        }
        _ => Ordering::Equal,
    }
}

/// Orders absorbed amounts so that a deeper pool sorts [`Ordering::Less`].
fn compare_absorbed(left: Option<AtomicAmount>, right: Option<AtomicAmount>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => right.get().cmp(&left.get()),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Maps an optional impact to a comparable key where `None` is the weakest.
fn depth_impact_key(impact: Option<Bps>) -> (u8, u16) {
    match impact {
        Some(bps) => (0, bps.get()),
        None => (1, 0),
    }
}
