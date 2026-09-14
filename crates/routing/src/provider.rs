//! Provider-backed route composition (P84B).
//!
//! Builds a locked [`RouteQuote`]/[`NetDelta`]/[`RouteScore`] for an externally
//! supplied provider gross output (for example an OKX Swap quote), applying PEP
//! buy/sell tax exactly as the local planner does and validating through the same
//! locked [`execution_preview::validate_delta_preview_with_assessment`] bridge.
//!
//! This module is deliberately pure: it never calls a provider, the network, a
//! wall clock, an RNG, or floating point, and it never signs. The provider amount
//! and reference time are supplied by the caller. The provider output is
//! untrusted until the locked bridge accepts the composed delta.
//!
//! The provider route is represented as a single synthetic leg with caller-
//! supplied validated [`VenueLabel`]/[`PoolRefLabel`] text, so the locked
//! `RoutePlan`/`NetDelta` shape and the `ExecutionPreview` validator are reused
//! unchanged. `route_impact_bps` is `None` because no local pool model exists for
//! a provider route; the exact on-chain slippage floor is bound to the provider
//! proposal before signing in a later slice.

use domain::{RouteLeg, RoutePlan, RouteScore, TradeIntent, TradeSide};
use execution_preview::{validate_delta_preview_with_assessment, NetDelta};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, Sequence};
use tax_engine::TaxAssessment;

use crate::error::{BridgeRejectClass, RoutingError};
use crate::label::{PoolRefLabel, VenueLabel};
use crate::quote::{map_tax_error, nonzero, validate_assessment_fields, RouteQuote};
use crate::score::ScoringInputs;

/// Fully injected input for one provider-route composition.
pub struct ProviderRouteInput<'a> {
    /// Trusted, already-built intent (pair/side/risk bound by the caller).
    pub intent: &'a TradeIntent,
    /// Full wallet debit in `intent.token_in` (gross, before any sell tax).
    pub amount_in: AtomicAmount,
    /// Provider gross output in `intent.token_out` (before any buy tax).
    pub provider_gross_output: AtomicAmount,
    /// Fresh, asset-bound tax assessment for the assessed side.
    pub assessment: &'a TaxAssessment,
    /// Caller freshness policy for the assessment.
    pub freshness_policy: &'a FreshnessPolicy,
    /// Caller reference time.
    pub now_ms: i64,
    /// Validated provider venue label (for example `"okx"`).
    pub venue: &'a VenueLabel,
    /// Validated provider pool/reference label.
    pub pool_ref: &'a PoolRefLabel,
    /// Caller-supplied router cost/risk scoring inputs.
    pub scoring: &'a ScoringInputs,
    /// Provider-reported absolute price impact in basis points, or `None` when
    /// the provider did not report one. When the intent sets a non-zero
    /// `max_price_impact`, `None` fails closed exactly like the local planner.
    pub price_impact_bps: Option<Bps>,
}

/// A provider route composed into the locked contracts.
#[derive(Clone, Debug)]
pub struct ProviderRouteQuote {
    /// Locked, bridge-validated route and net delta.
    pub quote: RouteQuote,
    /// Score for the provider route (gas/provider fees are `None`: no local model).
    pub score: RouteScore,
}

/// Composes and validates one provider route.
///
/// Sell-side input tax is applied before the provider swap and buy-side output
/// tax after it, exactly like [`crate::quote::quote_path`]. The composed
/// `RoutePlan`/`NetDelta` are validated structurally and then through the locked
/// assessment-bound bridge, so a provider output that does not satisfy the
/// intent, tax, or risk contracts is rejected with a payload-free
/// [`RoutingError::SelectedRejected`].
pub fn quote_provider_route(
    input: &ProviderRouteInput<'_>,
) -> Result<ProviderRouteQuote, RoutingError> {
    let intent = input.intent;
    intent.validate(input.now_ms)?;
    validate_assessment_fields(
        intent,
        input.assessment,
        input.freshness_policy,
        input.now_ms,
    )?;

    if input.amount_in.is_zero() {
        return Err(RoutingError::InputConservationViolated);
    }

    // Sell-side input tax is applied before the provider swap.
    let mut swapped_input = input.amount_in;
    let mut input_tax_cost: Option<AssetAmount> = None;
    if intent.side == TradeSide::Sell {
        let gross_input = AssetAmount {
            asset: intent.token_in.clone(),
            amount: input.amount_in,
        };
        let taxed = input
            .assessment
            .apply_sell_tax_to_input(&gross_input)
            .map_err(map_tax_error)?;
        input_tax_cost = nonzero(taxed.tax_cost.clone());
        swapped_input = taxed.net_transferable_input.amount;
    }
    if swapped_input.is_zero() {
        return Err(RoutingError::ZeroHopOutput);
    }

    let gross_amount = input.provider_gross_output;
    if gross_amount.is_zero() {
        return Err(RoutingError::ZeroHopOutput);
    }

    // Price-impact gate: mirror the locked local planner. A non-zero intent cap
    // requires a modeled impact at or below it; the router's `0` is the
    // documented "unbounded" sentinel, so an unmodeled impact is admitted only
    // when the caller has explicitly opted out of the cap. This prevents a
    // provider route from silently bypassing the cap the local route enforces.
    if intent.risk.max_price_impact.get() != 0 {
        match input.price_impact_bps {
            None => return Err(RoutingError::ImpactUnavailable),
            Some(impact) if impact.get() > intent.risk.max_price_impact.get() => {
                return Err(RoutingError::ImpactExceedsCap);
            }
            Some(_) => {}
        }
    }
    let score_impact = match input.price_impact_bps {
        Some(impact) => impact,
        None => Bps::new(0).map_err(|_| RoutingError::Internal("zero bps invalid"))?,
    };

    // Buy-side output tax is applied after the provider swap.
    let (net_amount, tax_cost) = match intent.side {
        TradeSide::Buy => {
            let gross = AssetAmount {
                asset: intent.token_out.clone(),
                amount: gross_amount,
            };
            let taxed = input
                .assessment
                .apply_buy_tax(&gross)
                .map_err(map_tax_error)?;
            (taxed.net_output.amount, nonzero(taxed.tax_cost.clone()))
        }
        TradeSide::Sell => (gross_amount, input_tax_cost),
    };
    if net_amount.is_zero() {
        return Err(RoutingError::ZeroNetOutput);
    }

    let leg = RouteLeg {
        venue: input.venue.as_str().to_string(),
        pool_ref: input.pool_ref.as_str().to_string(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        amount_in: swapped_input,
        expected_amount_out: gross_amount,
    };
    let plan = RoutePlan {
        legs: vec![leg],
        expected_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: net_amount,
        },
        state: Freshness {
            observed_at_ms: input.now_ms,
            chain_height: 0,
            sequence: Sequence(1),
        },
    };
    plan.validate()?;

    let net_delta = NetDelta {
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: input.amount_in,
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: gross_amount,
        },
        net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: net_amount,
        },
        dex_fee: None,
        tax_cost: tax_cost.clone(),
    };
    net_delta
        .validate()
        .map_err(|_| RoutingError::Internal("provider net delta failed validation"))?;

    validate_delta_preview_with_assessment(
        intent,
        &plan,
        &net_delta,
        input.assessment,
        input.now_ms,
    )
    .map_err(|error| {
        RoutingError::SelectedRejected(BridgeRejectClass::from_bridge_error(&error))
    })?;

    let gross_output = AssetAmount {
        asset: intent.token_out.clone(),
        amount: gross_amount,
    };
    let net_output = AssetAmount {
        asset: intent.token_out.clone(),
        amount: net_amount,
    };
    let score = RouteScore {
        gross_output: gross_output.clone(),
        simulated_net_output: net_output.clone(),
        tax_cost: tax_cost.clone(),
        dex_fee: None,
        provider_fee: None,
        gas_cost: None,
        price_impact: score_impact,
        expected_slippage: input.scoring.expected_slippage_bps,
        mev_risk: input.scoring.mev_risk_bps,
        failure_probability: input.scoring.failure_probability_bps,
        state_age_ms: 0,
        provider_reliability: input.scoring.provider_reliability_bps,
        latency_ms: input.scoring.latency_ms,
    };

    Ok(ProviderRouteQuote {
        quote: RouteQuote {
            plan,
            net_delta,
            hop_quotes: Vec::new(),
            gross_output,
            net_output,
            tax_cost,
            route_impact_bps: input.price_impact_bps,
        },
        score,
    })
}
