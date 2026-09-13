//! Phase 4 R1: pure, deterministic single-path (linear) routing substrate.
//!
//! The crate plans a linear route over caller-supplied local pool state, bounded
//! to a direct path or exactly one bridge asset (at most two pools per path). It
//! composes **exact-input** quotes through the landed CPMM/CLMM/Bin simulation
//! kernels, applies buy/sell tax exclusively through the landed `tax-engine`
//! arithmetic, projects the result into the locked [`domain::RoutePlan`] and
//! [`execution_preview::NetDelta`] contracts, builds a gas-aware
//! [`domain::RouteScore`], and verifies the selected route through the public
//! [`execution_preview::validate_delta_preview_with_assessment`] bridge.
//!
//! # Purity and bounds
//! All pool state, tax assessment, freshness policy, gas model, and the reference
//! timestamp are supplied by the caller. There is no RPC, network, wall clock,
//! floating point, randomness, or filesystem access. Enumeration is bounded by
//! [`MAX_POOLS_SCANNED`], [`MAX_BRIDGE_ASSETS`], and [`MAX_ROUTE_CANDIDATES`], and
//! never brute-forces the token graph.
//!
//! # Non-goals
//! Split/spatial multi-path execution, exact-output quotes, depth-aware ranking,
//! provider benchmarks, DEX adapters, and any signing/policy/storage/relay wiring
//! are explicitly out of scope; no split-plan type exists here.

#![forbid(unsafe_code)]

pub mod error;
pub mod graph;
pub mod impact;
pub mod label;
pub mod leg;
pub mod plan;
pub mod quote;
pub mod score;
pub mod types;

use domain::{AmountType, RouteScore, TradeIntent};
use execution_preview::validate_delta_preview_with_assessment;
use market_types::{AtomicAmount, FreshnessPolicy};
use serde::{Deserialize, Serialize};
use tax_engine::TaxAssessment;

pub use error::{BridgeRejectClass, RoutingError};
pub use graph::{enumerate_candidates, CandidateLeg, CandidatePath, CandidateSet, PoolDescriptor};
pub use label::{PoolRefLabel, VenueLabel};
pub use leg::{simulate_leg, swap_dir};
pub use plan::{plan_direct_route, select_best_path, to_route_plan};
pub use quote::{HopQuote, PoolKindClass, RouteQuote};
pub use score::{GasConversion, GasEstimator, ScoringInputs};
pub use types::{
    EvaluatedLeg, EvaluatedPath, PoolCandidate, RouteDecision, RoutingConfig, RoutingInput, SwapDir,
};

/// Maximum pools per route path.
pub const MAX_ROUTE_HOPS: usize = 2;
/// Hard bound on the number of descriptors accepted in one call.
pub const MAX_POOLS_SCANNED: usize = 256;
/// Deterministic bridge-asset truncation bound (clipping sets `truncated`).
pub const MAX_BRIDGE_ASSETS: usize = 32;
/// Deterministic route-candidate truncation bound (clipping sets `truncated`).
pub const MAX_ROUTE_CANDIDATES: usize = 64;

/// Fully injected, deterministic single-path planning request.
pub struct RouteRequest<'a> {
    /// Trade intent the route must satisfy.
    pub intent: &'a TradeIntent,
    /// Caller-supplied pool descriptors; enumeration is bounded over this slice.
    pub descriptors: &'a [PoolDescriptor],
    /// Exact wallet debit for the route (`AmountType::InputAssetAtomic` only).
    pub amount_in: AtomicAmount,
    /// Required, asset-bound, fresh tax assessment.
    pub assessment: &'a TaxAssessment,
    /// Requested maximum hop count (`1..=MAX_ROUTE_HOPS`).
    pub max_hops: usize,
    /// Caller reference timestamp for all deterministic freshness evaluation.
    pub now_ms: i64,
    /// Caller freshness policy; the default policy is also enforced internally.
    pub freshness_policy: &'a FreshnessPolicy,
    /// Caller-supplied risk/latency/reliability inputs for the score.
    pub scoring: &'a ScoringInputs,
    /// Optional injected gas model.
    pub gas: Option<&'a dyn GasEstimator>,
    /// Asset-bound gas-asset to output-asset conversion, when a gas view exists.
    pub gas_price_in_output: Option<GasConversion>,
}

/// A quoted route together with its assembled score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoredRoute {
    /// Contract-validated route quote.
    pub quote: RouteQuote,
    /// Gas-aware score for the quote.
    pub score: RouteScore,
}

/// Deterministic planning decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Surviving candidates in deterministic best-first order.
    pub candidates: Vec<ScoredRoute>,
    /// The selected route, or `None` when nothing survived.
    pub selected: Option<RouteQuote>,
    /// `true` when a bridge-asset or route-candidate cap clipped enumeration.
    pub truncated: bool,
}

/// Reduces per-candidate failures to the most specific payload-free error.
///
/// A uniform price-impact gap, cap breach, kernel-failure class, or internal
/// composition failure is surfaced so a caller can distinguish a
/// model/configuration gap from a genuinely empty route set; stale pools,
/// disconnection, and mixed failures collapse to [`RoutingError::NoViableRoute`]
/// because a dropped candidate is not itself a hard routing failure.
fn aggregate_failure(failures: &[RoutingError]) -> RoutingError {
    if failures.is_empty() {
        return RoutingError::NoViableRoute;
    }
    if failures
        .iter()
        .all(|failure| *failure == RoutingError::ImpactUnavailable)
    {
        return RoutingError::ImpactUnavailable;
    }
    if failures
        .iter()
        .all(|failure| *failure == RoutingError::ImpactExceedsCap)
    {
        return RoutingError::ImpactExceedsCap;
    }
    // A uniform gas binding/conversion failure is caller configuration, not an
    // empty route set, so surface it rather than masking it as `NoViableRoute`.
    if failures
        .iter()
        .all(|failure| *failure == RoutingError::GasChainMismatch)
    {
        return RoutingError::GasChainMismatch;
    }
    if failures
        .iter()
        .all(|failure| *failure == RoutingError::GasConversionFailed)
    {
        return RoutingError::GasConversionFailed;
    }
    // A uniform internal composition failure is a bug, not an empty route set;
    // surface it rather than masking it as `NoViableRoute`.
    if failures
        .iter()
        .all(|failure| matches!(failure, RoutingError::Internal(_)))
    {
        return RoutingError::Internal("all candidates failed an internal invariant");
    }
    if let Some(RoutingError::HopSimulationFailed(class)) = failures.first() {
        if failures
            .iter()
            .all(|failure| *failure == RoutingError::HopSimulationFailed(*class))
        {
            return RoutingError::HopSimulationFailed(*class);
        }
    }
    RoutingError::NoViableRoute
}

/// Plans the best bounded linear route for the supplied request.
///
/// Candidate failures are isolated and never abort the search: a per-candidate
/// quote failure, gas-estimation failure, or gas-conversion failure simply drops
/// that candidate so one bad candidate cannot hide a viable route. Every
/// surviving candidate is then verified unconditionally through
/// [`validate_delta_preview_with_assessment`], which binds the route to the
/// intent's risk constraints (tax caps, limit price, `max_total_cost`, amount)
/// and to the supplied tax assessment. There is no public opt-out. If candidates
/// existed but none survived verification, the payload-free rejection class is
/// returned.
pub fn plan_single_path(req: &RouteRequest<'_>) -> Result<RoutingDecision, RoutingError> {
    if req.intent.token_in == req.intent.token_out {
        return Err(RoutingError::SameAssetPair);
    }
    // R1 is exact-input only; reject output/USD amount types unconditionally so
    // no caller can receive a route outside the locked input-asset scope.
    if req.intent.amount_type != AmountType::InputAssetAtomic {
        return Err(RoutingError::Domain(
            domain::DomainError::UnsupportedAmountType,
        ));
    }
    if req.max_hops == 0 || req.max_hops > MAX_ROUTE_HOPS {
        return Err(RoutingError::UnsupportedHopCount);
    }
    req.intent.validate(req.now_ms)?;
    if req.amount_in.is_zero() || req.amount_in.get() > req.intent.amount.get() {
        return Err(RoutingError::InputConservationViolated);
    }

    quote::validate_assessment(req)?;

    let candidate_set = graph::enumerate_candidates(req.intent, req.max_hops, req.descriptors)?;

    let mut ranked: Vec<(ScoredRoute, Option<u128>)> = Vec::new();
    let mut failures: Vec<RoutingError> = Vec::new();

    for path in &candidate_set.paths {
        let gas_cost = match score::estimate_gas_cost(req, path.legs.len()) {
            Ok(cost) => cost,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let quote = match quote::quote_path(req, req.descriptors, path) {
            Ok(quote) => quote,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        let score = score::build_score(
            req.intent,
            &quote,
            req.scoring,
            gas_cost.clone(),
            req.now_ms,
        )?;
        let net_after = match score::net_after_gas(
            &quote.net_output,
            gas_cost.as_ref(),
            req.gas_price_in_output.as_ref(),
        ) {
            Ok(value) => value,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
        ranked.push((ScoredRoute { quote, score }, net_after));
    }

    if ranked.is_empty() {
        return Err(aggregate_failure(&failures));
    }

    ranked.sort_by(|left, right| score::compare_scored(&left.0, left.1, &right.0, right.1));

    let mut final_routes: Vec<ScoredRoute> = Vec::with_capacity(ranked.len());
    let mut first_reject: Option<BridgeRejectClass> = None;

    // Verification is unconditional: every surviving candidate must pass the
    // locked bridge against the intent and the fresh assessment. There is no
    // caller-controlled bypass.
    for (route, _) in ranked {
        match validate_delta_preview_with_assessment(
            req.intent,
            &route.quote.plan,
            &route.quote.net_delta,
            req.assessment,
            req.now_ms,
        ) {
            Ok(_) => final_routes.push(route),
            Err(error) => {
                if first_reject.is_none() {
                    first_reject = Some(BridgeRejectClass::from_bridge_error(&error));
                }
            }
        }
    }
    if final_routes.is_empty() {
        let class = match first_reject {
            Some(class) => class,
            None => BridgeRejectClass::Domain,
        };
        return Err(RoutingError::SelectedRejected(class));
    }

    let selected = final_routes.first().map(|route| route.quote.clone());

    Ok(RoutingDecision {
        candidates: final_routes,
        selected,
        truncated: candidate_set.truncated,
    })
}
