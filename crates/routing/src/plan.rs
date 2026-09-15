//! Exact direct-route planning: bounded candidate evaluation, net-output
//! ranking, score assembly, and validated [`RoutePlan`] construction.
//!
//! This slice deliberately implements single-hop, single-leg direct routes only.
//! Splits, multi-hop search, depth targets, gas modelling, and DEX adapters are
//! deferred (see the slice non-goals). Provider benchmarking lives in the
//! additive [`crate::benchmark`] comparator, which only compares externally
//! supplied quotes; this planner never calls it.

use std::cmp::Ordering;

use domain::{RouteLeg, RoutePlan, RouteScore, TradeIntent};
use market_types::{AssetAmount, PoolKindState};

use crate::error::RoutingError;
use crate::leg::{simulate_leg, validate_tax_assessment};
use crate::types::{EvaluatedLeg, EvaluatedPath, PoolCandidate, RouteDecision, RoutingInput};

/// Plans the best single-hop direct route for the supplied input.
///
/// Candidates are bounded by [`crate::RoutingConfig::max_candidates`]. Every
/// candidate failure is isolated: a failed candidate is skipped and never aborts
/// the search. The winner is selected by simulated net output (never gross) with
/// deterministic `(pool_ref, venue)` tie-breaking.
///
/// The intent is validated before the resource budget so an invalid intent is
/// never masked by `BudgetExceeded`. A tax assessment is mandatory: a missing
/// assessment fails closed with [`RoutingError::TaxAssessmentRequired`] rather
/// than assuming a zero-tax token. When one is supplied, its binding and
/// freshness are validated once up front so a bad assessment is surfaced as the
/// typed error instead of being erased as `NoViableRoute`. Candidates with an
/// empty or whitespace `venue`/`pool_ref` cannot form a valid route plan and are
/// skipped during the candidate loop.
pub fn plan_direct_route(input: &RoutingInput<'_>) -> Result<RouteDecision, RoutingError> {
    input.intent.validate(input.now_ms)?;

    if input.config.max_candidates == 0 || input.candidates.len() > input.config.max_candidates {
        return Err(RoutingError::BudgetExceeded);
    }

    let tax = input.tax.ok_or(RoutingError::TaxAssessmentRequired)?;
    validate_tax_assessment(input.intent, tax, input.freshness_policy, input.now_ms)?;

    let mut ranked: Vec<(EvaluatedPath, &PoolCandidate)> = Vec::new();
    for candidate in input.candidates {
        if candidate.venue.trim().is_empty() || candidate.pool_ref.trim().is_empty() {
            continue;
        }
        if !contains_pair(&candidate.state, input.intent) {
            continue;
        }
        let leg = match simulate_leg(
            candidate,
            input.intent,
            input.intent.amount,
            Some(tax),
            input.freshness_policy,
            input.now_ms,
        ) {
            Ok(leg) => leg,
            Err(_) => continue,
        };
        let path = build_path(candidate, leg, input.now_ms);
        ranked.push((path, candidate));
    }

    if ranked.is_empty() {
        return Err(RoutingError::NoViableRoute);
    }

    let paths: Vec<EvaluatedPath> = ranked.iter().map(|(path, _)| path.clone()).collect();
    let index = best_index(&paths).ok_or(RoutingError::NoViableRoute)?;
    let winner = paths[index].clone();
    let candidate = ranked[index].1;

    let score = assemble_score(candidate, &winner);
    let plan = to_route_plan(&winner)?;

    Ok(RouteDecision {
        winner,
        score,
        plan,
    })
}

/// Builds a validated [`RoutePlan`] from an evaluated path.
///
/// One [`RouteLeg`] is emitted per [`EvaluatedLeg`]. `expected_net_output` is
/// the winner's exact simulated net output and `state` is the winner's freshness.
/// `RoutePlan::validate()` is invoked before returning.
pub fn to_route_plan(winner: &EvaluatedPath) -> Result<RoutePlan, RoutingError> {
    let legs = winner
        .legs
        .iter()
        .map(|leg| RouteLeg {
            venue: leg.venue.clone(),
            pool_ref: leg.pool_ref.clone(),
            token_in: leg.token_in.clone(),
            token_out: leg.token_out.clone(),
            amount_in: leg.amount_in,
            expected_amount_out: leg.expected_amount_out,
        })
        .collect();

    let plan = RoutePlan {
        legs,
        expected_net_output: winner.net_output.clone(),
        state: winner.freshness,
    };
    plan.validate()?;
    Ok(plan)
}

/// Selects the best path by deterministic net-output ranking.
///
/// Exposed so the net-vs-gross ordering invariant can be verified directly with
/// independently constructed paths.
pub fn select_best_path(paths: &[EvaluatedPath]) -> Option<&EvaluatedPath> {
    best_index(paths).and_then(|index| paths.get(index))
}

fn best_index(paths: &[EvaluatedPath]) -> Option<usize> {
    paths
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| compare_paths(left, right))
        .map(|(index, _)| index)
}

/// Orders paths so that the "best" one compares [`Ordering::Less`]: higher
/// `net_output` first, then `(pool_ref, venue)` ascending. Gross output is never
/// a ranking key.
fn compare_paths(left: &EvaluatedPath, right: &EvaluatedPath) -> Ordering {
    right
        .net_output
        .amount
        .cmp(&left.net_output.amount)
        .then_with(|| ref_key(left).cmp(&ref_key(right)))
}

fn ref_key(path: &EvaluatedPath) -> (&str, &str) {
    match path.legs.first() {
        Some(leg) => (leg.pool_ref.as_str(), leg.venue.as_str()),
        None => ("", ""),
    }
}

fn contains_pair(state: &PoolKindState, intent: &TradeIntent) -> bool {
    if state.token_0().chain != intent.chain || state.token_1().chain != intent.chain {
        return false;
    }
    let has_in = state.token_0() == &intent.token_in || state.token_1() == &intent.token_in;
    let has_out = state.token_0() == &intent.token_out || state.token_1() == &intent.token_out;
    has_in && has_out
}

fn build_path(candidate: &PoolCandidate, leg: EvaluatedLeg, now_ms: i64) -> EvaluatedPath {
    let token_out = leg.token_out.clone();
    let gross_output = AssetAmount {
        asset: token_out.clone(),
        amount: leg.gross_output,
    };
    let net_output = AssetAmount {
        asset: token_out,
        amount: leg.net_output,
    };
    let state_age_ms = (now_ms - candidate.freshness.observed_at_ms).max(0) as u64;

    EvaluatedPath {
        legs: vec![leg.clone()],
        gross_output,
        net_output,
        dex_fee: leg.dex_fee.clone(),
        tax_cost: leg.tax_cost.clone(),
        state_age_ms,
        freshness: candidate.freshness,
    }
}

fn assemble_score(candidate: &PoolCandidate, winner: &EvaluatedPath) -> RouteScore {
    RouteScore {
        gross_output: winner.gross_output.clone(),
        simulated_net_output: winner.net_output.clone(),
        tax_cost: winner.tax_cost.clone(),
        dex_fee: winner.dex_fee.clone(),
        provider_fee: None,
        gas_cost: None,
        price_impact: candidate.price_impact_bps,
        expected_slippage: candidate.expected_slippage_bps,
        mev_risk: candidate.mev_risk_bps,
        failure_probability: candidate.failure_probability_bps,
        state_age_ms: winner.state_age_ms,
        provider_reliability: candidate.provider_reliability_bps,
        latency_ms: candidate.latency_ms,
    }
}
