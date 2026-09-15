//! Phase 4 split optimizer: bounded parallel two-path search extended to 3-5 legs.
//!
//! A spatial split funds `N` parallel contiguous routes that all start at
//! `intent.token_in` and end at `intent.token_out` with disjoint gross input
//! budgets summing to the executed input. This module reuses the landed exact
//! single-path kernels ([`crate::quote::quote_path`]) for every branch, aggregates
//! the exact per-branch [`NetDelta`]s, and returns a [`domain::SplitPlan`] only
//! when the aggregate clears the configured improvement gate and every branch
//! clears the dust gate.
//!
//! # Purity and bounds
//! There is no RPC, network, wall clock, floating point, randomness, or
//! filesystem access. Every loop is bounded by a compile-time constant, and every
//! `quote_path` call is charged against [`crate::MAX_SPLIT_QUOTES`]. Failure to
//! stay inside that budget fails closed with
//! [`RoutingError::SplitBudgetExceeded`] rather than silently truncating.
//!
//! # Fail-closed
//! `routing` never validates or signs a split itself. The selected candidate is
//! returned only after [`execution_preview::validate_split_delta_preview_with_assessment`]
//! accepted the aggregate against the intent and the fresh assessment. When the
//! split cannot be validated the incumbent single path is returned; when neither
//! validates the call fails closed with [`RoutingError::SelectedRejected`].

use std::cmp::Ordering;

use chain_types::AssetId;
use domain::{AmountType, RouteScore, SplitLeg, SplitPlan, TradeIntent};
use execution_preview::{validate_split_delta_preview_with_assessment, NetDelta};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, PriceRatio, Sequence};
use serde::{Deserialize, Serialize};
use simulation::{div_u256_by_u128_floor, mul_u128_wide};

use crate::error::{BridgeRejectClass, RoutingError};
use crate::graph::{enumerate_candidates, CandidatePath, PoolDescriptor};
use crate::quote::{self, RouteQuote};
use crate::score::{self, GasConversion};
use crate::{
    RouteRequest, ScoredRoute, MAX_ROUTE_HOPS, MAX_SPLIT_LEGS, MAX_SPLIT_PAIRS, MAX_SPLIT_QUOTES,
    MAX_SPLIT_REFINE_STEPS, MIN_SPLIT_LEGS, SPLIT_GRID_STEPS,
};

/// Asset-bound USD conversion used by the per-leg USD dust gate.
///
/// `PriceRatio` carries no asset identity, so the conversion names the input
/// asset it prices; the binding is checked before any arithmetic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitUsdConversion {
    /// Must equal `intent.token_in`.
    pub input_asset: AssetId,
    /// Exact micro-USD value of one atomic unit of `input_asset`.
    pub usd_micros_per_atomic: PriceRatio,
}

/// Caller-supplied split optimizer policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitConfig {
    /// Strict improvement threshold in bps over the best quoted single path.
    pub min_split_improvement_bps: Bps,
    /// Minimum gross input per branch, atomic `token_in` (fraction dust).
    pub min_leg_input: AtomicAmount,
    /// Minimum branch expected net output, atomic `token_out` (fraction dust).
    pub min_leg_output: AtomicAmount,
    /// Minimum branch USD notional in micros; `0` disables the USD gate.
    pub min_leg_usd_micros: u64,
    /// Required when `min_leg_usd_micros > 0`.
    pub usd_conversion: Option<SplitUsdConversion>,
    /// Branch cap, `MIN_SPLIT_LEGS..=MAX_SPLIT_LEGS`.
    pub max_legs: usize,
}

impl SplitConfig {
    /// Validates the configuration against the intent's input asset.
    pub fn validate(&self, intent: &TradeIntent) -> Result<(), RoutingError> {
        if self.max_legs < MIN_SPLIT_LEGS || self.max_legs > MAX_SPLIT_LEGS {
            return Err(RoutingError::UnsupportedSplitLegCount);
        }
        if self.min_leg_input.is_zero() || self.min_leg_output.is_zero() {
            return Err(RoutingError::InvalidSplitConfig);
        }
        if self.min_leg_usd_micros > 0 {
            let Some(conversion) = &self.usd_conversion else {
                return Err(RoutingError::InvalidSplitConfig);
            };
            if conversion.input_asset != intent.token_in {
                return Err(RoutingError::InvalidSplitConfig);
            }
        }
        Ok(())
    }
}

/// One branch of a quoted split: gross budget plus the reused [`RouteQuote`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitLegQuote {
    /// Gross wallet-debit budget allocated to this branch.
    pub amount_in: AtomicAmount,
    /// Exact single-path quote for the branch.
    pub quote: RouteQuote,
}

/// A fully composed split candidate (plan + aggregate economics + score).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitQuote {
    /// Signable/bindable split plan, one [`SplitLeg`] per branch.
    pub split: SplitPlan,
    /// Aggregate exact wallet-level net delta.
    pub net_delta: NetDelta,
    /// Per-branch quotes (aligned with `split.legs`).
    pub legs: Vec<SplitLegQuote>,
    /// Aggregate gross output in `token_out`.
    pub gross_output: AssetAmount,
    /// Aggregate post-tax output in `token_out`.
    pub net_output: AssetAmount,
    /// Aggregate tax cost, `None` when exactly zero.
    pub tax_cost: Option<AssetAmount>,
    /// Aggregate pool fee, `None` when exactly zero.
    pub dex_fee: Option<AssetAmount>,
    /// Gas-aware aggregate score.
    pub score: RouteScore,
    /// Canonical deterministic branch key `(venue, pool_ref, token_in, token_out)`.
    pub canonical_key: Vec<(String, String, String, String)>,
}

/// Deterministic split planning decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitDecision {
    /// Verified split candidates, best first (empty when no split improved).
    pub candidates: Vec<SplitQuote>,
    /// Selected split; `None` means "use the incumbent single path".
    pub selected: Option<SplitQuote>,
    /// The verified best single path (incumbent fallback), if one existed.
    pub incumbent: Option<ScoredRoute>,
    /// `true` when bridge-asset or route-candidate enumeration was clipped.
    pub truncated: bool,
}

/// A baseline single path with its full-total quote and gas-adjusted ranking value.
#[derive(Clone)]
struct SingleBaseline {
    path: CandidatePath,
    scored: ScoredRoute,
    net_after_gas: Option<u128>,
}

/// A quoted two-path split point on the coarse grid.
#[derive(Clone)]
struct TwoPathPoint {
    x: u128,
    left: RouteQuote,
    right: RouteQuote,
    value: u128,
}

/// One branch of an in-progress extended split, bound back to its candidate path.
#[derive(Clone)]
struct LegState {
    top_index: usize,
    budget: u128,
    quote: RouteQuote,
}

/// A split candidate plus the `top` path indices that produced its branches.
#[derive(Clone)]
struct CandidateWithPaths {
    candidate: SplitQuote,
    paths: Vec<usize>,
}

/// Charges one exact quote against the shared bounded budget.
fn charge_budget(budget_used: &mut usize) -> Result<(), RoutingError> {
    *budget_used = budget_used
        .checked_add(1)
        .ok_or(RoutingError::SplitBudgetExceeded)?;
    if *budget_used > MAX_SPLIT_QUOTES {
        return Err(RoutingError::SplitBudgetExceeded);
    }
    Ok(())
}

/// Quotes one branch path at `budget`, charging the exact-quote budget.
fn quote_branch(
    req: &RouteRequest<'_>,
    path: &CandidatePath,
    budget: AtomicAmount,
    budget_used: &mut usize,
) -> Result<RouteQuote, RoutingError> {
    charge_budget(budget_used)?;
    let branch_req = RouteRequest {
        intent: req.intent,
        descriptors: req.descriptors,
        amount_in: budget,
        assessment: req.assessment,
        max_hops: req.max_hops,
        now_ms: req.now_ms,
        freshness_policy: req.freshness_policy,
        scoring: req.scoring,
        gas: req.gas,
        gas_price_in_output: req.gas_price_in_output.clone(),
        // Split branches keep the pre-depth economics: depth ranking is a
        // single-path key and never changes split leg selection.
        depth_targets: &[],
    };
    quote::quote_path(&branch_req, req.descriptors, path)
}

/// Quotes a branch, treating a non-budget failure as a skipped probe.
fn try_quote_branch(
    req: &RouteRequest<'_>,
    path: &CandidatePath,
    budget: AtomicAmount,
    budget_used: &mut usize,
) -> Result<Option<RouteQuote>, RoutingError> {
    match quote_branch(req, path, budget, budget_used) {
        Ok(quote) => Ok(Some(quote)),
        Err(RoutingError::SplitBudgetExceeded) => Err(RoutingError::SplitBudgetExceeded),
        Err(_) => Ok(None),
    }
}

/// Exact `floor(a * b / d)` using 256-bit intermediate arithmetic.
fn mul_div_floor(a: u128, b: u128, d: u128) -> Result<u128, RoutingError> {
    let (hi, lo) = mul_u128_wide(a, b);
    div_u256_by_u128_floor(hi, lo, d).ok_or(RoutingError::AmountOverflow)
}

/// Per-branch dust gate: gross input, net output, and optional USD notional.
fn passes_dust(
    budget: u128,
    quote: &RouteQuote,
    config: &SplitConfig,
) -> Result<bool, RoutingError> {
    if budget < config.min_leg_input.get() {
        return Ok(false);
    }
    if quote.net_output.amount < config.min_leg_output {
        return Ok(false);
    }
    if config.min_leg_usd_micros > 0 {
        let conversion = config
            .usd_conversion
            .as_ref()
            .ok_or(RoutingError::InvalidSplitConfig)?;
        let (hi, lo) = mul_u128_wide(budget, conversion.usd_micros_per_atomic.numerator_atomic());
        let usd = div_u256_by_u128_floor(
            hi,
            lo,
            conversion.usd_micros_per_atomic.denominator_atomic(),
        )
        .ok_or(RoutingError::InvalidSplitConfig)?;
        if usd < u128::from(config.min_leg_usd_micros) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Strict improvement gate: `split * 10_000 > single * (10_000 + bps)`.
fn split_improves(split: u128, single: u128, bps: u16) -> bool {
    domain::cmp_u128_products(split, 10_000, single, 10_000 + u128::from(bps)) == Ordering::Greater
}

/// The split's comparable primary value: net-after-gas when a complete gas view
/// exists, otherwise the raw aggregate net output. Mirrors `score::primary_net`
/// for single paths so the improvement gate is apples-to-apples.
fn split_primary_net(
    candidate: &SplitQuote,
    gas_price_in_output: Option<&GasConversion>,
) -> Result<u128, RoutingError> {
    match score::net_after_gas(
        &candidate.net_output,
        candidate.score.gas_cost.as_ref(),
        gas_price_in_output,
    )? {
        Some(value) => Ok(value),
        None => Ok(candidate.net_output.amount.get()),
    }
}

/// The distinct pool references used by a candidate path.
///
/// Two branches that reuse a pool must never be quoted independently: each
/// branch is simulated against the *initial* pool state, so reusing a pool in
/// two branches would overstate the aggregate. Splits are therefore restricted
/// to pool-disjoint branches.
fn path_pool_refs<'a>(descriptors: &'a [PoolDescriptor], path: &CandidatePath) -> Vec<&'a str> {
    path.legs
        .iter()
        .filter_map(|leg| descriptors.get(leg.descriptor_index))
        .map(|descriptor| descriptor.envelope.pool_id.address.as_str())
        .collect()
}

fn pools_overlap(left: &[&str], right: &[&str]) -> bool {
    left.iter().any(|pool| right.contains(pool))
}

/// Aggregate branch freshness: min observed_at_ms and min sequence.
fn aggregate_state(quotes: &[&RouteQuote]) -> Result<Freshness, RoutingError> {
    let mut observed_min = i64::MAX;
    let mut sequence_min: Option<Sequence> = None;
    for quote in quotes {
        observed_min = observed_min.min(quote.plan.state.observed_at_ms);
        let sequence = quote.plan.state.sequence;
        sequence_min = Some(match sequence_min {
            Some(current) if current.get() <= sequence.get() => current,
            _ => sequence,
        });
    }
    let sequence = sequence_min.ok_or(RoutingError::Internal("split has no branches"))?;
    Ok(Freshness {
        observed_at_ms: observed_min,
        chain_height: 0,
        sequence,
    })
}

/// Aggregate gas cost: summed only when every branch produced a same-asset view.
fn split_gas_cost(
    req: &RouteRequest<'_>,
    legs: &[(u128, RouteQuote)],
) -> Result<Option<AssetAmount>, RoutingError> {
    let mut total: Option<AssetAmount> = None;
    for (_, quote) in legs {
        let Some(cost) = score::estimate_gas_cost(req, quote.plan.legs.len())? else {
            return Ok(None);
        };
        total = Some(match total {
            None => cost,
            Some(current) if current.asset == cost.asset => {
                let Some(sum) = current.amount.get().checked_add(cost.amount.get()) else {
                    return Ok(None);
                };
                AssetAmount {
                    asset: current.asset,
                    amount: AtomicAmount::new(sum),
                }
            }
            Some(_) => return Ok(None),
        });
    }
    Ok(total)
}

/// Canonical deterministic branch key over the whole split.
fn canonical_key_for_split(split: &SplitPlan) -> Vec<(String, String, String, String)> {
    let mut key = Vec::new();
    for branch in &split.legs {
        for leg in &branch.route.legs {
            key.push((
                leg.venue.clone(),
                leg.pool_ref.clone(),
                leg.token_in.address.clone(),
                leg.token_out.address.clone(),
            ));
        }
    }
    key
}

/// Builds one aggregate score for a committed split.
fn build_split_score(
    req: &RouteRequest<'_>,
    legs: &[(u128, RouteQuote)],
    aggregate: &NetDelta,
    split: &SplitPlan,
) -> Result<RouteScore, RoutingError> {
    let mut impact = Bps::new(0).map_err(|_| RoutingError::Internal("zero bps invalid"))?;
    for (_, quote) in legs {
        if let Some(branch_impact) = quote.route_impact_bps {
            if branch_impact.get() > impact.get() {
                impact = branch_impact;
            }
        }
    }
    let gas_cost = split_gas_cost(req, legs)?;
    let state_age_ms = req.now_ms.saturating_sub(split.state.observed_at_ms).max(0) as u64;

    let score = RouteScore {
        gross_output: aggregate.gross_output.clone(),
        simulated_net_output: aggregate.net_output.clone(),
        tax_cost: aggregate.tax_cost.clone(),
        dex_fee: aggregate.dex_fee.clone(),
        provider_fee: None,
        gas_cost,
        price_impact: impact,
        expected_slippage: req.scoring.expected_slippage_bps,
        mev_risk: req.scoring.mev_risk_bps,
        failure_probability: req.scoring.failure_probability_bps,
        state_age_ms,
        provider_reliability: req.scoring.provider_reliability_bps,
        latency_ms: req.scoring.latency_ms,
    };
    score::validate_score(req.intent, &score)?;
    Ok(score)
}

/// Builds a validated-geometry split candidate from quoted branches.
///
/// Returns `Ok(None)` when the branches cannot form a structurally valid
/// aggregate (dust gate, conservation, or plan validation). This never returns
/// an unvalidated split: the caller still runs the locked aggregate bridge.
fn build_split_quote(
    req: &RouteRequest<'_>,
    legs: &[(u128, RouteQuote)],
    config: &SplitConfig,
) -> Result<Option<SplitQuote>, RoutingError> {
    if legs.len() < MIN_SPLIT_LEGS {
        return Ok(None);
    }
    if legs.len() > MAX_SPLIT_LEGS {
        return Ok(None);
    }
    for (budget, quote) in legs {
        if !passes_dust(*budget, quote, config)? {
            return Ok(None);
        }
    }

    let branch_deltas: Vec<NetDelta> = legs
        .iter()
        .map(|(_, quote)| quote.net_delta.clone())
        .collect();
    let aggregate = match NetDelta::aggregate(&branch_deltas) {
        Ok(delta) => delta,
        Err(_) => return Ok(None),
    };

    let mut split_legs: Vec<SplitLeg> = Vec::with_capacity(legs.len());
    let mut output_sum: u128 = 0;
    for (budget, quote) in legs {
        output_sum = match output_sum.checked_add(quote.plan.expected_net_output.amount.get()) {
            Some(sum) => sum,
            None => return Ok(None),
        };
        split_legs.push(SplitLeg {
            amount_in: AtomicAmount::new(*budget),
            route: quote.plan.clone(),
        });
    }

    let expected_net_output = AssetAmount {
        asset: req.intent.token_out.clone(),
        amount: AtomicAmount::new(output_sum),
    };
    if expected_net_output != aggregate.net_output {
        return Ok(None);
    }
    let state = aggregate_state(&legs.iter().map(|(_, quote)| quote).collect::<Vec<_>>())?;
    let split = SplitPlan {
        legs: split_legs,
        expected_net_output,
        state,
    };
    if split.validate(req.intent).is_err() {
        return Ok(None);
    }

    let score = build_split_score(req, legs, &aggregate, &split)?;
    let canonical_key = canonical_key_for_split(&split);
    let split_legs = legs
        .iter()
        .map(|(budget, quote)| SplitLegQuote {
            amount_in: AtomicAmount::new(*budget),
            quote: quote.clone(),
        })
        .collect();

    Ok(Some(SplitQuote {
        split,
        net_delta: aggregate.clone(),
        legs: split_legs,
        gross_output: aggregate.gross_output.clone(),
        net_output: aggregate.net_output.clone(),
        tax_cost: aggregate.tax_cost.clone(),
        dex_fee: aggregate.dex_fee.clone(),
        score,
        canonical_key,
    }))
}

/// Evaluates one two-path grid point, skipping any point that cannot be quoted
/// or does not clear the dust gate. A budget overrun always propagates.
fn eval_two_path(
    req: &RouteRequest<'_>,
    total: u128,
    path_i: &CandidatePath,
    path_j: &CandidatePath,
    x: u128,
    config: &SplitConfig,
    budget_used: &mut usize,
) -> Result<Option<TwoPathPoint>, RoutingError> {
    if x < config.min_leg_input.get() {
        return Ok(None);
    }
    let right = total.saturating_sub(x);
    if right < config.min_leg_input.get() {
        return Ok(None);
    }
    let Some(left) = try_quote_branch(req, path_i, AtomicAmount::new(x), budget_used)? else {
        return Ok(None);
    };
    let Some(right_quote) = try_quote_branch(req, path_j, AtomicAmount::new(right), budget_used)?
    else {
        return Ok(None);
    };
    if !passes_dust(x, &left, config)? || !passes_dust(right, &right_quote, config)? {
        return Ok(None);
    }
    let Some(value) = left
        .net_output
        .amount
        .get()
        .checked_add(right_quote.net_output.amount.get())
    else {
        return Ok(None);
    };
    Ok(Some(TwoPathPoint {
        x,
        left,
        right: right_quote,
        value,
    }))
}

/// Searches the best continuous two-path allocation for one candidate pair.
fn best_two_path(
    req: &RouteRequest<'_>,
    total: u128,
    path_i: &CandidatePath,
    path_j: &CandidatePath,
    config: &SplitConfig,
    budget_used: &mut usize,
) -> Result<Option<TwoPathPoint>, RoutingError> {
    let min_input = config.min_leg_input.get();
    if total < min_input.saturating_mul(2) {
        return Ok(None);
    }

    // Coarse grid: `x_k = floor(total * k / SPLIT_GRID_STEPS)`.
    let mut points: Vec<TwoPathPoint> = Vec::new();
    for k in 1..SPLIT_GRID_STEPS {
        let x = mul_div_floor(total, k, SPLIT_GRID_STEPS)?;
        if let Some(point) = eval_two_path(req, total, path_i, path_j, x, config, budget_used)? {
            points.push(point);
        }
    }
    let mut best = match points
        .iter()
        .max_by(|a, b| a.value.cmp(&b.value).then_with(|| b.x.cmp(&a.x)))
    {
        Some(point) => point.clone(),
        None => return Ok(None),
    };

    // Local bisection around the best grid point, bounded and deterministic.
    let step = total / SPLIT_GRID_STEPS;
    let mut lo = best.x.saturating_sub(step).max(min_input);
    let mut hi = best
        .x
        .saturating_add(step)
        .min(total.saturating_sub(min_input));
    let mut lo_point = eval_two_path(req, total, path_i, path_j, lo, config, budget_used)?;
    let mut hi_point = eval_two_path(req, total, path_i, path_j, hi, config, budget_used)?;

    for _ in 0..MAX_SPLIT_REFINE_STEPS {
        if hi <= lo.saturating_add(1) {
            break;
        }
        let mid = lo + (hi - lo) / 2;
        match eval_two_path(req, total, path_i, path_j, mid, config, budget_used)? {
            Some(point) => {
                if point.value > best.value || (point.value == best.value && point.x < best.x) {
                    best = point.clone();
                }
                let lo_val = lo_point.as_ref().map(|p| p.value).unwrap_or(0);
                let hi_val = hi_point.as_ref().map(|p| p.value).unwrap_or(0);
                if lo_val <= hi_val {
                    lo = mid;
                    lo_point = Some(point);
                } else {
                    hi = mid;
                    hi_point = Some(point);
                }
            }
            None => match (lo_point.as_ref(), hi_point.as_ref()) {
                (Some(_), Some(_)) => {
                    let lo_val = lo_point.as_ref().map(|p| p.value).unwrap_or(0);
                    let hi_val = hi_point.as_ref().map(|p| p.value).unwrap_or(0);
                    if lo_val <= hi_val {
                        lo = mid;
                    } else {
                        hi = mid;
                    }
                }
                (Some(_), None) => hi = mid,
                (None, Some(_)) => lo = mid,
                (None, None) => break,
            },
        }
    }

    Ok(Some(best))
}

/// Aggregate net output of a set of quoted legs, or `None` when inconsistent.
fn aggregate_net(legs: &[LegState]) -> Option<u128> {
    let deltas: Vec<NetDelta> = legs.iter().map(|leg| leg.quote.net_delta.clone()).collect();
    NetDelta::aggregate(&deltas)
        .ok()
        .map(|delta| delta.net_output.amount.get())
}

/// Aggregate net output with one leg's quote replaced by a probe.
fn aggregate_net_with(
    legs: &[LegState],
    a: usize,
    a_quote: &RouteQuote,
    b: usize,
    b_quote: &RouteQuote,
) -> Option<u128> {
    let mut deltas: Vec<NetDelta> = Vec::with_capacity(legs.len());
    for (index, leg) in legs.iter().enumerate() {
        if index == a {
            deltas.push(a_quote.net_delta.clone());
        } else if index == b {
            deltas.push(b_quote.net_delta.clone());
        } else {
            deltas.push(leg.quote.net_delta.clone());
        }
    }
    NetDelta::aggregate(&deltas)
        .ok()
        .map(|delta| delta.net_output.amount.get())
}

/// Deterministic best-first order over split candidates.
fn compare_candidates(left: &CandidateWithPaths, right: &CandidateWithPaths) -> Ordering {
    right
        .candidate
        .net_output
        .amount
        .get()
        .cmp(&left.candidate.net_output.amount.get())
        .then_with(|| left.candidate.legs.len().cmp(&right.candidate.legs.len()))
        .then_with(|| {
            left.candidate
                .canonical_key
                .cmp(&right.candidate.canonical_key)
        })
}

/// Plans the best bounded split from the same candidate set as
/// [`crate::plan_single_path`].
///
/// The incumbent single path is always verified through the locked single-route
/// bridge. A split is only returned after the locked aggregate bridge accepted
/// it; otherwise the incumbent is returned, and if neither validates the call
/// fails closed with [`RoutingError::SelectedRejected`].
pub fn plan_split(
    req: &RouteRequest<'_>,
    config: &SplitConfig,
) -> Result<SplitDecision, RoutingError> {
    // Phase 0: request validation, mirroring `plan_single_path`.
    if req.intent.token_in == req.intent.token_out {
        return Err(RoutingError::SameAssetPair);
    }
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
    config.validate(req.intent)?;
    quote::validate_assessment(req)?;

    let total = req.amount_in.get();
    let candidate_set = enumerate_candidates(req.intent, req.max_hops, req.descriptors)?;

    let mut budget_used: usize = 0;
    let mut failures: Vec<RoutingError> = Vec::new();
    let mut baseline: Vec<SingleBaseline> = Vec::new();

    for path in &candidate_set.paths {
        charge_budget(&mut budget_used)?;
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
        let scored = match score::build_score(
            req.intent,
            &quote,
            req.scoring,
            gas_cost.clone(),
            req.now_ms,
        ) {
            Ok(score) => score,
            Err(error) => {
                failures.push(error);
                continue;
            }
        };
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
        baseline.push(SingleBaseline {
            path: path.clone(),
            scored: ScoredRoute {
                quote,
                score: scored,
            },
            net_after_gas: net_after,
        });
    }

    if baseline.is_empty() {
        return Err(crate::aggregate_failure(&failures));
    }

    baseline.sort_by(|left, right| {
        score::compare_scored(
            &left.scored,
            left.net_after_gas,
            None,
            &right.scored,
            right.net_after_gas,
            None,
        )
    });

    let incumbent_net = match baseline[0].net_after_gas {
        Some(value) => value,
        None => baseline[0].scored.quote.net_output.amount.get(),
    };

    // Verify singles in best-first order for the fallback incumbent.
    let mut incumbent: Option<ScoredRoute> = None;
    let mut first_reject: Option<BridgeRejectClass> = None;
    for entry in &baseline {
        match crate::validate_delta_preview_with_assessment(
            req.intent,
            &entry.scored.quote.plan,
            &entry.scored.quote.net_delta,
            req.assessment,
            req.now_ms,
        ) {
            Ok(_) => {
                incumbent = Some(entry.scored.clone());
                break;
            }
            Err(error) => {
                if first_reject.is_none() {
                    first_reject = Some(BridgeRejectClass::from_bridge_error(&error));
                }
            }
        }
    }

    const TOP_LIMIT: usize = MAX_SPLIT_PAIRS;
    let top: Vec<SingleBaseline> = baseline.iter().take(TOP_LIMIT).cloned().collect();

    let mut split_candidates: Vec<CandidateWithPaths> = Vec::new();
    let pool_sets: Vec<Vec<&str>> = top
        .iter()
        .map(|entry| path_pool_refs(req.descriptors, &entry.path))
        .collect();

    // Phase 1: continuous two-path search over the top single paths.
    for i in 0..top.len() {
        for j in (i + 1)..top.len() {
            if pools_overlap(&pool_sets[i], &pool_sets[j]) {
                continue;
            }
            let Some(point) = best_two_path(
                req,
                total,
                &top[i].path,
                &top[j].path,
                config,
                &mut budget_used,
            )?
            else {
                continue;
            };
            let legs = vec![
                (point.x, point.left.clone()),
                (total - point.x, point.right.clone()),
            ];
            let Some(candidate) = build_split_quote(req, &legs, config)? else {
                continue;
            };
            if split_improves(
                split_primary_net(&candidate, req.gas_price_in_output.as_ref())?,
                incumbent_net,
                config.min_split_improvement_bps.get(),
            ) {
                split_candidates.push(CandidateWithPaths {
                    candidate,
                    paths: vec![i, j],
                });
            }
        }
    }

    split_candidates.sort_by(compare_candidates);

    // Phase 3: pairwise extension to 3..=max_legs started from the best two-path
    // split. Each adopted extension strictly improves the current aggregate and
    // clears the same gate against the incumbent.
    if let Some(base) = split_candidates.first().cloned() {
        let mut current_legs: Vec<LegState> = base
            .paths
            .iter()
            .zip(&base.candidate.legs)
            .map(|(index, leg)| LegState {
                top_index: *index,
                budget: leg.amount_in.get(),
                quote: leg.quote.clone(),
            })
            .collect();
        let mut current_net = base.candidate.net_output.amount.get();

        loop {
            let target = current_legs.len() + 1;
            if target > config.max_legs {
                break;
            }
            let mut adopted_any = false;

            for p in 0..top.len() {
                // `current_legs` can grow inside this loop, so the hard branch cap
                // must be re-checked before every extension attempt.
                if current_legs.len() >= config.max_legs {
                    break;
                }
                if current_legs.iter().any(|leg| leg.top_index == p) {
                    continue;
                }
                if current_legs
                    .iter()
                    .any(|leg| pools_overlap(&pool_sets[leg.top_index], &pool_sets[p]))
                {
                    continue;
                }
                let n = current_legs.len();
                let mut scaled_sum: u128 = 0;
                let mut scaled: Vec<u128> = Vec::with_capacity(n);
                let mut scale_ok = true;
                for leg in &current_legs {
                    let value = mul_div_floor(leg.budget, n as u128, (n + 1) as u128)?;
                    match scaled_sum.checked_add(value) {
                        Some(sum) => {
                            scaled_sum = sum;
                            scaled.push(value);
                        }
                        None => {
                            scale_ok = false;
                            break;
                        }
                    }
                }
                if !scale_ok {
                    continue;
                }
                let Some(new_budget) = total.checked_sub(scaled_sum) else {
                    continue;
                };
                if new_budget < config.min_leg_input.get() {
                    continue;
                }

                let mut trial: Vec<LegState> = Vec::with_capacity(n + 1);
                let mut trial_ok = true;
                for (leg, budget) in current_legs.iter().zip(&scaled) {
                    match try_quote_branch(
                        req,
                        &top[leg.top_index].path,
                        AtomicAmount::new(*budget),
                        &mut budget_used,
                    )? {
                        Some(quote) if passes_dust(*budget, &quote, config)? => {
                            trial.push(LegState {
                                top_index: leg.top_index,
                                budget: *budget,
                                quote,
                            });
                        }
                        _ => {
                            trial_ok = false;
                            break;
                        }
                    }
                }
                if !trial_ok {
                    continue;
                }
                match try_quote_branch(
                    req,
                    &top[p].path,
                    AtomicAmount::new(new_budget),
                    &mut budget_used,
                )? {
                    Some(quote) if passes_dust(new_budget, &quote, config)? => {
                        trial.push(LegState {
                            top_index: p,
                            budget: new_budget,
                            quote,
                        });
                    }
                    _ => continue,
                }

                // Coordinate ascent: move budget between branch pairs while the
                // aggregate strictly increases and every branch clears dust.
                let mut trial_net = match aggregate_net(&trial) {
                    Some(value) => value,
                    None => continue,
                };
                for _ in 0..MAX_SPLIT_REFINE_STEPS {
                    let mut accepted = false;
                    for a in 0..trial.len() {
                        for b in 0..trial.len() {
                            if a == b {
                                continue;
                            }
                            let quantum = (trial[a].budget / 8).max(config.min_leg_input.get());
                            if trial[a].budget <= quantum {
                                continue;
                            }
                            let new_a = trial[a].budget - quantum;
                            let Some(new_b) = trial[b].budget.checked_add(quantum) else {
                                continue;
                            };
                            let Some(a_quote) = try_quote_branch(
                                req,
                                &top[trial[a].top_index].path,
                                AtomicAmount::new(new_a),
                                &mut budget_used,
                            )?
                            else {
                                continue;
                            };
                            let Some(b_quote) = try_quote_branch(
                                req,
                                &top[trial[b].top_index].path,
                                AtomicAmount::new(new_b),
                                &mut budget_used,
                            )?
                            else {
                                continue;
                            };
                            if !passes_dust(new_a, &a_quote, config)?
                                || !passes_dust(new_b, &b_quote, config)?
                            {
                                continue;
                            }
                            let Some(probe_net) =
                                aggregate_net_with(&trial, a, &a_quote, b, &b_quote)
                            else {
                                continue;
                            };
                            if probe_net > trial_net {
                                trial[a].budget = new_a;
                                trial[a].quote = a_quote;
                                trial[b].budget = new_b;
                                trial[b].quote = b_quote;
                                trial_net = probe_net;
                                accepted = true;
                            }
                        }
                    }
                    if !accepted {
                        break;
                    }
                }

                if trial_net <= current_net {
                    continue;
                }

                let legs: Vec<(u128, RouteQuote)> = trial
                    .iter()
                    .map(|leg| (leg.budget, leg.quote.clone()))
                    .collect();
                let Some(candidate) = build_split_quote(req, &legs, config)? else {
                    continue;
                };
                if candidate.net_output.amount.get() != trial_net {
                    continue;
                }
                if !split_improves(
                    split_primary_net(&candidate, req.gas_price_in_output.as_ref())?,
                    incumbent_net,
                    config.min_split_improvement_bps.get(),
                ) {
                    continue;
                }
                let paths: Vec<usize> = trial.iter().map(|leg| leg.top_index).collect();
                split_candidates.push(CandidateWithPaths { candidate, paths });
                current_legs = trial;
                current_net = trial_net;
                adopted_any = true;
            }

            if !adopted_any {
                break;
            }
        }
    }

    split_candidates.sort_by(compare_candidates);

    // Phase 4: fail-closed aggregate validation. `candidates` holds only the
    // verified split plans, best first.
    let mut verified: Vec<SplitQuote> = Vec::new();
    let mut split_reject: Option<BridgeRejectClass> = None;
    for candidate in &split_candidates {
        let branch_deltas: Vec<NetDelta> = candidate
            .candidate
            .legs
            .iter()
            .map(|leg| leg.quote.net_delta.clone())
            .collect();
        match validate_split_delta_preview_with_assessment(
            req.intent,
            &candidate.candidate.split,
            &branch_deltas,
            req.assessment,
            req.now_ms,
        ) {
            Ok(_) => verified.push(candidate.candidate.clone()),
            Err(error) => {
                if split_reject.is_none() {
                    split_reject = Some(BridgeRejectClass::from_bridge_error(&error));
                }
            }
        }
    }

    let selected = verified.first().cloned();
    if selected.is_none() && incumbent.is_none() {
        let class = split_reject
            .or(first_reject)
            .unwrap_or(BridgeRejectClass::Domain);
        return Err(RoutingError::SelectedRejected(class));
    }

    Ok(SplitDecision {
        candidates: verified,
        selected,
        incumbent,
        truncated: candidate_set.truncated,
    })
}
