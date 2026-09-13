//! Exact-input crossing composition across one or two pool hops.
//!
//! Each hop dispatches to the landed CPMM/CLMM/Bin exact-input kernels with a
//! directed request asserting the expected output asset. Buy/sell tax is applied
//! at the route boundary exclusively through
//! [`TaxAssessment::apply_buy_tax`] / [`TaxAssessment::apply_sell_tax_to_input`],
//! so the bps floor arithmetic is never re-implemented here. The composed result
//! is projected into the locked [`domain::RoutePlan`] and
//! [`execution_preview::NetDelta`] contracts, both of which are validated before
//! the quote is returned.

use chain_types::AssetId;
use domain::{RouteLeg, RoutePlan, TradeSide};
use execution_preview::NetDelta;
use market_types::{
    evaluate_freshness, AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy,
    FreshnessStatus, PoolKindState, PoolStateEnvelope, Sequence,
};
use serde::{Deserialize, Serialize};
use simulation::{
    simulate_bin_exact_input, simulate_clmm_exact_input, simulate_cpmm_exact_input,
    BinExactInputRequest, ClmmExactInputRequest, CpmmExactInputRequest,
};
use tax_engine::{assessed_asset_for_intent, TaxSafetyError};

use crate::error::RoutingError;
use crate::graph::{CandidatePath, PoolDescriptor};
use crate::impact::{combine_impacts, cpmm_impact_bps};
use crate::RouteRequest;

/// Coarse, payload-free pool class used by hop quotes and error classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKindClass {
    /// Constant-product pool.
    Cpmm,
    /// Concentrated-liquidity pool.
    Clmm,
    /// Bin / DLMM pool.
    Bin,
}

impl std::fmt::Display for PoolKindClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Cpmm => "cpmm",
            Self::Clmm => "clmm",
            Self::Bin => "bin",
        };
        f.write_str(label)
    }
}

/// Deterministically simulated single-hop economics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopQuote {
    /// Router/venue id for the hop.
    pub venue: String,
    /// Pool account or program id for the hop.
    pub pool_ref: String,
    /// Directed input asset.
    pub token_in: AssetId,
    /// Directed output asset.
    pub token_out: AssetId,
    /// Exact input consumed by this pool.
    pub amount_in: AtomicAmount,
    /// Exact pre-output-tax output produced by this pool.
    pub amount_out: AtomicAmount,
    /// Input-side pool fee, `None` when exactly zero.
    pub fee: Option<AssetAmount>,
    /// Coarse pool class.
    pub kind: PoolKindClass,
    /// Price impact for this hop, `None` when unavailable (CLMM/Bin without override).
    pub impact_bps: Option<Bps>,
}

/// Fully composed and contract-validated linear route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteQuote {
    /// Locked contiguous route plan for the selected path.
    pub plan: RoutePlan,
    /// Locked full-wallet-debit net delta for the same path.
    pub net_delta: NetDelta,
    /// Per-hop exact economics in execution order.
    pub hop_quotes: Vec<HopQuote>,
    /// Pre-output-tax output asset and amount.
    pub gross_output: AssetAmount,
    /// Post-tax output asset and amount.
    pub net_output: AssetAmount,
    /// Route-level tax cost, `None` when exactly zero.
    pub tax_cost: Option<AssetAmount>,
    /// Maximum per-hop price impact, `None` when any hop lacks an impact model.
    pub route_impact_bps: Option<Bps>,
}

#[inline]
fn nonzero(amount: AssetAmount) -> Option<AssetAmount> {
    if amount.amount.is_zero() {
        None
    } else {
        Some(amount)
    }
}

/// Validates the caller-supplied assessment against the intent and both policies.
///
/// Fails closed on a chain/asset mismatch or when the assessment is not fresh
/// under either the caller policy or [`FreshnessPolicy::default`].
pub(crate) fn validate_assessment(req: &RouteRequest<'_>) -> Result<(), RoutingError> {
    let assessment = req.assessment;
    if assessment.chain != req.intent.chain {
        return Err(RoutingError::TaxAssessmentMismatch);
    }
    if assessment.assessed_asset != *assessed_asset_for_intent(req.intent) {
        return Err(RoutingError::TaxAssessmentMismatch);
    }
    if assessment.freshness.status != FreshnessStatus::Fresh {
        return Err(RoutingError::TaxAssessmentNotFresh);
    }
    // `evaluate_freshness` ignores the sequence unless a gap is flagged, so a
    // zero sequence must be rejected explicitly to mirror the pool-state gate.
    if assessment.freshness.sequence.is_zero() {
        return Err(RoutingError::TaxAssessmentNotFresh);
    }

    let caller_meta = evaluate_freshness(
        req.freshness_policy,
        assessment.freshness.observed_at_ms,
        req.now_ms,
        assessment.freshness.sequence,
        false,
    )
    .map_err(|_| RoutingError::Internal("assessment freshness evaluation failed"))?;
    if caller_meta.status != FreshnessStatus::Fresh {
        return Err(RoutingError::TaxAssessmentNotFresh);
    }

    let default_policy = FreshnessPolicy::default();
    let default_meta = evaluate_freshness(
        &default_policy,
        assessment.freshness.observed_at_ms,
        req.now_ms,
        assessment.freshness.sequence,
        false,
    )
    .map_err(|_| RoutingError::Internal("assessment freshness evaluation failed"))?;
    if default_meta.status != FreshnessStatus::Fresh {
        return Err(RoutingError::TaxAssessmentNotFresh);
    }

    Ok(())
}

fn map_tax_error(error: TaxSafetyError) -> RoutingError {
    match error {
        TaxSafetyError::StaleObservation | TaxSafetyError::ResyncRequired => {
            RoutingError::TaxAssessmentNotFresh
        }
        TaxSafetyError::AssessedAssetMismatch | TaxSafetyError::ChainMismatch => {
            RoutingError::TaxAssessmentMismatch
        }
        TaxSafetyError::ZeroNetOutput | TaxSafetyError::ZeroGrossOutput => {
            RoutingError::ZeroNetOutput
        }
        // A zero post-tax input is a zero effective hop input, not a zero output.
        TaxSafetyError::ZeroNetInput | TaxSafetyError::ZeroGrossInput => {
            RoutingError::ZeroHopOutput
        }
        other => RoutingError::Tax(other),
    }
}

/// Composes one candidate path into a validated [`RouteQuote`].
///
/// The candidate is rejected (never panicking) if a used pool is stale under
/// either policy, a hop outputs zero, a cost or amount overflows, the route
/// impact is required but unavailable, or the composed contracts fail.
pub(crate) fn quote_path(
    req: &RouteRequest<'_>,
    descriptors: &[PoolDescriptor],
    path: &CandidatePath,
) -> Result<RouteQuote, RoutingError> {
    let intent = req.intent;

    if path.legs.is_empty() {
        return Err(RoutingError::Internal("candidate path has no legs"));
    }

    // Freshness gate: every used pool must be usable under both policies.
    let mut observed_min = i64::MAX;
    let mut sequence_min: Option<Sequence> = None;
    for leg in &path.legs {
        let descriptor = descriptors
            .get(leg.descriptor_index)
            .ok_or(RoutingError::Internal(
                "candidate descriptor index out of range",
            ))?;
        check_envelope_freshness(&descriptor.envelope, req.freshness_policy, req.now_ms)?;
        observed_min = observed_min.min(descriptor.envelope.observed_at_ms);
        let sequence = descriptor.envelope.sequence;
        sequence_min = Some(match sequence_min {
            Some(current) if current.get() <= sequence.get() => current,
            _ => sequence,
        });
    }
    let sequence = sequence_min.ok_or(RoutingError::Internal("candidate has no used pools"))?;

    // Input-side sell tax is applied before the first hop.
    let mut input_tax_cost: Option<AssetAmount> = None;
    let mut amount = req.amount_in;
    if intent.side == TradeSide::Sell {
        let gross_input = AssetAmount {
            asset: intent.token_in.clone(),
            amount: req.amount_in,
        };
        let taxed = req
            .assessment
            .apply_sell_tax_to_input(&gross_input)
            .map_err(map_tax_error)?;
        input_tax_cost = nonzero(taxed.tax_cost.clone());
        amount = taxed.net_transferable_input.amount;
    }
    if amount.is_zero() {
        return Err(RoutingError::ZeroHopOutput);
    }

    // Exact-in hop composition.
    let mut hop_quotes: Vec<HopQuote> = Vec::with_capacity(path.legs.len());
    let mut impacts: Vec<Option<Bps>> = Vec::with_capacity(path.legs.len());
    let mut current = amount;
    for leg in &path.legs {
        let descriptor = descriptors
            .get(leg.descriptor_index)
            .ok_or(RoutingError::Internal(
                "candidate descriptor index out of range",
            ))?;
        let hop = simulate_hop(descriptor, &leg.token_in, &leg.token_out, current)?;
        if hop.amount_out.is_zero() {
            return Err(RoutingError::ZeroHopOutput);
        }
        hop_quotes.push(HopQuote {
            venue: descriptor.venue.as_str().to_string(),
            pool_ref: descriptor.leg_pool_ref.as_str().to_string(),
            token_in: leg.token_in.clone(),
            token_out: leg.token_out.clone(),
            amount_in: current,
            amount_out: hop.amount_out,
            fee: hop.fee,
            kind: hop.kind,
            impact_bps: hop.impact_bps,
        });
        impacts.push(hop.impact_bps);
        current = hop.amount_out;
    }

    let route_impact = combine_impacts(&impacts);
    if intent.risk.max_price_impact.get() != 0 {
        match route_impact {
            None => return Err(RoutingError::ImpactUnavailable),
            Some(impact) if impact.get() > intent.risk.max_price_impact.get() => {
                return Err(RoutingError::ImpactExceedsCap);
            }
            Some(_) => {}
        }
    }

    // Output-side buy tax is applied after the final hop.
    let (gross_amount, net_amount, tax_cost) = match intent.side {
        TradeSide::Buy => {
            let gross = AssetAmount {
                asset: intent.token_out.clone(),
                amount: current,
            };
            let taxed = req
                .assessment
                .apply_buy_tax(&gross)
                .map_err(map_tax_error)?;
            (
                current,
                taxed.net_output.amount,
                nonzero(taxed.tax_cost.clone()),
            )
        }
        TradeSide::Sell => (current, current, input_tax_cost),
    };
    if net_amount.is_zero() {
        return Err(RoutingError::ZeroNetOutput);
    }

    // `dex_fee` is only representable when a single input-denominated hop exists.
    let dex_fee = if path.legs.len() == 1 {
        hop_quotes.first().and_then(|hop| hop.fee.clone())
    } else {
        None
    };

    let mut legs = Vec::with_capacity(hop_quotes.len());
    let mut leg_input = amount;
    for hop in &hop_quotes {
        legs.push(RouteLeg {
            venue: hop.venue.clone(),
            pool_ref: hop.pool_ref.clone(),
            token_in: hop.token_in.clone(),
            token_out: hop.token_out.clone(),
            amount_in: leg_input,
            expected_amount_out: hop.amount_out,
        });
        leg_input = hop.amount_out;
    }

    let gross_output = AssetAmount {
        asset: intent.token_out.clone(),
        amount: gross_amount,
    };
    let net_output = AssetAmount {
        asset: intent.token_out.clone(),
        amount: net_amount,
    };

    let plan = RoutePlan {
        legs,
        expected_net_output: net_output.clone(),
        state: Freshness {
            observed_at_ms: observed_min,
            chain_height: 0,
            sequence,
        },
    };
    plan.validate()?;

    let net_delta = NetDelta {
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: req.amount_in,
        },
        gross_output: gross_output.clone(),
        net_output: net_output.clone(),
        dex_fee,
        tax_cost: tax_cost.clone(),
    };
    net_delta
        .validate()
        .map_err(|_| RoutingError::Internal("composed net delta failed validation"))?;

    Ok(RouteQuote {
        plan,
        net_delta,
        hop_quotes,
        gross_output,
        net_output,
        tax_cost,
        route_impact_bps: route_impact,
    })
}

struct SimulatedHop {
    amount_out: AtomicAmount,
    fee: Option<AssetAmount>,
    kind: PoolKindClass,
    impact_bps: Option<Bps>,
}

fn simulate_hop(
    descriptor: &PoolDescriptor,
    token_in: &AssetId,
    token_out: &AssetId,
    amount_in: AtomicAmount,
) -> Result<SimulatedHop, RoutingError> {
    match &descriptor.envelope.state {
        PoolKindState::Cpmm(pool) => {
            let request =
                CpmmExactInputRequest::new_directed(token_in.clone(), amount_in, token_out.clone());
            let quote = simulate_cpmm_exact_input(pool, &request)
                .map_err(|_| RoutingError::HopSimulationFailed(PoolKindClass::Cpmm))?;
            let impact = cpmm_impact_bps(
                quote.effective_input.amount.get(),
                quote.resulting_reserve_in.get(),
                amount_in.get(),
            );
            Ok(SimulatedHop {
                amount_out: quote.output.amount,
                fee: nonzero(quote.pool_fee.clone()),
                kind: PoolKindClass::Cpmm,
                impact_bps: impact,
            })
        }
        PoolKindState::Clmm(pool) => {
            let request = ClmmExactInputRequest {
                token_in: token_in.clone(),
                amount_in,
                token_out: Some(token_out.clone()),
            };
            let quote = simulate_clmm_exact_input(pool, &request)
                .map_err(|_| RoutingError::HopSimulationFailed(PoolKindClass::Clmm))?;
            Ok(SimulatedHop {
                amount_out: quote.output.amount,
                fee: nonzero(quote.fee.clone()),
                kind: PoolKindClass::Clmm,
                impact_bps: descriptor.impact_override_bps,
            })
        }
        PoolKindState::Bin(pool) => {
            let request =
                BinExactInputRequest::new_directed(token_in.clone(), amount_in, token_out.clone());
            let quote = simulate_bin_exact_input(pool, &request)
                .map_err(|_| RoutingError::HopSimulationFailed(PoolKindClass::Bin))?;
            Ok(SimulatedHop {
                amount_out: quote.output.amount,
                fee: nonzero(quote.fee.clone()),
                kind: PoolKindClass::Bin,
                impact_bps: descriptor.impact_override_bps,
            })
        }
    }
}

/// Freshness gate for a single pool envelope under caller and default policies.
fn check_envelope_freshness(
    envelope: &PoolStateEnvelope,
    caller_policy: &FreshnessPolicy,
    now_ms: i64,
) -> Result<(), RoutingError> {
    if envelope.sequence.is_zero() {
        return Err(RoutingError::ResyncRequired);
    }
    if envelope.observed_at_ms <= 0 {
        return Err(RoutingError::StalePoolState);
    }

    let default_policy = FreshnessPolicy::default();
    for policy in [caller_policy, &default_policy] {
        let meta = evaluate_freshness(
            policy,
            envelope.observed_at_ms,
            now_ms,
            envelope.sequence,
            false,
        )
        .map_err(|_| RoutingError::Internal("pool freshness evaluation failed"))?;
        match meta.status {
            FreshnessStatus::Fresh => {}
            FreshnessStatus::Stale => return Err(RoutingError::StalePoolState),
            FreshnessStatus::ResyncRequired => return Err(RoutingError::ResyncRequired),
        }
    }
    Ok(())
}
