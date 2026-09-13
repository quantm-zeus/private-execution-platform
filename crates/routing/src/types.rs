//! Public routing inputs, candidate envelope, and evaluated path types.

use chain_types::AssetId;
use domain::{RoutePlan, RouteScore, TradeIntent};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, PoolKindState};
use serde::{Deserialize, Serialize};
use tax_engine::TaxAssessment;

/// Swap direction within a two-token pool relative to the input asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDir {
    /// `token_0` is the input and `token_1` is the output.
    ZeroForOne,
    /// `token_1` is the input and `token_0` is the output.
    OneForZero,
}

/// Adapter-neutral candidate pool offered to the direct-route planner.
///
/// Carries the injected pool state, deterministic freshness metadata, and the
/// scoring/risk telemetry used to build a [`RouteScore`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolCandidate {
    pub venue: String,
    pub pool_ref: String,
    pub state: PoolKindState,
    pub freshness: Freshness,
    pub price_impact_bps: Bps,
    pub expected_slippage_bps: Bps,
    pub mev_risk_bps: Bps,
    pub failure_probability_bps: Bps,
    pub provider_reliability_bps: Bps,
    pub latency_ms: u64,
}

/// Bounded direct-route planner configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Maximum number of candidates the planner will consider in one call.
    pub max_candidates: usize,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self { max_candidates: 64 }
    }
}

/// Fully injected, deterministic direct-route planning input.
pub struct RoutingInput<'a> {
    pub intent: &'a TradeIntent,
    pub candidates: &'a [PoolCandidate],
    pub tax: Option<&'a TaxAssessment>,
    pub now_ms: i64,
    pub freshness_policy: &'a FreshnessPolicy,
    pub config: &'a RoutingConfig,
}

/// Deterministically simulated single-hop leg economics.
///
/// `gross_output` is the pre-output-tax pool output; `net_output` is what the
/// route receives after output-side tax. `dex_fee` and `tax_cost` are `None`
/// when exactly zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedLeg {
    pub venue: String,
    pub pool_ref: String,
    pub token_in: AssetId,
    pub token_out: AssetId,
    pub amount_in: AtomicAmount,
    pub expected_amount_out: AtomicAmount,
    pub gross_output: AtomicAmount,
    pub net_output: AtomicAmount,
    pub dex_fee: Option<AssetAmount>,
    pub tax_cost: Option<AssetAmount>,
}

/// Deterministically evaluated single-hop path plus the freshness it was built from.
///
/// The `freshness` field is an implementation adaptation of the slice sketch:
/// [`RoutePlan::state`] requires a full [`Freshness`] value, while the plan's
/// `state_age_ms` alone cannot reconstruct `chain_height`/`sequence`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedPath {
    pub legs: Vec<EvaluatedLeg>,
    pub gross_output: AssetAmount,
    pub net_output: AssetAmount,
    pub dex_fee: Option<AssetAmount>,
    pub tax_cost: Option<AssetAmount>,
    pub state_age_ms: u64,
    pub freshness: Freshness,
}

/// Winning route decision: the evaluated path, its redacted score, and the
/// validated [`RoutePlan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub winner: EvaluatedPath,
    pub score: RouteScore,
    pub plan: RoutePlan,
}
