//! Shared deterministic fixtures for the R1 routing integration tests.
//!
//! This module is included by each integration test binary via `mod common;`.
//! It contains no clock, RPC, or randomness: every timestamp and sequence is a
//! literal so the tests are byte-stable.

#![allow(dead_code)]

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeIntent, TradeSide,
    TradeSource, UserId, WalletRef,
};
use market_types::{
    AssetAmount, AtomicAmount, BinPoolState, Bps, ClmmPoolState, ClmmTick, CpmmPoolState,
    FreshnessPolicy, FreshnessStatus, LiquidityBin, PoolId, PoolKindState, PoolStateEnvelope,
    SafeFreshnessMeta, Sequence,
};
use routing::{
    GasConversion, GasEstimator, PoolDescriptor, PoolRefLabel, RouteRequest, RoutingError,
    ScoringInputs, VenueLabel,
};
use tax_engine::TaxAssessment;

pub const NOW_MS: i64 = 1_000_000;
pub const CALLER_STALENESS_MS: u64 = 60_000;
pub const FUTURE_SKEW_MS: u64 = 2_000;

pub fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid base asset")
}

pub fn solana_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Solana, address).expect("valid solana asset")
}

pub fn usdc() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000001")
}

pub fn weth() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000002")
}

pub fn token2() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000003")
}

pub fn another_token() -> AssetId {
    base_asset("0x00000000000000000000000000000000000000aa")
}

pub fn native_gas() -> AssetId {
    base_asset("0x00000000000000000000000000000000000000ee")
}

pub fn caller_policy() -> FreshnessPolicy {
    FreshnessPolicy::new(CALLER_STALENESS_MS, FUTURE_SKEW_MS).expect("valid caller policy")
}

pub fn scoring() -> ScoringInputs {
    ScoringInputs {
        expected_slippage_bps: Bps::new(20).expect("bps"),
        mev_risk_bps: Bps::new(5).expect("bps"),
        failure_probability_bps: Bps::new(1).expect("bps"),
        provider_reliability_bps: Bps::new(9_900).expect("bps"),
        latency_ms: 42,
    }
}

pub fn cpmm(
    token_0: AssetId,
    token_1: AssetId,
    reserve_0: u128,
    reserve_1: u128,
    fee_bps: u16,
) -> CpmmPoolState {
    CpmmPoolState {
        token_0,
        token_1,
        decimals_0: 18,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(reserve_0),
        reserve_1: AtomicAmount::new(reserve_1),
        total_lp_supply: None,
        fee_bps: Bps::new(fee_bps).expect("fee bps"),
    }
}

/// Valid single-range CLMM pool mirroring the landed simulation sample.
pub fn clmm(token_0: AssetId, token_1: AssetId) -> ClmmPoolState {
    ClmmPoolState {
        token_0,
        token_1,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: 18_476_281_010_653_910_144,
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(30).expect("fee bps"),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    }
}

/// Valid zero-fee Bin/DLMM pool (`{0: (0, 3000), 1: (1000, 2000)}`, active 1).
pub fn bin(token_0: AssetId, token_1: AssetId) -> BinPoolState {
    BinPoolState {
        token_0,
        token_1,
        decimals_0: 0,
        decimals_1: 0,
        active_bin_id: 1,
        bin_step: 100,
        fee_bps: Bps::new(0).expect("fee bps"),
        bins: vec![
            LiquidityBin::new(0, AtomicAmount::new(0), AtomicAmount::new(3_000)),
            LiquidityBin::new(1, AtomicAmount::new(1_000), AtomicAmount::new(2_000)),
        ],
    }
}

pub fn descriptor_on(
    chain: ChainId,
    venue: &str,
    pool_ref: &str,
    state: PoolKindState,
    observed_at_ms: i64,
    sequence: u64,
    impact_override_bps: Option<u16>,
) -> PoolDescriptor {
    PoolDescriptor {
        envelope: PoolStateEnvelope {
            pool_id: PoolId::new(chain, pool_ref).expect("valid pool id"),
            sequence: Sequence(sequence),
            observed_at_ms,
            state,
        },
        venue: VenueLabel::new(venue).expect("valid venue"),
        leg_pool_ref: PoolRefLabel::new(pool_ref).expect("valid pool ref"),
        impact_override_bps: impact_override_bps.map(|bps| Bps::new(bps).expect("bps")),
    }
}

pub fn descriptor(
    venue: &str,
    pool_ref: &str,
    state: PoolKindState,
    observed_at_ms: i64,
    sequence: u64,
    impact_override_bps: Option<u16>,
) -> PoolDescriptor {
    descriptor_on(
        ChainId::Base,
        venue,
        pool_ref,
        state,
        observed_at_ms,
        sequence,
        impact_override_bps,
    )
}

pub fn fresh_descriptor(venue: &str, pool_ref: &str, state: PoolKindState) -> PoolDescriptor {
    descriptor(venue, pool_ref, state, NOW_MS, 1, None)
}

pub fn risk(max_price_impact_bps: u16) -> RiskConstraints {
    RiskConstraints {
        max_buy_tax: Bps::new(10_000).expect("bps"),
        max_sell_tax: Bps::new(10_000).expect("bps"),
        max_price_impact: Bps::new(max_price_impact_bps).expect("bps"),
        max_slippage: Bps::new(500).expect("bps"),
        max_total_cost: None,
    }
}

pub fn intent_with_risk(
    side: TradeSide,
    token_in: AssetId,
    token_out: AssetId,
    amount: u128,
    risk: RiskConstraints,
) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("id"),
        source: TradeSource::Internal,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: token_in.chain.clone(),
        token_in,
        token_out,
        side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
        order_type: OrderType::Market,
        limit_price: None,
        risk,
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

pub fn buy(token_in: AssetId, token_out: AssetId, amount: u128) -> TradeIntent {
    intent_with_risk(TradeSide::Buy, token_in, token_out, amount, risk(500))
}

pub fn sell(token_in: AssetId, token_out: AssetId, amount: u128) -> TradeIntent {
    intent_with_risk(TradeSide::Sell, token_in, token_out, amount, risk(500))
}

pub fn assessment_at(
    chain: ChainId,
    asset: AssetId,
    buy_tax: u16,
    sell_tax: u16,
    observed_at_ms: i64,
    status: FreshnessStatus,
) -> TaxAssessment {
    TaxAssessment::new(
        asset,
        chain,
        Bps::new(buy_tax).expect("buy tax"),
        Bps::new(sell_tax).expect("sell tax"),
        SafeFreshnessMeta {
            status,
            observed_at_ms,
            evaluated_at_ms: observed_at_ms,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    )
}

pub fn assessment(asset: AssetId, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    assessment_at(
        ChainId::Base,
        asset,
        buy_tax,
        sell_tax,
        NOW_MS,
        FreshnessStatus::Fresh,
    )
}

pub fn zero_tax_for(intent: &TradeIntent) -> TaxAssessment {
    let assessed = match intent.side {
        TradeSide::Buy => intent.token_out.clone(),
        TradeSide::Sell => intent.token_in.clone(),
    };
    assessment_at(
        intent.chain.clone(),
        assessed,
        0,
        0,
        NOW_MS,
        FreshnessStatus::Fresh,
    )
}

/// Gas model charging a fixed per-hop amount denominated in `asset`.
pub struct FixedGas {
    pub asset: AssetId,
    pub per_hop: u128,
}

impl GasEstimator for FixedGas {
    fn estimate_gas(
        &self,
        _chain: &ChainId,
        hop_count: usize,
    ) -> Result<AssetAmount, RoutingError> {
        let amount = self.per_hop.saturating_mul(hop_count as u128);
        Ok(AssetAmount {
            asset: self.asset.clone(),
            amount: AtomicAmount::new(amount),
        })
    }
}

/// Builds a full [`RouteRequest`] borrowing the supplied fixtures.
#[allow(clippy::too_many_arguments)]
pub fn request<'a>(
    intent: &'a TradeIntent,
    descriptors: &'a [PoolDescriptor],
    amount_in: u128,
    assessment: &'a TaxAssessment,
    max_hops: usize,
    freshness_policy: &'a FreshnessPolicy,
    scoring_inputs: &'a ScoringInputs,
    gas: Option<&'a dyn GasEstimator>,
    gas_price_in_output: Option<GasConversion>,
) -> RouteRequest<'a> {
    request_with_depth(
        intent,
        descriptors,
        amount_in,
        assessment,
        max_hops,
        freshness_policy,
        scoring_inputs,
        gas,
        gas_price_in_output,
        &[],
    )
}

/// Like [`request`] but with an explicit depth-target list.
#[allow(clippy::too_many_arguments)]
pub fn request_with_depth<'a>(
    intent: &'a TradeIntent,
    descriptors: &'a [PoolDescriptor],
    amount_in: u128,
    assessment: &'a TaxAssessment,
    max_hops: usize,
    freshness_policy: &'a FreshnessPolicy,
    scoring_inputs: &'a ScoringInputs,
    gas: Option<&'a dyn GasEstimator>,
    gas_price_in_output: Option<GasConversion>,
    depth_targets: &'a [Bps],
) -> RouteRequest<'a> {
    RouteRequest {
        intent,
        descriptors,
        amount_in: AtomicAmount::new(amount_in),
        assessment,
        max_hops,
        now_ms: NOW_MS,
        freshness_policy,
        scoring: scoring_inputs,
        gas,
        gas_price_in_output,
        depth_targets,
    }
}
