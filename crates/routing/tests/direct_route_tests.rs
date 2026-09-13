//! Focused regression tests for the P43 exact direct-route planner.
//!
//! Cases mirror the slice specification: pinned CPMM Buy/Sell vectors, CLMM and
//! Bin direct legs, exact Bin tax composition, net-vs-gross ranking, fail-closed
//! rejection classes, determinism, and error redaction.

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, DomainError, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeIntent,
    TradeSide, TradeSource, UserId, WalletRef,
};
use market_types::{
    AssetAmount, AtomicAmount, BinPoolState, Bps, ClmmPoolState, ClmmTick, CpmmPoolState,
    Freshness, FreshnessPolicy, FreshnessStatus, LiquidityBin, PoolKindState, SafeFreshnessMeta,
    Sequence,
};
use routing::{
    plan_direct_route, select_best_path, simulate_leg, to_route_plan, EvaluatedLeg, EvaluatedPath,
    PoolCandidate, RoutingConfig, RoutingError, RoutingInput,
};
use simulation::{BinSimulationError, ClmmSimulationError, CpmmSimulationErrorClass};
use tax_engine::{TaxAssessment, TaxSafetyError};

const NOW_MS: i64 = 1_000_000;
const STALENESS_MS: u64 = 10_000;
const FUTURE_SKEW_MS: u64 = 2_000;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid base asset")
}

fn solana_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Solana, address).expect("valid solana asset")
}

fn base_token_0() -> AssetId {
    asset("0x0000000000000000000000000000000000000001")
}

fn base_token_1() -> AssetId {
    asset("0x0000000000000000000000000000000000000002")
}

fn other_token() -> AssetId {
    asset("0x00000000000000000000000000000000000000ff")
}

fn fresh_freshness() -> Freshness {
    Freshness {
        observed_at_ms: NOW_MS,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

fn freshness_at(observed_at_ms: i64) -> Freshness {
    Freshness {
        observed_at_ms,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

fn policy() -> FreshnessPolicy {
    FreshnessPolicy::new(STALENESS_MS, FUTURE_SKEW_MS).expect("valid policy")
}

fn config(max_candidates: usize) -> RoutingConfig {
    RoutingConfig { max_candidates }
}

fn risk() -> RiskConstraints {
    RiskConstraints {
        max_buy_tax: Bps::new(10_000).expect("bps"),
        max_sell_tax: Bps::new(10_000).expect("bps"),
        max_price_impact: Bps::new(500).expect("bps"),
        max_slippage: Bps::new(500).expect("bps"),
        max_total_cost: None,
    }
}

fn intent_with_chain(
    chain: ChainId,
    side: TradeSide,
    token_in: AssetId,
    token_out: AssetId,
    amount: u128,
) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("id"),
        source: TradeSource::Internal,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain,
        token_in,
        token_out,
        side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
        order_type: OrderType::Market,
        limit_price: None,
        risk: risk(),
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn base_intent(
    side: TradeSide,
    token_in: AssetId,
    token_out: AssetId,
    amount: u128,
) -> TradeIntent {
    intent_with_chain(ChainId::Base, side, token_in, token_out, amount)
}

fn candidate(
    venue: &str,
    pool_ref: &str,
    state: PoolKindState,
    freshness: Freshness,
) -> PoolCandidate {
    PoolCandidate {
        venue: venue.to_string(),
        pool_ref: pool_ref.to_string(),
        state,
        freshness,
        price_impact_bps: Bps::new(10).expect("bps"),
        expected_slippage_bps: Bps::new(20).expect("bps"),
        mev_risk_bps: Bps::new(5).expect("bps"),
        failure_probability_bps: Bps::new(1).expect("bps"),
        provider_reliability_bps: Bps::new(9_900).expect("bps"),
        latency_ms: 42,
    }
}

fn cpmm_pool(
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

/// Sample CLMM pool copied from `simulation/tests/clmm_tests.rs` (fee 30 bps).
fn sample_clmm_pool() -> ClmmPoolState {
    ClmmPoolState {
        token_0: solana_asset("So11111111111111111111111111111111111111112"),
        token_1: solana_asset("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
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

/// P37 vector-A Bin pool: `{0: (0, 3000), 1: (1000, 2000)}`, active 1, step 100, zero fee.
fn bin_pool_a(token_0: AssetId, token_1: AssetId) -> BinPoolState {
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

fn tax_assessment_on(chain: ChainId, asset: AssetId, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    TaxAssessment::new(
        asset,
        chain,
        Bps::new(buy_tax).expect("buy tax"),
        Bps::new(sell_tax).expect("sell tax"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: NOW_MS,
            evaluated_at_ms: NOW_MS,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    )
}

fn tax_assessment(asset: AssetId, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    tax_assessment_on(ChainId::Base, asset, buy_tax, sell_tax)
}

/// Zero-tax assessment bound to the intent's assessed asset.
///
/// The planner requires an explicit assessment, so untaxed-economics tests use
/// this fixture instead of `None`. The zero rates keep gross == net.
fn zero_tax_for(intent: &TradeIntent) -> TaxAssessment {
    let assessed = match intent.side {
        TradeSide::Buy => intent.token_out.clone(),
        TradeSide::Sell => intent.token_in.clone(),
    };
    tax_assessment_on(intent.chain.clone(), assessed, 0, 0)
}

fn plan_with<'a>(
    intent: &'a TradeIntent,
    candidates: &'a [PoolCandidate],
    tax: Option<&'a TaxAssessment>,
    policy: &'a FreshnessPolicy,
    config: &'a RoutingConfig,
) -> Result<routing::RouteDecision, RoutingError> {
    let input = RoutingInput {
        intent,
        candidates,
        tax,
        now_ms: NOW_MS,
        freshness_policy: policy,
        config,
    };
    plan_direct_route(&input)
}

// ---------------------------------------------------------------------------
// 1. Pinned CPMM direct Buy (zero tax)
// ---------------------------------------------------------------------------

#[test]
fn cpmm_direct_buy_zero_tax_is_pinned() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "uniswap_v2",
        "pool-cpmm-buy",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in.clone(), token_out.clone(), 10_000);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);

    let leg = simulate_leg(&candidate, &trade, trade.amount, None, &policy, NOW_MS).expect("leg");
    assert_eq!(leg.amount_in.get(), 10_000);
    assert_eq!(leg.gross_output.get(), 19_743);
    assert_eq!(leg.net_output.get(), 19_743);
    assert_eq!(leg.expected_amount_out.get(), 19_743);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(30),
        })
    );
    assert_eq!(leg.tax_cost, None);

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");

    assert_eq!(decision.winner.legs.len(), 1);
    assert_eq!(decision.plan.legs.len(), 1);
    assert_eq!(decision.plan.expected_net_output.amount.get(), 19_743);
    assert_eq!(decision.plan.expected_net_output.asset, token_out);
    assert!(decision.plan.validate().is_ok());
    assert_eq!(decision.plan.state, fresh_freshness());
    assert_eq!(decision.score.gross_output.amount.get(), 19_743);
    assert_eq!(decision.score.simulated_net_output.amount.get(), 19_743);
    assert_eq!(decision.score.price_impact, candidate.price_impact_bps);
    assert_eq!(
        decision.score.expected_slippage,
        candidate.expected_slippage_bps
    );
    assert_eq!(decision.score.mev_risk, candidate.mev_risk_bps);
    assert_eq!(
        decision.score.failure_probability,
        candidate.failure_probability_bps
    );
    assert_eq!(
        decision.score.provider_reliability,
        candidate.provider_reliability_bps
    );
    assert_eq!(decision.score.provider_fee, None);
    assert_eq!(decision.score.gas_cost, None);
    assert_eq!(decision.score.latency_ms, 42);
    assert_eq!(decision.score.state_age_ms, 0);
}

// ---------------------------------------------------------------------------
// 2. Pinned CPMM direct Sell with sell tax (input-side tax before swap)
// ---------------------------------------------------------------------------

#[test]
fn cpmm_direct_sell_with_sell_tax_is_pinned() {
    let token_out = base_token_0();
    let token_in = base_token_1();
    // R0 = 1_000_000 (token_0 = output), R1 = 2_000_000 (token_1 = sold input).
    let pool = cpmm_pool(
        token_out.clone(),
        token_in.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "uniswap_v2",
        "pool-cpmm-sell",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Sell, token_in.clone(), token_out.clone(), 10_000);
    let tax = tax_assessment(token_in.clone(), 0, 100);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    assert_eq!(leg.amount_in.get(), 9_900);
    assert_eq!(leg.gross_output.get(), 4_911);
    assert_eq!(leg.net_output.get(), 4_911);
    assert_eq!(leg.expected_amount_out.get(), 4_911);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(29),
        })
    );
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(100),
        })
    );

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 4_911);
    assert_eq!(decision.plan.expected_net_output.asset, token_out);
    assert_eq!(decision.plan.legs[0].amount_in.get(), 9_900);
    assert!(decision.plan.validate().is_ok());
    assert_eq!(
        decision.score.tax_cost.as_ref().expect("tax").amount.get(),
        100
    );
    assert_eq!(
        decision.score.dex_fee.as_ref().expect("fee").amount.get(),
        29
    );
}

// ---------------------------------------------------------------------------
// 3. CLMM direct using the sample pool (fee 300 on 100_000)
// ---------------------------------------------------------------------------

#[test]
fn clmm_direct_records_fee_and_net_equals_gross() {
    let pool = sample_clmm_pool();
    let token_in = pool.token_0.clone();
    let token_out = pool.token_1.clone();
    let candidate = candidate(
        "orca",
        "pool-clmm",
        PoolKindState::Clmm(pool),
        fresh_freshness(),
    );
    let trade = intent_with_chain(
        ChainId::Solana,
        TradeSide::Buy,
        token_in.clone(),
        token_out.clone(),
        100_000,
    );
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);

    let leg = simulate_leg(&candidate, &trade, trade.amount, None, &policy, NOW_MS).expect("leg");
    assert_eq!(leg.gross_output, leg.net_output);
    assert!(leg.net_output.get() > 0);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(300),
        })
    );
    assert_eq!(leg.tax_cost, None);

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.legs.len(), 1);
    assert_eq!(decision.winner.legs.len(), 1);
    assert_eq!(
        decision.score.simulated_net_output,
        decision.score.gross_output
    );
    assert!(decision.plan.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 4. Bin direct: P37 vector A (token_0 in 1010 -> 1020)
// ---------------------------------------------------------------------------

#[test]
fn bin_direct_vector_a_zero_tax() {
    let token_0 = base_token_0();
    let token_1 = base_token_1();
    let pool = bin_pool_a(token_0.clone(), token_1.clone());
    let candidate = candidate(
        "meteora",
        "pool-bin-a",
        PoolKindState::Bin(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_0.clone(), token_1.clone(), 1_010);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);

    let leg = simulate_leg(&candidate, &trade, trade.amount, None, &policy, NOW_MS).expect("leg");
    assert_eq!(leg.amount_in.get(), 1_010);
    assert_eq!(leg.gross_output.get(), 1_020);
    assert_eq!(leg.net_output.get(), 1_020);
    assert_eq!(leg.dex_fee, None);
    assert_eq!(leg.tax_cost, None);

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 1_020);
    assert!(decision.plan.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 5. Bin taxed Buy: buy tax applied to gross output, conservation asserted
// ---------------------------------------------------------------------------

#[test]
fn bin_buy_tax_composes_on_gross_output_with_conservation() {
    let token_0 = base_token_0();
    let token_1 = base_token_1();
    let pool = bin_pool_a(token_0.clone(), token_1.clone());
    let candidate = candidate(
        "meteora",
        "pool-bin-buy-tax",
        PoolKindState::Bin(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_0.clone(), token_1.clone(), 1_010);
    let tax = tax_assessment(token_1.clone(), 500, 0);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    // gross output 1020, buy tax floor(1020 * 500 / 10000) = 51, net = 969.
    assert_eq!(leg.gross_output.get(), 1_020);
    assert_eq!(leg.net_output.get(), 969);
    assert_eq!(leg.expected_amount_out.get(), 969);
    assert_eq!(leg.amount_in.get(), 1_010);
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_1.clone(),
            amount: AtomicAmount::new(51),
        })
    );
    assert_eq!(
        leg.gross_output.get(),
        leg.net_output.get() + leg.tax_cost.as_ref().expect("tax").amount.get()
    );

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 969);
    assert_eq!(decision.score.gross_output.amount.get(), 1_020);
    assert_eq!(decision.score.simulated_net_output.amount.get(), 969);
    assert_eq!(
        decision.score.tax_cost.as_ref().expect("tax").amount.get(),
        51
    );
    assert!(decision.plan.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 6. Bin taxed Sell: sell tax applied to gross input before the swap
// ---------------------------------------------------------------------------

#[test]
fn bin_sell_tax_composes_on_input_before_swap_with_conservation() {
    let token_0 = base_token_0();
    let token_1 = base_token_1();
    let pool = bin_pool_a(token_0.clone(), token_1.clone());
    let candidate = candidate(
        "meteora",
        "pool-bin-sell-tax",
        PoolKindState::Bin(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Sell, token_1.clone(), token_0.clone(), 1_010);
    let tax = tax_assessment(token_1.clone(), 0, 1_000);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    // sell tax floor(1010 * 1000 / 10000) = 101; net input 909 -> output 900.
    assert_eq!(leg.amount_in.get(), 909);
    assert_eq!(leg.gross_output.get(), 900);
    assert_eq!(leg.net_output.get(), 900);
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_1.clone(),
            amount: AtomicAmount::new(101),
        })
    );
    assert_eq!(
        leg.amount_in.get() + leg.tax_cost.as_ref().expect("tax").amount.get(),
        trade.amount.get()
    );
    assert_eq!(leg.dex_fee, None);
}

// ---------------------------------------------------------------------------
// 6b. Tax-aware CPMM Buy: buy tax applied to gross output, conservation asserted
// ---------------------------------------------------------------------------

#[test]
fn cpmm_buy_tax_composes_on_gross_output_with_conservation() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "uniswap_v2",
        "pool-cpmm-buy-tax",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in.clone(), token_out.clone(), 10_000);
    let tax = tax_assessment(token_out.clone(), 500, 0);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    // Gross output 19_743, buy tax floor(19_743 * 500 / 10_000) = 987, net 18_756.
    assert_eq!(leg.amount_in.get(), 10_000);
    assert_eq!(leg.gross_output.get(), 19_743);
    assert_eq!(leg.net_output.get(), 18_756);
    assert_eq!(leg.expected_amount_out.get(), 18_756);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(30),
        })
    );
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(987),
        })
    );
    assert_eq!(
        leg.gross_output.get(),
        leg.net_output.get() + leg.tax_cost.as_ref().expect("tax").amount.get()
    );

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 18_756);
    assert_eq!(decision.score.gross_output.amount.get(), 19_743);
    assert_eq!(decision.score.simulated_net_output.amount.get(), 18_756);
    assert_eq!(
        decision.score.tax_cost.as_ref().expect("tax").amount.get(),
        987
    );
    assert!(decision.plan.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 6c. Tax-aware CLMM Buy and Sell branches
// ---------------------------------------------------------------------------

#[test]
fn clmm_buy_tax_composes_on_gross_output_with_conservation() {
    let pool = sample_clmm_pool();
    let token_in = pool.token_0.clone();
    let token_out = pool.token_1.clone();
    let candidate = candidate(
        "orca",
        "pool-clmm-buy-tax",
        PoolKindState::Clmm(pool),
        fresh_freshness(),
    );
    let trade = intent_with_chain(
        ChainId::Solana,
        TradeSide::Buy,
        token_in.clone(),
        token_out.clone(),
        100_000,
    );
    let tax = tax_assessment_on(ChainId::Solana, token_out.clone(), 250, 0);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    // Gross 100_018, buy tax floor(100_018 * 250 / 10_000) = 2_500, net 97_518.
    assert_eq!(leg.amount_in.get(), 100_000);
    assert_eq!(leg.gross_output.get(), 100_018);
    assert_eq!(leg.net_output.get(), 97_518);
    assert_eq!(leg.expected_amount_out.get(), 97_518);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(300),
        })
    );
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(2_500),
        })
    );
    assert_eq!(
        leg.gross_output.get(),
        leg.net_output.get() + leg.tax_cost.as_ref().expect("tax").amount.get()
    );

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 97_518);
    assert_eq!(decision.score.gross_output.amount.get(), 100_018);
    assert!(decision.plan.validate().is_ok());
}

#[test]
fn clmm_sell_tax_composes_on_input_before_swap_with_conservation() {
    let pool = sample_clmm_pool();
    let token_in = pool.token_0.clone();
    let token_out = pool.token_1.clone();
    let candidate = candidate(
        "orca",
        "pool-clmm-sell-tax",
        PoolKindState::Clmm(pool),
        fresh_freshness(),
    );
    let trade = intent_with_chain(
        ChainId::Solana,
        TradeSide::Sell,
        token_in.clone(),
        token_out.clone(),
        100_000,
    );
    let tax = tax_assessment_on(ChainId::Solana, token_in.clone(), 0, 250);
    let policy = policy();

    let leg = simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&tax),
        &policy,
        NOW_MS,
    )
    .expect("leg");
    // Sell tax floor(100_000 * 250 / 10_000) = 2_500; net input 97_500 -> output 97_518.
    assert_eq!(leg.amount_in.get(), 97_500);
    assert_eq!(leg.gross_output.get(), 97_518);
    assert_eq!(leg.net_output.get(), 97_518);
    assert_eq!(leg.expected_amount_out.get(), 97_518);
    assert_eq!(
        leg.dex_fee,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(292),
        })
    );
    assert_eq!(
        leg.tax_cost,
        Some(AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(2_500),
        })
    );
    assert_eq!(
        leg.amount_in.get() + leg.tax_cost.as_ref().expect("tax").amount.get(),
        trade.amount.get()
    );

    let config = config(64);
    let decision = plan_with(
        &trade,
        std::slice::from_ref(&candidate),
        Some(&tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.plan.expected_net_output.amount.get(), 97_518);
    assert_eq!(decision.plan.legs[0].amount_in.get(), 97_500);
    assert!(decision.plan.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 7. Net-vs-gross: primary ranking key is simulated net output, never gross
// ---------------------------------------------------------------------------

fn make_path(net: u128, gross: u128, pool_ref: &str, venue: &str) -> EvaluatedPath {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let leg = EvaluatedLeg {
        venue: venue.to_string(),
        pool_ref: pool_ref.to_string(),
        token_in,
        token_out: token_out.clone(),
        amount_in: AtomicAmount::new(1_000),
        expected_amount_out: AtomicAmount::new(net),
        gross_output: AtomicAmount::new(gross),
        net_output: AtomicAmount::new(net),
        dex_fee: None,
        tax_cost: None,
    };
    EvaluatedPath {
        legs: vec![leg],
        gross_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(gross),
        },
        net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(net),
        },
        dex_fee: None,
        tax_cost: None,
        state_age_ms: 0,
        freshness: fresh_freshness(),
    }
}

#[test]
fn select_best_path_prefers_higher_net_even_when_gross_is_lower() {
    // A naive gross-ranking comparator would pick `high_gross_low_net`.
    let high_gross_low_net = make_path(9_000, 10_000, "pool-a", "venue-a");
    let low_gross_high_net = make_path(9_500, 9_500, "pool-b", "venue-b");

    let forward = [high_gross_low_net.clone(), low_gross_high_net.clone()];
    let winner = select_best_path(&forward).expect("winner");
    assert_eq!(winner.net_output.amount.get(), 9_500);
    assert_eq!(winner.legs[0].pool_ref, "pool-b");

    // Order does not matter.
    let reversed = [low_gross_high_net, high_gross_low_net];
    let winner_reversed = select_best_path(&reversed).expect("winner");
    assert_eq!(winner_reversed.net_output.amount.get(), 9_500);
}

#[test]
fn select_best_path_tie_breaks_on_pool_ref_then_venue() {
    let b = make_path(1_000, 1_000, "pool-b", "venue-a");
    let a = make_path(1_000, 1_000, "pool-a", "venue-z");
    let first_pair = [b.clone(), a.clone()];
    let winner = select_best_path(&first_pair).expect("winner");
    assert_eq!(winner.legs[0].pool_ref, "pool-a");

    let same_ref_z = make_path(1_000, 1_000, "pool-a", "venue-z");
    let same_ref_a = make_path(1_000, 1_000, "pool-a", "venue-a");
    let second_pair = [same_ref_z.clone(), same_ref_a.clone()];
    let winner_venue = select_best_path(&second_pair).expect("winner");
    assert_eq!(winner_venue.legs[0].venue, "venue-a");
}

#[test]
fn plan_direct_route_selects_max_net_output_end_to_end() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let candidate_a = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let candidate_b = candidate(
        "venue-b",
        "pool-b",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_100_000,
            0,
        )),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);
    let config = config(64);

    let decision = plan_with(
        &trade,
        &[candidate_a, candidate_b],
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.winner.legs[0].pool_ref, "pool-b");
    assert_eq!(decision.score.simulated_net_output.amount.get(), 20_792);
    assert_eq!(decision.score.gross_output.amount.get(), 20_792);
}

// ---------------------------------------------------------------------------
// 8. Determinism: repeat run and candidate-order permutation
// ---------------------------------------------------------------------------

fn two_candidates() -> (
    TradeIntent,
    Vec<PoolCandidate>,
    FreshnessPolicy,
    RoutingConfig,
) {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let mut candidate_a = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let mut candidate_b = candidate(
        "venue-b",
        "pool-b",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_100_000,
            0,
        )),
        fresh_freshness(),
    );
    candidate_a.latency_ms = 1;
    candidate_b.latency_ms = 2;
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    (trade, vec![candidate_a, candidate_b], policy(), config(64))
}

#[test]
fn repeated_planning_is_identical_and_serializes_identically() {
    let (trade, candidates, policy, config) = two_candidates();
    let zero_tax = zero_tax_for(&trade);
    let first = plan_with(&trade, &candidates, Some(&zero_tax), &policy, &config).expect("first");
    let second = plan_with(&trade, &candidates, Some(&zero_tax), &policy, &config).expect("second");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_string(&first).expect("json"),
        serde_json::to_string(&second).expect("json")
    );
}

#[test]
fn candidate_order_permutation_yields_same_winner_and_score() {
    let (trade, candidates, policy, config) = two_candidates();
    let zero_tax = zero_tax_for(&trade);
    let forward =
        plan_with(&trade, &candidates, Some(&zero_tax), &policy, &config).expect("forward");

    let mut reversed = candidates.clone();
    reversed.reverse();
    let backward =
        plan_with(&trade, &reversed, Some(&zero_tax), &policy, &config).expect("backward");

    assert_eq!(forward.winner, backward.winner);
    assert_eq!(forward.score, backward.score);
    assert_eq!(forward.plan, backward.plan);
    assert_eq!(forward.winner.legs[0].pool_ref, "pool-b");
    // Winner telemetry comes from candidate B.
    assert_eq!(forward.score.latency_ms, 2);
}

// ---------------------------------------------------------------------------
// 9. Fail-closed: stale/resync skipped, zero-output skipped, no viable route
// ---------------------------------------------------------------------------

#[test]
fn stale_and_resync_candidates_are_skipped() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let good = candidate(
        "venue-good",
        "pool-good",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let stale = candidate(
        "venue-stale",
        "pool-stale",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_100_000,
            0,
        )),
        freshness_at(NOW_MS - 20_000),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);
    let config = config(64);

    let decision = plan_with(
        &trade,
        &[stale.clone(), good.clone()],
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.winner.legs[0].pool_ref, "pool-good");

    // A single stale candidate yields no viable route.
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&stale),
            Some(&zero_tax),
            &policy,
            &config
        ),
        Err(RoutingError::NoViableRoute)
    );

    // Direct leg simulation surfaces the typed stale/resync classes.
    assert_eq!(
        simulate_leg(&stale, &trade, trade.amount, None, &policy, NOW_MS),
        Err(RoutingError::StaleState)
    );
    let resync = candidate(
        "venue-resync",
        "pool-resync",
        stale.state.clone(),
        freshness_at(NOW_MS + 5_000),
    );
    assert_eq!(
        simulate_leg(&resync, &trade, trade.amount, None, &policy, NOW_MS),
        Err(RoutingError::ResyncRequired)
    );
}

#[test]
fn zero_output_candidate_is_skipped_without_aborting_search() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    // Tiny output reserve makes the simulated output floor to zero.
    let zero_output = candidate(
        "venue-zero",
        "pool-zero",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            1,
            0,
        )),
        fresh_freshness(),
    );
    let good = candidate(
        "venue-good",
        "pool-good",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);
    let config = config(64);

    assert_eq!(
        simulate_leg(&zero_output, &trade, trade.amount, None, &policy, NOW_MS),
        Err(RoutingError::Cpmm(
            CpmmSimulationErrorClass::ZeroOutputAmount
        ))
    );

    let decision = plan_with(
        &trade,
        &[zero_output.clone(), good],
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.winner.legs[0].pool_ref, "pool-good");

    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&zero_output),
            Some(&zero_tax),
            &policy,
            &config
        ),
        Err(RoutingError::NoViableRoute)
    );
}

#[test]
fn unusable_candidates_yield_no_viable_route() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let policy = policy();
    let config = config(64);
    let trade = base_intent(TradeSide::Buy, token_in.clone(), token_out, 10_000);
    let zero_tax = zero_tax_for(&trade);

    // Candidate pair does not contain the intent output token.
    let wrong_pair = candidate(
        "venue-x",
        "pool-x",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            other_token(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&wrong_pair),
            Some(&zero_tax),
            &policy,
            &config
        ),
        Err(RoutingError::NoViableRoute)
    );

    // Candidate lives on a different chain.
    let wrong_chain = candidate(
        "venue-y",
        "pool-y",
        PoolKindState::Cpmm(cpmm_pool(
            solana_asset("So11111111111111111111111111111111111111112"),
            solana_asset("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&wrong_chain),
            Some(&zero_tax),
            &policy,
            &config
        ),
        Err(RoutingError::NoViableRoute)
    );
    assert_eq!(
        simulate_leg(&wrong_chain, &trade, trade.amount, None, &policy, NOW_MS),
        Err(RoutingError::Domain(DomainError::ChainMismatch))
    );

    // Empty candidate set.
    assert_eq!(
        plan_with(&trade, &[], Some(&zero_tax), &policy, &config),
        Err(RoutingError::NoViableRoute)
    );
}

// ---------------------------------------------------------------------------
// 9b. Malformed candidate references never abort the search (FIX 1)
// ---------------------------------------------------------------------------

#[test]
fn malformed_best_net_candidate_is_skipped_for_viable_lower_net() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    // This candidate has the best net output but a whitespace venue, so it can
    // never produce a valid `RoutePlan`.
    let malformed_best = candidate(
        "   ",
        "pool-high-net",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_100_000,
            0,
        )),
        fresh_freshness(),
    );
    let viable_lower = candidate(
        "venue-good",
        "pool-good",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in.clone(), token_out.clone(), 10_000);
    let zero_tax = zero_tax_for(&trade);
    let policy = policy();
    let config = config(64);

    let decision = plan_with(
        &trade,
        &[malformed_best.clone(), viable_lower.clone()],
        Some(&zero_tax),
        &policy,
        &config,
    )
    .expect("decision");
    assert_eq!(decision.winner.legs[0].pool_ref, "pool-good");
    assert_eq!(decision.plan.legs[0].pool_ref, "pool-good");

    // A whitespace pool_ref is equally malformed, and a candidate set with only
    // malformed candidates fails closed as `NoViableRoute` (not a domain error).
    let malformed_ref = candidate(
        "venue-x",
        "\t ",
        PoolKindState::Cpmm(cpmm_pool(
            token_in.clone(),
            token_out.clone(),
            1_000_000,
            2_100_000,
            0,
        )),
        fresh_freshness(),
    );
    for malformed in [&malformed_best, &malformed_ref] {
        assert_eq!(
            plan_with(
                &trade,
                std::slice::from_ref(malformed),
                Some(&zero_tax),
                &policy,
                &config
            ),
            Err(RoutingError::NoViableRoute)
        );
    }
    assert_eq!(
        plan_with(
            &trade,
            &[malformed_best, malformed_ref],
            Some(&zero_tax),
            &policy,
            &config
        ),
        Err(RoutingError::NoViableRoute)
    );
}

#[test]
fn unknown_direction_or_token_is_a_typed_kernel_error() {
    let policy = policy();

    // CPMM: input token absent from the pool.
    let token_0 = base_token_0();
    let token_1 = base_token_1();
    let cpmm_candidate = candidate(
        "venue-cpmm",
        "pool-cpmm",
        PoolKindState::Cpmm(cpmm_pool(
            token_0.clone(),
            token_1.clone(),
            1_000_000,
            2_000_000,
            30,
        )),
        fresh_freshness(),
    );
    let cpmm_trade = base_intent(TradeSide::Buy, other_token(), base_token_1(), 10_000);
    assert_eq!(
        simulate_leg(
            &cpmm_candidate,
            &cpmm_trade,
            cpmm_trade.amount,
            None,
            &policy,
            NOW_MS
        ),
        Err(RoutingError::Cpmm(
            CpmmSimulationErrorClass::AssetNotFoundInPool
        ))
    );

    // CLMM: input token absent from the pool.
    let clmm_pool = sample_clmm_pool();
    let clmm_candidate = candidate(
        "venue-clmm",
        "pool-clmm",
        PoolKindState::Clmm(clmm_pool.clone()),
        fresh_freshness(),
    );
    let clmm_trade = intent_with_chain(
        ChainId::Solana,
        TradeSide::Buy,
        solana_asset("Unknown111111111111111111111111111111111111"),
        clmm_pool.token_1.clone(),
        100_000,
    );
    assert_eq!(
        simulate_leg(
            &clmm_candidate,
            &clmm_trade,
            clmm_trade.amount,
            None,
            &policy,
            NOW_MS
        ),
        Err(RoutingError::Clmm(
            ClmmSimulationError::InvalidAssetDirection
        ))
    );

    // Bin: input token absent from the pool.
    let bin_pool = bin_pool_a(token_0.clone(), token_1.clone());
    let bin_candidate = candidate(
        "venue-bin",
        "pool-bin",
        PoolKindState::Bin(bin_pool.clone()),
        fresh_freshness(),
    );
    let bin_trade = base_intent(TradeSide::Buy, other_token(), base_token_1(), 1_010);
    assert_eq!(
        simulate_leg(
            &bin_candidate,
            &bin_trade,
            bin_trade.amount,
            None,
            &policy,
            NOW_MS
        ),
        Err(RoutingError::Bin(BinSimulationError::InvalidAssetDirection))
    );
}

#[test]
fn tax_asset_mismatch_fails_closed_as_tax_error() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let mismatched = tax_assessment(other_token(), 500, 0);
    let policy = policy();

    assert_eq!(
        simulate_leg(
            &candidate,
            &trade,
            trade.amount,
            Some(&mismatched),
            &policy,
            NOW_MS
        ),
        Err(RoutingError::Tax(TaxSafetyError::AssessedAssetMismatch))
    );
}

// ---------------------------------------------------------------------------
// 9c. Tax assessment binding, freshness, and presence (FIX 2/3/4)
// ---------------------------------------------------------------------------

#[test]
fn plan_surfaces_unbound_tax_assessment_instead_of_no_viable_route() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out.clone(), 10_000);
    let policy = policy();
    let config = config(64);

    // Assessed asset is not the intent's `token_out` for a Buy: surfaced as the
    // typed Tax error, not masked as `NoViableRoute`.
    let wrong_asset = tax_assessment(other_token(), 500, 0);
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&wrong_asset),
            &policy,
            &config
        ),
        Err(RoutingError::Tax(TaxSafetyError::AssessedAssetMismatch))
    );

    // Chain mismatch is surfaced the same way.
    let wrong_chain = tax_assessment_on(ChainId::Solana, token_out, 500, 0);
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&wrong_chain),
            &policy,
            &config
        ),
        Err(RoutingError::Tax(TaxSafetyError::ChainMismatch))
    );
}

#[test]
fn plan_fails_closed_on_stale_tax_assessment() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out.clone(), 10_000);
    let policy = policy();
    let config = config(64);

    // The preserved status itself is unusable.
    let status_stale = TaxAssessment::new(
        token_out.clone(),
        ChainId::Base,
        Bps::new(500).expect("bps"),
        Bps::new(0).expect("bps"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Stale,
            observed_at_ms: NOW_MS,
            evaluated_at_ms: NOW_MS,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    );
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&status_stale),
            &policy,
            &config
        ),
        Err(RoutingError::StaleState)
    );

    let resync = TaxAssessment::new(
        token_out.clone(),
        ChainId::Base,
        Bps::new(500).expect("bps"),
        Bps::new(0).expect("bps"),
        SafeFreshnessMeta {
            status: FreshnessStatus::ResyncRequired,
            observed_at_ms: NOW_MS,
            evaluated_at_ms: NOW_MS,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    );
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&resync),
            &policy,
            &config
        ),
        Err(RoutingError::ResyncRequired)
    );

    // Status says Fresh, but `observed_at_ms` is older than the caller's policy
    // window at `now_ms`: the planner re-evaluates and fails closed.
    let observation_stale = TaxAssessment::new(
        token_out,
        ChainId::Base,
        Bps::new(500).expect("bps"),
        Bps::new(0).expect("bps"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: NOW_MS - 20_000,
            evaluated_at_ms: NOW_MS - 20_000,
            age_ms: 20_000,
            sequence: Sequence(1),
        },
        1,
    );
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&observation_stale),
            &policy,
            &config
        ),
        Err(RoutingError::StaleState)
    );
}

#[test]
fn missing_tax_assessment_fails_closed() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let policy = policy();
    let config = config(64);

    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            None,
            &policy,
            &config
        ),
        Err(RoutingError::TaxAssessmentRequired)
    );

    // `simulate_leg` retains its `Option` for internal/test use, and an explicit
    // zero-tax assessment keeps the untaxed expectations.
    let zero_tax = zero_tax_for(&trade);
    assert!(simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&zero_tax),
        &policy,
        NOW_MS
    )
    .is_ok());
    assert!(simulate_leg(&candidate, &trade, trade.amount, None, &policy, NOW_MS).is_ok());
}

#[test]
fn buy_amount_mismatch_is_rejected() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);

    // A direct caller cannot simulate an arbitrary Buy amount.
    assert_eq!(
        simulate_leg(
            &candidate,
            &trade,
            AtomicAmount::new(trade.amount.get() + 1),
            Some(&zero_tax),
            &policy,
            NOW_MS
        ),
        Err(RoutingError::InputConservationViolated)
    );
    assert_eq!(
        simulate_leg(
            &candidate,
            &trade,
            AtomicAmount::new(trade.amount.get() - 1),
            Some(&zero_tax),
            &policy,
            NOW_MS
        ),
        Err(RoutingError::InputConservationViolated)
    );
    // The same binding holds even without an assessment.
    assert_eq!(
        simulate_leg(
            &candidate,
            &trade,
            AtomicAmount::new(trade.amount.get() + 1),
            None,
            &policy,
            NOW_MS
        ),
        Err(RoutingError::InputConservationViolated)
    );
    // The exact intent amount still simulates.
    assert!(simulate_leg(
        &candidate,
        &trade,
        trade.amount,
        Some(&zero_tax),
        &policy,
        NOW_MS
    )
    .is_ok());
}

#[test]
fn budget_exceeded_when_candidate_count_over_cap() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidates = vec![
        candidate(
            "venue-a",
            "pool-a",
            PoolKindState::Cpmm(pool.clone()),
            fresh_freshness(),
        ),
        candidate(
            "venue-b",
            "pool-b",
            PoolKindState::Cpmm(pool),
            fresh_freshness(),
        ),
    ];
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 10_000);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);

    assert_eq!(
        plan_with(&trade, &candidates, Some(&zero_tax), &policy, &config(1)),
        Err(RoutingError::BudgetExceeded)
    );
    assert_eq!(
        plan_with(&trade, &candidates, Some(&zero_tax), &policy, &config(0)),
        Err(RoutingError::BudgetExceeded)
    );
}

#[test]
fn invalid_intent_fails_closed_before_search() {
    let token_in = base_token_0();
    let token_out = base_token_1();
    let pool = cpmm_pool(
        token_in.clone(),
        token_out.clone(),
        1_000_000,
        2_000_000,
        30,
    );
    let candidate = candidate(
        "venue-a",
        "pool-a",
        PoolKindState::Cpmm(pool),
        fresh_freshness(),
    );
    let trade = base_intent(TradeSide::Buy, token_in, token_out, 0);
    let policy = policy();
    let zero_tax = zero_tax_for(&trade);
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&zero_tax),
            &policy,
            &config(64)
        ),
        Err(RoutingError::Domain(DomainError::ZeroTradeAmount))
    );

    // Intent validity is checked before the candidate budget, so an invalid
    // intent is never masked by `BudgetExceeded`.
    assert_eq!(
        plan_with(
            &trade,
            std::slice::from_ref(&candidate),
            Some(&zero_tax),
            &policy,
            &config(0)
        ),
        Err(RoutingError::Domain(DomainError::ZeroTradeAmount))
    );
}

// ---------------------------------------------------------------------------
// 10. RoutePlan construction calls validate()
// ---------------------------------------------------------------------------

#[test]
fn to_route_plan_validates_and_rejects_empty_legs() {
    let token_out = base_token_1();
    let empty = EvaluatedPath {
        legs: Vec::new(),
        gross_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(1_000),
        },
        net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(1_000),
        },
        dex_fee: None,
        tax_cost: None,
        state_age_ms: 0,
        freshness: fresh_freshness(),
    };
    assert_eq!(
        to_route_plan(&empty),
        Err(RoutingError::Domain(DomainError::EmptyRoute))
    );
}

// ---------------------------------------------------------------------------
// 11. Error redaction: no amounts, assets, or addresses in Display/Debug
// ---------------------------------------------------------------------------

#[test]
fn routing_errors_are_redacted_and_payload_free() {
    let sentinel_address = "SENTINEL_ASSET_ADDRESS_987654321";
    let sentinel_amount: u128 = 987_654_321_012_345;
    let sentinel_asset = asset(sentinel_address);

    let roster = vec![
        RoutingError::Domain(DomainError::ChainMismatch),
        RoutingError::Cpmm(CpmmSimulationErrorClass::InvalidPoolState),
        RoutingError::Clmm(ClmmSimulationError::InvalidPrice),
        RoutingError::Bin(BinSimulationError::InvalidBinStep),
        RoutingError::Tax(TaxSafetyError::AssessedAssetMismatch),
        RoutingError::NoViableRoute,
        RoutingError::TaxAssessmentRequired,
        RoutingError::StaleState,
        RoutingError::ResyncRequired,
        RoutingError::UnsupportedPoolKind,
        RoutingError::UnsupportedBinTaxComposition,
        RoutingError::InputConservationViolated,
        RoutingError::BudgetExceeded,
        RoutingError::Internal("routing invariant"),
    ];

    for error in &roster {
        assert_no_sentinel(&format!("{error}"), sentinel_address, sentinel_amount);
        assert_no_sentinel(&format!("{error:?}"), sentinel_address, sentinel_amount);
    }

    // Trigger real failures whose inputs carry the sentinels and confirm they do
    // not leak into the redacted Display/Debug output.
    let policy = policy();
    let token_0 = base_token_0();
    let token_1 = base_token_1();

    let stale_candidate = candidate(
        "venue-stale",
        sentinel_address,
        PoolKindState::Cpmm(cpmm_pool(
            token_0.clone(),
            token_1.clone(),
            1_000_000,
            sentinel_amount,
            0,
        )),
        freshness_at(NOW_MS - 20_000),
    );
    let stale_trade = base_intent(
        TradeSide::Buy,
        token_0.clone(),
        token_1.clone(),
        sentinel_amount,
    );
    let stale_error = simulate_leg(
        &stale_candidate,
        &stale_trade,
        stale_trade.amount,
        None,
        &policy,
        NOW_MS,
    )
    .expect_err("stale");
    assert_no_sentinel(&format!("{stale_error}"), sentinel_address, sentinel_amount);
    assert_no_sentinel(
        &format!("{stale_error:?}"),
        sentinel_address,
        sentinel_amount,
    );

    let unknown_candidate = candidate(
        "venue-unknown",
        sentinel_address,
        PoolKindState::Cpmm(cpmm_pool(
            token_0.clone(),
            token_1.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let unknown_trade = base_intent(
        TradeSide::Buy,
        sentinel_asset.clone(),
        token_1.clone(),
        sentinel_amount,
    );
    let unknown_error = simulate_leg(
        &unknown_candidate,
        &unknown_trade,
        unknown_trade.amount,
        None,
        &policy,
        NOW_MS,
    )
    .expect_err("unknown token");
    assert_no_sentinel(
        &format!("{unknown_error}"),
        sentinel_address,
        sentinel_amount,
    );
    assert_no_sentinel(
        &format!("{unknown_error:?}"),
        sentinel_address,
        sentinel_amount,
    );

    let mismatch_candidate = candidate(
        "venue-mismatch",
        sentinel_address,
        PoolKindState::Cpmm(cpmm_pool(
            token_0.clone(),
            token_1.clone(),
            1_000_000,
            2_000_000,
            0,
        )),
        fresh_freshness(),
    );
    let mismatch_trade = base_intent(TradeSide::Buy, token_0, token_1, sentinel_amount);
    let mismatch_tax = tax_assessment(sentinel_asset, 500, 0);
    let mismatch_error = simulate_leg(
        &mismatch_candidate,
        &mismatch_trade,
        mismatch_trade.amount,
        Some(&mismatch_tax),
        &policy,
        NOW_MS,
    )
    .expect_err("tax mismatch");
    assert_no_sentinel(
        &format!("{mismatch_error}"),
        sentinel_address,
        sentinel_amount,
    );
    assert_no_sentinel(
        &format!("{mismatch_error:?}"),
        sentinel_address,
        sentinel_amount,
    );
}

fn assert_no_sentinel(text: &str, sentinel_address: &str, sentinel_amount: u128) {
    assert!(
        !text.contains(sentinel_address),
        "error text leaked an asset address: {text}"
    );
    assert!(
        !text.contains(&sentinel_amount.to_string()),
        "error text leaked an amount: {text}"
    );
    assert!(
        !text.chars().any(|character| character.is_ascii_digit()),
        "error text leaked a numeric payload: {text}"
    );
}
