//! Pinned-vector and fail-closed tests for the exact-simulation net-delta bridge.
//!
//! All economics are exact integers. Pool fixture: USDC = token_0 (6 decimals),
//! TOKEN = token_1 (18 decimals), reserves 1_000_000 / 2_000_000, fee 30 bps.

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, DomainError, IdempotencyKey, IntentId, LimitPrice, OrderType, RiskConstraints,
    RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::{
    build_execution_preview, validate_delta_preview, validate_delta_preview_with_assessment,
    BridgeError, NetDelta,
};
use market_types::{
    AssetAmount, AtomicAmount, BinPoolState, Bps, ClmmPoolState, ClmmTick, CpmmPoolState,
    Freshness, FreshnessStatus, LiquidityBin, MarketTypeError, PriceRatio, SafeFreshnessMeta,
    Sequence,
};
use simulation::{
    simulate_bin_exact_input, simulate_clmm_exact_input, simulate_cpmm_exact_input,
    simulate_tax_aware_cpmm_buy_exact_input, simulate_tax_aware_cpmm_sell_exact_input,
    BinExactInputRequest, BinSimulationError, ClmmExactInputRequest, ClmmSimulationError,
    CpmmExactInputRequest, CpmmSimulationErrorClass,
};
use tax_engine::{TaxAssessment, TaxSafetyError};

const USDC_ADDR: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TOKEN_ADDR: &str = "0x4200000000000000000000000000000000000006";
const OTHER_ADDR: &str = "0x0000000000000000000000000000000000000001";
const SOL_ADDR: &str = "So11111111111111111111111111111111111111112";
const SOL_USDC_ADDR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).unwrap()
}

fn sol_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Solana, address).unwrap()
}

fn usdc() -> AssetId {
    base_asset(USDC_ADDR)
}

fn token() -> AssetId {
    base_asset(TOKEN_ADDR)
}

fn amount(asset: &AssetId, value: u128) -> AssetAmount {
    AssetAmount {
        asset: asset.clone(),
        amount: AtomicAmount::new(value),
    }
}

fn cpmm_pool(fee_bps: u16) -> CpmmPoolState {
    CpmmPoolState {
        token_0: usdc(),
        token_1: token(),
        decimals_0: 6,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(1_000_000),
        reserve_1: AtomicAmount::new(2_000_000),
        total_lp_supply: Some(AtomicAmount::new(10_000_000)),
        fee_bps: Bps::new(fee_bps).unwrap(),
    }
}

fn assessment(chain: ChainId, address: &str, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    let freshness = SafeFreshnessMeta {
        status: FreshnessStatus::Fresh,
        observed_at_ms: 1_000,
        evaluated_at_ms: 1_000,
        age_ms: 0,
        sequence: Sequence(1),
    };
    TaxAssessment::new(
        AssetId::new(chain.clone(), address).unwrap(),
        chain,
        Bps::new(buy_tax).unwrap(),
        Bps::new(sell_tax).unwrap(),
        freshness,
        1,
    )
}

fn base_intent(
    side: TradeSide,
    token_in: &AssetId,
    token_out: &AssetId,
    value: u128,
    limit_price: Option<LimitPrice>,
    allow_partial_fill: bool,
) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-p38").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-p38").unwrap(),
        wallet_ref: WalletRef::new("wallet-p38").unwrap(),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(value),
        order_type: if limit_price.is_some() {
            OrderType::Limit
        } else {
            OrderType::Market
        },
        limit_price,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-p38").unwrap(),
    }
}

fn route(
    token_in: &AssetId,
    token_out: &AssetId,
    amount_in: u128,
    expected_amount_out: u128,
    expected_net_output: u128,
    observed_at_ms: i64,
    sequence: Sequence,
) -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "0xpool-p38".to_string(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(amount_in),
            expected_amount_out: AtomicAmount::new(expected_amount_out),
        }],
        expected_net_output: amount(token_out, expected_net_output),
        state: Freshness {
            observed_at_ms,
            chain_height: 100,
            sequence,
        },
    }
}

fn buy_limit(token_in: &AssetId, token_out: &AssetId, num: u128, den: u128) -> LimitPrice {
    LimitPrice {
        numerator_asset: token_in.clone(),
        denominator_asset: token_out.clone(),
        ratio: PriceRatio::new(num, den).unwrap(),
    }
}

fn sell_limit(token_in: &AssetId, token_out: &AssetId, num: u128, den: u128) -> LimitPrice {
    // Sell limit price is quote received (token_out) per base sold (token_in).
    LimitPrice {
        numerator_asset: token_out.clone(),
        denominator_asset: token_in.clone(),
        ratio: PriceRatio::new(num, den).unwrap(),
    }
}

fn plain_delta(
    token_in: &AssetId,
    token_out: &AssetId,
    net_input: u128,
    gross_output: u128,
    net_output: u128,
    dex_fee: Option<(AssetId, u128)>,
    tax_cost: Option<(AssetId, u128)>,
) -> NetDelta {
    NetDelta {
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        net_input: amount(token_in, net_input),
        gross_output: amount(token_out, gross_output),
        net_output: amount(token_out, net_output),
        dex_fee: dex_fee.map(|(asset, value)| amount(&asset, value)),
        tax_cost: tax_cost.map(|(asset, value)| amount(&asset, value)),
    }
}

// ---------------------------------------------------------------------------
// 1. CPMM plain BUY exact vector
// ---------------------------------------------------------------------------

#[test]
fn vector_1_cpmm_plain_buy_normalizes_exactly_and_validates() {
    let pool = cpmm_pool(30);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_cpmm_exact_input(&pool, &request).unwrap();
    let delta = NetDelta::from_cpmm(&quote).unwrap();

    assert_eq!(delta.token_in, usdc());
    assert_eq!(delta.token_out, token());
    assert_eq!(delta.net_input, amount(&usdc(), 10_000));
    assert_eq!(delta.gross_output, amount(&token(), 19_743));
    assert_eq!(delta.net_output, amount(&token(), 19_743));
    assert_eq!(delta.dex_fee, Some(amount(&usdc(), 30)));
    assert_eq!(delta.tax_cost, None);
    assert!(delta.validate().is_ok());

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_743,
        1_000,
        Sequence(1),
    );
    let validated = validate_delta_preview(&intent, &plan, &delta, 1_000).unwrap();

    assert_eq!(
        validated.preview().simulated_net_input,
        amount(&usdc(), 10_000)
    );
    assert_eq!(
        validated.preview().simulated_net_output,
        amount(&token(), 19_743)
    );
    assert_eq!(validated.preview().gross_output, amount(&token(), 19_743));
    assert_eq!(
        validated.preview().cost_components.dex_fee,
        Some(amount(&usdc(), 30))
    );
    assert_eq!(validated.preview().cost_components.tax_cost, None);
    assert_eq!(
        validated.preview().local_state_freshness,
        FreshnessStatus::Fresh
    );
}

// ---------------------------------------------------------------------------
// 2. Tax-aware BUY: output-side tax conservation
// ---------------------------------------------------------------------------

#[test]
fn vector_2_tax_aware_buy_conservation() {
    let pool = cpmm_pool(30);
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 200, 0);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &request, &tax).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_buy(&quote).unwrap();

    assert_eq!(delta.net_input, amount(&usdc(), 10_000));
    assert_eq!(delta.gross_output, amount(&token(), 19_743));
    assert_eq!(delta.tax_cost, Some(amount(&token(), 394)));
    assert_eq!(delta.net_output, amount(&token(), 19_349));
    assert_eq!(
        delta.gross_output.amount.get(),
        delta.net_output.amount.get() + delta.tax_cost.as_ref().unwrap().amount.get()
    );
    assert_eq!(delta.dex_fee, Some(amount(&usdc(), 30)));

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_349,
        1_000,
        Sequence(1),
    );
    let validated = validate_delta_preview(&intent, &plan, &delta, 1_000).unwrap();
    assert_eq!(
        validated.preview().cost_components.tax_cost,
        Some(amount(&token(), 394))
    );
    assert_eq!(
        validated.preview().cost_components.dex_fee,
        Some(amount(&usdc(), 30))
    );
}

// ---------------------------------------------------------------------------
// 3 + 7. Tax-aware SELL: input-side tax before the pool swap
// ---------------------------------------------------------------------------

#[test]
fn vector_3_and_7_tax_aware_sell_full_debit_and_input_side_costs() {
    let pool = cpmm_pool(30);
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 0, 100);
    let request = CpmmExactInputRequest::new(token(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_sell_exact_input(&pool, &request, &tax).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_sell(&quote).unwrap();

    // Full wallet debit is the original 10_000 TOKEN, not the 9_900 net transferable.
    assert_eq!(delta.net_input, amount(&token(), 10_000));
    assert_eq!(delta.tax_cost, Some(amount(&token(), 100)));
    assert_eq!(delta.dex_fee, Some(amount(&token(), 29)));
    assert_eq!(delta.gross_output, amount(&usdc(), 4_911));
    assert_eq!(delta.net_output, amount(&usdc(), 4_911));

    // Input-side conservation: tax + pool fee fit inside the full debit.
    let net_transferable =
        delta.net_input.amount.get() - delta.tax_cost.as_ref().unwrap().amount.get();
    assert_eq!(net_transferable, 9_900);
    assert!(delta.dex_fee.as_ref().unwrap().amount.get() <= net_transferable);

    let intent = base_intent(TradeSide::Sell, &token(), &usdc(), 10_000, None, true);
    let plan = route(&token(), &usdc(), 10_000, 4_911, 4_911, 1_000, Sequence(1));
    let preview = build_execution_preview(&intent, &delta, FreshnessStatus::Fresh).unwrap();

    // Vector 7: both sell costs are token_in, so output-denominated costs are zero
    // and the locked internal validator passes without ZeroCostComponent.
    assert!(preview.validate_internal().is_ok());
    assert_eq!(preview.simulated_net_input, amount(&token(), 10_000));
    assert_eq!(preview.cost_components.dex_fee, Some(amount(&token(), 29)));
    assert_eq!(
        preview.cost_components.tax_cost,
        Some(amount(&token(), 100))
    );

    let validated = validate_delta_preview(&intent, &plan, &delta, 1_000).unwrap();
    assert_eq!(
        validated.executable_net_price().unwrap(),
        PriceRatio::new(4_911, 10_000).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 4 + 8. Zero fee/tax maps to None, never Some(0)
// ---------------------------------------------------------------------------

#[test]
fn vector_4_and_8_zero_fee_and_zero_tax_map_to_none() {
    let pool = cpmm_pool(0);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(1_000));
    let quote = simulate_cpmm_exact_input(&pool, &request).unwrap();
    let delta = NetDelta::from_cpmm(&quote).unwrap();

    assert_eq!(delta.gross_output, amount(&token(), 1_998));
    assert_eq!(delta.net_output, amount(&token(), 1_998));
    assert_eq!(delta.dex_fee, None);
    assert_eq!(delta.tax_cost, None);

    // Zero-tax tax-aware buy on a zero-fee pool is also fully `None`.
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 0, 0);
    let tax_quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &request, &tax).unwrap();
    let tax_delta = NetDelta::from_tax_aware_cpmm_buy(&tax_quote).unwrap();
    assert_eq!(tax_delta.gross_output, amount(&token(), 1_998));
    assert_eq!(tax_delta.dex_fee, None);
    assert_eq!(tax_delta.tax_cost, None);

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 1_000, None, true);
    let preview = build_execution_preview(&intent, &tax_delta, FreshnessStatus::Fresh).unwrap();
    assert_eq!(preview.cost_components.dex_fee, None);
    assert_eq!(preview.cost_components.tax_cost, None);
    assert_ne!(preview.cost_components.dex_fee, Some(amount(&usdc(), 0)));
    assert_ne!(preview.cost_components.tax_cost, Some(amount(&token(), 0)));
    assert!(preview.validate_internal().is_ok());
}

// ---------------------------------------------------------------------------
// 5. BUY net limit uses post-tax net output, not gross output
// ---------------------------------------------------------------------------

#[test]
fn vector_5_buy_net_limit_violation_uses_net_output() {
    let pool = cpmm_pool(30);
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 200, 0);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &request, &tax).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_buy(&quote).unwrap();
    assert_eq!(delta.net_output.amount.get(), 19_349);
    assert_eq!(delta.gross_output.amount.get(), 19_743);

    // Gross economics would pass 51/100: 10_000 * 100 <= 51 * 19_743.
    assert!(10_000u128 * 100 <= 51 * delta.gross_output.amount.get());

    let limit = buy_limit(&usdc(), &token(), 51, 100);
    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, Some(limit), true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_349,
        1_000,
        Sequence(1),
    );

    assert_eq!(
        validate_delta_preview(&intent, &plan, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::LimitPriceViolated))
    );
}

// ---------------------------------------------------------------------------
// 6. SELL net limit uses the full debit, not the net transferable input
// ---------------------------------------------------------------------------

#[test]
fn vector_6_sell_net_limit_violation_uses_full_debit() {
    let pool = cpmm_pool(30);
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 0, 100);
    let request = CpmmExactInputRequest::new(token(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_sell_exact_input(&pool, &request, &tax).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_sell(&quote).unwrap();

    // If the 9_900 net transferable were used as the sell input, 99/200 would pass:
    // 4_911 * 200 >= 99 * 9_900.
    let net_transferable =
        delta.net_input.amount.get() - delta.tax_cost.as_ref().unwrap().amount.get();
    let proceeds = delta.net_output.amount.get();
    assert!(proceeds * 200 >= 99 * net_transferable);
    // With the full 10_000 debit it fails: 4_911 * 200 < 99 * 10_000.
    assert!(proceeds * 200 < 99 * delta.net_input.amount.get());

    let limit = sell_limit(&token(), &usdc(), 99, 200);
    let intent = base_intent(
        TradeSide::Sell,
        &token(),
        &usdc(),
        10_000,
        Some(limit),
        true,
    );
    let plan = route(&token(), &usdc(), 10_000, 4_911, 4_911, 1_000, Sequence(1));

    assert_eq!(
        validate_delta_preview(&intent, &plan, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::LimitPriceViolated))
    );
}

// ---------------------------------------------------------------------------
// 9. Route expected_net_output stays an independent check
// ---------------------------------------------------------------------------

#[test]
fn vector_9_route_output_amount_mismatch() {
    let pool = cpmm_pool(30);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_cpmm_exact_input(&pool, &request).unwrap();
    let delta = NetDelta::from_cpmm(&quote).unwrap();

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_744,
        1_000,
        Sequence(1),
    );

    assert_eq!(
        validate_delta_preview(&intent, &plan, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::RouteOutputAmountMismatch))
    );
}

// ---------------------------------------------------------------------------
// 10. All-or-nothing intents reject partial simulated input
// ---------------------------------------------------------------------------

#[test]
fn vector_10_all_or_nothing_partial_fill_mismatch() {
    let delta = plain_delta(&usdc(), &token(), 999, 19_743, 19_743, None, None);
    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 1_000, None, false);
    let plan = route(&usdc(), &token(), 999, 19_743, 19_743, 1_000, Sequence(1));

    assert!(matches!(
        validate_delta_preview(&intent, &plan, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::InconsistentNetEconomics(
            _
        )))
    ));
}

// ---------------------------------------------------------------------------
// 11. Freshness derivation and fail-closed route state
// ---------------------------------------------------------------------------

#[test]
fn vector_11_freshness_fail_closed() {
    let pool = cpmm_pool(30);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_cpmm_exact_input(&pool, &request).unwrap();
    let delta = NetDelta::from_cpmm(&quote).unwrap();
    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);

    // Stale route: observed 1_000 evaluated at 21_000 exceeds the 10s default.
    let stale = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_743,
        1_000,
        Sequence(1),
    );
    assert_eq!(
        validate_delta_preview(&intent, &stale, &delta, 21_000),
        Err(BridgeError::Domain(DomainError::StaleMarketState))
    );

    // Zero sequence requires resync.
    let zero_seq = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_743,
        1_000,
        Sequence(0),
    );
    assert_eq!(
        validate_delta_preview(&intent, &zero_seq, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::ResyncRequired))
    );

    // Excessive future skew requires resync.
    let future = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_743,
        6_000,
        Sequence(1),
    );
    assert_eq!(
        validate_delta_preview(&intent, &future, &delta, 1_000),
        Err(BridgeError::Domain(DomainError::ResyncRequired))
    );

    // Non-positive observation timestamps cannot be classified.
    let unavailable = route(&usdc(), &token(), 10_000, 19_743, 19_743, 0, Sequence(1));
    assert_eq!(
        validate_delta_preview(&intent, &unavailable, &delta, 1_000),
        Err(BridgeError::FreshnessUnavailable)
    );
}

// ---------------------------------------------------------------------------
// 12. Delta vs intent chain/asset binding fails closed with structural errors
// ---------------------------------------------------------------------------

#[test]
fn vector_12_delta_intent_binding_mismatch() {
    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 1_000, None, true);

    // Chain mismatch: internally consistent Solana delta against a Base intent.
    let cross_chain = plain_delta(
        &sol_asset(SOL_ADDR),
        &sol_asset(SOL_USDC_ADDR),
        1_000,
        2_000,
        2_000,
        None,
        None,
    );
    assert!(cross_chain.validate().is_ok());
    let plan = route(&usdc(), &token(), 1_000, 2_000, 2_000, 1_000, Sequence(1));
    assert_eq!(
        validate_delta_preview(&intent, &plan, &cross_chain, 1_000),
        Err(BridgeError::ChainMismatch)
    );

    // Input asset mismatch on the same chain.
    let wrong_in = plain_delta(
        &base_asset(OTHER_ADDR),
        &token(),
        1_000,
        2_000,
        2_000,
        None,
        None,
    );
    assert_eq!(
        build_execution_preview(&intent, &wrong_in, FreshnessStatus::Fresh),
        Err(BridgeError::InputAssetMismatch)
    );

    // Output asset mismatch on the same chain.
    let wrong_out = plain_delta(
        &usdc(),
        &base_asset(OTHER_ADDR),
        1_000,
        2_000,
        2_000,
        None,
        None,
    );
    assert_eq!(
        build_execution_preview(&intent, &wrong_out, FreshnessStatus::Fresh),
        Err(BridgeError::OutputAssetMismatch)
    );
}

// ---------------------------------------------------------------------------
// 13. Hand-built inconsistent deltas fail closed
// ---------------------------------------------------------------------------

#[test]
fn vector_13_hand_built_inconsistent_delta_fail_closed() {
    let token_in = usdc();
    let token_out = token();

    // Output tax that does not reconcile net + tax == gross.
    let bad_conservation = plain_delta(
        &token_in,
        &token_out,
        1_000,
        200,
        100,
        None,
        Some((token_out.clone(), 10)),
    );
    assert!(matches!(
        bad_conservation.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Pool fee cannot exceed the full wallet debit.
    let bad_fee = plain_delta(
        &token_in,
        &token_out,
        1_000,
        2_000,
        2_000,
        Some((token_in.clone(), 2_000)),
        None,
    );
    assert!(matches!(
        bad_fee.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Sell input tax leaves less than the pool fee behind.
    let bad_sell = plain_delta(
        &token_in,
        &token_out,
        1_000,
        2_000,
        2_000,
        Some((token_in.clone(), 600)),
        Some((token_in.clone(), 500)),
    );
    assert!(matches!(
        bad_sell.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Zero amounts are rejected.
    let zero_in = plain_delta(&token_in, &token_out, 0, 2_000, 2_000, None, None);
    assert!(matches!(
        zero_in.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Net output cannot exceed gross output.
    let bad_net = plain_delta(&token_in, &token_out, 1_000, 100, 200, None, None);
    assert!(matches!(
        bad_net.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Same asset pair is rejected.
    let same_pair = plain_delta(&token_in, &token_in, 1_000, 2_000, 2_000, None, None);
    assert!(matches!(
        same_pair.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));

    // Tax denominated in neither pair asset is rejected.
    let bad_denomination = plain_delta(
        &token_in,
        &token_out,
        1_000,
        2_000,
        2_000,
        None,
        Some((base_asset(OTHER_ADDR), 10)),
    );
    assert!(matches!(
        bad_denomination.validate(),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));
}

// ---------------------------------------------------------------------------
// 14. Plain CLMM buy on the clmm_tests sample pool
// ---------------------------------------------------------------------------

fn clmm_sample_pool() -> ClmmPoolState {
    ClmmPoolState {
        token_0: sol_asset(SOL_ADDR),
        token_1: sol_asset(SOL_USDC_ADDR),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: 18_476_281_010_653_910_144,
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(30).unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    }
}

#[test]
fn vector_14_clmm_plain_buy_validates() {
    let pool = clmm_sample_pool();
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let quote = simulate_clmm_exact_input(&pool, &request).unwrap();
    assert_eq!(quote.input.amount.get(), 100_000);
    assert_eq!(quote.fee.amount.get(), 300);

    let delta = NetDelta::from_clmm(&quote).unwrap();
    assert_eq!(delta.net_input, amount(&pool.token_0, 100_000));
    assert_eq!(delta.dex_fee, Some(amount(&pool.token_0, 300)));
    assert_eq!(delta.gross_output, quote.output);
    assert_eq!(delta.net_output, quote.output);
    assert_eq!(delta.tax_cost, None);

    let token_in = pool.token_0.clone();
    let token_out = pool.token_1.clone();
    let intent = TradeIntent {
        id: IntentId::new("intent-p38-clmm").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-p38").unwrap(),
        wallet_ref: WalletRef::new("wallet-p38").unwrap(),
        chain: ChainId::Solana,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(100_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-p38-clmm").unwrap(),
    };
    let plan = route(
        &token_in,
        &token_out,
        100_000,
        quote.output.amount.get(),
        quote.output.amount.get(),
        1_000,
        Sequence(1),
    );
    let validated = validate_delta_preview(&intent, &plan, &delta, 1_000).unwrap();
    assert_eq!(validated.preview().simulated_net_output, quote.output);
}

// ---------------------------------------------------------------------------
// 14b. Plain Bin/DLMM quote normalization (input-side fee)
// ---------------------------------------------------------------------------

#[test]
fn bin_quote_normalizes_with_input_side_fee() {
    let pool = BinPoolState {
        token_0: sol_asset(SOL_ADDR),
        token_1: sol_asset(SOL_USDC_ADDR),
        decimals_0: 0,
        decimals_1: 0,
        active_bin_id: 0,
        bin_step: 100,
        fee_bps: Bps::new(100).unwrap(),
        bins: vec![
            LiquidityBin::new(-1, AtomicAmount::new(0), AtomicAmount::new(5_000)),
            LiquidityBin::new(0, AtomicAmount::new(500), AtomicAmount::new(1_000)),
        ],
    };
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1_500));
    let quote = simulate_bin_exact_input(&pool, &request).unwrap();
    assert_eq!(quote.fee.amount.get(), 15);
    assert_eq!(quote.output.amount.get(), 1_480);

    let delta = NetDelta::from_bin(&quote).unwrap();
    assert_eq!(delta.net_input, amount(&pool.token_0, 1_500));
    assert_eq!(delta.dex_fee, Some(amount(&pool.token_0, 15)));
    assert_eq!(delta.gross_output, amount(&pool.token_1, 1_480));
    assert_eq!(delta.net_output, amount(&pool.token_1, 1_480));
    assert_eq!(delta.tax_cost, None);
    assert!(delta.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 15. Assessment tax caps and assessed-asset binding
// ---------------------------------------------------------------------------

#[test]
fn vector_15_assessment_tax_caps_and_asset_binding() {
    let pool = cpmm_pool(30);
    let in_cap = assessment(ChainId::Base, TOKEN_ADDR, 200, 0);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &request, &in_cap).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_buy(&quote).unwrap();

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_349,
        1_000,
        Sequence(1),
    );

    // Buy tax 200 within the 500 bps cap succeeds.
    assert!(validate_delta_preview_with_assessment(&intent, &plan, &delta, &in_cap, 1_000).is_ok());

    // Buy tax 600 exceeds the cap.
    let over_cap = assessment(ChainId::Base, TOKEN_ADDR, 600, 0);
    assert_eq!(
        validate_delta_preview_with_assessment(&intent, &plan, &delta, &over_cap, 1_000),
        Err(BridgeError::TaxCapExceeded)
    );

    // Assessed asset must bind to token_out for a buy.
    let wrong_asset = assessment(ChainId::Base, USDC_ADDR, 200, 0);
    assert_eq!(
        validate_delta_preview_with_assessment(&intent, &plan, &delta, &wrong_asset, 1_000),
        Err(BridgeError::AssessedAssetMismatch)
    );

    // Assessment chain must match the intent chain.
    let wrong_chain = assessment(ChainId::Solana, SOL_ADDR, 200, 0);
    assert_eq!(
        validate_delta_preview_with_assessment(&intent, &plan, &delta, &wrong_chain, 1_000),
        Err(BridgeError::ChainMismatch)
    );

    // Sell side cap and binding.
    let sell_tax = assessment(ChainId::Base, TOKEN_ADDR, 0, 100);
    let sell_request = CpmmExactInputRequest::new(token(), AtomicAmount::new(10_000));
    let sell_quote =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &sell_request, &sell_tax).unwrap();
    let sell_delta = NetDelta::from_tax_aware_cpmm_sell(&sell_quote).unwrap();
    let sell_intent = base_intent(TradeSide::Sell, &token(), &usdc(), 10_000, None, true);
    let sell_plan = route(&token(), &usdc(), 10_000, 4_911, 4_911, 1_000, Sequence(1));
    assert!(validate_delta_preview_with_assessment(
        &sell_intent,
        &sell_plan,
        &sell_delta,
        &sell_tax,
        1_000
    )
    .is_ok());

    let sell_over_cap = assessment(ChainId::Base, TOKEN_ADDR, 0, 600);
    assert_eq!(
        validate_delta_preview_with_assessment(
            &sell_intent,
            &sell_plan,
            &sell_delta,
            &sell_over_cap,
            1_000
        ),
        Err(BridgeError::TaxCapExceeded)
    );
}

// ---------------------------------------------------------------------------
// 16. Serde round-trips of NetDelta and ExecutionPreview
// ---------------------------------------------------------------------------

#[test]
fn vector_16_serde_round_trip() {
    let pool = cpmm_pool(30);
    let tax = assessment(ChainId::Base, TOKEN_ADDR, 200, 0);
    let request = CpmmExactInputRequest::new(usdc(), AtomicAmount::new(10_000));
    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &request, &tax).unwrap();
    let delta = NetDelta::from_tax_aware_cpmm_buy(&quote).unwrap();

    let encoded = serde_json::to_string(&delta).unwrap();
    let decoded: NetDelta = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, delta);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);

    let intent = base_intent(TradeSide::Buy, &usdc(), &token(), 10_000, None, true);
    let plan = route(
        &usdc(),
        &token(),
        10_000,
        19_743,
        19_349,
        1_000,
        Sequence(1),
    );
    let validated = validate_delta_preview(&intent, &plan, &delta, 1_000).unwrap();
    let preview = validated.into_inner();

    let preview_json = serde_json::to_string(&preview).unwrap();
    let decoded_preview: domain::ExecutionPreview = serde_json::from_str(&preview_json).unwrap();
    assert_eq!(decoded_preview, preview);
    assert_eq!(
        serde_json::to_string(&decoded_preview).unwrap(),
        preview_json
    );
}

// ---------------------------------------------------------------------------
// BridgeError redaction
// ---------------------------------------------------------------------------

#[test]
fn bridge_error_messages_are_redacted() {
    let errors = [
        BridgeError::NetDeltaInconsistent("net_output plus tax_cost must equal gross_output"),
        BridgeError::Domain(DomainError::LimitPriceViolated),
        BridgeError::Cpmm(CpmmSimulationErrorClass::ArithmeticOverflow),
        BridgeError::Clmm(ClmmSimulationError::TickCrossingExceeded),
        BridgeError::Bin(BinSimulationError::BinCrossingExceeded),
        BridgeError::Tax(TaxSafetyError::AssessedAssetMismatch),
        BridgeError::Market(MarketTypeError::ChainMismatch),
        BridgeError::DirectionMismatch,
        BridgeError::ChainMismatch,
        BridgeError::InputAssetMismatch,
        BridgeError::OutputAssetMismatch,
        BridgeError::AssessedAssetMismatch,
        BridgeError::TaxCapExceeded,
        BridgeError::FreshnessUnavailable,
    ];

    let forbidden = [
        "0x",
        "So11111111111111111111111111111111111111112",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "secret",
        "credential",
        "password",
        "bearer",
        "payload",
        "endpoint",
        "http://",
        "https://",
    ];

    for error in errors {
        let display = error.to_string();
        let debug = format!("{error:?}");
        for pattern in forbidden {
            assert!(
                !display.contains(pattern),
                "Display leaked '{pattern}': {display}"
            );
            assert!(
                !debug.contains(pattern),
                "Debug leaked '{pattern}': {debug}"
            );
        }
        assert!(
            !display.chars().any(|c| c.is_ascii_digit()),
            "Display leaked a numeric amount: {display}"
        );
    }
}
