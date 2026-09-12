//! Deterministic unit and integration tests for tax-aware CLMM buy/sell round-trip composition.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, ClmmPoolState, ClmmTick, FreshnessStatus, SafeFreshnessMeta, Sequence,
};

use simulation::{
    simulate_tax_aware_clmm_roundtrip_exact_input, ClmmExactInputRequest,
    TaxAwareClmmRoundtripQuote, TaxAwareClmmSimulationError,
};
use tax_engine::{TaxAssessment, TaxSafetyError};

fn sample_assets() -> (AssetId, AssetId) {
    let sol = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112".to_string(),
    )
    .expect("valid sol asset");
    let usdc = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
    )
    .expect("valid usdc asset");
    (sol, usdc)
}

fn sample_clmm_pool() -> ClmmPoolState {
    let (sol, usdc) = sample_assets();
    ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: 18_476_281_010_653_910_144,
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(30).expect("valid fee bps"),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    }
}

fn sample_assessment(
    chain: ChainId,
    asset: AssetId,
    buy_tax_bps: u16,
    sell_tax_bps: u16,
    status: FreshnessStatus,
) -> TaxAssessment {
    let freshness = SafeFreshnessMeta {
        status,
        observed_at_ms: 100_000,
        evaluated_at_ms: 105_000,
        age_ms: 5_000,
        sequence: Sequence::new(50_000),
    };
    TaxAssessment::new(
        asset,
        chain,
        Bps::new(buy_tax_bps).expect("valid buy tax bps"),
        Bps::new(sell_tax_bps).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

#[test]
fn test_deterministic_clmm_roundtrip_both_directions() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Buy 0 -> 1: gross 1_000_000 SOL, buy tax 250 bps on acquired USDC.
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(1_000_000),
        token_out: None,
    };
    let initial_request = request.clone();
    let buy_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::Fresh,
    );
    let sell_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );
    let initial_buy_assessment = buy_assessment.clone();
    let initial_sell_assessment = sell_assessment.clone();

    let quote = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("round-trip 0->1 must succeed");

    // Buy leg literals.
    assert_eq!(quote.buy_quote.clmm_quote.input.amount.get(), 1_000_000);
    assert_eq!(quote.buy_quote.clmm_quote.fee.amount.get(), 3_000);
    assert_eq!(
        quote.buy_quote.clmm_quote.effective_input.amount.get(),
        997_000
    );
    assert_eq!(quote.buy_quote.clmm_quote.output.amount.get(), 1_000_095);
    assert_eq!(
        quote.buy_quote.clmm_quote.resulting_sqrt_price_x64,
        18_474_436_160_115_377_038
    );
    assert_eq!(quote.buy_quote.clmm_quote.resulting_tick, 30);
    assert_eq!(
        quote.buy_quote.clmm_quote.resulting_liquidity,
        10_000_000_000
    );
    assert_eq!(
        quote.buy_quote.tax_output.gross_output.amount.get(),
        1_000_095
    );
    assert_eq!(quote.buy_quote.tax_output.tax_cost.amount.get(), 25_002);
    assert_eq!(quote.buy_quote.tax_output.net_output.amount.get(), 975_093);

    // Sell leg literals: sells exactly the net acquired USDC back to SOL.
    assert_eq!(quote.sell_quote.tax_input.gross_input.asset, pool.token_1);
    assert_eq!(quote.sell_quote.tax_input.gross_input.amount.get(), 975_093);
    assert_eq!(quote.sell_quote.tax_input.tax_cost.amount.get(), 48_754);
    assert_eq!(
        quote
            .sell_quote
            .tax_input
            .net_transferable_input
            .amount
            .get(),
        926_339
    );
    assert_eq!(quote.sell_quote.clmm_quote.input.amount.get(), 926_339);
    assert_eq!(quote.sell_quote.clmm_quote.fee.amount.get(), 2_779);
    assert_eq!(
        quote.sell_quote.clmm_quote.effective_input.amount.get(),
        923_560
    );
    assert_eq!(quote.sell_quote.clmm_quote.output.asset, pool.token_0);
    assert_eq!(quote.sell_quote.clmm_quote.output.amount.get(), 920_708);
    assert_eq!(
        quote.sell_quote.clmm_quote.resulting_sqrt_price_x64,
        18_476_139_827_611_048_557
    );
    assert_eq!(quote.sell_quote.clmm_quote.resulting_tick, 31);
    assert_eq!(
        quote.sell_quote.clmm_quote.resulting_liquidity,
        10_000_000_000
    );

    // Conservation across both legs.
    assert_eq!(
        quote.buy_quote.tax_output.net_output.amount.get()
            + quote.buy_quote.tax_output.tax_cost.amount.get(),
        quote.buy_quote.tax_output.gross_output.amount.get()
    );
    assert_eq!(
        quote.sell_quote.tax_input.gross_input.amount.get(),
        quote.buy_quote.tax_output.net_output.amount.get()
    );
    assert_eq!(
        quote.sell_quote.tax_input.tax_cost.amount.get()
            + quote
                .sell_quote
                .tax_input
                .net_transferable_input
                .amount
                .get(),
        quote.sell_quote.tax_input.gross_input.amount.get()
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(request, initial_request);
    assert_eq!(buy_assessment, initial_buy_assessment);
    assert_eq!(sell_assessment, initial_sell_assessment);

    // Buy 1 -> 0: gross 1_000_000 USDC, acquired SOL.
    let request_rev = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(1_000_000),
        token_out: None,
    };
    let initial_request_rev = request_rev.clone();
    let buy_assessment_rev = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        0,
        FreshnessStatus::Fresh,
    );
    let sell_assessment_rev = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );

    let quote_rev = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request_rev,
        &buy_assessment_rev,
        &sell_assessment_rev,
    )
    .expect("round-trip 1->0 must succeed");

    assert_eq!(quote_rev.buy_quote.clmm_quote.fee.amount.get(), 3_000);
    assert_eq!(
        quote_rev.buy_quote.clmm_quote.effective_input.amount.get(),
        997_000
    );
    assert_eq!(quote_rev.buy_quote.clmm_quote.output.amount.get(), 993_715);
    assert_eq!(
        quote_rev.buy_quote.clmm_quote.resulting_sqrt_price_x64,
        18_478_120_151_038_058_986
    );
    assert_eq!(quote_rev.buy_quote.clmm_quote.resulting_tick, 33);
    assert_eq!(quote_rev.buy_quote.tax_output.tax_cost.amount.get(), 24_842);
    assert_eq!(
        quote_rev.buy_quote.tax_output.net_output.amount.get(),
        968_873
    );

    assert_eq!(
        quote_rev.sell_quote.tax_input.gross_input.asset,
        pool.token_0
    );
    assert_eq!(
        quote_rev.sell_quote.tax_input.gross_input.amount.get(),
        968_873
    );
    assert_eq!(quote_rev.sell_quote.tax_input.tax_cost.amount.get(), 48_443);
    assert_eq!(
        quote_rev
            .sell_quote
            .tax_input
            .net_transferable_input
            .amount
            .get(),
        920_430
    );
    assert_eq!(quote_rev.sell_quote.clmm_quote.fee.amount.get(), 2_761);
    assert_eq!(
        quote_rev.sell_quote.clmm_quote.effective_input.amount.get(),
        917_669
    );
    assert_eq!(quote_rev.sell_quote.clmm_quote.output.amount.get(), 920_708);
    assert_eq!(
        quote_rev.sell_quote.clmm_quote.resulting_sqrt_price_x64,
        18_476_421_743_173_964_973
    );
    assert_eq!(quote_rev.sell_quote.clmm_quote.resulting_tick, 32);
    assert_eq!(
        quote_rev.sell_quote.clmm_quote.resulting_liquidity,
        10_000_000_000
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(request_rev, initial_request_rev);
}

#[test]
fn test_roundtrip_zero_tax_conservation() {
    let pool = sample_clmm_pool();
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let buy_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        0,
        FreshnessStatus::Fresh,
    );
    let sell_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        0,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("zero-tax round-trip must succeed");

    assert_eq!(
        quote.buy_quote.tax_output.gross_output.amount.get(),
        100_018
    );
    assert_eq!(quote.buy_quote.tax_output.tax_cost.amount.get(), 0);
    assert_eq!(quote.buy_quote.tax_output.net_output.amount.get(), 100_018);
    assert_eq!(quote.buy_quote.clmm_quote.output.amount.get(), 100_018);
    assert_eq!(
        quote.buy_quote.tax_output.gross_output,
        quote.buy_quote.clmm_quote.output
    );

    assert_eq!(quote.sell_quote.tax_input.gross_input.amount.get(), 100_018);
    assert_eq!(quote.sell_quote.tax_input.tax_cost.amount.get(), 0);
    assert_eq!(
        quote
            .sell_quote
            .tax_input
            .net_transferable_input
            .amount
            .get(),
        100_018
    );
    assert_eq!(quote.sell_quote.clmm_quote.fee.amount.get(), 300);
    assert_eq!(
        quote.sell_quote.clmm_quote.effective_input.amount.get(),
        99_718
    );
    assert_eq!(quote.sell_quote.clmm_quote.output.amount.get(), 99_400);
    assert_eq!(
        quote.sell_quote.clmm_quote.resulting_sqrt_price_x64,
        18_476_280_456_262_426_713
    );
    assert_eq!(quote.sell_quote.clmm_quote.resulting_tick, 31);
}

#[test]
fn test_roundtrip_crossing_ticks_staged_state() {
    let pool = sample_clmm_pool();
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let buy_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::Fresh,
    );
    let sell_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("crossing round-trip must succeed");

    // Buy leg crosses tick 0 downward; staged liquidity must reflect the crossing.
    assert_eq!(quote.buy_quote.clmm_quote.output.amount.get(), 24_942_609);
    assert_eq!(quote.buy_quote.clmm_quote.resulting_tick, -18);
    assert_eq!(
        quote.buy_quote.clmm_quote.resulting_liquidity,
        9_995_000_000
    );
    assert_eq!(quote.buy_quote.tax_output.tax_cost.amount.get(), 623_565);
    assert_eq!(
        quote.buy_quote.tax_output.net_output.amount.get(),
        24_319_044
    );

    // Sell leg starts from the staged post-buy state and crosses back up through tick 0.
    assert_eq!(
        quote.sell_quote.tax_input.gross_input.amount.get(),
        24_319_044
    );
    assert_eq!(quote.sell_quote.tax_input.tax_cost.amount.get(), 1_215_952);
    assert_eq!(
        quote
            .sell_quote
            .tax_input
            .net_transferable_input
            .amount
            .get(),
        23_103_092
    );
    assert_eq!(quote.sell_quote.clmm_quote.fee.amount.get(), 69_309);
    assert_eq!(
        quote.sell_quote.clmm_quote.effective_input.amount.get(),
        23_033_783
    );
    assert_eq!(quote.sell_quote.clmm_quote.output.amount.get(), 23_021_906);
    assert_eq!(
        quote.sell_quote.clmm_quote.resulting_sqrt_price_x64,
        18_472_759_845_228_748_708
    );
    assert_eq!(quote.sell_quote.clmm_quote.resulting_tick, 28);
    assert_eq!(
        quote.sell_quote.clmm_quote.resulting_liquidity,
        10_000_000_000
    );
}

#[test]
fn test_roundtrip_fail_closed_with_immutability() {
    let pool = sample_clmm_pool();
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(1_000_000),
        token_out: None,
    };
    let fresh_buy = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::Fresh,
    );
    let fresh_sell = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );

    // Stale buy assessment fails before any sell leg.
    let stale_buy = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::Stale,
    );
    let pool_snapshot = pool.clone();
    let request_snapshot = request.clone();
    let sell_snapshot = fresh_sell.clone();
    let err =
        simulate_tax_aware_clmm_roundtrip_exact_input(&pool, &request, &stale_buy, &fresh_sell)
            .expect_err("stale buy must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::StaleObservation)
    );
    assert_eq!(pool, pool_snapshot);
    assert_eq!(request, request_snapshot);
    assert_eq!(fresh_sell, sell_snapshot);

    // Stale sell assessment fails after a successful buy, leaving caller inputs untouched.
    let stale_sell = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        500,
        FreshnessStatus::ResyncRequired,
    );
    let err =
        simulate_tax_aware_clmm_roundtrip_exact_input(&pool, &request, &fresh_buy, &stale_sell)
            .expect_err("stale sell must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_eq!(pool, pool_snapshot);
    assert_eq!(request, request_snapshot);

    // Sell assessment bound to the wrong asset fails closed.
    let wrong_asset_sell = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );
    let err = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &fresh_buy,
        &wrong_asset_sell,
    )
    .expect_err("wrong sell assessed asset must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );
    assert_eq!(pool, pool_snapshot);
    assert_eq!(request, request_snapshot);

    // Resync-required buy assessment fails closed.
    let resync_buy = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::ResyncRequired,
    );
    let err =
        simulate_tax_aware_clmm_roundtrip_exact_input(&pool, &request, &resync_buy, &fresh_sell)
            .expect_err("resync buy must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_eq!(pool, pool_snapshot);
    assert_eq!(request, request_snapshot);

    // Chain-mismatched sell assessment fails closed after a successful buy.
    let eth_output_asset = AssetId::new(
        ChainId::Ethereum,
        "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
    )
    .unwrap();
    let chain_mismatch_sell = sample_assessment(
        ChainId::Ethereum,
        eth_output_asset,
        0,
        500,
        FreshnessStatus::Fresh,
    );
    let err = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &fresh_buy,
        &chain_mismatch_sell,
    )
    .expect_err("chain-mismatched sell must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
    assert_eq!(pool, pool_snapshot);
    assert_eq!(request, request_snapshot);
}

#[test]
fn test_roundtrip_serialization() {
    let pool = sample_clmm_pool();
    let request = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let buy_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        0,
        FreshnessStatus::Fresh,
    );
    let sell_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        500,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_roundtrip_exact_input(
        &pool,
        &request,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("round-trip must succeed");

    let json = serde_json::to_string(&quote).expect("serialize round-trip quote");
    assert!(json.contains("buy_quote"));
    assert!(json.contains("sell_quote"));
    let deserialized: TaxAwareClmmRoundtripQuote =
        serde_json::from_str(&json).expect("deserialize round-trip quote");
    assert_eq!(deserialized, quote);
}
