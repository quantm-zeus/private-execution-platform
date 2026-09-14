//! Deterministic unit and integration tests for sell-side tax-aware CLMM simulation composition.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, ClmmPoolState, ClmmTick, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use simulation::clmm::sqrt_price_from_tick_index;
use simulation::{
    simulate_clmm_exact_input, simulate_tax_aware_clmm_sell_exact_input, ClmmExactInputRequest,
    ClmmSimulationError, TaxAwareClmmSellQuote, TaxAwareClmmSimulationError,
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

/// Sell-side assessment: the assessed asset is the input being disposed and sell tax is set.
fn sample_sell_assessment(
    chain: ChainId,
    asset: AssetId,
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
        Bps::new(0).expect("valid buy tax bps"),
        Bps::new(sell_tax_bps).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

#[test]
fn test_deterministic_clmm_sell_single_range_both_directions() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Direction 0 -> 1: gross input 100_000 SOL, sell tax 250 bps -> net 97_500 SOL.
    let req_0_to_1 = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_req_0_to_1 = req_0_to_1.clone();
    let assessment_0_to_1 = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_assessment_0_to_1 = assessment_0_to_1.clone();

    let result = simulate_tax_aware_clmm_sell_exact_input(&pool, &req_0_to_1, &assessment_0_to_1)
        .expect("tax-aware CLMM sell 0->1 simulation must succeed");

    // Literal sell-tax input economics.
    assert_eq!(result.tax_input.gross_input.asset, pool.token_0);
    assert_eq!(result.tax_input.gross_input.amount.get(), 100_000);
    assert_eq!(result.tax_input.tax_cost.asset, pool.token_0);
    assert_eq!(result.tax_input.tax_cost.amount.get(), 2_500);
    assert_eq!(result.tax_input.net_transferable_input.asset, pool.token_0);
    assert_eq!(result.tax_input.net_transferable_input.amount.get(), 97_500);

    // Literal complete CLMM vector executed on the net transferable input.
    assert_eq!(result.clmm_quote.input.asset, pool.token_0);
    assert_eq!(result.clmm_quote.input.amount.get(), 97_500);
    assert_eq!(result.clmm_quote.fee.asset, pool.token_0);
    assert_eq!(result.clmm_quote.fee.amount.get(), 292);
    assert_eq!(result.clmm_quote.effective_input.asset, pool.token_0);
    assert_eq!(result.clmm_quote.effective_input.amount.get(), 97_208);
    assert_eq!(result.clmm_quote.output.asset, pool.token_1);
    assert_eq!(result.clmm_quote.output.amount.get(), 97_518);
    assert_eq!(result.clmm_quote.fee_bps, pool.fee_bps);
    assert_eq!(
        result.clmm_quote.resulting_sqrt_price_x64,
        18_476_101_120_590_539_481
    );
    assert_eq!(result.clmm_quote.resulting_tick, 31);
    assert_eq!(result.clmm_quote.resulting_liquidity, 10_000_000_000);

    // Exact conservation identities.
    assert_eq!(
        result.tax_input.tax_cost.amount.get()
            + result.tax_input.net_transferable_input.amount.get(),
        result.tax_input.gross_input.amount.get()
    );
    assert_eq!(
        result.clmm_quote.fee.amount.get() + result.clmm_quote.effective_input.amount.get(),
        result.clmm_quote.input.amount.get()
    );

    // Structural cross-checks against the landed standalone CLMM kernel.
    let standalone = simulate_clmm_exact_input(
        &pool,
        &ClmmExactInputRequest {
            amount_in: AtomicAmount::new(97_500),
            ..req_0_to_1.clone()
        },
    )
    .expect("standalone net-input CLMM simulation must succeed");
    assert_eq!(result.clmm_quote, standalone);

    // Input immutability.
    assert_eq!(pool, initial_pool);
    assert_eq!(req_0_to_1, initial_req_0_to_1);
    assert_eq!(assessment_0_to_1, initial_assessment_0_to_1);

    // Direction 1 -> 0: gross input 100_000 USDC, sell tax 500 bps -> net 95_000 USDC.
    let req_1_to_0 = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_req_1_to_0 = req_1_to_0.clone();
    let assessment_1_to_0 = sample_sell_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        500,
        FreshnessStatus::Fresh,
    );
    let initial_assessment_1_to_0 = assessment_1_to_0.clone();

    let result_rev =
        simulate_tax_aware_clmm_sell_exact_input(&pool, &req_1_to_0, &assessment_1_to_0)
            .expect("tax-aware CLMM sell 1->0 simulation must succeed");

    assert_eq!(result_rev.tax_input.gross_input.amount.get(), 100_000);
    assert_eq!(result_rev.tax_input.tax_cost.amount.get(), 5_000);
    assert_eq!(
        result_rev.tax_input.net_transferable_input.amount.get(),
        95_000
    );

    assert_eq!(result_rev.clmm_quote.input.asset, pool.token_1);
    assert_eq!(result_rev.clmm_quote.input.amount.get(), 95_000);
    assert_eq!(result_rev.clmm_quote.fee.amount.get(), 285);
    assert_eq!(result_rev.clmm_quote.effective_input.amount.get(), 94_715);
    assert_eq!(result_rev.clmm_quote.output.asset, pool.token_0);
    assert_eq!(result_rev.clmm_quote.output.amount.get(), 94_411);
    assert_eq!(
        result_rev.clmm_quote.resulting_sqrt_price_x64,
        18_476_455_728_990_404_284
    );
    assert_eq!(result_rev.clmm_quote.resulting_tick, 32);
    assert_eq!(result_rev.clmm_quote.resulting_liquidity, 10_000_000_000);

    assert_eq!(
        result_rev.tax_input.tax_cost.amount.get()
            + result_rev.tax_input.net_transferable_input.amount.get(),
        result_rev.tax_input.gross_input.amount.get()
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(req_1_to_0, initial_req_1_to_0);
    assert_eq!(assessment_1_to_0, initial_assessment_1_to_0);
}

#[test]
fn test_deterministic_clmm_sell_crossing_ticks_exact_conservation() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Direction 0 -> 1 crossing tick 0 into [-128, 0):
    // gross 25_000_000 SOL, sell tax 250 bps -> net 24_375_000 SOL.
    let req_cross_down = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_down = req_cross_down.clone();
    let assessment_down = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_assessment_down = assessment_down.clone();

    let result_down =
        simulate_tax_aware_clmm_sell_exact_input(&pool, &req_cross_down, &assessment_down)
            .expect("tax-aware cross-tick sell 0->1 simulation must succeed");

    assert_eq!(result_down.tax_input.gross_input.amount.get(), 25_000_000);
    assert_eq!(result_down.tax_input.tax_cost.amount.get(), 625_000);
    assert_eq!(
        result_down.tax_input.net_transferable_input.amount.get(),
        24_375_000
    );
    assert_eq!(result_down.clmm_quote.input.amount.get(), 24_375_000);
    assert_eq!(result_down.clmm_quote.fee.amount.get(), 73_125);
    assert_eq!(
        result_down.clmm_quote.effective_input.amount.get(),
        24_301_875
    );
    assert_eq!(result_down.clmm_quote.output.asset, pool.token_1);
    assert_eq!(result_down.clmm_quote.output.amount.get(), 24_320_558);
    assert_eq!(
        result_down.clmm_quote.resulting_sqrt_price_x64,
        18_431_409_830_410_217_756
    );
    assert_eq!(result_down.clmm_quote.resulting_tick, -17);
    assert_eq!(result_down.clmm_quote.resulting_liquidity, 9_995_000_000);
    assert_eq!(
        result_down.tax_input.tax_cost.amount.get()
            + result_down.tax_input.net_transferable_input.amount.get(),
        result_down.tax_input.gross_input.amount.get()
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(req_cross_down, initial_req_down);
    assert_eq!(assessment_down, initial_assessment_down);

    // Direction 1 -> 0 crossing tick 64 into [64, 128):
    // gross 25_000_000 USDC, sell tax 500 bps -> net 23_750_000 USDC.
    let req_cross_up = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_up = req_cross_up.clone();
    let assessment_up = sample_sell_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        500,
        FreshnessStatus::Fresh,
    );
    let initial_assessment_up = assessment_up.clone();

    let result_up = simulate_tax_aware_clmm_sell_exact_input(&pool, &req_cross_up, &assessment_up)
        .expect("tax-aware cross-tick sell 1->0 simulation must succeed");

    assert_eq!(result_up.tax_input.gross_input.amount.get(), 25_000_000);
    assert_eq!(result_up.tax_input.tax_cost.amount.get(), 1_250_000);
    assert_eq!(
        result_up.tax_input.net_transferable_input.amount.get(),
        23_750_000
    );
    assert_eq!(result_up.clmm_quote.input.amount.get(), 23_750_000);
    assert_eq!(result_up.clmm_quote.fee.amount.get(), 71_250);
    assert_eq!(
        result_up.clmm_quote.effective_input.amount.get(),
        23_678_750
    );
    assert_eq!(result_up.clmm_quote.output.asset, pool.token_0);
    assert_eq!(result_up.clmm_quote.output.amount.get(), 23_547_429);
    assert_eq!(
        result_up.clmm_quote.resulting_sqrt_price_x64,
        18_519_970_466_652_930_559
    );
    assert_eq!(result_up.clmm_quote.resulting_tick, 79);
    assert_eq!(result_up.clmm_quote.resulting_liquidity, 9_993_000_000);
    assert_eq!(
        result_up.tax_input.tax_cost.amount.get()
            + result_up.tax_input.net_transferable_input.amount.get(),
        result_up.tax_input.gross_input.amount.get()
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(req_cross_up, initial_req_up);
    assert_eq!(assessment_up, initial_assessment_up);
}

#[test]
fn test_sell_tax_floor_rounding_sub_unit_remainders_and_conservation_sweep() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };

    // Hard-coded literal (sell_tax_bps, tax_cost, net_transferable, pool_fee, effective, output).
    let vectors: &[(u16, u128, u128, u128, u128, u128)] = &[
        (1, 10, 99_990, 299, 99_691, 100_009),
        (5, 50, 99_950, 299, 99_651, 99_969),
        (10, 100, 99_900, 299, 99_601, 99_919),
        (50, 500, 99_500, 298, 99_202, 99_518),
        (100, 1_000, 99_000, 297, 98_703, 99_018),
        (333, 3_330, 96_670, 290, 96_380, 96_687),
        (1_000, 10_000, 90_000, 270, 89_730, 90_016),
        (5_000, 50_000, 50_000, 150, 49_850, 50_009),
        (9_999, 99_990, 10, 0, 10, 10),
    ];

    for &(bps, exp_tax, exp_net, exp_fee, exp_eff, exp_out) in vectors {
        let assessment = sample_sell_assessment(
            ChainId::Solana,
            pool.token_0.clone(),
            bps,
            FreshnessStatus::Fresh,
        );
        let quote = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
            .unwrap_or_else(|e| panic!("failed for bps {}: {:?}", bps, e));

        assert_eq!(quote.tax_input.gross_input.amount.get(), 100_000);
        assert_eq!(
            quote.tax_input.tax_cost.amount.get(),
            exp_tax,
            "bps {}",
            bps
        );
        assert_eq!(
            quote.tax_input.net_transferable_input.amount.get(),
            exp_net,
            "bps {}",
            bps
        );
        assert_eq!(quote.clmm_quote.input.amount.get(), exp_net, "bps {}", bps);
        assert_eq!(quote.clmm_quote.fee.amount.get(), exp_fee, "bps {}", bps);
        assert_eq!(
            quote.clmm_quote.effective_input.amount.get(),
            exp_eff,
            "bps {}",
            bps
        );
        assert_eq!(quote.clmm_quote.output.amount.get(), exp_out, "bps {}", bps);
        assert_eq!(
            quote.tax_input.tax_cost.amount.get()
                + quote.tax_input.net_transferable_input.amount.get(),
            quote.tax_input.gross_input.amount.get(),
            "conservation bps {}",
            bps
        );
    }
}

#[test]
fn test_zero_sell_tax_success() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        0,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
        .expect("zero sell tax must succeed");

    assert_eq!(quote.tax_input.tax_cost.amount.get(), 0);
    assert_eq!(quote.tax_input.net_transferable_input.amount.get(), 100_000);
    assert_eq!(quote.clmm_quote.input.amount.get(), 100_000);
    assert_eq!(quote.clmm_quote.fee.amount.get(), 300);
    assert_eq!(quote.clmm_quote.effective_input.amount.get(), 99_700);
    assert_eq!(quote.clmm_quote.output.amount.get(), 100_018);
}

#[test]
fn test_max_sell_tax_zero_net_rejection_and_immutability() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_pool = pool.clone();
    let initial_req = req.clone();
    let assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        10_000,
        FreshnessStatus::Fresh,
    );
    let initial_assessment = assessment.clone();

    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
        .expect_err("100% sell tax must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );

    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
    assert_eq!(assessment, initial_assessment);
}

#[test]
fn test_stale_and_resync_assessments_fail_closed_with_immutability() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_pool = pool.clone();
    let initial_req = req.clone();

    for (status, expected) in [
        (
            FreshnessStatus::Stale,
            TaxAwareClmmSimulationError::Tax(TaxSafetyError::StaleObservation),
        ),
        (
            FreshnessStatus::ResyncRequired,
            TaxAwareClmmSimulationError::Tax(TaxSafetyError::ResyncRequired),
        ),
    ] {
        let assessment = sample_sell_assessment(ChainId::Solana, pool.token_0.clone(), 250, status);
        let initial_assessment = assessment.clone();
        let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
            .expect_err("non-fresh assessment must fail closed");
        assert_eq!(err, expected);
        assert_eq!(assessment, initial_assessment);
    }

    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
}

#[test]
fn test_assessed_input_asset_and_chain_mismatch_fail_closed() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };

    // Assessed asset mismatch (same chain, different asset).
    let foreign_solana = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let asset_mismatch =
        sample_sell_assessment(ChainId::Solana, foreign_solana, 250, FreshnessStatus::Fresh);
    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &asset_mismatch)
        .expect_err("assessed asset mismatch must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // Chain mismatch (input asset chain differs from assessment chain).
    let foreign_eth = AssetId::new(
        ChainId::Ethereum,
        "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
    )
    .unwrap();
    let chain_mismatch =
        sample_sell_assessment(ChainId::Ethereum, foreign_eth, 250, FreshnessStatus::Fresh);
    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &chain_mismatch)
        .expect_err("chain mismatch must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
}

#[test]
fn test_underlying_clmm_rejections_fail_closed_with_immutability() {
    let pool = sample_clmm_pool();

    // Invalid asset direction: assessed/input asset is on-pool-chain but absent from the pool.
    let absent = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let absent_req = ClmmExactInputRequest {
        token_in: absent.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let absent_assessment =
        sample_sell_assessment(ChainId::Solana, absent, 250, FreshnessStatus::Fresh);
    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &absent_req, &absent_assessment)
        .expect_err("absent pool asset must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidAssetDirection)
    );

    // CLMM chain mismatch: a coherent Ethereum-bounded input/assessment against a Solana pool.
    let eth_asset = AssetId::new(
        ChainId::Ethereum,
        "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
    )
    .unwrap();
    let eth_req = ClmmExactInputRequest {
        token_in: eth_asset.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let eth_assessment =
        sample_sell_assessment(ChainId::Ethereum, eth_asset, 250, FreshnessStatus::Fresh);
    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &eth_req, &eth_assessment)
        .expect_err("cross-chain pool input must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::ChainMismatch)
    );

    // Invalid pool fee is rejected by the CLMM layer after the sell tax layer accepts the input.
    let mut fee_pool = pool.clone();
    fee_pool.fee_bps = Bps::new(10_000).unwrap();
    let fee_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let fee_assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        0,
        FreshnessStatus::Fresh,
    );
    let fee_pool_snapshot = fee_pool.clone();
    let err = simulate_tax_aware_clmm_sell_exact_input(&fee_pool, &fee_req, &fee_assessment)
        .expect_err("invalid pool fee must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidFee)
    );
    assert_eq!(fee_pool, fee_pool_snapshot);

    // Input beyond every represented tick fails closed with tick-crossing exhaustion.
    let huge_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(1_000_000_000_000_000_000_000_000_000_000),
        token_out: None,
    };
    let huge_assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        0,
        FreshnessStatus::Fresh,
    );
    let err = simulate_tax_aware_clmm_sell_exact_input(&pool, &huge_req, &huge_assessment)
        .expect_err("exhausted tick traversal must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::TickCrossingExceeded)
    );

    // Pool tick/price desynchronization fails before quoting.
    let mut bad_pool = pool.clone();
    bad_pool.current_tick = 31;
    let good_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let good_assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let bad_pool_snapshot = bad_pool.clone();
    let err = simulate_tax_aware_clmm_sell_exact_input(&bad_pool, &good_req, &good_assessment)
        .expect_err("desynchronized pool must fail closed");
    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidRange)
    );
    assert_eq!(bad_pool, bad_pool_snapshot);
}

#[test]
fn test_large_safe_amount_and_bounded_arithmetic() {
    let (sol, usdc) = sample_assets();
    let s_0 = sqrt_price_from_tick_index(0).unwrap();
    let pool = ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: s_0,
        liquidity: 10_000_000_000_000_000,
        fee_bps: Bps::new(30).unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000_000_000_000, 5_000_000_000_000_000),
            ClmmTick::new(0, 20_000_000_000_000_000, 2_000_000_000_000_000),
            ClmmTick::new(64, 25_000_000_000_000_000, -3_000_000_000_000_000),
            ClmmTick::new(128, 15_000_000_000_000_000, -4_000_000_000_000_000),
        ],
    };

    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000_000_000_000),
        token_out: None,
    };
    let assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        350,
        FreshnessStatus::Fresh,
    );

    let result = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
        .expect("large safe input simulation must succeed");

    // Literal complete vector: gross 50e12, sell tax 350 bps.
    assert_eq!(result.tax_input.tax_cost.amount.get(), 1_750_000_000_000);
    assert_eq!(
        result.tax_input.net_transferable_input.amount.get(),
        48_250_000_000_000
    );
    assert_eq!(result.clmm_quote.input.amount.get(), 48_250_000_000_000);
    assert_eq!(result.clmm_quote.fee.amount.get(), 144_750_000_000);
    assert_eq!(
        result.clmm_quote.effective_input.amount.get(),
        48_105_250_000_000
    );
    assert_eq!(result.clmm_quote.output.amount.get(), 47_817_714_610_528);
    assert_eq!(
        result.clmm_quote.resulting_sqrt_price_x64,
        18_336_483_930_758_287_851
    );
    assert_eq!(result.clmm_quote.resulting_tick, -120);
    assert_eq!(result.clmm_quote.resulting_liquidity, 8_000_000_000_000_000);
}

#[test]
fn test_serialization_determinism() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let assessment = sample_sell_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment).unwrap();
    let json = serde_json::to_string(&quote).expect("serialize TaxAwareClmmSellQuote");
    assert!(json.contains("clmm_quote"));
    assert!(json.contains("tax_input"));
    assert!(json.contains("net_transferable_input"));

    let deserialized: TaxAwareClmmSellQuote =
        serde_json::from_str(&json).expect("deserialize TaxAwareClmmSellQuote");
    assert_eq!(deserialized, quote);
}

#[test]
fn test_display_and_debug_redaction_comprehensive() {
    let distinct_foreign_addr = "0xcccccccccccccccccccccccccccccccccccccccc";
    let distinct_amount_in = 123_456_789u128;
    let distinct_observed_ms = 12_345_678i64;
    let distinct_evaluated_ms = 12_399_999i64;
    let distinct_slot = 987_654_321u64;
    let distinct_tax_bps = 345u16;

    let sensitive_snippets = &[
        "So111111",
        "EPjFWdd5",
        "cccccccc",
        "123456789",
        "12345678",
        "12399999",
        "987654321",
    ];

    let assert_redacted = |err: &TaxAwareClmmSimulationError, label: &str| {
        let display_str = err.to_string();
        let debug_str = format!("{:?}", err);
        for snippet in sensitive_snippets {
            assert!(
                !display_str.contains(snippet),
                "[{}] Display leaked '{}': {}",
                label,
                snippet,
                display_str
            );
            assert!(
                !debug_str.contains(snippet),
                "[{}] Debug leaked '{}': {}",
                label,
                snippet,
                debug_str
            );
        }
    };

    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(distinct_amount_in),
        token_out: None,
    };
    let fresh = SafeFreshnessMeta {
        status: FreshnessStatus::Fresh,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 5_000,
        sequence: Sequence::new(distinct_slot),
    };
    let stale = SafeFreshnessMeta {
        status: FreshnessStatus::Stale,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 54_321,
        sequence: Sequence::new(distinct_slot),
    };

    // Stale: reaches the tax layer because sell tax is applied before CLMM.
    let stale_assessment = TaxAssessment::new(
        pool.token_0.clone(),
        ChainId::Solana,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        stale,
        distinct_slot,
    );
    let err_stale = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &stale_assessment)
        .expect_err("stale must fail");
    assert_redacted(&err_stale, "StaleObservation");
    assert_eq!(
        err_stale,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::StaleObservation)
    );

    // Zero gross input reaches the tax layer before CLMM.
    let zero_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(0),
        token_out: None,
    };
    let normal_assessment = TaxAssessment::new(
        pool.token_0.clone(),
        ChainId::Solana,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        fresh,
        distinct_slot,
    );
    let err_zero_in =
        simulate_tax_aware_clmm_sell_exact_input(&pool, &zero_req, &normal_assessment)
            .expect_err("zero input must fail");
    assert_redacted(&err_zero_in, "ZeroGrossInput");
    assert_eq!(
        err_zero_in,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ZeroGrossInput)
    );

    // Assessed asset mismatch.
    let foreign_assessment = TaxAssessment::new(
        AssetId::new(ChainId::Solana, distinct_foreign_addr.to_string()).unwrap(),
        ChainId::Solana,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        fresh,
        distinct_slot,
    );
    let err_mismatch = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &foreign_assessment)
        .expect_err("assessed asset mismatch must fail");
    assert_redacted(&err_mismatch, "AssessedAssetMismatch");
    assert_eq!(
        err_mismatch,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // Zero net input (100% tax) reaches the tax layer.
    let max_tax_assessment = TaxAssessment::new(
        pool.token_0.clone(),
        ChainId::Solana,
        Bps::new(0).unwrap(),
        Bps::new(10_000).unwrap(),
        fresh,
        distinct_slot,
    );
    let err_zero_net = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &max_tax_assessment)
        .expect_err("zero net input must fail");
    assert_redacted(&err_zero_net, "ZeroNetInput");
    assert_eq!(
        err_zero_net,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );

    // Direction mismatch reaches CLMM after a valid zero-tax input.
    let absent = AssetId::new(ChainId::Solana, distinct_foreign_addr.to_string()).unwrap();
    let absent_req = ClmmExactInputRequest {
        token_in: absent.clone(),
        amount_in: AtomicAmount::new(distinct_amount_in),
        token_out: None,
    };
    let absent_assessment = TaxAssessment::new(
        absent,
        ChainId::Solana,
        Bps::new(0).unwrap(),
        Bps::new(0).unwrap(),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: distinct_observed_ms,
            evaluated_at_ms: distinct_evaluated_ms,
            age_ms: 5_000,
            sequence: Sequence::new(distinct_slot),
        },
        distinct_slot,
    );
    let err_dir = simulate_tax_aware_clmm_sell_exact_input(&pool, &absent_req, &absent_assessment)
        .expect_err("absent pool asset must fail");
    assert_redacted(&err_dir, "InvalidAssetDirection");
    assert_eq!(
        err_dir,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidAssetDirection)
    );

    // Scan every CLMM and applicable tax error variant directly.
    let clmm_variants = [
        ClmmSimulationError::InvalidPoolState,
        ClmmSimulationError::ZeroInputAmount,
        ClmmSimulationError::InvalidLiquidity,
        ClmmSimulationError::InvalidFee,
        ClmmSimulationError::InvalidPrice,
        ClmmSimulationError::InvalidTick,
        ClmmSimulationError::InvalidRange,
        ClmmSimulationError::TickCrossingExceeded,
        ClmmSimulationError::InvalidAssetDirection,
        ClmmSimulationError::OutputAssetMismatch,
        ClmmSimulationError::ChainMismatch,
        ClmmSimulationError::ZeroEffectiveInput,
        ClmmSimulationError::ZeroOutputAmount,
        ClmmSimulationError::ArithmeticOverflow,
        ClmmSimulationError::InvariantViolated,
        ClmmSimulationError::OutputUnreachable,
        ClmmSimulationError::StaleOrUnavailableState,
    ];
    for variant in clmm_variants {
        assert_redacted(
            &TaxAwareClmmSimulationError::Clmm(variant),
            &format!("Clmm({:?})", variant),
        );
    }

    let tax_variants = [
        TaxSafetyError::MissingObservation,
        TaxSafetyError::ChainMismatch,
        TaxSafetyError::AssessedAssetMismatch,
        TaxSafetyError::FreshnessEvaluationFailed,
        TaxSafetyError::StaleObservation,
        TaxSafetyError::ResyncRequired,
        TaxSafetyError::BuySimulationFailed,
        TaxSafetyError::SellSimulationFailed,
        TaxSafetyError::TokenNotSellable,
        TaxSafetyError::BuyTaxExceedsCap,
        TaxSafetyError::SellTaxExceedsCap,
        TaxSafetyError::ZeroGrossOutput,
        TaxSafetyError::ZeroNetOutput,
        TaxSafetyError::ZeroGrossInput,
        TaxSafetyError::ZeroNetInput,
    ];
    for variant in tax_variants {
        let label = format!("Tax({:?})", variant);
        assert_redacted(&TaxAwareClmmSimulationError::Tax(variant), &label);
    }
}

#[test]
fn test_sell_tax_floor_remainder_discriminates_from_ceil() {
    // (sell_tax_bps, floor tax, ceil tax, net input, pool fee, effective, output, sqrt).
    type FloorVector = (u16, u128, u128, u128, u128, u128, u128, u128);

    // Gross inputs that are NOT multiples of 10_000 so the sell-tax division has a
    // non-zero remainder. A ceil-rounded tax (or a pool-fee-before-tax ordering with a
    // different net) would change these literals.
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_003),
        token_out: None,
    };

    let vectors: &[FloorVector] = &[
        (
            1,
            10,
            11,
            99_993,
            299,
            99_694,
            100_012,
            18_476_096_520_123_169_893,
        ),
        (
            3,
            30,
            31,
            99_973,
            299,
            99_674,
            99_992,
            18_476_096_557_134_161_312,
        ),
        (
            333,
            3_330,
            3_331,
            96_673,
            290,
            96_383,
            96_690,
            18_476_102_647_294_818_870,
        ),
        (
            500,
            5_000,
            5_001,
            95_003,
            285,
            94_718,
            95_020,
            18_476_105_728_462_405_705,
        ),
    ];

    for &(bps, floor_tax, ceil_tax, exp_net, exp_fee, exp_eff, exp_out, exp_sqrt) in vectors {
        assert_ne!(
            floor_tax, ceil_tax,
            "vector must discriminate floor from ceil"
        );
        let assessment = sample_sell_assessment(
            ChainId::Solana,
            pool.token_0.clone(),
            bps,
            FreshnessStatus::Fresh,
        );
        let quote = simulate_tax_aware_clmm_sell_exact_input(&pool, &req, &assessment)
            .unwrap_or_else(|e| panic!("failed for bps {}: {:?}", bps, e));
        assert_eq!(
            quote.tax_input.tax_cost.amount.get(),
            floor_tax,
            "floor tax bps {}",
            bps
        );
        assert_eq!(
            quote.tax_input.net_transferable_input.amount.get(),
            exp_net,
            "net bps {}",
            bps
        );
        assert_eq!(
            quote.clmm_quote.fee.amount.get(),
            exp_fee,
            "fee bps {}",
            bps
        );
        assert_eq!(
            quote.clmm_quote.effective_input.amount.get(),
            exp_eff,
            "eff bps {}",
            bps
        );
        assert_eq!(
            quote.clmm_quote.output.amount.get(),
            exp_out,
            "out bps {}",
            bps
        );
        assert_eq!(
            quote.clmm_quote.resulting_sqrt_price_x64, exp_sqrt,
            "sqrt bps {}",
            bps
        );
        assert_eq!(
            quote.tax_input.tax_cost.amount.get()
                + quote.tax_input.net_transferable_input.amount.get(),
            100_003
        );
    }
}
