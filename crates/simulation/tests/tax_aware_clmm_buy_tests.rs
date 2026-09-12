//! Deterministic unit and integration tests for buy-side tax-aware CLMM simulation composition.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, ClmmPoolState, ClmmTick, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use simulation::clmm::sqrt_price_from_tick_index;
use simulation::{
    simulate_clmm_exact_input, simulate_tax_aware_clmm_buy_exact_input, ClmmExactInputRequest,
    ClmmSimulationError, TaxAwareClmmBuyQuote, TaxAwareClmmSimulationError,
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
    // Active range [0, 64):
    // tick 0: sqrt_price_x64 = 18446744073709551616 (1.0 in Q64)
    // tick 64: sqrt_price_x64 = 18505865242158250041
    // current_tick 32: sqrt_price_x64 = 18476281010653910144
    ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: 18_476_281_010_653_910_144,
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(30).expect("valid fee bps"), // 0.30%
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
        Bps::new(0).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

// =========================================================================
// 1. Hard-coded deterministic CLMM buy vectors
//    - Single range quote (within active ticks)
//    - Cross-tick quote (crosses initialized ticks)
//    - Both swap directions (0 -> 1 and 1 -> 0)
//    - Exact preservation of gross CLMM quote, pool fee, tax cost, net output,
//      and exact conservation: gross_output == net_output + tax_cost
// =========================================================================

#[test]
fn test_deterministic_clmm_buy_single_range_both_directions() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Direction 0 -> 1: Input SOL (token 0), output USDC (token 1).
    // Swap 100_000 SOL.
    // Pool fee: 100_000 * 30 / 10_000 = 300 SOL
    // Effective input: 99_700 SOL
    let req_0_to_1 = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_req_0_to_1 = req_0_to_1.clone();

    // Standalone CLMM simulation to verify exact baseline quote
    let standalone_quote = simulate_clmm_exact_input(&pool, &req_0_to_1)
        .expect("standalone CLMM simulation should succeed");

    // Tax assessment on output asset (USDC / token 1) with 250 bps buy tax (2.5%)
    let assessment_usdc = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_assessment = assessment_usdc.clone();

    let result: TaxAwareClmmBuyQuote =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &req_0_to_1, &assessment_usdc)
            .expect("tax-aware CLMM buy simulation must succeed");

    // 1. Exact gross CLMM quote preservation
    assert_eq!(result.clmm_quote, standalone_quote);
    assert_eq!(result.clmm_quote.input.asset, pool.token_0);
    assert_eq!(result.clmm_quote.input.amount.get(), 100_000);
    assert_eq!(result.clmm_quote.fee.asset, pool.token_0);
    assert_eq!(result.clmm_quote.fee.amount.get(), 300);
    assert_eq!(result.clmm_quote.effective_input.asset, pool.token_0);
    assert_eq!(result.clmm_quote.effective_input.amount.get(), 99_700);
    assert_eq!(
        result.clmm_quote.fee.amount.get() + result.clmm_quote.effective_input.amount.get(),
        result.clmm_quote.input.amount.get()
    );
    assert_eq!(result.clmm_quote.output.asset, pool.token_1);
    assert_eq!(result.clmm_quote.fee_bps, pool.fee_bps);

    // 2. Tax output economics
    let gross_out = result.clmm_quote.output.amount.get();
    let expected_tax = gross_out * 250 / 10_000;
    let expected_net = gross_out - expected_tax;

    assert_eq!(result.tax_output.gross_output, result.clmm_quote.output);
    assert_eq!(result.tax_output.tax_cost.asset, pool.token_1);
    assert_eq!(result.tax_output.tax_cost.amount.get(), expected_tax);
    assert_eq!(result.tax_output.net_output.asset, pool.token_1);
    assert_eq!(result.tax_output.net_output.amount.get(), expected_net);

    // 3. Exact conservation: net_output + tax_cost == gross_output
    assert_eq!(
        result.tax_output.net_output.amount.get() + result.tax_output.tax_cost.amount.get(),
        result.tax_output.gross_output.amount.get()
    );

    // 4. Input immutability
    assert_eq!(pool, initial_pool);
    assert_eq!(req_0_to_1, initial_req_0_to_1);
    assert_eq!(assessment_usdc, initial_assessment);

    // Direction 1 -> 0: Input USDC (token 1), output SOL (token 0).
    // Swap 100_000 USDC.
    let req_1_to_0 = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let standalone_quote_rev = simulate_clmm_exact_input(&pool, &req_1_to_0)
        .expect("standalone CLMM 1->0 simulation should succeed");

    // Tax assessment on output asset (SOL / token 0) with 500 bps buy tax (5.0%)
    let assessment_sol = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        500,
        FreshnessStatus::Fresh,
    );
    let result_rev = simulate_tax_aware_clmm_buy_exact_input(&pool, &req_1_to_0, &assessment_sol)
        .expect("tax-aware CLMM buy 1->0 simulation must succeed");

    assert_eq!(result_rev.clmm_quote, standalone_quote_rev);
    assert_eq!(result_rev.clmm_quote.output.asset, pool.token_0);
    assert_eq!(
        result_rev.tax_output.gross_output,
        result_rev.clmm_quote.output
    );

    let gross_out_rev = result_rev.clmm_quote.output.amount.get();
    let expected_tax_rev = gross_out_rev * 500 / 10_000;
    let expected_net_rev = gross_out_rev - expected_tax_rev;

    assert_eq!(
        result_rev.tax_output.tax_cost.amount.get(),
        expected_tax_rev
    );
    assert_eq!(
        result_rev.tax_output.net_output.amount.get(),
        expected_net_rev
    );
    assert_eq!(
        result_rev.tax_output.net_output.amount.get() + result_rev.tax_output.tax_cost.amount.get(),
        result_rev.tax_output.gross_output.amount.get()
    );
}

#[test]
fn test_deterministic_clmm_buy_crossing_ticks_exact_conservation() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Direction 0 -> 1 crossing tick 0 moving down:
    // Initial active range [0, 64), current tick 32.
    // Crossing tick 0 moving into [-128, 0).
    // Input: 25_000_000 SOL.
    // Pool fee: 25_000_000 * 30 / 10_000 = 75_000 SOL.
    // Effective input: 24_925_000 SOL.
    // Landed standalone quote produces gross output: 24_942_609 USDC.
    // Resulting sqrt price: 18_430_261_775_357_090_295.
    // Resulting tick: -18 (crossed tick 0).
    // Resulting liquidity: 9_995_000_000.
    let req_cross_down = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_down = req_cross_down.clone();

    let standalone_quote_down = simulate_clmm_exact_input(&pool, &req_cross_down)
        .expect("standalone cross-tick CLMM simulation should succeed");
    assert_eq!(standalone_quote_down.resulting_tick, -18);
    assert_eq!(standalone_quote_down.output.amount.get(), 24_942_609);

    // Apply buy tax to output USDC: 250 bps (2.5%)
    // tax_cost = floor(24_942_609 * 250 / 10_000) = floor(6_235_652_250 / 10_000) = 623_565
    // net_output = 24_942_609 - 623_565 = 24_319_044
    let assessment_usdc = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_assessment = assessment_usdc.clone();

    let result_cross_down =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &req_cross_down, &assessment_usdc)
            .expect("tax-aware cross-tick simulation must succeed");

    // Intact preservation of CLMM quote across tick boundary:
    assert_eq!(result_cross_down.clmm_quote, standalone_quote_down);
    assert_eq!(result_cross_down.clmm_quote.input.amount.get(), 25_000_000);
    assert_eq!(result_cross_down.clmm_quote.fee.amount.get(), 75_000);
    assert_eq!(
        result_cross_down.clmm_quote.effective_input.amount.get(),
        24_925_000
    );
    assert_eq!(result_cross_down.clmm_quote.output.amount.get(), 24_942_609);
    assert_eq!(result_cross_down.clmm_quote.resulting_tick, -18);
    assert_eq!(
        result_cross_down.clmm_quote.resulting_liquidity,
        9_995_000_000
    );
    assert_eq!(
        result_cross_down.clmm_quote.resulting_sqrt_price_x64,
        18_430_261_775_357_090_295
    );

    // Tax output economics:
    assert_eq!(
        result_cross_down.tax_output.gross_output,
        result_cross_down.clmm_quote.output
    );
    assert_eq!(result_cross_down.tax_output.tax_cost.amount.get(), 623_565);
    assert_eq!(
        result_cross_down.tax_output.net_output.amount.get(),
        24_319_044
    );

    // Exact output conservation: net + tax == gross
    assert_eq!(
        result_cross_down.tax_output.net_output.amount.get()
            + result_cross_down.tax_output.tax_cost.amount.get(),
        result_cross_down.tax_output.gross_output.amount.get()
    );

    // Immutability:
    assert_eq!(pool, initial_pool);
    assert_eq!(req_cross_down, initial_req_down);
    assert_eq!(assessment_usdc, initial_assessment);

    // Direction 1 -> 0 crossing tick 64 moving up:
    // Input: 25_000_000 USDC.
    // Pool fee: 75_000 USDC.
    // Effective input: 24_925_000 USDC.
    // Landed standalone quote produces gross output: 24_783_689 SOL.
    // Resulting tick: 81 (crossed tick 64).
    // Resulting liquidity: 9_993_000_000.
    let req_cross_up = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let standalone_quote_up = simulate_clmm_exact_input(&pool, &req_cross_up)
        .expect("standalone cross-tick up simulation should succeed");
    assert_eq!(standalone_quote_up.resulting_tick, 81);
    assert_eq!(standalone_quote_up.output.amount.get(), 24_783_689);

    // Apply buy tax to output SOL: 500 bps (5.0%)
    // tax_cost = floor(24_783_689 * 500 / 10_000) = floor(12_391_844_500 / 10_000) = 1_239_184
    // net_output = 24_783_689 - 1_239_184 = 23_544_505
    let assessment_sol = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        500,
        FreshnessStatus::Fresh,
    );
    let result_cross_up =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &req_cross_up, &assessment_sol)
            .expect("tax-aware cross-tick up simulation must succeed");

    assert_eq!(result_cross_up.clmm_quote, standalone_quote_up);
    assert_eq!(result_cross_up.clmm_quote.input.amount.get(), 25_000_000);
    assert_eq!(result_cross_up.clmm_quote.fee.amount.get(), 75_000);
    assert_eq!(result_cross_up.clmm_quote.output.amount.get(), 24_783_689);
    assert_eq!(result_cross_up.clmm_quote.resulting_tick, 81);
    assert_eq!(result_cross_up.tax_output.tax_cost.amount.get(), 1_239_184);
    assert_eq!(
        result_cross_up.tax_output.net_output.amount.get(),
        23_544_505
    );
    assert_eq!(
        result_cross_up.tax_output.net_output.amount.get()
            + result_cross_up.tax_output.tax_cost.amount.get(),
        result_cross_up.tax_output.gross_output.amount.get()
    );
}

#[test]
fn test_tax_floor_rounding_sub_unit_remainders_and_conservation_sweep() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let standalone = simulate_clmm_exact_input(&pool, &req).unwrap();
    let gross_out = standalone.output.amount.get();

    let tax_vectors: &[(u16, u128, u128)] = &[
        // (bps, expected_tax, expected_net)
        (1, gross_out / 10_000, gross_out - (gross_out / 10_000)),
        (
            5,
            gross_out * 5 / 10_000,
            gross_out - (gross_out * 5 / 10_000),
        ),
        (
            10,
            gross_out * 10 / 10_000,
            gross_out - (gross_out * 10 / 10_000),
        ),
        (
            50,
            gross_out * 50 / 10_000,
            gross_out - (gross_out * 50 / 10_000),
        ),
        (
            100,
            gross_out * 100 / 10_000,
            gross_out - (gross_out * 100 / 10_000),
        ),
        (
            333,
            gross_out * 333 / 10_000,
            gross_out - (gross_out * 333 / 10_000),
        ),
        (
            1_000,
            gross_out * 1_000 / 10_000,
            gross_out - (gross_out * 1_000 / 10_000),
        ),
        (
            9_999,
            gross_out * 9_999 / 10_000,
            gross_out - (gross_out * 9_999 / 10_000),
        ),
    ];

    for &(bps, exp_tax, exp_net) in tax_vectors {
        let assessment = sample_assessment(
            ChainId::Solana,
            pool.token_1.clone(),
            bps,
            FreshnessStatus::Fresh,
        );
        let quote = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &assessment)
            .unwrap_or_else(|e| panic!("failed for bps {}: {:?}", bps, e));

        assert_eq!(
            quote.tax_output.tax_cost.amount.get(),
            exp_tax,
            "tax mismatch for bps {}",
            bps
        );
        assert_eq!(
            quote.tax_output.net_output.amount.get(),
            exp_net,
            "net mismatch for bps {}",
            bps
        );
        assert_eq!(
            quote.tax_output.gross_output.amount.get(),
            quote.tax_output.tax_cost.amount.get() + quote.tax_output.net_output.amount.get(),
            "conservation failed for bps {}",
            bps
        );
    }
}

// =========================================================================
// 2. Zero buy-tax success and max-tax/zero-net rejection
// =========================================================================

#[test]
fn test_zero_buy_tax_success() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let assessment_zero = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        0,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &assessment_zero)
        .expect("zero-tax buy must succeed");

    assert_eq!(quote.tax_output.tax_cost.amount.get(), 0);
    assert_eq!(
        quote.tax_output.net_output.amount.get(),
        quote.tax_output.gross_output.amount.get()
    );
    assert_eq!(
        quote.tax_output.gross_output.amount.get(),
        quote.tax_output.tax_cost.amount.get() + quote.tax_output.net_output.amount.get()
    );
}

#[test]
fn test_max_tax_and_zero_net_rejection() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };

    // 100% tax = 10_000 bps -> net output = 0 -> must fail closed with ZeroNetOutput
    let assessment_100 = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        10_000,
        FreshnessStatus::Fresh,
    );
    let err = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &assessment_100)
        .expect_err("100% tax must fail closed");

    assert_eq!(
        err,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ZeroNetOutput)
    );
}

// =========================================================================
// 3. Stale and resync assessment rejection, assessed output asset/chain mismatch,
//    and invalid CLMM request/pool/traversal rejection, all with input immutability
// =========================================================================

#[test]
fn test_stale_and_resync_assessments_fail_closed_with_immutability() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_req = req.clone();

    // 3A: Stale assessment
    let stale_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::Stale,
    );
    let initial_stale = stale_assessment.clone();
    let err_stale = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &stale_assessment)
        .expect_err("stale assessment must fail closed");
    assert_eq!(
        err_stale,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::StaleObservation)
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
    assert_eq!(stale_assessment, initial_stale);

    // 3B: ResyncRequired assessment
    let resync_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::ResyncRequired,
    );
    let initial_resync = resync_assessment.clone();
    let err_resync = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &resync_assessment)
        .expect_err("resync assessment must fail closed");
    assert_eq!(
        err_resync,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
    assert_eq!(resync_assessment, initial_resync);
}

#[test]
fn test_assessed_output_asset_and_chain_mismatch_fail_closed() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_req = req.clone();

    // 3C: Assessment is for input asset (token 0 / SOL) instead of gross output (token 1 / USDC)
    let mismatch_assessment = sample_assessment(
        ChainId::Solana,
        pool.token_0.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_mismatch = mismatch_assessment.clone();
    let err_mismatch = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &mismatch_assessment)
        .expect_err("assessed asset mismatch must fail closed");
    assert_eq!(
        err_mismatch,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
    assert_eq!(mismatch_assessment, initial_mismatch);

    // 3D: Assessment is on a different chain (Ethereum vs Solana)
    let foreign_asset = AssetId::new(
        ChainId::Ethereum,
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
    )
    .unwrap();
    let chain_mismatch_assessment = sample_assessment(
        ChainId::Ethereum,
        foreign_asset,
        250,
        FreshnessStatus::Fresh,
    );
    let initial_chain_mismatch = chain_mismatch_assessment.clone();
    let err_chain =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &chain_mismatch_assessment)
            .expect_err("chain mismatch must fail closed");
    assert_eq!(
        err_chain,
        TaxAwareClmmSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req, initial_req);
    assert_eq!(chain_mismatch_assessment, initial_chain_mismatch);
}

#[test]
fn test_underlying_clmm_rejections_fail_closed_with_immutability() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();
    let assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::Fresh,
    );
    let initial_assessment = assessment.clone();

    // 3E1: Zero input amount
    let zero_in_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(0),
        token_out: None,
    };
    let initial_zero_in = zero_in_req.clone();
    let err_zero_in = simulate_tax_aware_clmm_buy_exact_input(&pool, &zero_in_req, &assessment)
        .expect_err("zero input amount must fail closed");
    assert_eq!(
        err_zero_in,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::ZeroInputAmount)
    );
    assert_eq!(zero_in_req, initial_zero_in);
    assert_eq!(pool, initial_pool);
    assert_eq!(assessment, initial_assessment);

    // 3E2: Unknown input asset not in pool
    let unknown_asset = AssetId::new(
        ChainId::Solana,
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
    )
    .unwrap();
    let unknown_in_req = ClmmExactInputRequest {
        token_in: unknown_asset,
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_unknown_in = unknown_in_req.clone();
    let err_unknown_in =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &unknown_in_req, &assessment)
            .expect_err("unknown input asset must fail closed");
    assert_eq!(
        err_unknown_in,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidAssetDirection)
    );
    assert_eq!(unknown_in_req, initial_unknown_in);
    assert_eq!(pool, initial_pool);
    assert_eq!(assessment, initial_assessment);

    // 3E3: Same asset in and out -> InvalidAssetDirection
    let same_asset_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: Some(pool.token_0.clone()),
    };
    let initial_same = same_asset_req.clone();
    let err_same = simulate_tax_aware_clmm_buy_exact_input(&pool, &same_asset_req, &assessment)
        .expect_err("same asset in and out must fail closed");
    assert_eq!(
        err_same,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidAssetDirection)
    );
    assert_eq!(same_asset_req, initial_same);

    // 3E4: Caller-asserted output asset mismatch (unrelated token on same chain) -> OutputAssetMismatch
    let unrelated_asset = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let mismatch_out_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: Some(unrelated_asset),
    };
    let initial_mismatch_out = mismatch_out_req.clone();
    let err_out_mismatch =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &mismatch_out_req, &assessment)
            .expect_err("caller-asserted output asset mismatch must fail closed");
    assert_eq!(
        err_out_mismatch,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::OutputAssetMismatch)
    );
    assert_eq!(mismatch_out_req, initial_mismatch_out);
    assert_eq!(pool, initial_pool);
    assert_eq!(assessment, initial_assessment);

    // 3E5: Input asset chain mismatch (e.g. EVM token in Solana pool)
    let evm_token = AssetId::new(
        ChainId::Ethereum,
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
    )
    .unwrap();
    let evm_req = ClmmExactInputRequest {
        token_in: evm_token,
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let err_chain = simulate_tax_aware_clmm_buy_exact_input(&pool, &evm_req, &assessment)
        .expect_err("chain mismatch must fail closed");
    assert_eq!(
        err_chain,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::ChainMismatch)
    );

    // 3E5: Huge input amount that exceeds boundary / tick crossing capacity
    let huge_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(u128::MAX / 2),
        token_out: None,
    };
    let err_huge = simulate_tax_aware_clmm_buy_exact_input(&pool, &huge_req, &assessment)
        .expect_err("huge input exceeding crossing capacity must fail closed");
    assert_eq!(
        err_huge,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::TickCrossingExceeded)
    );

    // 3E6: Pool current tick and sqrt price desynchronization -> InvalidRange
    let mut desync_pool = pool.clone();
    desync_pool.current_tick = 63;
    desync_pool.sqrt_price_x64 = sqrt_price_from_tick_index(64).unwrap();
    let valid_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let err_desync = simulate_tax_aware_clmm_buy_exact_input(&desync_pool, &valid_req, &assessment)
        .expect_err("desynchronized pool must fail closed");
    assert_eq!(
        err_desync,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidRange)
    );

    // 3E7: Invalid zero sqrt price -> InvalidPrice
    let mut zero_price_pool = pool.clone();
    zero_price_pool.sqrt_price_x64 = 0;
    let err_zero_price =
        simulate_tax_aware_clmm_buy_exact_input(&zero_price_pool, &valid_req, &assessment)
            .expect_err("zero price pool must fail closed");
    assert_eq!(
        err_zero_price,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidPrice)
    );

    // 3E8: Zero pool liquidity -> InvalidLiquidity
    let mut zero_liq_pool = pool.clone();
    zero_liq_pool.liquidity = 0;
    let err_zero_liq =
        simulate_tax_aware_clmm_buy_exact_input(&zero_liq_pool, &valid_req, &assessment)
            .expect_err("zero liquidity pool must fail closed");
    assert_eq!(
        err_zero_liq,
        TaxAwareClmmSimulationError::Clmm(ClmmSimulationError::InvalidLiquidity)
    );
}

// =========================================================================
// 4. Large safe amount / bounded arithmetic vector plus serialization determinism
// =========================================================================

#[test]
fn test_large_safe_amount_and_bounded_arithmetic() {
    let (sol, usdc) = sample_assets();
    // High liquidity pool: L = 10^16, active tick 0
    let s_0 = sqrt_price_from_tick_index(0).unwrap();
    let pool = ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: s_0,
        liquidity: 10_000_000_000_000_000, // 10^16
        fee_bps: Bps::new(30).unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000_000_000_000, 5_000_000_000_000_000),
            ClmmTick::new(0, 20_000_000_000_000_000, 2_000_000_000_000_000),
            ClmmTick::new(64, 25_000_000_000_000_000, -3_000_000_000_000_000),
            ClmmTick::new(128, 15_000_000_000_000_000, -4_000_000_000_000_000),
        ],
    };

    // Large input: 50_000_000_000_000 (50 trillion atomic units)
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000_000_000_000),
        token_out: None,
    };

    let assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        350, // 3.50%
        FreshnessStatus::Fresh,
    );

    let result = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &assessment)
        .expect("large safe input simulation must succeed");

    assert_eq!(result.clmm_quote.input.amount.get(), 50_000_000_000_000);
    assert_eq!(result.clmm_quote.fee.amount.get(), 150_000_000_000); // 30 bps
    assert_eq!(
        result.clmm_quote.effective_input.amount.get(),
        49_850_000_000_000
    );

    let gross_out = result.clmm_quote.output.amount.get();
    let expected_tax = gross_out * 350 / 10_000;
    let expected_net = gross_out - expected_tax;

    assert_eq!(result.tax_output.tax_cost.amount.get(), expected_tax);
    assert_eq!(result.tax_output.net_output.amount.get(), expected_net);
    assert_eq!(
        result.tax_output.net_output.amount.get() + result.tax_output.tax_cost.amount.get(),
        result.tax_output.gross_output.amount.get()
    );
}

#[test]
fn test_serialization_determinism() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let assessment = sample_assessment(
        ChainId::Solana,
        pool.token_1.clone(),
        250,
        FreshnessStatus::Fresh,
    );

    let quote = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &assessment).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&quote).expect("serialize TaxAwareClmmBuyQuote");
    assert!(json.contains("clmm_quote"));
    assert!(json.contains("tax_output"));
    assert!(json.contains("gross_output"));
    assert!(json.contains("tax_cost"));
    assert!(json.contains("net_output"));

    // Deserialize back and assert exact structural equality
    let deserialized: TaxAwareClmmBuyQuote =
        serde_json::from_str(&json).expect("deserialize TaxAwareClmmBuyQuote");
    assert_eq!(deserialized, quote);
    assert_eq!(deserialized.clmm_quote, quote.clmm_quote);
    assert_eq!(deserialized.tax_output, quote.tax_output);
}

// =========================================================================
// 5. Comprehensive Debug/Display redaction scan for all new errors
// =========================================================================

#[test]
fn test_display_and_debug_redaction_comprehensive() {
    let distinct_addr_0 = "So11111111111111111111111111111111111111112";
    let distinct_addr_1 = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let distinct_foreign_addr = "0xcccccccccccccccccccccccccccccccccccccccc";
    let distinct_amount_in = 777_888_999_000_111u128;
    let distinct_liquidity = 555_666_777_888_999u128;
    let distinct_sqrt_price = 18_476_281_010_653_910_144u128;
    let distinct_observed_ms = 12_345_678i64;
    let distinct_evaluated_ms = 12_399_999i64;
    let distinct_slot = 987_654_321u64;
    let distinct_tax_bps = 345u16;

    let sensitive_snippets = &[
        "So111111",
        "EPjFWdd5",
        "cccccccc",
        "777888999",
        "555666777",
        "18476281010653910144",
        "12345678",
        "12399999",
        "987654321",
        "345",
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

    // 5A: Stale assessment error
    let freshness_stale = SafeFreshnessMeta {
        status: FreshnessStatus::Stale,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 54_321,
        sequence: Sequence::new(distinct_slot),
    };
    let stale_assessment = TaxAssessment::new(
        AssetId::new(ChainId::Solana, distinct_addr_1.to_string()).unwrap(),
        ChainId::Solana,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_stale,
        distinct_slot,
    );
    let pool = ClmmPoolState {
        token_0: AssetId::new(ChainId::Solana, distinct_addr_0.to_string()).unwrap(),
        token_1: AssetId::new(ChainId::Solana, distinct_addr_1.to_string()).unwrap(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: distinct_sqrt_price,
        liquidity: distinct_liquidity,
        fee_bps: Bps::new(30).unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    };
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(distinct_amount_in),
        token_out: None,
    };

    let err_stale = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &stale_assessment)
        .expect_err("stale must fail");
    assert_redacted(&err_stale, "StaleObservation");

    // 5B: Resync assessment error
    let freshness_resync = SafeFreshnessMeta {
        status: FreshnessStatus::ResyncRequired,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 54_321,
        sequence: Sequence::new(distinct_slot),
    };
    let resync_assessment = TaxAssessment::new(
        AssetId::new(ChainId::Solana, distinct_addr_1.to_string()).unwrap(),
        ChainId::Solana,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_resync,
        distinct_slot,
    );
    let err_resync = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &resync_assessment)
        .expect_err("resync must fail");
    assert_redacted(&err_resync, "ResyncRequired");

    // 5C: Assessed asset mismatch
    let freshness_fresh = SafeFreshnessMeta {
        status: FreshnessStatus::Fresh,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 5_000,
        sequence: Sequence::new(distinct_slot),
    };
    let mismatch_assessment = TaxAssessment::new(
        AssetId::new(ChainId::Solana, distinct_foreign_addr.to_string()).unwrap(),
        ChainId::Solana,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_fresh,
        distinct_slot,
    );
    let err_mismatch = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &mismatch_assessment)
        .expect_err("mismatch must fail");
    assert_redacted(&err_mismatch, "AssessedAssetMismatch");

    // 5D: Chain mismatch
    let chain_mismatch_assessment = TaxAssessment::new(
        AssetId::new(ChainId::Ethereum, distinct_foreign_addr.to_string()).unwrap(),
        ChainId::Ethereum,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_fresh,
        distinct_slot,
    );
    let err_chain =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &chain_mismatch_assessment)
            .expect_err("chain mismatch must fail");
    assert_redacted(&err_chain, "ChainMismatch");

    // 5E: Zero net output (100% tax)
    let max_tax_assessment = TaxAssessment::new(
        pool.token_1.clone(),
        ChainId::Solana,
        Bps::new(10_000).unwrap(),
        Bps::new(0).unwrap(),
        freshness_fresh,
        distinct_slot,
    );
    let err_zero_net = simulate_tax_aware_clmm_buy_exact_input(&pool, &req, &max_tax_assessment)
        .expect_err("zero net must fail");
    assert_redacted(&err_zero_net, "ZeroNetOutput");

    // 5F: Zero input amount
    let zero_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(0),
        token_out: None,
    };
    let normal_assessment = TaxAssessment::new(
        pool.token_1.clone(),
        ChainId::Solana,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_fresh,
        distinct_slot,
    );
    let err_zero_in = simulate_tax_aware_clmm_buy_exact_input(&pool, &zero_req, &normal_assessment)
        .expect_err("zero input must fail");
    assert_redacted(&err_zero_in, "ZeroInputAmount");

    // 5G: Output asset mismatch (directed to unrelated counter-token on Solana)
    let unrelated_solana_asset = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let mismatch_out_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(distinct_amount_in),
        token_out: Some(unrelated_solana_asset),
    };
    let err_out_mismatch =
        simulate_tax_aware_clmm_buy_exact_input(&pool, &mismatch_out_req, &normal_assessment)
            .expect_err("output mismatch must fail");
    assert_redacted(&err_out_mismatch, "OutputAssetMismatch");

    // 5H: Scan every single ClmmSimulationError variant
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
        ClmmSimulationError::StaleOrUnavailableState,
    ];
    for variant in clmm_variants {
        let err = TaxAwareClmmSimulationError::Clmm(variant);
        assert_redacted(&err, &format!("Clmm({:?})", variant));
    }

    // 5I: Scan every applicable TaxSafetyError variant
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
        let err = TaxAwareClmmSimulationError::Tax(variant);
        assert_redacted(&err, &label);
    }
}
