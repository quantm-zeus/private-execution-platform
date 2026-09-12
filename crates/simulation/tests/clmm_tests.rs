//! Focused regression tests for CLMM single-range deterministic simulation.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, ClmmPoolState, ClmmTick};
use simulation::clmm::{sqrt_price_from_tick_index, tick_index_from_sqrt_price};
use simulation::{
    ClmmExactInputRequest, ClmmSimulationError, ClmmSimulationQuote, MAX_CLMM_TICK_CROSSES,
};

fn sample_assets() -> (AssetId, AssetId) {
    let sol = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112".to_string(),
    )
    .unwrap();
    let usdc = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
    )
    .unwrap();
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
        fee_bps: Bps::new(30).unwrap(), // 0.30%
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    }
}

// ---------------------------------------------------------------------------
// 1. Deterministic known vectors in both directions within one active range
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_known_vectors_both_directions() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // Direction 0 -> 1 (token_0 in, token_1 out)
    // Price moves down, within [0, 64)
    let req_0_to_1 = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let quote_0_to_1 = simulation::simulate_clmm_exact_input(&pool, &req_0_to_1)
        .expect("0->1 simulation within active range should succeed");

    // Fee: 100_000 * 30 / 10_000 = 300
    // Effective input: 100_000 - 300 = 99_700
    assert_eq!(quote_0_to_1.input.asset, pool.token_0);
    assert_eq!(quote_0_to_1.input.amount.get(), 100_000);
    assert_eq!(quote_0_to_1.fee.asset, pool.token_0);
    assert_eq!(quote_0_to_1.fee.amount.get(), 300);
    assert_eq!(quote_0_to_1.effective_input.asset, pool.token_0);
    assert_eq!(quote_0_to_1.effective_input.amount.get(), 99_700);
    assert_eq!(
        quote_0_to_1.fee.amount.get() + quote_0_to_1.effective_input.amount.get(),
        quote_0_to_1.input.amount.get()
    );
    assert_eq!(quote_0_to_1.output.asset, pool.token_1);
    assert!(quote_0_to_1.output.amount.get() > 0);
    assert_eq!(quote_0_to_1.fee_bps, pool.fee_bps);

    // Price moved strictly down
    assert!(quote_0_to_1.resulting_sqrt_price_x64 < pool.sqrt_price_x64);
    let s_lower = sqrt_price_from_tick_index(0).unwrap();
    assert!(quote_0_to_1.resulting_sqrt_price_x64 > s_lower);
    assert!((0..64).contains(&quote_0_to_1.resulting_tick));
    assert_eq!(quote_0_to_1.resulting_liquidity, pool.liquidity);

    // Direction 1 -> 0 (token_1 in, token_0 out)
    // Price moves up, within [0, 64)
    let req_1_to_0 = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let quote_1_to_0 = simulation::simulate_clmm_exact_input(&pool, &req_1_to_0)
        .expect("1->0 simulation within active range should succeed");

    assert_eq!(quote_1_to_0.input.asset, pool.token_1);
    assert_eq!(quote_1_to_0.input.amount.get(), 100_000);
    assert_eq!(quote_1_to_0.fee.asset, pool.token_1);
    assert_eq!(quote_1_to_0.fee.amount.get(), 300);
    assert_eq!(quote_1_to_0.effective_input.asset, pool.token_1);
    assert_eq!(quote_1_to_0.effective_input.amount.get(), 99_700);
    assert_eq!(
        quote_1_to_0.fee.amount.get() + quote_1_to_0.effective_input.amount.get(),
        quote_1_to_0.input.amount.get()
    );
    assert_eq!(quote_1_to_0.output.asset, pool.token_0);
    assert!(quote_1_to_0.output.amount.get() > 0);
    assert_eq!(quote_1_to_0.fee_bps, pool.fee_bps);

    // Price moved strictly up
    assert!(quote_1_to_0.resulting_sqrt_price_x64 > pool.sqrt_price_x64);
    let s_upper = sqrt_price_from_tick_index(64).unwrap();
    assert!(quote_1_to_0.resulting_sqrt_price_x64 < s_upper);
    assert!((0..64).contains(&quote_1_to_0.resulting_tick));
    assert_eq!(quote_1_to_0.resulting_liquidity, pool.liquidity);

    // Caller inputs immutability
    assert_eq!(pool, initial_pool);
}

// ---------------------------------------------------------------------------
// 2. Exact fee, effective input, sub-unit rounding, and asset/chain binding
// ---------------------------------------------------------------------------

#[test]
fn test_fee_economics_and_directed_output_binding() {
    let mut pool = sample_clmm_pool();

    // 2A: Zero fee pool
    pool.fee_bps = Bps::new(0).unwrap();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000),
        token_out: Some(pool.token_1.clone()),
    };
    let quote = simulation::simulate_clmm_exact_input(&pool, &req).unwrap();
    assert_eq!(quote.fee.amount.get(), 0);
    assert_eq!(quote.effective_input.amount.get(), 50_000);

    // 2B: Sub-unit fee floor rounding (amount_in small enough that fee rounds to 0)
    pool.fee_bps = Bps::new(30).unwrap();
    let small_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(10),
        token_out: Some(pool.token_1.clone()),
    };
    let small_quote = simulation::simulate_clmm_exact_input(&pool, &small_req).unwrap();
    // 10 * 30 / 10_000 = 0
    assert_eq!(small_quote.fee.amount.get(), 0);
    assert_eq!(small_quote.effective_input.amount.get(), 10);

    // 2C: Directed output matching counter-asset succeeds
    let directed_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000),
        token_out: Some(pool.token_1.clone()),
    };
    assert!(simulation::simulate_clmm_exact_input(&pool, &directed_req).is_ok());

    // 2D: Directed output matching same input asset rejects with InvalidAssetDirection
    let same_asset_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000),
        token_out: Some(pool.token_0.clone()),
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &same_asset_req).unwrap_err(),
        ClmmSimulationError::InvalidAssetDirection
    );

    // 2E: Directed output mismatch (unrelated token) rejects with OutputAssetMismatch
    let unrelated = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let mismatch_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000),
        token_out: Some(unrelated),
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &mismatch_req).unwrap_err(),
        ClmmSimulationError::OutputAssetMismatch
    );

    // 2F: Chain mismatch on input asset
    let evm_asset = AssetId::new(
        ChainId::Ethereum,
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
    )
    .unwrap();
    let evm_req = ClmmExactInputRequest {
        token_in: evm_asset,
        amount_in: AtomicAmount::new(25_000),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &evm_req).unwrap_err(),
        ClmmSimulationError::ChainMismatch
    );

    // 2G: Chain mismatch on directed output asset
    let evm_out = AssetId::new(
        ChainId::Ethereum,
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
    )
    .unwrap();
    let evm_out_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000),
        token_out: Some(evm_out),
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &evm_out_req).unwrap_err(),
        ClmmSimulationError::ChainMismatch
    );

    // 2H: Input asset not in pool
    let other_sol = AssetId::new(
        ChainId::Solana,
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
    )
    .unwrap();
    let unknown_in_req = ClmmExactInputRequest {
        token_in: other_sol,
        amount_in: AtomicAmount::new(25_000),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &unknown_in_req).unwrap_err(),
        ClmmSimulationError::InvalidAssetDirection
    );
}

// ---------------------------------------------------------------------------
// 3. Active range boundary preflight & fail-closed crossing rejection
// ---------------------------------------------------------------------------

#[test]
fn test_tick_boundary_crossing_rejects_fail_closed() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // 3A: Direction 0 -> 1. Huge input that would cross tick 0 lower boundary
    let huge_req_0 = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000_000_000),
        token_out: None,
    };
    let err_0 = simulation::simulate_clmm_exact_input(&pool, &huge_req_0).unwrap_err();
    assert_eq!(err_0, ClmmSimulationError::TickCrossingExceeded);
    assert_eq!(pool, initial_pool);

    // 3B: Direction 1 -> 0. Huge input that would cross tick 64 upper boundary
    let huge_req_1 = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(100_000_000_000),
        token_out: None,
    };
    let err_1 = simulation::simulate_clmm_exact_input(&pool, &huge_req_1).unwrap_err();
    assert_eq!(err_1, ClmmSimulationError::TickCrossingExceeded);
    assert_eq!(pool, initial_pool);

    // 3C: Pool price at lowest represented tick 0 (no lower ticks): any 0->1 swap must reject
    let mut boundary_pool_lower = pool.clone();
    boundary_pool_lower.ticks = vec![
        ClmmTick::new(0, 20_000_000, 5_000_000),
        ClmmTick::new(64, 25_000_000, -7_000_000),
        ClmmTick::new(128, 15_000_000, -8_000_000),
    ];
    boundary_pool_lower.current_tick = 0;
    boundary_pool_lower.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap();
    let initial_lower = boundary_pool_lower.clone();
    let req_at_lower = ClmmExactInputRequest {
        token_in: boundary_pool_lower.token_0.clone(),
        amount_in: AtomicAmount::new(1_000),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&boundary_pool_lower, &req_at_lower).unwrap_err(),
        ClmmSimulationError::TickCrossingExceeded
    );
    assert_eq!(boundary_pool_lower, initial_lower);

    // 3D: Pool price near upper boundary tick 64 (no higher ticks): any 1->0 swap crossing upper tick must reject
    let mut boundary_pool_upper = pool.clone();
    boundary_pool_upper.ticks = vec![
        ClmmTick::new(-128, 10_000_000, 10_000_000),
        ClmmTick::new(0, 20_000_000, 5_000_000),
        ClmmTick::new(64, 25_000_000, -7_000_000),
    ];
    boundary_pool_upper.current_tick = 63;
    boundary_pool_upper.sqrt_price_x64 = sqrt_price_from_tick_index(64).unwrap() - 1;
    let initial_upper = boundary_pool_upper.clone();
    let req_at_upper = ClmmExactInputRequest {
        token_in: boundary_pool_upper.token_1.clone(),
        amount_in: AtomicAmount::new(1_000),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&boundary_pool_upper, &req_at_upper).unwrap_err(),
        ClmmSimulationError::TickCrossingExceeded
    );
    assert_eq!(boundary_pool_upper, initial_upper);
}

// ---------------------------------------------------------------------------
// 4. Malformed pool state, invalid fees/prices/ticks/range, and zero input
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_and_invalid_inputs_rejection() {
    let pool = sample_clmm_pool();

    // 4A: Zero input amount
    let zero_input_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(0),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &zero_input_req).unwrap_err(),
        ClmmSimulationError::ZeroInputAmount
    );

    let valid_req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(1_000),
        token_out: None,
    };

    // 4B: Zero liquidity
    let mut zero_liq_pool = pool.clone();
    zero_liq_pool.liquidity = 0;
    assert_eq!(
        simulation::simulate_clmm_exact_input(&zero_liq_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidLiquidity
    );

    // 4C: Zero sqrt price
    let mut zero_price_pool = pool.clone();
    zero_price_pool.sqrt_price_x64 = 0;
    assert_eq!(
        simulation::simulate_clmm_exact_input(&zero_price_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidPrice
    );

    // 4D: Sub-minimum sqrt price
    let mut min_price_pool = pool.clone();
    min_price_pool.sqrt_price_x64 = 100;
    assert_eq!(
        simulation::simulate_clmm_exact_input(&min_price_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidPrice
    );

    // 4E: Fee >= 100% (10,000 bps)
    let mut max_fee_pool = pool.clone();
    max_fee_pool.fee_bps = Bps::new(10_000).unwrap();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&max_fee_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidFee
    );

    // 4F: Empty or single-tick pool ticks
    let mut empty_ticks_pool = pool.clone();
    empty_ticks_pool.ticks = vec![];
    assert_eq!(
        simulation::simulate_clmm_exact_input(&empty_ticks_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );

    let mut single_tick_pool = pool.clone();
    single_tick_pool.ticks = vec![ClmmTick::new(0, 1000, 0)];
    assert_eq!(
        simulation::simulate_clmm_exact_input(&single_tick_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );

    // 4G: current_tick outside initialized range bounds
    let mut out_of_bounds_tick_pool = pool.clone();
    out_of_bounds_tick_pool.current_tick = 200; // max tick in pool is 128
    assert_eq!(
        simulation::simulate_clmm_exact_input(&out_of_bounds_tick_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );

    // 4H: Price outside range bounds [s_lower, s_upper]
    let mut out_of_range_price_pool = pool.clone();
    out_of_range_price_pool.sqrt_price_x64 = sqrt_price_from_tick_index(200).unwrap();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&out_of_range_price_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );

    // 4I: Current tick outside global MIN_TICK..=MAX_TICK
    let mut invalid_tick_pool = pool.clone();
    invalid_tick_pool.current_tick = 1_000_000;
    assert_eq!(
        simulation::simulate_clmm_exact_input(&invalid_tick_pool, &valid_req).unwrap_err(),
        ClmmSimulationError::InvalidTick
    );
}

// ---------------------------------------------------------------------------
// 5. Serialization determinism
// ---------------------------------------------------------------------------

#[test]
fn test_serialization_determinism() {
    let pool = sample_clmm_pool();
    let req = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000),
        token_out: Some(pool.token_1.clone()),
    };
    let quote = simulation::simulate_clmm_exact_input(&pool, &req).unwrap();

    // 5A: ClmmSimulationQuote round-trip
    let json_1 = serde_json::to_string(&quote).unwrap();
    let deserialized: ClmmSimulationQuote = serde_json::from_str(&json_1).unwrap();
    assert_eq!(quote, deserialized);
    let json_2 = serde_json::to_string(&deserialized).unwrap();
    assert_eq!(json_1, json_2);

    // 5B: ClmmExactInputRequest round-trip
    let req_json_1 = serde_json::to_string(&req).unwrap();
    let deserialized_req: ClmmExactInputRequest = serde_json::from_str(&req_json_1).unwrap();
    assert_eq!(req, deserialized_req);
    let req_json_2 = serde_json::to_string(&deserialized_req).unwrap();
    assert_eq!(req_json_1, req_json_2);

    // 5C: ClmmSimulationError round-trip
    let err = ClmmSimulationError::TickCrossingExceeded;
    let err_json = serde_json::to_string(&err).unwrap();
    let deserialized_err: ClmmSimulationError = serde_json::from_str(&err_json).unwrap();
    assert_eq!(err, deserialized_err);
}

// ---------------------------------------------------------------------------
// 6. Error redaction verification in Debug and Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_redaction_debug_and_display() {
    let all_errors = vec![
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

    let forbidden_patterns = [
        "So11111111111111111111111111111111111111112",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "secret",
        "credential",
        "password",
        "bearer",
        "payload",
        "endpoint",
        "http://",
        "https://",
    ];

    for err in all_errors {
        let display_str = format!("{}", err);
        let debug_str = format!("{:?}", err);

        for pattern in &forbidden_patterns {
            assert!(
                !display_str.contains(pattern),
                "Display string contains forbidden pattern '{pattern}': {display_str}"
            );
            assert!(
                !debug_str.contains(pattern),
                "Debug string contains forbidden pattern '{pattern}': {debug_str}"
            );
        }

        // Must not contain numeric values (amounts, ticks, reserves, liquidity, prices)
        for ch in display_str.chars() {
            assert!(
                !ch.is_ascii_digit(),
                "Display of error contains digits: {display_str}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 7. Tick to sqrt price and sqrt price to tick determinism and consistency
// ---------------------------------------------------------------------------

#[test]
fn test_tick_math_inversion_and_known_points() {
    // Tick 0 -> 2^64
    assert_eq!(
        sqrt_price_from_tick_index(0).unwrap(),
        18_446_744_073_709_551_616
    );
    assert_eq!(
        tick_index_from_sqrt_price(18_446_744_073_709_551_616).unwrap(),
        0
    );

    // Known test ticks from Orca Whirlpools reference
    let test_ticks = [
        -128, -64, -32, -16, -8, -4, -2, -1, 0, 1, 2, 4, 8, 16, 32, 64, 128,
    ];
    for &t in &test_ticks {
        let s = sqrt_price_from_tick_index(t).unwrap();
        let recovered_tick = tick_index_from_sqrt_price(s).unwrap();
        assert_eq!(
            recovered_tick, t,
            "Tick recovery failed for tick {t}: got {recovered_tick}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Fail closed on CLMM current-tick / sqrt-price desynchronization
// ---------------------------------------------------------------------------

#[test]
fn test_fail_closed_on_current_tick_sqrt_price_desynchronization() {
    let pool = sample_clmm_pool();

    // -----------------------------------------------------------------------
    // A. Confirmed defect regression:
    // Upper-boundary price with prior-current-tick (current_tick = upper_tick - 1
    // but sqrt_price_x64 = sqrt_price(upper_tick)).
    // Must fail closed for BOTH input directions and preserve pool and request unchanged.
    // -----------------------------------------------------------------------
    let mut upper_desync_pool = pool.clone();
    upper_desync_pool.current_tick = 63;
    upper_desync_pool.sqrt_price_x64 = sqrt_price_from_tick_index(64).unwrap();
    let initial_upper_pool = upper_desync_pool.clone();

    // A1: Token-0-in request (price moves down) - the confirmed defect path
    let req_0 = ClmmExactInputRequest {
        token_in: upper_desync_pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000),
        token_out: None,
    };
    let initial_req_0 = req_0.clone();
    let res_upper_0 = simulation::simulate_clmm_exact_input(&upper_desync_pool, &req_0);
    assert_eq!(
        res_upper_0.unwrap_err(),
        ClmmSimulationError::InvalidRange,
        "Upper boundary with prior current_tick must reject token-0-in fail-closed"
    );
    assert_eq!(upper_desync_pool, initial_upper_pool);
    assert_eq!(req_0, initial_req_0);

    // A2: Token-1-in request (price moves up)
    let req_1 = ClmmExactInputRequest {
        token_in: upper_desync_pool.token_1.clone(),
        amount_in: AtomicAmount::new(50_000),
        token_out: None,
    };
    let initial_req_1 = req_1.clone();
    let res_upper_1 = simulation::simulate_clmm_exact_input(&upper_desync_pool, &req_1);
    assert_eq!(
        res_upper_1.unwrap_err(),
        ClmmSimulationError::InvalidRange,
        "Upper boundary with prior current_tick must reject token-1-in fail-closed"
    );
    assert_eq!(upper_desync_pool, initial_upper_pool);
    assert_eq!(req_1, initial_req_1);

    // -----------------------------------------------------------------------
    // B. Symmetric lower-boundary / wrong-current-tick cases:
    // Must fail closed for BOTH input directions and preserve pool and request unchanged.
    // -----------------------------------------------------------------------

    // B1: Lower-boundary price sqrt_price(0) with prior-current-tick (-1)
    let mut lower_desync_prior = pool.clone();
    lower_desync_prior.current_tick = -1;
    lower_desync_prior.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap();
    let initial_lower_prior = lower_desync_prior.clone();

    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_desync_prior, &req_0).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_desync_prior, initial_lower_prior);
    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_desync_prior, &req_1).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_desync_prior, initial_lower_prior);

    // B2: Lower-boundary price sqrt_price(0) with next-current-tick (+1)
    let mut lower_desync_next = pool.clone();
    lower_desync_next.current_tick = 1;
    lower_desync_next.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap();
    let initial_lower_next = lower_desync_next.clone();

    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_desync_next, &req_0).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_desync_next, initial_lower_next);
    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_desync_next, &req_1).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_desync_next, initial_lower_next);

    // B3: Lower-boundary tick 0 with price strictly below lower boundary (sqrt_price(0) - 1)
    let mut lower_price_under = pool.clone();
    lower_price_under.current_tick = 0;
    lower_price_under.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap() - 1;
    let initial_lower_under = lower_price_under.clone();

    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_price_under, &req_0).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_price_under, initial_lower_under);
    assert_eq!(
        simulation::simulate_clmm_exact_input(&lower_price_under, &req_1).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(lower_price_under, initial_lower_under);

    // -----------------------------------------------------------------------
    // C. Coherent interior control:
    // Reported current_tick (32) agrees with recovered price tick (32).
    // Both directions must succeed and produce valid quotes.
    // -----------------------------------------------------------------------
    let coherent_pool = pool.clone();
    let initial_coherent = coherent_pool.clone();

    let quote_0 = simulation::simulate_clmm_exact_input(&coherent_pool, &req_0)
        .expect("Coherent interior swap 0->1 must succeed");
    assert!(quote_0.output.amount.get() > 0);
    assert!(quote_0.resulting_sqrt_price_x64 < coherent_pool.sqrt_price_x64);
    assert!((0..64).contains(&quote_0.resulting_tick));
    assert_eq!(coherent_pool, initial_coherent);
    assert_eq!(req_0, initial_req_0);

    let quote_1 = simulation::simulate_clmm_exact_input(&coherent_pool, &req_1)
        .expect("Coherent interior swap 1->0 must succeed");
    assert!(quote_1.output.amount.get() > 0);
    assert!(quote_1.resulting_sqrt_price_x64 > coherent_pool.sqrt_price_x64);
    assert!((0..64).contains(&quote_1.resulting_tick));
    assert_eq!(coherent_pool, initial_coherent);
    assert_eq!(req_1, initial_req_1);

    // -----------------------------------------------------------------------
    // D. Coherent exact boundary control:
    // Reported current_tick (0) agrees with recovered price tick (0) at lower boundary.
    // - Direction 1->0 (moving price up into range) succeeds unambiguously.
    // - Direction 0->1 (moving price down out of represented range) rejects with TickCrossingExceeded.
    // -----------------------------------------------------------------------
    let mut coherent_boundary_pool = pool.clone();
    coherent_boundary_pool.ticks = vec![
        ClmmTick::new(0, 20_000_000, 5_000_000),
        ClmmTick::new(64, 25_000_000, -7_000_000),
        ClmmTick::new(128, 15_000_000, -8_000_000),
    ];
    coherent_boundary_pool.current_tick = 0;
    coherent_boundary_pool.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap();
    let initial_coherent_boundary = coherent_boundary_pool.clone();

    let boundary_quote_1 = simulation::simulate_clmm_exact_input(&coherent_boundary_pool, &req_1)
        .expect("Coherent lower-boundary swap moving into range must succeed");
    assert!(boundary_quote_1.output.amount.get() > 0);
    assert!(boundary_quote_1.resulting_sqrt_price_x64 > coherent_boundary_pool.sqrt_price_x64);
    assert!((0..64).contains(&boundary_quote_1.resulting_tick));
    assert_eq!(coherent_boundary_pool, initial_coherent_boundary);

    let boundary_err_0 = simulation::simulate_clmm_exact_input(&coherent_boundary_pool, &req_0)
        .expect_err("Coherent lower-boundary swap moving out of range must fail closed");
    assert_eq!(boundary_err_0, ClmmSimulationError::TickCrossingExceeded);
    assert_eq!(coherent_boundary_pool, initial_coherent_boundary);
}

// ---------------------------------------------------------------------------
// 9. Bounded tick traversal across single and multiple initialized ticks
// ---------------------------------------------------------------------------

#[test]
fn test_single_and_multiple_tick_crossing_both_directions() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // 9A: Direction 0 -> 1 crossing 1 tick (tick 0).
    // In sample_clmm_pool, current_tick is 32. Ticks: [-128, 0, 64, 128].
    // Crossing tick 0 moving down: tick 0 has liquidity_net = 5_000_000.
    // L_initial = 10_000_000_000.
    // L_post_cross = 10_000_000_000 - 5_000_000 = 9_995_000_000.
    let req_cross_1_down = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_down = req_cross_1_down.clone();
    let quote_cross_1_down = simulation::simulate_clmm_exact_input(&pool, &req_cross_1_down)
        .expect("0->1 single-tick crossing should succeed");

    // Exact deterministic quote vector:
    assert_eq!(quote_cross_1_down.input.asset, pool.token_0);
    assert_eq!(quote_cross_1_down.input.amount.get(), 25_000_000);
    assert_eq!(quote_cross_1_down.fee.asset, pool.token_0);
    assert_eq!(quote_cross_1_down.fee.amount.get(), 75_000);
    assert_eq!(quote_cross_1_down.effective_input.asset, pool.token_0);
    assert_eq!(quote_cross_1_down.effective_input.amount.get(), 24_925_000);
    assert_eq!(
        quote_cross_1_down.fee.amount.get() + quote_cross_1_down.effective_input.amount.get(),
        quote_cross_1_down.input.amount.get()
    );
    assert_eq!(quote_cross_1_down.output.asset, pool.token_1);
    assert_eq!(quote_cross_1_down.output.amount.get(), 24_942_609);
    assert_eq!(quote_cross_1_down.fee_bps, pool.fee_bps);
    assert_eq!(
        quote_cross_1_down.resulting_sqrt_price_x64,
        18_430_261_775_357_090_295
    );
    assert_eq!(quote_cross_1_down.resulting_tick, -18);
    assert_eq!(quote_cross_1_down.resulting_liquidity, 9_995_000_000);

    // Consistency & bounds checks:
    let s_tick_0 = sqrt_price_from_tick_index(0).unwrap();
    let s_tick_neg_128 = sqrt_price_from_tick_index(-128).unwrap();
    assert!(quote_cross_1_down.resulting_sqrt_price_x64 < s_tick_0);
    assert!(quote_cross_1_down.resulting_sqrt_price_x64 >= s_tick_neg_128);
    assert!(quote_cross_1_down.resulting_tick < 0);
    assert!(quote_cross_1_down.resulting_tick >= -128);
    assert_eq!(
        quote_cross_1_down.resulting_tick,
        tick_index_from_sqrt_price(quote_cross_1_down.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req_cross_1_down, initial_req_down);

    // 9B: Direction 1 -> 0 crossing 1 tick (tick 64).
    // Crossing tick 64 moving up: tick 64 has liquidity_net = -7_000_000.
    // L_initial = 10_000_000_000.
    // L_post_cross = 10_000_000_000 + (-7_000_000) = 9_993_000_000.
    let req_cross_1_up = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_up = req_cross_1_up.clone();
    let quote_cross_1_up = simulation::simulate_clmm_exact_input(&pool, &req_cross_1_up)
        .expect("1->0 single-tick crossing should succeed");

    // Exact deterministic quote vector:
    assert_eq!(quote_cross_1_up.input.asset, pool.token_1);
    assert_eq!(quote_cross_1_up.input.amount.get(), 25_000_000);
    assert_eq!(quote_cross_1_up.fee.asset, pool.token_1);
    assert_eq!(quote_cross_1_up.fee.amount.get(), 75_000);
    assert_eq!(quote_cross_1_up.effective_input.asset, pool.token_1);
    assert_eq!(quote_cross_1_up.effective_input.amount.get(), 24_925_000);
    assert_eq!(
        quote_cross_1_up.fee.amount.get() + quote_cross_1_up.effective_input.amount.get(),
        quote_cross_1_up.input.amount.get()
    );
    assert_eq!(quote_cross_1_up.output.asset, pool.token_0);
    assert_eq!(quote_cross_1_up.output.amount.get(), 24_783_689);
    assert_eq!(quote_cross_1_up.fee_bps, pool.fee_bps);
    assert_eq!(
        quote_cross_1_up.resulting_sqrt_price_x64,
        18_522_271_002_508_215_311
    );
    assert_eq!(quote_cross_1_up.resulting_tick, 81);
    assert_eq!(quote_cross_1_up.resulting_liquidity, 9_993_000_000);

    // Consistency & bounds checks:
    let s_tick_64 = sqrt_price_from_tick_index(64).unwrap();
    let s_tick_128 = sqrt_price_from_tick_index(128).unwrap();
    assert!(quote_cross_1_up.resulting_sqrt_price_x64 > s_tick_64);
    assert!(quote_cross_1_up.resulting_sqrt_price_x64 < s_tick_128);
    assert!(quote_cross_1_up.resulting_tick >= 64);
    assert!(quote_cross_1_up.resulting_tick < 128);
    assert_eq!(
        quote_cross_1_up.resulting_tick,
        tick_index_from_sqrt_price(quote_cross_1_up.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req_cross_1_up, initial_req_up);

    // 9C: Multiple tick crossing in both directions.
    let (sol, usdc) = sample_assets();
    let multi_pool = ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(20).unwrap(), // 0.20%
        ticks: vec![
            ClmmTick::new(-192, 10_000_000, 10_000_000),
            ClmmTick::new(-128, 15_000_000, 5_000_000),
            ClmmTick::new(-64, 20_000_000, -2_000_000),
            ClmmTick::new(0, 30_000_000, 3_000_000),
            ClmmTick::new(64, 25_000_000, -4_000_000),
            ClmmTick::new(128, 20_000_000, -6_000_000),
            ClmmTick::new(192, 10_000_000, -8_000_000),
        ],
    };
    let initial_multi = multi_pool.clone();

    // Multi-cross UP (1 -> 0): Starts at 0.
    // Crosses tick 64 (L += -4_000_000 -> 9_996_000_000),
    // then crosses tick 128 (L += -6_000_000 -> 9_990_000_000),
    // lands in [128, 192).
    let multi_up_req = ClmmExactInputRequest {
        token_in: multi_pool.token_1.clone(),
        amount_in: AtomicAmount::new(80_000_000),
        token_out: None,
    };
    let initial_multi_up = multi_up_req.clone();
    let multi_up_quote = simulation::simulate_clmm_exact_input(&multi_pool, &multi_up_req)
        .expect("multi-tick crossing up should succeed");

    // Exact deterministic quote vector:
    assert_eq!(multi_up_quote.input.asset, multi_pool.token_1);
    assert_eq!(multi_up_quote.input.amount.get(), 80_000_000);
    assert_eq!(multi_up_quote.fee.asset, multi_pool.token_1);
    assert_eq!(multi_up_quote.fee.amount.get(), 160_000);
    assert_eq!(multi_up_quote.effective_input.asset, multi_pool.token_1);
    assert_eq!(multi_up_quote.effective_input.amount.get(), 79_840_000);
    assert_eq!(
        multi_up_quote.fee.amount.get() + multi_up_quote.effective_input.amount.get(),
        multi_up_quote.input.amount.get()
    );
    assert_eq!(multi_up_quote.output.asset, multi_pool.token_0);
    assert_eq!(multi_up_quote.output.amount.get(), 79_207_499);
    assert_eq!(multi_up_quote.fee_bps, multi_pool.fee_bps);
    assert_eq!(
        multi_up_quote.resulting_sqrt_price_x64,
        18_594_075_501_025_459_409
    );
    assert_eq!(multi_up_quote.resulting_tick, 159);
    assert_eq!(multi_up_quote.resulting_liquidity, 9_990_000_000);

    // Consistency & bounds checks:
    let s_128 = sqrt_price_from_tick_index(128).unwrap();
    let s_192 = sqrt_price_from_tick_index(192).unwrap();
    assert!(multi_up_quote.resulting_sqrt_price_x64 > s_128);
    assert!(multi_up_quote.resulting_sqrt_price_x64 < s_192);
    assert!(multi_up_quote.resulting_tick >= 128);
    assert!(multi_up_quote.resulting_tick < 192);
    assert_eq!(
        multi_up_quote.resulting_tick,
        tick_index_from_sqrt_price(multi_up_quote.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(multi_pool, initial_multi);
    assert_eq!(multi_up_req, initial_multi_up);

    // Multi-cross DOWN (0 -> 1): Starts at 0.
    // Crosses tick 0 downwards: L -= net(0) (3_000_000) -> 9_997_000_000.
    // Then crosses tick -64 downwards: L -= net(-64) (-2_000_000) -> 9_999_000_000.
    // Lands in [-128, -64).
    let multi_down_req = ClmmExactInputRequest {
        token_in: multi_pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000_000),
        token_out: None,
    };
    let initial_multi_down = multi_down_req.clone();
    let multi_down_quote = simulation::simulate_clmm_exact_input(&multi_pool, &multi_down_req)
        .expect("multi-tick crossing down should succeed");

    // Exact deterministic quote vector:
    assert_eq!(multi_down_quote.input.asset, multi_pool.token_0);
    assert_eq!(multi_down_quote.input.amount.get(), 50_000_000);
    assert_eq!(multi_down_quote.fee.asset, multi_pool.token_0);
    assert_eq!(multi_down_quote.fee.amount.get(), 100_000);
    assert_eq!(multi_down_quote.effective_input.asset, multi_pool.token_0);
    assert_eq!(multi_down_quote.effective_input.amount.get(), 49_900_000);
    assert_eq!(
        multi_down_quote.fee.amount.get() + multi_down_quote.effective_input.amount.get(),
        multi_down_quote.input.amount.get()
    );
    assert_eq!(multi_down_quote.output.asset, multi_pool.token_1);
    assert_eq!(multi_down_quote.output.amount.get(), 49_652_166);
    assert_eq!(multi_down_quote.fee_bps, multi_pool.fee_bps);
    assert_eq!(
        multi_down_quote.resulting_sqrt_price_x64,
        18_355_131_043_464_493_861
    );
    assert_eq!(multi_down_quote.resulting_tick, -100);
    assert_eq!(multi_down_quote.resulting_liquidity, 9_999_000_000);

    // Consistency & bounds checks:
    let s_neg_64 = sqrt_price_from_tick_index(-64).unwrap();
    let s_neg_128 = sqrt_price_from_tick_index(-128).unwrap();
    assert!(multi_down_quote.resulting_sqrt_price_x64 < s_neg_64);
    assert!(multi_down_quote.resulting_sqrt_price_x64 >= s_neg_128);
    assert!(multi_down_quote.resulting_tick < -64);
    assert!(multi_down_quote.resulting_tick >= -128);
    assert_eq!(
        multi_down_quote.resulting_tick,
        tick_index_from_sqrt_price(multi_down_quote.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(multi_pool, initial_multi);
    assert_eq!(multi_down_req, initial_multi_down);
}

// ---------------------------------------------------------------------------
// 10. Canonical exact-boundary transitions and follow-on quote coherence
// ---------------------------------------------------------------------------

#[test]
fn test_canonical_exact_boundary_transitions_and_follow_on_quotes() {
    let pool = sample_clmm_pool();

    // 10A: Land EXACTLY on tick 64 moving UP.
    let mut zero_fee_pool = pool.clone();
    zero_fee_pool.fee_bps = Bps::new(0).unwrap();
    let initial_zero_fee = zero_fee_pool.clone();

    let s_curr = zero_fee_pool.sqrt_price_x64;
    let s_64 = sqrt_price_from_tick_index(64).unwrap();
    let delta_s = s_64 - s_curr;
    let (hi, lo) = simulation::cpmm::mul_u128_wide(zero_fee_pool.liquidity, delta_s);
    let rem = lo & 0xFFFF_FFFF_FFFF_FFFF;
    let quot = (lo >> 64) | (hi << 64);
    let exact_input_to_64 = quot + if rem != 0 { 1 } else { 0 };
    assert_eq!(exact_input_to_64, 16_037_645);

    let req_exact_up = ClmmExactInputRequest {
        token_in: zero_fee_pool.token_1.clone(),
        amount_in: AtomicAmount::new(exact_input_to_64),
        token_out: None,
    };
    let initial_req_exact_up = req_exact_up.clone();
    let quote_exact_up = simulation::simulate_clmm_exact_input(&zero_fee_pool, &req_exact_up)
        .expect("exact boundary arrival moving up should succeed");

    assert_eq!(quote_exact_up.input.asset, zero_fee_pool.token_1);
    assert_eq!(quote_exact_up.input.amount.get(), 16_037_645);
    assert_eq!(quote_exact_up.fee.amount.get(), 0);
    assert_eq!(quote_exact_up.effective_input.amount.get(), 16_037_645);
    assert_eq!(quote_exact_up.output.asset, zero_fee_pool.token_0);
    assert_eq!(quote_exact_up.output.amount.get(), 15_960_851);
    assert_eq!(quote_exact_up.resulting_sqrt_price_x64, s_64);
    assert_eq!(
        quote_exact_up.resulting_sqrt_price_x64,
        18_505_865_242_158_250_041
    );
    assert_eq!(quote_exact_up.resulting_tick, 64);
    // At tick 64, crossed into [64, 128) -> L = 10_000_000_000 + (-7_000_000) = 9_993_000_000
    assert_eq!(quote_exact_up.resulting_liquidity, 9_993_000_000);
    assert_eq!(zero_fee_pool, initial_zero_fee);
    assert_eq!(req_exact_up, initial_req_exact_up);

    // Follow-on pool from exact boundary state:
    let follow_on_pool_up = ClmmPoolState {
        current_tick: quote_exact_up.resulting_tick,
        sqrt_price_x64: quote_exact_up.resulting_sqrt_price_x64,
        liquidity: quote_exact_up.resulting_liquidity,
        ..zero_fee_pool.clone()
    };
    let initial_follow_on_up = follow_on_pool_up.clone();

    // Follow-on UP from tick 64: moves into [64, 128)
    let follow_req_up = ClmmExactInputRequest {
        token_in: follow_on_pool_up.token_1.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_follow_req_up = follow_req_up.clone();
    let follow_quote_up = simulation::simulate_clmm_exact_input(&follow_on_pool_up, &follow_req_up)
        .expect("follow-on quote moving up from exact boundary should succeed");
    assert_eq!(follow_quote_up.input.amount.get(), 100_000);
    assert_eq!(follow_quote_up.fee.amount.get(), 0);
    assert_eq!(follow_quote_up.effective_input.amount.get(), 100_000);
    assert_eq!(follow_quote_up.output.amount.get(), 99_361);
    assert_eq!(
        follow_quote_up.resulting_sqrt_price_x64,
        18_506_049_838_816_648_015
    );
    assert!(follow_quote_up.resulting_sqrt_price_x64 > s_64);
    assert_eq!(
        follow_quote_up.resulting_tick,
        tick_index_from_sqrt_price(follow_quote_up.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(follow_quote_up.resulting_tick, 64);
    assert_eq!(follow_quote_up.resulting_liquidity, 9_993_000_000);
    assert_eq!(follow_on_pool_up, initial_follow_on_up);
    assert_eq!(follow_req_up, initial_follow_req_up);

    // Follow-on DOWN from tick 64: moves into [0, 64) crossing tick 64 downwards
    let follow_req_down = ClmmExactInputRequest {
        token_in: follow_on_pool_up.token_0.clone(),
        amount_in: AtomicAmount::new(100_000),
        token_out: None,
    };
    let initial_follow_req_down = follow_req_down.clone();
    let follow_quote_down =
        simulation::simulate_clmm_exact_input(&follow_on_pool_up, &follow_req_down)
            .expect("follow-on quote moving down from exact boundary should succeed");
    assert_eq!(follow_quote_down.input.amount.get(), 100_000);
    assert_eq!(follow_quote_down.fee.amount.get(), 0);
    assert_eq!(follow_quote_down.effective_input.amount.get(), 100_000);
    assert_eq!(follow_quote_down.output.amount.get(), 100_641);
    assert_eq!(
        follow_quote_down.resulting_sqrt_price_x64,
        18_505_679_592_261_780_216
    );
    assert!(follow_quote_down.resulting_sqrt_price_x64 < s_64);
    assert_eq!(
        follow_quote_down.resulting_tick,
        tick_index_from_sqrt_price(follow_quote_down.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(follow_quote_down.resulting_tick, 63);
    // When crossed back down across tick 64, liquidity restored to 10_000_000_000:
    assert_eq!(follow_quote_down.resulting_liquidity, 10_000_000_000);
    assert_eq!(follow_on_pool_up, initial_follow_on_up);
    assert_eq!(follow_req_down, initial_follow_req_down);

    // 10B: Land EXACTLY on tick 0 moving DOWN, and follow-on in both directions:
    let req_exact_down = ClmmExactInputRequest {
        token_in: zero_fee_pool.token_0.clone(),
        amount_in: AtomicAmount::new(15_986_409),
        token_out: None,
    };
    let initial_req_exact_down = req_exact_down.clone();
    let quote_exact_down = simulation::simulate_clmm_exact_input(&zero_fee_pool, &req_exact_down)
        .expect("exact boundary arrival moving down should succeed");

    let s_0 = sqrt_price_from_tick_index(0).unwrap();
    assert_eq!(quote_exact_down.input.asset, zero_fee_pool.token_0);
    assert_eq!(quote_exact_down.input.amount.get(), 15_986_409);
    assert_eq!(quote_exact_down.fee.amount.get(), 0);
    assert_eq!(quote_exact_down.effective_input.amount.get(), 15_986_409);
    assert_eq!(quote_exact_down.output.asset, zero_fee_pool.token_1);
    assert_eq!(quote_exact_down.output.amount.get(), 16_012_005);
    assert_eq!(quote_exact_down.resulting_sqrt_price_x64, s_0);
    assert_eq!(
        quote_exact_down.resulting_sqrt_price_x64,
        18_446_744_073_709_551_616
    );
    assert_eq!(quote_exact_down.resulting_tick, 0);
    assert_eq!(quote_exact_down.resulting_liquidity, 10_000_000_000);
    assert_eq!(zero_fee_pool, initial_zero_fee);
    assert_eq!(req_exact_down, initial_req_exact_down);

    let boundary_pool_0 = ClmmPoolState {
        current_tick: quote_exact_down.resulting_tick,
        sqrt_price_x64: quote_exact_down.resulting_sqrt_price_x64,
        liquidity: quote_exact_down.resulting_liquidity,
        ..zero_fee_pool.clone()
    };
    let initial_boundary_0 = boundary_pool_0.clone();

    // Follow-on UP from tick 0: moves into [0, 64) with L = 10_000_000_000
    let follow_0_up = simulation::simulate_clmm_exact_input(&boundary_pool_0, &follow_req_up)
        .expect("follow-on quote moving up from tick 0 should succeed");
    assert_eq!(follow_0_up.input.amount.get(), 100_000);
    assert_eq!(follow_0_up.fee.amount.get(), 0);
    assert_eq!(follow_0_up.effective_input.amount.get(), 100_000);
    assert_eq!(follow_0_up.output.amount.get(), 99_999);
    assert_eq!(
        follow_0_up.resulting_sqrt_price_x64,
        18_446_928_541_150_288_711
    );
    assert!(follow_0_up.resulting_sqrt_price_x64 > s_0);
    assert_eq!(
        follow_0_up.resulting_tick,
        tick_index_from_sqrt_price(follow_0_up.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(follow_0_up.resulting_tick, 0);
    assert_eq!(follow_0_up.resulting_liquidity, 10_000_000_000);
    assert_eq!(boundary_pool_0, initial_boundary_0);

    // Follow-on DOWN from tick 0: crosses tick 0 downwards into [-128, 0)
    let follow_0_down = simulation::simulate_clmm_exact_input(&boundary_pool_0, &follow_req_down)
        .expect("follow-on quote moving down from tick 0 should succeed");
    assert_eq!(follow_0_down.input.amount.get(), 100_000);
    assert_eq!(follow_0_down.fee.amount.get(), 0);
    assert_eq!(follow_0_down.effective_input.amount.get(), 100_000);
    assert_eq!(follow_0_down.output.amount.get(), 99_998);
    assert_eq!(
        follow_0_down.resulting_sqrt_price_x64,
        18_446_559_515_835_456_214
    );
    assert!(follow_0_down.resulting_sqrt_price_x64 < s_0);
    assert_eq!(
        follow_0_down.resulting_tick,
        tick_index_from_sqrt_price(follow_0_down.resulting_sqrt_price_x64).unwrap()
    );
    assert_eq!(follow_0_down.resulting_tick, -1);
    assert_eq!(follow_0_down.resulting_liquidity, 9_995_000_000);
    assert_eq!(boundary_pool_0, initial_boundary_0);
}

// ---------------------------------------------------------------------------
// 11. Tick crossing cap breach and missing next tick fail closed
// ---------------------------------------------------------------------------

#[test]
fn test_tick_crossing_cap_breach_and_missing_next_tick_fail_closed() {
    let (sol, usdc) = sample_assets();

    // 11A: MAX_CLMM_TICK_CROSSES cap enforcement
    assert_eq!(MAX_CLMM_TICK_CROSSES, 32);
    let num_ticks = MAX_CLMM_TICK_CROSSES + 4;
    let ticks: Vec<ClmmTick> = (0..=num_ticks as i32)
        .map(|i| ClmmTick::new(i * 64, 10_000_000, 0))
        .collect();

    let cap_pool = ClmmPoolState {
        token_0: sol.clone(),
        token_1: usdc.clone(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(0).unwrap(),
        ticks,
    };
    let initial_cap_pool = cap_pool.clone();

    // Enormous input that traverses beyond 32 tick crossings:
    let huge_cap_req = ClmmExactInputRequest {
        token_in: cap_pool.token_1.clone(),
        amount_in: AtomicAmount::new(10_000_000_000_000),
        token_out: None,
    };
    let initial_cap_req = huge_cap_req.clone();

    let cap_err = simulation::simulate_clmm_exact_input(&cap_pool, &huge_cap_req).unwrap_err();
    assert_eq!(cap_err, ClmmSimulationError::TickCrossingExceeded);
    assert_eq!(cap_pool, initial_cap_pool);
    assert_eq!(huge_cap_req, initial_cap_req);

    // 11B: Missing next tick at upper boundary of represented ticks:
    let upper_bound_pool = ClmmPoolState {
        token_0: sol.clone(),
        token_1: usdc.clone(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 64,
        sqrt_price_x64: sqrt_price_from_tick_index(64).unwrap(),
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(0).unwrap(),
        ticks: vec![
            ClmmTick::new(0, 10_000_000, 0),
            ClmmTick::new(64, 10_000_000, 0),
            ClmmTick::new(128, 10_000_000, 0),
        ],
    };
    let req_cross_upper = ClmmExactInputRequest {
        token_in: upper_bound_pool.token_1.clone(),
        amount_in: AtomicAmount::new(1_000_000_000),
        token_out: None,
    };
    let err_upper =
        simulation::simulate_clmm_exact_input(&upper_bound_pool, &req_cross_upper).unwrap_err();
    assert_eq!(err_upper, ClmmSimulationError::TickCrossingExceeded);

    // 11C: Missing next tick at lower boundary of represented ticks:
    let lower_bound_pool = ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        liquidity: 10_000_000_000,
        fee_bps: Bps::new(0).unwrap(),
        ticks: vec![
            ClmmTick::new(0, 10_000_000, 0),
            ClmmTick::new(64, 10_000_000, 0),
        ],
    };
    let req_cross_lower = ClmmExactInputRequest {
        token_in: lower_bound_pool.token_0.clone(),
        amount_in: AtomicAmount::new(1_000_000),
        token_out: None,
    };
    let err_lower =
        simulation::simulate_clmm_exact_input(&lower_bound_pool, &req_cross_lower).unwrap_err();
    assert_eq!(err_lower, ClmmSimulationError::TickCrossingExceeded);
}

// ---------------------------------------------------------------------------
// 12. Post-cross liquidity zero, overflow, and underflow fail closed
// ---------------------------------------------------------------------------

#[test]
fn test_post_cross_liquidity_zero_and_overflow_fail_closed() {
    let (sol, usdc) = sample_assets();

    // 12A: Net liquidity results in zero active liquidity post-cross moving UP
    let zero_post_liq_pool = ClmmPoolState {
        token_0: sol.clone(),
        token_1: usdc.clone(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        liquidity: 5_000_000,
        fee_bps: Bps::new(0).unwrap(),
        ticks: vec![
            ClmmTick::new(-64, 5_000_000, 5_000_000),
            ClmmTick::new(0, 5_000_000, 0),
            // At tick 64, net is -5_000_000, so L + (-5_000_000) = 0!
            ClmmTick::new(64, 5_000_000, -5_000_000),
            ClmmTick::new(128, 5_000_000, 0),
        ],
    };
    let initial_zero_liq = zero_post_liq_pool.clone();
    let req_cross = ClmmExactInputRequest {
        token_in: zero_post_liq_pool.token_1.clone(),
        amount_in: AtomicAmount::new(50_000_000),
        token_out: None,
    };
    let initial_req = req_cross.clone();
    let err = simulation::simulate_clmm_exact_input(&zero_post_liq_pool, &req_cross).unwrap_err();
    assert_eq!(err, ClmmSimulationError::InvalidLiquidity);
    assert_eq!(zero_post_liq_pool, initial_zero_liq);
    assert_eq!(req_cross, initial_req);

    // 12B: Downward cross results in zero active liquidity:
    // At tick 0, net is 5_000_000. Crossing downwards: L - net = 5_000_000 - 5_000_000 = 0!
    let zero_down_pool = ClmmPoolState {
        token_0: sol.clone(),
        token_1: usdc.clone(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        liquidity: 5_000_000,
        fee_bps: Bps::new(0).unwrap(),
        ticks: vec![
            ClmmTick::new(-64, 5_000_000, 0),
            ClmmTick::new(0, 5_000_000, 5_000_000),
            ClmmTick::new(64, 5_000_000, 0),
        ],
    };
    let initial_down = zero_down_pool.clone();
    let req_down = ClmmExactInputRequest {
        token_in: zero_down_pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000_000),
        token_out: None,
    };
    let err_down = simulation::simulate_clmm_exact_input(&zero_down_pool, &req_down).unwrap_err();
    assert_eq!(err_down, ClmmSimulationError::InvalidLiquidity);
    assert_eq!(zero_down_pool, initial_down);
}

// ---------------------------------------------------------------------------
// 13. Malformed ticks and spacing fail closed
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_ticks_and_spacing_fail_closed() {
    let pool = sample_clmm_pool();

    // 13A: Unsorted ticks
    let mut unsorted_pool = pool.clone();
    unsorted_pool.ticks = vec![ClmmTick::new(0, 10_000, 0), ClmmTick::new(-64, 10_000, 0)];
    let req = ClmmExactInputRequest {
        token_in: unsorted_pool.token_0.clone(),
        amount_in: AtomicAmount::new(1000),
        token_out: None,
    };
    let initial_req = req.clone();
    let initial_unsorted = unsorted_pool.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&unsorted_pool, &req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(unsorted_pool, initial_unsorted);
    assert_eq!(req, initial_req);

    // 13B: Duplicate ticks
    let mut dup_pool = pool.clone();
    dup_pool.ticks = vec![ClmmTick::new(0, 10_000, 0), ClmmTick::new(0, 10_000, 0)];
    let initial_dup = dup_pool.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&dup_pool, &req).unwrap_err(),
        ClmmSimulationError::InvalidRange
    );
    assert_eq!(dup_pool, initial_dup);

    // 13C: Tick spacing mismatch
    let mut spacing_pool = pool.clone();
    spacing_pool.tick_spacing = 64;
    spacing_pool.ticks = vec![
        ClmmTick::new(0, 10_000, 0),
        ClmmTick::new(33, 10_000, 0), // 33 % 64 != 0
    ];
    let initial_spacing = spacing_pool.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&spacing_pool, &req).unwrap_err(),
        ClmmSimulationError::InvalidTick
    );
    assert_eq!(spacing_pool, initial_spacing);
}

// ---------------------------------------------------------------------------
// 14. Immutability across success and all failures
// ---------------------------------------------------------------------------

#[test]
fn test_caller_input_immutability_across_success_and_failures() {
    let pool = sample_clmm_pool();
    let initial_pool = pool.clone();

    // 14A: Immutability on single-range success
    let req_single = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(50_000),
        token_out: None,
    };
    let initial_req_single = req_single.clone();
    assert!(simulation::simulate_clmm_exact_input(&pool, &req_single).is_ok());
    assert_eq!(pool, initial_pool);
    assert_eq!(req_single, initial_req_single);

    // 14B: Immutability on multi-range traversal success
    let req_multi = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(25_000_000),
        token_out: None,
    };
    let initial_req_multi = req_multi.clone();
    assert!(simulation::simulate_clmm_exact_input(&pool, &req_multi).is_ok());
    assert_eq!(pool, initial_pool);
    assert_eq!(req_multi, initial_req_multi);

    // 14C: Immutability on tick crossing cap breach failure
    let ticks: Vec<ClmmTick> = (0..=36)
        .map(|i| ClmmTick::new(i * 64, 10_000_000, 0))
        .collect();
    let cap_pool = ClmmPoolState {
        ticks,
        current_tick: 0,
        sqrt_price_x64: sqrt_price_from_tick_index(0).unwrap(),
        ..pool.clone()
    };
    let initial_cap_pool = cap_pool.clone();
    let req_cap = ClmmExactInputRequest {
        token_in: pool.token_1.clone(),
        amount_in: AtomicAmount::new(10_000_000_000_000),
        token_out: None,
    };
    let initial_req_cap = req_cap.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&cap_pool, &req_cap).unwrap_err(),
        ClmmSimulationError::TickCrossingExceeded
    );
    assert_eq!(cap_pool, initial_cap_pool);
    assert_eq!(req_cap, initial_req_cap);

    // 14D: Immutability on missing tick failure
    let req_missing = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(100_000_000_000),
        token_out: None,
    };
    let initial_req_missing = req_missing.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &req_missing).unwrap_err(),
        ClmmSimulationError::TickCrossingExceeded
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req_missing, initial_req_missing);

    // 14E: Immutability on zero input failure
    let req_zero = ClmmExactInputRequest {
        token_in: pool.token_0.clone(),
        amount_in: AtomicAmount::new(0),
        token_out: None,
    };
    let initial_req_zero = req_zero.clone();
    assert_eq!(
        simulation::simulate_clmm_exact_input(&pool, &req_zero).unwrap_err(),
        ClmmSimulationError::ZeroInputAmount
    );
    assert_eq!(pool, initial_pool);
    assert_eq!(req_zero, initial_req_zero);
}
