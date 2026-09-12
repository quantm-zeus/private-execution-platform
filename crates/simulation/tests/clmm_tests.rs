//! Focused regression tests for CLMM single-range deterministic simulation.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, ClmmPoolState, ClmmTick};
use simulation::clmm::{sqrt_price_from_tick_index, tick_index_from_sqrt_price};
use simulation::{ClmmExactInputRequest, ClmmSimulationError, ClmmSimulationQuote};

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

    // 3C: Pool price already at lower boundary tick 0: any 0->1 swap must reject
    let mut boundary_pool_lower = pool.clone();
    boundary_pool_lower.current_tick = 0;
    boundary_pool_lower.sqrt_price_x64 = sqrt_price_from_tick_index(0).unwrap();
    let req_at_lower = ClmmExactInputRequest {
        token_in: boundary_pool_lower.token_0.clone(),
        amount_in: AtomicAmount::new(1_000),
        token_out: None,
    };
    assert_eq!(
        simulation::simulate_clmm_exact_input(&boundary_pool_lower, &req_at_lower).unwrap_err(),
        ClmmSimulationError::TickCrossingExceeded
    );

    // 3D: Pool price near upper boundary tick 64: any 1->0 swap crossing upper tick must reject
    let mut boundary_pool_upper = pool.clone();
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
    // - Direction 0->1 (moving price down out of range) rejects with TickCrossingExceeded.
    // -----------------------------------------------------------------------
    let mut coherent_boundary_pool = pool.clone();
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
