//! Focused regression tests for Bin/DLMM (Liquidity Book) deterministic simulation.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, BinPoolState, Bps, LiquidityBin};
use simulation::{
    simulate_bin_exact_input, BinExactInputRequest, BinSimulationError, BinSimulationQuote,
    MAX_BIN_CROSSES,
};

fn sol_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Solana, address.to_string()).unwrap()
}

fn sample_assets() -> (AssetId, AssetId) {
    let token_0 = sol_asset("So11111111111111111111111111111111111111112");
    let token_1 = sol_asset("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    (token_0, token_1)
}

fn unrelated_asset() -> AssetId {
    sol_asset("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB")
}

fn evm_asset() -> AssetId {
    AssetId::new(
        ChainId::Ethereum,
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
    )
    .unwrap()
}

fn bin(id: i32, reserve_0: u128, reserve_1: u128) -> LiquidityBin {
    LiquidityBin::new(
        id,
        AtomicAmount::new(reserve_0),
        AtomicAmount::new(reserve_1),
    )
}

fn make_pool(
    bin_step: u16,
    decimals_0: u8,
    decimals_1: u8,
    active_bin_id: i32,
    fee_bps: u16,
    bins: Vec<LiquidityBin>,
) -> BinPoolState {
    let (token_0, token_1) = sample_assets();
    BinPoolState {
        token_0,
        token_1,
        decimals_0,
        decimals_1,
        active_bin_id,
        bin_step,
        fee_bps: Bps::new(fee_bps).unwrap(),
        bins,
    }
}

/// Vector A/B pool: `{0: (0, 3000), 1: (1000, 2000)}`, active 1, step 100 bps.
fn pool_a() -> BinPoolState {
    make_pool(100, 0, 0, 1, 0, vec![bin(0, 0, 3000), bin(1, 1000, 2000)])
}

/// Vector B pool adds `{2: (4000, 0)}` above the active bin.
fn pool_b() -> BinPoolState {
    make_pool(
        100,
        0,
        0,
        1,
        0,
        vec![bin(0, 0, 3000), bin(1, 1000, 2000), bin(2, 4000, 0)],
    )
}

/// Vector C pool: `{-1: (0, 5000), 0: (500, 1000)}`, active 0, step 100 bps.
fn pool_c() -> BinPoolState {
    make_pool(100, 0, 0, 0, 0, vec![bin(-1, 0, 5000), bin(0, 500, 1000)])
}

/// Vector D pool: single active bin with 6/18 decimals and a 1.01 atomic price.
fn pool_d() -> BinPoolState {
    make_pool(
        100,
        6,
        18,
        1,
        0,
        vec![bin(1, 1_000_000, 1_000_000_000_000_000_000)],
    )
}

fn assert_quote_common(
    pool: &BinPoolState,
    request: &BinExactInputRequest,
    quote: &BinSimulationQuote,
) {
    assert_eq!(quote.input.asset, request.token_in);
    assert_eq!(quote.input.amount, request.amount_in);
    assert_eq!(quote.fee.asset, request.token_in);
    assert_eq!(quote.effective_input.asset, request.token_in);
    assert_eq!(quote.fee_bps, pool.fee_bps);
    assert_eq!(
        quote.fee.amount.get() + quote.effective_input.amount.get(),
        request.amount_in.get(),
        "fee + effective_input must equal amount_in"
    );
    let expected_out = if request.token_in == pool.token_0 {
        &pool.token_1
    } else {
        &pool.token_0
    };
    assert_eq!(quote.output.asset, *expected_out);
    assert!(quote.output.amount.get() > 0);
}

// ---------------------------------------------------------------------------
// 1. Pinned vectors A through D
// ---------------------------------------------------------------------------

#[test]
fn test_pinned_vector_a() {
    let pool = pool_a();
    let initial_pool = pool.clone();
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1010));

    let quote = simulate_bin_exact_input(&pool, &request).expect("vector A must succeed");

    assert_quote_common(&pool, &request, &quote);
    assert_eq!(quote.output.asset, pool.token_1);
    assert_eq!(quote.output.amount.get(), 1020);
    assert_eq!(quote.fee.amount.get(), 0);
    assert_eq!(quote.effective_input.amount.get(), 1010);
    assert_eq!(quote.bins_crossed, 0);
    assert_eq!(quote.resulting_active_bin_id, 1);
    assert_eq!(pool, initial_pool);
}

#[test]
fn test_pinned_vector_b() {
    let pool = pool_b();
    let initial_pool = pool.clone();
    let request = BinExactInputRequest::new(pool.token_1.clone(), AtomicAmount::new(2000));

    let quote = simulate_bin_exact_input(&pool, &request).expect("vector B must succeed");

    assert_quote_common(&pool, &request, &quote);
    assert_eq!(quote.output.asset, pool.token_0);
    assert_eq!(quote.output.amount.get(), 1970);
    assert_eq!(quote.fee.amount.get(), 0);
    assert_eq!(quote.effective_input.amount.get(), 2000);
    assert_eq!(quote.bins_crossed, 1);
    assert_eq!(quote.resulting_active_bin_id, 2);
    assert_eq!(pool, initial_pool);
}

#[test]
fn test_pinned_vector_c() {
    let pool = pool_c();
    let initial_pool = pool.clone();

    // C1: zero-fee traversal crossing one bin.
    let request_zero_fee = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1500));
    let quote_zero_fee =
        simulate_bin_exact_input(&pool, &request_zero_fee).expect("vector C1 must succeed");
    assert_quote_common(&pool, &request_zero_fee, &quote_zero_fee);
    assert_eq!(quote_zero_fee.output.amount.get(), 1495);
    assert_eq!(quote_zero_fee.fee.amount.get(), 0);
    assert_eq!(quote_zero_fee.effective_input.amount.get(), 1500);
    assert_eq!(quote_zero_fee.bins_crossed, 1);
    assert_eq!(quote_zero_fee.resulting_active_bin_id, -1);

    // C2: 1% fee reduces effective input and output.
    let mut fee_pool = pool.clone();
    fee_pool.fee_bps = Bps::new(100).unwrap();
    let initial_fee_pool = fee_pool.clone();
    let request_fee = BinExactInputRequest::new(fee_pool.token_0.clone(), AtomicAmount::new(1500));
    let quote_fee =
        simulate_bin_exact_input(&fee_pool, &request_fee).expect("vector C2 must succeed");
    assert_quote_common(&fee_pool, &request_fee, &quote_fee);
    assert_eq!(quote_fee.fee.amount.get(), 15);
    assert_eq!(quote_fee.effective_input.amount.get(), 1485);
    assert_eq!(quote_fee.output.amount.get(), 1480);
    assert_eq!(quote_fee.bins_crossed, 1);
    assert_eq!(quote_fee.resulting_active_bin_id, -1);
    assert_eq!(fee_pool, initial_fee_pool);

    // C3: input exactly exhausts the active bin without crossing.
    let request_exact = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1000));
    let quote_exact =
        simulate_bin_exact_input(&pool, &request_exact).expect("vector C3 must succeed");
    assert_quote_common(&pool, &request_exact, &quote_exact);
    assert_eq!(quote_exact.output.amount.get(), 1000);
    assert_eq!(quote_exact.fee.amount.get(), 0);
    assert_eq!(quote_exact.effective_input.amount.get(), 1000);
    assert_eq!(quote_exact.bins_crossed, 0);
    assert_eq!(quote_exact.resulting_active_bin_id, 0);
    assert_eq!(pool, initial_pool);
}

#[test]
fn test_pinned_vector_d() {
    let pool = pool_d();
    let initial_pool = pool.clone();

    // D1: token_0 in, atomic price 1.01 with 12 decimal scaling.
    let request_0 = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(500_000));
    let quote_0 = simulate_bin_exact_input(&pool, &request_0).expect("vector D1 must succeed");
    assert_quote_common(&pool, &request_0, &quote_0);
    assert_eq!(quote_0.output.asset, pool.token_1);
    assert_eq!(quote_0.output.amount.get(), 505_000_000_000_000_000);
    assert_eq!(quote_0.fee.amount.get(), 0);
    assert_eq!(quote_0.effective_input.amount.get(), 500_000);
    assert_eq!(quote_0.bins_crossed, 0);
    assert_eq!(quote_0.resulting_active_bin_id, 1);

    // D2: token_1 in, inverse price floor.
    let request_1 = BinExactInputRequest::new(
        pool.token_1.clone(),
        AtomicAmount::new(1_000_000_000_000_000_000),
    );
    let quote_1 = simulate_bin_exact_input(&pool, &request_1).expect("vector D2 must succeed");
    assert_quote_common(&pool, &request_1, &quote_1);
    assert_eq!(quote_1.output.asset, pool.token_0);
    assert_eq!(quote_1.output.amount.get(), 990_099);
    assert_eq!(quote_1.fee.amount.get(), 0);
    assert_eq!(
        quote_1.effective_input.amount.get(),
        1_000_000_000_000_000_000
    );
    assert_eq!(quote_1.bins_crossed, 0);
    assert_eq!(quote_1.resulting_active_bin_id, 1);

    assert_eq!(pool, initial_pool);
}

// ---------------------------------------------------------------------------
// 2. Request constructors and directed output binding
// ---------------------------------------------------------------------------

#[test]
fn test_request_constructors_and_directed_output_binding() {
    let (token_0, token_1) = sample_assets();
    let inferred = BinExactInputRequest::new(token_0.clone(), AtomicAmount::new(1010));
    assert_eq!(inferred.token_out, None);

    let directed = BinExactInputRequest::new_directed(
        token_0.clone(),
        AtomicAmount::new(1010),
        token_1.clone(),
    );
    assert_eq!(directed.token_out, Some(token_1.clone()));

    let pool = pool_a();

    // Matching counter-asset succeeds.
    let ok = simulate_bin_exact_input(&pool, &directed).unwrap();
    assert_eq!(ok.output.asset, pool.token_1);

    // Same input asset as asserted output rejects with InvalidAssetDirection.
    let same = BinExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1010),
        pool.token_0.clone(),
    );
    assert_eq!(
        simulate_bin_exact_input(&pool, &same).unwrap_err(),
        BinSimulationError::InvalidAssetDirection
    );

    // Unrelated output asset rejects with OutputAssetMismatch.
    let mismatched = BinExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1010),
        unrelated_asset(),
    );
    assert_eq!(
        simulate_bin_exact_input(&pool, &mismatched).unwrap_err(),
        BinSimulationError::OutputAssetMismatch
    );
}

// ---------------------------------------------------------------------------
// 3. Validation order and fail-closed safety
// ---------------------------------------------------------------------------

#[test]
fn test_zero_input_and_invalid_direction_rejected() {
    let pool = pool_a();

    let zero = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(0));
    assert_eq!(
        simulate_bin_exact_input(&pool, &zero).unwrap_err(),
        BinSimulationError::ZeroInputAmount
    );

    let unknown = BinExactInputRequest::new(unrelated_asset(), AtomicAmount::new(1010));
    assert_eq!(
        simulate_bin_exact_input(&pool, &unknown).unwrap_err(),
        BinSimulationError::InvalidAssetDirection
    );
}

#[test]
fn test_chain_mismatch_rejected() {
    let pool = pool_a();

    let evm_in = BinExactInputRequest::new(evm_asset(), AtomicAmount::new(1010));
    assert_eq!(
        simulate_bin_exact_input(&pool, &evm_in).unwrap_err(),
        BinSimulationError::ChainMismatch
    );

    let evm_out = BinExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1010),
        evm_asset(),
    );
    assert_eq!(
        simulate_bin_exact_input(&pool, &evm_out).unwrap_err(),
        BinSimulationError::ChainMismatch
    );
}

#[test]
fn test_invalid_fee_and_invalid_bin_step_rejected() {
    let pool = pool_a();
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1010));

    let mut max_fee_pool = pool.clone();
    max_fee_pool.fee_bps = Bps::new(Bps::MAX).unwrap();
    assert_eq!(
        simulate_bin_exact_input(&max_fee_pool, &request).unwrap_err(),
        BinSimulationError::InvalidFee
    );

    let mut zero_step_pool = pool.clone();
    zero_step_pool.bin_step = 0;
    assert_eq!(
        simulate_bin_exact_input(&zero_step_pool, &request).unwrap_err(),
        BinSimulationError::InvalidBinStep
    );
}

#[test]
fn test_missing_active_bin_rejected() {
    // All represented bins lie strictly below the active id, so pool validation passes
    // while the active bin itself is missing.
    let pool = make_pool(100, 0, 0, 0, 0, vec![bin(-2, 0, 10), bin(-1, 0, 10)]);
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(5));
    assert_eq!(
        simulate_bin_exact_input(&pool, &request).unwrap_err(),
        BinSimulationError::InvalidRange
    );
}

#[test]
fn test_input_exceeding_all_liquidity_rejects_fail_closed() {
    let pool = pool_c();
    let initial_pool = pool.clone();
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1_000_000));

    assert_eq!(
        simulate_bin_exact_input(&pool, &request).unwrap_err(),
        BinSimulationError::BinCrossingExceeded
    );
    assert_eq!(pool, initial_pool);
}

#[test]
fn test_fee_rounding_to_zero_output_fails_closed() {
    let mut pool = pool_d();
    pool.fee_bps = Bps::new(9999).unwrap();
    let request = BinExactInputRequest::new(pool.token_1.clone(), AtomicAmount::new(1));

    let err = simulate_bin_exact_input(&pool, &request).unwrap_err();

    // `fee = floor(amount_in * fee_bps / 10_000)` can never consume the whole input while
    // `fee_bps < Bps::MAX`: for `amount_in >= 1` and `fee_bps <= 9999`,
    // `floor(amount_in * fee_bps / 10_000) <= amount_in - 1`, so `effective_input >= 1`.
    // `ZeroEffectiveInput` is therefore arithmetically unreachable through the public API,
    // and the actual fail-closed outcome is the sub-unit output rounding to zero.
    assert!(matches!(
        err,
        BinSimulationError::ZeroEffectiveInput | BinSimulationError::ZeroOutputAmount
    ));
    assert_eq!(err, BinSimulationError::ZeroOutputAmount);
}

// ---------------------------------------------------------------------------
// 4. Bounded traversal: bin-crossing cap and price-arithmetic overflow
// ---------------------------------------------------------------------------

#[test]
fn test_max_bin_crosses_bound_binds_fail_closed() {
    assert_eq!(MAX_BIN_CROSSES, 32);

    // bin_step 1000 bps reduces the base price to 11/10, so 11^32 and 10^32 both fit
    // in u128: the crossing cap binds before any price arithmetic overflow.
    let bins: Vec<LiquidityBin> = (-100..=0).map(|id| bin(id, 0, 1)).collect();
    let pool = make_pool(1000, 0, 0, 0, 0, bins);
    let initial_pool = pool.clone();

    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1_000_000));
    assert_eq!(
        simulate_bin_exact_input(&pool, &request).unwrap_err(),
        BinSimulationError::BinCrossingExceeded
    );
    assert_eq!(pool, initial_pool);
}

#[test]
fn test_deep_traversal_price_overflow_fails_closed() {
    // With bin_step 100 the base price is 101/100; traversing 20 represented bins
    // requires 100^20, which exceeds u128, so the kernel fails closed on overflow.
    let bins: Vec<LiquidityBin> = (-100..=0).map(|id| bin(id, 0, 1)).collect();
    let pool = make_pool(100, 0, 0, 0, 0, bins);

    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1_000_000));
    assert_eq!(
        simulate_bin_exact_input(&pool, &request).unwrap_err(),
        BinSimulationError::ArithmeticOverflow
    );
}

// ---------------------------------------------------------------------------
// 5. Serialization determinism
// ---------------------------------------------------------------------------

#[test]
fn test_serialization_determinism() {
    let pool = pool_a();
    let request = BinExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1010),
        pool.token_1.clone(),
    );
    let quote = simulate_bin_exact_input(&pool, &request).unwrap();

    let quote_json = serde_json::to_string(&quote).unwrap();
    let deserialized: BinSimulationQuote = serde_json::from_str(&quote_json).unwrap();
    assert_eq!(quote, deserialized);
    assert_eq!(quote_json, serde_json::to_string(&deserialized).unwrap());

    let request_json = serde_json::to_string(&request).unwrap();
    let deserialized_request: BinExactInputRequest = serde_json::from_str(&request_json).unwrap();
    assert_eq!(request, deserialized_request);

    // Inferred output asset is omitted from the wire representation.
    let inferred = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1010));
    let inferred_json = serde_json::to_string(&inferred).unwrap();
    assert!(!inferred_json.contains("token_out"));

    let err = BinSimulationError::BinCrossingExceeded;
    let err_json = serde_json::to_string(&err).unwrap();
    let deserialized_err: BinSimulationError = serde_json::from_str(&err_json).unwrap();
    assert_eq!(err, deserialized_err);
}

// ---------------------------------------------------------------------------
// 6. Error redaction in Debug and Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_redaction_debug_and_display() {
    // Exact generic messages for representative variants.
    assert_eq!(
        format!("{}", BinSimulationError::ChainMismatch),
        "chain mismatch: asset chain does not match pool chain"
    );
    assert_eq!(
        format!("{}", BinSimulationError::ZeroInputAmount),
        "swap input amount must be greater than zero"
    );
    assert_eq!(
        format!("{}", BinSimulationError::BinCrossingExceeded),
        "bin crossing limit exceeded"
    );
    assert_eq!(
        format!("{}", BinSimulationError::ZeroOutputAmount),
        "simulated output amount is zero"
    );

    let all_errors = [
        BinSimulationError::InvalidPoolState,
        BinSimulationError::ZeroInputAmount,
        BinSimulationError::InvalidFee,
        BinSimulationError::InvalidBinStep,
        BinSimulationError::InvalidRange,
        BinSimulationError::BinCrossingExceeded,
        BinSimulationError::InvalidAssetDirection,
        BinSimulationError::OutputAssetMismatch,
        BinSimulationError::ChainMismatch,
        BinSimulationError::ZeroEffectiveInput,
        BinSimulationError::ZeroOutputAmount,
        BinSimulationError::ArithmeticOverflow,
        BinSimulationError::InvariantViolated,
        BinSimulationError::StaleOrUnavailableState,
    ];

    let forbidden_patterns = [
        "1010",
        "500000",
        "500_000",
        "So11111111111111111111111111111111111111112",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
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

        // No amounts, bin ids, prices, or reserve values leak as digits.
        assert!(
            display_str.chars().all(|ch| !ch.is_ascii_digit()),
            "Display of error contains digits: {display_str}"
        );
        assert!(
            debug_str.chars().all(|ch| !ch.is_ascii_digit()),
            "Debug of error contains digits: {debug_str}"
        );
    }

    // A representative runtime error stays redacted regardless of the input amount.
    let pool = pool_a();
    let request = BinExactInputRequest::new(unrelated_asset(), AtomicAmount::new(1010));
    let err = simulate_bin_exact_input(&pool, &request).unwrap_err();
    assert_eq!(err, BinSimulationError::InvalidAssetDirection);
    let display_str = format!("{}", err);
    let debug_str = format!("{:?}", err);
    assert_eq!(display_str, "asset direction is invalid");
    assert!(!display_str.contains("1010"));
    assert!(!debug_str.contains("1010"));
    assert!(debug_str.chars().all(|ch| !ch.is_ascii_digit()));
}
