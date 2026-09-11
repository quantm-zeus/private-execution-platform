use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, CpmmPoolState};
use simulation::{
    cmp_u128_products, div_u256_by_u128_floor, mul_u128_wide, simulate_cpmm_exact_input,
    simulate_cpmm_swap, simulate_cpmm_swap_directed, CpmmExactInputRequest, SimulationError,
};

fn sample_assets() -> (AssetId, AssetId) {
    let token_0 =
        AssetId::new(ChainId::Base, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap(); // USDC
    let token_1 =
        AssetId::new(ChainId::Base, "0x4200000000000000000000000000000000000006").unwrap(); // WETH
    (token_0, token_1)
}

fn sample_pool(reserve_0: u128, reserve_1: u128, fee_bps: u16) -> CpmmPoolState {
    let (token_0, token_1) = sample_assets();
    CpmmPoolState {
        token_0,
        token_1,
        decimals_0: 6,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(reserve_0),
        reserve_1: AtomicAmount::new(reserve_1),
        total_lp_supply: Some(AtomicAmount::new(10_000_000)),
        fee_bps: Bps::new(fee_bps).unwrap(),
    }
}

// 1. Proving deterministic known vectors in both pool directions
#[test]
fn test_deterministic_known_vectors_both_directions() {
    let pool = sample_pool(1_000_000, 2_000_000, 30); // 30 bps = 0.3%

    // --- Direction 0 -> 1 ---
    // amount_in = 10_000
    // fee = floor(10_000 * 30 / 10_000) = 30
    // effective_input = 10_000 - 30 = 9_970
    // numerator = 9_970 * 2_000_000 = 19_940_000_000
    // denominator = 1_000_000 + 9_970 = 1_009_970
    // amount_out = floor(19_940_000_000 / 1_009_970) = 19_743
    // resulting_reserve_0 = 1_000_000 + 10_000 = 1_010_000
    // resulting_reserve_1 = 2_000_000 - 19_743 = 1_980_257
    let quote_0_to_1 = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(10_000)).unwrap();

    assert_eq!(quote_0_to_1.input.asset, pool.token_0);
    assert_eq!(quote_0_to_1.input.amount.get(), 10_000);
    assert_eq!(quote_0_to_1.output.asset, pool.token_1);
    assert_eq!(quote_0_to_1.output.amount.get(), 19_743);
    assert_eq!(quote_0_to_1.pool_fee.asset, pool.token_0);
    assert_eq!(quote_0_to_1.pool_fee.amount.get(), 30);
    assert_eq!(quote_0_to_1.effective_input.asset, pool.token_0);
    assert_eq!(quote_0_to_1.effective_input.amount.get(), 9_970);
    assert_eq!(quote_0_to_1.resulting_reserve_0.get(), 1_010_000);
    assert_eq!(quote_0_to_1.resulting_reserve_1.get(), 1_980_257);
    assert_eq!(quote_0_to_1.resulting_reserve_in.get(), 1_010_000);
    assert_eq!(quote_0_to_1.resulting_reserve_out.get(), 1_980_257);
    assert_eq!(quote_0_to_1.fee_bps.get(), 30);

    // Verify constant-product invariant k_new >= k_old
    let k_old = 1_000_000u128 * 2_000_000u128;
    let k_new = quote_0_to_1.resulting_reserve_0.get() * quote_0_to_1.resulting_reserve_1.get();
    assert!(k_new >= k_old);

    // --- Direction 1 -> 0 ---
    // amount_in = 20_000
    // fee = floor(20_000 * 30 / 10_000) = 60
    // effective_input = 20_000 - 60 = 19_940
    // numerator = 19_940 * 1_000_000 = 19_940_000_000
    // denominator = 2_000_000 + 19_940 = 2_019_940
    // amount_out = floor(19_940_000_000 / 2_019_940) = 9_871
    // resulting_reserve_0 = 1_000_000 - 9_871 = 990_129
    // resulting_reserve_1 = 2_000_000 + 20_000 = 2_020_000
    let quote_1_to_0 = simulate_cpmm_swap(&pool, &pool.token_1, AtomicAmount::new(20_000)).unwrap();

    assert_eq!(quote_1_to_0.input.asset, pool.token_1);
    assert_eq!(quote_1_to_0.input.amount.get(), 20_000);
    assert_eq!(quote_1_to_0.output.asset, pool.token_0);
    assert_eq!(quote_1_to_0.output.amount.get(), 9_871);
    assert_eq!(quote_1_to_0.pool_fee.asset, pool.token_1);
    assert_eq!(quote_1_to_0.pool_fee.amount.get(), 60);
    assert_eq!(quote_1_to_0.effective_input.asset, pool.token_1);
    assert_eq!(quote_1_to_0.effective_input.amount.get(), 19_940);
    assert_eq!(quote_1_to_0.resulting_reserve_0.get(), 990_129);
    assert_eq!(quote_1_to_0.resulting_reserve_1.get(), 2_020_000);
    assert_eq!(quote_1_to_0.resulting_reserve_in.get(), 2_020_000);
    assert_eq!(quote_1_to_0.resulting_reserve_out.get(), 990_129);
    assert_eq!(quote_1_to_0.fee_bps.get(), 30);

    let k_new_rev = quote_1_to_0.resulting_reserve_0.get() * quote_1_to_0.resulting_reserve_1.get();
    assert!(k_new_rev >= k_old);
}

// 2. Proving integer-floor fee and output behavior
#[test]
fn test_integer_floor_fee_and_output_behavior() {
    let pool = sample_pool(10_000_000, 10_000_000, 30);

    // Case 2A: fee truncation where amount_in * fee_bps < 10_000 -> fee is strictly 0
    let small_quote = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(300)).unwrap();
    // 300 * 30 = 9_000 < 10_000 => fee is 0
    assert_eq!(small_quote.pool_fee.amount.get(), 0);
    assert_eq!(small_quote.effective_input.amount.get(), 300);

    // Case 2B: fee truncation with positive remainder
    // 999 * 30 = 29_970. 29_970 / 10_000 = 2 (remainder 9_970, not rounded up to 3)
    let rem_quote = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(999)).unwrap();
    assert_eq!(rem_quote.pool_fee.amount.get(), 2);
    assert_eq!(rem_quote.effective_input.amount.get(), 997);
    assert_eq!(
        rem_quote.pool_fee.amount.get() + rem_quote.effective_input.amount.get(),
        999
    );

    // Case 2C: output truncation with explicit floor checking
    // effective_input = 997, reserve_out = 10_000_000, reserve_in = 10_000_000
    // numerator = 997 * 10_000_000 = 9_970_000_000
    // denominator = 10_000_000 + 997 = 10_000_997
    // Exact quotient = 9_970_000_000 / 10_000_997 = 996.9006...
    // Floor MUST be 996 (never rounded up to 997)
    assert_eq!(rem_quote.output.amount.get(), 996);

    // Assert that floor behavior holds: (amount_out + 1) * denominator > numerator
    let num = 997u128 * 10_000_000u128;
    let den = 10_000_000u128 + 997u128;
    let out = rem_quote.output.amount.get();
    assert!(out * den <= num);
    assert!((out + 1) * den > num);
}

// 3. Proving nonzero output strictly below output reserve
#[test]
fn test_nonzero_output_strictly_below_output_reserve() {
    // 3A: Sub-satoshi output where calculation would produce zero -> fail-closed ZeroOutputAmount
    let unbalanced_pool = sample_pool(1_000_000_000, 100, 30);
    // input = 1 -> effective_input = 1. numerator = 1 * 100 = 100. denominator = 1_000_000_001.
    // amount_out = 0 -> MUST reject fail-closed!
    let zero_res = simulate_cpmm_swap(
        &unbalanced_pool,
        &unbalanced_pool.token_0,
        AtomicAmount::new(1),
    );
    assert_eq!(zero_res, Err(SimulationError::ZeroOutputAmount));

    // 3B: Output is strictly below output reserve even under extreme liquidity draw
    let pool = sample_pool(1_000, 1_000, 30);
    let huge_quote = simulate_cpmm_swap(
        &pool,
        &pool.token_0,
        AtomicAmount::new(10_000_000_000), // massive relative input
    )
    .unwrap();

    // Output must be strictly less than reserve_1 (1_000)
    assert!(huge_quote.output.amount.get() < pool.reserve_1.get());
    assert_eq!(huge_quote.output.amount.get(), 999);
    // Pool must never be completely drained
    assert!(huge_quote.resulting_reserve_1.get() > 0);
    assert_eq!(huge_quote.resulting_reserve_1.get(), 1);
}

// 4. Proving asset-direction rejection
#[test]
fn test_asset_direction_rejection() {
    let pool = sample_pool(1_000_000, 1_000_000, 30);

    // 4A: input asset not in pool
    let foreign_asset =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000099").unwrap();
    let res = simulate_cpmm_swap(&pool, &foreign_asset, AtomicAmount::new(1_000));
    assert_eq!(
        res,
        Err(SimulationError::AssetNotFoundInPool(foreign_asset.clone()))
    );

    // 4B: chain mismatch
    let solana_asset = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let res_chain = simulate_cpmm_swap(&pool, &solana_asset, AtomicAmount::new(1_000));
    assert_eq!(res_chain, Err(SimulationError::ChainMismatch));

    // 4C: caller asserts output asset identical to input asset
    let req_same = CpmmExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1_000),
        pool.token_0.clone(),
    );
    let res_same = simulate_cpmm_exact_input(&pool, &req_same);
    assert_eq!(
        res_same,
        Err(SimulationError::OutputAssetMismatch {
            expected: pool.token_1.clone(),
            received: pool.token_0.clone(),
        })
    );

    // 4D: caller asserts output asset that is a foreign token
    let req_foreign = CpmmExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(1_000),
        foreign_asset.clone(),
    );
    let res_foreign = simulate_cpmm_exact_input(&pool, &req_foreign);
    assert_eq!(
        res_foreign,
        Err(SimulationError::OutputAssetMismatch {
            expected: pool.token_1.clone(),
            received: foreign_asset,
        })
    );

    // 4E: Direction 1->0 but caller asserts output is token_1
    let req_rev_mismatch = CpmmExactInputRequest::new_directed(
        pool.token_1.clone(),
        AtomicAmount::new(1_000),
        pool.token_1.clone(),
    );
    let res_rev = simulate_cpmm_exact_input(&pool, &req_rev_mismatch);
    assert_eq!(
        res_rev,
        Err(SimulationError::OutputAssetMismatch {
            expected: pool.token_0.clone(),
            received: pool.token_1.clone(),
        })
    );
}

// 5. Proving zero/invalid fee/reserve/input rejection
#[test]
fn test_zero_and_invalid_inputs_reserves_fees_rejection() {
    let base_pool = sample_pool(1_000_000, 1_000_000, 30);

    // 5A: Zero input amount
    let zero_in = simulate_cpmm_swap(&base_pool, &base_pool.token_0, AtomicAmount::ZERO);
    assert_eq!(zero_in, Err(SimulationError::ZeroInputAmount));

    // 5B: Zero reserve_0
    let mut zero_res0 = base_pool.clone();
    zero_res0.reserve_0 = AtomicAmount::ZERO;
    let res_zero_0 = simulate_cpmm_swap(&zero_res0, &zero_res0.token_0, AtomicAmount::new(1_000));
    assert_eq!(res_zero_0, Err(SimulationError::ZeroReserve));

    // 5C: Zero reserve_1
    let mut zero_res1 = base_pool.clone();
    zero_res1.reserve_1 = AtomicAmount::ZERO;
    let res_zero_1 = simulate_cpmm_swap(&zero_res1, &zero_res1.token_0, AtomicAmount::new(1_000));
    assert_eq!(res_zero_1, Err(SimulationError::ZeroReserve));

    // 5D: Both reserves zero
    let mut zero_both = base_pool.clone();
    zero_both.reserve_0 = AtomicAmount::ZERO;
    zero_both.reserve_1 = AtomicAmount::ZERO;
    let res_zero_both =
        simulate_cpmm_swap(&zero_both, &zero_both.token_0, AtomicAmount::new(1_000));
    assert_eq!(res_zero_both, Err(SimulationError::ZeroReserve));

    // 5E: Zero fee basis points
    let mut zero_fee_pool = base_pool.clone();
    zero_fee_pool.fee_bps = Bps::new(0).unwrap();
    let res_zero_fee = simulate_cpmm_swap(
        &zero_fee_pool,
        &zero_fee_pool.token_0,
        AtomicAmount::new(1_000),
    );
    assert_eq!(res_zero_fee, Err(SimulationError::ZeroFee));

    // 5F: Invalid 100% fee (10_000 bps)
    let mut max_fee_pool = base_pool.clone();
    max_fee_pool.fee_bps = Bps::new(10_000).unwrap();
    let res_max_fee = simulate_cpmm_swap(
        &max_fee_pool,
        &max_fee_pool.token_0,
        AtomicAmount::new(1_000),
    );
    assert_eq!(res_max_fee, Err(SimulationError::InvalidFeeBps(10_000)));

    // 5G: Invalid pool state (identical tokens)
    let mut invalid_state = base_pool.clone();
    invalid_state.token_1 = invalid_state.token_0.clone();
    let res_invalid = simulate_cpmm_swap(
        &invalid_state,
        &invalid_state.token_0,
        AtomicAmount::new(1_000),
    );
    assert!(matches!(
        res_invalid,
        Err(SimulationError::InvalidPoolState(_))
    ));
}

// 6. Proving overflow failure without panic
#[test]
fn test_overflow_failure_without_panic() {
    let pool = sample_pool(1_000_000, 1_000_000, 30);

    // 6A: Max u128 input amount
    let max_in_res = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(u128::MAX));
    assert_eq!(max_in_res, Err(SimulationError::ArithmeticOverflow));

    // 6B: Reserve addition overflow (reserve_in + amount_in > u128::MAX)
    let mut huge_reserve_pool = sample_pool(u128::MAX - 5, 1_000_000, 30);
    let res_add_overflow = simulate_cpmm_swap(
        &huge_reserve_pool,
        &huge_reserve_pool.token_0,
        AtomicAmount::new(10),
    );
    assert_eq!(res_add_overflow, Err(SimulationError::ArithmeticOverflow));

    // 6C: Invariant reserve_0 addition overflow
    huge_reserve_pool.reserve_0 = AtomicAmount::new(u128::MAX);
    let res_res0_overflow = simulate_cpmm_swap(
        &huge_reserve_pool,
        &huge_reserve_pool.token_0,
        AtomicAmount::new(1),
    );
    assert_eq!(res_res0_overflow, Err(SimulationError::ArithmeticOverflow));
}

// 7. Proving input pool state immutability after success and failure
#[test]
fn test_pool_state_immutability_on_success_and_failure() {
    let pool = sample_pool(1_000_000, 2_000_000, 30);
    let pool_snapshot = pool.clone();

    // 7A: Immutability across successful swap
    let quote = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(5_000)).unwrap();
    assert_eq!(quote.output.amount.get(), 9_920);
    assert_eq!(pool, pool_snapshot, "pool must not mutate on success");

    // 7B: Immutability across zero input failure
    let _ = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::ZERO);
    assert_eq!(pool, pool_snapshot, "pool must not mutate on zero input");

    // 7C: Immutability across zero output failure
    let unbal = sample_pool(1_000_000_000, 10, 30);
    let unbal_snapshot = unbal.clone();
    let _ = simulate_cpmm_swap(&unbal, &unbal.token_0, AtomicAmount::new(1));
    assert_eq!(unbal, unbal_snapshot, "pool must not mutate on zero output");

    // 7D: Immutability across foreign asset failure
    let foreign =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000077").unwrap();
    let _ = simulate_cpmm_swap(&pool, &foreign, AtomicAmount::new(1_000));
    assert_eq!(pool, pool_snapshot, "pool must not mutate on wrong asset");

    // 7E: Immutability across overflow failure
    let _ = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(u128::MAX));
    assert_eq!(pool, pool_snapshot, "pool must not mutate on overflow");
}

// 8. Bounded deterministic sweep / property-style test
#[test]
fn test_bounded_deterministic_property_sweep() {
    let pool = sample_pool(100_000_000_000, 200_000_000_000, 30); // 100k, 200k units
    let mut prev_output = 0u128;

    // Sweep 100 progressively increasing input amounts
    for step in 1..=100 {
        let amount_in = step as u128 * 100_000_000; // from 100 to 10,000 units
        let quote = simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(amount_in)).unwrap();

        let out = quote.output.amount.get();
        let fee = quote.pool_fee.amount.get();
        let eff_in = quote.effective_input.amount.get();

        // 1. Output must be strictly positive and below pool reserve
        assert!(out > 0);
        assert!(out < pool.reserve_1.get());

        // 2. Input conservation: fee + effective_input == amount_in
        assert_eq!(fee + eff_in, amount_in);

        // 3. Monotonicity: larger input must produce non-decreasing output
        assert!(out >= prev_output);
        prev_output = out;

        // 4. Reserve conservation
        assert_eq!(
            quote.resulting_reserve_in.get(),
            pool.reserve_0.get() + amount_in
        );
        assert_eq!(
            quote.resulting_reserve_out.get(),
            pool.reserve_1.get() - out
        );
        assert_eq!(
            quote.resulting_reserve_0.get(),
            quote.resulting_reserve_in.get()
        );
        assert_eq!(
            quote.resulting_reserve_1.get(),
            quote.resulting_reserve_out.get()
        );

        // 5. Invariant preservation: k_new >= k_old
        assert!(
            cmp_u128_products(
                quote.resulting_reserve_in.get(),
                quote.resulting_reserve_out.get(),
                pool.reserve_0.get(),
                pool.reserve_1.get()
            ) != std::cmp::Ordering::Less
        );
    }
}

// 9. Wide multiplication and 256/128 division precision tests
#[test]
fn test_wide_math_primitives() {
    // mul_u128_wide identity and bounds
    assert_eq!(mul_u128_wide(0, 100), (0, 0));
    assert_eq!(mul_u128_wide(1, 1), (0, 1));
    assert_eq!(mul_u128_wide(10, 20), (0, 200));

    let (hi, lo) = mul_u128_wide(u128::MAX, u128::MAX);
    assert_eq!(hi, u128::MAX - 1);
    assert_eq!(lo, 1);

    // div_u256_by_u128_floor
    assert_eq!(div_u256_by_u128_floor(0, 100, 0), None);
    assert_eq!(div_u256_by_u128_floor(10, 100, 5), None); // hi >= den => quotient > u128::MAX
    assert_eq!(div_u256_by_u128_floor(0, 999, 10), Some(99)); // floor of 99.9

    // Div with hi > 0 where quotient fits in u128
    // (1 * 2^128 + 0) / (2^128 - 1)
    let quot = div_u256_by_u128_floor(1, 0, u128::MAX);
    assert_eq!(quot, Some(1));
}

// 10. Directed swap helper and request methods
#[test]
fn test_directed_swap_helpers() {
    let pool = sample_pool(1_000_000, 2_000_000, 30);
    let quote = simulate_cpmm_swap_directed(
        &pool,
        &pool.token_0,
        AtomicAmount::new(10_000),
        &pool.token_1,
    )
    .unwrap();
    assert_eq!(quote.output.amount.get(), 19_743);

    // Price ratio helper
    let ratio = quote.quote_price_ratio().unwrap();
    assert_eq!(ratio.numerator_atomic(), 19_743);
    assert_eq!(ratio.denominator_atomic(), 10_000);
}
