//! Focused tests for the CPMM exact-output kernel.
//!
//! The harness independently recomputes the required post-fee effective input and
//! the realized output from the locked exact-input floor rules, so the sweep is
//! not circular: it reuses only the raw constant-product identity and integer
//! arithmetic, never the new inversion code.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, CpmmPoolState};
use simulation::{
    cmp_u128_products, div_u256_by_u128_ceil, simulate_cpmm_exact_input,
    simulate_cpmm_exact_output, CpmmExactInputRequest, CpmmExactOutputQuote,
    CpmmExactOutputRequest, CpmmSimulationKernel, SimulationError,
};
use std::cmp::Ordering;

fn sample_assets() -> (AssetId, AssetId) {
    let token_0 =
        AssetId::new(ChainId::Base, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
    let token_1 =
        AssetId::new(ChainId::Base, "0x4200000000000000000000000000000000000006").unwrap();
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

/// Independent oracle: exact-input output under the locked floor rules.
#[inline]
fn oracle_exact_input_output(amount_in: u128, fee_bps: u16, r_in: u128, r_out: u128) -> u128 {
    let fee = amount_in * fee_bps as u128 / 10_000;
    let effective = amount_in - fee;
    effective * r_out / (r_in + effective)
}

/// Independent oracle: effective post-fee input under the locked floor rules.
#[inline]
fn oracle_effective_input(amount_in: u128, fee_bps: u16) -> u128 {
    amount_in - amount_in * fee_bps as u128 / 10_000
}

/// Deterministic seeded PRNG (splitmix64), no external dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u128) -> u128 {
        debug_assert!(bound > 0);
        self.next_u64() as u128 % bound
    }
}

fn assert_quote_matches_oracle(
    quote: &CpmmExactOutputQuote,
    pool: &CpmmPoolState,
    token_in: &AssetId,
    requested_out: u128,
) {
    let fee_bps = pool.fee_bps.get();
    let (r_in, r_out, out_asset) = if token_in == &pool.token_0 {
        (
            pool.reserve_0.get(),
            pool.reserve_1.get(),
            pool.token_1.clone(),
        )
    } else {
        (
            pool.reserve_1.get(),
            pool.reserve_0.get(),
            pool.token_0.clone(),
        )
    };

    let amount_in = quote.input.amount.get();
    let effective = quote.effective_input.amount.get();
    let fee = quote.pool_fee.amount.get();

    // Denominations.
    assert_eq!(quote.input.asset, *token_in);
    assert_eq!(quote.output.asset, out_asset);
    assert_eq!(quote.requested_output.asset, out_asset);
    assert_eq!(quote.requested_output.amount.get(), requested_out);
    assert_eq!(quote.fee_bps.get(), fee_bps);

    // Exact fee/effective decomposition of the gross input.
    assert!(amount_in >= 1);
    assert_eq!(fee, amount_in * fee_bps as u128 / 10_000);
    assert_eq!(effective, oracle_effective_input(amount_in, fee_bps));
    assert_eq!(amount_in, fee + effective);
    assert!(effective >= 1);

    // The effective input is minimal for the requested output, checked with
    // independent 256-bit products: e*(R_out - dy) >= dy*R_in and the same with
    // e-1 must be strictly below. No reuse of the new ceil/clamp code.
    let gap = r_out - requested_out;
    assert_ne!(
        cmp_u128_products(effective, gap, requested_out, r_in),
        Ordering::Less,
        "effective input does not reach the requested output"
    );
    if effective > 1 {
        assert_eq!(
            cmp_u128_products(effective - 1, gap, requested_out, r_in),
            Ordering::Less,
            "effective input is not minimal"
        );
    }

    // The gross input is minimal for that effective input.
    if amount_in > 1 {
        assert!(
            oracle_effective_input(amount_in - 1, fee_bps) < effective,
            "gross input is not minimal for the effective input"
        );
    }

    // Realized output recomputed independently from the constant-product floor.
    let expected_out = oracle_exact_input_output(amount_in, fee_bps, r_in, r_out);
    assert_eq!(quote.output.amount.get(), expected_out);
    assert!(expected_out >= requested_out);
    assert!(expected_out < r_out);
    assert_eq!(quote.output_overshoot().get(), expected_out - requested_out);

    // Resulting reserves are the exact post-swap state.
    assert_eq!(quote.resulting_reserve_in.get(), r_in + amount_in);
    assert_eq!(quote.resulting_reserve_out.get(), r_out - expected_out);
    if token_in == &pool.token_0 {
        assert_eq!(quote.resulting_reserve_0.get(), r_in + amount_in);
        assert_eq!(quote.resulting_reserve_1.get(), r_out - expected_out);
    } else {
        assert_eq!(quote.resulting_reserve_0.get(), r_out - expected_out);
        assert_eq!(quote.resulting_reserve_1.get(), r_in + amount_in);
    }

    // Cross-kernel consistency: feeding `input` to the exact-input kernel must
    // reproduce every realized figure.
    let realized = simulate_cpmm_exact_input(
        pool,
        &CpmmExactInputRequest::new(token_in.clone(), AtomicAmount::new(amount_in)),
    )
    .expect("required input must simulate");
    assert_eq!(realized.output.amount.get(), expected_out);
    assert_eq!(realized.effective_input.amount.get(), effective);
    assert_eq!(realized.pool_fee.amount.get(), fee);

    // Minimality by simulation: one unit less never covers the request.
    if amount_in > 1 {
        if let Ok(previous) = simulate_cpmm_exact_input(
            pool,
            &CpmmExactInputRequest::new(token_in.clone(), AtomicAmount::new(amount_in - 1)),
        ) {
            assert!(
                previous.output.amount.get() < requested_out,
                "one unit less already covers the request"
            );
        }
    }
}

#[test]
fn ceil_division_helper_is_exact_and_fail_closed() {
    assert_eq!(div_u256_by_u128_ceil(0, 100, 10), Some(10));
    assert_eq!(div_u256_by_u128_ceil(0, 101, 10), Some(11));
    assert_eq!(div_u256_by_u128_ceil(0, 1, 10), Some(1));
    assert_eq!(div_u256_by_u128_ceil(0, 0, 10), Some(0));
    assert_eq!(div_u256_by_u128_ceil(0, 10, 0), None);
    // 2^128 / 2 == 2^127 (still representable).
    assert_eq!(div_u256_by_u128_ceil(1, 0, 2), Some(1u128 << 127));
    // quotient already exceeds u128::MAX.
    assert_eq!(div_u256_by_u128_ceil(1, 0, 1), None);
    // floor == u128::MAX with a non-zero remainder: the ceiling overflows.
    assert_eq!(div_u256_by_u128_ceil(1, u128::MAX, 2), None);

    // Independent naive oracle for small values.
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    for _ in 0..20_000 {
        let lo = rng.below(1_000_000);
        let den = rng.below(999) + 1;
        let expected = lo.div_ceil(den);
        assert_eq!(div_u256_by_u128_ceil(0, lo, den), Some(expected));
    }
}

#[test]
fn known_vectors_both_directions_are_minimal() {
    let pool = sample_pool(1_000_000, 2_000_000, 30);

    // Direction 0 -> 1: request the output that the exact-input kernel produces
    // for 10_000 input. The true minimal input is 9_999 (not 10_000), because
    // floor(9_999 * 30 / 10_000) == 29.
    let quote = simulate_cpmm_exact_output(
        &pool,
        &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(19_743)),
    )
    .unwrap();
    assert_eq!(quote.input.amount.get(), 9_999);
    assert_eq!(quote.output.amount.get(), 19_743);
    assert_eq!(quote.pool_fee.amount.get(), 29);
    assert_eq!(quote.effective_input.amount.get(), 9_970);
    assert_eq!(quote.resulting_reserve_0.get(), 1_009_999);
    assert_eq!(quote.resulting_reserve_1.get(), 1_980_257);
    assert_eq!(quote.output_overshoot().get(), 0);
    assert_quote_matches_oracle(&quote, &pool, &pool.token_0, 19_743);

    // Direction 1 -> 0.
    let quote = simulate_cpmm_exact_output(
        &pool,
        &CpmmExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(9_871)),
    )
    .unwrap();
    assert_eq!(quote.input.amount.get(), 19_998);
    assert_eq!(quote.output.amount.get(), 9_871);
    assert_eq!(quote.pool_fee.amount.get(), 59);
    assert_eq!(quote.effective_input.amount.get(), 19_939);
    assert_eq!(quote.resulting_reserve_0.get(), 990_129);
    assert_eq!(quote.resulting_reserve_1.get(), 2_019_998);
    assert_eq!(quote.output_overshoot().get(), 0);
    assert_quote_matches_oracle(&quote, &pool, &pool.token_1, 9_871);
}

#[test]
fn rounding_overshoot_is_real_and_bounded_by_minimality() {
    // A shallow pool: the one-unit input jumps output far above the request.
    let pool = sample_pool(1, 10, 0);
    let quote = CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(1))
        .simulate(&pool)
        .unwrap();
    assert_eq!(quote.input.amount.get(), 1);
    assert_eq!(quote.effective_input.amount.get(), 1);
    assert_eq!(quote.output.amount.get(), 5);
    assert_eq!(quote.output_overshoot().get(), 4);
    assert_quote_matches_oracle(&quote, &pool, &pool.token_0, 1);

    // With a fee the minimal gross input can still be one unit.
    let pool = sample_pool(1, 10, 30);
    let quote = CpmmSimulationKernel::simulate_exact_output(
        &pool,
        &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(1)),
    )
    .unwrap();
    assert_eq!(quote.input.amount.get(), 1);
    assert_eq!(quote.pool_fee.amount.get(), 0);
    assert_eq!(quote.output.amount.get(), 5);
    assert_quote_matches_oracle(&quote, &pool, &pool.token_0, 1);
}

#[test]
fn exhaustive_small_sweep_matches_independent_oracle() {
    let fees = [0u16, 1, 7, 30, 100, 999, 9_999];
    let mut cases = 0usize;
    for reserve_0 in 1u128..=8 {
        for reserve_1 in 1u128..=10 {
            for fee in fees {
                let pool = sample_pool(reserve_0, reserve_1, fee);
                for (token_in, r_out) in [
                    (&pool.token_0, pool.reserve_1.get()),
                    (&pool.token_1, pool.reserve_0.get()),
                ] {
                    for requested in 1..r_out {
                        assert_quote_matches_oracle(
                            &simulate_cpmm_exact_output(
                                &pool,
                                &CpmmExactOutputRequest::new(
                                    token_in.clone(),
                                    AtomicAmount::new(requested),
                                ),
                            )
                            .unwrap(),
                            &pool,
                            token_in,
                            requested,
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert!(cases > 3_000, "sweep shrank unexpectedly: {cases}");
}

#[test]
fn seeded_random_sweep_matches_independent_oracle() {
    let fees = [0u16, 1, 7, 30, 100, 300, 1_000, 5_000, 9_999];
    let mut rng = Rng(0x5EED_0F64_1234_ABCD);
    for _ in 0..20_000 {
        let reserve_0 = rng.below(200_000) + 2;
        let reserve_1 = rng.below(200_000) + 2;
        let fee = fees[rng.below(fees.len() as u128) as usize];
        let pool = sample_pool(reserve_0, reserve_1, fee);
        let token_0_in = rng.next_u64() & 1 == 0;
        let (token_in, r_out) = if token_0_in {
            (pool.token_0.clone(), pool.reserve_1.get())
        } else {
            (pool.token_1.clone(), pool.reserve_0.get())
        };
        let requested = rng.below(r_out - 1) + 1;
        let quote = simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(requested)),
        )
        .expect("valid exact-output");
        assert_quote_matches_oracle(&quote, &pool, &token_in, requested);
    }
}

#[test]
fn fail_closed_cases_are_typed() {
    let pool = sample_pool(1_000_000, 2_000_000, 30);

    // Zero requested output.
    assert_eq!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(0)),
        ),
        Err(SimulationError::ZeroOutputAmount)
    );

    // Requested output at or above the output reserve.
    assert_eq!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(2_000_000)),
        ),
        Err(SimulationError::ImpossibleOutput)
    );
    assert_eq!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(2_000_001)),
        ),
        Err(SimulationError::ImpossibleOutput)
    );

    // Token not in the pool.
    let outsider =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000001").unwrap();
    assert!(matches!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(outsider, AtomicAmount::new(1)),
        ),
        Err(SimulationError::AssetNotFoundInPool(_))
    ));

    // Caller-asserted output asset that does not match the direction.
    assert!(matches!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new_directed(
                pool.token_0.clone(),
                AtomicAmount::new(1),
                pool.token_0.clone(),
            ),
        ),
        Err(SimulationError::OutputAssetMismatch { .. })
    ));

    // Cross-chain input.
    let other_chain = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    assert_eq!(
        simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(other_chain, AtomicAmount::new(1)),
        ),
        Err(SimulationError::ChainMismatch)
    );

    // Fee at the locked maximum is rejected.
    let full_fee = sample_pool(1_000_000, 2_000_000, 10_000);
    assert_eq!(
        simulate_cpmm_exact_output(
            &full_fee,
            &CpmmExactOutputRequest::new(full_fee.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(SimulationError::InvalidFeeBps(10_000))
    );

    // Zero reserve is rejected (the pool type itself does not validate reserves).
    let zero_reserve = sample_pool(0, 2_000_000, 30);
    assert_eq!(
        simulate_cpmm_exact_output(
            &zero_reserve,
            &CpmmExactOutputRequest::new(zero_reserve.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(SimulationError::ZeroReserve)
    );
}

#[test]
fn extreme_values_fail_closed_without_panic() {
    // Requesting nearly the whole (u128::MAX) reserve needs an input whose
    // numerator overflows the representable quotient: fail closed, never panic.
    let pool = sample_pool(u128::MAX, u128::MAX, 30);
    let result = simulate_cpmm_exact_output(
        &pool,
        &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(u128::MAX - 1)),
    );
    assert!(result.is_err());

    // Zero-fee deep pool still resolves a tiny request exactly and bounded.
    // (The reserve is kept below u128::MAX so the exact-input kernel's
    // `reserve_in + effective_input` cannot overflow.)
    let big = u128::MAX / 2;
    let pool = sample_pool(big, big, 0);
    let quote = simulate_cpmm_exact_output(
        &pool,
        &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(1)),
    )
    .unwrap();
    assert_eq!(quote.input.amount.get(), 2);
    assert_eq!(quote.output.amount.get(), 1);
}

#[test]
fn input_pool_state_is_never_mutated() {
    let pool = sample_pool(123_456, 654_321, 30);
    let before = pool.clone();
    for requested in [1u128, 10, 1_000, 100_000, 500_000] {
        let _ = simulate_cpmm_exact_output(
            &pool,
            &CpmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(requested)),
        );
    }
    assert_eq!(pool, before);
}
