//! Focused tests for the CLMM exact-output kernel.
//!
//! The harness re-derives coverage and minimality from the landed exact-input
//! kernel only (never from the new inversion code), so the sweep is not circular.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, ClmmPoolState, ClmmTick};
use simulation::clmm::sqrt_price_from_tick_index;
use simulation::{
    simulate_clmm_exact_input, simulate_clmm_exact_output, ClmmExactInputRequest,
    ClmmExactOutputQuote, ClmmExactOutputRequest, ClmmSimulationError,
};

fn sample_assets() -> (AssetId, AssetId) {
    let token_0 =
        AssetId::new(ChainId::Base, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
    let token_1 =
        AssetId::new(ChainId::Base, "0x4200000000000000000000000000000000000006").unwrap();
    (token_0, token_1)
}

/// A small multi-range pool whose total reachable output is cheap to scan,
/// spanning four initialized ranges in each direction around the active range.
fn toy_clmm_pool(liquidity: u128, fee_bps: u16) -> ClmmPoolState {
    let (token_0, token_1) = sample_assets();
    let ticks = [-256i32, -192, -128, -64, 0, 64, 128, 192, 256]
        .into_iter()
        .map(|index| ClmmTick::new(index, 10_000_000, 0))
        .collect();
    ClmmPoolState {
        token_0,
        token_1,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: sqrt_price_from_tick_index(32).unwrap(),
        liquidity,
        fee_bps: Bps::new(fee_bps).unwrap(),
        ticks,
    }
}

/// The library's single-range sample pool (also used by `clmm_tests.rs`).
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
        fee_bps: Bps::new(30).unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    }
}

/// Deterministic splitmix64 generator (no external dependency).
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: u128, hi: u128) -> u128 {
        if hi <= lo {
            return lo;
        }
        lo + (u128::from(self.next_u64()) % (hi - lo))
    }
}

fn exact_input(
    pool: &ClmmPoolState,
    token_in: &AssetId,
    amount_in: u128,
) -> Result<u128, ClmmSimulationError> {
    simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in: AtomicAmount::new(amount_in),
            token_out: None,
        },
    )
    .map(|quote| quote.output.amount.get())
}

fn is_low(err: &ClmmSimulationError) -> bool {
    matches!(
        err,
        ClmmSimulationError::ZeroOutputAmount
            | ClmmSimulationError::ZeroEffectiveInput
            | ClmmSimulationError::InvariantViolated
    )
}

/// Independent coverage + minimality + decomposition check for one quote.
fn assert_quote_is_exact(
    quote: &ClmmExactOutputQuote,
    pool: &ClmmPoolState,
    token_in: &AssetId,
    requested: u128,
) {
    let fee_bps = pool.fee_bps.get();
    let expected_out = if token_in == &pool.token_0 {
        pool.token_1.clone()
    } else {
        pool.token_0.clone()
    };

    assert_eq!(quote.input.asset, *token_in);
    assert_eq!(quote.output.asset, expected_out);
    assert_eq!(quote.requested_output.asset, expected_out);
    assert_eq!(quote.requested_output.amount.get(), requested);
    assert_eq!(quote.fee_bps, pool.fee_bps);

    let amount_in = quote.input.amount.get();
    // `f(0)` must never be requested: the minimal gross input is always >= 1.
    assert!(amount_in >= 1, "minimal input must be positive");
    let fee = amount_in * u128::from(fee_bps) / 10_000;
    assert_eq!(quote.fee.amount.get(), fee, "fee is the exact floor");
    assert_eq!(
        quote.effective_input.amount.get(),
        amount_in - fee,
        "effective input is gross minus fee"
    );

    // The realized quote is the authoritative exact-input quote at `input`.
    let realized = exact_input(pool, token_in, amount_in).expect("required input must simulate");
    assert_eq!(realized, quote.output.amount.get(), "output reproduces");
    let realized_quote = simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in: AtomicAmount::new(amount_in),
            token_out: None,
        },
    )
    .unwrap();
    assert_eq!(
        realized_quote.resulting_sqrt_price_x64,
        quote.resulting_sqrt_price_x64
    );
    assert_eq!(realized_quote.resulting_tick, quote.resulting_tick);
    assert_eq!(
        realized_quote.resulting_liquidity,
        quote.resulting_liquidity
    );

    // Coverage.
    assert!(
        quote.output.amount.get() >= requested,
        "output {} does not cover request {requested}",
        quote.output.amount.get()
    );
    assert_eq!(
        quote.output_overshoot().get(),
        quote.output.amount.get() - requested
    );

    // Minimality: one unit less is either a low-end failure or below target.
    if amount_in > 1 {
        match exact_input(pool, token_in, amount_in - 1) {
            Ok(previous) => assert!(
                previous < requested,
                "one unit less already covers the request"
            ),
            Err(err) => assert!(is_low(&err), "unexpected error at input-1: {err:?}"),
        }
    }
}

/// Scan the exact-input reachable region (the independent oracle).
struct Reachability {
    max_output: u128,
    max_input: u128,
    first_cross_input: u128,
    first_range_max: u128,
    saw_high: bool,
}

/// Locates the active initialized range `[lower, upper)` containing `current_tick`.
fn active_range(pool: &ClmmPoolState) -> (i32, i32) {
    for i in 0..(pool.ticks.len() - 1) {
        if pool.ticks[i].index <= pool.current_tick && pool.current_tick < pool.ticks[i + 1].index {
            return (pool.ticks[i].index, pool.ticks[i + 1].index);
        }
    }
    panic!("active range not found");
}

fn scan_reachability(
    pool: &ClmmPoolState,
    token_in: &AssetId,
    is_token_0_in: bool,
    bound: u128,
) -> Reachability {
    let (lower, upper) = active_range(pool);
    let mut max_output = 0u128;
    let mut max_input = 0u128;
    let mut first_cross_input = 0u128;
    let mut first_range_max = 0u128;
    let mut saw_high = false;
    for g in 1..=bound {
        match simulate_clmm_exact_input(
            pool,
            &ClmmExactInputRequest {
                token_in: token_in.clone(),
                amount_in: AtomicAmount::new(g),
                token_out: None,
            },
        ) {
            Ok(quote) => {
                let out = quote.output.amount.get();
                if out > max_output {
                    max_output = out;
                    max_input = g;
                }
                // A tick boundary is crossed once the resulting tick leaves the
                // active range (independent of net-liquidity changes).
                let crossed = if is_token_0_in {
                    quote.resulting_tick < lower
                } else {
                    quote.resulting_tick >= upper
                };
                if first_cross_input == 0 && crossed {
                    first_cross_input = g;
                }
                if !crossed {
                    first_range_max = first_range_max.max(out);
                }
            }
            Err(ClmmSimulationError::TickCrossingExceeded)
            | Err(ClmmSimulationError::ArithmeticOverflow) => {
                saw_high = true;
            }
            Err(_) => {}
        }
    }
    Reachability {
        max_output,
        max_input,
        first_cross_input,
        first_range_max,
        saw_high,
    }
}

#[test]
fn exhaustive_target_sweep_covers_both_directions() {
    let mut cases = 0usize;
    for fee_bps in [0u16, 1, 30, 300, 9_999] {
        let pool = toy_clmm_pool(10_000, fee_bps);
        for (token_in, is_token_0_in) in
            [(pool.token_0.clone(), true), (pool.token_1.clone(), false)]
        {
            let reach = scan_reachability(&pool, &token_in, is_token_0_in, 1_000);
            // Extremely high fees can floor the effective input to a single unit
            // across the whole scan window, so no output is observable cheaply.
            if reach.max_output == 0 {
                continue;
            }
            for target in 1..=reach.max_output {
                let quote = simulate_clmm_exact_output(
                    &pool,
                    &ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(target)),
                )
                .expect("reachable target must resolve");
                assert_quote_is_exact(&quote, &pool, &token_in, target);
                cases += 1;
            }
        }
    }
    assert!(cases > 300, "sweep shrank unexpectedly: {cases}");
}

#[test]
fn seeded_random_sweep_matches_independent_oracle() {
    let (token_0, token_1) = sample_assets();
    let mut rng = Lcg::new(0xC111_0F33);
    let mut ok_cases = 0u32;
    for _ in 0..10_000 {
        let liquidity = rng.range(5_000, 10_000_000);
        let fee = u16::try_from(rng.range(0, 10_000)).unwrap();
        let offset = rng.range(0, 480) as i32 - 240; // within [-256, 256)
        let current_tick = offset;
        let ticks = [-256i32, -192, -128, -64, 0, 64, 128, 192, 256]
            .into_iter()
            .map(|index| ClmmTick::new(index, 10_000_000, 0))
            .collect();
        let pool = ClmmPoolState {
            token_0: token_0.clone(),
            token_1: token_1.clone(),
            decimals_0: 9,
            decimals_1: 6,
            tick_spacing: 64,
            current_tick,
            sqrt_price_x64: sqrt_price_from_tick_index(current_tick).unwrap(),
            liquidity,
            fee_bps: Bps::new(fee).unwrap(),
            ticks,
        };
        let forward = rng.next_u64() & 1 == 0;
        let token_in = if forward {
            pool.token_0.clone()
        } else {
            pool.token_1.clone()
        };
        let probe = rng.range(1, 5_000);
        if let Ok(out) = exact_input(&pool, &token_in, probe) {
            if out == 0 {
                continue;
            }
            let quote = simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(out)),
            )
            .expect("a probed output is reachable");
            assert_quote_is_exact(&quote, &pool, &token_in, out);
            ok_cases += 1;
        }
    }
    assert!(ok_cases > 1_000, "too few executable cases: {ok_cases}");
}

#[test]
fn both_directions_and_caller_asserted_token_out() {
    let pool = toy_clmm_pool(10_000, 30);
    let target = 3u128;

    // token 0 in -> token 1 out, correct assertion.
    let quote = ClmmExactOutputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(target),
        pool.token_1.clone(),
    )
    .simulate(&pool)
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_0, target);
    assert_eq!(quote.output.asset, pool.token_1);

    // token 1 in -> token 0 out, correct assertion.
    let quote = ClmmExactOutputRequest::new_directed(
        pool.token_1.clone(),
        AtomicAmount::new(target),
        pool.token_0.clone(),
    )
    .simulate(&pool)
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_1, target);
    assert_eq!(quote.output.asset, pool.token_0);

    // Wrong asserted output asset (same chain, but neither direction).
    let outsider =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000009").unwrap();
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new_directed(
                pool.token_0.clone(),
                AtomicAmount::new(target),
                outsider,
            ),
        ),
        Err(ClmmSimulationError::OutputAssetMismatch)
    );

    // Asserting the input asset as output is an invalid direction.
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new_directed(
                pool.token_0.clone(),
                AtomicAmount::new(target),
                pool.token_0.clone(),
            ),
        ),
        Err(ClmmSimulationError::InvalidAssetDirection)
    );
}

#[test]
fn crossing_boundary_is_minimal_and_unreachable_is_typed() {
    let pool = toy_clmm_pool(10_000, 30);
    let (lower, upper) = active_range(&pool);
    for (token_in, is_token_0_in) in [(pool.token_0.clone(), true), (pool.token_1.clone(), false)] {
        let reach = scan_reachability(&pool, &token_in, is_token_0_in, 1_000);
        assert!(reach.saw_high, "scan must reach the ceiling");
        assert!(reach.max_output > reach.first_range_max);
        assert!(reach.first_cross_input > 0);

        // The maximum reachable output forces at least one tick crossing.
        let quote = simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(reach.max_output)),
        )
        .unwrap();
        assert_quote_is_exact(&quote, &pool, &token_in, reach.max_output);
        let crossed = if is_token_0_in {
            quote.resulting_tick < lower
        } else {
            quote.resulting_tick >= upper
        };
        assert!(crossed, "max reachable output must cross a tick boundary");
        assert!(quote.input.amount.get() <= reach.max_input);

        // A target above the reachable ceiling is unreachable.
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(
                    token_in.clone(),
                    AtomicAmount::new(reach.max_output + 1),
                ),
            ),
            Err(ClmmSimulationError::OutputUnreachable)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(u128::MAX)),
            ),
            Err(ClmmSimulationError::OutputUnreachable)
        );
    }
}

#[test]
fn output_unreachable_reachable_on_real_sample_pool() {
    let pool = sample_clmm_pool();
    // The sample pool cannot produce u128::MAX units of either counter-asset.
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(u128::MAX)),
        ),
        Err(ClmmSimulationError::OutputUnreachable)
    );
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(u128::MAX)),
        ),
        Err(ClmmSimulationError::OutputUnreachable)
    );
}

#[test]
fn input_pool_state_is_never_mutated() {
    let pool = toy_clmm_pool(10_000, 30);
    let before = pool.clone();
    for target in [1u128, 2, 5, 25, 100] {
        let _ = simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(target)),
        );
        let _ = simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(target)),
        );
    }
    assert_eq!(pool, before);
}

#[test]
fn fail_closed_cases_are_typed() {
    let pool = toy_clmm_pool(10_000, 30);

    // Zero requested output.
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(0)),
        ),
        Err(ClmmSimulationError::ZeroOutputAmount)
    );

    // Asset not in the pool.
    let outsider =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000001").unwrap();
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(outsider, AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidAssetDirection)
    );

    // Cross-chain input.
    let other_chain = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    assert_eq!(
        simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(other_chain, AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::ChainMismatch)
    );

    // Fee at or above the locked maximum.
    let full_fee = toy_clmm_pool(10_000, 10_000);
    assert_eq!(
        simulate_clmm_exact_output(
            &full_fee,
            &ClmmExactOutputRequest::new(full_fee.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidFee)
    );

    // Malformed pools fail closed with typed errors.
    let mut zero_liquidity = toy_clmm_pool(10_000, 30);
    zero_liquidity.liquidity = 0;
    assert_eq!(
        simulate_clmm_exact_output(
            &zero_liquidity,
            &ClmmExactOutputRequest::new(zero_liquidity.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidLiquidity)
    );

    let mut zero_price = toy_clmm_pool(10_000, 30);
    zero_price.sqrt_price_x64 = 0;
    assert_eq!(
        simulate_clmm_exact_output(
            &zero_price,
            &ClmmExactOutputRequest::new(zero_price.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidPrice)
    );

    let mut bad_tick = toy_clmm_pool(10_000, 30);
    bad_tick.current_tick = 1_000_000;
    assert_eq!(
        simulate_clmm_exact_output(
            &bad_tick,
            &ClmmExactOutputRequest::new(bad_tick.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidTick)
    );

    // Self-pooled tokens fail pool validation.
    let mut same_tokens = toy_clmm_pool(10_000, 30);
    same_tokens.token_1 = same_tokens.token_0.clone();
    assert_eq!(
        simulate_clmm_exact_output(
            &same_tokens,
            &ClmmExactOutputRequest::new(same_tokens.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(ClmmSimulationError::InvalidPoolState)
    );
}

#[test]
fn panic_fuzz_100k_never_panics_and_ok_quotes_are_sound() {
    let (token_0, token_1) = sample_assets();
    let mut rng = Lcg::new(0x00D1_5EA5_E0FF_1234);
    let mut ok_cases = 0u32;
    let mut unreachable_cases = 0u32;
    for _ in 0..100_000 {
        let liquidity = rng.range(100_000, 2_000_000);
        let fee = u16::try_from(rng.range(0, 10_000)).unwrap();
        let offset = (rng.range(0, 500) as i32) - 250;
        let ticks = [-256i32, -192, -128, -64, 0, 64, 128, 192, 256]
            .into_iter()
            .map(|index| ClmmTick::new(index, 10_000_000, 0))
            .collect();
        let pool = ClmmPoolState {
            token_0: token_0.clone(),
            token_1: token_1.clone(),
            decimals_0: 9,
            decimals_1: 6,
            tick_spacing: 64,
            current_tick: offset,
            sqrt_price_x64: sqrt_price_from_tick_index(offset).unwrap(),
            liquidity,
            fee_bps: Bps::new(fee).unwrap(),
            ticks,
        };
        let token_in = if rng.next_u64() & 1 == 0 {
            pool.token_0.clone()
        } else {
            pool.token_1.clone()
        };
        // Most targets resolve in the first range and keep the sweep cheap; every
        // sixteenth target is enormous and exercises `OutputUnreachable`.
        let target = if rng.next_u64() % 16 == 0 {
            rng.range(1_000_000, u128::MAX / 2)
        } else {
            rng.range(1, 4_000)
        };
        match simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(target)),
        ) {
            Ok(quote) => {
                ok_cases += 1;
                assert_quote_is_exact(&quote, &pool, &token_in, target);
            }
            Err(ClmmSimulationError::OutputUnreachable) => unreachable_cases += 1,
            Err(other) => panic!("unexpected fuzz error: {other:?}"),
        }
    }
    assert!(
        ok_cases > 1_000,
        "too few executable fuzz cases: {ok_cases}"
    );
    assert!(
        unreachable_cases > 0,
        "fuzz must exercise the unreachable path"
    );
}

/// Regression for the P73 review CRITICAL: a *valid* CLMM pool can make the
/// exact-input kernel return `InvariantViolated` in the middle of an otherwise
/// `Ok` input range (a rounding artifact when a swap crosses into a
/// much-larger-liquidity range with a small residual). That hole breaks the
/// feasibility-interval lemma the minimal-input search relies on. The inversion
/// must fail closed rather than return a larger (non-minimal) input that still
/// covers the target.
#[test]
fn mid_interval_invariant_hole_fails_closed_instead_of_a_non_minimal_quote() {
    let (t0, t1) = sample_assets();
    for (l2_shift, fee) in [(70u32, 0u16), (70, 30), (75, 30), (80, 3000)] {
        let l1: u128 = 1_000_000;
        let l2: u128 = 1u128 << l2_shift;
        let pool = ClmmPoolState {
            token_0: t0.clone(),
            token_1: t1.clone(),
            decimals_0: 9,
            decimals_1: 6,
            tick_spacing: 2,
            current_tick: 1,
            sqrt_price_x64: sqrt_price_from_tick_index(1).unwrap(),
            liquidity: l1,
            fee_bps: Bps::new(fee).unwrap(),
            ticks: vec![
                ClmmTick::new(-2, 0, 0),
                ClmmTick::new(0, l2 - l1, l1 as i128 - l2 as i128),
                ClmmTick::new(2, 0, 0),
            ],
        };
        pool.validate().expect("valid pool");
        let before = pool.clone();

        // Independent scan: an Ok output below the hole, the hole, then an Ok
        // input above it. `out_before` is a target whose true minimal input sits
        // below the hole.
        let mut out_before: Option<u128> = None;
        let mut saw_hole = false;
        let mut saw_ok_after_hole = false;
        for g in 1..=200_000u128 {
            match exact_input(&pool, &t0, g) {
                Ok(out) => {
                    if saw_hole {
                        saw_ok_after_hole = true;
                        break;
                    }
                    out_before = Some(out);
                }
                Err(ClmmSimulationError::InvariantViolated) => saw_hole = true,
                Err(other) => panic!("unexpected error at g={g}: {other:?}"),
            }
        }
        assert!(
            saw_hole && saw_ok_after_hole,
            "fixture must contain a mid-interval hole followed by Ok (l2=2^{l2_shift}, fee={fee})"
        );
        let target = out_before.expect("an Ok output below the hole");

        let result = simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(t0.clone(), AtomicAmount::new(target)),
        );
        // Fail closed: never a non-minimal quote.
        assert_eq!(
            result,
            Err(ClmmSimulationError::InvariantViolated),
            "a mid-interval hole must fail closed (l2=2^{l2_shift}, fee={fee})"
        );
        assert_eq!(pool, before, "the pool must not be mutated");
    }
}
