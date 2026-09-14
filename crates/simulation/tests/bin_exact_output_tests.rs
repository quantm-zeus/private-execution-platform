//! Focused tests for the Bin/DLMM exact-output kernel.
//!
//! The harness re-derives coverage and minimality from the landed exact-input
//! kernel only (never from the new inversion code), so the sweep is not circular.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, BinPoolState, Bps, LiquidityBin};
use simulation::{
    simulate_bin_exact_input, simulate_bin_exact_output, BinExactInputRequest, BinExactOutputQuote,
    BinExactOutputRequest, BinSimulationError,
};

fn base_assets() -> (AssetId, AssetId) {
    let token_0 =
        AssetId::new(ChainId::Base, "0x00000000000000000000000000000000000000a0").unwrap();
    let token_1 =
        AssetId::new(ChainId::Base, "0x00000000000000000000000000000000000000b0").unwrap();
    (token_0, token_1)
}

fn bin_pool(bins: &[(i32, u128, u128)], active: i32, step: u16, fee_bps: u16) -> BinPoolState {
    let (token_0, token_1) = base_assets();
    BinPoolState {
        token_0,
        token_1,
        decimals_0: 0,
        decimals_1: 0,
        active_bin_id: active,
        bin_step: step,
        fee_bps: Bps::new(fee_bps).unwrap(),
        bins: bins
            .iter()
            .map(|(id, reserve_0, reserve_1)| {
                LiquidityBin::new(
                    *id,
                    AtomicAmount::new(*reserve_0),
                    AtomicAmount::new(*reserve_1),
                )
            })
            .collect(),
    }
}

/// Active bin `0` in the middle of a five-bin pool.
///
/// Downward (token 0 in) the reachable output is `100 + 200 + 300 = 600`; upward
/// (token 1 in) it is `500 + 400 + 300 = 1200`.
fn main_bin_pool(fee_bps: u16) -> BinPoolState {
    bin_pool(
        &[
            (-2, 0, 300),
            (-1, 0, 200),
            (0, 500, 100),
            (1, 400, 0),
            (2, 300, 0),
        ],
        0,
        100,
        fee_bps,
    )
}

const DOWN_REACHABLE: u128 = 600;
const UP_REACHABLE: u128 = 1200;

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
    pool: &BinPoolState,
    token_in: &AssetId,
    amount_in: u128,
) -> Result<u128, BinSimulationError> {
    simulate_bin_exact_input(
        pool,
        &BinExactInputRequest::new(token_in.clone(), AtomicAmount::new(amount_in)),
    )
    .map(|quote| quote.output.amount.get())
}

fn is_low(err: &BinSimulationError) -> bool {
    matches!(
        err,
        BinSimulationError::ZeroOutputAmount
            | BinSimulationError::ZeroEffectiveInput
            | BinSimulationError::InvariantViolated
    )
}

/// Independent coverage + minimality + decomposition check for one quote.
fn assert_quote_is_exact(
    quote: &BinExactOutputQuote,
    pool: &BinPoolState,
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
    assert!(amount_in >= 1, "minimal input must be positive");
    let fee = amount_in * u128::from(fee_bps) / 10_000;
    assert_eq!(quote.fee.amount.get(), fee, "fee is the exact floor");
    assert_eq!(
        quote.effective_input.amount.get(),
        amount_in - fee,
        "effective input is gross minus fee"
    );

    // The realized quote is the authoritative exact-input quote at `input`.
    let realized = simulate_bin_exact_input(
        pool,
        &BinExactInputRequest::new(token_in.clone(), AtomicAmount::new(amount_in)),
    )
    .expect("required input must simulate");
    assert_eq!(realized.output.amount.get(), quote.output.amount.get());
    assert_eq!(realized.fee.amount.get(), quote.fee.amount.get());
    assert_eq!(
        realized.effective_input.amount.get(),
        quote.effective_input.amount.get()
    );
    assert_eq!(
        realized.resulting_active_bin_id,
        quote.resulting_active_bin_id
    );
    assert_eq!(realized.bins_crossed, quote.bins_crossed);

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

#[test]
fn exhaustive_target_sweep_covers_both_directions() {
    let mut cases = 0usize;
    for fee_bps in [0u16, 1, 30, 300, 9_999] {
        let pool = main_bin_pool(fee_bps);
        for (token_in, reachable) in [
            (pool.token_0.clone(), DOWN_REACHABLE),
            (pool.token_1.clone(), UP_REACHABLE),
        ] {
            for target in 1..=reachable {
                let quote = simulate_bin_exact_output(
                    &pool,
                    &BinExactOutputRequest::new(token_in.clone(), AtomicAmount::new(target)),
                )
                .expect("reachable target must resolve");
                assert_quote_is_exact(&quote, &pool, &token_in, target);
                cases += 1;
            }
        }
    }
    assert!(cases > 5_000, "sweep shrank unexpectedly: {cases}");
}

#[test]
fn seeded_random_sweep_matches_independent_oracle() {
    let (token_0, token_1) = base_assets();
    let mut rng = Lcg::new(0xB10F_5EED);
    let mut ok_cases = 0u32;
    for _ in 0..20_000 {
        let step = u16::try_from(rng.range(1, 1_001)).unwrap();
        let fee = u16::try_from(rng.range(0, 10_000)).unwrap();
        let pool = bin_pool(
            &[
                (-2, 0, rng.range(1, 500)),
                (-1, 0, rng.range(1, 500)),
                (0, rng.range(1, 500), rng.range(0, 500)),
                (1, rng.range(1, 500), 0),
                (2, rng.range(1, 500), 0),
            ],
            0,
            step,
            fee,
        );
        let token_in = if rng.next_u64() & 1 == 0 {
            token_0.clone()
        } else {
            token_1.clone()
        };
        let probe = rng.range(1, 2_000);
        if let Ok(out) = exact_input(&pool, &token_in, probe) {
            if out == 0 {
                continue;
            }
            let quote = simulate_bin_exact_output(
                &pool,
                &BinExactOutputRequest::new(token_in.clone(), AtomicAmount::new(out)),
            )
            .expect("a probed output is reachable");
            assert_quote_is_exact(&quote, &pool, &token_in, out);
            ok_cases += 1;
        }
    }
    assert!(ok_cases > 2_000, "too few executable cases: {ok_cases}");
}

#[test]
fn both_directions_and_caller_asserted_token_out() {
    let pool = main_bin_pool(30);
    let target = 25u128;

    // token 0 in -> token 1 out, correct assertion.
    let quote = BinExactOutputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(target),
        pool.token_1.clone(),
    )
    .simulate(&pool)
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_0, target);
    assert_eq!(quote.output.asset, pool.token_1);

    // token 1 in -> token 0 out, correct assertion.
    let quote = BinExactOutputRequest::new_directed(
        pool.token_1.clone(),
        AtomicAmount::new(target),
        pool.token_0.clone(),
    )
    .simulate(&pool)
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_1, target);
    assert_eq!(quote.output.asset, pool.token_0);

    // Wrong asserted output asset.
    let outsider =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000009").unwrap();
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new_directed(
                pool.token_0.clone(),
                AtomicAmount::new(target),
                outsider,
            ),
        ),
        Err(BinSimulationError::OutputAssetMismatch)
    );

    // Asserting the input asset as output is an invalid direction.
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new_directed(
                pool.token_0.clone(),
                AtomicAmount::new(target),
                pool.token_0.clone(),
            ),
        ),
        Err(BinSimulationError::InvalidAssetDirection)
    );
}

#[test]
fn crossing_boundary_is_minimal_and_unreachable_is_typed() {
    let pool = main_bin_pool(30);

    // Downward: 150 exceeds the active bin's 100 output and forces one cross.
    let quote = simulate_bin_exact_output(
        &pool,
        &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(150)),
    )
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_0, 150);
    assert_eq!(quote.resulting_active_bin_id, -1);
    assert!(quote.bins_crossed >= 1);

    // Downward maximum drains all three bins and crosses twice.
    let quote = simulate_bin_exact_output(
        &pool,
        &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(DOWN_REACHABLE)),
    )
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_0, DOWN_REACHABLE);
    assert_eq!(quote.resulting_active_bin_id, -2);
    assert_eq!(quote.bins_crossed, 2);

    // Upward maximum drains all three bins and crosses twice.
    let quote = simulate_bin_exact_output(
        &pool,
        &BinExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(UP_REACHABLE)),
    )
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_1, UP_REACHABLE);
    assert_eq!(quote.resulting_active_bin_id, 2);
    assert_eq!(quote.bins_crossed, 2);

    // Anything above the total reachable output is unreachable.
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(
                pool.token_0.clone(),
                AtomicAmount::new(DOWN_REACHABLE + 1)
            ),
        ),
        Err(BinSimulationError::OutputUnreachable)
    );
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(UP_REACHABLE + 1)),
        ),
        Err(BinSimulationError::OutputUnreachable)
    );
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(u128::MAX)),
        ),
        Err(BinSimulationError::OutputUnreachable)
    );
}

#[test]
fn output_unreachable_is_reachable_when_one_side_is_empty() {
    // Active bin is the lowest represented bin: no downward liquidity at all.
    let pool = bin_pool(&[(0, 500, 0), (1, 400, 0), (2, 300, 0)], 0, 100, 30);
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::OutputUnreachable)
    );
    // Upward still works.
    let quote = simulate_bin_exact_output(
        &pool,
        &BinExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(1)),
    )
    .unwrap();
    assert_quote_is_exact(&quote, &pool, &pool.token_1, 1);
}

#[test]
fn input_pool_state_is_never_mutated() {
    let pool = main_bin_pool(30);
    let before = pool.clone();
    for target in [1u128, 2, 25, 150, 600, 1_200, 10_000] {
        let _ = simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(target)),
        );
        let _ = simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_1.clone(), AtomicAmount::new(target)),
        );
    }
    assert_eq!(pool, before);
}

#[test]
fn fail_closed_cases_are_typed() {
    let pool = main_bin_pool(30);

    // Zero requested output.
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(0)),
        ),
        Err(BinSimulationError::ZeroOutputAmount)
    );

    // Asset not in the pool.
    let outsider =
        AssetId::new(ChainId::Base, "0x0000000000000000000000000000000000000001").unwrap();
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(outsider, AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::InvalidAssetDirection)
    );

    // Cross-chain input.
    let other_chain = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    assert_eq!(
        simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(other_chain, AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::ChainMismatch)
    );

    // Fee at or above the locked maximum.
    let full_fee = main_bin_pool(10_000);
    assert_eq!(
        simulate_bin_exact_output(
            &full_fee,
            &BinExactOutputRequest::new(full_fee.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::InvalidFee)
    );

    // The active bin must be represented.
    let mut missing_active = main_bin_pool(30);
    missing_active.active_bin_id = 5;
    assert_eq!(
        simulate_bin_exact_output(
            &missing_active,
            &BinExactOutputRequest::new(missing_active.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::InvalidRange)
    );

    // Self-pooled tokens fail pool validation.
    let mut same_tokens = main_bin_pool(30);
    same_tokens.token_1 = same_tokens.token_0.clone();
    assert_eq!(
        simulate_bin_exact_output(
            &same_tokens,
            &BinExactOutputRequest::new(same_tokens.token_0.clone(), AtomicAmount::new(1)),
        ),
        Err(BinSimulationError::InvalidPoolState)
    );
}

#[test]
fn panic_fuzz_100k_never_panics_and_ok_quotes_are_sound() {
    let (token_0, token_1) = base_assets();
    let mut rng = Lcg::new(0x00D1_5EA5_B171_2345);
    let mut ok_cases = 0u32;
    let mut unreachable_cases = 0u32;
    for _ in 0..100_000 {
        let step = u16::try_from(rng.range(1, 1_001)).unwrap();
        let fee = u16::try_from(rng.range(0, 10_000)).unwrap();
        let pool = bin_pool(
            &[
                (-3, 0, rng.range(1, 2_000)),
                (-2, 0, rng.range(1, 2_000)),
                (-1, 0, rng.range(1, 2_000)),
                (0, rng.range(1, 2_000), rng.range(0, 2_000)),
                (1, rng.range(1, 2_000), 0),
                (2, rng.range(1, 2_000), 0),
                (3, rng.range(1, 2_000), 0),
            ],
            0,
            step,
            fee,
        );
        let token_in = if rng.next_u64() & 1 == 0 {
            token_0.clone()
        } else {
            token_1.clone()
        };
        // Most targets are small; every sixteenth is enormous to force the
        // unreachable path.
        let target = if rng.next_u64() % 16 == 0 {
            rng.range(1_000_000, u128::MAX / 2)
        } else {
            rng.range(1, 5_000)
        };
        match simulate_bin_exact_output(
            &pool,
            &BinExactOutputRequest::new(token_in.clone(), AtomicAmount::new(target)),
        ) {
            Ok(quote) => {
                ok_cases += 1;
                assert_quote_is_exact(&quote, &pool, &token_in, target);
            }
            Err(BinSimulationError::OutputUnreachable) => unreachable_cases += 1,
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
