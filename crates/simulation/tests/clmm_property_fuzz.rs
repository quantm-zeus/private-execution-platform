//! P82 — seeded, deterministic property/fuzz suite for the CLMM exact-input and
//! exact-output kernels (`crates/simulation/src/clmm.rs`).
//!
//! Every assertion is an independent recomputation from the exact-input oracle,
//! the fee definition, or the pool's declared bounds — never a restatement of a
//! production postcondition. The suite is aimed squarely at the P73 CRITICAL:
//! a valid pool can make the exact-input kernel return `InvariantViolated` in
//! the middle of an otherwise-`Ok` input interval (a "hole"), which breaks the
//! monotonicity lemma a naive minimal-input search relies on. The hole fixture
//! plus a local replay of the search with the P73 `Hole`/`seen_ok` guard removed
//! make the non-vacuity of that property explicit.
//!
//! The generator is a copy of the seeded splitmix64 `Lcg` used by
//! `tests/property_fuzz.rs`; no `proptest` or other dependency is introduced.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps, ClmmPoolState, ClmmTick};
use simulation::clmm::{sqrt_price_from_tick_index, tick_index_from_sqrt_price};
use simulation::{
    div_u256_by_u128_ceil, div_u256_by_u128_floor, mul_u128_wide, simulate_clmm_exact_input,
    simulate_clmm_exact_output, ClmmExactInputRequest, ClmmExactOutputRequest, ClmmSimulationError,
};

// ---------------------------------------------------------------------------
// Deterministic splitmix64 generator (same construction as `property_fuzz.rs`).
// ---------------------------------------------------------------------------

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

    /// Uniform-ish value in `[lo, hi)`; `hi <= lo` returns `lo`.
    fn range(&mut self, lo: u128, hi: u128) -> u128 {
        if hi <= lo {
            return lo;
        }
        lo + (u128::from(self.next_u64()) % (hi - lo))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn base_assets() -> (AssetId, AssetId) {
    let token_0 = AssetId::new(ChainId::Base, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        .expect("fixture token_0 address is valid");
    let token_1 = AssetId::new(ChainId::Base, "0x4200000000000000000000000000000000000006")
        .expect("fixture token_1 address is valid");
    (token_0, token_1)
}

fn bps(value: u16) -> Bps {
    Bps::new(value).expect("fixture bps is within 0..=10_000")
}

fn sqrt_price(tick: i32) -> u128 {
    sqrt_price_from_tick_index(tick).expect("fixture tick is within MIN_TICK..=MAX_TICK")
}

/// A coherent, valid multi-range pool: the active range contains `current_tick`,
/// `sqrt_price_x64` is exactly the canonical price of `current_tick`, and the
/// tick grid is spaced and sorted so `ClmmPoolState::validate` accepts it.
fn random_valid_pool(rng: &mut Lcg) -> ClmmPoolState {
    let (token_0, token_1) = base_assets();
    let spacing = [1u32, 2, 4, 5, 8, 10, 16, 32, 64][rng.range(0, 9) as usize];
    let spacing_i32 = i32::try_from(spacing).expect("fixture spacing fits i32");
    let active = i32::try_from(rng.range(0, 9)).expect("small active index") - 4; // -4..=4

    let mut ticks = Vec::with_capacity(13);
    for offset in -6i32..=6 {
        let index = (active + offset) * spacing_i32;
        let gross = rng.range(0, 1_000_000_000);
        // Most boundaries carry no net so the generic sweep keeps a large Ok
        // region; a quarter carry a signed jump to exercise net-liquidity paths.
        let net = if rng.range(0, 4) == 0 {
            let magnitude = i128::try_from(rng.range(0, gross + 1)).expect("fixture net fits i128");
            if rng.next_u64() & 1 == 0 {
                magnitude
            } else {
                -magnitude
            }
        } else {
            0
        };
        ticks.push(ClmmTick::new(index, gross, net));
    }

    // Sit strictly inside a range where the spacing allows it, so both directions
    // have an interior region before any boundary crossing.
    let current_tick = active * spacing_i32 + spacing_i32 / 2;
    ClmmPoolState {
        token_0,
        token_1,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: spacing,
        current_tick,
        sqrt_price_x64: sqrt_price(current_tick),
        liquidity: rng.range(1_000_000_000, 1_000_000_000_000),
        fee_bps: bps(u16::try_from(rng.range(0, 10_000)).expect("fee below 10_000")),
        ticks,
    }
}

/// The P73 jump-pool construction: active range `[0, 2)` with small liquidity
/// `l1`, and tick `0` carrying `net = l1 - l2` so that crossing down jumps the
/// active liquidity to `l2 = 2^shift`, which is orders of magnitude larger. The
/// post-cross residual is then tiny relative to `l2`, and the exact-input kernel
/// rejects some of those residuals with `InvariantViolated` — a mid-interval hole
/// between `Ok` inputs. Note `liquidity_net != 0` at tick 0 (the jump), and the
/// pool passes `ClmmPoolState::validate` (`|net| == gross`).
fn fixed_hole_pool(l1: u128, shift: u32, fee_bps: u16) -> ClmmPoolState {
    let (token_0, token_1) = base_assets();
    let l2: u128 = 1u128 << shift;
    let net = i128::try_from(l1).expect("l1 fits i128") - i128::try_from(l2).expect("l2 fits i128");
    ClmmPoolState {
        token_0,
        token_1,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 2,
        current_tick: 1,
        sqrt_price_x64: sqrt_price(1),
        liquidity: l1,
        fee_bps: bps(fee_bps),
        ticks: vec![
            ClmmTick::new(-2, 0, 0),
            ClmmTick::new(0, l2 - l1, net),
            ClmmTick::new(2, 0, 0),
        ],
    }
}

fn hole_class_pool(rng: &mut Lcg) -> ClmmPoolState {
    let l1 = rng.range(100_000, 5_000_000);
    let shift = u32::try_from(rng.range(66, 78)).expect("shift fits u32");
    let fee_bps = u16::try_from(rng.range(0, 3_000)).expect("fee fits u16");
    fixed_hole_pool(l1, shift, fee_bps)
}

/// A single effective range `[0, 64)` with zero net liquidity: traversal either
/// stays inside the range or fails closed at the boundary.
fn single_range_pool(liquidity: u128, fee_bps: u16) -> ClmmPoolState {
    let (token_0, token_1) = base_assets();
    ClmmPoolState {
        token_0,
        token_1,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: sqrt_price(32),
        liquidity,
        fee_bps: bps(fee_bps),
        ticks: vec![ClmmTick::new(0, 0, 0), ClmmTick::new(64, 0, 0)],
    }
}

fn exact_input(
    pool: &ClmmPoolState,
    token_in: &AssetId,
    amount: u128,
) -> Result<u128, ClmmSimulationError> {
    simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in: AtomicAmount::new(amount),
            token_out: None,
        },
    )
    .map(|quote| quote.output.amount.get())
}

/// Uses the exact-input kernel alone to locate the single-range ceiling: the
/// smallest input that fails with a terminal high error, plus the largest `Ok`
/// output immediately below it. Returns `None` when the direction never produces
/// `Ok` output (a tiny range can floor every output to zero).
fn single_range_ceiling(pool: &ClmmPoolState, token_in: &AssetId) -> Option<(u128, u128)> {
    let is_high = |outcome: &Result<u128, ClmmSimulationError>| {
        matches!(
            outcome,
            Err(ClmmSimulationError::TickCrossingExceeded)
                | Err(ClmmSimulationError::ArithmeticOverflow)
        )
    };

    // Bracket a high error by doubling (exact-input is non-terminal below it).
    let mut hi = 1u128;
    while !is_high(&exact_input(pool, token_in, hi)) {
        if hi > u128::MAX / 2 {
            return None;
        }
        hi *= 2;
    }
    if is_high(&exact_input(pool, token_in, 1)) {
        return None;
    }

    // Smallest high-error input in `(1, hi]`.
    let mut lo = 1u128;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if is_high(&exact_input(pool, token_in, mid)) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let first_high = hi;

    // The largest Ok output sits immediately below the ceiling.
    let mut g = first_high - 1;
    let mut steps = 0u32;
    loop {
        if let Ok(out) = exact_input(pool, token_in, g) {
            return Some((out, first_high));
        }
        if g <= 1 || steps >= 10_000 {
            return None;
        }
        g -= 1;
        steps += 1;
    }
}

/// Errors a *coherent, valid* pool may legitimately produce. Anything else means
/// the generator produced an incoherent pool or the kernel regressed.
fn legit_error(error: &ClmmSimulationError) -> bool {
    matches!(
        error,
        ClmmSimulationError::OutputUnreachable
            | ClmmSimulationError::InvariantViolated
            | ClmmSimulationError::ZeroOutputAmount
            | ClmmSimulationError::ZeroEffectiveInput
            | ClmmSimulationError::TickCrossingExceeded
            | ClmmSimulationError::ArithmeticOverflow
            | ClmmSimulationError::InvalidLiquidity
    )
}

fn all_error_variants() -> Vec<ClmmSimulationError> {
    vec![
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
    ]
}

/// Sentinel style reused from `crates/routing/tests/negative_security_tests.rs`.
fn assert_no_payload(text: &str) {
    let mut run = 0usize;
    let mut longest = 0usize;
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(longest < 8, "hex-looking payload leaked: {text}");
    for sentinel in [
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "0x4200000000000000000000000000000000000006",
        "So11111111111111111111111111111111111111112",
        "123456789",
    ] {
        assert!(!text.contains(sentinel), "sentinel leaked: {text}");
    }
}

// ---------------------------------------------------------------------------
// Local replay of the production search with the P73 guard REMOVED.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeClass {
    Low,
    High,
    Hole,
    Unexpected,
}

fn clmm_probe_class(error: &ClmmSimulationError) -> ProbeClass {
    match error {
        ClmmSimulationError::ZeroOutputAmount | ClmmSimulationError::ZeroEffectiveInput => {
            ProbeClass::Low
        }
        ClmmSimulationError::InvariantViolated => ProbeClass::Hole,
        ClmmSimulationError::TickCrossingExceeded | ClmmSimulationError::ArithmeticOverflow => {
            ProbeClass::High
        }
        _ => ProbeClass::Unexpected,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchOutcome {
    Found(u128),
    Unreachable,
    Invariant,
}

/// Mirrors the production `find_min_gross_input`, but folds every `Hole` into
/// `Low` (i.e. removes the `Hole`/`seen_ok` guard). Used only to prove that the
/// guard is load-bearing; its output is never treated as a valid quote.
fn unguarded_find_min_gross_input<E>(
    target: u128,
    mut f: impl FnMut(u128) -> Result<u128, E>,
    classify: impl Fn(&E) -> ProbeClass,
) -> Result<SearchOutcome, E> {
    let mut prev: u128 = 0;
    let mut g: u128 = 1;
    let hi: u128 = loop {
        match f(g) {
            Ok(out) => {
                if out >= target {
                    break g;
                }
                prev = g;
            }
            Err(error) => match classify(&error) {
                ProbeClass::Low | ProbeClass::Hole => prev = g,
                ProbeClass::High => {
                    let mut lo = prev;
                    let mut high = g;
                    while high - lo > 1 {
                        let mid = lo + (high - lo) / 2;
                        match f(mid) {
                            Ok(_) => lo = mid,
                            Err(inner) => match classify(&inner) {
                                ProbeClass::High => high = mid,
                                ProbeClass::Low | ProbeClass::Hole => lo = mid,
                                ProbeClass::Unexpected => return Err(inner),
                            },
                        }
                    }
                    let g_max = high - 1;
                    if g_max == 0 {
                        return Ok(SearchOutcome::Unreachable);
                    }
                    match f(g_max) {
                        Ok(out) => {
                            if out >= target {
                                break g_max;
                            }
                            return Ok(SearchOutcome::Unreachable);
                        }
                        Err(inner) => match classify(&inner) {
                            ProbeClass::Unexpected => return Err(inner),
                            ProbeClass::Low | ProbeClass::High | ProbeClass::Hole => {
                                return Ok(SearchOutcome::Unreachable);
                            }
                        },
                    }
                }
                ProbeClass::Unexpected => return Err(error),
            },
        }
        if g == u128::MAX {
            return Ok(SearchOutcome::Unreachable);
        }
        if g > u128::MAX / 2 {
            g = u128::MAX;
        } else {
            g *= 2;
        }
    };

    let mut lo: u128 = 1;
    let mut bound: u128 = hi;
    while lo < bound {
        let mid = lo + (bound - lo) / 2;
        let covers = match f(mid) {
            Ok(out) => out >= target,
            Err(error) => match classify(&error) {
                ProbeClass::Low | ProbeClass::Hole => false,
                ProbeClass::High | ProbeClass::Unexpected => return Err(error),
            },
        };
        if covers {
            bound = mid;
        } else {
            lo = mid + 1;
        }
    }
    let g_star = lo;
    match f(g_star) {
        Ok(out) if out >= target => {}
        _ => return Ok(SearchOutcome::Invariant),
    }
    if g_star > 1 {
        match f(g_star - 1) {
            Ok(previous) => {
                if previous >= target {
                    return Ok(SearchOutcome::Invariant);
                }
            }
            Err(error) => match classify(&error) {
                ProbeClass::Low | ProbeClass::Hole => {}
                ProbeClass::High | ProbeClass::Unexpected => return Err(error),
            },
        }
    }
    Ok(SearchOutcome::Found(g_star))
}

// ---------------------------------------------------------------------------
// 1/2/3. Exact-input: typed failure only, non-zero Ok output, pool immutability,
//        and exact floor fee arithmetic over a large seeded sweep.
// ---------------------------------------------------------------------------

#[test]
fn exact_input_sweep_is_typed_sound_and_pure() {
    let mut rng = Lcg::new(0x0050_8200_0000_0001);
    let mut ok_cases = 0u32;
    let mut err_cases = 0u32;
    let mut floor_differs_from_ceil = 0u32;

    for case in 0..20_000u32 {
        let pool = random_valid_pool(&mut rng);
        pool.validate().expect("generated pool must validate");
        assert_eq!(
            tick_index_from_sqrt_price(pool.sqrt_price_x64),
            Ok(pool.current_tick),
            "case {case}: tick and sqrt price must be coherent"
        );
        let before = pool.clone();

        let token_in = if rng.next_u64() & 1 == 0 {
            pool.token_0.clone()
        } else {
            pool.token_1.clone()
        };
        // Mostly small in-range inputs so the Ok branch dominates; every sixteenth
        // input is huge to exercise the fail-closed boundary branches.
        let amount = if rng.next_u64() & 15 == 0 {
            rng.range(1_000_000_000, 1_000_000_000_000)
        } else {
            rng.range(1, 1_000_000)
        };
        let request = ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in: AtomicAmount::new(amount),
            token_out: None,
        };

        match simulate_clmm_exact_input(&pool, &request) {
            Ok(quote) => {
                ok_cases += 1;
                assert!(
                    quote.output.amount.get() > 0,
                    "case {case}: Ok quote must have a non-zero output"
                );
                assert_eq!(
                    quote.input.asset, token_in,
                    "case {case}: input asset binding"
                );
                assert_eq!(
                    quote.input.amount.get(),
                    amount,
                    "case {case}: input amount binding"
                );

                let fee_bps = u128::from(pool.fee_bps.get());
                let (hi, lo) = mul_u128_wide(amount, fee_bps);
                let expected_fee = div_u256_by_u128_floor(hi, lo, 10_000)
                    .expect("bounded fee division always fits u128");
                assert_eq!(
                    quote.fee.amount.get(),
                    expected_fee,
                    "case {case}: fee must be the exact floor"
                );
                assert_eq!(
                    quote.effective_input.amount.get(),
                    amount - expected_fee,
                    "case {case}: effective input is gross minus fee"
                );
                assert_eq!(
                    quote.fee.amount.get() + quote.effective_input.amount.get(),
                    amount,
                    "case {case}: fee split must reconstruct the input"
                );

                let ceil_fee = div_u256_by_u128_ceil(hi, lo, 10_000)
                    .expect("bounded fee division always fits u128");
                if ceil_fee != expected_fee {
                    floor_differs_from_ceil += 1;
                }
            }
            Err(error) => {
                err_cases += 1;
                assert!(
                    legit_error(&error),
                    "case {case}: unexpected typed error {error:?}"
                );
            }
        }

        assert_eq!(pool, before, "case {case}: pool must not be mutated");
    }

    assert!(ok_cases > 10_000, "too few Ok cases: {ok_cases}");
    assert!(err_cases > 0, "sweep never exercised an error path");
    assert!(
        floor_differs_from_ceil > 0,
        "sweep never exercised a case where floor != ceil"
    );
}

#[test]
fn fee_floor_is_pinned_against_ceil() {
    let pool = single_range_pool(10_000_000_000, 30);
    let amount = 100_003u128;
    let (hi, lo) = mul_u128_wide(amount, 30);
    let floor = div_u256_by_u128_floor(hi, lo, 10_000).expect("bounded fee division");
    let ceil = div_u256_by_u128_ceil(hi, lo, 10_000).expect("bounded fee division");

    // 100_003 * 30 / 10_000 = 300.009: the kernel must charge the floor, 300.
    assert_eq!(floor, 300);
    assert_eq!(ceil, 301);
    assert_ne!(floor, ceil);

    let quote = simulate_clmm_exact_input(
        &pool,
        &ClmmExactInputRequest {
            token_in: pool.token_0.clone(),
            amount_in: AtomicAmount::new(amount),
            token_out: None,
        },
    )
    .expect("in-range swap must succeed");
    assert_eq!(quote.fee.amount.get(), floor);
    assert_eq!(quote.effective_input.amount.get(), amount - floor);
}

// ---------------------------------------------------------------------------
// 4. Direction and chain binding fail closed with the exact typed variant.
// ---------------------------------------------------------------------------

#[test]
fn direction_and_chain_binding_fail_closed_with_exact_variants() {
    let mut rng = Lcg::new(0x0050_8200_0000_0004);
    let outsider = AssetId::new(ChainId::Base, "0x00000000000000000000000000000000000000f1")
        .expect("fixture outsider address is valid");
    let foreign_chain = AssetId::new(
        ChainId::Ethereum,
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    )
    .expect("fixture EVM address is valid");
    let foreign_out = AssetId::new(
        ChainId::Ethereum,
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    )
    .expect("fixture EVM address is valid");

    let mut invalid_input = 0u32;
    let mut wrong_output = 0u32;
    let mut chain_mismatch = 0u32;

    for _ in 0..512 {
        let pool = random_valid_pool(&mut rng);
        let before = pool.clone();
        let amount = AtomicAmount::new(10_000);

        // Input asset not in the pool (exact-input and exact-output).
        assert_eq!(
            simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: outsider.clone(),
                    amount_in: amount,
                    token_out: None,
                },
            ),
            Err(ClmmSimulationError::InvalidAssetDirection)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(outsider.clone(), AtomicAmount::new(5)),
            ),
            Err(ClmmSimulationError::InvalidAssetDirection)
        );
        invalid_input += 1;

        // Foreign-chain input asset.
        assert_eq!(
            simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: foreign_chain.clone(),
                    amount_in: amount,
                    token_out: None,
                },
            ),
            Err(ClmmSimulationError::ChainMismatch)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(foreign_chain.clone(), AtomicAmount::new(5)),
            ),
            Err(ClmmSimulationError::ChainMismatch)
        );
        chain_mismatch += 1;

        // Caller-asserted output that is not the counter-asset.
        assert_eq!(
            simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: pool.token_0.clone(),
                    amount_in: amount,
                    token_out: Some(outsider.clone()),
                },
            ),
            Err(ClmmSimulationError::OutputAssetMismatch)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new_directed(
                    pool.token_0.clone(),
                    AtomicAmount::new(5),
                    outsider.clone(),
                ),
            ),
            Err(ClmmSimulationError::OutputAssetMismatch)
        );
        wrong_output += 1;

        // Caller-asserted output equal to the input asset.
        assert_eq!(
            simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: pool.token_0.clone(),
                    amount_in: amount,
                    token_out: Some(pool.token_0.clone()),
                },
            ),
            Err(ClmmSimulationError::InvalidAssetDirection)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new_directed(
                    pool.token_0.clone(),
                    AtomicAmount::new(5),
                    pool.token_0.clone(),
                ),
            ),
            Err(ClmmSimulationError::InvalidAssetDirection)
        );

        // Foreign-chain caller-asserted output.
        assert_eq!(
            simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: pool.token_0.clone(),
                    amount_in: amount,
                    token_out: Some(foreign_out.clone()),
                },
            ),
            Err(ClmmSimulationError::ChainMismatch)
        );
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new_directed(
                    pool.token_0.clone(),
                    AtomicAmount::new(5),
                    foreign_out.clone(),
                ),
            ),
            Err(ClmmSimulationError::ChainMismatch)
        );

        assert_eq!(pool, before, "binding failures must not mutate the pool");
    }

    assert!(invalid_input > 0);
    assert!(wrong_output > 0);
    assert!(chain_mismatch > 0);
}

// ---------------------------------------------------------------------------
// 5. Single-range boundary fail-closed and output bounded by the full range.
// ---------------------------------------------------------------------------

#[test]
fn single_range_boundary_is_fail_closed_and_output_is_bounded() {
    let mut rng = Lcg::new(0x0050_8200_0000_0005);
    let mut ceiling_cases = 0u32;
    let mut bounded_ok = 0u32;

    for (liquidity, fee_bps) in [
        (1_000_000_000u128, 0u16),
        (10_000_000_000, 30),
        (100_000_000_000, 300),
        (1_000_000_000_000, 30),
    ] {
        let pool = single_range_pool(liquidity, fee_bps);
        pool.validate().expect("single-range fixture must validate");
        let before = pool.clone();

        for token_in in [pool.token_0.clone(), pool.token_1.clone()] {
            let ceiling = single_range_ceiling(&pool, &token_in);
            if let Some((capacity, first_high)) = ceiling {
                // An input beyond the located ceiling must fail closed rather than
                // fabricate an output.
                let huge = first_high.saturating_mul(2);
                assert!(
                    matches!(
                        exact_input(&pool, &token_in, huge),
                        Err(ClmmSimulationError::TickCrossingExceeded)
                            | Err(ClmmSimulationError::ZeroOutputAmount)
                            | Err(ClmmSimulationError::ArithmeticOverflow)
                    ),
                    "exhausted single range must fail closed"
                );
                ceiling_cases += 1;

                // Every in-range Ok output is bounded by the capacity the full
                // range produced at its independent ceiling.
                for _ in 0..64 {
                    let amount = rng.range(1, first_high);
                    if let Ok(out) = exact_input(&pool, &token_in, amount) {
                        assert!(
                            out <= capacity,
                            "output {out} exceeds the single-range capacity {capacity}"
                        );
                        bounded_ok += 1;
                    }
                }
            } else {
                // Degenerate direction: no observable output, but a huge input must
                // still fail closed instead of fabricating one.
                let huge = 1_000_000_000_000_000_000u128;
                assert!(
                    matches!(
                        exact_input(&pool, &token_in, huge),
                        Err(ClmmSimulationError::TickCrossingExceeded)
                            | Err(ClmmSimulationError::ZeroOutputAmount)
                            | Err(ClmmSimulationError::ArithmeticOverflow)
                    ),
                    "exhausted single range must fail closed"
                );
            }
        }

        assert_eq!(pool, before, "single-range sweep must not mutate the pool");
    }

    assert!(ceiling_cases >= 6, "too few ceiling cases: {ceiling_cases}");
    assert!(bounded_ok > 0, "no in-range Ok case was bounded");
}

// ---------------------------------------------------------------------------
// 6. Exact-output minimality over randomized pools, including jump-pool holes.
// ---------------------------------------------------------------------------

#[test]
fn exact_output_minimality_over_random_and_jump_pools() {
    let mut rng = Lcg::new(0x0050_8200_0000_0006);
    let mut ok_cases = 0u32;
    let mut err_cases = 0u32;
    let mut unreachable_cases = 0u32;
    let mut expected_unreachable_error_cases = 0u32;
    let mut invariant_hole_cases = 0u32;
    let mut input_minus_one_checks = 0u32;
    let mut input_minus_one_error_cases = 0u32;
    let mut input_minus_one_lower_cases = 0u32;
    let mut exhaustive_minimality_checks = 0u32;

    for case in 0..20_000u32 {
        let is_hole_class = case & 7 == 0;
        let pool = if is_hole_class {
            hole_class_pool(&mut rng)
        } else {
            random_valid_pool(&mut rng)
        };
        pool.validate().expect("generated pool must validate");
        let before = pool.clone();

        // Jump pools are biased toward the token-0 direction that provokes the
        // hole; generic pools alternate evenly.
        let token_in = if is_hole_class {
            if rng.range(0, 4) == 0 {
                pool.token_1.clone()
            } else {
                pool.token_0.clone()
            }
        } else if rng.next_u64() & 1 == 0 {
            pool.token_0.clone()
        } else {
            pool.token_1.clone()
        };

        // A generic target is derived from a small exact-input probe, so the
        // minimal input is small and the sweep stays cheap while still exercising
        // real minimality. Jump pools request an independent small target so the
        // search is forced through the mid-interval hole. Every 64th target is
        // astronomically above the total reachable output and must never yield
        // `Ok`.
        let (target, expect_unreachable) = if is_hole_class {
            (rng.range(1, 2_000), false)
        } else if rng.next_u64() & 63 == 0 {
            (rng.range(1u128 << 100, u128::MAX / 2), true)
        } else {
            let probe = rng.range(1, 12);
            let probe_target = match exact_input(&pool, &token_in, probe) {
                Ok(out) if out > 0 => out,
                _ => rng.range(1, 16),
            };
            (probe_target, false)
        };

        let request = ClmmExactOutputRequest::new(token_in.clone(), AtomicAmount::new(target));
        match simulate_clmm_exact_output(&pool, &request) {
            Ok(quote) => {
                assert!(
                    !expect_unreachable,
                    "case {case}: Ok returned for unreachable target {target}"
                );
                ok_cases += 1;
                assert_eq!(quote.input.asset, token_in, "case {case}: input asset");
                assert!(
                    quote.input.amount.get() >= 1,
                    "case {case}: minimal input must be positive"
                );
                assert_eq!(
                    quote.requested_output.amount.get(),
                    target,
                    "case {case}: requested output recorded"
                );
                assert!(
                    quote.output.amount.get() >= target,
                    "case {case}: an Ok quote must cover the requested target"
                );

                // The realized quote is exactly the authoritative exact-input
                // quote at the claimed input.
                let realized = exact_input(&pool, &token_in, quote.input.amount.get())
                    .expect("the Ok exact-output input must reproduce through exact-input");
                assert_eq!(
                    realized,
                    quote.output.amount.get(),
                    "case {case}: realized output mismatch"
                );

                if quote.input.amount.get() <= 64 && exhaustive_minimality_checks < 40 {
                    // Strong, assumption-free minimality: no smaller input covers
                    // the target anywhere in `[1, input - 1]`.
                    let mut smaller_covers = None;
                    for smaller in 1..quote.input.amount.get() {
                        if let Ok(out) = exact_input(&pool, &token_in, smaller) {
                            if out >= target {
                                smaller_covers = Some(smaller);
                                break;
                            }
                        }
                    }
                    assert!(
                        smaller_covers.is_none(),
                        "case {case}: smaller input {smaller_covers:?} already covers target {target}"
                    );
                    exhaustive_minimality_checks += 1;
                } else if quote.input.amount.get() > 1 {
                    input_minus_one_checks += 1;
                    match exact_input(&pool, &token_in, quote.input.amount.get() - 1) {
                        Ok(previous) => {
                            assert!(
                                previous < target,
                                "case {case}: input - 1 already covers the target"
                            );
                            input_minus_one_lower_cases += 1;
                        }
                        Err(error) => {
                            assert!(
                                legit_error(&error),
                                "case {case}: unexpected input - 1 error {error:?}"
                            );
                            input_minus_one_error_cases += 1;
                        }
                    }
                }
            }
            Err(error) => {
                err_cases += 1;
                assert!(
                    legit_error(&error),
                    "case {case}: unexpected typed error {error:?}"
                );
                if expect_unreachable {
                    expected_unreachable_error_cases += 1;
                }
                match error {
                    ClmmSimulationError::OutputUnreachable => unreachable_cases += 1,
                    ClmmSimulationError::InvariantViolated => invariant_hole_cases += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(pool, before, "case {case}: pool must not be mutated");
    }

    assert!(
        ok_cases > 5_000,
        "too few Ok exact-output cases: {ok_cases}"
    );
    assert!(err_cases > 0, "sweep never exercised an error path");
    assert!(
        unreachable_cases > 0,
        "sweep never exercised OutputUnreachable"
    );
    assert!(
        expected_unreachable_error_cases > 0,
        "sweep never exercised a known-unreachable target"
    );
    assert!(
        invariant_hole_cases > 0,
        "jump-pool mid-interval hole was never exercised"
    );
    assert!(
        exhaustive_minimality_checks >= 20,
        "too few exhaustive minimality proofs: {exhaustive_minimality_checks}"
    );
    assert!(
        input_minus_one_checks > 0,
        "input - 1 minimality branch was never exercised"
    );
    assert_eq!(
        input_minus_one_checks,
        input_minus_one_lower_cases + input_minus_one_error_cases,
        "input - 1 accounting must classify every probe"
    );
}

/// Regression/non-vacuity for the P73 hole. Each fixture is a *valid* pool whose
/// exact-input kernel returns `InvariantViolated` between two `Ok` inputs. The
/// landed exact-output kernel must fail closed. To prove the fixture is not
/// vacuous, the local `unguarded_find_min_gross_input` (the same search with the
/// `Hole`/`seen_ok` guard removed) is replayed: it returns a larger, non-minimal
/// input whose `input - 1` lands inside the hole, so a naive `input - 1`
/// minimality check would wrongly accept it. Since `src/` is untouched, this
/// local replay is the only honest way to demonstrate the guard is load-bearing.
#[test]
fn mid_interval_hole_fails_closed_and_unguarded_search_would_overpay() {
    let (token_0, _token_1) = base_assets();
    // These three valid jump pools reproduce the P73 mid-interval hole; they come
    // from the landed regression test and are re-verified by the independent scan
    // below. Randomized jump pools are exercised separately by the large
    // property-6 sweep.
    let configs: [(u128, u32, u16); 3] =
        [(1_000_000, 70, 0), (1_000_000, 70, 30), (1_000_000, 75, 30)];

    let mut holes_seen = 0u32;
    let mut guard_fail_closed = 0u32;
    let mut guard_free_overpay_proved = 0u32;

    for (l1, shift, fee_bps) in configs {
        let pool = fixed_hole_pool(l1, shift, fee_bps);
        pool.validate().expect("hole fixture must be a valid pool");
        let before = pool.clone();

        // Independently scan for the first mid-interval hole and the Ok output
        // immediately below it.
        let mut out_before = 0u128;
        let mut hole_start = 0u128;
        let mut saw_ok_after_hole = false;
        for g in 1..=30_000u128 {
            match exact_input(&pool, &token_0, g) {
                Ok(out) => {
                    if hole_start != 0 {
                        saw_ok_after_hole = true;
                        break;
                    }
                    out_before = out;
                }
                Err(ClmmSimulationError::InvariantViolated) => {
                    if hole_start == 0 {
                        hole_start = g;
                    }
                }
                Err(_) => {}
            }
        }
        assert!(
            hole_start != 0 && out_before != 0 && saw_ok_after_hole,
            "fixture must contain a hole between Ok inputs (l1={l1}, shift={shift}, fee={fee_bps})"
        );
        holes_seen += 1;
        let target = out_before;

        // The landed kernel must fail closed rather than pay a non-minimal input.
        assert_eq!(
            simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(token_0.clone(), AtomicAmount::new(target)),
            ),
            Err(ClmmSimulationError::InvariantViolated),
            "mid-interval hole must fail closed (l1={l1}, shift={shift}, fee={fee_bps})"
        );
        guard_fail_closed += 1;

        // Independent true minimum below the hole.
        let mut true_min = 0u128;
        for g in 1..hole_start {
            if let Ok(out) = exact_input(&pool, &token_0, g) {
                if out >= target {
                    true_min = g;
                    break;
                }
            }
        }
        assert!(true_min > 0, "target must be reachable below the hole");

        // Guard-free replay: a larger input is accepted only because `input - 1`
        // falls inside the hole.
        if let Ok(SearchOutcome::Found(g)) = unguarded_find_min_gross_input(
            target,
            |probe| exact_input(&pool, &token_0, probe),
            clmm_probe_class,
        ) {
            assert!(
                g > true_min,
                "guard-free search should skip the smaller covering input {true_min} and return {g}"
            );
            assert!(
                matches!(
                    exact_input(&pool, &token_0, g - 1),
                    Err(ClmmSimulationError::InvariantViolated)
                ),
                "guard-free search is accepted only because input - 1 lands in the hole"
            );
            guard_free_overpay_proved += 1;
        }

        assert_eq!(pool, before, "hole scan must not mutate the pool");
    }

    assert!(
        holes_seen >= 2,
        "fixture series must contain mid-interval holes: {holes_seen}"
    );
    assert_eq!(
        guard_fail_closed, holes_seen,
        "every hole fixture must fail closed"
    );
    assert!(
        guard_free_overpay_proved >= 1,
        "guard-free replay must overpay at least once"
    );
}

// ---------------------------------------------------------------------------
// 7. Determinism: identical seeds reproduce identical outcomes.
// ---------------------------------------------------------------------------

#[test]
fn sweeps_are_deterministic_for_identical_seeds() {
    fn run(seed: u64) -> Vec<String> {
        let mut rng = Lcg::new(seed);
        let mut out = Vec::with_capacity(300);
        for _ in 0..300 {
            let pool = random_valid_pool(&mut rng);
            let token_in = if rng.next_u64() & 1 == 0 {
                pool.token_0.clone()
            } else {
                pool.token_1.clone()
            };
            let amount = rng.range(1, 1_000_000);
            let input = simulate_clmm_exact_input(
                &pool,
                &ClmmExactInputRequest {
                    token_in: token_in.clone(),
                    amount_in: AtomicAmount::new(amount),
                    token_out: None,
                },
            );
            let target = rng.range(1, 64);
            let output = simulate_clmm_exact_output(
                &pool,
                &ClmmExactOutputRequest::new(token_in, AtomicAmount::new(target)),
            );
            out.push(format!("{input:?}|{output:?}"));
        }
        out
    }

    assert_eq!(run(0x0050_8200_0000_0070), run(0x0050_8200_0000_0070));
    assert_ne!(run(0x0050_8200_0000_0070), run(0x0050_8200_0000_0071));
}

// ---------------------------------------------------------------------------
// 8. Redaction: every error variant's Display and Debug carries no payload.
// ---------------------------------------------------------------------------

#[test]
fn error_debug_and_display_are_redacted() {
    for error in all_error_variants() {
        assert_no_payload(&format!("{error}"));
        assert_no_payload(&format!("{error:?}"));
    }

    let mut rng = Lcg::new(0x0050_8200_0000_0080);
    let mut produced = 0u32;
    for _ in 0..200 {
        let pool = hole_class_pool(&mut rng);
        let target = rng.range(1, 2_000);
        if let Err(error) = simulate_clmm_exact_output(
            &pool,
            &ClmmExactOutputRequest::new(pool.token_0.clone(), AtomicAmount::new(target)),
        ) {
            assert_no_payload(&format!("{error:?}"));
            assert_no_payload(&format!("{error}"));
            produced += 1;
        }
    }
    assert!(produced > 0, "redaction sweep produced no errors");
}
