//! P49 — deterministic property/fuzz sweeps for the AMM and bin kernels.
//!
//! These are randomized, seeded sweeps (no `proptest` dependency): a splitmix64
//! generator drives thousands of pool/amount combinations and asserts the exact
//! integer invariants the kernels must preserve. Every assertion is an
//! independent recomputation (exact floor fee, exact floor output, exact
//! reserves), not a restatement of a production postcondition.

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, BinPoolState, Bps, CpmmPoolState, LiquidityBin};
use simulation::{
    div_u256_by_u128_floor, mul_u128_wide, simulate_bin_exact_input, simulate_cpmm_swap,
    BinExactInputRequest, MAX_BIN_CROSSES,
};

/// Deterministic splitmix64 generator (well-mixed output bits).
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

fn base_assets() -> (AssetId, AssetId) {
    let token_0 =
        AssetId::new(ChainId::Base, "0x00000000000000000000000000000000000000a0").unwrap();
    let token_1 =
        AssetId::new(ChainId::Base, "0x00000000000000000000000000000000000000b0").unwrap();
    (token_0, token_1)
}

fn cpmm_pool(reserve_0: u128, reserve_1: u128, fee_bps: u16) -> CpmmPoolState {
    let (token_0, token_1) = base_assets();
    CpmmPoolState {
        token_0,
        token_1,
        decimals_0: 18,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(reserve_0),
        reserve_1: AtomicAmount::new(reserve_1),
        total_lp_supply: Some(AtomicAmount::new(1_000_000)),
        fee_bps: Bps::new(fee_bps).unwrap(),
    }
}

/// Exact CPMM output recomputed independently from the definition.
fn expected_cpmm_output(
    amount_in: u128,
    fee_bps: u16,
    reserve_in: u128,
    reserve_out: u128,
) -> u128 {
    let fee = amount_in * u128::from(fee_bps) / 10_000;
    let effective = amount_in - fee;
    let (hi, lo) = mul_u128_wide(effective, reserve_out);
    div_u256_by_u128_floor(hi, lo, reserve_in + effective).expect("bounded values")
}

#[test]
fn cpmm_exact_input_random_sweep_preserves_invariants() {
    let mut rng = Lcg::new(0xC0FF_EE00);
    let mut ok_cases = 0u32;
    for case in 0..20_000u32 {
        let reserve_0 = rng.range(1_000, 1_000_000_000);
        let reserve_1 = rng.range(1_000, 1_000_000_000);
        let fee_bps = u16::try_from(rng.range(0, 1_000)).unwrap();
        let pool = cpmm_pool(reserve_0, reserve_1, fee_bps);

        // Alternate directions so both kernel branches are exercised.
        let forward = rng.range(0, 2) == 0;
        let (token_in, reserve_in, reserve_out) = if forward {
            (&pool.token_0, reserve_0, reserve_1)
        } else {
            (&pool.token_1, reserve_1, reserve_0)
        };
        let amount_in = rng.range(1, reserve_in + 1);
        if let Ok(quote) = simulate_cpmm_swap(&pool, token_in, AtomicAmount::new(amount_in)) {
            ok_cases += 1;
            let expected_fee = amount_in * u128::from(fee_bps) / 10_000;
            let expected_out = expected_cpmm_output(amount_in, fee_bps, reserve_in, reserve_out);
            let case = format!("case {case} forward={forward}");
            assert_eq!(quote.input.amount.get(), amount_in, "{case}");
            assert_eq!(
                quote.pool_fee.amount.get(),
                expected_fee,
                "exact floor fee, {case}"
            );
            assert_eq!(
                quote.effective_input.amount.get() + quote.pool_fee.amount.get(),
                amount_in,
                "fee split, {case}"
            );
            assert_eq!(
                quote.output.amount.get(),
                expected_out,
                "exact output, {case}"
            );
            assert!(quote.output.amount.get() > 0, "{case}");
            assert!(quote.output.amount.get() < reserve_out, "{case}");
            assert_eq!(
                quote.resulting_reserve_in.get(),
                reserve_in + amount_in,
                "{case}"
            );
            assert_eq!(
                quote.resulting_reserve_out.get(),
                reserve_out - quote.output.amount.get(),
                "{case}"
            );
            if fee_bps > 0 && amount_in >= 10_000 {
                assert!(quote.pool_fee.amount.get() > 0, "fee charged, {case}");
            }
        }
    }
    assert!(
        ok_cases > 15_000,
        "sweep exercised too few successes: {ok_cases}"
    );
}

#[test]
fn cpmm_zero_and_zero_fee_edge_cases_are_typed() {
    let pool = cpmm_pool(1_000_000, 2_000_000, 30);
    assert!(simulate_cpmm_swap(&pool, &pool.token_0, AtomicAmount::new(0)).is_err());
    let zero_fee = cpmm_pool(1_000_000, 2_000_000, 0);
    let quote = simulate_cpmm_swap(&zero_fee, &zero_fee.token_0, AtomicAmount::new(1_000))
        .expect("zero-fee swap succeeds");
    assert_eq!(quote.pool_fee.amount.get(), 0);
    assert_eq!(quote.effective_input.amount.get(), 1_000);
}

#[test]
fn cpmm_sweep_is_deterministic_for_identical_inputs() {
    let mut first_rng = Lcg::new(0x5EED_1234);
    let mut second_rng = Lcg::new(0x5EED_1234);
    let mut differences = 0u32;
    for _ in 0..2_000 {
        let build = |rng: &mut Lcg| {
            cpmm_pool(
                rng.range(1_000, 1_000_000),
                rng.range(1_000, 1_000_000),
                u16::try_from(rng.range(0, 500)).unwrap(),
            )
        };
        let a = build(&mut first_rng);
        let b = build(&mut second_rng);
        assert_eq!(a, b, "same seed must yield the same inputs");
        let amount = 50_000;
        let first = simulate_cpmm_swap(&a, &a.token_0, AtomicAmount::new(amount));
        let second = simulate_cpmm_swap(&b, &b.token_0, AtomicAmount::new(amount));
        assert_eq!(first, second);
        if first != simulate_cpmm_swap(&a, &a.token_0, AtomicAmount::new(amount + 1)) {
            differences += 1;
        }
    }
    assert!(differences > 0, "sweep was degenerate");
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

/// A wide pool whose crossing bound can actually bind: 20 bins below and 20
/// above the active bin, each randomly funded on its valid side.
fn wide_bin_pool(rng: &mut Lcg, fee_bps: u16) -> BinPoolState {
    let mut bins = Vec::new();
    for id in -20i32..=20 {
        let (reserve_0, reserve_1) = if id < 0 {
            (0, rng.range(50, 500))
        } else if id > 0 {
            (rng.range(50, 500), 0)
        } else {
            (rng.range(50, 500), rng.range(50, 500))
        };
        bins.push((id, reserve_0, reserve_1));
    }
    bin_pool(&bins, 0, 100, fee_bps)
}

#[test]
fn bin_exact_input_random_sweep_never_panics_and_preserves_invariants() {
    let mut rng = Lcg::new(0xB1_1900);
    let mut ok_cases = 0u32;
    let mut max_crossed = 0usize;
    for case in 0..20_000u32 {
        let fee_bps = u16::try_from(rng.range(0, 1_000)).unwrap();
        let pool = wide_bin_pool(&mut rng, fee_bps);
        let forward = rng.range(0, 2) == 0;
        let token_in = if forward {
            pool.token_0.clone()
        } else {
            pool.token_1.clone()
        };
        let amount_in = rng.range(1, 5_000);
        let request = BinExactInputRequest::new(token_in, AtomicAmount::new(amount_in));
        if let Ok(quote) = simulate_bin_exact_input(&pool, &request) {
            ok_cases += 1;
            max_crossed = max_crossed.max(quote.bins_crossed);
            let expected_fee = amount_in * u128::from(fee_bps) / 10_000;
            let case = format!("case {case} forward={forward}");
            assert_eq!(quote.input.amount.get(), amount_in, "{case}");
            assert_eq!(
                quote.fee.amount.get(),
                expected_fee,
                "exact floor fee, {case}"
            );
            assert_eq!(
                quote.effective_input.amount.get() + quote.fee.amount.get(),
                amount_in,
                "fee split, {case}"
            );
            assert!(quote.output.amount.get() > 0, "{case}");
            assert!(
                quote.bins_crossed <= MAX_BIN_CROSSES,
                "bin traversal escaped its bound, {case}"
            );
        }
    }
    assert!(
        ok_cases > 5_000,
        "bin sweep produced too few executable cases: {ok_cases}"
    );
    // The crossing cap must genuinely be reachable by this pool shape: a sweep
    // that only ever crossed one bin would hide a `MAX_BIN_CROSSES = 1` defect.
    assert!(
        max_crossed >= 2,
        "bin sweep never crossed more than one bin: {max_crossed}"
    );
}

#[test]
fn bin_zero_amount_is_typed() {
    let (mut rng, fee_bps) = (Lcg::new(0x1234), 30u16);
    let pool = wide_bin_pool(&mut rng, fee_bps);
    let request = BinExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(0));
    assert!(simulate_bin_exact_input(&pool, &request).is_err());
}
