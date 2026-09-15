//! P86 depth-aware CLMM/Bin ranking tests.
//!
//! Every depth value is checked against the landed exact-input kernels and an
//! independent `f64` impact oracle. No clock, RPC, or randomness is used.

mod common;

use common::*;
use market_types::{
    AtomicAmount, BinPoolState, Bps, ClmmPoolState, ClmmTick, LiquidityBin, PoolKindState,
};
use routing::{depth_at_bps, depth_rank, plan_single_path, RoutingError, DEPTH_TARGETS_BPS};
use simulation::{simulate_clmm_exact_input, ClmmExactInputRequest};

fn bps(value: u16) -> Bps {
    Bps::new(value).expect("valid bps")
}

fn targets(values: &[u16]) -> Vec<Bps> {
    values.iter().map(|value| bps(*value)).collect()
}

fn default_targets() -> Vec<Bps> {
    targets(&DEPTH_TARGETS_BPS)
}

/// Single-range CLMM state shared with the landed simulation fixture geometry.
fn clmm_with_ticks(fee_bps: u16, ticks: Vec<ClmmTick>) -> ClmmPoolState {
    ClmmPoolState {
        token_0: weth(),
        token_1: usdc(),
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 32,
        sqrt_price_x64: 18_476_281_010_653_910_144,
        liquidity: 10_000_000_000,
        fee_bps: bps(fee_bps),
        ticks,
    }
}

/// Narrow range `[0, 64)`: only ~32 bps of downward room.
fn narrow_pool(fee_bps: u16) -> ClmmPoolState {
    clmm_with_ticks(
        fee_bps,
        vec![
            ClmmTick::new(0, 20_000_000, 5_000_000),
            ClmmTick::new(64, 25_000_000, -7_000_000),
        ],
    )
}

/// Wide range `[-128, 128)`: ~160 bps of downward room.
fn wide_pool(fee_bps: u16) -> ClmmPoolState {
    clmm_with_ticks(
        fee_bps,
        vec![
            ClmmTick::new(-128, 10_000_000, 10_000_000),
            ClmmTick::new(128, 15_000_000, -8_000_000),
        ],
    )
}

/// Independent float oracle of the CLMM price move in basis points.
fn clmm_impact_f64(pool_sqrt: u128, resulting_sqrt: u128) -> f64 {
    let before = pool_sqrt as f64;
    let after = resulting_sqrt as f64;
    ((after * after - before * before) / (before * before)).abs() * 10_000.0
}

fn clmm_resulting_sqrt(
    pool: &ClmmPoolState,
    token_in: &chain_types::AssetId,
    amount: u128,
) -> Option<u128> {
    simulate_clmm_exact_input(
        pool,
        &ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in: AtomicAmount::new(amount),
            token_out: None,
        },
    )
    .ok()
    .map(|quote| quote.resulting_sqrt_price_x64)
}

#[test]
fn clmm_depth_boundary_is_exact_and_monotone() {
    let pool = narrow_pool(30);
    let state = PoolKindState::Clmm(pool.clone());
    let targets = default_targets();
    let profile = depth_at_bps(&state, &weth(), AtomicAmount::new(1_000_000), &targets)
        .expect("depth profile");

    assert_eq!(profile.levels.len(), targets.len());
    let mut previous = 0u128;
    for level in &profile.levels {
        if let Some(absorbed) = level.absorbed_in {
            assert!(absorbed.get() > 0);
            // Monotone: a wider band never absorbs less.
            assert!(absorbed.get() >= previous, "depth must be monotone");
            previous = absorbed.get();

            // The absorbed input is genuinely inside the band...
            let resulting =
                clmm_resulting_sqrt(&pool, &weth(), absorbed.get()).expect("absorbed input quotes");
            let impact = clmm_impact_f64(pool.sqrt_price_x64, resulting);
            assert!(
                impact <= level.target_bps.get() as f64 + 1.0,
                "absorbed input {} has impact {} > target {}",
                absorbed.get(),
                impact,
                level.target_bps.get()
            );

            // ...and one more unit is outside the band (or fails closed).
            if let Some(next) = clmm_resulting_sqrt(&pool, &weth(), absorbed.get() + 1) {
                let next_impact = clmm_impact_f64(pool.sqrt_price_x64, next);
                assert!(
                    next_impact > level.target_bps.get() as f64,
                    "absorbed+1 {} still within target {}",
                    absorbed.get() + 1,
                    level.target_bps.get()
                );
            }
        }
    }
    assert!(profile.trade_impact_bps.is_some());
}

#[test]
fn clmm_range_exhaustion_caps_depth() {
    let narrow = PoolKindState::Clmm(narrow_pool(30));
    let wide = PoolKindState::Clmm(wide_pool(30));
    let targets = default_targets();
    let amount = AtomicAmount::new(1_000_000);

    let narrow_profile = depth_at_bps(&narrow, &weth(), amount, &targets).expect("narrow");
    let wide_profile = depth_at_bps(&wide, &weth(), amount, &targets).expect("wide");

    let widest = targets.len() - 1;
    let narrow_cap = narrow_profile.levels[widest]
        .absorbed_in
        .expect("narrow absorbs its whole range");
    let wide_cap = wide_profile.levels[widest]
        .absorbed_in
        .expect("wide absorbs its whole range");
    assert!(
        wide_cap.get() > narrow_cap.get(),
        "the wide range must absorb more before leaving its range"
    );
    // The narrow range is exhausted before 250 bps, so 100/250 agree with the cap.
    assert_eq!(narrow_profile.levels[3].absorbed_in, Some(narrow_cap));
    assert_eq!(narrow_profile.levels[4].absorbed_in, Some(narrow_cap));
}

#[test]
fn bin_depth_pins_exact_bin_capacity() {
    let pool = bin(weth(), usdc());
    let state = PoolKindState::Bin(pool);
    let targets = targets(&[50, 100, 250]);
    let profile = depth_at_bps(&state, &weth(), AtomicAmount::new(1_000), &targets)
        .expect("bin depth profile");

    // Bin 1 holds 2_000 quote units at price 101/100: ceil(2_000 * 100 / 101) = 1_981.
    assert_eq!(
        profile.levels[0].absorbed_in,
        Some(AtomicAmount::new(1_981))
    );
    // Bin 0 holds 3_000 quote units at price 1/1: +3_000 = 4_981.
    assert_eq!(
        profile.levels[1].absorbed_in,
        Some(AtomicAmount::new(4_981))
    );
    assert_eq!(
        profile.levels[2].absorbed_in,
        Some(AtomicAmount::new(4_981))
    );
    // 1_000 input stays inside the active bin, so its exact impact is zero.
    assert_eq!(profile.trade_impact_bps, Some(bps(0)));
}

#[test]
fn depth_is_deterministic() {
    let state = PoolKindState::Clmm(narrow_pool(30));
    let targets = default_targets();
    let first = depth_at_bps(&state, &weth(), AtomicAmount::new(1_000_000), &targets).unwrap();
    let second = depth_at_bps(&state, &weth(), AtomicAmount::new(1_000_000), &targets).unwrap();
    assert_eq!(first, second);

    let rank = depth_rank(&state, &weth(), AtomicAmount::new(1_000_000), &targets).unwrap();
    assert_eq!(rank.levels.len(), targets.len());
    // Rank levels are sorted widest-band first.
    assert!(rank
        .levels
        .windows(2)
        .all(|pair| pair[0].target_bps.get() >= pair[1].target_bps.get()));
    assert_eq!(rank.levels.first().unwrap().target_bps.get(), 250);
}

#[test]
fn depth_rejects_inapplicable_states() {
    let targets = default_targets();
    let amount = AtomicAmount::new(1_000);

    let cpmm = PoolKindState::Cpmm(cpmm(weth(), usdc(), 1_000_000, 1_000_000, 30));
    assert_eq!(
        depth_at_bps(&cpmm, &weth(), amount, &targets),
        Err(RoutingError::UnsupportedPoolKind)
    );

    let clmm = PoolKindState::Clmm(narrow_pool(30));
    // A same-chain asset that is not in the pool is unsupported, not guessed.
    assert_eq!(
        depth_at_bps(&clmm, &token2(), amount, &targets),
        Err(RoutingError::UnsupportedPoolKind)
    );

    // A foreign-chain input fails the chain binding.
    let solana = solana_asset("So11111111111111111111111111111111111111112");
    assert_eq!(
        depth_at_bps(&clmm, &solana, amount, &targets),
        Err(RoutingError::PoolChainMismatch)
    );

    // A structurally invalid pool cannot be traversed at all.
    let mut broken = narrow_pool(30);
    broken.liquidity = 0;
    assert_eq!(
        depth_at_bps(&PoolKindState::Clmm(broken), &weth(), amount, &targets),
        Err(RoutingError::UnsupportedPoolKind)
    );
}

#[test]
fn depth_debug_is_redacted() {
    let pool = bin(weth(), usdc());
    let state = PoolKindState::Bin(pool);
    let profile = depth_at_bps(
        &state,
        &weth(),
        AtomicAmount::new(1_000),
        &targets(&[50, 100]),
    )
    .expect("bin depth profile");
    let rendered = format!("{profile:?}");
    assert!(rendered.contains("covered"), "expected redacted structure");
    assert!(
        !rendered.contains("1981") && !rendered.contains("4981"),
        "depth Debug must not render absorbed amounts: {rendered}"
    );

    let rank = depth_rank(
        &state,
        &weth(),
        AtomicAmount::new(1_000),
        &targets(&[50, 100]),
    )
    .expect("bin depth rank");
    let rank_rendered = format!("{rank:?}");
    assert!(
        !rank_rendered.contains("1981") && !rank_rendered.contains("4981"),
        "depth rank Debug must not render absorbed amounts: {rank_rendered}"
    );
}

#[test]
fn planner_prefers_deeper_pool_when_net_ties() {
    let intent = buy(weth(), usdc(), 1_000_000);
    let tax = zero_tax_for(&intent);
    let scoring = scoring();
    let policy = caller_policy();
    let descriptors = vec![
        descriptor(
            "uniswap_v3",
            "pool-narrow",
            PoolKindState::Clmm(narrow_pool(30)),
            NOW_MS,
            1,
            None,
        ),
        descriptor(
            "uniswap_v3",
            "pool-wide",
            PoolKindState::Clmm(wide_pool(30)),
            NOW_MS,
            1,
            None,
        ),
    ];
    let targets = default_targets();
    let req = request_with_depth(
        &intent,
        &descriptors,
        1_000_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
        &targets,
    );
    let decision = plan_single_path(&req).expect("planner succeeds");

    assert_eq!(decision.candidates.len(), 2);
    // Both pools quote the same output for the small trade, so depth breaks the tie.
    assert_eq!(
        decision.candidates[0].score.simulated_net_output,
        decision.candidates[1].score.simulated_net_output
    );
    let selected = decision.selected.expect("a winner");
    assert_eq!(selected.plan.legs[0].pool_ref, "pool-wide");
}

#[test]
fn planner_keeps_net_output_primary_over_depth() {
    let intent = buy(weth(), usdc(), 1_000_000);
    let tax = zero_tax_for(&intent);
    let scoring = scoring();
    let policy = caller_policy();
    // The narrow pool is shallower but charges no fee, so its net output is higher.
    let descriptors = vec![
        descriptor(
            "uniswap_v3",
            "pool-narrow-cheap",
            PoolKindState::Clmm(narrow_pool(0)),
            NOW_MS,
            1,
            None,
        ),
        descriptor(
            "uniswap_v3",
            "pool-wide",
            PoolKindState::Clmm(wide_pool(30)),
            NOW_MS,
            1,
            None,
        ),
    ];
    let targets = default_targets();
    let req = request_with_depth(
        &intent,
        &descriptors,
        1_000_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
        &targets,
    );
    let decision = plan_single_path(&req).expect("planner succeeds");

    let selected = decision.selected.expect("a winner");
    assert_eq!(selected.plan.legs[0].pool_ref, "pool-narrow-cheap");
}

#[test]
fn planner_depth_is_opt_in_and_disabled_is_unchanged() {
    let intent = buy(weth(), usdc(), 1_000_000);
    let tax = zero_tax_for(&intent);
    let scoring = scoring();
    let policy = caller_policy();
    let descriptors = vec![descriptor(
        "uniswap_v3",
        "pool-narrow",
        PoolKindState::Clmm(narrow_pool(30)),
        NOW_MS,
        1,
        Some(10),
    )];

    // Disabled: the caller override governs the score impact, exactly as before.
    let disabled = request(
        &intent,
        &descriptors,
        1_000_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    let disabled_decision = plan_single_path(&disabled).expect("disabled planner succeeds");
    assert_eq!(disabled_decision.candidates[0].score.price_impact, bps(10));

    // An explicit empty target list is byte-identical to the helper default.
    let empty = request_with_depth(
        &intent,
        &descriptors,
        1_000_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
        &[],
    );
    assert_eq!(
        plan_single_path(&empty).expect("empty planner succeeds"),
        disabled_decision
    );

    // Enabled: the exact kernel-derived impact replaces the override.
    let targets = default_targets();
    let enabled = request_with_depth(
        &intent,
        &descriptors,
        1_000_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
        &targets,
    );
    let enabled_decision = plan_single_path(&enabled).expect("enabled planner succeeds");
    assert_ne!(enabled_decision.candidates[0].score.price_impact, bps(10));
    assert!(enabled_decision.candidates[0].score.price_impact.get() >= 1);
    assert!(enabled_decision.candidates[0].score.price_impact.get() <= 5);
}

/// Compile-time guard: a foreign-chain CLMM input is rejected before any kernel work.
#[test]
fn depth_foreign_chain_is_rejected_before_traversal() {
    let pool = narrow_pool(30);
    let foreign = solana_asset("So11111111111111111111111111111111111111112");
    assert_eq!(
        depth_at_bps(
            &PoolKindState::Clmm(pool),
            &foreign,
            AtomicAmount::new(1),
            &default_targets(),
        ),
        Err(RoutingError::PoolChainMismatch)
    );
}

/// Far-from-zero active bin: every per-bin price is representable, but the
/// `base^|diff|` form overflows `u128`, so the depth must be derived from the
/// kernel's reduced per-bin prices instead of a large power.
fn far_active_bin_pool() -> BinPoolState {
    BinPoolState {
        token_0: weth(),
        token_1: usdc(),
        decimals_0: 0,
        decimals_1: 0,
        active_bin_id: -9,
        bin_step: 1,
        fee_bps: bps(0),
        bins: (-9i32..=9)
            .map(|id| {
                // Above the active bin only the base asset (reserve_0) is allowed.
                let quote = if id == -9 { 1_000_000_000 } else { 0 };
                LiquidityBin::new(
                    id,
                    AtomicAmount::new(1_000_000_000),
                    AtomicAmount::new(quote),
                )
            })
            .collect(),
    }
}

#[test]
fn bin_depth_is_exact_for_a_far_from_zero_active_bin() {
    let state = PoolKindState::Bin(far_active_bin_pool());
    let profile = depth_at_bps(&state, &usdc(), AtomicAmount::new(1_000), &targets(&[250]))
        .expect("far-active-bin depth profile");
    // The whole 19-bin range is only ~18 bps wide, so 250 bps covers all of it.
    // `sum_{i=-9..=9} ceil(1e9 * price(i))` independently recomputed.
    assert_eq!(
        profile.levels[0].absorbed_in,
        Some(AtomicAmount::new(19_000_002_857))
    );
    // The profiled trade (1_000) stays inside the active bin, so its impact is 0.
    // The cross-bin impact is pinned directly in the `depth.rs` unit tests.
    assert_eq!(profile.trade_impact_bps, Some(bps(0)));

    // A narrower band must stop earlier: 1 bp needs only the first bin.
    let narrow = depth_at_bps(&state, &usdc(), AtomicAmount::new(1_000), &targets(&[1]))
        .expect("far-active-bin narrow profile");
    let first = narrow.levels[0].absorbed_in.expect("bin -9 is inside 1 bp");
    assert!(first.get() < 19_000_002_857);
    assert!(first.get() > 0);
}

#[test]
fn depth_survives_a_one_unit_rounding_hole() {
    // A very deep pool can reject a one-unit exact quote (`InvariantViolated`,
    // zero price movement) while accepting a larger input; depth must still be
    // computed rather than being disabled wholesale.
    let mut pool = wide_pool(30);
    pool.liquidity = 1_000_000_000_000_000_000_000_000_000_000; // 1e30
    let state = PoolKindState::Clmm(pool);
    let profile = depth_at_bps(&state, &weth(), AtomicAmount::new(1), &default_targets())
        .expect("a deep pool with a 1-unit rounding hole must still be profileable");
    assert!(profile
        .levels
        .iter()
        .any(|level| level.absorbed_in.is_some()));
}
