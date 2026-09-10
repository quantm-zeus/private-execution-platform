//! Deterministic local pool-state reducers test suite (P22).
//!
//! Tests bounded reconstruction, atomic staged transitions, rollback safety,
//! sticky resync latching, and recovery across CPMM, CLMM/tick, and Bin/DLMM models.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, BinPoolDelta, BinPoolDeltaEnvelope, BinPoolReducer, BinPoolState, ClmmPoolDelta,
    ClmmPoolDeltaEnvelope, ClmmPoolReducer, ClmmPoolState, ClmmTick, CpmmPoolDelta,
    CpmmPoolDeltaEnvelope, CpmmPoolReducer, CpmmPoolState, DeltaClassification, LiquidityBin,
    MarketTypeError, PoolDeltaEnvelope, PoolId, PoolKindDelta, PoolKindState, PoolReducer,
    PoolStateEnvelope, Sequence, SequenceRange, SnapshotClassification, MAX_BIN_COUNT,
    MAX_BIN_DELTA_BINS, MAX_BIN_ID, MAX_CLMM_DELTA_TICKS, MAX_CLMM_TICKS, MAX_TICK, MIN_BIN_ID,
    MIN_TICK,
};

fn sample_pool_id() -> PoolId {
    PoolId::new(
        ChainId::Solana,
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    )
    .unwrap()
}

fn sample_assets() -> (AssetId, AssetId) {
    let sol = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let usdc = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();
    (sol, usdc)
}

fn sample_cpmm_state() -> CpmmPoolState {
    let (sol, usdc) = sample_assets();
    CpmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        reserve_0: AtomicAmount::new(1_000_000_000),
        reserve_1: AtomicAmount::new(150_000_000_000u128),
        total_lp_supply: Some(AtomicAmount::new(500_000_000u128)),
        fee_bps: 30.try_into().unwrap(),
    }
}

fn sample_clmm_state() -> ClmmPoolState {
    let (sol, usdc) = sample_assets();
    ClmmPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        tick_spacing: 64,
        current_tick: 0,
        sqrt_price_x64: 18446744073709551616, // 1.0 in Q64
        liquidity: 50_000,
        fee_bps: 5.try_into().unwrap(),
        ticks: vec![
            ClmmTick::new(-128, 10_000, 10_000),
            ClmmTick::new(0, 20_000, -5_000),
            ClmmTick::new(128, 15_000, -5_000),
        ],
    }
}

fn sample_bin_state() -> BinPoolState {
    let (sol, usdc) = sample_assets();
    BinPoolState {
        token_0: sol,
        token_1: usdc,
        decimals_0: 9,
        decimals_1: 6,
        active_bin_id: 100,
        bin_step: 10,
        fee_bps: 10.try_into().unwrap(),
        bins: vec![
            LiquidityBin::new(98, AtomicAmount::new(0), AtomicAmount::new(50_000)),
            LiquidityBin::new(100, AtomicAmount::new(20_000), AtomicAmount::new(30_000)),
            LiquidityBin::new(102, AtomicAmount::new(60_000), AtomicAmount::new(0)),
        ],
    }
}

// =========================================================================
// CPMM Pool Reducer Tests
// =========================================================================

#[test]
fn test_cpmm_reducer_happy_path_contiguous_progression() {
    let pool_id = sample_pool_id();
    let initial_state = sample_cpmm_state();
    let mut reducer =
        CpmmPoolReducer::new(pool_id.clone(), Sequence(100), 1_000_000, initial_state).unwrap();

    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.timestamp_ms(), 1_000_000);
    assert!(!reducer.is_resync_required());

    // Delta 101: update reserve_0 and reserve_1
    let d101 = CpmmPoolDelta::new(
        Some(AtomicAmount::new(1_050_000_000)),
        Some(AtomicAmount::new(145_000_000_000u128)),
        None,
        None,
    );
    let outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &d101,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(101));
    assert_eq!(reducer.timestamp_ms(), 1_000_100);
    assert_eq!(reducer.state().reserve_0.get(), 1_050_000_000);
    assert_eq!(reducer.state().reserve_1.get(), 145_000_000_000);
    // Unchanged fields preserved
    assert_eq!(reducer.state().total_lp_supply.unwrap().get(), 500_000_000);
    assert_eq!(reducer.state().fee_bps.get(), 30);

    // Delta [102, 104]: multi-sequence step updating total_lp_supply and fee_bps
    let d102_104 = CpmmPoolDelta::new(
        None,
        None,
        Some(AtomicAmount::new(510_000_000u128)),
        Some(25.try_into().unwrap()),
    );
    let range = SequenceRange::new(Sequence(102), Sequence(104)).unwrap();
    let outcome = reducer.apply_delta(range, 1_000_400, &d102_104).unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(104)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(104));
    assert_eq!(reducer.state().total_lp_supply.unwrap().get(), 510_000_000);
    assert_eq!(reducer.state().fee_bps.get(), 25);

    // Idempotent duplicate: delta ending at 104
    let dup_outcome = reducer.apply_delta(range, 1_000_450, &d102_104).unwrap();
    assert_eq!(
        dup_outcome,
        DeltaClassification::Duplicate {
            sequence: Sequence(104)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(104));

    // Idempotent stale: delta ending before 104
    let stale_range = SequenceRange::new(Sequence(101), Sequence(103)).unwrap();
    let stale_outcome = reducer
        .apply_delta(stale_range, 1_000_500, &d102_104)
        .unwrap();
    assert_eq!(
        stale_outcome,
        DeltaClassification::Stale {
            sequence: Sequence(103),
            current: Sequence(104),
        }
    );
    assert_eq!(reducer.sequence(), Sequence(104));

    // Conversion to canonical envelope
    let env = reducer.to_envelope();
    assert_eq!(env.pool_id, pool_id);
    assert_eq!(env.sequence, Sequence(104));
    assert_eq!(env.observed_at_ms, 1_000_400);
    assert!(matches!(env.state, PoolKindState::Cpmm(_)));
}

#[test]
fn test_cpmm_reducer_rollback_on_zero_reserves() {
    let pool_id = sample_pool_id();
    let initial_state = sample_cpmm_state();
    let mut reducer =
        CpmmPoolReducer::new(pool_id, Sequence(100), 1_000_000, initial_state.clone()).unwrap();

    // Contiguous delta setting reserve_0 to zero -> fails closed with ZeroAmount
    let zero_r0 = CpmmPoolDelta::new(Some(AtomicAmount::new(0)), None, None, None);
    let res = reducer.apply_delta(
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        &zero_r0,
    );
    assert_eq!(res, Err(MarketTypeError::ZeroAmount));

    // State completely unchanged
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.timestamp_ms(), 1_000_000);
    assert_eq!(reducer.state(), &initial_state);
    assert!(!reducer.is_resync_required());

    // Contiguous delta setting reserve_1 to zero -> fails closed with ZeroAmount
    let zero_r1 = CpmmPoolDelta::new(None, Some(AtomicAmount::new(0)), None, None);
    let res = reducer.apply_delta(
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        &zero_r1,
    );
    assert_eq!(res, Err(MarketTypeError::ZeroAmount));
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);
}

#[test]
fn test_cpmm_reducer_gap_and_overlap_latches_resync_and_recovers() {
    let pool_id = sample_pool_id();
    let initial_state = sample_cpmm_state();
    let mut reducer = CpmmPoolReducer::new(
        pool_id.clone(),
        Sequence(100),
        1_000_000,
        initial_state.clone(),
    )
    .unwrap();

    // Sequence Gap: delta [105, 105] on current 100 (expected 101)
    let gap_delta = CpmmPoolDelta::new(Some(AtomicAmount::new(2_000_000_000)), None, None, None);
    let outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(105)).unwrap(),
            1_000_100,
            &gap_delta,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(105),
        }
    );
    assert!(reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // While latched: next delta [101, 101] MUST still return ResyncRequired
    let next_delta = CpmmPoolDelta::new(Some(AtomicAmount::new(1_100_000_000)), None, None, None);
    let latched_outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_200,
            &next_delta,
        )
        .unwrap();
    assert_eq!(
        latched_outcome,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(101),
        }
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // Stale snapshot (seq 95 < 100): rejected, latch held
    let stale_snap = initial_state.clone();
    let stale_outcome = reducer
        .apply_snapshot(Sequence(95), 1_000_250, stale_snap)
        .unwrap();
    assert_eq!(
        stale_outcome,
        SnapshotClassification::Stale {
            sequence: Sequence(95),
            current: Sequence(100),
        }
    );
    assert!(reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(100));

    // Duplicate snapshot (seq 100 == 100): rejected, latch held
    let dup_snap = initial_state.clone();
    let dup_outcome = reducer
        .apply_snapshot(Sequence(100), 1_000_260, dup_snap)
        .unwrap();
    assert_eq!(
        dup_outcome,
        SnapshotClassification::Duplicate {
            sequence: Sequence(100),
        }
    );
    assert!(reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(100));

    // Valid newer snapshot (seq 110 > 100): accepted, latch cleared!
    let mut newer_state = initial_state.clone();
    newer_state.reserve_0 = AtomicAmount::new(1_200_000_000);
    let recovery_outcome = reducer
        .apply_snapshot(Sequence(110), 1_000_300, newer_state.clone())
        .unwrap();
    assert_eq!(
        recovery_outcome,
        SnapshotClassification::Accepted {
            new_sequence: Sequence(110),
        }
    );
    assert!(!reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(110));
    assert_eq!(reducer.state(), &newer_state);

    // Contiguous delta after recovery succeeds cleanly
    let post_recovery_delta =
        CpmmPoolDelta::new(Some(AtomicAmount::new(1_250_000_000)), None, None, None);
    let post_outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(111)).unwrap(),
            1_000_400,
            &post_recovery_delta,
        )
        .unwrap();
    assert_eq!(
        post_outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(111)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(111));
    assert_eq!(reducer.state().reserve_0.get(), 1_250_000_000);
}

#[test]
fn test_cpmm_reducer_overlap_latches_resync_and_preserves_state() {
    let pool_id = sample_pool_id();
    let initial_state = sample_cpmm_state();
    let mut reducer =
        CpmmPoolReducer::new(pool_id, Sequence(100), 1_000_000, initial_state.clone()).unwrap();

    // Overlapping delta: [99, 105] on current 100
    let overlap_range = SequenceRange::new(Sequence(99), Sequence(105)).unwrap();
    let delta = CpmmPoolDelta::new(Some(AtomicAmount::new(2_000_000_000)), None, None, None);
    let outcome = reducer
        .apply_delta(overlap_range, 1_000_100, &delta)
        .unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(99),
        }
    );
    assert!(reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);
}

// =========================================================================
// CLMM Pool Reducer Tests
// =========================================================================

#[test]
fn test_clmm_reducer_happy_path_tick_reconstruction() {
    let pool_id = sample_pool_id();
    let initial_state = sample_clmm_state();
    let mut reducer =
        ClmmPoolReducer::new(pool_id.clone(), Sequence(100), 1_000_000, initial_state, 50).unwrap();

    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.ticks().len(), 3);
    assert_eq!(reducer.ticks()[0].index, -128);
    assert_eq!(reducer.ticks()[1].index, 0);
    assert_eq!(reducer.ticks()[2].index, 128);

    // Delta 101:
    // - Insert new tick at 64
    // - Update existing tick at 0
    // - Update current_tick, sqrt_price_x64, liquidity
    let delta101 = ClmmPoolDelta::new(
        Some(32),
        Some(18500000000000000000),
        Some(60_000),
        None,
        vec![
            ClmmTick::new(0, 25_000, -2_000),
            ClmmTick::new(64, 10_000, 5_000),
        ],
    );
    let outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &delta101,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(101));
    assert_eq!(reducer.current_tick(), 32);
    assert_eq!(reducer.sqrt_price_x64(), 18500000000000000000);
    assert_eq!(reducer.liquidity(), 60_000);

    // Ticks must be strictly sorted: [-128, 0, 64, 128]
    assert_eq!(reducer.ticks().len(), 4);
    assert_eq!(reducer.ticks()[0].index, -128);
    assert_eq!(reducer.ticks()[1].index, 0);
    assert_eq!(reducer.ticks()[1].liquidity_gross, 25_000);
    assert_eq!(reducer.ticks()[1].liquidity_net, -2_000);
    assert_eq!(reducer.ticks()[2].index, 64);
    assert_eq!(reducer.ticks()[2].liquidity_gross, 10_000);
    assert_eq!(reducer.ticks()[2].liquidity_net, 5_000);
    assert_eq!(reducer.ticks()[3].index, 128);

    // Delta 102: Delete tick at -128 using gross = 0, net = 0
    let delta102 = ClmmPoolDelta::new(None, None, None, None, vec![ClmmTick::new(-128, 0, 0)]);
    let outcome102 = reducer
        .apply_delta(
            SequenceRange::point(Sequence(102)).unwrap(),
            1_000_200,
            &delta102,
        )
        .unwrap();

    assert_eq!(
        outcome102,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(102)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(102));
    // Ticks now: [0, 64, 128]
    assert_eq!(reducer.ticks().len(), 3);
    assert_eq!(reducer.ticks()[0].index, 0);
    assert_eq!(reducer.ticks()[1].index, 64);
    assert_eq!(reducer.ticks()[2].index, 128);
}

#[test]
fn test_clmm_reducer_bounds_and_invalid_ticks_fail_closed() {
    let pool_id = sample_pool_id();
    let initial_state = sample_clmm_state();
    let mut reducer = ClmmPoolReducer::new(
        pool_id,
        Sequence(100),
        1_000_000,
        initial_state.clone(),
        5, // max 5 ticks
    )
    .unwrap();

    // 1. Tick unaligned with spacing (tick_spacing = 64, index = 65)
    let unaligned_delta = ClmmPoolDelta::new(
        None,
        None,
        None,
        None,
        vec![ClmmTick::new(65, 5_000, 1_000)],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &unaligned_delta
        ),
        Err(MarketTypeError::TickSpacingMismatch {
            tick: 65,
            spacing: 64,
        })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 2. Tick index out of range
    let out_of_range_delta = ClmmPoolDelta::new(
        None,
        None,
        None,
        None,
        vec![ClmmTick::new(MAX_TICK + 64, 5_000, 1_000)],
    );
    assert!(matches!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &out_of_range_delta
        ),
        Err(MarketTypeError::TickOutOfRange { .. })
    ));
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 3. Invalid liquidity: |net| > gross
    let bad_liq_delta = ClmmPoolDelta::new(
        None,
        None,
        None,
        None,
        vec![ClmmTick::new(64, 1_000, 2_000)],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_liq_delta
        ),
        Err(MarketTypeError::InvalidTickLiquidity(64))
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 4. Invalid liquidity: gross == 0 but net != 0
    let zero_gross_nonzero_net =
        ClmmPoolDelta::new(None, None, None, None, vec![ClmmTick::new(64, 0, -100)]);
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &zero_gross_nonzero_net
        ),
        Err(MarketTypeError::InvalidTickLiquidity(64))
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 5. Zero sqrt price
    let zero_sqrt = ClmmPoolDelta::new(None, Some(0), None, None, vec![]);
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &zero_sqrt
        ),
        Err(MarketTypeError::ZeroPrice)
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 6. Exceeding max_ticks capacity (initial has 3 ticks, max is 5; trying to insert 3 new ticks = 6 > 5)
    let overflow_delta = ClmmPoolDelta::new(
        None,
        None,
        None,
        None,
        vec![
            ClmmTick::new(64, 1_000, 500),
            ClmmTick::new(192, 1_000, 500),
            ClmmTick::new(256, 1_000, 500),
        ],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &overflow_delta
        ),
        Err(MarketTypeError::ClmmTicksExceeded { count: 6, max: 5 })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 7. Delta input exceeding MAX_CLMM_DELTA_TICKS
    let mut huge_ticks = Vec::new();
    for i in 1..=(MAX_CLMM_DELTA_TICKS + 1) {
        huge_ticks.push(ClmmTick::new((i * 64) as i32, 100, 0));
    }
    let overbound_delta = ClmmPoolDelta::new(None, None, None, None, huge_ticks);
    assert!(matches!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &overbound_delta
        ),
        Err(MarketTypeError::ClmmTicksExceeded { .. })
    ));
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);
}

#[test]
fn test_clmm_reducer_gap_and_recovery() {
    let pool_id = sample_pool_id();
    let initial_state = sample_clmm_state();
    let mut reducer =
        ClmmPoolReducer::new(pool_id, Sequence(100), 1_000_000, initial_state.clone(), 50).unwrap();

    // Gap delta [105, 105]
    let gap_delta = ClmmPoolDelta::new(None, None, None, None, vec![]);
    let outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(105)).unwrap(),
            1_000_100,
            &gap_delta,
        )
        .unwrap();
    assert_eq!(
        outcome,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(105),
        }
    );
    assert!(reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(100));

    // Recovery via newer snapshot at sequence 120
    let mut newer_state = initial_state.clone();
    newer_state.current_tick = 64;
    let rec_outcome = reducer
        .apply_snapshot(Sequence(120), 1_000_300, newer_state.clone())
        .unwrap();
    assert_eq!(
        rec_outcome,
        SnapshotClassification::Accepted {
            new_sequence: Sequence(120),
        }
    );
    assert!(!reducer.is_resync_required());
    assert_eq!(reducer.sequence(), Sequence(120));
    assert_eq!(reducer.current_tick(), 64);
}

// =========================================================================
// Bin / DLMM Pool Reducer Tests
// =========================================================================

#[test]
fn test_bin_reducer_happy_path_bin_reconstruction() {
    let pool_id = sample_pool_id();
    let initial_state = sample_bin_state();
    let mut reducer =
        BinPoolReducer::new(pool_id.clone(), Sequence(100), 1_000_000, initial_state, 50).unwrap();

    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.bins().len(), 3);
    assert_eq!(reducer.active_bin_id(), 100);

    // Delta 101:
    // - Insert new bin at 104 (above active 100: reserve_0 = 40_000, reserve_1 = 0)
    // - Update existing active bin at 100 (reserve_0 = 25_000, reserve_1 = 25_000)
    let delta101 = BinPoolDelta::new(
        None,
        None,
        None,
        vec![
            LiquidityBin::new(100, AtomicAmount::new(25_000), AtomicAmount::new(25_000)),
            LiquidityBin::new(104, AtomicAmount::new(40_000), AtomicAmount::new(0)),
        ],
    );
    let outcome = reducer
        .apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &delta101,
        )
        .unwrap();

    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(101));
    assert_eq!(reducer.bins().len(), 4);
    // Bins strictly sorted: [98, 100, 102, 104]
    assert_eq!(reducer.bins()[0].id, 98);
    assert_eq!(reducer.bins()[1].id, 100);
    assert_eq!(reducer.bins()[1].reserve_0.get(), 25_000);
    assert_eq!(reducer.bins()[1].reserve_1.get(), 25_000);
    assert_eq!(reducer.bins()[2].id, 102);
    assert_eq!(reducer.bins()[3].id, 104);
    assert_eq!(reducer.bins()[3].reserve_0.get(), 40_000);
    assert_eq!(reducer.bins()[3].reserve_1.get(), 0);

    // Delta 102: Delete bin at 98 using reserve_0 = 0, reserve_1 = 0
    let delta102 = BinPoolDelta::new(
        None,
        None,
        None,
        vec![LiquidityBin::new(
            98,
            AtomicAmount::new(0),
            AtomicAmount::new(0),
        )],
    );
    let outcome102 = reducer
        .apply_delta(
            SequenceRange::point(Sequence(102)).unwrap(),
            1_000_200,
            &delta102,
        )
        .unwrap();

    assert_eq!(
        outcome102,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(102)
        }
    );
    assert_eq!(reducer.sequence(), Sequence(102));
    assert_eq!(reducer.bins().len(), 3);
    assert_eq!(reducer.bins()[0].id, 100);
    assert_eq!(reducer.bins()[1].id, 102);
    assert_eq!(reducer.bins()[2].id, 104);
}

#[test]
fn test_bin_reducer_rollback_on_reserve_side_violation() {
    let pool_id = sample_pool_id();
    let initial_state = sample_bin_state();
    let mut reducer =
        BinPoolReducer::new(pool_id, Sequence(100), 1_000_000, initial_state.clone(), 50).unwrap();

    // Active bin is 100.
    // 1. Bin below active bin (e.g. 98) cannot have reserve_0 > 0
    let bad_below_delta = BinPoolDelta::new(
        None,
        None,
        None,
        vec![LiquidityBin::new(
            98,
            AtomicAmount::new(100),
            AtomicAmount::new(50_000),
        )],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_below_delta
        ),
        Err(MarketTypeError::BinReserveSideViolation {
            bin_id: 98,
            active_bin_id: 100,
        })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 2. Bin above active bin (e.g. 102) cannot have reserve_1 > 0
    let bad_above_delta = BinPoolDelta::new(
        None,
        None,
        None,
        vec![LiquidityBin::new(
            102,
            AtomicAmount::new(60_000),
            AtomicAmount::new(100),
        )],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_above_delta
        ),
        Err(MarketTypeError::BinReserveSideViolation {
            bin_id: 102,
            active_bin_id: 100,
        })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 3. Shifting active_bin_id to 105 without clearing reserve_0 on bin 102 (now below active_bin_id 105)
    let bad_shift_delta = BinPoolDelta::new(Some(105), None, None, vec![]);
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_shift_delta
        ),
        Err(MarketTypeError::BinReserveSideViolation {
            bin_id: 100, // bin 100 now below active 105, but has reserve_0 > 0
            active_bin_id: 105,
        })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);
}

#[test]
fn test_bin_reducer_bounds_and_malformed_inputs_fail_closed() {
    let pool_id = sample_pool_id();
    let initial_state = sample_bin_state();
    let mut reducer = BinPoolReducer::new(
        pool_id,
        Sequence(100),
        1_000_000,
        initial_state.clone(),
        5, // max 5 bins
    )
    .unwrap();

    // 1. Bin id out of range
    let bad_id_delta = BinPoolDelta::new(
        None,
        None,
        None,
        vec![LiquidityBin::new(
            MAX_BIN_ID + 1,
            AtomicAmount::new(100),
            AtomicAmount::new(0),
        )],
    );
    assert!(matches!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_id_delta
        ),
        Err(MarketTypeError::BinOutOfRange { .. })
    ));
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 2. Bin step out of range (0 or > 1000)
    let bad_step_delta = BinPoolDelta::new(None, Some(0), None, vec![]);
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_step_delta
        ),
        Err(MarketTypeError::InvalidBinStep(0))
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);

    // 3. Exceeding max_bins (initial has 3, max 5; adding 3 = 6 > 5)
    let overflow_delta = BinPoolDelta::new(
        None,
        None,
        None,
        vec![
            LiquidityBin::new(104, AtomicAmount::new(1_000), AtomicAmount::new(0)),
            LiquidityBin::new(106, AtomicAmount::new(1_000), AtomicAmount::new(0)),
            LiquidityBin::new(108, AtomicAmount::new(1_000), AtomicAmount::new(0)),
        ],
    );
    assert_eq!(
        reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &overflow_delta
        ),
        Err(MarketTypeError::BinsExceeded { count: 6, max: 5 })
    );
    assert_eq!(reducer.sequence(), Sequence(100));
    assert_eq!(reducer.state(), &initial_state);
}

// =========================================================================
// Unified PoolReducer Tests
// =========================================================================

#[test]
fn test_unified_pool_reducer_polymorphism_and_kind_mismatch() {
    let pool_id = sample_pool_id();
    let cpmm_env = PoolStateEnvelope {
        pool_id: pool_id.clone(),
        sequence: Sequence(100),
        observed_at_ms: 1_000_000,
        state: PoolKindState::Cpmm(sample_cpmm_state()),
    };

    let mut unified = PoolReducer::new(cpmm_env).unwrap();
    assert!(unified.as_cpmm().is_some());
    assert!(unified.as_clmm().is_none());
    assert!(unified.as_bin().is_none());
    assert_eq!(unified.sequence(), Sequence(100));

    // Applying CLMM delta to CPMM reducer must fail closed with PoolKindMismatch
    let clmm_delta = PoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        PoolKindDelta::Clmm(ClmmPoolDelta::new(Some(64), None, None, None, vec![])),
    )
    .unwrap();

    let err = unified.apply_delta(&clmm_delta);
    assert_eq!(
        err,
        Err(MarketTypeError::PoolKindMismatch {
            expected: "cpmm",
            received: "clmm",
        })
    );
    assert_eq!(unified.sequence(), Sequence(100));

    // Target mismatch with different PoolId
    let diff_pool = PoolId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let target_mismatch_delta = PoolDeltaEnvelope::new(
        diff_pool,
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        PoolKindDelta::Cpmm(CpmmPoolDelta::new(
            Some(AtomicAmount::new(1_000_000)),
            None,
            None,
            None,
        )),
    )
    .unwrap();

    assert_eq!(
        unified.apply_delta(&target_mismatch_delta),
        Err(MarketTypeError::TargetMismatch)
    );
    assert_eq!(unified.sequence(), Sequence(100));

    // Valid CPMM delta succeeds
    let valid_cpmm_delta = PoolDeltaEnvelope::new(
        pool_id,
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        PoolKindDelta::Cpmm(CpmmPoolDelta::new(
            Some(AtomicAmount::new(1_050_000_000)),
            None,
            None,
            None,
        )),
    )
    .unwrap();

    let outcome = unified.apply_delta(&valid_cpmm_delta).unwrap();
    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );
    assert_eq!(unified.sequence(), Sequence(101));
}

#[test]
fn test_pool_delta_envelope_serialization_round_trips() {
    let pool_id = sample_pool_id();

    // 1. CPMM Delta
    let cpmm_delta_env = PoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::new(Sequence(10), Sequence(12)).unwrap(),
        1_700_000_000,
        PoolKindDelta::Cpmm(CpmmPoolDelta::new(
            Some(AtomicAmount::new(50_000_000)),
            Some(AtomicAmount::new(60_000_000)),
            Some(AtomicAmount::new(10_000)),
            Some(30.try_into().unwrap()),
        )),
    )
    .unwrap();
    let json = serde_json::to_string(&cpmm_delta_env).unwrap();
    let decoded: PoolDeltaEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, cpmm_delta_env);

    // 2. CLMM Delta
    let clmm_delta_env = PoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(15)).unwrap(),
        1_700_000_100,
        PoolKindDelta::Clmm(ClmmPoolDelta::new(
            Some(128),
            Some(18446744073709551616),
            Some(100_000),
            Some(5.try_into().unwrap()),
            vec![ClmmTick::new(128, 50_000, 10_000)],
        )),
    )
    .unwrap();
    let json = serde_json::to_string(&clmm_delta_env).unwrap();
    let decoded: PoolDeltaEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, clmm_delta_env);

    // 3. Bin Delta
    let bin_delta_env = PoolDeltaEnvelope::new(
        pool_id,
        SequenceRange::point(Sequence(20)).unwrap(),
        1_700_000_200,
        PoolKindDelta::Bin(BinPoolDelta::new(
            Some(105),
            Some(15),
            Some(10.try_into().unwrap()),
            vec![LiquidityBin::new(
                105,
                AtomicAmount::new(10_000),
                AtomicAmount::new(20_000),
            )],
        )),
    )
    .unwrap();
    let json = serde_json::to_string(&bin_delta_env).unwrap();
    let decoded: PoolDeltaEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, bin_delta_env);
}

#[test]
fn test_typed_delta_envelopes_and_boundary_limits() {
    let pool_id = sample_pool_id();

    // 1. CpmmPoolDeltaEnvelope
    let mut cpmm_reducer = CpmmPoolReducer::new(
        pool_id.clone(),
        Sequence(100),
        1_000_000,
        sample_cpmm_state(),
    )
    .unwrap();
    let cpmm_env = CpmmPoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        CpmmPoolDelta::new(Some(AtomicAmount::new(1_100_000_000)), None, None, None),
    )
    .unwrap();
    let general_cpmm = cpmm_env.to_envelope();
    assert_eq!(general_cpmm.pool_id, pool_id);
    let outcome = cpmm_reducer.apply_delta_envelope(&cpmm_env).unwrap();
    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );
    assert_eq!(cpmm_reducer.sequence(), Sequence(101));

    // 2. ClmmPoolDeltaEnvelope with tick at MIN_TICK boundary and underflow
    let mut clmm_reducer = ClmmPoolReducer::new(
        pool_id.clone(),
        Sequence(100),
        1_000_000,
        sample_clmm_state(),
        50,
    )
    .unwrap();
    // MIN_TICK is -887272. Let's check spacing 64 alignment: -887272 % 64 is -40, so not aligned with 64.
    // Nearest aligned tick >= MIN_TICK: -887232 is aligned with 64.
    let aligned_min = (MIN_TICK / 64) * 64;
    let clmm_env = ClmmPoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        ClmmPoolDelta::new(
            None,
            None,
            None,
            None,
            vec![ClmmTick::new(aligned_min, 1_000, 500)],
        ),
    )
    .unwrap();
    let general_clmm = clmm_env.to_envelope();
    assert_eq!(general_clmm.pool_id, pool_id);
    let outcome = clmm_reducer.apply_delta_envelope(&clmm_env).unwrap();
    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );

    // Out of range tick below MIN_TICK fails closed at construction
    let underflow_clmm_res = ClmmPoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(102)).unwrap(),
        1_000_200,
        ClmmPoolDelta::new(
            None,
            None,
            None,
            None,
            vec![ClmmTick::new(MIN_TICK - 64, 1_000, 0)],
        ),
    );
    assert!(matches!(
        underflow_clmm_res,
        Err(MarketTypeError::TickOutOfRange { .. })
    ));

    // 3. BinPoolDeltaEnvelope with bin at MIN_BIN_ID
    let mut bin_reducer = BinPoolReducer::new(
        pool_id.clone(),
        Sequence(100),
        1_000_000,
        sample_bin_state(),
        50,
    )
    .unwrap();
    let bin_env = BinPoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(101)).unwrap(),
        1_000_100,
        BinPoolDelta::new(
            None,
            None,
            None,
            vec![LiquidityBin::new(
                MIN_BIN_ID,
                AtomicAmount::ZERO,
                AtomicAmount::new(10_000),
            )],
        ),
    )
    .unwrap();
    let general_bin = bin_env.to_envelope();
    assert_eq!(general_bin.pool_id, pool_id);
    let outcome = bin_reducer.apply_delta_envelope(&bin_env).unwrap();
    assert_eq!(
        outcome,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101)
        }
    );

    // Out of range bin below MIN_BIN_ID fails closed at construction
    let underflow_bin_res = BinPoolDeltaEnvelope::new(
        pool_id.clone(),
        SequenceRange::point(Sequence(102)).unwrap(),
        1_000_200,
        BinPoolDelta::new(
            None,
            None,
            None,
            vec![LiquidityBin::new(
                MIN_BIN_ID - 1,
                AtomicAmount::ZERO,
                AtomicAmount::new(10_000),
            )],
        ),
    );
    assert!(matches!(
        underflow_bin_res,
        Err(MarketTypeError::BinOutOfRange { .. })
    ));

    // 4. Overbound reducer initialization capacity limits
    assert_eq!(
        ClmmPoolReducer::new(
            pool_id.clone(),
            Sequence(100),
            1_000_000,
            sample_clmm_state(),
            MAX_CLMM_TICKS + 1,
        ),
        Err(MarketTypeError::ClmmTicksExceeded {
            count: MAX_CLMM_TICKS + 1,
            max: MAX_CLMM_TICKS,
        })
    );
    assert_eq!(
        BinPoolReducer::new(
            pool_id,
            Sequence(100),
            1_000_000,
            sample_bin_state(),
            MAX_BIN_COUNT + 1,
        ),
        Err(MarketTypeError::BinsExceeded {
            count: MAX_BIN_COUNT + 1,
            max: MAX_BIN_COUNT,
        })
    );

    // 5. Overbound delta inputs exceeding MAX_BIN_DELTA_BINS
    let mut huge_bins = Vec::new();
    for i in 1..=(MAX_BIN_DELTA_BINS + 1) {
        huge_bins.push(LiquidityBin::new(
            (i as i32) + 200,
            AtomicAmount::new(10),
            AtomicAmount::ZERO,
        ));
    }
    let overbound_bin_delta = BinPoolDelta::new(None, None, None, huge_bins);
    assert_eq!(
        bin_reducer.apply_delta(
            SequenceRange::point(Sequence(102)).unwrap(),
            1_000_200,
            &overbound_bin_delta,
        ),
        Err(MarketTypeError::BinsExceeded {
            count: MAX_BIN_DELTA_BINS + 1,
            max: MAX_BIN_DELTA_BINS,
        })
    );
}
