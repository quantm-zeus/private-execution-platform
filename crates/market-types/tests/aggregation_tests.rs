//! Focused tests for bounded deterministic OHLCV and depth aggregation (P23 Slice A).
//!
//! Covers:
//! 1. Deterministic window rollup (intra-window merging, window rollover, epoch boundary alignment).
//! 2. Sequence and freshness propagation (monotonic contiguous ordering, duplicate/stale handling, deterministic age/skew evaluation).
//! 3. Bounds and arithmetic overflow enforcement (retained windows, depth levels, bucket limits, volume/trade overflow).
//! 4. Atomic rollback safety (crossed books, target mismatch, malformed bounds preserve pre-failure state).
//! 5. Sticky resync latching and validated recovery (gap/overlap triggers fail-closed resync, cleared only by validated newer snapshot/baseline).
//! 6. Level aggregation / price bucketing and microprice calculations.
//! 7. Unified MarketAggregator coordination.

use chain_types::{AssetId, ChainId};
use market_types::{
    AggregatedDepthBook, AggregatedDepthSnapshot, Candle, CandleTimeframe, CanonicalFeedEnvelope,
    CanonicalFeedPayload, ChainFamily, DeltaClassification, DepthAggregator, DepthDelta,
    DepthLevel, DepthSnapshot, FeedFinality, FeedObservationContext, FeedSourceLabel, FeedTarget,
    FreshnessPolicy, FreshnessStatus, InstrumentId, MarketAggregator, MarketTypeError,
    NormalizedPrice, NormalizedQuantity, OhlcvAggregator, SafeFreshnessMeta, Sequence,
    SequenceRange, SnapshotClassification, MAX_AGGREGATED_BUCKETS, MAX_DEPTH_LEVELS,
    MAX_RETAINED_WINDOWS,
};

fn sample_instrument() -> InstrumentId {
    let base = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let quote = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();
    InstrumentId::new(base, quote).unwrap()
}

fn other_instrument() -> InstrumentId {
    let base = AssetId::new(
        ChainId::Solana,
        "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So",
    )
    .unwrap();
    let quote = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();
    InstrumentId::new(base, quote).unwrap()
}

fn sample_target() -> FeedTarget {
    FeedTarget::Instrument(sample_instrument())
}

fn price(v: f64) -> NormalizedPrice {
    NormalizedPrice::new(v).unwrap()
}

fn qty(v: f64) -> NormalizedQuantity {
    NormalizedQuantity::new(v).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn make_candle(
    instrument: InstrumentId,
    timeframe: CandleTimeframe,
    open_ms: i64,
    close_ms: i64,
    o: f64,
    h: f64,
    l: f64,
    c: f64,
    v: f64,
    quote_v: Option<f64>,
    trades: Option<u64>,
) -> Candle {
    Candle {
        instrument,
        timeframe,
        open_time_ms: open_ms,
        close_time_ms: close_ms,
        open: price(o),
        high: price(h),
        low: price(l),
        close: price(c),
        volume: qty(v),
        quote_volume: quote_v.map(qty),
        trades_count: trades,
    }
}

fn sample_snapshot(seq: u64, ts: i64) -> DepthSnapshot {
    DepthSnapshot {
        target: sample_target(),
        sequence: Sequence(seq),
        timestamp_ms: ts,
        bids: vec![
            DepthLevel::new(price(150.0), qty(10.0)),
            DepthLevel::new(price(149.0), qty(20.0)),
            DepthLevel::new(price(148.0), qty(30.0)),
        ],
        asks: vec![
            DepthLevel::new(price(151.0), qty(15.0)),
            DepthLevel::new(price(152.0), qty(25.0)),
            DepthLevel::new(price(153.0), qty(35.0)),
        ],
    }
}

fn sample_delta(
    start: u64,
    end: u64,
    ts: i64,
    bids: Vec<DepthLevel>,
    asks: Vec<DepthLevel>,
) -> DepthDelta {
    DepthDelta {
        target: sample_target(),
        sequence_range: SequenceRange::new(Sequence(start), Sequence(end)).unwrap(),
        timestamp_ms: ts,
        bids,
        asks,
    }
}

// =========================================================================
// Group 1: Deterministic Window Rollup
// =========================================================================

#[test]
fn test_ohlcv_intra_window_rollup() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M5, 100).unwrap();

    // Ingest 3 1-minute candles in the [300_000, 600_000) window
    let c1 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        300_000,
        360_000,
        150.0,
        152.0,
        149.0,
        151.0,
        10.0,
        Some(1505.0),
        Some(5),
    );
    let c2 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        360_000,
        420_000,
        151.0,
        155.0,
        150.5,
        154.0,
        20.0,
        Some(3060.0),
        Some(8),
    );
    let c3 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        420_000,
        480_000,
        154.0,
        154.5,
        147.0,
        148.0,
        30.0,
        Some(4500.0),
        Some(12),
    );

    assert_eq!(
        agg.apply_candle(&c1, Some(Sequence(1))).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(1)
        }
    );
    assert_eq!(
        agg.apply_candle(&c2, Some(Sequence(2))).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(2)
        }
    );
    assert_eq!(
        agg.apply_candle(&c3, Some(Sequence(3))).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(3)
        }
    );

    let active = agg.active_window().unwrap();
    assert_eq!(active.open_time_ms, 300_000);
    assert_eq!(active.close_time_ms, 600_000);
    assert_eq!(active.open, price(150.0));
    assert_eq!(active.high, price(155.0)); // max(152, 155, 154.5)
    assert_eq!(active.low, price(147.0)); // min(149, 150.5, 147)
    assert_eq!(active.close, price(148.0)); // last close
    assert_eq!(active.volume, qty(60.0)); // 10 + 20 + 30
    assert_eq!(active.quote_volume, Some(qty(9065.0)));
    assert_eq!(active.trades_count, Some(25)); // 5 + 8 + 12
    assert_eq!(active.update_count, 3);
    assert_eq!(agg.retained_count(), 0);
}

#[test]
fn test_ohlcv_window_rollover_and_bounded_retention() {
    let inst = sample_instrument();
    let max_windows = 3;
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M1, max_windows).unwrap();

    // Window 1: [60_000, 120_000)
    let c1 = make_candle(
        inst.clone(),
        CandleTimeframe::S15,
        60_000,
        75_000,
        100.0,
        105.0,
        99.0,
        102.0,
        10.0,
        None,
        Some(2),
    );
    agg.apply_candle(&c1, Some(Sequence(1))).unwrap();

    // Window 2: [120_000, 180_000) -> triggers rollover of window 1
    let c2 = make_candle(
        inst.clone(),
        CandleTimeframe::S15,
        120_000,
        135_000,
        102.0,
        106.0,
        101.0,
        104.0,
        15.0,
        None,
        Some(3),
    );
    agg.apply_candle(&c2, Some(Sequence(2))).unwrap();

    assert_eq!(agg.retained_count(), 1);
    let finalized_1 = &agg.retained_candles()[0];
    assert_eq!(finalized_1.open_time_ms, 60_000);
    assert_eq!(finalized_1.close_time_ms, 120_000);
    assert_eq!(finalized_1.open, price(100.0));
    assert_eq!(finalized_1.close, price(102.0));

    // Window 3: [180_000, 240_000) -> triggers rollover of window 2
    let c3 = make_candle(
        inst.clone(),
        CandleTimeframe::S15,
        180_000,
        195_000,
        104.0,
        108.0,
        103.0,
        107.0,
        20.0,
        None,
        Some(4),
    );
    agg.apply_candle(&c3, Some(Sequence(3))).unwrap();
    assert_eq!(agg.retained_count(), 2);

    // Window 4: [240_000, 300_000) -> triggers rollover of window 3
    let c4 = make_candle(
        inst.clone(),
        CandleTimeframe::S15,
        240_000,
        255_000,
        107.0,
        110.0,
        106.0,
        109.0,
        25.0,
        None,
        Some(5),
    );
    agg.apply_candle(&c4, Some(Sequence(4))).unwrap();
    assert_eq!(agg.retained_count(), 3);

    // Window 5: [300_000, 360_000) -> triggers rollover of window 4 and FIFO drops window 1 (cap = 3)
    let c5 = make_candle(
        inst.clone(),
        CandleTimeframe::S15,
        300_000,
        315_000,
        109.0,
        112.0,
        108.0,
        111.0,
        30.0,
        None,
        Some(6),
    );
    let res5 = agg.apply_candle(&c5, Some(Sequence(5))).unwrap();
    assert_eq!(
        res5,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(5)
        }
    );
    assert_eq!(agg.retained_count(), 3);

    // Verify oldest is now window 2 [120_000, 180_000)
    assert_eq!(agg.retained_candles()[0].open_time_ms, 120_000);
    assert_eq!(agg.retained_candles()[1].open_time_ms, 180_000);
    assert_eq!(agg.retained_candles()[2].open_time_ms, 240_000);
}

#[test]
fn test_ohlcv_rejects_crossing_timeframe_boundary() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M1, 10).unwrap();

    // 1-minute window boundaries are [60_000, 120_000), [120_000, 180_000)
    // A candle starting at 90_000 and ending at 150_000 crosses the 120_000 boundary
    let crossing = make_candle(
        inst.clone(),
        CandleTimeframe::Custom(60_000),
        90_000,
        150_000,
        100.0,
        105.0,
        95.0,
        102.0,
        10.0,
        None,
        None,
    );
    let res = agg.apply_candle(&crossing, Some(Sequence(1)));
    assert_eq!(
        res,
        Err(MarketTypeError::InvalidCandleBounds {
            reason: "candle window crosses aggregation timeframe boundary"
        })
    );
    assert!(agg.active_window().is_none());
}

#[test]
fn test_ohlcv_stale_candle_window_rejected_fail_closed() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M5, 10).unwrap();

    // First candle in [300_000, 600_000)
    let c1 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        300_000,
        360_000,
        100.0,
        102.0,
        99.0,
        101.0,
        10.0,
        None,
        None,
    );
    agg.apply_candle(&c1, Some(Sequence(1))).unwrap();

    // Second candle belongs to an earlier window [0, 300_000)
    let c_stale = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        100_000,
        160_000,
        98.0,
        100.0,
        97.0,
        99.0,
        5.0,
        None,
        None,
    );
    let res = agg.apply_candle(&c_stale, Some(Sequence(2)));
    assert_eq!(
        res,
        Err(MarketTypeError::StaleCandleWindow {
            candle_open_ms: 100_000,
            current_close_ms: 600_000,
        })
    );

    // State is strictly unchanged
    let active = agg.active_window().unwrap();
    assert_eq!(active.open_time_ms, 300_000);
    assert_eq!(active.update_count, 1);
}

// =========================================================================
// Group 2: Sequence and Freshness Propagation
// =========================================================================

#[test]
fn test_depth_sequence_advancement_and_stale_duplicate() {
    let mut agg = DepthAggregator::new(sample_target(), 100).unwrap();
    let snap = sample_snapshot(100, 1_000_000);
    agg.apply_snapshot(&snap).unwrap();

    assert_eq!(agg.sequence(), Some(Sequence(100)));

    // Stale delta (< 100)
    let d_stale = sample_delta(90, 95, 950_000, vec![], vec![]);
    assert_eq!(
        agg.apply_delta(&d_stale).unwrap(),
        DeltaClassification::Stale {
            sequence: Sequence(95),
            current: Sequence(100),
        }
    );

    // Duplicate delta (== 100)
    let d_dup = sample_delta(98, 100, 1_000_000, vec![], vec![]);
    assert_eq!(
        agg.apply_delta(&d_dup).unwrap(),
        DeltaClassification::Duplicate {
            sequence: Sequence(100),
        }
    );

    // Contiguous delta (101)
    let d_cont = sample_delta(
        101,
        101,
        1_001_000,
        vec![DepthLevel::new(price(150.5), qty(5.0))],
        vec![],
    );
    assert_eq!(
        agg.apply_delta(&d_cont).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(101),
        }
    );
    assert_eq!(agg.sequence(), Some(Sequence(101)));
}

#[test]
fn test_deterministic_freshness_evaluation_without_wall_clock() {
    let mut agg = DepthAggregator::new(sample_target(), 50).unwrap();
    let policy = FreshnessPolicy::new(5_000, 1_000).unwrap(); // 5s max staleness, 1s max future skew
    agg = agg.with_freshness_policy(policy).unwrap();

    // Baseline observed at 10_000 ms
    let snap = sample_snapshot(1, 10_000);
    agg.apply_snapshot(&snap).unwrap();

    // 1. Fresh evaluation at 12_000 ms (age = 2_000 ms <= 5_000 ms)
    let meta_fresh = agg.evaluate_freshness(12_000).unwrap();
    assert_eq!(meta_fresh.status, FreshnessStatus::Fresh);
    assert_eq!(meta_fresh.age_ms, 2_000);
    assert_eq!(meta_fresh.sequence, Sequence(1));

    // 2. Stale evaluation at 16_000 ms (age = 6_000 ms > 5_000 ms)
    let meta_stale = agg.evaluate_freshness(16_000).unwrap();
    assert_eq!(meta_stale.status, FreshnessStatus::Stale);
    assert_eq!(meta_stale.age_ms, 6_000);

    // 3. Negative age (future observation within allowed skew of 1_000 ms):
    // observed = 10_000, evaluated = 9_500 (skew = 500 ms <= 1_000 ms) -> Fresh
    let meta_skew_ok = agg.evaluate_freshness(9_500).unwrap();
    assert_eq!(meta_skew_ok.status, FreshnessStatus::Fresh);
    assert_eq!(meta_skew_ok.age_ms, 0);

    // 4. Excessive future skew: observed = 10_000, evaluated = 8_000 (skew = 2_000 ms > 1_000 ms) -> ResyncRequired
    let meta_skew_excess = agg.evaluate_freshness(8_000).unwrap();
    assert_eq!(meta_skew_excess.status, FreshnessStatus::ResyncRequired);

    // 5. When resync is latched -> always ResyncRequired regardless of timestamp
    agg.trigger_resync();
    let meta_resync = agg.evaluate_freshness(10_100).unwrap();
    assert_eq!(meta_resync.status, FreshnessStatus::ResyncRequired);
}

// =========================================================================
// Group 3: Bounds and Overflow Enforcement
// =========================================================================

#[test]
fn test_configuration_bounds_enforced_fail_closed() {
    let inst = sample_instrument();

    // OHLCV max_retained_windows 0 fails
    assert_eq!(
        OhlcvAggregator::new(inst.clone(), CandleTimeframe::M1, 0),
        Err(MarketTypeError::RetainedWindowsExceeded {
            count: 0,
            max: MAX_RETAINED_WINDOWS
        })
    );

    // OHLCV max_retained_windows > 10_000 fails
    assert_eq!(
        OhlcvAggregator::new(inst.clone(), CandleTimeframe::M1, MAX_RETAINED_WINDOWS + 1),
        Err(MarketTypeError::RetainedWindowsExceeded {
            count: MAX_RETAINED_WINDOWS + 1,
            max: MAX_RETAINED_WINDOWS
        })
    );

    // DepthAggregator max_levels 0 fails
    assert_eq!(
        DepthAggregator::new(sample_target(), 0),
        Err(MarketTypeError::DepthLevelsExceeded {
            count: 0,
            max: MAX_DEPTH_LEVELS
        })
    );

    // DepthAggregator max_levels > 5_000 fails
    assert_eq!(
        DepthAggregator::new(sample_target(), MAX_DEPTH_LEVELS + 1),
        Err(MarketTypeError::DepthLevelsExceeded {
            count: MAX_DEPTH_LEVELS + 1,
            max: MAX_DEPTH_LEVELS
        })
    );
}

#[test]
fn test_ohlcv_arithmetic_overflow_fails_closed_with_state_intact() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M5, 10).unwrap();

    let c1 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        300_000,
        360_000,
        100.0,
        105.0,
        95.0,
        102.0,
        1.0e308,
        None,
        Some(u64::MAX - 2),
    );
    agg.apply_candle(&c1, Some(Sequence(1))).unwrap();

    // Ingest candle that would cause trade count u64 overflow
    let c_overflow_trades = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        360_000,
        420_000,
        102.0,
        104.0,
        101.0,
        103.0,
        10.0,
        None,
        Some(5),
    );
    let err_trades = agg.apply_candle(&c_overflow_trades, Some(Sequence(2)));
    assert_eq!(
        err_trades,
        Err(MarketTypeError::ArithmeticOverflow("trades count overflow"))
    );

    // Verify active window was rolled back and is completely unchanged
    let active = agg.active_window().unwrap();
    assert_eq!(active.volume.get(), 1.0e308);
    assert_eq!(active.trades_count, Some(u64::MAX - 2));
    assert_eq!(active.update_count, 1);
    assert_eq!(agg.current_sequence(), Some(Sequence(1)));

    // Ingest candle that would cause volume overflow (1.0e308 + 1.0e308 = inf)
    let c_overflow_vol = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        360_000,
        420_000,
        102.0,
        104.0,
        101.0,
        103.0,
        1.0e308,
        None,
        Some(1),
    );
    let err_vol = agg.apply_candle(&c_overflow_vol, Some(Sequence(2)));
    assert_eq!(
        err_vol,
        Err(MarketTypeError::ArithmeticOverflow(
            "candle volume accumulation overflow"
        ))
    );

    // State remains untouched
    assert_eq!(agg.active_window().unwrap().update_count, 1);
}

// =========================================================================
// Group 4: Atomic Rollback Safety
// =========================================================================

#[test]
fn test_depth_delta_crossed_order_book_rolls_back_completely() {
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();
    let snap = sample_snapshot(10, 1_000_000); // best_bid = 150.0, best_ask = 151.0
    agg.apply_snapshot(&snap).unwrap();

    let initial_bids = agg.bids().to_vec();
    let initial_asks = agg.asks().to_vec();

    // Delta that moves bid to 152.0, crossing ask 151.0
    let bad_delta = sample_delta(
        11,
        11,
        1_001_000,
        vec![DepthLevel::new(price(152.0), qty(10.0))],
        vec![],
    );

    let res = agg.apply_delta(&bad_delta);
    assert_eq!(res, Err(MarketTypeError::CrossedOrderBook));

    // Verify full rollback: bids, asks, sequence, timestamp strictly untouched
    assert_eq!(agg.bids(), initial_bids.as_slice());
    assert_eq!(agg.asks(), initial_asks.as_slice());
    assert_eq!(agg.sequence(), Some(Sequence(10)));
    assert_eq!(agg.timestamp_ms(), Some(1_000_000));
}

#[test]
fn test_aggregation_target_mismatch_fails_closed_state_unchanged() {
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();
    agg.apply_snapshot(&sample_snapshot(1, 1000)).unwrap();

    let wrong_target_snap = DepthSnapshot {
        target: FeedTarget::Instrument(other_instrument()),
        sequence: Sequence(2),
        timestamp_ms: 2000,
        bids: vec![DepthLevel::new(price(20.0), qty(1.0))],
        asks: vec![DepthLevel::new(price(21.0), qty(1.0))],
    };

    let res = agg.apply_snapshot(&wrong_target_snap);
    assert_eq!(res, Err(MarketTypeError::TargetMismatch));
    assert_eq!(agg.sequence(), Some(Sequence(1)));

    let wrong_target_delta = DepthDelta {
        target: FeedTarget::Instrument(other_instrument()),
        sequence_range: SequenceRange::new(Sequence(2), Sequence(2)).unwrap(),
        timestamp_ms: 2000,
        bids: vec![],
        asks: vec![],
    };

    let res_delta = agg.apply_delta(&wrong_target_delta);
    assert_eq!(res_delta, Err(MarketTypeError::TargetMismatch));
    assert_eq!(agg.sequence(), Some(Sequence(1)));
}

// =========================================================================
// Group 5: Sticky Resync Latching and Validated Recovery
// =========================================================================

#[test]
fn test_depth_gap_and_overlap_latches_sticky_resync_and_recovers_via_snapshot() {
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();
    agg.apply_snapshot(&sample_snapshot(100, 1_000_000))
        .unwrap();

    // 1. Enforce sequence gap: current = 100, incoming = 102..102 (expected 101)
    let gap_delta = sample_delta(
        102,
        102,
        1_002_000,
        vec![DepthLevel::new(price(150.1), qty(2.0))],
        vec![],
    );
    let gap_res = agg.apply_delta(&gap_delta).unwrap();
    assert_eq!(
        gap_res,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(102),
        }
    );
    assert!(agg.is_resync_required());
    assert_eq!(agg.sequence(), Some(Sequence(100))); // State did NOT advance!

    // 2. While latched, even a contiguous delta (101..101) is rejected
    let cont_delta = sample_delta(101, 101, 1_001_000, vec![], vec![]);
    let rej_res = agg.apply_delta(&cont_delta).unwrap();
    assert_eq!(
        rej_res,
        DeltaClassification::ResyncRequired {
            expected: Sequence(101),
            received: Sequence(101),
        }
    );

    // 3. Stale snapshot (95 < 100) does NOT clear the latch
    let stale_snap = sample_snapshot(95, 950_000);
    assert_eq!(
        agg.apply_snapshot(&stale_snap).unwrap(),
        SnapshotClassification::Stale {
            sequence: Sequence(95),
            current: Sequence(100),
        }
    );
    assert!(agg.is_resync_required());

    // 4. Duplicate snapshot (100) does NOT clear the latch
    let dup_snap = sample_snapshot(100, 1_000_000);
    assert_eq!(
        agg.apply_snapshot(&dup_snap).unwrap(),
        SnapshotClassification::Duplicate {
            sequence: Sequence(100),
        }
    );
    assert!(agg.is_resync_required());

    // 5. Validated newer snapshot (110 > 100) CLEARS latch and restores normal operation!
    let fresh_snap = sample_snapshot(110, 1_100_000);
    assert_eq!(
        agg.apply_snapshot(&fresh_snap).unwrap(),
        SnapshotClassification::Accepted {
            new_sequence: Sequence(110),
        }
    );
    assert!(!agg.is_resync_required());
    assert_eq!(agg.sequence(), Some(Sequence(110)));

    // 6. Contiguous delta (111..111) is now accepted normally!
    let next_delta = sample_delta(
        111,
        111,
        1_101_000,
        vec![DepthLevel::new(price(150.2), qty(3.0))],
        vec![],
    );
    assert_eq!(
        agg.apply_delta(&next_delta).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(111),
        }
    );
    assert_eq!(agg.sequence(), Some(Sequence(111)));

    // 7. Unaligned sequence overlap (start <= current < end): 110..112 when current is 111
    let overlap_delta = sample_delta(110, 112, 1_102_000, vec![], vec![]);
    let overlap_res = agg.apply_delta(&overlap_delta).unwrap();
    assert_eq!(
        overlap_res,
        DeltaClassification::ResyncRequired {
            expected: Sequence(112),
            received: Sequence(110),
        }
    );
    assert!(agg.is_resync_required());
    assert_eq!(agg.sequence(), Some(Sequence(111))); // state untouched
}

#[test]
fn test_ohlcv_gap_latches_resync_and_recovers_via_baseline() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M5, 10).unwrap();

    let c1 = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        300_000,
        360_000,
        100.0,
        102.0,
        99.0,
        101.0,
        10.0,
        None,
        None,
    );
    agg.apply_candle(&c1, Some(Sequence(10))).unwrap();
    assert_eq!(agg.current_sequence(), Some(Sequence(10)));

    // Candle with sequence gap: arrives with sequence 15 (expected 11)
    let c_gap = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        360_000,
        420_000,
        101.0,
        103.0,
        100.0,
        102.0,
        10.0,
        None,
        None,
    );
    let gap_res = agg.apply_candle(&c_gap, Some(Sequence(15))).unwrap();
    assert_eq!(
        gap_res,
        DeltaClassification::ResyncRequired {
            expected: Sequence(11),
            received: Sequence(15),
        }
    );
    assert!(agg.is_resync_required());

    // Normal candle is rejected while resync is latched
    let c_norm = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        420_000,
        480_000,
        102.0,
        104.0,
        101.0,
        103.0,
        10.0,
        None,
        None,
    );
    let rej = agg.apply_candle(&c_norm, Some(Sequence(11))).unwrap();
    assert!(matches!(rej, DeltaClassification::ResyncRequired { .. }));

    // Validated recovery via reset_with_baseline with newer sequence 20 clears latch
    let c_baseline = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        480_000,
        540_000,
        105.0,
        107.0,
        104.0,
        106.0,
        12.0,
        None,
        None,
    );
    agg.reset_with_baseline(Sequence(20), &c_baseline).unwrap();

    assert!(!agg.is_resync_required());
    assert_eq!(agg.current_sequence(), Some(Sequence(20)));

    // Next contiguous candle (seq 21) accepted
    let c_next = make_candle(
        inst.clone(),
        CandleTimeframe::M1,
        540_000,
        600_000,
        106.0,
        108.0,
        105.0,
        107.0,
        15.0,
        None,
        None,
    );
    assert_eq!(
        agg.apply_candle(&c_next, Some(Sequence(21))).unwrap(),
        DeltaClassification::Contiguous {
            new_sequence: Sequence(21)
        }
    );
}

// =========================================================================
// Group 6: Level Aggregation, Cumulative Depth & Microprice
// =========================================================================

#[test]
fn test_depth_tick_size_bucketing_and_cumulative_metrics() {
    let mut agg = DepthAggregator::new(sample_target(), 50).unwrap();

    // Snapshot with un-bucketed fine levels
    let snap = DepthSnapshot {
        target: sample_target(),
        sequence: Sequence(1),
        timestamp_ms: 1_000,
        bids: vec![
            DepthLevel::new(price(100.12), qty(10.0)),
            DepthLevel::new(price(100.08), qty(15.0)),
            DepthLevel::new(price(99.85), qty(20.0)),
            DepthLevel::new(price(99.40), qty(25.0)),
        ],
        asks: vec![
            DepthLevel::new(price(100.55), qty(12.0)),
            DepthLevel::new(price(100.80), qty(18.0)),
            DepthLevel::new(price(101.25), qty(30.0)),
        ],
    };
    agg.apply_snapshot(&snap).unwrap();

    // Aggregate with tick_size = 0.50
    let bucketed = agg.aggregate_by_tick_size(price(0.50), 10).unwrap();
    assert_eq!(bucketed.tick_size, price(0.50));

    // Bids should group to floors of 0.50:
    // 100.12, 100.08 -> bucket 100.00 (qty = 10 + 15 = 25.0, count = 2)
    // 99.85 -> bucket 99.50 (qty = 20.0, count = 1)
    // 99.40 -> bucket 99.00 (qty = 25.0, count = 1)
    assert_eq!(bucketed.bids.len(), 3);
    assert_eq!(bucketed.bids[0].price, price(100.00));
    assert_eq!(bucketed.bids[0].quantity, qty(25.0));
    assert_eq!(bucketed.bids[0].orders_or_levels_count, 2);

    assert_eq!(bucketed.bids[1].price, price(99.50));
    assert_eq!(bucketed.bids[1].quantity, qty(20.0));

    assert_eq!(bucketed.bids[2].price, price(99.00));
    assert_eq!(bucketed.bids[2].quantity, qty(25.0));

    // Asks should group to ceilings of 0.50:
    // 100.55, 100.80 -> bucket 101.00 (qty = 12 + 18 = 30.0, count = 2)
    // 101.25 -> bucket 101.50 (qty = 30.0, count = 1)
    assert_eq!(bucketed.asks.len(), 2);
    assert_eq!(bucketed.asks[0].price, price(101.00));
    assert_eq!(bucketed.asks[0].quantity, qty(30.0));
    assert_eq!(bucketed.asks[0].orders_or_levels_count, 2);

    assert_eq!(bucketed.asks[1].price, price(101.50));
    assert_eq!(bucketed.asks[1].quantity, qty(30.0));

    // Test Cumulative Depth
    let cum_bids = agg.cumulative_bids().unwrap();
    assert_eq!(cum_bids.len(), 4);
    assert_eq!(cum_bids[0].cumulative_quantity, qty(10.0));
    assert_eq!(cum_bids[1].cumulative_quantity, qty(25.0)); // 10 + 15
    assert_eq!(cum_bids[2].cumulative_quantity, qty(45.0)); // 25 + 20
    assert_eq!(cum_bids[3].cumulative_quantity, qty(70.0)); // 45 + 25

    // Total quantity
    assert_eq!(agg.total_bid_quantity().unwrap(), qty(70.0));
    assert_eq!(agg.total_ask_quantity().unwrap(), qty(60.0));

    // Weighted mid price (microprice):
    // best_bid = 100.12 (qty 10.0), best_ask = 100.55 (qty 12.0)
    // num = 100.12 * 12.0 + 100.55 * 10.0 = 1201.44 + 1005.5 = 2206.94
    // denom = 10.0 + 12.0 = 22.0
    // expected = 2206.94 / 22.0 = 100.31545454545455
    let w_mid = agg.weighted_mid_price().unwrap();
    let diff = (w_mid.get() - (2206.94 / 22.0)).abs();
    assert!(diff < 1e-10);
}

// =========================================================================
// Group 7: Unified Market Aggregator Coordination
// =========================================================================

#[test]
fn test_unified_market_aggregator_coordination() {
    let inst = sample_instrument();
    let mut unified =
        MarketAggregator::for_instrument(inst.clone(), CandleTimeframe::M1, 20, 10).unwrap();

    let context = FeedObservationContext {
        source_family: ChainFamily::Solana,
        source_label: FeedSourceLabel::new("solana-direct").unwrap(),
        finality: FeedFinality::Confirmed,
        slot_or_block: Some(100),
        observed_at_ms: 60_000,
    };
    let freshness = SafeFreshnessMeta {
        status: FreshnessStatus::Fresh,
        observed_at_ms: 60_000,
        evaluated_at_ms: 60_100,
        age_ms: 100,
        sequence: Sequence(1),
    };

    // 1. Feed snapshot via CanonicalFeedEnvelope
    let snap = sample_snapshot(1, 60_000);
    let snap_env = CanonicalFeedEnvelope {
        context: context.clone(),
        freshness,
        payload: CanonicalFeedPayload::OrderBookSnapshot(snap),
    };

    let res = unified.apply_envelope(&snap_env).unwrap();
    assert!(matches!(
        res,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(1)
        }
    ));

    // Verify depth updated and OHLCV received mid-price tick
    assert_eq!(unified.depth().sequence(), Some(Sequence(1)));
    assert_eq!(unified.depth().best_bid().unwrap().price, price(150.0));
    assert_eq!(unified.depth().best_ask().unwrap().price, price(151.0));

    let ohlcv_win = unified.ohlcv().unwrap().active_window().unwrap();
    assert_eq!(ohlcv_win.close, price(150.5)); // mid price = (150 + 151) / 2

    // 2. Feed contiguous delta via envelope
    let delta = sample_delta(
        2,
        2,
        61_000,
        vec![DepthLevel::new(price(150.2), qty(12.0))],
        vec![DepthLevel::new(price(150.8), qty(14.0))],
    );
    let delta_env = CanonicalFeedEnvelope {
        context,
        freshness: SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: 61_000,
            evaluated_at_ms: 61_050,
            age_ms: 50,
            sequence: Sequence(2),
        },
        payload: CanonicalFeedPayload::OrderBookDelta(delta),
    };

    let res_delta = unified.apply_envelope(&delta_env).unwrap();
    assert_eq!(
        res_delta,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(2)
        }
    );

    assert_eq!(unified.depth().sequence(), Some(Sequence(2)));
    assert_eq!(unified.depth().best_bid().unwrap().price, price(150.2));
    assert_eq!(unified.depth().best_ask().unwrap().price, price(150.8));

    // Mid price updated: (150.2 + 150.8) / 2 = 150.5
    assert_eq!(unified.depth().mid_price(), Some(price(150.5)));
}

// =========================================================================
// Group 8: Additional Edge Cases & Serialization
// =========================================================================

#[test]
fn test_ohlcv_apply_tick_and_flush_active_window() {
    let inst = sample_instrument();
    let mut agg = OhlcvAggregator::new(inst.clone(), CandleTimeframe::M5, 5).unwrap();

    // Ingest 2 individual price ticks within [300_000, 600_000)
    agg.apply_tick(price(100.0), qty(2.5), 300_000, Some(Sequence(1)))
        .unwrap();
    agg.apply_tick(price(102.5), qty(3.5), 350_000, Some(Sequence(2)))
        .unwrap();

    let active = agg.active_window().unwrap();
    assert_eq!(active.open, price(100.0));
    assert_eq!(active.high, price(102.5));
    assert_eq!(active.low, price(100.0));
    assert_eq!(active.close, price(102.5));
    assert_eq!(active.volume, qty(6.0));
    assert_eq!(active.trades_count, Some(2));
    assert_eq!(agg.retained_count(), 0);

    // Flush active window deterministically
    let flushed = agg.flush_active_window().unwrap();
    assert!(flushed.is_some());
    let c = flushed.unwrap();
    assert_eq!(c.open_time_ms, 300_000);
    assert_eq!(c.close_time_ms, 600_000);
    assert_eq!(c.volume, qty(6.0));
    assert_eq!(agg.retained_count(), 1);
    assert!(agg.active_window().is_none());
}

#[test]
fn test_depth_aggregator_delta_before_baseline_fails_closed() {
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();

    // Try applying a delta when no baseline snapshot was ever established
    let delta = sample_delta(
        1,
        1,
        1000,
        vec![DepthLevel::new(price(100.0), qty(1.0))],
        vec![],
    );
    let res = agg.apply_delta(&delta).unwrap();
    assert_eq!(
        res,
        DeltaClassification::ResyncRequired {
            expected: Sequence(1),
            received: Sequence(1),
        }
    );
    assert!(agg.is_resync_required());
    assert!(agg.sequence().is_none());
}

#[test]
fn test_depth_tick_bucketing_bounds_exceeded() {
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();
    agg.apply_snapshot(&sample_snapshot(1, 1000)).unwrap();

    // 0 buckets fails
    assert_eq!(
        agg.aggregate_by_tick_size(price(1.0), 0),
        Err(MarketTypeError::AggregatedBucketsExceeded {
            count: 0,
            max: MAX_AGGREGATED_BUCKETS,
        })
    );

    // > MAX_AGGREGATED_BUCKETS fails
    assert_eq!(
        agg.aggregate_by_tick_size(price(1.0), MAX_AGGREGATED_BUCKETS + 1),
        Err(MarketTypeError::AggregatedBucketsExceeded {
            count: MAX_AGGREGATED_BUCKETS + 1,
            max: MAX_AGGREGATED_BUCKETS,
        })
    );
}

#[test]
fn test_serialization_round_trips_for_aggregated_types() {
    let snap = sample_snapshot(42, 500_000);
    let mut agg = DepthAggregator::new(sample_target(), 10).unwrap();
    agg.apply_snapshot(&snap).unwrap();

    let agg_snap = agg.to_aggregated_snapshot(501_000).unwrap();
    let json = serde_json::to_string(&agg_snap).unwrap();
    let decoded: AggregatedDepthSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.sequence, agg_snap.sequence);
    assert_eq!(decoded.timestamp_ms, agg_snap.timestamp_ms);
    assert_eq!(decoded.bids, agg_snap.bids);
    assert_eq!(decoded.asks, agg_snap.asks);
    assert_eq!(decoded.total_bid_quantity, agg_snap.total_bid_quantity);

    let bucketed = agg.aggregate_by_tick_size(price(1.0), 10).unwrap();
    let json_b = serde_json::to_string(&bucketed).unwrap();
    let decoded_b: AggregatedDepthBook = serde_json::from_str(&json_b).unwrap();
    assert_eq!(decoded_b.tick_size, bucketed.tick_size);
    assert_eq!(decoded_b.bids, bucketed.bids);
}
