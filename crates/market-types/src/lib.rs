//! Lossless canonical market data contracts and local pool state types.

pub mod error;
pub mod freshness;
pub mod identity;
pub mod ohlcv;
pub mod orderbook;
pub mod pool;
pub mod primitives;
pub mod sequence;

pub use error::MarketTypeError;
pub use freshness::{
    evaluate_freshness, FreshnessPolicy, FreshnessStatus, SafeFreshnessMeta,
    DEFAULT_MAX_FUTURE_SKEW_MS, DEFAULT_MAX_STALENESS_MS, MAX_POLICY_FUTURE_SKEW_MS,
    MAX_POLICY_STALENESS_MS, MIN_POLICY_STALENESS_MS,
};
pub use identity::{FeedTarget, InstrumentId, PoolId};
pub use ohlcv::{Candle, CandleTimeframe, MAX_CANDLE_WINDOW_MS};
pub use orderbook::{
    DepthDelta, DepthLevel, DepthSnapshot, NormalizedPrice, NormalizedQuantity, OrderBookDepth,
    MAX_DEPTH_LEVELS,
};
pub use pool::{
    BinPoolState, ClmmPoolState, ClmmTick, CpmmPoolState, LiquidityBin, PoolKindState,
    PoolStateEnvelope, MAX_BIN_COUNT, MAX_BIN_ID, MAX_BIN_STEP_BPS, MAX_CLMM_TICKS, MAX_DECIMALS,
    MAX_TICK, MIN_BIN_ID, MIN_TICK,
};
pub use primitives::{AssetAmount, AtomicAmount, Bps, Freshness, PriceRatio, Sequence, Version};
pub use sequence::{
    DeltaClassification, SequenceRange, SequencedDelta, SequencedSnapshot, SequencedStreamTracker,
    SnapshotClassification,
};

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::{AssetId, ChainId};

    // --- Original Lossless Primitives Tests (Backwards Compatibility) ---

    #[test]
    fn bps_bounds_are_enforced() {
        assert_eq!(Bps::new(10_000).unwrap().get(), 10_000);
        assert_eq!(
            Bps::new(10_001),
            Err(MarketTypeError::BpsOutOfRange(10_001))
        );
    }

    #[test]
    fn price_ratio_rejects_zero_sides() {
        assert_eq!(
            PriceRatio::new(0, 1),
            Err(MarketTypeError::ZeroPriceNumerator)
        );
        assert_eq!(
            PriceRatio::new(1, 0),
            Err(MarketTypeError::ZeroPriceDenominator)
        );
    }

    #[test]
    fn price_round_trip_is_lossless() {
        let price = PriceRatio::new(u128::MAX - 7, 1_000_000_000_000_000_000).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        let decoded: PriceRatio = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, price);
    }

    #[test]
    fn bps_rejects_out_of_range_json() {
        assert!(serde_json::from_str::<Bps>("10001").is_err());
        assert!(serde_json::from_str::<Bps>("10000").is_ok());
    }

    #[test]
    fn price_ratio_rejects_zero_sides_in_json() {
        let zero_num = serde_json::from_str::<PriceRatio>(
            r#"{"numerator_atomic": 0, "denominator_atomic": 1}"#,
        );
        assert_eq!(
            zero_num.unwrap_err().to_string(),
            MarketTypeError::ZeroPriceNumerator.to_string()
        );
        let zero_den = serde_json::from_str::<PriceRatio>(
            r#"{"numerator_atomic": 1, "denominator_atomic": 0}"#,
        );
        assert_eq!(
            zero_den.unwrap_err().to_string(),
            MarketTypeError::ZeroPriceDenominator.to_string()
        );
    }

    #[test]
    fn version_rejects_zero_json() {
        assert!(serde_json::from_str::<Version>("0").is_err());
        assert!(serde_json::from_str::<Version>("1").is_ok());
    }

    #[test]
    fn bps_round_trip_is_lossless() {
        for value in [0u16, 1, 9_999, 10_000] {
            let bps = Bps::new(value).unwrap();
            let json = serde_json::to_string(&bps).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: Bps = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, bps);
        }
    }

    #[test]
    fn version_round_trip_is_lossless() {
        for value in [1u64, u64::MAX - 1, u64::MAX] {
            let version = Version::new(value).unwrap();
            let json = serde_json::to_string(&version).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: Version = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, version);
        }
    }

    #[test]
    fn atomic_amount_round_trip_is_lossless() {
        for value in [0u128, 1, u128::MAX] {
            let amount = AtomicAmount::new(value);
            let json = serde_json::to_string(&amount).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: AtomicAmount = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, amount);
        }
    }

    #[test]
    fn price_ratio_json_shape_is_preserved() {
        let price = PriceRatio::new(123, 456).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        assert_eq!(json, r#"{"numerator_atomic":123,"denominator_atomic":456}"#);
    }

    #[test]
    fn high_u128_price_ratio_round_trip_is_lossless() {
        let price = PriceRatio::new(u128::MAX, u128::MAX - 1).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        let decoded: PriceRatio = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.numerator_atomic(), u128::MAX);
        assert_eq!(decoded.denominator_atomic(), u128::MAX - 1);
    }

    // --- Helpers for New Contract Tests ---

    fn sample_pool_id() -> PoolId {
        PoolId::new(
            ChainId::Solana,
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        )
        .unwrap()
    }

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

    // --- Contract 1: Sequenced Market Snapshots/Deltas & Gap-Resync ---

    #[test]
    fn pool_id_and_instrument_id_validation() {
        assert_eq!(
            PoolId::new(ChainId::Solana, "   "),
            Err(MarketTypeError::EmptyAddress)
        );

        let sol = AssetId::new(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        )
        .unwrap();
        let eth_asset = AssetId::new(
            ChainId::Ethereum,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        .unwrap();
        assert_eq!(
            InstrumentId::new(sol.clone(), eth_asset),
            Err(MarketTypeError::ChainMismatch)
        );
        assert_eq!(
            InstrumentId::new(sol.clone(), sol.clone()),
            Err(MarketTypeError::SameAssetPair)
        );
    }

    #[test]
    fn sequence_range_bounds_validation() {
        assert_eq!(
            SequenceRange::new(Sequence(0), Sequence(10)),
            Err(MarketTypeError::ZeroSequence)
        );
        assert_eq!(
            SequenceRange::new(Sequence(10), Sequence(5)),
            Err(MarketTypeError::InvalidSequenceRange { start: 10, end: 5 })
        );
        let range = SequenceRange::new(Sequence(5), Sequence(10)).unwrap();
        assert_eq!(range.len(), 6);
        assert!(range.contains(Sequence(5)));
        assert!(range.contains(Sequence(7)));
        assert!(range.contains(Sequence(10)));
        assert!(!range.contains(Sequence(4)));
        assert!(!range.contains(Sequence(11)));
    }

    #[test]
    fn stream_tracker_contiguous_ordering_and_classifications() {
        let target = FeedTarget::Pool(sample_pool_id());
        let mut tracker = SequencedStreamTracker::new(target);

        // Applying delta before snapshot baseline must require resync (fail-closed)
        let early_delta = SequenceRange::new(Sequence(1), Sequence(1)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(early_delta, 1000),
            DeltaClassification::ResyncRequired {
                expected: Sequence(1),
                received: Sequence(1)
            }
        );
        assert!(tracker.is_resync_required());

        // Snapshot baseline establishes sequence
        let snap_outcome = tracker.apply_snapshot_sequence(Sequence(100), 1000);
        assert_eq!(
            snap_outcome,
            SnapshotClassification::Accepted {
                new_sequence: Sequence(100)
            }
        );
        assert!(!tracker.is_resync_required());
        assert_eq!(tracker.current_sequence(), Some(Sequence(100)));

        // Applying older snapshot is classified Stale
        assert_eq!(
            tracker.apply_snapshot_sequence(Sequence(99), 1001),
            SnapshotClassification::Stale {
                sequence: Sequence(99),
                current: Sequence(100)
            }
        );

        // Applying identical snapshot is classified Duplicate
        assert_eq!(
            tracker.apply_snapshot_sequence(Sequence(100), 1002),
            SnapshotClassification::Duplicate {
                sequence: Sequence(100)
            }
        );

        // Contiguous single delta [101, 101] advances sequence to 101
        let d101 = SequenceRange::point(Sequence(101)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(d101, 1003),
            DeltaClassification::Contiguous {
                new_sequence: Sequence(101)
            }
        );
        assert_eq!(tracker.current_sequence(), Some(Sequence(101)));

        // Duplicate delta [101, 101] classified idempotently
        assert_eq!(
            tracker.apply_delta_range(d101, 1004),
            DeltaClassification::Duplicate {
                sequence: Sequence(101)
            }
        );
        assert_eq!(tracker.current_sequence(), Some(Sequence(101)));

        // Stale delta [90, 100] classified idempotently
        let stale_range = SequenceRange::new(Sequence(90), Sequence(100)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(stale_range, 1005),
            DeltaClassification::Stale {
                sequence: Sequence(100),
                current: Sequence(101)
            }
        );
        assert_eq!(tracker.current_sequence(), Some(Sequence(101)));

        // Contiguous multi-delta range [102, 105] advances sequence to 105
        let range_102_105 = SequenceRange::new(Sequence(102), Sequence(105)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(range_102_105, 1006),
            DeltaClassification::Contiguous {
                new_sequence: Sequence(105)
            }
        );
        assert_eq!(tracker.current_sequence(), Some(Sequence(105)));

        // Sequence Gap [107, 107] (missing 106) fails-closed with ResyncRequired
        let gap_delta = SequenceRange::point(Sequence(107)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(gap_delta, 1007),
            DeltaClassification::ResyncRequired {
                expected: Sequence(106),
                received: Sequence(107)
            }
        );
        assert!(tracker.is_resync_required());

        // Subsequent deltas must fail-closed while resync is required, never interpolate
        let next_delta = SequenceRange::point(Sequence(108)).unwrap();
        assert_eq!(
            tracker.apply_delta_range(next_delta, 1008),
            DeltaClassification::ResyncRequired {
                expected: Sequence(106),
                received: Sequence(108)
            }
        );

        // Fresh snapshot baseline clears resync flag
        let fresh_snap = tracker.apply_snapshot_sequence(Sequence(200), 2000);
        assert_eq!(
            fresh_snap,
            SnapshotClassification::Accepted {
                new_sequence: Sequence(200)
            }
        );
        assert!(!tracker.is_resync_required());
        assert_eq!(tracker.current_sequence(), Some(Sequence(200)));
    }

    #[test]
    fn property_contiguous_progression_1000_steps() {
        let target = FeedTarget::Instrument(sample_instrument());
        let mut tracker = SequencedStreamTracker::new(target);
        tracker.apply_snapshot_sequence(Sequence(1), 1_000_000);

        let mut current_seq = 1u64;
        let mut timestamp = 1_000_000i64;

        for step in 1..=1000 {
            let start = Sequence(current_seq + 1);
            let span = (step % 5) as u64; // spans of 0, 1, 2, 3, 4
            let end = Sequence(start.0 + span);
            let range = SequenceRange::new(start, end).unwrap();

            timestamp += 100;
            let outcome = tracker.apply_delta_range(range, timestamp);

            assert_eq!(
                outcome,
                DeltaClassification::Contiguous { new_sequence: end }
            );
            assert_eq!(tracker.current_sequence(), Some(end));
            assert!(!tracker.is_resync_required());

            current_seq = end.0;
        }
        assert_eq!(tracker.current_sequence().unwrap().0, current_seq);
    }

    // --- Contract 2: Deterministic Freshness Policy & Transitions ---

    #[test]
    fn freshness_policy_bounds_validation() {
        assert!(FreshnessPolicy::new(0, 1000).is_err());
        assert!(FreshnessPolicy::new(MAX_POLICY_STALENESS_MS + 1, 1000).is_err());
        assert!(FreshnessPolicy::new(1000, MAX_POLICY_FUTURE_SKEW_MS + 1).is_err());
        assert!(FreshnessPolicy::new(5000, 2000).is_ok());
    }

    #[test]
    fn freshness_transitions_without_wall_clock() {
        let policy = FreshnessPolicy::new(10_000, 2_000).unwrap();
        let seq = Sequence(42);

        // Invalid timestamps rejected
        assert_eq!(
            evaluate_freshness(&policy, 0, 1000, seq, false),
            Err(MarketTypeError::InvalidTimestamp(0))
        );
        assert_eq!(
            evaluate_freshness(&policy, 1000, -1, seq, false),
            Err(MarketTypeError::InvalidTimestamp(-1))
        );

        // Age 0 ms => Fresh
        let meta = evaluate_freshness(&policy, 1_000_000, 1_000_000, seq, false).unwrap();
        assert_eq!(meta.status, FreshnessStatus::Fresh);
        assert_eq!(meta.age_ms, 0);

        // Age exactly max_staleness_ms (10_000) => Fresh
        let meta = evaluate_freshness(&policy, 1_000_000, 1_010_000, seq, false).unwrap();
        assert_eq!(meta.status, FreshnessStatus::Fresh);
        assert_eq!(meta.age_ms, 10_000);

        // Age 10_001 ms => Stale
        let meta = evaluate_freshness(&policy, 1_000_000, 1_010_001, seq, false).unwrap();
        assert_eq!(meta.status, FreshnessStatus::Stale);
        assert_eq!(meta.age_ms, 10_001);

        // Future skew within tolerance (2000ms) => Fresh
        let meta = evaluate_freshness(&policy, 1_002_000, 1_000_000, seq, false).unwrap();
        assert_eq!(meta.status, FreshnessStatus::Fresh);

        // Future skew exceeding tolerance (2001ms) => ResyncRequired
        let meta = evaluate_freshness(&policy, 1_002_001, 1_000_000, seq, false).unwrap();
        assert_eq!(meta.status, FreshnessStatus::ResyncRequired);

        // Gap flag set => ResyncRequired unconditionally
        let meta = evaluate_freshness(&policy, 1_000_000, 1_000_000, seq, true).unwrap();
        assert_eq!(meta.status, FreshnessStatus::ResyncRequired);
    }

    #[test]
    fn property_freshness_sweep_around_staleness_threshold() {
        let policy = FreshnessPolicy::new(5_000, 1_000).unwrap();
        let observed_ms = 100_000i64;
        let seq = Sequence(1);

        for offset in 0..=10_000 {
            let evaluated_ms = observed_ms + offset;
            let meta = evaluate_freshness(&policy, observed_ms, evaluated_ms, seq, false).unwrap();
            assert_eq!(meta.age_ms, offset as u64);
            if offset <= 5_000 {
                assert_eq!(meta.status, FreshnessStatus::Fresh);
            } else {
                assert_eq!(meta.status, FreshnessStatus::Stale);
            }
        }
    }

    // --- Contract 3: OHLCV & Depth Representations ---

    #[test]
    fn normalized_price_and_quantity_invariants() {
        assert_eq!(
            NormalizedPrice::new(f64::NAN),
            Err(MarketTypeError::NonFinitePrice)
        );
        assert_eq!(
            NormalizedPrice::new(f64::INFINITY),
            Err(MarketTypeError::NonFinitePrice)
        );
        assert_eq!(
            NormalizedPrice::new(f64::NEG_INFINITY),
            Err(MarketTypeError::NonFinitePrice)
        );
        assert_eq!(
            NormalizedPrice::new(-0.0001),
            Err(MarketTypeError::NegativePrice)
        );

        let zero_price = NormalizedPrice::new(-0.0).unwrap();
        assert_eq!(zero_price.get(), 0.0);
        assert_eq!(
            NormalizedPrice::new_positive(0.0),
            Err(MarketTypeError::ZeroPrice)
        );

        assert_eq!(
            NormalizedQuantity::new(f64::NAN),
            Err(MarketTypeError::NonFiniteQuantity)
        );
        assert_eq!(
            NormalizedQuantity::new(-1.0),
            Err(MarketTypeError::NegativeQuantity)
        );
        assert_eq!(
            NormalizedQuantity::new_positive(0.0),
            Err(MarketTypeError::ZeroQuantity)
        );
    }

    #[test]
    fn normalized_price_deserializes_from_both_number_and_string() {
        let from_num: NormalizedPrice = serde_json::from_str("123.45").unwrap();
        let from_str: NormalizedPrice = serde_json::from_str(r#""123.45""#).unwrap();
        assert_eq!(from_num, from_str);
        assert_eq!(from_num.get(), 123.45);

        let from_qty_str: NormalizedQuantity = serde_json::from_str(r#""99.9""#).unwrap();
        assert_eq!(from_qty_str.get(), 99.9);
    }

    #[test]
    fn candle_invariants_and_bounds() {
        let instrument = sample_instrument();
        let valid_candle = Candle {
            instrument: instrument.clone(),
            timeframe: CandleTimeframe::M1,
            open_time_ms: 1_000_000,
            close_time_ms: 1_060_000,
            open: NormalizedPrice::new(100.0).unwrap(),
            high: NormalizedPrice::new(105.0).unwrap(),
            low: NormalizedPrice::new(95.0).unwrap(),
            close: NormalizedPrice::new(102.0).unwrap(),
            volume: NormalizedQuantity::new(500.0).unwrap(),
            quote_volume: Some(NormalizedQuantity::new(51_000.0).unwrap()),
            trades_count: Some(12),
        };
        assert!(valid_candle.validate().is_ok());

        // Inverted time window
        let mut inverted_time = valid_candle.clone();
        inverted_time.close_time_ms = inverted_time.open_time_ms;
        assert!(matches!(
            inverted_time.validate(),
            Err(MarketTypeError::InvalidCandleWindow { .. })
        ));

        // Window exceeding max
        let mut excessive_window = valid_candle.clone();
        excessive_window.close_time_ms =
            excessive_window.open_time_ms + (MAX_CANDLE_WINDOW_MS as i64) + 1;
        assert!(matches!(
            excessive_window.validate(),
            Err(MarketTypeError::CandleWindowExceeded { .. })
        ));

        // Low > Open
        let mut bad_low = valid_candle.clone();
        bad_low.low = NormalizedPrice::new(101.0).unwrap();
        assert!(matches!(
            bad_low.validate(),
            Err(MarketTypeError::InvalidCandleBounds { .. })
        ));

        // High < Close
        let mut bad_high = valid_candle.clone();
        bad_high.high = NormalizedPrice::new(101.0).unwrap();
        assert!(matches!(
            bad_high.validate(),
            Err(MarketTypeError::InvalidCandleBounds { .. })
        ));
    }

    #[test]
    fn depth_snapshot_ordering_and_crossed_book_validation() {
        let target = FeedTarget::Instrument(sample_instrument());

        let bids = vec![
            DepthLevel::new(
                NormalizedPrice::new(100.0).unwrap(),
                NormalizedQuantity::new(10.0).unwrap(),
            ),
            DepthLevel::new(
                NormalizedPrice::new(99.0).unwrap(),
                NormalizedQuantity::new(20.0).unwrap(),
            ),
        ];
        let asks = vec![
            DepthLevel::new(
                NormalizedPrice::new(101.0).unwrap(),
                NormalizedQuantity::new(15.0).unwrap(),
            ),
            DepthLevel::new(
                NormalizedPrice::new(102.0).unwrap(),
                NormalizedQuantity::new(25.0).unwrap(),
            ),
        ];

        let valid_snap = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(10),
            timestamp_ms: 1_000_000,
            bids: bids.clone(),
            asks: asks.clone(),
        };
        assert!(valid_snap.validate().is_ok());

        // Bids unsorted (ascending instead of descending)
        let mut unsorted_bids = valid_snap.clone();
        unsorted_bids.bids.reverse();
        assert_eq!(
            unsorted_bids.validate(),
            Err(MarketTypeError::UnsortedDepthLevels { side: "bids" })
        );

        // Bids with duplicate price level
        let mut dup_bids = valid_snap.clone();
        dup_bids.bids[1].price = dup_bids.bids[0].price;
        assert_eq!(
            dup_bids.validate(),
            Err(MarketTypeError::DuplicateDepthPriceLevel { side: "bids" })
        );

        // Asks unsorted (descending instead of ascending)
        let mut unsorted_asks = valid_snap.clone();
        unsorted_asks.asks.reverse();
        assert_eq!(
            unsorted_asks.validate(),
            Err(MarketTypeError::UnsortedDepthLevels { side: "asks" })
        );

        // Crossed order book (best bid >= best ask)
        let mut crossed = valid_snap.clone();
        crossed.bids[0].price = NormalizedPrice::new(101.5).unwrap();
        assert_eq!(crossed.validate(), Err(MarketTypeError::CrossedOrderBook));
    }

    #[test]
    fn order_book_depth_apply_delta_and_gap_handling() {
        let target = FeedTarget::Instrument(sample_instrument());
        let snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(100),
            timestamp_ms: 1_000_000,
            bids: vec![
                DepthLevel::new(
                    NormalizedPrice::new(100.0).unwrap(),
                    NormalizedQuantity::new(10.0).unwrap(),
                ),
                DepthLevel::new(
                    NormalizedPrice::new(99.0).unwrap(),
                    NormalizedQuantity::new(20.0).unwrap(),
                ),
            ],
            asks: vec![
                DepthLevel::new(
                    NormalizedPrice::new(101.0).unwrap(),
                    NormalizedQuantity::new(15.0).unwrap(),
                ),
                DepthLevel::new(
                    NormalizedPrice::new(102.0).unwrap(),
                    NormalizedQuantity::new(25.0).unwrap(),
                ),
            ],
        };

        let mut book = OrderBookDepth::new(snapshot, 10).unwrap();
        assert_eq!(book.spread(), Some(1.0));
        assert_eq!(book.mid_price().unwrap().get(), 100.5);

        // Apply contiguous delta: insert new top bid (100.5), update ask (101.0 quantity to 30.0)
        let delta1 = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(101)).unwrap(),
            timestamp_ms: 1_000_100,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(101.0).unwrap(),
                NormalizedQuantity::new(30.0).unwrap(),
            )],
        };
        let outcome = book.apply_delta(&delta1).unwrap();
        assert_eq!(
            outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(101)
            }
        );
        assert_eq!(book.best_bid().unwrap().price.get(), 100.5);
        assert_eq!(book.best_ask().unwrap().quantity.get(), 30.0);
        assert_eq!(book.spread(), Some(0.5));

        // Delete top bid using quantity 0
        let delta2 = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(102)).unwrap(),
            timestamp_ms: 1_000_200,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(0.0).unwrap(),
            )],
            asks: vec![],
        };
        book.apply_delta(&delta2).unwrap();
        assert_eq!(book.best_bid().unwrap().price.get(), 100.0);

        // Gap in sequence produces ResyncRequired
        let delta_gap = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(105)).unwrap(),
            timestamp_ms: 1_000_300,
            bids: vec![],
            asks: vec![],
        };
        let outcome_gap = book.apply_delta(&delta_gap).unwrap();
        assert_eq!(
            outcome_gap,
            DeltaClassification::ResyncRequired {
                expected: Sequence(103),
                received: Sequence(105)
            }
        );
    }

    #[test]
    fn regression_orderbook_overlap_range_rejects_with_resync_and_state_unchanged() {
        let target = FeedTarget::Instrument(sample_instrument());
        let initial_bids = vec![DepthLevel::new(
            NormalizedPrice::new(100.0).unwrap(),
            NormalizedQuantity::new(10.0).unwrap(),
        )];
        let initial_asks = vec![DepthLevel::new(
            NormalizedPrice::new(102.0).unwrap(),
            NormalizedQuantity::new(10.0).unwrap(),
        )];
        let snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(100),
            timestamp_ms: 1_000_000,
            bids: initial_bids.clone(),
            asks: initial_asks.clone(),
        };

        let mut book = OrderBookDepth::new(snapshot, 10).unwrap();

        // 1. Overlapping range where start <= current < end (e.g. [99, 105])
        let overlap_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::new(Sequence(99), Sequence(105)).unwrap(),
            timestamp_ms: 1_000_100,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![],
        };
        let outcome = book.apply_delta(&overlap_delta).unwrap();
        assert_eq!(
            outcome,
            DeltaClassification::ResyncRequired {
                expected: Sequence(101),
                received: Sequence(99),
            }
        );

        // Assert state is completely unchanged
        assert_eq!(book.sequence(), Sequence(100));
        assert_eq!(book.timestamp_ms(), 1_000_000);
        assert_eq!(book.bids(), &initial_bids);
        assert_eq!(book.asks(), &initial_asks);
        assert!(book.is_resync_required());

        // 2. Overlap starting exactly at current sequence [100, 105]
        let mut book2 = OrderBookDepth::new(
            DepthSnapshot {
                target: target.clone(),
                sequence: Sequence(100),
                timestamp_ms: 1_000_000,
                bids: initial_bids.clone(),
                asks: initial_asks.clone(),
            },
            10,
        )
        .unwrap();

        let overlap_delta2 = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::new(Sequence(100), Sequence(105)).unwrap(),
            timestamp_ms: 1_000_100,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![],
        };
        let outcome2 = book2.apply_delta(&overlap_delta2).unwrap();
        assert_eq!(
            outcome2,
            DeltaClassification::ResyncRequired {
                expected: Sequence(101),
                received: Sequence(100),
            }
        );
        assert_eq!(book2.sequence(), Sequence(100));
        assert_eq!(book2.timestamp_ms(), 1_000_000);
        assert_eq!(book2.bids(), &initial_bids);
        assert_eq!(book2.asks(), &initial_asks);
        assert!(book2.is_resync_required());
    }

    #[test]
    fn regression_orderbook_gap_latches_resync_and_recovers_via_snapshot() {
        let target = FeedTarget::Instrument(sample_instrument());
        let snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(100),
            timestamp_ms: 1_000_000,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.0).unwrap(),
                NormalizedQuantity::new(10.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(102.0).unwrap(),
                NormalizedQuantity::new(10.0).unwrap(),
            )],
        };

        let mut book = OrderBookDepth::new(snapshot, 10).unwrap();
        assert!(!book.is_resync_required());

        // Gap delta at [105, 105] latches resync
        let gap_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(105)).unwrap(),
            timestamp_ms: 1_000_100,
            bids: vec![],
            asks: vec![],
        };
        let gap_outcome = book.apply_delta(&gap_delta).unwrap();
        assert_eq!(
            gap_outcome,
            DeltaClassification::ResyncRequired {
                expected: Sequence(101),
                received: Sequence(105),
            }
        );
        assert!(book.is_resync_required());
        assert_eq!(book.sequence(), Sequence(100));

        // Subsequent contiguous delta [101, 101] MUST STILL reject while resync latch is held
        let contiguous_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(101)).unwrap(),
            timestamp_ms: 1_000_200,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![],
        };
        let rejected_outcome = book.apply_delta(&contiguous_delta).unwrap();
        assert_eq!(
            rejected_outcome,
            DeltaClassification::ResyncRequired {
                expected: Sequence(101),
                received: Sequence(101),
            }
        );
        assert_eq!(book.sequence(), Sequence(100)); // still unchanged!
        assert!(book.is_resync_required());

        // Recover via validated fresh snapshot at sequence 110
        let fresh_snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(110),
            timestamp_ms: 1_000_300,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(101.0).unwrap(),
                NormalizedQuantity::new(20.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(103.0).unwrap(),
                NormalizedQuantity::new(25.0).unwrap(),
            )],
        };
        let snap_outcome = book.apply_snapshot(fresh_snapshot).unwrap();
        assert_eq!(
            snap_outcome,
            SnapshotClassification::Accepted {
                new_sequence: Sequence(110)
            }
        );
        assert!(!book.is_resync_required());
        assert_eq!(book.sequence(), Sequence(110));

        // After recovery, normal contiguous advancement works
        let next_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(111)).unwrap(),
            timestamp_ms: 1_000_400,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(101.5).unwrap(),
                NormalizedQuantity::new(15.0).unwrap(),
            )],
            asks: vec![],
        };
        let next_outcome = book.apply_delta(&next_delta).unwrap();
        assert_eq!(
            next_outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(111)
            }
        );
        assert_eq!(book.sequence(), Sequence(111));
        assert_eq!(book.best_bid().unwrap().price.get(), 101.5);
    }

    #[test]
    fn regression_orderbook_crossing_delta_rolls_back_completely() {
        let target = FeedTarget::Instrument(sample_instrument());
        let initial_bids = vec![
            DepthLevel::new(
                NormalizedPrice::new(100.0).unwrap(),
                NormalizedQuantity::new(10.0).unwrap(),
            ),
            DepthLevel::new(
                NormalizedPrice::new(99.0).unwrap(),
                NormalizedQuantity::new(20.0).unwrap(),
            ),
        ];
        let initial_asks = vec![
            DepthLevel::new(
                NormalizedPrice::new(102.0).unwrap(),
                NormalizedQuantity::new(15.0).unwrap(),
            ),
            DepthLevel::new(
                NormalizedPrice::new(103.0).unwrap(),
                NormalizedQuantity::new(25.0).unwrap(),
            ),
        ];

        let snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(100),
            timestamp_ms: 1_000_000,
            bids: initial_bids.clone(),
            asks: initial_asks.clone(),
        };

        let mut book = OrderBookDepth::new(snapshot, 10).unwrap();

        // Contiguous delta [101, 101] attempting to cross book by setting bid to 102.5 (>= best ask 102.0)
        let crossing_bid_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(101)).unwrap(),
            timestamp_ms: 1_000_100,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(102.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![],
        };
        let result = book.apply_delta(&crossing_bid_delta);
        assert_eq!(result, Err(MarketTypeError::CrossedOrderBook));

        // Exact rollback: sequence, timestamp, bids, and asks must remain unchanged!
        assert_eq!(book.sequence(), Sequence(100));
        assert_eq!(book.timestamp_ms(), 1_000_000);
        assert_eq!(book.bids(), &initial_bids);
        assert_eq!(book.asks(), &initial_asks);

        // Contiguous delta [101, 101] attempting to cross book by setting ask to 99.5 (<= best bid 100.0)
        let crossing_ask_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(101)).unwrap(),
            timestamp_ms: 1_000_200,
            bids: vec![],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(99.5).unwrap(),
                NormalizedQuantity::new(8.0).unwrap(),
            )],
        };
        let result2 = book.apply_delta(&crossing_ask_delta);
        assert_eq!(result2, Err(MarketTypeError::CrossedOrderBook));

        // Exact rollback again
        assert_eq!(book.sequence(), Sequence(100));
        assert_eq!(book.timestamp_ms(), 1_000_000);
        assert_eq!(book.bids(), &initial_bids);
        assert_eq!(book.asks(), &initial_asks);

        // Valid contiguous delta [101, 101] succeeds and mutates cleanly
        let valid_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(101)).unwrap(),
            timestamp_ms: 1_000_300,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(100.5).unwrap(),
                NormalizedQuantity::new(12.0).unwrap(),
            )],
            asks: vec![],
        };
        let valid_result = book.apply_delta(&valid_delta).unwrap();
        assert_eq!(
            valid_result,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(101)
            }
        );
        assert_eq!(book.sequence(), Sequence(101));
        assert_eq!(book.timestamp_ms(), 1_000_300);
        assert_eq!(book.best_bid().unwrap().price.get(), 100.5);
    }

    // --- Contract 4: Adapter-Neutral Pool State (CPMM, CLMM, Bin) ---

    #[test]
    fn cpmm_pool_state_invariants() {
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

        let cpmm = CpmmPoolState {
            token_0: sol.clone(),
            token_1: usdc.clone(),
            decimals_0: 9,
            decimals_1: 6,
            reserve_0: AtomicAmount::new(1_000_000_000),
            reserve_1: AtomicAmount::new(150_000_000_000),
            total_lp_supply: Some(AtomicAmount::new(500_000_000)),
            fee_bps: Bps::new(30).unwrap(),
        };
        assert!(cpmm.validate().is_ok());

        // Same token rejected
        let mut same_token = cpmm.clone();
        same_token.token_1 = sol.clone();
        assert_eq!(same_token.validate(), Err(MarketTypeError::SamePoolTokens));

        // Decimals exceeded rejected
        let mut bad_decimals = cpmm.clone();
        bad_decimals.decimals_0 = 31;
        assert_eq!(
            bad_decimals.validate(),
            Err(MarketTypeError::DecimalsExceeded {
                decimals: 31,
                max: MAX_DECIMALS
            })
        );
    }

    #[test]
    fn clmm_pool_state_invariants() {
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

        let ticks = vec![
            ClmmTick {
                index: -128,
                liquidity_gross: 10_000,
                liquidity_net: 10_000,
            },
            ClmmTick {
                index: 0,
                liquidity_gross: 20_000,
                liquidity_net: -5_000,
            },
            ClmmTick {
                index: 128,
                liquidity_gross: 15_000,
                liquidity_net: -5_000,
            },
        ];

        let clmm = ClmmPoolState {
            token_0: sol.clone(),
            token_1: usdc.clone(),
            decimals_0: 9,
            decimals_1: 6,
            tick_spacing: 64,
            current_tick: 0,
            sqrt_price_x64: 18446744073709551616, // 1.0 in Q64
            liquidity: 50_000,
            fee_bps: Bps::new(5).unwrap(),
            ticks: ticks.clone(),
        };
        assert!(clmm.validate().is_ok());

        // Tick spacing 0 rejected
        let mut bad_spacing = clmm.clone();
        bad_spacing.tick_spacing = 0;
        assert_eq!(
            bad_spacing.validate(),
            Err(MarketTypeError::InvalidTickSpacing(0))
        );

        // Tick not aligned with spacing (e.g. index 65 with spacing 64)
        let mut unaligned_tick = clmm.clone();
        unaligned_tick.ticks[1].index = 65;
        assert_eq!(
            unaligned_tick.validate(),
            Err(MarketTypeError::TickSpacingMismatch {
                tick: 65,
                spacing: 64
            })
        );

        // Ticks unsorted rejected
        let mut unsorted_ticks = clmm.clone();
        unsorted_ticks.ticks.reverse();
        assert_eq!(
            unsorted_ticks.validate(),
            Err(MarketTypeError::UnsortedClmmTicks)
        );

        // Net liquidity exceeding gross rejected
        let mut bad_net = clmm.clone();
        bad_net.ticks[0].liquidity_net = 10_001; // > gross 10_000
        assert_eq!(
            bad_net.validate(),
            Err(MarketTypeError::InvalidTickLiquidity(-128))
        );
    }

    #[test]
    fn bin_pool_state_invariants() {
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

        let active_bin_id = 100;
        let bins = vec![
            // Below active bin: only quote asset (reserve_1)
            LiquidityBin {
                id: 98,
                reserve_0: AtomicAmount::ZERO,
                reserve_1: AtomicAmount::new(50_000),
            },
            // Active bin: both can be present
            LiquidityBin {
                id: 100,
                reserve_0: AtomicAmount::new(20_000),
                reserve_1: AtomicAmount::new(30_000),
            },
            // Above active bin: only base asset (reserve_0)
            LiquidityBin {
                id: 102,
                reserve_0: AtomicAmount::new(60_000),
                reserve_1: AtomicAmount::ZERO,
            },
        ];

        let bin_pool = BinPoolState {
            token_0: sol.clone(),
            token_1: usdc.clone(),
            decimals_0: 9,
            decimals_1: 6,
            active_bin_id,
            bin_step: 10,
            fee_bps: Bps::new(10).unwrap(),
            bins: bins.clone(),
        };
        assert!(bin_pool.validate().is_ok());

        // Reserve side violation below active bin (reserve_0 > 0)
        let mut bad_left_bin = bin_pool.clone();
        bad_left_bin.bins[0].reserve_0 = AtomicAmount::new(1);
        assert_eq!(
            bad_left_bin.validate(),
            Err(MarketTypeError::BinReserveSideViolation {
                bin_id: 98,
                active_bin_id: 100
            })
        );

        // Reserve side violation above active bin (reserve_1 > 0)
        let mut bad_right_bin = bin_pool.clone();
        bad_right_bin.bins[2].reserve_1 = AtomicAmount::new(1);
        assert_eq!(
            bad_right_bin.validate(),
            Err(MarketTypeError::BinReserveSideViolation {
                bin_id: 102,
                active_bin_id: 100
            })
        );

        // Empty bin rejected
        let mut empty_bin = bin_pool.clone();
        empty_bin.bins[0].reserve_1 = AtomicAmount::ZERO;
        assert_eq!(empty_bin.validate(), Err(MarketTypeError::EmptyBin(98)));

        // Unsorted bins rejected
        let mut unsorted = bin_pool.clone();
        unsorted.bins.reverse();
        assert_eq!(unsorted.validate(), Err(MarketTypeError::UnsortedBins));
    }

    #[test]
    fn pool_state_envelope_validation_and_chain_matching() {
        let pool_id = sample_pool_id();
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

        let cpmm = CpmmPoolState {
            token_0: sol.clone(),
            token_1: usdc.clone(),
            decimals_0: 9,
            decimals_1: 6,
            reserve_0: AtomicAmount::new(100),
            reserve_1: AtomicAmount::new(200),
            total_lp_supply: None,
            fee_bps: Bps::new(25).unwrap(),
        };

        let envelope = PoolStateEnvelope {
            pool_id: pool_id.clone(),
            sequence: Sequence(1),
            observed_at_ms: 1_000_000,
            state: PoolKindState::Cpmm(cpmm),
        };
        assert!(envelope.validate().is_ok());
        assert_eq!(envelope.pool_id(), &pool_id);
        assert_eq!(envelope.token_0(), &sol);
        assert_eq!(envelope.token_1(), &usdc);

        // Chain mismatch between pool_id and state tokens
        let mut mismatched_envelope = envelope.clone();
        mismatched_envelope.pool_id.chain = ChainId::Base;
        assert_eq!(
            mismatched_envelope.validate(),
            Err(MarketTypeError::ChainMismatch)
        );
    }

    // --- Contract 5: Serialization Round Trips ---

    #[test]
    fn pool_state_envelope_json_round_trips_cpmm_clmm_bin() {
        let pool_id = sample_pool_id();
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

        // 1. CPMM Envelope
        let cpmm_env = PoolStateEnvelope {
            pool_id: pool_id.clone(),
            sequence: Sequence(10),
            observed_at_ms: 1_700_000_000_000,
            state: PoolKindState::Cpmm(CpmmPoolState {
                token_0: sol.clone(),
                token_1: usdc.clone(),
                decimals_0: 9,
                decimals_1: 6,
                reserve_0: AtomicAmount::new(50_000_000_000),
                reserve_1: AtomicAmount::new(7_500_000_000),
                total_lp_supply: Some(AtomicAmount::new(10_000_000)),
                fee_bps: Bps::new(30).unwrap(),
            }),
        };
        let cpmm_json = serde_json::to_string(&cpmm_env).unwrap();
        let cpmm_decoded: PoolStateEnvelope = serde_json::from_str(&cpmm_json).unwrap();
        assert_eq!(cpmm_decoded, cpmm_env);

        // 2. CLMM Envelope
        let clmm_env = PoolStateEnvelope {
            pool_id: pool_id.clone(),
            sequence: Sequence(11),
            observed_at_ms: 1_700_000_000_100,
            state: PoolKindState::Clmm(ClmmPoolState {
                token_0: sol.clone(),
                token_1: usdc.clone(),
                decimals_0: 9,
                decimals_1: 6,
                tick_spacing: 64,
                current_tick: 128,
                sqrt_price_x64: 18446744073709551616,
                liquidity: 999_999,
                fee_bps: Bps::new(5).unwrap(),
                ticks: vec![ClmmTick {
                    index: 128,
                    liquidity_gross: 500,
                    liquidity_net: 500,
                }],
            }),
        };
        let clmm_json = serde_json::to_string(&clmm_env).unwrap();
        let clmm_decoded: PoolStateEnvelope = serde_json::from_str(&clmm_json).unwrap();
        assert_eq!(clmm_decoded, clmm_env);

        // 3. Bin Envelope
        let bin_env = PoolStateEnvelope {
            pool_id: pool_id.clone(),
            sequence: Sequence(12),
            observed_at_ms: 1_700_000_000_200,
            state: PoolKindState::Bin(BinPoolState {
                token_0: sol.clone(),
                token_1: usdc.clone(),
                decimals_0: 9,
                decimals_1: 6,
                active_bin_id: 50,
                bin_step: 15,
                fee_bps: Bps::new(15).unwrap(),
                bins: vec![LiquidityBin {
                    id: 50,
                    reserve_0: AtomicAmount::new(100),
                    reserve_1: AtomicAmount::new(200),
                }],
            }),
        };
        let bin_json = serde_json::to_string(&bin_env).unwrap();
        let bin_decoded: PoolStateEnvelope = serde_json::from_str(&bin_json).unwrap();
        assert_eq!(bin_decoded, bin_env);
    }

    #[test]
    fn candle_and_depth_json_round_trips() {
        let instrument = sample_instrument();
        let candle = Candle {
            instrument: instrument.clone(),
            timeframe: CandleTimeframe::H1,
            open_time_ms: 1_700_000_000_000,
            close_time_ms: 1_700_003_600_000,
            open: NormalizedPrice::new(150.25).unwrap(),
            high: NormalizedPrice::new(155.0).unwrap(),
            low: NormalizedPrice::new(149.8).unwrap(),
            close: NormalizedPrice::new(154.5).unwrap(),
            volume: NormalizedQuantity::new(1234.567).unwrap(),
            quote_volume: Some(NormalizedQuantity::new(188_000.0).unwrap()),
            trades_count: Some(543),
        };
        let candle_json = serde_json::to_string(&candle).unwrap();
        let decoded_candle: Candle = serde_json::from_str(&candle_json).unwrap();
        assert_eq!(decoded_candle, candle);

        let target = FeedTarget::Instrument(instrument);
        let depth_snap = DepthSnapshot {
            target,
            sequence: Sequence(77),
            timestamp_ms: 1_700_000_000_000,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(150.0).unwrap(),
                NormalizedQuantity::new(10.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(151.0).unwrap(),
                NormalizedQuantity::new(12.0).unwrap(),
            )],
        };
        let snap_json = serde_json::to_string(&depth_snap).unwrap();
        let decoded_snap: DepthSnapshot = serde_json::from_str(&snap_json).unwrap();
        assert_eq!(decoded_snap, depth_snap);
    }
}
