//! Lossless canonical market data contracts and local pool state types.

pub mod aggregation;
pub mod consumer;
pub mod error;
pub mod feed;
pub mod freshness;
pub mod identity;
pub mod mapper;
pub mod ohlcv;
pub mod orderbook;
pub mod pool;
pub mod primitives;
pub mod sequence;

pub use aggregation::{
    ActiveCandleWindow, AggregatedDepthBook, AggregatedDepthLevel, AggregatedDepthSnapshot,
    CumulativeDepthLevel, DepthAggregator, MarketAggregator, OhlcvAggregator,
    MAX_AGGREGATED_BUCKETS, MAX_RETAINED_WINDOWS,
};
pub use consumer::{
    AggregationOutput, ConsumerBatch, ConsumerBatchAck, ConsumerBatchConfig, ConsumerBatchItem,
    ConsumerBatchQueue, MarketConsumerBatcher, MAX_CONSUMER_BATCH_SIZE,
    MAX_CONSUMER_QUEUE_CAPACITY,
};
pub use error::MarketTypeError;
pub use feed::{
    CanonicalFeedEnvelope, CanonicalFeedPayload, ChainFamily, FeedFinality, FeedObservationContext,
    FeedSourceLabel, InjectedFeedSource, MarketFeedSource, RawBinState, RawCandle, RawClmmState,
    RawClmmTick, RawCpmmState, RawDepthDelta, RawDepthLevel, RawDepthSnapshot, RawFeedEnvelope,
    RawFeedPayload, RawLiquidityBin, RawPoolKindState, RawPoolState, MAX_FEED_BATCH_SIZE,
    MAX_SOURCE_LABEL_LEN,
};
pub use freshness::{
    evaluate_freshness, FreshnessPolicy, FreshnessStatus, SafeFreshnessMeta,
    DEFAULT_MAX_FUTURE_SKEW_MS, DEFAULT_MAX_STALENESS_MS, MAX_POLICY_FUTURE_SKEW_MS,
    MAX_POLICY_STALENESS_MS, MIN_POLICY_STALENESS_MS,
};
pub use identity::{FeedTarget, InstrumentId, PoolId};
pub use mapper::CanonicalMarketFeedMapper;
pub use ohlcv::{Candle, CandleTimeframe, MAX_CANDLE_WINDOW_MS};
pub use orderbook::{
    DepthDelta, DepthLevel, DepthSnapshot, NormalizedPrice, NormalizedQuantity, OrderBookDepth,
    MAX_DEPTH_LEVELS,
};
pub use pool::{
    BinPoolDelta, BinPoolDeltaEnvelope, BinPoolReducer, BinPoolState, ClmmPoolDelta,
    ClmmPoolDeltaEnvelope, ClmmPoolReducer, ClmmPoolState, ClmmTick, CpmmPoolDelta,
    CpmmPoolDeltaEnvelope, CpmmPoolReducer, CpmmPoolState, LiquidityBin, PoolDelta,
    PoolDeltaEnvelope, PoolKindDelta, PoolKindState, PoolReducer, PoolStateEnvelope, MAX_BIN_COUNT,
    MAX_BIN_DELTA_BINS, MAX_BIN_ID, MAX_BIN_STEP_BPS, MAX_CLMM_DELTA_TICKS, MAX_CLMM_TICKS,
    MAX_DECIMALS, MAX_TICK, MIN_BIN_ID, MIN_TICK,
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
    fn regression_orderbook_latched_snapshot_sequence_safety() {
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

        // Trigger gap latch: sequence 100 sees gap delta [105, 105]
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

        // 1. Gap latch -> stale snapshot (sequence 95 < 100):
        // Remains latched and all state unchanged!
        let stale_snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(95),
            timestamp_ms: 1_000_050,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(90.0).unwrap(),
                NormalizedQuantity::new(1.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(110.0).unwrap(),
                NormalizedQuantity::new(1.0).unwrap(),
            )],
        };
        let stale_outcome = book.apply_snapshot(stale_snapshot).unwrap();
        assert_eq!(
            stale_outcome,
            SnapshotClassification::Stale {
                sequence: Sequence(95),
                current: Sequence(100),
            }
        );
        assert!(book.is_resync_required());
        assert_eq!(book.sequence(), Sequence(100));
        assert_eq!(book.timestamp_ms(), 1_000_000);
        assert_eq!(book.bids(), &initial_bids);
        assert_eq!(book.asks(), &initial_asks);

        // 2. Gap latch -> duplicate snapshot (sequence 100 == 100):
        // Remains latched and all state unchanged!
        let dup_snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(100),
            timestamp_ms: 1_000_090,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(95.0).unwrap(),
                NormalizedQuantity::new(2.0).unwrap(),
            )],
            asks: vec![DepthLevel::new(
                NormalizedPrice::new(105.0).unwrap(),
                NormalizedQuantity::new(2.0).unwrap(),
            )],
        };
        let dup_outcome = book.apply_snapshot(dup_snapshot).unwrap();
        assert_eq!(
            dup_outcome,
            SnapshotClassification::Duplicate {
                sequence: Sequence(100),
            }
        );
        assert!(book.is_resync_required());
        assert_eq!(book.sequence(), Sequence(100));
        assert_eq!(book.timestamp_ms(), 1_000_000);
        assert_eq!(book.bids(), &initial_bids);
        assert_eq!(book.asks(), &initial_asks);

        // 3. Gap latch -> newer validated snapshot (sequence 110 > 100):
        // Advances state and clears latch!
        let newer_bids = vec![DepthLevel::new(
            NormalizedPrice::new(101.0).unwrap(),
            NormalizedQuantity::new(15.0).unwrap(),
        )];
        let newer_asks = vec![DepthLevel::new(
            NormalizedPrice::new(103.0).unwrap(),
            NormalizedQuantity::new(20.0).unwrap(),
        )];
        let newer_snapshot = DepthSnapshot {
            target: target.clone(),
            sequence: Sequence(110),
            timestamp_ms: 1_000_200,
            bids: newer_bids.clone(),
            asks: newer_asks.clone(),
        };
        let newer_outcome = book.apply_snapshot(newer_snapshot).unwrap();
        assert_eq!(
            newer_outcome,
            SnapshotClassification::Accepted {
                new_sequence: Sequence(110),
            }
        );
        assert!(!book.is_resync_required());
        assert_eq!(book.sequence(), Sequence(110));
        assert_eq!(book.timestamp_ms(), 1_000_200);
        assert_eq!(book.bids(), &newer_bids);
        assert_eq!(book.asks(), &newer_asks);

        // Next contiguous delta [111, 111] now succeeds cleanly
        let next_delta = DepthDelta {
            target: target.clone(),
            sequence_range: SequenceRange::point(Sequence(111)).unwrap(),
            timestamp_ms: 1_000_300,
            bids: vec![DepthLevel::new(
                NormalizedPrice::new(101.5).unwrap(),
                NormalizedQuantity::new(5.0).unwrap(),
            )],
            asks: vec![],
        };
        let next_outcome = book.apply_delta(&next_delta).unwrap();
        assert_eq!(
            next_outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(111),
            }
        );
        assert_eq!(book.sequence(), Sequence(111));
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

    // --- AGY P21 Slice A: Injected Market Feed Boundary & Canonical Mapper Tests ---

    fn sample_sol_context(label: &str, slot: u64, ts: i64) -> FeedObservationContext {
        FeedObservationContext::new(
            ChainFamily::Solana,
            FeedSourceLabel::new(label).unwrap(),
            FeedFinality::Confirmed,
            Some(slot),
            ts,
        )
        .unwrap()
    }

    fn sample_evm_context(label: &str, block: u64, ts: i64) -> FeedObservationContext {
        FeedObservationContext::new(
            ChainFamily::Evm,
            FeedSourceLabel::new(label).unwrap(),
            FeedFinality::Finalized,
            Some(block),
            ts,
        )
        .unwrap()
    }

    #[test]
    fn test_solana_neutral_input_normalizes_with_preserved_metadata() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        let context_snap = sample_sol_context("yellowstone-primary", 250_000_100, 1_000_000);
        let raw_snap = RawFeedEnvelope::new(
            context_snap.clone(),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![
                    RawDepthLevel::new(150.0, 10.0),
                    RawDepthLevel::new(149.0, 20.0),
                ],
                asks: vec![
                    RawDepthLevel::new(151.0, 15.0),
                    RawDepthLevel::new(152.0, 25.0),
                ],
            }),
        )
        .unwrap();

        let context_delta = sample_sol_context("yellowstone-primary", 250_000_101, 1_000_100);
        let raw_delta = RawFeedEnvelope::new(
            context_delta.clone(),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(150.5, 5.0)],
                asks: vec![],
            }),
        )
        .unwrap();

        // Injected fake source playback
        let mut source = InjectedFeedSource::from_envelopes(vec![raw_snap, raw_delta]).unwrap();
        assert_eq!(source.len(), 2);

        // Map snapshot
        let canonical_snap = mapper
            .process_from_source(&mut source, 1_000_100)
            .unwrap()
            .unwrap();
        assert_eq!(canonical_snap.context, context_snap);
        assert_eq!(canonical_snap.context.source_family, ChainFamily::Solana);
        assert_eq!(
            canonical_snap.context.source_label.as_str(),
            "yellowstone-primary"
        );
        assert_eq!(canonical_snap.context.finality, FeedFinality::Confirmed);
        assert_eq!(canonical_snap.context.slot_or_block, Some(250_000_100));
        assert_eq!(canonical_snap.freshness.status, FreshnessStatus::Fresh);

        match &canonical_snap.payload {
            CanonicalFeedPayload::OrderBookSnapshot(snap) => {
                assert_eq!(snap.sequence, Sequence(100));
                assert_eq!(snap.bids[0].price.get(), 150.0);
                assert_eq!(snap.asks[0].price.get(), 151.0);
            }
            _ => panic!("expected OrderBookSnapshot"),
        }
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            150.0
        );

        // Map contiguous delta
        let canonical_delta = mapper
            .process_from_source(&mut source, 1_000_100)
            .unwrap()
            .unwrap();
        assert_eq!(canonical_delta.context, context_delta);
        assert_eq!(canonical_delta.context.slot_or_block, Some(250_000_101));
        assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            150.5
        );
        assert_eq!(mapper.order_book().unwrap().spread(), Some(0.5));

        // Source exhausted
        assert!(mapper
            .process_from_source(&mut source, 1_000_100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_evm_neutral_input_normalizes_with_preserved_metadata() {
        let pool_id = PoolId::new(
            ChainId::Ethereum,
            "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
        )
        .unwrap();
        let target = FeedTarget::Pool(pool_id.clone());
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        let usdc = AssetId::new(
            ChainId::Ethereum,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        )
        .unwrap();
        let weth = AssetId::new(
            ChainId::Ethereum,
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        )
        .unwrap();

        let context = sample_evm_context("reth-ws-feed", 19_500_000, 1_700_000_000_000);
        let raw_cpmm = RawFeedEnvelope::new(
            context.clone(),
            target.clone(),
            RawFeedPayload::PoolState(RawPoolState {
                sequence: 1,
                kind: RawPoolKindState::Cpmm(RawCpmmState {
                    token_0: usdc.clone(),
                    token_1: weth.clone(),
                    decimals_0: 6,
                    decimals_1: 18,
                    reserve_0: 50_000_000_000,
                    reserve_1: 15_000_000_000_000_000_000,
                    total_lp_supply: Some(1_000_000_000),
                    fee_bps: 30,
                }),
            }),
        )
        .unwrap();

        let canonical_env = mapper.map_envelope(raw_cpmm, 1_700_000_000_000).unwrap();
        assert_eq!(canonical_env.context, context);
        assert_eq!(canonical_env.context.source_family, ChainFamily::Evm);
        assert_eq!(canonical_env.context.source_label.as_str(), "reth-ws-feed");
        assert_eq!(canonical_env.context.finality, FeedFinality::Finalized);
        assert_eq!(canonical_env.context.slot_or_block, Some(19_500_000));
        assert_eq!(canonical_env.freshness.status, FreshnessStatus::Fresh);

        match &canonical_env.payload {
            CanonicalFeedPayload::PoolState(pool_env) => {
                assert_eq!(pool_env.sequence, Sequence(1));
                assert_eq!(pool_env.pool_id(), &pool_id);
                match &pool_env.state {
                    PoolKindState::Cpmm(cpmm) => {
                        assert_eq!(cpmm.reserve_0, AtomicAmount::new(50_000_000_000));
                        assert_eq!(
                            cpmm.reserve_1,
                            AtomicAmount::new(15_000_000_000_000_000_000)
                        );
                        assert_eq!(cpmm.fee_bps.get(), 30);
                    }
                    _ => panic!("expected CPMM pool state"),
                }
            }
            _ => panic!("expected PoolState"),
        }
        assert_eq!(mapper.current_sequence(), Some(Sequence(1)));
        assert_eq!(mapper.last_pool_state().unwrap().pool_id(), &pool_id);
    }

    #[test]
    fn test_clmm_and_bin_pool_state_normalization() {
        // 1. CLMM Normalization
        let pool_id = sample_pool_id();
        let target = FeedTarget::Pool(pool_id.clone());
        let mut clmm_mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

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

        let clmm_context = sample_sol_context("solana-geyser", 260_000_000, 1_000_000);
        let raw_clmm = RawFeedEnvelope::new(
            clmm_context.clone(),
            target.clone(),
            RawFeedPayload::PoolState(RawPoolState {
                sequence: 5,
                kind: RawPoolKindState::Clmm(RawClmmState {
                    token_0: sol.clone(),
                    token_1: usdc.clone(),
                    decimals_0: 9,
                    decimals_1: 6,
                    tick_spacing: 64,
                    current_tick: 0,
                    sqrt_price_x64: 18446744073709551616,
                    liquidity: 100_000,
                    fee_bps: 5,
                    ticks: vec![
                        RawClmmTick {
                            index: -64,
                            liquidity_gross: 1000,
                            liquidity_net: 1000,
                        },
                        RawClmmTick {
                            index: 64,
                            liquidity_gross: 1000,
                            liquidity_net: -1000,
                        },
                    ],
                }),
            }),
        )
        .unwrap();

        let clmm_env = clmm_mapper.map_envelope(raw_clmm, 1_000_000).unwrap();
        assert_eq!(clmm_env.context, clmm_context);
        match clmm_env.payload {
            CanonicalFeedPayload::PoolState(env) => match env.state {
                PoolKindState::Clmm(clmm) => {
                    assert_eq!(clmm.liquidity, 100_000);
                    assert_eq!(clmm.ticks.len(), 2);
                }
                _ => panic!("expected CLMM"),
            },
            _ => panic!("expected PoolState"),
        }

        // 2. Bin Normalization
        let mut bin_mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();
        let bin_context = sample_sol_context("meteora-dlmm", 260_000_001, 1_000_000);
        let raw_bin = RawFeedEnvelope::new(
            bin_context.clone(),
            target.clone(),
            RawFeedPayload::PoolState(RawPoolState {
                sequence: 1,
                kind: RawPoolKindState::Bin(RawBinState {
                    token_0: sol.clone(),
                    token_1: usdc.clone(),
                    decimals_0: 9,
                    decimals_1: 6,
                    active_bin_id: 100,
                    bin_step: 10,
                    fee_bps: 10,
                    bins: vec![
                        RawLiquidityBin {
                            id: 99,
                            reserve_0: 0,
                            reserve_1: 50_000,
                        },
                        RawLiquidityBin {
                            id: 100,
                            reserve_0: 10_000,
                            reserve_1: 10_000,
                        },
                        RawLiquidityBin {
                            id: 101,
                            reserve_0: 50_000,
                            reserve_1: 0,
                        },
                    ],
                }),
            }),
        )
        .unwrap();

        let bin_env = bin_mapper.map_envelope(raw_bin, 1_000_000).unwrap();
        assert_eq!(bin_env.context, bin_context);
        match bin_env.payload {
            CanonicalFeedPayload::PoolState(env) => match env.state {
                PoolKindState::Bin(bin) => {
                    assert_eq!(bin.active_bin_id, 100);
                    assert_eq!(bin.bins.len(), 3);
                }
                _ => panic!("expected Bin"),
            },
            _ => panic!("expected PoolState"),
        }
    }

    #[test]
    fn test_candle_normalization() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument.clone());
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        let context = sample_sol_context("jupiter-candles", 250_000_000, 1_700_000_060_000);
        let raw_candle = RawFeedEnvelope::new(
            context.clone(),
            target.clone(),
            RawFeedPayload::Candle(RawCandle {
                timeframe: CandleTimeframe::M1,
                open_time_ms: 1_700_000_000_000,
                close_time_ms: 1_700_000_060_000,
                open: 100.0,
                high: 105.0,
                low: 99.0,
                close: 103.0,
                volume: 500.0,
                quote_volume: Some(51_000.0),
                trades_count: Some(42),
                sequence: Some(10),
            }),
        )
        .unwrap();

        let canonical_env = mapper.map_envelope(raw_candle, 1_700_000_060_000).unwrap();
        assert_eq!(canonical_env.context, context);
        match canonical_env.payload {
            CanonicalFeedPayload::Candle(candle) => {
                assert_eq!(candle.instrument, instrument);
                assert_eq!(candle.timeframe, CandleTimeframe::M1);
                assert_eq!(candle.open.get(), 100.0);
                assert_eq!(candle.high.get(), 105.0);
                assert_eq!(candle.low.get(), 99.0);
                assert_eq!(candle.close.get(), 103.0);
                assert_eq!(candle.volume.get(), 500.0);
                assert_eq!(candle.trades_count, Some(42));
            }
            _ => panic!("expected Candle"),
        }
    }

    #[test]
    fn test_bounded_source_label_enforcement() {
        // Empty rejected
        assert_eq!(
            FeedSourceLabel::new("   "),
            Err(MarketTypeError::EmptySourceLabel)
        );

        // Exceeding MAX_SOURCE_LABEL_LEN (64) rejected
        let long_str = "a".repeat(65);
        assert_eq!(
            FeedSourceLabel::new(&long_str),
            Err(MarketTypeError::SourceLabelTooLong {
                len: 65,
                max: MAX_SOURCE_LABEL_LEN,
            })
        );

        // Valid bounded label accepted
        let valid = FeedSourceLabel::new("yellowstone-primary:sub_1.backup").unwrap();
        assert_eq!(valid.as_str(), "yellowstone-primary:sub_1.backup");

        // Forbidden protocol schemes rejected
        assert!(matches!(
            FeedSourceLabel::new("https://solana.rpc.com/api"),
            Err(MarketTypeError::InvalidSourceLabel(_))
        ));
        assert!(matches!(
            FeedSourceLabel::new("ws://mainnet.infura.io"),
            Err(MarketTypeError::InvalidSourceLabel(_))
        ));

        // Forbidden credentials keywords rejected
        assert!(matches!(
            FeedSourceLabel::new("provider_api_key_123"),
            Err(MarketTypeError::InvalidSourceLabel(_))
        ));
        assert!(matches!(
            FeedSourceLabel::new("secret-token-feed"),
            Err(MarketTypeError::InvalidSourceLabel(_))
        ));
        assert!(matches!(
            FeedSourceLabel::new("user:password@endpoint"),
            Err(MarketTypeError::InvalidSourceLabel(_))
        ));
    }

    #[test]
    fn test_bounded_payload_limits_enforced_fail_closed() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Over-bound depth levels (> MAX_DEPTH_LEVELS)
        let too_many_bids: Vec<RawDepthLevel> = (0..5001)
            .map(|i| RawDepthLevel::new(100.0 - (i as f64 * 0.01), 1.0))
            .collect();
        let raw_overbound = RawFeedEnvelope::new(
            sample_sol_context("source-1", 100, 1000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 1,
                bids: too_many_bids,
                asks: vec![],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(raw_overbound, 1000),
            Err(MarketTypeError::DepthLevelsExceeded {
                count: 5001,
                max: MAX_DEPTH_LEVELS,
            })
        );
        // Mapper state must not advance
        assert_eq!(mapper.current_sequence(), None);
        assert!(mapper.order_book().is_none());
    }

    #[test]
    fn test_malformed_and_non_finite_inputs_fail_closed_without_state_advancement() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // 1. Establish initial baseline at sequence 100
        let baseline = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(100.0, 10.0)],
                asks: vec![RawDepthLevel::new(102.0, 10.0)],
            }),
        )
        .unwrap();
        mapper.map_envelope(baseline, 1000).unwrap();
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 2. Non-finite price in delta (NaN)
        let nan_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1001),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(f64::NAN, 5.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(nan_delta, 1001),
            Err(MarketTypeError::NonFinitePrice)
        );
        // State sequence and book remain unchanged at 100
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
        assert_eq!(mapper.order_book().unwrap().sequence(), Sequence(100));

        // 3. Non-finite quantity in delta (Infinity)
        let inf_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1002),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(99.0, f64::INFINITY)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(inf_delta, 1002),
            Err(MarketTypeError::NonFiniteQuantity)
        );
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 4. Negative price in delta
        let neg_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1003),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(-5.0, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(neg_delta, 1003),
            Err(MarketTypeError::NegativePrice)
        );
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 5. Unsorted bids in snapshot
        let unsorted_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 102, 1004),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 105,
                bids: vec![
                    RawDepthLevel::new(90.0, 1.0),
                    RawDepthLevel::new(95.0, 1.0), // ascending instead of descending
                ],
                asks: vec![RawDepthLevel::new(105.0, 1.0)],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(unsorted_snap, 1004),
            Err(MarketTypeError::UnsortedDepthLevels { side: "bids" })
        );
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    }

    #[test]
    fn test_wrong_target_and_chain_family_mismatch_fail_closed() {
        let sol_instrument = sample_instrument();
        let target = FeedTarget::Instrument(sol_instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // 1. Target mismatch (different instrument)
        let other_base = AssetId::new(
            ChainId::Solana,
            "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
        )
        .unwrap();
        let other_quote = AssetId::new(
            ChainId::Solana,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )
        .unwrap();
        let other_target =
            FeedTarget::Instrument(InstrumentId::new(other_base, other_quote).unwrap());

        let wrong_target_env = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1000),
            other_target,
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 1,
                bids: vec![RawDepthLevel::new(10.0, 1.0)],
                asks: vec![RawDepthLevel::new(12.0, 1.0)],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(wrong_target_env, 1000),
            Err(MarketTypeError::TargetMismatch)
        );
        assert_eq!(mapper.current_sequence(), None);

        // 2. Chain family mismatch: EVM source context targeting Solana instrument
        let evm_context_on_sol = sample_evm_context("reth-feed", 19_000_000, 1000);
        let family_mismatch_env = RawFeedEnvelope::new(
            evm_context_on_sol,
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 1,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![RawDepthLevel::new(102.0, 1.0)],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(family_mismatch_env, 1000),
            Err(MarketTypeError::SourceChainFamilyMismatch {
                source_family: "evm",
                target_chain: "solana",
            })
        );
        assert_eq!(mapper.current_sequence(), None);
    }

    #[test]
    fn test_sequence_gap_latches_resync_fail_closed() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // 1. Establish baseline at sequence 100
        let snap = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(100.0, 10.0)],
                asks: vec![RawDepthLevel::new(102.0, 10.0)],
            }),
        )
        .unwrap();
        mapper.map_envelope(snap, 1000).unwrap();
        assert!(!mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 2. Sequence gap delta [105, 105] (expected 101, received 105)
        let gap_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1010),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 105,
                end_sequence: 105,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();

        let gap_err = mapper.map_envelope(gap_delta, 1010);
        assert_eq!(
            gap_err,
            Err(MarketTypeError::SequenceGap {
                expected: 101,
                received: 105,
            })
        );
        // Latch is sticky resync, state sequence is STILL 100
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 3. Subsequent contiguous delta [101, 101] MUST STILL be rejected while latched
        let next_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 102, 1020),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(next_delta, 1020),
            Err(MarketTypeError::ResyncRequired {
                reason: "stream resync latched: valid snapshot required",
            })
        );
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 4. Stale snapshot at sequence 95 rejected, latch remains held
        let stale_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 103, 1030),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 95,
                bids: vec![RawDepthLevel::new(99.0, 1.0)],
                asks: vec![RawDepthLevel::new(103.0, 1.0)],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(stale_snap, 1030),
            Err(MarketTypeError::StaleSequence {
                sequence: 95,
                current: 100,
            })
        );
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 5. Duplicate snapshot at sequence 100 rejected, latch remains held
        let dup_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 104, 1040),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(99.0, 1.0)],
                asks: vec![RawDepthLevel::new(103.0, 1.0)],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(dup_snap, 1040),
            Err(MarketTypeError::DuplicateSequence(100))
        );
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // 6. Valid newer snapshot at sequence 110 recovers and clears latch
        let recovery_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 105, 1050),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 110,
                bids: vec![RawDepthLevel::new(101.0, 20.0)],
                asks: vec![RawDepthLevel::new(103.0, 20.0)],
            }),
        )
        .unwrap();
        let recovery_res = mapper.map_envelope(recovery_snap, 1050).unwrap();
        assert!(!mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(110)));
        match recovery_res.payload {
            CanonicalFeedPayload::OrderBookSnapshot(s) => assert_eq!(s.sequence, Sequence(110)),
            _ => panic!("expected snapshot"),
        }

        // 7. Subsequent delta at 111 now succeeds cleanly
        let delta_111 = RawFeedEnvelope::new(
            sample_sol_context("src", 106, 1060),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 111,
                end_sequence: 111,
                bids: vec![RawDepthLevel::new(101.5, 5.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        mapper.map_envelope(delta_111, 1060).unwrap();
        assert_eq!(mapper.current_sequence(), Some(Sequence(111)));
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            101.5
        );
    }

    #[test]
    fn test_sequence_overlap_latches_resync_fail_closed() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Baseline at sequence 100
        let snap = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(100.0, 10.0)],
                asks: vec![RawDepthLevel::new(102.0, 10.0)],
            }),
        )
        .unwrap();
        mapper.map_envelope(snap, 1000).unwrap();

        // Overlapping delta: [99, 105] (start 99 <= current 100 < end 105)
        let overlap_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1010),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 99,
                end_sequence: 105,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(overlap_delta, 1010),
            Err(MarketTypeError::SequenceOverlap {
                start: 99,
                end: 105,
                current: 100,
            })
        );
        // Resync latched, sequence unchanged
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

        // Overlap starting exactly at current: [100, 105]
        let overlap_delta2 = RawFeedEnvelope::new(
            sample_sol_context("src", 102, 1020),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 100,
                end_sequence: 105,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(overlap_delta2, 1020),
            Err(MarketTypeError::ResyncRequired {
                reason: "stream resync latched: valid snapshot required",
            })
        );
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    }

    #[test]
    fn test_crossed_order_book_delta_rolls_back_completely() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Snapshot at 100: bid 100.0, ask 102.0
        let snap = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(100.0, 10.0)],
                asks: vec![RawDepthLevel::new(102.0, 10.0)],
            }),
        )
        .unwrap();
        mapper.map_envelope(snap, 1000).unwrap();
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            100.0
        );
        assert_eq!(
            mapper.order_book().unwrap().best_ask().unwrap().price.get(),
            102.0
        );

        // Delta at 101 attempts to set bid to 103.0 (crossing best ask 102.0)
        let crossing_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1010),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(103.0, 5.0)],
                asks: vec![],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(crossing_delta, 1010),
            Err(MarketTypeError::CrossedOrderBook)
        );

        // Sequence, bids, and asks must remain untouched
        assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
        assert_eq!(mapper.order_book().unwrap().sequence(), Sequence(100));
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            100.0
        );
        assert_eq!(
            mapper.order_book().unwrap().best_ask().unwrap().price.get(),
            102.0
        );

        // Valid contiguous delta at 101 with bid 101.0 succeeds cleanly
        let valid_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1020),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(101.0, 5.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        mapper.map_envelope(valid_delta, 1020).unwrap();
        assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
        assert_eq!(
            mapper.order_book().unwrap().best_bid().unwrap().price.get(),
            101.0
        );
    }

    #[test]
    fn test_delta_before_baseline_snapshot_fails_closed() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        let delta = RawFeedEnvelope::new(
            sample_sol_context("src", 1, 1000),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 1,
                end_sequence: 1,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();

        assert_eq!(
            mapper.map_envelope(delta, 1000),
            Err(MarketTypeError::MissingBaselineSnapshot)
        );
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), None);
    }

    #[test]
    fn test_injected_source_error_propagation() {
        struct FailingSource;
        impl MarketFeedSource for FailingSource {
            fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
                Err(MarketTypeError::InjectedSourceError(
                    "simulated feed corruption",
                ))
            }
        }

        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

        let mut failing = FailingSource;
        let res = mapper.process_from_source(&mut failing, 1000);
        assert_eq!(
            res,
            Err(MarketTypeError::InjectedSourceError(
                "simulated feed corruption"
            ))
        );
        assert_eq!(mapper.current_sequence(), None);
    }

    #[test]
    fn test_serialization_round_trips_for_feed_types() {
        // 1. FeedSourceLabel round trip
        let label = FeedSourceLabel::new("yellowstone-primary-feed").unwrap();
        let label_json = serde_json::to_string(&label).unwrap();
        assert_eq!(label_json, r#""yellowstone-primary-feed""#);
        let decoded_label: FeedSourceLabel = serde_json::from_str(&label_json).unwrap();
        assert_eq!(decoded_label, label);

        // 2. FeedObservationContext round trip
        let context = sample_sol_context("solana-geyser", 250_000_100, 1_700_000_000_000);
        let context_json = serde_json::to_string(&context).unwrap();
        let decoded_context: FeedObservationContext = serde_json::from_str(&context_json).unwrap();
        assert_eq!(decoded_context, context);

        // 3. RawFeedEnvelope round trip
        let raw_env = RawFeedEnvelope::new(
            context.clone(),
            FeedTarget::Instrument(sample_instrument()),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 42,
                bids: vec![RawDepthLevel::new(100.0, 5.0)],
                asks: vec![RawDepthLevel::new(101.0, 5.0)],
            }),
        )
        .unwrap();
        let raw_json = serde_json::to_string(&raw_env).unwrap();
        let decoded_raw: RawFeedEnvelope = serde_json::from_str(&raw_json).unwrap();
        assert_eq!(decoded_raw, raw_env);

        // 4. CanonicalFeedEnvelope round trip
        let mut mapper = CanonicalMarketFeedMapper::new(raw_env.target.clone()).unwrap();
        let canonical_env = mapper.map_envelope(raw_env, 1_700_000_000_000).unwrap();
        let canonical_json = serde_json::to_string(&canonical_env).unwrap();
        let decoded_canonical: CanonicalFeedEnvelope =
            serde_json::from_str(&canonical_json).unwrap();
        assert_eq!(decoded_canonical, canonical_env);
    }

    #[test]
    fn regression_fresh_snapshot_deterministic_nonzero_and_zero_age() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        let ctx = sample_sol_context("yellowstone", 100, 1_000_000);
        let raw_snap = RawFeedEnvelope::new(
            ctx,
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 10,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![RawDepthLevel::new(101.0, 1.0)],
            }),
        )
        .unwrap();

        // 1. Non-zero age relative to explicitly supplied evaluation time
        let env_nonzero = mapper.map_envelope(raw_snap.clone(), 1_005_000).unwrap();
        assert_eq!(env_nonzero.freshness.status, FreshnessStatus::Fresh);
        assert_eq!(env_nonzero.freshness.age_ms, 5_000);
        assert_eq!(env_nonzero.freshness.observed_at_ms, 1_000_000);
        assert_eq!(env_nonzero.freshness.evaluated_at_ms, 1_005_000);

        // 2. Zero age relative to explicitly supplied evaluation time == observed time
        let mut mapper_zero = CanonicalMarketFeedMapper::new(target).unwrap();
        let env_zero = mapper_zero.map_envelope(raw_snap, 1_000_000).unwrap();
        assert_eq!(env_zero.freshness.status, FreshnessStatus::Fresh);
        assert_eq!(env_zero.freshness.age_ms, 0);
        assert_eq!(env_zero.freshness.observed_at_ms, 1_000_000);
        assert_eq!(env_zero.freshness.evaluated_at_ms, 1_000_000);
    }

    #[test]
    fn regression_stale_snapshot_returns_stale_with_correct_age() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Observed at 1_000_000, evaluated at 1_015_000 (age 15_000ms > policy staleness 10_000ms)
        let ctx = sample_sol_context("yellowstone", 100, 1_000_000);
        let raw_snap = RawFeedEnvelope::new(
            ctx,
            target,
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 10,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![RawDepthLevel::new(101.0, 1.0)],
            }),
        )
        .unwrap();

        let env = mapper.map_envelope(raw_snap, 1_015_000).unwrap();
        assert_eq!(env.freshness.status, FreshnessStatus::Stale);
        assert_eq!(env.freshness.age_ms, 15_000);
        assert_eq!(env.freshness.observed_at_ms, 1_000_000);
        assert_eq!(env.freshness.evaluated_at_ms, 1_015_000);
        // Stale snapshot establishes baseline sequence but retains Stale classification
        assert_eq!(mapper.current_sequence(), Some(Sequence(10)));
        assert!(!mapper.is_resync_required());
    }

    #[test]
    fn regression_future_skew_returns_resync_required_fail_closed() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Observed at 1_005_000, evaluated at 1_000_000 (skew 5_000ms > default policy max skew 2_000ms)
        let ctx = sample_sol_context("yellowstone", 100, 1_005_000);
        let raw_snap = RawFeedEnvelope::new(
            ctx,
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 10,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![RawDepthLevel::new(101.0, 1.0)],
            }),
        )
        .unwrap();

        let env = mapper.map_envelope(raw_snap, 1_000_000).unwrap();
        assert_eq!(env.freshness.status, FreshnessStatus::ResyncRequired);
        assert_eq!(env.freshness.age_ms, 0);
        assert_eq!(env.freshness.observed_at_ms, 1_005_000);
        assert_eq!(env.freshness.evaluated_at_ms, 1_000_000);

        // Fail closed: mapper must latch resync_required and NOT establish baseline sequence
        assert!(mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), None);
        assert!(mapper.order_book().is_none());

        // Subsequent delta must be rejected fail-closed
        let delta = RawFeedEnvelope::new(
            sample_sol_context("yellowstone", 101, 1_005_100),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 11,
                end_sequence: 11,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(delta, 1_005_100),
            Err(MarketTypeError::ResyncRequired {
                reason: "stream resync latched: valid snapshot required",
            })
        );

        // A valid fresh snapshot clears the latch and restores baseline
        let fresh_snap = RawFeedEnvelope::new(
            sample_sol_context("yellowstone", 102, 1_006_000),
            target,
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 20,
                bids: vec![RawDepthLevel::new(100.0, 1.0)],
                asks: vec![RawDepthLevel::new(101.0, 1.0)],
            }),
        )
        .unwrap();
        let fresh_env = mapper.map_envelope(fresh_snap, 1_006_100).unwrap();
        assert_eq!(fresh_env.freshness.status, FreshnessStatus::Fresh);
        assert!(!mapper.is_resync_required());
        assert_eq!(mapper.current_sequence(), Some(Sequence(20)));
    }

    #[test]
    fn regression_non_orderbook_payloads_preserve_freshness_semantics() {
        // 1. Pool State (CPMM)
        let pool_id = sample_pool_id();
        let pool_target = FeedTarget::Pool(pool_id.clone());
        let mut pool_mapper = CanonicalMarketFeedMapper::new(pool_target.clone()).unwrap();

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

        // 1a. Stale pool state: observed 1_000_000, evaluated 1_020_000 (age 20_000ms > 10_000ms)
        let raw_cpmm = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1_000_000),
            pool_target.clone(),
            RawFeedPayload::PoolState(RawPoolState {
                sequence: 1,
                kind: RawPoolKindState::Cpmm(RawCpmmState {
                    token_0: sol.clone(),
                    token_1: usdc.clone(),
                    decimals_0: 9,
                    decimals_1: 6,
                    reserve_0: 1_000_000_000,
                    reserve_1: 20_000_000,
                    total_lp_supply: Some(100_000),
                    fee_bps: 25,
                }),
            }),
        )
        .unwrap();
        let stale_pool_env = pool_mapper.map_envelope(raw_cpmm, 1_020_000).unwrap();
        assert_eq!(stale_pool_env.freshness.status, FreshnessStatus::Stale);
        assert_eq!(stale_pool_env.freshness.age_ms, 20_000);
        assert_eq!(pool_mapper.current_sequence(), Some(Sequence(1)));

        // 1b. Future skew pool state: observed 1_010_000, evaluated 1_000_000 (skew 10_000ms > 2_000ms)
        let mut skew_pool_mapper = CanonicalMarketFeedMapper::new(pool_target.clone()).unwrap();
        let raw_cpmm_skew = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_010_000),
            pool_target,
            RawFeedPayload::PoolState(RawPoolState {
                sequence: 2,
                kind: RawPoolKindState::Cpmm(RawCpmmState {
                    token_0: sol,
                    token_1: usdc,
                    decimals_0: 9,
                    decimals_1: 6,
                    reserve_0: 1_000_000_000,
                    reserve_1: 20_000_000,
                    total_lp_supply: Some(100_000),
                    fee_bps: 25,
                }),
            }),
        )
        .unwrap();
        let skew_pool_env = skew_pool_mapper
            .map_envelope(raw_cpmm_skew, 1_000_000)
            .unwrap();
        assert_eq!(
            skew_pool_env.freshness.status,
            FreshnessStatus::ResyncRequired
        );
        assert!(skew_pool_mapper.is_resync_required());
        assert_eq!(skew_pool_mapper.current_sequence(), None);
        assert!(skew_pool_mapper.last_pool_state().is_none());

        // 2. Candle payload
        let instrument = sample_instrument();
        let inst_target = FeedTarget::Instrument(instrument.clone());
        let mut candle_mapper = CanonicalMarketFeedMapper::new(inst_target.clone()).unwrap();

        // 2a. Stale candle
        let raw_candle_stale = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1_000_000),
            inst_target.clone(),
            RawFeedPayload::Candle(RawCandle {
                timeframe: CandleTimeframe::M1,
                open_time_ms: 940_000,
                close_time_ms: 1_000_000,
                open: 100.0,
                high: 105.0,
                low: 99.0,
                close: 102.0,
                volume: 50.0,
                quote_volume: None,
                trades_count: None,
                sequence: Some(5),
            }),
        )
        .unwrap();
        let stale_candle_env = candle_mapper
            .map_envelope(raw_candle_stale, 1_020_000)
            .unwrap();
        assert_eq!(stale_candle_env.freshness.status, FreshnessStatus::Stale);
        assert_eq!(stale_candle_env.freshness.age_ms, 20_000);

        // 2b. Future skew candle
        let mut skew_candle_mapper = CanonicalMarketFeedMapper::new(inst_target.clone()).unwrap();
        let raw_candle_skew = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_010_000),
            inst_target,
            RawFeedPayload::Candle(RawCandle {
                timeframe: CandleTimeframe::M1,
                open_time_ms: 950_000,
                close_time_ms: 1_010_000,
                open: 100.0,
                high: 105.0,
                low: 99.0,
                close: 102.0,
                volume: 50.0,
                quote_volume: None,
                trades_count: None,
                sequence: Some(6),
            }),
        )
        .unwrap();
        let skew_candle_env = skew_candle_mapper
            .map_envelope(raw_candle_skew, 1_000_000)
            .unwrap();
        assert_eq!(
            skew_candle_env.freshness.status,
            FreshnessStatus::ResyncRequired
        );
        assert!(skew_candle_mapper.is_resync_required());
    }

    #[test]
    fn regression_rejected_mapper_input_leaves_state_unchanged() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument.clone());
        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

        // Establish initial valid baseline
        let snap = RawFeedEnvelope::new(
            sample_sol_context("src", 100, 1_000_000),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(100.0, 10.0)],
                asks: vec![RawDepthLevel::new(102.0, 10.0)],
            }),
        )
        .unwrap();
        mapper.map_envelope(snap, 1_000_000).unwrap();

        let initial_seq = mapper.current_sequence();
        let initial_ts = mapper.last_timestamp_ms();
        let initial_resync = mapper.is_resync_required();
        let initial_book = mapper.order_book().cloned().unwrap();

        // 1. Rejected on invalid evaluation timestamp (<= 0)
        let delta_valid_data = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_000_100),
            target.clone(),
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(delta_valid_data.clone(), 0),
            Err(MarketTypeError::InvalidTimestamp(0))
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);

        assert_eq!(
            mapper.map_envelope(delta_valid_data, -5),
            Err(MarketTypeError::InvalidTimestamp(-5))
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);

        // 2. Rejected on target mismatch
        let other_target = FeedTarget::Pool(sample_pool_id());
        let wrong_target = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_000_100),
            other_target,
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(100.5, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(wrong_target, 1_000_100),
            Err(MarketTypeError::TargetMismatch)
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);

        // 3. Rejected on stale sequence
        let stale_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_000_100),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 99,
                bids: vec![RawDepthLevel::new(99.0, 1.0)],
                asks: vec![RawDepthLevel::new(103.0, 1.0)],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(stale_snap, 1_000_100),
            Err(MarketTypeError::StaleSequence {
                sequence: 99,
                current: 100
            })
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);

        // 4. Rejected on duplicate sequence
        let dup_snap = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_000_100),
            target.clone(),
            RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                sequence: 100,
                bids: vec![RawDepthLevel::new(99.0, 1.0)],
                asks: vec![RawDepthLevel::new(103.0, 1.0)],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(dup_snap, 1_000_100),
            Err(MarketTypeError::DuplicateSequence(100))
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);

        // 5. Rejected on crossed order book delta
        let crossed_delta = RawFeedEnvelope::new(
            sample_sol_context("src", 101, 1_000_100),
            target,
            RawFeedPayload::OrderBookDelta(RawDepthDelta {
                start_sequence: 101,
                end_sequence: 101,
                bids: vec![RawDepthLevel::new(103.0, 1.0)],
                asks: vec![],
            }),
        )
        .unwrap();
        assert_eq!(
            mapper.map_envelope(crossed_delta, 1_000_100),
            Err(MarketTypeError::CrossedOrderBook)
        );
        assert_eq!(mapper.current_sequence(), initial_seq);
        assert_eq!(mapper.last_timestamp_ms(), initial_ts);
        assert_eq!(mapper.is_resync_required(), initial_resync);
        assert_eq!(mapper.order_book().unwrap(), &initial_book);
    }

    #[test]
    fn regression_bounded_batch_helpers_reject_over_limit_safely() {
        let instrument = sample_instrument();
        let target = FeedTarget::Instrument(instrument);

        let make_envelope = |seq: u64| {
            RawFeedEnvelope::new(
                sample_sol_context("src", seq, 1_000_000),
                target.clone(),
                RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                    sequence: seq,
                    bids: vec![RawDepthLevel::new(100.0, 1.0)],
                    asks: vec![RawDepthLevel::new(101.0, 1.0)],
                }),
            )
            .unwrap()
        };

        // 1. InjectedFeedSource::from_envelopes rejects over-limit input
        let over_limit_vec: Vec<RawFeedEnvelope> = (0..=MAX_FEED_BATCH_SIZE)
            .map(|i| make_envelope(i as u64 + 1))
            .collect();
        assert_eq!(over_limit_vec.len(), MAX_FEED_BATCH_SIZE + 1);

        let err = InjectedFeedSource::from_envelopes(over_limit_vec);
        assert_eq!(
            err.unwrap_err(),
            MarketTypeError::FeedBatchExceeded {
                count: MAX_FEED_BATCH_SIZE + 1,
                max: MAX_FEED_BATCH_SIZE,
            }
        );

        // 2. Exactly at MAX_FEED_BATCH_SIZE succeeds
        let exact_vec: Vec<RawFeedEnvelope> = (0..MAX_FEED_BATCH_SIZE)
            .map(|i| make_envelope(i as u64 + 1))
            .collect();
        let mut source = InjectedFeedSource::from_envelopes(exact_vec).unwrap();
        assert_eq!(source.len(), MAX_FEED_BATCH_SIZE);

        // 3. push_back rejects when capacity reached
        let extra = make_envelope(999_999);
        assert_eq!(
            source.push_back(extra),
            Err(MarketTypeError::FeedBatchExceeded {
                count: MAX_FEED_BATCH_SIZE + 1,
                max: MAX_FEED_BATCH_SIZE,
            })
        );
        assert_eq!(source.len(), MAX_FEED_BATCH_SIZE);

        // 4. process_all_from_source enforces MAX_FEED_BATCH_SIZE before mapping
        // and does NOT advance mapper state for envelope MAX + 1.
        struct TrackingSource {
            target: FeedTarget,
            count: u64,
            yielded_sequences: Vec<u64>,
        }
        impl MarketFeedSource for TrackingSource {
            fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
                self.count += 1;
                let (seq, ts, bid_price, ask_price) = if self.count <= MAX_FEED_BATCH_SIZE as u64 {
                    (
                        self.count,
                        1_000_000 + self.count as i64,
                        100.0 + self.count as f64 * 0.01,
                        200.0 + self.count as f64 * 0.01,
                    )
                } else {
                    // Clearly distinguishable sequence, timestamp, and orderbook prices for MAX+1
                    (99_999, 9_999_999, 888.88, 999.99)
                };

                self.yielded_sequences.push(seq);
                let env = RawFeedEnvelope::new(
                    sample_sol_context("src", seq, ts),
                    self.target.clone(),
                    RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                        sequence: seq,
                        bids: vec![RawDepthLevel::new(bid_price, 10.0 + self.count as f64)],
                        asks: vec![RawDepthLevel::new(ask_price, 20.0 + self.count as f64)],
                    }),
                )?;
                Ok(Some(env))
            }
        }

        // Run baseline mapper with exact MAX_FEED_BATCH_SIZE items
        struct ExactBoundedSource {
            target: FeedTarget,
            count: u64,
        }
        impl MarketFeedSource for ExactBoundedSource {
            fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
                if self.count >= MAX_FEED_BATCH_SIZE as u64 {
                    return Ok(None);
                }
                self.count += 1;
                let seq = self.count;
                let ts = 1_000_000 + self.count as i64;
                let bid_price = 100.0 + self.count as f64 * 0.01;
                let ask_price = 200.0 + self.count as f64 * 0.01;
                let env = RawFeedEnvelope::new(
                    sample_sol_context("src", seq, ts),
                    self.target.clone(),
                    RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                        sequence: seq,
                        bids: vec![RawDepthLevel::new(bid_price, 10.0 + self.count as f64)],
                        asks: vec![RawDepthLevel::new(ask_price, 20.0 + self.count as f64)],
                    }),
                )?;
                Ok(Some(env))
            }
        }

        let mut baseline_mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();
        let mut exact_source = ExactBoundedSource {
            target: target.clone(),
            count: 0,
        };
        let baseline_res = baseline_mapper.process_all_from_source(&mut exact_source, 2_000_000);
        assert_eq!(baseline_res.unwrap().len(), MAX_FEED_BATCH_SIZE);

        let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();
        let mut tracking_source = TrackingSource {
            target: target.clone(),
            count: 0,
            yielded_sequences: Vec::new(),
        };
        let batch_err = mapper.process_all_from_source(&mut tracking_source, 2_000_000);
        assert_eq!(
            batch_err.unwrap_err(),
            MarketTypeError::FeedBatchExceeded {
                count: MAX_FEED_BATCH_SIZE + 1,
                max: MAX_FEED_BATCH_SIZE,
            }
        );

        // Fake source proves that envelope MAX + 1 was yielded to establish attempted count
        assert_eq!(tracking_source.count, (MAX_FEED_BATCH_SIZE + 1) as u64);
        assert_eq!(
            tracking_source.yielded_sequences.len(),
            MAX_FEED_BATCH_SIZE + 1
        );
        assert_eq!(
            tracking_source.yielded_sequences.last().copied(),
            Some(99_999)
        );

        // Mapper state must exactly equal baseline mapper after first MAX_FEED_BATCH_SIZE accepted events
        assert_eq!(mapper, baseline_mapper);
        assert_eq!(
            mapper.current_sequence(),
            Some(Sequence::new(MAX_FEED_BATCH_SIZE as u64))
        );
        assert_eq!(
            mapper.last_timestamp_ms(),
            Some(1_000_000 + MAX_FEED_BATCH_SIZE as i64)
        );
        assert!(!mapper.is_resync_required());

        let book = mapper.order_book().unwrap();
        assert_eq!(book.sequence(), Sequence::new(MAX_FEED_BATCH_SIZE as u64));
        assert_eq!(book.timestamp_ms(), 1_000_000 + MAX_FEED_BATCH_SIZE as i64);
        assert_eq!(
            book.best_bid().unwrap().price.get(),
            100.0 + MAX_FEED_BATCH_SIZE as f64 * 0.01
        );
        assert_eq!(
            book.best_bid().unwrap().quantity.get(),
            10.0 + MAX_FEED_BATCH_SIZE as f64
        );
        assert_eq!(
            book.best_ask().unwrap().price.get(),
            200.0 + MAX_FEED_BATCH_SIZE as f64 * 0.01
        );
        assert_eq!(
            book.best_ask().unwrap().quantity.get(),
            20.0 + MAX_FEED_BATCH_SIZE as f64
        );

        // Explicitly assert that MAX+1 distinguishable properties never leaked into mapper state
        assert_ne!(mapper.current_sequence(), Some(Sequence::new(99_999)));
        assert_ne!(mapper.last_timestamp_ms(), Some(9_999_999));
        assert_ne!(book.best_bid().unwrap().price.get(), 888.88);
        assert_ne!(book.best_ask().unwrap().price.get(), 999.99);

        // 5. Fake source proves extra envelope was not mapped:
        // Envelope MAX+1 carries an invalid target. If map_envelope were called on MAX+1,
        // it would return Err(TargetMismatch). Instead, process_all_from_source returns
        // FeedBatchExceeded, proving MAX+1 never reached map_envelope.
        let other_target = FeedTarget::Pool(sample_pool_id());
        struct PoisonExtraSource {
            valid_target: FeedTarget,
            invalid_target: FeedTarget,
            count: u64,
        }
        impl MarketFeedSource for PoisonExtraSource {
            fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
                self.count += 1;
                let target = if self.count <= MAX_FEED_BATCH_SIZE as u64 {
                    self.valid_target.clone()
                } else {
                    self.invalid_target.clone()
                };
                let env = RawFeedEnvelope::new(
                    sample_sol_context("src", self.count, 1_000_000 + self.count as i64),
                    target,
                    RawFeedPayload::OrderBookSnapshot(RawDepthSnapshot {
                        sequence: self.count,
                        bids: vec![RawDepthLevel::new(
                            100.0 + self.count as f64 * 0.01,
                            10.0 + self.count as f64,
                        )],
                        asks: vec![RawDepthLevel::new(
                            200.0 + self.count as f64 * 0.01,
                            20.0 + self.count as f64,
                        )],
                    }),
                )?;
                Ok(Some(env))
            }
        }

        let mut poison_mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();
        let mut poison_source = PoisonExtraSource {
            valid_target: target,
            invalid_target: other_target,
            count: 0,
        };
        let poison_err = poison_mapper.process_all_from_source(&mut poison_source, 2_000_000);
        assert_eq!(
            poison_err.unwrap_err(),
            MarketTypeError::FeedBatchExceeded {
                count: MAX_FEED_BATCH_SIZE + 1,
                max: MAX_FEED_BATCH_SIZE,
            }
        );
        assert_eq!(poison_source.count, (MAX_FEED_BATCH_SIZE + 1) as u64);
        assert_eq!(poison_mapper, baseline_mapper);

        // 6. Pool state: process_all_from_source enforces MAX_FEED_BATCH_SIZE before mapping
        let pool_id = sample_pool_id();
        let pool_target = FeedTarget::Pool(pool_id);
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

        struct PoolBatchSource {
            target: FeedTarget,
            sol: AssetId,
            usdc: AssetId,
            count: u64,
            max: usize,
        }
        impl MarketFeedSource for PoolBatchSource {
            fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
                if self.count >= self.max as u64 {
                    return Ok(None);
                }
                self.count += 1;
                let (seq, ts, reserve_0) = if self.count <= MAX_FEED_BATCH_SIZE as u64 {
                    (
                        self.count,
                        1_000_000 + self.count as i64,
                        1_000_000_000 + self.count as u128,
                    )
                } else {
                    (99_999, 9_999_999, 999_999_999_999)
                };
                let env = RawFeedEnvelope::new(
                    sample_sol_context("src", seq, ts),
                    self.target.clone(),
                    RawFeedPayload::PoolState(RawPoolState {
                        sequence: seq,
                        kind: RawPoolKindState::Cpmm(RawCpmmState {
                            token_0: self.sol.clone(),
                            token_1: self.usdc.clone(),
                            decimals_0: 9,
                            decimals_1: 6,
                            reserve_0,
                            reserve_1: 20_000_000,
                            total_lp_supply: Some(100_000),
                            fee_bps: 25,
                        }),
                    }),
                )?;
                Ok(Some(env))
            }
        }

        let mut baseline_pool_mapper = CanonicalMarketFeedMapper::new(pool_target.clone()).unwrap();
        let mut baseline_pool_source = PoolBatchSource {
            target: pool_target.clone(),
            sol: sol.clone(),
            usdc: usdc.clone(),
            count: 0,
            max: MAX_FEED_BATCH_SIZE,
        };
        let baseline_pool_res =
            baseline_pool_mapper.process_all_from_source(&mut baseline_pool_source, 2_000_000);
        assert_eq!(baseline_pool_res.unwrap().len(), MAX_FEED_BATCH_SIZE);

        let mut pool_mapper = CanonicalMarketFeedMapper::new(pool_target.clone()).unwrap();
        let mut over_pool_source = PoolBatchSource {
            target: pool_target,
            sol,
            usdc,
            count: 0,
            max: MAX_FEED_BATCH_SIZE + 1,
        };
        let pool_batch_err = pool_mapper.process_all_from_source(&mut over_pool_source, 2_000_000);
        assert_eq!(
            pool_batch_err.unwrap_err(),
            MarketTypeError::FeedBatchExceeded {
                count: MAX_FEED_BATCH_SIZE + 1,
                max: MAX_FEED_BATCH_SIZE,
            }
        );
        assert_eq!(over_pool_source.count, (MAX_FEED_BATCH_SIZE + 1) as u64);
        assert_eq!(pool_mapper, baseline_pool_mapper);
        assert_eq!(
            pool_mapper.current_sequence(),
            Some(Sequence::new(MAX_FEED_BATCH_SIZE as u64))
        );
        assert_eq!(
            pool_mapper.last_timestamp_ms(),
            Some(1_000_000 + MAX_FEED_BATCH_SIZE as i64)
        );
        assert_ne!(pool_mapper.current_sequence(), Some(Sequence::new(99_999)));
        assert_ne!(pool_mapper.last_timestamp_ms(), Some(9_999_999));

        let pool_state = pool_mapper.last_pool_state().unwrap();
        assert_eq!(
            pool_state.sequence,
            Sequence::new(MAX_FEED_BATCH_SIZE as u64)
        );
        assert_eq!(
            pool_state.observed_at_ms,
            1_000_000 + MAX_FEED_BATCH_SIZE as i64
        );
        match &pool_state.state {
            PoolKindState::Cpmm(cpmm) => {
                assert_eq!(
                    cpmm.reserve_0.get(),
                    1_000_000_000 + MAX_FEED_BATCH_SIZE as u128
                );
                assert_ne!(cpmm.reserve_0.get(), 999_999_999_999);
            }
            _ => panic!("expected cpmm pool state"),
        }
    }

    // --- Contract 8: Deterministic Local Pool-State Reducers (P22) ---

    #[test]
    fn test_cpmm_reducer_atomic_staging_and_rollback() {
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
            token_0: sol,
            token_1: usdc,
            decimals_0: 9,
            decimals_1: 6,
            reserve_0: AtomicAmount::new(1_000_000_000),
            reserve_1: AtomicAmount::new(150_000_000_000),
            total_lp_supply: Some(AtomicAmount::new(500_000_000)),
            fee_bps: Bps::new(30).unwrap(),
        };

        let mut reducer =
            CpmmPoolReducer::new(pool_id, Sequence(100), 1_000_000, cpmm.clone()).unwrap();

        // 1. Invalid timestamp (<= 0)
        let delta = CpmmPoolDelta::new(Some(AtomicAmount::new(2_000_000_000)), None, None, None);
        let err = reducer.apply_delta(SequenceRange::point(Sequence(101)).unwrap(), 0, &delta);
        assert_eq!(err, Err(MarketTypeError::InvalidTimestamp(0)));
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.state().reserve_0.get(), 1_000_000_000);

        // 2. Setting reserve_0 to zero fails closed with ZeroAmount
        let zero_delta = CpmmPoolDelta::new(Some(AtomicAmount::ZERO), None, None, None);
        let err2 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &zero_delta,
        );
        assert_eq!(err2, Err(MarketTypeError::ZeroAmount));
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.state().reserve_0.get(), 1_000_000_000);

        // 3. Setting reserve_1 to zero fails closed with ZeroAmount
        let zero_delta1 = CpmmPoolDelta::new(None, Some(AtomicAmount::ZERO), None, None);
        let err3 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &zero_delta1,
        );
        assert_eq!(err3, Err(MarketTypeError::ZeroAmount));
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.state().reserve_1.get(), 150_000_000_000);

        // 4. Valid contiguous delta commits atomically
        let valid_delta = CpmmPoolDelta::new(
            Some(AtomicAmount::new(1_100_000_000)),
            Some(AtomicAmount::new(140_000_000_000)),
            Some(AtomicAmount::new(510_000_000)),
            Some(Bps::new(25).unwrap()),
        );
        let outcome = reducer
            .apply_delta(
                SequenceRange::point(Sequence(101)).unwrap(),
                1_000_100,
                &valid_delta,
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
        assert_eq!(reducer.state().reserve_0.get(), 1_100_000_000);
        assert_eq!(reducer.state().reserve_1.get(), 140_000_000_000);
        assert_eq!(reducer.state().total_lp_supply.unwrap().get(), 510_000_000);
        assert_eq!(reducer.state().fee_bps.get(), 25);
    }

    #[test]
    fn test_clmm_reducer_atomic_staging_and_rollback() {
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
        let clmm = ClmmPoolState {
            token_0: sol,
            token_1: usdc,
            decimals_0: 9,
            decimals_1: 6,
            tick_spacing: 64,
            current_tick: 0,
            sqrt_price_x64: 18446744073709551616,
            liquidity: 50_000,
            fee_bps: Bps::new(5).unwrap(),
            ticks: vec![
                ClmmTick::new(-128, 10_000, 10_000),
                ClmmTick::new(0, 20_000, -5_000),
                ClmmTick::new(128, 15_000, -5_000),
            ],
        };

        let mut reducer =
            ClmmPoolReducer::new(pool_id, Sequence(100), 1_000_000, clmm.clone(), 5).unwrap();

        // 1. Tick spacing mismatch fails closed
        let bad_spacing =
            ClmmPoolDelta::new(None, None, None, None, vec![ClmmTick::new(65, 1_000, 100)]);
        let err = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_spacing,
        );
        assert_eq!(
            err,
            Err(MarketTypeError::TickSpacingMismatch {
                tick: 65,
                spacing: 64
            })
        );
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.ticks().len(), 3);

        // 2. Net liquidity > gross liquidity fails closed
        let bad_net = ClmmPoolDelta::new(
            None,
            None,
            None,
            None,
            vec![ClmmTick::new(64, 1_000, 2_000)],
        );
        let err2 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_net,
        );
        assert_eq!(err2, Err(MarketTypeError::InvalidTickLiquidity(64)));
        assert_eq!(reducer.sequence(), Sequence(100));

        // 3. Gross 0 but net != 0 fails closed
        let zero_gross_net =
            ClmmPoolDelta::new(None, None, None, None, vec![ClmmTick::new(64, 0, 500)]);
        let err3 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &zero_gross_net,
        );
        assert_eq!(err3, Err(MarketTypeError::InvalidTickLiquidity(64)));
        assert_eq!(reducer.sequence(), Sequence(100));

        // 4. Duplicate tick in delta fails closed
        let dup_tick_delta = ClmmPoolDelta::new(
            None,
            None,
            None,
            None,
            vec![ClmmTick::new(64, 1_000, 0), ClmmTick::new(64, 2_000, 0)],
        );
        let err4 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &dup_tick_delta,
        );
        assert_eq!(err4, Err(MarketTypeError::DuplicateClmmTick(64)));
        assert_eq!(reducer.sequence(), Sequence(100));

        // 5. Exceeding max_ticks (initial has 3, max is 5; adding 3 = 6 > 5) fails closed
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
        let err5 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &overflow_delta,
        );
        assert_eq!(
            err5,
            Err(MarketTypeError::ClmmTicksExceeded { count: 6, max: 5 })
        );
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.ticks().len(), 3);

        // 6. Valid insertion, update, and deletion in sorted order succeeds
        let valid_delta = ClmmPoolDelta::new(
            Some(64),
            Some(18500000000000000000),
            Some(55_000),
            Some(Bps::new(10).unwrap()),
            vec![
                ClmmTick::new(-128, 0, 0),          // delete -128
                ClmmTick::new(64, 8_000, 2_000),    // insert 64
                ClmmTick::new(128, 20_000, -2_000), // update 128
            ],
        );
        let outcome = reducer
            .apply_delta(
                SequenceRange::point(Sequence(101)).unwrap(),
                1_000_100,
                &valid_delta,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(101)
            }
        );
        assert_eq!(reducer.sequence(), Sequence(101));
        assert_eq!(reducer.current_tick(), 64);
        assert_eq!(reducer.sqrt_price_x64(), 18500000000000000000);
        assert_eq!(reducer.liquidity(), 55_000);
        // Ticks should be strictly sorted: [0, 64, 128]
        assert_eq!(reducer.ticks().len(), 3);
        assert_eq!(reducer.ticks()[0].index, 0);
        assert_eq!(reducer.ticks()[1].index, 64);
        assert_eq!(reducer.ticks()[1].liquidity_gross, 8_000);
        assert_eq!(reducer.ticks()[2].index, 128);
        assert_eq!(reducer.ticks()[2].liquidity_gross, 20_000);
    }

    #[test]
    fn test_bin_reducer_atomic_staging_and_rollback() {
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
        let bin_pool = BinPoolState {
            token_0: sol,
            token_1: usdc,
            decimals_0: 9,
            decimals_1: 6,
            active_bin_id: 100,
            bin_step: 10,
            fee_bps: Bps::new(10).unwrap(),
            bins: vec![
                LiquidityBin::new(98, AtomicAmount::ZERO, AtomicAmount::new(50_000)),
                LiquidityBin::new(100, AtomicAmount::new(20_000), AtomicAmount::new(30_000)),
                LiquidityBin::new(102, AtomicAmount::new(60_000), AtomicAmount::ZERO),
            ],
        };

        let mut reducer =
            BinPoolReducer::new(pool_id, Sequence(100), 1_000_000, bin_pool.clone(), 5).unwrap();

        // 1. Bin below active bin cannot have reserve_0 > 0
        let bad_below = BinPoolDelta::new(
            None,
            None,
            None,
            vec![LiquidityBin::new(
                98,
                AtomicAmount::new(1),
                AtomicAmount::new(50_000),
            )],
        );
        let err = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_below,
        );
        assert_eq!(
            err,
            Err(MarketTypeError::BinReserveSideViolation {
                bin_id: 98,
                active_bin_id: 100
            })
        );
        assert_eq!(reducer.sequence(), Sequence(100));
        assert_eq!(reducer.bins().len(), 3);

        // 2. Bin above active bin cannot have reserve_1 > 0
        let bad_above = BinPoolDelta::new(
            None,
            None,
            None,
            vec![LiquidityBin::new(
                102,
                AtomicAmount::new(60_000),
                AtomicAmount::new(1),
            )],
        );
        let err2 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_above,
        );
        assert_eq!(
            err2,
            Err(MarketTypeError::BinReserveSideViolation {
                bin_id: 102,
                active_bin_id: 100
            })
        );
        assert_eq!(reducer.sequence(), Sequence(100));

        // 3. Shift active_bin_id to 105 without clearing reserve_0 on bin 100/102 (now below active bin)
        let bad_shift = BinPoolDelta::new(Some(105), None, None, vec![]);
        let err3 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &bad_shift,
        );
        assert_eq!(
            err3,
            Err(MarketTypeError::BinReserveSideViolation {
                bin_id: 100,
                active_bin_id: 105
            })
        );
        assert_eq!(reducer.sequence(), Sequence(100));

        // 4. Duplicate bin in delta fails closed
        let dup_bin_delta = BinPoolDelta::new(
            None,
            None,
            None,
            vec![
                LiquidityBin::new(104, AtomicAmount::new(10_000), AtomicAmount::ZERO),
                LiquidityBin::new(104, AtomicAmount::new(20_000), AtomicAmount::ZERO),
            ],
        );
        let err4 = reducer.apply_delta(
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            &dup_bin_delta,
        );
        assert_eq!(err4, Err(MarketTypeError::DuplicateBin(104)));
        assert_eq!(reducer.sequence(), Sequence(100));

        // 5. Valid contiguous delta: insert 104, update 100, delete 98
        let valid_delta = BinPoolDelta::new(
            None,
            None,
            None,
            vec![
                LiquidityBin::new(98, AtomicAmount::ZERO, AtomicAmount::ZERO), // delete 98
                LiquidityBin::new(100, AtomicAmount::new(25_000), AtomicAmount::new(25_000)), // update 100
                LiquidityBin::new(104, AtomicAmount::new(40_000), AtomicAmount::ZERO), // insert 104
            ],
        );
        let outcome = reducer
            .apply_delta(
                SequenceRange::point(Sequence(101)).unwrap(),
                1_000_100,
                &valid_delta,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(101)
            }
        );
        assert_eq!(reducer.sequence(), Sequence(101));
        assert_eq!(reducer.bins().len(), 3);
        assert_eq!(reducer.bins()[0].id, 100);
        assert_eq!(reducer.bins()[1].id, 102);
        assert_eq!(reducer.bins()[2].id, 104);
    }

    #[test]
    fn test_pool_reducers_sticky_resync_gap_overlap_and_newer_snapshot_recovery() {
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
            reserve_0: AtomicAmount::new(1_000_000_000),
            reserve_1: AtomicAmount::new(150_000_000_000),
            total_lp_supply: Some(AtomicAmount::new(500_000_000)),
            fee_bps: Bps::new(30).unwrap(),
        };

        let mut reducer =
            CpmmPoolReducer::new(pool_id.clone(), Sequence(100), 1_000_000, cpmm.clone()).unwrap();

        // Gap delta [105, 105] on current 100 latches resync
        let gap_delta =
            CpmmPoolDelta::new(Some(AtomicAmount::new(1_050_000_000)), None, None, None);
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

        // Subsequent contiguous delta [101, 101] MUST still return ResyncRequired
        let cont_delta =
            CpmmPoolDelta::new(Some(AtomicAmount::new(1_050_000_000)), None, None, None);
        let rejected = reducer
            .apply_delta(
                SequenceRange::point(Sequence(101)).unwrap(),
                1_000_200,
                &cont_delta,
            )
            .unwrap();
        assert_eq!(
            rejected,
            DeltaClassification::ResyncRequired {
                expected: Sequence(101),
                received: Sequence(101),
            }
        );
        assert_eq!(reducer.sequence(), Sequence(100));

        // Stale snapshot (< 100) rejected, latch held
        let stale_snap = cpmm.clone();
        let stale_res = reducer
            .apply_snapshot(Sequence(99), 1_000_250, stale_snap)
            .unwrap();
        assert_eq!(
            stale_res,
            SnapshotClassification::Stale {
                sequence: Sequence(99),
                current: Sequence(100)
            }
        );
        assert!(reducer.is_resync_required());

        // Duplicate snapshot (== 100) rejected, latch held
        let dup_snap = cpmm.clone();
        let dup_res = reducer
            .apply_snapshot(Sequence(100), 1_000_260, dup_snap)
            .unwrap();
        assert_eq!(
            dup_res,
            SnapshotClassification::Duplicate {
                sequence: Sequence(100)
            }
        );
        assert!(reducer.is_resync_required());

        // Valid newer snapshot (> 100) accepted, clears latch!
        let mut newer_cpmm = cpmm.clone();
        newer_cpmm.reserve_0 = AtomicAmount::new(2_000_000_000);
        let accepted = reducer
            .apply_snapshot(Sequence(110), 1_000_300, newer_cpmm)
            .unwrap();
        assert_eq!(
            accepted,
            SnapshotClassification::Accepted {
                new_sequence: Sequence(110)
            }
        );
        assert!(!reducer.is_resync_required());
        assert_eq!(reducer.sequence(), Sequence(110));
        assert_eq!(reducer.state().reserve_0.get(), 2_000_000_000);

        // Next contiguous delta [111, 111] now succeeds cleanly
        let next_delta =
            CpmmPoolDelta::new(Some(AtomicAmount::new(2_100_000_000)), None, None, None);
        let next_outcome = reducer
            .apply_delta(
                SequenceRange::point(Sequence(111)).unwrap(),
                1_000_400,
                &next_delta,
            )
            .unwrap();
        assert_eq!(
            next_outcome,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(111)
            }
        );
        assert_eq!(reducer.sequence(), Sequence(111));
    }

    #[test]
    fn test_unified_pool_reducer_cross_dispatch_and_fail_closed() {
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
            token_0: sol,
            token_1: usdc,
            decimals_0: 9,
            decimals_1: 6,
            reserve_0: AtomicAmount::new(1_000_000_000),
            reserve_1: AtomicAmount::new(150_000_000_000),
            total_lp_supply: Some(AtomicAmount::new(500_000_000)),
            fee_bps: Bps::new(30).unwrap(),
        };
        let envelope = PoolStateEnvelope {
            pool_id: pool_id.clone(),
            sequence: Sequence(100),
            observed_at_ms: 1_000_000,
            state: PoolKindState::Cpmm(cpmm),
        };

        let mut unified = PoolReducer::new(envelope).unwrap();
        assert_eq!(unified.sequence(), Sequence(100));

        // Applying CLMM delta to CPMM reducer fails closed with PoolKindMismatch
        let clmm_delta_envelope = PoolDeltaEnvelope::new(
            pool_id.clone(),
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            PoolKindDelta::Clmm(ClmmPoolDelta::new(Some(0), None, None, None, vec![])),
        )
        .unwrap();
        let err = unified.apply_delta(&clmm_delta_envelope);
        assert_eq!(
            err,
            Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: "clmm"
            })
        );
        assert_eq!(unified.sequence(), Sequence(100));

        // Applying Bin delta to CPMM reducer fails closed with PoolKindMismatch
        let bin_delta_envelope = PoolDeltaEnvelope::new(
            pool_id.clone(),
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            PoolKindDelta::Bin(BinPoolDelta::new(Some(100), None, None, vec![])),
        )
        .unwrap();
        let err2 = unified.apply_delta(&bin_delta_envelope);
        assert_eq!(
            err2,
            Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: "bin"
            })
        );
        assert_eq!(unified.sequence(), Sequence(100));

        // Applying CPMM delta with mismatched PoolId fails closed with TargetMismatch
        let other_pool_id =
            PoolId::new(ChainId::Solana, "11111111111111111111111111111111").unwrap();
        let target_mismatch_delta = PoolDeltaEnvelope::new(
            other_pool_id,
            SequenceRange::point(Sequence(101)).unwrap(),
            1_000_100,
            PoolKindDelta::Cpmm(CpmmPoolDelta::new(
                Some(AtomicAmount::new(2_000_000_000)),
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
}
