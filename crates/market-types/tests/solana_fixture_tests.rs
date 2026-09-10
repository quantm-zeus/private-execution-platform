//! Deterministic Solana snapshot and delta fixture normalization tests.
//!
//! Validates fixture-driven normalization of deterministic Solana order-book snapshots
//! and deltas through the CanonicalMarketFeedMapper boundary. Exercises serialized raw feed
//! envelopes using synthetic, non-sensitive fixtures.

use chain_types::{AssetId, ChainId};
use market_types::{
    CanonicalFeedPayload, CanonicalMarketFeedMapper, ChainFamily, FeedFinality,
    FeedObservationContext, FeedSourceLabel, FeedTarget, FreshnessStatus, InjectedFeedSource,
    InstrumentId, MarketTypeError, RawDepthDelta, RawDepthLevel, RawFeedEnvelope, RawFeedPayload,
    Sequence, SequenceRange, MAX_DEPTH_LEVELS,
};

// Fixture JSON definitions loaded deterministically at compile-time
const FIXTURE_VALID_SNAPSHOT: &str = include_str!("fixtures/solana/valid_snapshot.json");
const FIXTURE_VALID_DELTA_101: &str = include_str!("fixtures/solana/valid_delta_101.json");
const FIXTURE_VALID_DELTA_102: &str = include_str!("fixtures/solana/valid_delta_102.json");
const FIXTURE_GAP_DELTA: &str = include_str!("fixtures/solana/gap_delta.json");
const FIXTURE_OVERLAP_DELTA: &str = include_str!("fixtures/solana/overlap_delta.json");
const FIXTURE_TARGET_MISMATCH: &str = include_str!("fixtures/solana/snapshot_target_mismatch.json");
const FIXTURE_CHAIN_MISMATCH: &str = include_str!("fixtures/solana/snapshot_chain_mismatch.json");
const FIXTURE_NEGATIVE_PRICE: &str = include_str!("fixtures/solana/snapshot_negative_price.json");
const FIXTURE_NEGATIVE_QUANTITY: &str =
    include_str!("fixtures/solana/delta_negative_quantity.json");
const FIXTURE_OVERBOUND_LEVELS: &str =
    include_str!("fixtures/solana/snapshot_overbound_levels.json");
const FIXTURE_STALE_SNAPSHOT: &str = include_str!("fixtures/solana/snapshot_stale.json");
const FIXTURE_DUPLICATE_SNAPSHOT: &str = include_str!("fixtures/solana/snapshot_duplicate.json");
const FIXTURE_RECOVERY_SNAPSHOT: &str = include_str!("fixtures/solana/snapshot_recovery.json");
const FIXTURE_POST_RECOVERY_DELTA: &str = include_str!("fixtures/solana/delta_post_recovery.json");
const FIXTURE_MALFORMED_ENVELOPE: &str = include_str!("fixtures/solana/malformed_envelope.json");

/// Helper to deserialize a raw feed envelope from a fixture JSON string.
fn load_envelope_fixture(json_str: &str) -> RawFeedEnvelope {
    serde_json::from_str(json_str).expect("failed to deserialize raw feed envelope fixture")
}

/// Helper to construct canonical synthetic SOL/USDC instrument target.
fn synthetic_sol_usdc_target() -> FeedTarget {
    let base = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .expect("valid synthetic SOL asset");
    let quote = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .expect("valid synthetic USDC asset");
    FeedTarget::Instrument(InstrumentId::new(base, quote).expect("valid synthetic instrument pair"))
}

// ---------------------------------------------------------------------------
// 1. Valid Solana Snapshot & Contiguous Delta Normalization
// ---------------------------------------------------------------------------

#[test]
fn test_solana_fixtures_normalize_snapshot_and_contiguous_deltas() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target.clone())
        .expect("mapper initialization should succeed");

    // Evaluation timestamp explicitly supplied by caller (deterministic, no wall clock)
    let evaluated_at_ms = 1_700_000_000_500i64;

    // --- 1. Normalize valid snapshot fixture (sequence 100) ---
    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    assert_eq!(snap_env.target, target);
    assert_eq!(snap_env.context.source_family, ChainFamily::Solana);
    assert_eq!(
        snap_env.context.source_label.as_str(),
        "solana-synthetic-primary"
    );
    assert_eq!(snap_env.context.finality, FeedFinality::Confirmed);
    assert_eq!(snap_env.context.slot_or_block, Some(250_000_100));
    assert_eq!(snap_env.context.observed_at_ms, 1_700_000_000_000);

    let canonical_snap = mapper
        .map_envelope(snap_env.clone(), evaluated_at_ms)
        .expect("valid Solana snapshot fixture should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_snap.context, snap_env.context);
    assert_eq!(canonical_snap.context.source_family, ChainFamily::Solana);
    assert_eq!(
        canonical_snap.context.source_label.as_str(),
        "solana-synthetic-primary"
    );
    assert_eq!(canonical_snap.context.finality, FeedFinality::Confirmed);
    assert_eq!(canonical_snap.context.slot_or_block, Some(250_000_100));
    assert_eq!(canonical_snap.context.observed_at_ms, 1_700_000_000_000);

    // Assert deterministic freshness
    assert_eq!(canonical_snap.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(canonical_snap.freshness.age_ms, 500);
    assert_eq!(canonical_snap.freshness.observed_at_ms, 1_700_000_000_000);
    assert_eq!(canonical_snap.freshness.evaluated_at_ms, evaluated_at_ms);
    assert_eq!(canonical_snap.freshness.sequence, Sequence(100));

    // Assert canonical task-20 DepthSnapshot payload
    match &canonical_snap.payload {
        CanonicalFeedPayload::OrderBookSnapshot(snapshot) => {
            assert_eq!(snapshot.target, target);
            assert_eq!(snapshot.sequence, Sequence(100));
            assert_eq!(snapshot.timestamp_ms, 1_700_000_000_000);
            assert_eq!(snapshot.bids.len(), 3);
            assert_eq!(snapshot.bids[0].price.get(), 150.0);
            assert_eq!(snapshot.bids[0].quantity.get(), 10.0);
            assert_eq!(snapshot.bids[1].price.get(), 149.0);
            assert_eq!(snapshot.bids[1].quantity.get(), 20.0);
            assert_eq!(snapshot.bids[2].price.get(), 148.0);
            assert_eq!(snapshot.bids[2].quantity.get(), 30.0);
            assert_eq!(snapshot.asks.len(), 3);
            assert_eq!(snapshot.asks[0].price.get(), 151.0);
            assert_eq!(snapshot.asks[0].quantity.get(), 15.0);
            assert_eq!(snapshot.asks[1].price.get(), 152.0);
            assert_eq!(snapshot.asks[1].quantity.get(), 25.0);
            assert_eq!(snapshot.asks[2].price.get(), 153.0);
            assert_eq!(snapshot.asks[2].quantity.get(), 35.0);
        }
        _ => panic!("expected OrderBookSnapshot payload variant"),
    }

    // Assert mapper state after snapshot
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_000));
    assert!(!mapper.is_resync_required());
    let book = mapper
        .order_book()
        .expect("orderbook should be initialized");
    assert_eq!(book.sequence(), Sequence(100));
    assert_eq!(book.timestamp_ms(), 1_700_000_000_000);
    assert_eq!(book.best_bid().unwrap().price.get(), 150.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 151.0);
    assert_eq!(book.spread(), Some(1.0));
    assert_eq!(book.mid_price().unwrap().get(), 150.5);

    // --- 2. Normalize first contiguous delta fixture (sequence 101) ---
    let delta1_env = load_envelope_fixture(FIXTURE_VALID_DELTA_101);
    let canonical_delta1 = mapper
        .map_envelope(delta1_env.clone(), evaluated_at_ms)
        .expect("valid contiguous delta 101 should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_delta1.context, delta1_env.context);
    assert_eq!(canonical_delta1.context.source_family, ChainFamily::Solana);
    assert_eq!(canonical_delta1.context.slot_or_block, Some(250_000_101));
    assert_eq!(canonical_delta1.context.observed_at_ms, 1_700_000_000_100);

    // Assert deterministic freshness (age = 500 - 100 = 400ms)
    assert_eq!(canonical_delta1.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(canonical_delta1.freshness.age_ms, 400);
    assert_eq!(canonical_delta1.freshness.observed_at_ms, 1_700_000_000_100);
    assert_eq!(canonical_delta1.freshness.sequence, Sequence(101));

    // Assert canonical task-20 DepthDelta payload
    match &canonical_delta1.payload {
        CanonicalFeedPayload::OrderBookDelta(delta) => {
            assert_eq!(delta.target, target);
            assert_eq!(
                delta.sequence_range,
                SequenceRange::point(Sequence(101)).unwrap()
            );
            assert_eq!(delta.timestamp_ms, 1_700_000_000_100);
            assert_eq!(delta.bids.len(), 1);
            assert_eq!(delta.bids[0].price.get(), 150.5);
            assert_eq!(delta.bids[0].quantity.get(), 5.0);
            assert_eq!(delta.asks.len(), 1);
            assert_eq!(delta.asks[0].price.get(), 151.0);
            assert_eq!(delta.asks[0].quantity.get(), 0.0);
        }
        _ => panic!("expected OrderBookDelta payload variant"),
    }

    // Assert mapper state transitioned correctly
    assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_100));
    assert!(!mapper.is_resync_required());
    let book = mapper.order_book().unwrap();
    assert_eq!(book.sequence(), Sequence(101));
    assert_eq!(book.timestamp_ms(), 1_700_000_000_100);
    // New top bid is 150.5; top ask 151.0 was removed (quantity 0), so remaining best ask is 152.0
    assert_eq!(book.best_bid().unwrap().price.get(), 150.5);
    assert_eq!(book.best_bid().unwrap().quantity.get(), 5.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 152.0);
    assert_eq!(book.best_ask().unwrap().quantity.get(), 25.0);
    assert_eq!(book.spread(), Some(1.5));

    // --- 3. Normalize second contiguous delta fixture (sequence 102) ---
    let delta2_env = load_envelope_fixture(FIXTURE_VALID_DELTA_102);
    let canonical_delta2 = mapper
        .map_envelope(delta2_env.clone(), evaluated_at_ms)
        .expect("valid contiguous delta 102 should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_delta2.context, delta2_env.context);
    assert_eq!(canonical_delta2.context.slot_or_block, Some(250_000_102));
    assert_eq!(canonical_delta2.context.observed_at_ms, 1_700_000_000_200);

    // Assert deterministic freshness (age = 500 - 200 = 300ms)
    assert_eq!(canonical_delta2.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(canonical_delta2.freshness.age_ms, 300);
    assert_eq!(canonical_delta2.freshness.sequence, Sequence(102));

    // Assert canonical task-20 DepthDelta payload
    match &canonical_delta2.payload {
        CanonicalFeedPayload::OrderBookDelta(delta) => {
            assert_eq!(delta.target, target);
            assert_eq!(
                delta.sequence_range,
                SequenceRange::point(Sequence(102)).unwrap()
            );
            assert_eq!(delta.timestamp_ms, 1_700_000_000_200);
            assert_eq!(delta.bids.len(), 1);
            assert_eq!(delta.bids[0].price.get(), 150.0);
            assert_eq!(delta.bids[0].quantity.get(), 12.0);
            assert_eq!(delta.asks.len(), 1);
            assert_eq!(delta.asks[0].price.get(), 151.5);
            assert_eq!(delta.asks[0].quantity.get(), 8.0);
        }
        _ => panic!("expected OrderBookDelta payload variant"),
    }

    // Assert mapper state transitioned to sequence 102
    assert_eq!(mapper.current_sequence(), Some(Sequence(102)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_200));
    assert!(!mapper.is_resync_required());
    let book = mapper.order_book().unwrap();
    assert_eq!(book.sequence(), Sequence(102));
    assert_eq!(book.timestamp_ms(), 1_700_000_000_200);
    assert_eq!(book.best_bid().unwrap().price.get(), 150.5);
    // Ask 151.5 was inserted, which is better than 152.0
    assert_eq!(book.best_ask().unwrap().price.get(), 151.5);
    assert_eq!(book.best_ask().unwrap().quantity.get(), 8.0);
    assert_eq!(book.spread(), Some(1.0));
}

#[test]
fn test_solana_fixtures_batch_ingestion_via_source() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    let delta1_env = load_envelope_fixture(FIXTURE_VALID_DELTA_101);
    let delta2_env = load_envelope_fixture(FIXTURE_VALID_DELTA_102);

    let mut source = InjectedFeedSource::from_envelopes(vec![snap_env, delta1_env, delta2_env])
        .expect("batch of 3 fixture envelopes should be within limits");
    assert_eq!(source.len(), 3);

    let evaluated_at_ms = 1_700_000_000_500i64;
    let mapped_events = mapper
        .process_all_from_source(&mut source, evaluated_at_ms)
        .expect("batch processing from source should succeed");

    assert_eq!(mapped_events.len(), 3);
    assert_eq!(mapper.current_sequence(), Some(Sequence(102)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_200));
    assert!(!mapper.is_resync_required());
    assert!(source.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Fail-Closed Fixture Regressions: Malformed, Overbound, Non-Finite
// ---------------------------------------------------------------------------

#[test]
fn test_regression_malformed_fixture_json_fails_closed() {
    let res = serde_json::from_str::<RawFeedEnvelope>(FIXTURE_MALFORMED_ENVELOPE);
    assert!(
        res.is_err(),
        "malformed envelope fixture must fail deserialization"
    );
}

#[test]
fn test_regression_negative_price_fixture_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Establish baseline snapshot
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Attempt to map snapshot with negative price
    let bad_price_env = load_envelope_fixture(FIXTURE_NEGATIVE_PRICE);
    let err = mapper
        .map_envelope(bad_price_env, 1_700_000_000_500)
        .expect_err("negative price must be rejected");
    assert_eq!(err, MarketTypeError::NegativePrice);

    // Mapper state must remain strictly unchanged
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
}

#[test]
fn test_regression_negative_quantity_fixture_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Establish baseline snapshot
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Attempt to map delta with negative quantity
    let bad_qty_env = load_envelope_fixture(FIXTURE_NEGATIVE_QUANTITY);
    let err = mapper
        .map_envelope(bad_qty_env, 1_700_000_000_500)
        .expect_err("negative quantity must be rejected");
    assert_eq!(err, MarketTypeError::NegativeQuantity);

    // Mapper state must remain strictly unchanged
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
}

#[test]
fn test_regression_overbound_levels_fixture_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    let overbound_env = load_envelope_fixture(FIXTURE_OVERBOUND_LEVELS);
    let err = mapper
        .map_envelope(overbound_env, 1_700_000_000_500)
        .expect_err("overbound levels fixture (> 5000) must be rejected");
    assert_eq!(
        err,
        MarketTypeError::DepthLevelsExceeded {
            count: 5001,
            max: MAX_DEPTH_LEVELS,
        }
    );

    // Mapper state must remain uninitialized
    assert_eq!(mapper.current_sequence(), None);
    assert_eq!(mapper.last_timestamp_ms(), None);
    assert!(!mapper.is_resync_required());
    assert!(mapper.order_book().is_none());
}

#[test]
fn test_regression_non_finite_fixture_data_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

    // Baseline
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // 1. Non-finite price in delta (NaN)
    let nan_price_env = RawFeedEnvelope::new(
        FeedObservationContext::new(
            ChainFamily::Solana,
            FeedSourceLabel::new("solana-synthetic-primary").unwrap(),
            FeedFinality::Confirmed,
            Some(250_000_101),
            1_700_000_000_100,
        )
        .unwrap(),
        target.clone(),
        RawFeedPayload::OrderBookDelta(RawDepthDelta {
            start_sequence: 101,
            end_sequence: 101,
            bids: vec![RawDepthLevel::new(f64::NAN, 10.0)],
            asks: vec![],
        }),
    )
    .unwrap();

    let err = mapper
        .map_envelope(nan_price_env, 1_700_000_000_500)
        .expect_err("NaN price must be rejected");
    assert_eq!(err, MarketTypeError::NonFinitePrice);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert_eq!(mapper.order_book().unwrap(), &initial_book);

    // 2. Non-finite quantity in delta (Infinity)
    let inf_qty_env = RawFeedEnvelope::new(
        FeedObservationContext::new(
            ChainFamily::Solana,
            FeedSourceLabel::new("solana-synthetic-primary").unwrap(),
            FeedFinality::Confirmed,
            Some(250_000_101),
            1_700_000_000_100,
        )
        .unwrap(),
        target,
        RawFeedPayload::OrderBookDelta(RawDepthDelta {
            start_sequence: 101,
            end_sequence: 101,
            bids: vec![RawDepthLevel::new(150.0, f64::INFINITY)],
            asks: vec![],
        }),
    )
    .unwrap();

    let err_qty = mapper
        .map_envelope(inf_qty_env, 1_700_000_000_500)
        .expect_err("Infinity quantity must be rejected");
    assert_eq!(err_qty, MarketTypeError::NonFiniteQuantity);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
}

// ---------------------------------------------------------------------------
// 3. Fail-Closed Fixture Regressions: Target & Chain-Family Mismatch
// ---------------------------------------------------------------------------

#[test]
fn test_regression_target_mismatch_fixture_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Baseline
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map envelope with pool target instead of SOL/USDC instrument
    let mismatch_env = load_envelope_fixture(FIXTURE_TARGET_MISMATCH);
    let err = mapper
        .map_envelope(mismatch_env, 1_700_000_000_500)
        .expect_err("target mismatch fixture must be rejected");
    assert_eq!(err, MarketTypeError::TargetMismatch);

    // Mapper state completely untouched
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
}

#[test]
fn test_regression_chain_family_mismatch_fixture_rejected_state_unchanged() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Baseline
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map envelope where source_family is "evm" for a Solana target
    let mismatch_env = load_envelope_fixture(FIXTURE_CHAIN_MISMATCH);
    let err = mapper
        .map_envelope(mismatch_env, 1_700_000_000_500)
        .expect_err("chain family mismatch fixture must be rejected");
    assert_eq!(
        err,
        MarketTypeError::SourceChainFamilyMismatch {
            source_family: "evm",
            target_chain: "solana",
        }
    );

    // Mapper state completely untouched
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
}

// ---------------------------------------------------------------------------
// 4. Fail-Closed Fixture Regressions: Gap, Overlap, Resync Latch & Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_regression_gap_delta_latches_resync_until_recovery_snapshot() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // 1. Establish valid baseline snapshot (sequence 100)
    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper.map_envelope(snap_env, 1_700_000_000_500).unwrap();
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_000));
    assert!(!mapper.is_resync_required());
    let baseline_book = mapper.order_book().cloned().unwrap();

    // 2. Feed sequence gap delta fixture (start_sequence 105 when expecting 101)
    let gap_env = load_envelope_fixture(FIXTURE_GAP_DELTA);
    let gap_err = mapper
        .map_envelope(gap_env, 1_700_000_000_500)
        .expect_err("gap delta must fail closed");
    assert_eq!(
        gap_err,
        MarketTypeError::SequenceGap {
            expected: 101,
            received: 105,
        }
    );

    // Assert sequence and timestamp did NOT mutate to 105
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_000));
    assert!(
        mapper.is_resync_required(),
        "resync must be latched upon sequence gap"
    );

    // Assert order book contents are unmutated (bids/asks/seq/ts unchanged, but resync latched)
    let book = mapper.order_book().unwrap();
    assert_eq!(book.bids(), baseline_book.bids());
    assert_eq!(book.asks(), baseline_book.asks());
    assert_eq!(book.sequence(), baseline_book.sequence());
    assert_eq!(book.timestamp_ms(), baseline_book.timestamp_ms());
    assert!(book.is_resync_required());

    // 3. Subsequent contiguous delta 101 MUST BE REJECTED while latch is held
    let delta101_env = load_envelope_fixture(FIXTURE_VALID_DELTA_101);
    let latched_err = mapper
        .map_envelope(delta101_env, 1_700_000_000_500)
        .expect_err("deltas must be rejected while resync is latched");
    assert_eq!(
        latched_err,
        MarketTypeError::ResyncRequired {
            reason: "stream resync latched: valid snapshot required",
        }
    );
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));
    assert!(mapper.is_resync_required());

    // 4. Stale snapshot (sequence 95) rejected while latch is held
    let stale_env = load_envelope_fixture(FIXTURE_STALE_SNAPSHOT);
    let stale_err = mapper
        .map_envelope(stale_env, 1_700_000_000_500)
        .expect_err("stale snapshot must be rejected during latch");
    assert_eq!(
        stale_err,
        MarketTypeError::StaleSequence {
            sequence: 95,
            current: 100,
        }
    );
    assert!(mapper.is_resync_required());
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

    // 5. Duplicate snapshot (sequence 100) rejected while latch is held
    let dup_env = load_envelope_fixture(FIXTURE_DUPLICATE_SNAPSHOT);
    let dup_err = mapper
        .map_envelope(dup_env, 1_700_000_000_500)
        .expect_err("duplicate snapshot must be rejected during latch");
    assert_eq!(dup_err, MarketTypeError::DuplicateSequence(100));
    assert!(mapper.is_resync_required());
    assert_eq!(mapper.current_sequence(), Some(Sequence(100)));

    // 6. Valid newer snapshot (sequence 110) clears latch and establishes new baseline
    let recovery_env = load_envelope_fixture(FIXTURE_RECOVERY_SNAPSHOT);
    let recovery_res = mapper
        .map_envelope(recovery_env, 1_700_000_001_500)
        .expect("valid newer recovery snapshot must clear resync latch");

    assert!(!mapper.is_resync_required(), "resync latch must be cleared");
    assert_eq!(mapper.current_sequence(), Some(Sequence(110)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_001_000));
    match recovery_res.payload {
        CanonicalFeedPayload::OrderBookSnapshot(s) => {
            assert_eq!(s.sequence, Sequence(110));
            assert_eq!(s.bids[0].price.get(), 151.0);
            assert_eq!(s.asks[0].price.get(), 152.0);
        }
        _ => panic!("expected OrderBookSnapshot"),
    }
    let book = mapper.order_book().unwrap();
    assert_eq!(book.sequence(), Sequence(110));
    assert_eq!(book.best_bid().unwrap().price.get(), 151.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 152.0);
    assert!(!book.is_resync_required());

    // 7. Strictly contiguous delta 111 now succeeds cleanly post-recovery
    let post_recovery_env = load_envelope_fixture(FIXTURE_POST_RECOVERY_DELTA);
    let post_res = mapper
        .map_envelope(post_recovery_env, 1_700_000_001_500)
        .expect("contiguous delta post-recovery must succeed");

    assert_eq!(mapper.current_sequence(), Some(Sequence(111)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_001_100));
    assert!(!mapper.is_resync_required());
    match post_res.payload {
        CanonicalFeedPayload::OrderBookDelta(d) => {
            assert_eq!(
                d.sequence_range,
                SequenceRange::point(Sequence(111)).unwrap()
            );
        }
        _ => panic!("expected OrderBookDelta"),
    }
    assert_eq!(
        mapper.order_book().unwrap().best_bid().unwrap().price.get(),
        151.5
    );
}

#[test]
fn test_regression_overlap_delta_latches_resync_until_recovery_snapshot() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // 1. Establish valid baseline snapshot (sequence 100)
    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper.map_envelope(snap_env, 1_700_000_000_500).unwrap();

    // 2. Advance to sequence 101 via contiguous delta
    let delta101_env = load_envelope_fixture(FIXTURE_VALID_DELTA_101);
    mapper
        .map_envelope(delta101_env, 1_700_000_000_500)
        .unwrap();
    assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
    assert!(!mapper.is_resync_required());
    let book_at_101 = mapper.order_book().cloned().unwrap();

    // 3. Feed overlapping delta [100, 105] when current sequence is 101
    let overlap_env = load_envelope_fixture(FIXTURE_OVERLAP_DELTA);
    let overlap_err = mapper
        .map_envelope(overlap_env, 1_700_000_000_500)
        .expect_err("overlapping delta must fail closed");
    assert_eq!(
        overlap_err,
        MarketTypeError::SequenceOverlap {
            start: 100,
            end: 105,
            current: 101,
        }
    );

    // Assert sequence remains 101, timestamp unadvanced, and resync is latched
    assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
    assert_eq!(mapper.last_timestamp_ms(), Some(1_700_000_000_100));
    assert!(
        mapper.is_resync_required(),
        "resync must be latched upon sequence overlap"
    );

    // Assert order book contents are unmutated (bids/asks/seq/ts unchanged, but resync latched)
    let book = mapper.order_book().unwrap();
    assert_eq!(book.bids(), book_at_101.bids());
    assert_eq!(book.asks(), book_at_101.asks());
    assert_eq!(book.sequence(), book_at_101.sequence());
    assert_eq!(book.timestamp_ms(), book_at_101.timestamp_ms());
    assert!(book.is_resync_required());

    // 4. Subsequent delta 102 rejected while latch is held
    let delta102_env = load_envelope_fixture(FIXTURE_VALID_DELTA_102);
    let latched_err = mapper
        .map_envelope(delta102_env, 1_700_000_000_500)
        .expect_err("delta must be rejected while resync is latched");
    assert_eq!(
        latched_err,
        MarketTypeError::ResyncRequired {
            reason: "stream resync latched: valid snapshot required",
        }
    );
    assert_eq!(mapper.current_sequence(), Some(Sequence(101)));
    assert!(mapper.is_resync_required());

    // 5. Valid newer snapshot (sequence 110) clears latch
    let recovery_env = load_envelope_fixture(FIXTURE_RECOVERY_SNAPSHOT);
    mapper
        .map_envelope(recovery_env, 1_700_000_001_500)
        .expect("recovery snapshot should clear latch");
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.current_sequence(), Some(Sequence(110)));

    // 6. Contiguous delta 111 succeeds cleanly
    let post_env = load_envelope_fixture(FIXTURE_POST_RECOVERY_DELTA);
    mapper
        .map_envelope(post_env, 1_700_000_001_500)
        .expect("post recovery delta should succeed");
    assert_eq!(mapper.current_sequence(), Some(Sequence(111)));
}

// ---------------------------------------------------------------------------
// 5. Injected Evaluation Time Constraint & Freshness Verifications
// ---------------------------------------------------------------------------

#[test]
fn test_fixture_normalization_deterministic_freshness_zero_and_future_skew() {
    let target = synthetic_sol_usdc_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target.clone()).unwrap();

    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    let observed_at_ms = snap_env.context.observed_at_ms; // 1_700_000_000_000

    // 1. Evaluation time equal to observation time -> zero age, status Fresh
    let snap_zero = mapper
        .map_envelope(snap_env.clone(), observed_at_ms)
        .expect("zero-age evaluation should succeed");
    assert_eq!(snap_zero.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(snap_zero.freshness.age_ms, 0);

    // 2. Evaluation timestamp <= 0 fails closed immediately
    let mut mapper2 = CanonicalMarketFeedMapper::new(target.clone()).unwrap();
    assert_eq!(
        mapper2.map_envelope(snap_env.clone(), 0),
        Err(MarketTypeError::InvalidTimestamp(0))
    );
    assert_eq!(
        mapper2.map_envelope(snap_env.clone(), -100),
        Err(MarketTypeError::InvalidTimestamp(-100))
    );
    assert_eq!(mapper2.current_sequence(), None);

    // 3. Evaluation timestamp far behind observation timestamp (future skew > 2000ms max skew)
    // Observed at 1_700_000_000_000, evaluated at 1_699_999_995_000 (5000ms skew)
    let mut skew_mapper = CanonicalMarketFeedMapper::new(target).unwrap();
    let skew_env = skew_mapper
        .map_envelope(snap_env, 1_699_999_995_000)
        .expect("future-skewed input is returned with ResyncRequired freshness status");
    assert_eq!(skew_env.freshness.status, FreshnessStatus::ResyncRequired);
    assert!(
        skew_mapper.is_resync_required(),
        "future skew beyond policy tolerance latches resync"
    );
    assert_eq!(
        skew_mapper.current_sequence(),
        None,
        "baseline must not be established under excessive future skew"
    );
}
