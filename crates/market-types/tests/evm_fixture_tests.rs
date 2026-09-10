//! Deterministic EVM snapshot and delta fixture normalization tests.
//!
//! Validates fixture-driven normalization of deterministic EVM order-book snapshots
//! and deltas through the CanonicalMarketFeedMapper boundary. Exercises serialized raw feed
//! envelopes using synthetic, non-sensitive fixtures without any network/RPC/provider client,
//! live feed, or runtime ingestion dependency.

use chain_types::{AssetId, ChainId};
use market_types::{
    CanonicalFeedPayload, CanonicalMarketFeedMapper, ChainFamily, FeedFinality,
    FeedObservationContext, FeedSourceLabel, FeedTarget, FreshnessStatus, InjectedFeedSource,
    InstrumentId, MarketTypeError, RawDepthDelta, RawDepthLevel, RawFeedEnvelope, RawFeedPayload,
    Sequence, SequenceRange,
};

// Fixture JSON definitions loaded deterministically at compile-time
const FIXTURE_VALID_SNAPSHOT: &str = include_str!("fixtures/evm/valid_snapshot.json");
const FIXTURE_VALID_DELTA_101: &str = include_str!("fixtures/evm/valid_delta_101.json");
const FIXTURE_VALID_DELTA_102: &str = include_str!("fixtures/evm/valid_delta_102.json");
const FIXTURE_GAP_DELTA: &str = include_str!("fixtures/evm/gap_delta.json");
const FIXTURE_OVERLAP_DELTA: &str = include_str!("fixtures/evm/overlap_delta.json");
const FIXTURE_TARGET_MISMATCH: &str = include_str!("fixtures/evm/snapshot_target_mismatch.json");
const FIXTURE_CHAIN_MISMATCH: &str = include_str!("fixtures/evm/snapshot_chain_mismatch.json");
const FIXTURE_NEGATIVE_PRICE: &str = include_str!("fixtures/evm/snapshot_negative_price.json");
const FIXTURE_NEGATIVE_QUANTITY: &str = include_str!("fixtures/evm/delta_negative_quantity.json");
const FIXTURE_STALE_SNAPSHOT: &str = include_str!("fixtures/evm/snapshot_stale.json");
const FIXTURE_DUPLICATE_SNAPSHOT: &str = include_str!("fixtures/evm/snapshot_duplicate.json");
const FIXTURE_RECOVERY_SNAPSHOT: &str = include_str!("fixtures/evm/snapshot_recovery.json");
const FIXTURE_POST_RECOVERY_DELTA: &str = include_str!("fixtures/evm/delta_post_recovery.json");
const FIXTURE_MALFORMED_ENVELOPE: &str = include_str!("fixtures/evm/malformed_envelope.json");

/// Helper to deserialize a raw feed envelope from a fixture JSON string.
fn load_envelope_fixture(json_str: &str) -> RawFeedEnvelope {
    serde_json::from_str(json_str).expect("failed to deserialize raw feed envelope fixture")
}

/// Helper to construct canonical synthetic Ethereum instrument target (WETH/USDC).
fn synthetic_evm_target() -> FeedTarget {
    let base = AssetId::new(
        ChainId::Ethereum,
        "0x1111111111111111111111111111111111111111",
    )
    .expect("valid synthetic Ethereum base asset");
    let quote = AssetId::new(
        ChainId::Ethereum,
        "0x2222222222222222222222222222222222222222",
    )
    .expect("valid synthetic Ethereum quote asset");
    FeedTarget::Instrument(InstrumentId::new(base, quote).expect("valid synthetic instrument pair"))
}

/// Helper to construct canonical synthetic Base instrument target (WETH/USDC).
fn synthetic_base_target() -> FeedTarget {
    let base = AssetId::new(ChainId::Base, "0x1111111111111111111111111111111111111111")
        .expect("valid synthetic Base base asset");
    let quote = AssetId::new(ChainId::Base, "0x2222222222222222222222222222222222222222")
        .expect("valid synthetic Base quote asset");
    FeedTarget::Instrument(InstrumentId::new(base, quote).expect("valid synthetic instrument pair"))
}

// ---------------------------------------------------------------------------
// 1. Valid EVM Snapshot & Contiguous Delta Normalization
// ---------------------------------------------------------------------------

#[test]
fn test_evm_fixtures_normalize_snapshot_and_contiguous_deltas() {
    let target = synthetic_evm_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target.clone())
        .expect("mapper initialization should succeed");

    // Explicit caller-injected evaluation timestamp (deterministic, no wall clock)
    let evaluated_at_ms = 1_700_000_000_500i64;

    // --- 1. Normalize valid snapshot fixture (sequence 100) ---
    let snap_env = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    assert_eq!(snap_env.target, target);
    assert_eq!(snap_env.context.source_family, ChainFamily::Evm);
    assert_eq!(
        snap_env.context.source_label.as_str(),
        "evm-synthetic-primary"
    );
    assert_eq!(snap_env.context.finality, FeedFinality::Finalized);
    assert!(snap_env.context.finality.is_finalized());
    assert!(snap_env.context.finality.is_confirmed_or_better());
    assert_eq!(snap_env.context.slot_or_block, Some(19_500_100));
    assert_eq!(snap_env.context.observed_at_ms, 1_700_000_000_000);

    let canonical_snap = mapper
        .map_envelope(snap_env.clone(), evaluated_at_ms)
        .expect("valid EVM snapshot fixture should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_snap.context, snap_env.context);
    assert_eq!(canonical_snap.context.source_family, ChainFamily::Evm);
    assert_eq!(
        canonical_snap.context.source_label.as_str(),
        "evm-synthetic-primary"
    );
    assert_eq!(canonical_snap.context.finality, FeedFinality::Finalized);
    assert_eq!(canonical_snap.context.slot_or_block, Some(19_500_100));
    assert_eq!(canonical_snap.context.observed_at_ms, 1_700_000_000_000);

    // Assert deterministic freshness (age = 500 - 0 = 500ms)
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
            assert_eq!(snapshot.bids[0].price.get(), 2500.0);
            assert_eq!(snapshot.bids[0].quantity.get(), 10.0);
            assert_eq!(snapshot.bids[1].price.get(), 2490.0);
            assert_eq!(snapshot.bids[1].quantity.get(), 20.0);
            assert_eq!(snapshot.bids[2].price.get(), 2480.0);
            assert_eq!(snapshot.bids[2].quantity.get(), 30.0);
            assert_eq!(snapshot.asks.len(), 3);
            assert_eq!(snapshot.asks[0].price.get(), 2510.0);
            assert_eq!(snapshot.asks[0].quantity.get(), 15.0);
            assert_eq!(snapshot.asks[1].price.get(), 2520.0);
            assert_eq!(snapshot.asks[1].quantity.get(), 25.0);
            assert_eq!(snapshot.asks[2].price.get(), 2530.0);
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
    assert_eq!(book.best_bid().unwrap().price.get(), 2500.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 2510.0);
    assert_eq!(book.spread(), Some(10.0));
    assert_eq!(book.mid_price().unwrap().get(), 2505.0);

    // --- 2. Normalize first contiguous delta fixture (sequence 101) ---
    let delta1_env = load_envelope_fixture(FIXTURE_VALID_DELTA_101);
    let canonical_delta1 = mapper
        .map_envelope(delta1_env.clone(), evaluated_at_ms)
        .expect("valid contiguous delta 101 should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_delta1.context, delta1_env.context);
    assert_eq!(canonical_delta1.context.source_family, ChainFamily::Evm);
    assert_eq!(canonical_delta1.context.slot_or_block, Some(19_500_101));
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
            assert_eq!(delta.bids[0].price.get(), 2505.0);
            assert_eq!(delta.bids[0].quantity.get(), 5.0);
            assert_eq!(delta.asks.len(), 1);
            assert_eq!(delta.asks[0].price.get(), 2510.0);
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
    // New top bid is 2505.0; top ask 2510.0 was removed (quantity 0), so remaining best ask is 2520.0
    assert_eq!(book.best_bid().unwrap().price.get(), 2505.0);
    assert_eq!(book.best_bid().unwrap().quantity.get(), 5.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 2520.0);
    assert_eq!(book.best_ask().unwrap().quantity.get(), 25.0);
    assert_eq!(book.spread(), Some(15.0));

    // --- 3. Normalize second contiguous delta fixture (sequence 102) ---
    let delta2_env = load_envelope_fixture(FIXTURE_VALID_DELTA_102);
    let canonical_delta2 = mapper
        .map_envelope(delta2_env.clone(), evaluated_at_ms)
        .expect("valid contiguous delta 102 should normalize cleanly");

    // Assert preserved context and metadata
    assert_eq!(canonical_delta2.context, delta2_env.context);
    assert_eq!(canonical_delta2.context.slot_or_block, Some(19_500_102));
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
            assert_eq!(delta.bids[0].price.get(), 2500.0);
            assert_eq!(delta.bids[0].quantity.get(), 12.0);
            assert_eq!(delta.asks.len(), 1);
            assert_eq!(delta.asks[0].price.get(), 2515.0);
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
    assert_eq!(book.best_bid().unwrap().price.get(), 2505.0);
    // Ask 2515.0 was inserted, tighter than 2520.0
    assert_eq!(book.best_ask().unwrap().price.get(), 2515.0);
    assert_eq!(book.best_ask().unwrap().quantity.get(), 8.0);
    assert_eq!(book.spread(), Some(10.0));
}

#[test]
fn test_evm_fixtures_batch_ingestion_via_source() {
    let target = synthetic_evm_target();
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
// 2. Fail-Closed Fixture Regressions: Malformed, Negative, Non-Finite
// ---------------------------------------------------------------------------

#[test]
fn test_regression_malformed_fixture_json_fails_closed() {
    let res = serde_json::from_str::<RawFeedEnvelope>(FIXTURE_MALFORMED_ENVELOPE);
    assert!(
        res.is_err(),
        "malformed EVM envelope fixture must fail deserialization"
    );
}

#[test]
fn test_regression_negative_price_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
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
    assert!(mapper.last_pool_state().is_none());
}

#[test]
fn test_regression_negative_quantity_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
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
    assert!(mapper.last_pool_state().is_none());
}

#[test]
fn test_regression_non_finite_fixture_data_rejected_state_unchanged() {
    let target = synthetic_evm_target();
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
            ChainFamily::Evm,
            FeedSourceLabel::new("evm-synthetic-primary").unwrap(),
            FeedFinality::Finalized,
            Some(19_500_101),
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

    let err_nan_p = mapper
        .map_envelope(nan_price_env, 1_700_000_000_500)
        .expect_err("NaN price must be rejected");
    assert_eq!(err_nan_p, MarketTypeError::NonFinitePrice);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());

    // 2. Non-finite price in delta (Infinity)
    let inf_price_env = RawFeedEnvelope::new(
        FeedObservationContext::new(
            ChainFamily::Evm,
            FeedSourceLabel::new("evm-synthetic-primary").unwrap(),
            FeedFinality::Finalized,
            Some(19_500_101),
            1_700_000_000_100,
        )
        .unwrap(),
        target.clone(),
        RawFeedPayload::OrderBookDelta(RawDepthDelta {
            start_sequence: 101,
            end_sequence: 101,
            bids: vec![RawDepthLevel::new(f64::INFINITY, 10.0)],
            asks: vec![],
        }),
    )
    .unwrap();

    let err_inf_p = mapper
        .map_envelope(inf_price_env, 1_700_000_000_500)
        .expect_err("Infinity price must be rejected");
    assert_eq!(err_inf_p, MarketTypeError::NonFinitePrice);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());

    // 3. Non-finite quantity in delta (NaN)
    let nan_qty_env = RawFeedEnvelope::new(
        FeedObservationContext::new(
            ChainFamily::Evm,
            FeedSourceLabel::new("evm-synthetic-primary").unwrap(),
            FeedFinality::Finalized,
            Some(19_500_101),
            1_700_000_000_100,
        )
        .unwrap(),
        target.clone(),
        RawFeedPayload::OrderBookDelta(RawDepthDelta {
            start_sequence: 101,
            end_sequence: 101,
            bids: vec![RawDepthLevel::new(2500.0, f64::NAN)],
            asks: vec![],
        }),
    )
    .unwrap();

    let err_nan_q = mapper
        .map_envelope(nan_qty_env, 1_700_000_000_500)
        .expect_err("NaN quantity must be rejected");
    assert_eq!(err_nan_q, MarketTypeError::NonFiniteQuantity);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());

    // 4. Non-finite quantity in delta (Infinity)
    let inf_qty_env = RawFeedEnvelope::new(
        FeedObservationContext::new(
            ChainFamily::Evm,
            FeedSourceLabel::new("evm-synthetic-primary").unwrap(),
            FeedFinality::Finalized,
            Some(19_500_101),
            1_700_000_000_100,
        )
        .unwrap(),
        target,
        RawFeedPayload::OrderBookDelta(RawDepthDelta {
            start_sequence: 101,
            end_sequence: 101,
            bids: vec![RawDepthLevel::new(2500.0, f64::INFINITY)],
            asks: vec![],
        }),
    )
    .unwrap();

    let err_inf_q = mapper
        .map_envelope(inf_qty_env, 1_700_000_000_500)
        .expect_err("Infinity quantity must be rejected");
    assert_eq!(err_inf_q, MarketTypeError::NonFiniteQuantity);
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());
}

// ---------------------------------------------------------------------------
// 3. Fail-Closed Fixture Regressions: Target & Chain-Family Mismatch
// ---------------------------------------------------------------------------

#[test]
fn test_regression_target_mismatch_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Baseline
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map envelope with pool target instead of Ethereum instrument
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
    assert!(mapper.last_pool_state().is_none());
}

#[test]
fn test_regression_chain_family_mismatch_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Baseline
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map envelope where source_family is "solana" for an Ethereum target
    let mismatch_env = load_envelope_fixture(FIXTURE_CHAIN_MISMATCH);
    let err = mapper
        .map_envelope(mismatch_env, 1_700_000_000_500)
        .expect_err("chain family mismatch fixture must be rejected");
    assert_eq!(
        err,
        MarketTypeError::SourceChainFamilyMismatch {
            source_family: "solana",
            target_chain: "ethereum",
        }
    );

    // Mapper state completely untouched
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());
}

#[test]
fn test_regression_stale_snapshot_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Establish baseline snapshot at sequence 100
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map stale snapshot at sequence 95 (< 100)
    let stale_env = load_envelope_fixture(FIXTURE_STALE_SNAPSHOT);
    let err = mapper
        .map_envelope(stale_env, 1_700_000_000_500)
        .expect_err("stale snapshot fixture must be rejected");
    assert_eq!(
        err,
        MarketTypeError::StaleSequence {
            sequence: 95,
            current: 100,
        }
    );

    // Assert sequence, timestamp, resync latch, order book, and pool state are unmutated
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());
}

#[test]
fn test_regression_duplicate_snapshot_fixture_rejected_state_unchanged() {
    let target = synthetic_evm_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target).unwrap();

    // Establish baseline snapshot at sequence 100
    let baseline_snap = load_envelope_fixture(FIXTURE_VALID_SNAPSHOT);
    mapper
        .map_envelope(baseline_snap, 1_700_000_000_500)
        .unwrap();
    let initial_seq = mapper.current_sequence();
    let initial_ts = mapper.last_timestamp_ms();
    let initial_book = mapper.order_book().cloned().unwrap();

    // Map duplicate snapshot at sequence 100 (== 100)
    let dup_env = load_envelope_fixture(FIXTURE_DUPLICATE_SNAPSHOT);
    let err = mapper
        .map_envelope(dup_env, 1_700_000_000_500)
        .expect_err("duplicate snapshot fixture must be rejected");
    assert_eq!(err, MarketTypeError::DuplicateSequence(100));

    // Assert sequence, timestamp, resync latch, order book, and pool state are unmutated
    assert_eq!(mapper.current_sequence(), initial_seq);
    assert_eq!(mapper.last_timestamp_ms(), initial_ts);
    assert!(!mapper.is_resync_required());
    assert_eq!(mapper.order_book().unwrap(), &initial_book);
    assert!(mapper.last_pool_state().is_none());
}

// ---------------------------------------------------------------------------
// 4. Fail-Closed Fixture Regressions: Gap, Overlap, Resync Latch & Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_regression_gap_delta_latches_resync_until_recovery_snapshot() {
    let target = synthetic_evm_target();
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
            assert_eq!(s.bids[0].price.get(), 2508.0);
            assert_eq!(s.asks[0].price.get(), 2518.0);
        }
        _ => panic!("expected OrderBookSnapshot"),
    }
    let book = mapper.order_book().unwrap();
    assert_eq!(book.sequence(), Sequence(110));
    assert_eq!(book.best_bid().unwrap().price.get(), 2508.0);
    assert_eq!(book.best_ask().unwrap().price.get(), 2518.0);
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
        2512.0
    );
}

#[test]
fn test_regression_overlap_delta_latches_resync_until_recovery_snapshot() {
    let target = synthetic_evm_target();
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
fn test_evm_fixture_deterministic_freshness_zero_and_future_skew() {
    let target = synthetic_evm_target();
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

// ---------------------------------------------------------------------------
// 6. EVM Family Multi-Chain Coverage (Base ChainId)
// ---------------------------------------------------------------------------

#[test]
fn test_evm_base_chain_normalization() {
    let target = synthetic_base_target();
    let mut mapper = CanonicalMarketFeedMapper::new(target.clone())
        .expect("mapper initialization for Base target should succeed");

    let context = FeedObservationContext::new(
        ChainFamily::Evm,
        FeedSourceLabel::new("evm-base-primary").unwrap(),
        FeedFinality::Confirmed,
        Some(12_000_000),
        1_700_000_000_000,
    )
    .unwrap();

    let snap_env = RawFeedEnvelope::new(
        context,
        target.clone(),
        RawFeedPayload::OrderBookSnapshot(market_types::RawDepthSnapshot {
            sequence: 50,
            bids: vec![RawDepthLevel::new(3000.0, 5.0)],
            asks: vec![RawDepthLevel::new(3005.0, 5.0)],
        }),
    )
    .unwrap();

    let canonical = mapper
        .map_envelope(snap_env, 1_700_000_000_250)
        .expect("Base chain EVM envelope should normalize cleanly");

    assert_eq!(canonical.context.source_family, ChainFamily::Evm);
    assert_eq!(canonical.context.finality, FeedFinality::Confirmed);
    assert_eq!(canonical.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(canonical.freshness.age_ms, 250);
    assert_eq!(mapper.current_sequence(), Some(Sequence(50)));
}
