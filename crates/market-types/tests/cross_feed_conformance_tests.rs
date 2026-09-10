//! Cross-feed conformance tests for paired Solana and EVM serialized raw feed envelopes.
//!
//! Proves that semantically equivalent feeds from distinct blockchain sources (Solana, EVM)
//! normalize under identical caller-injected evaluation timestamps to:
//! 1. Identical canonical depth payload (order book bids, asks, sequence, timestamp).
//! 2. Identical canonical maintained orderbook depth state (bids, asks, best bid/ask, spread).
//! 3. Identical sequence and timestamp transition semantics.
//! 4. Identical deterministic freshness semantics (age, status, sequence).
//!
//! While preserving intentionally distinct explicit source metadata:
//! - Source family (Solana vs EVM)
//! - Source label
//! - Source finality (e.g. Confirmed vs Finalized)
//! - Slot / block number (Solana slot vs EVM block)
//! - Feed target identity (Solana base/quote vs EVM base/quote)
//!
//! Also proves fail-closed paired regressions:
//! - Sequence gap and overlap handling with sticky resync latching and state preservation.
//! - Malformed envelope and invalid numeric value rejection with state preservation.
//! - Rejection of cross-feed identity coercion attempts (cross-target injection, forged chain family)
//!   with zero state advancement or mutation.

use chain_types::{AssetId, ChainId};
use market_types::{
    CanonicalFeedPayload, CanonicalMarketFeedMapper, ChainFamily, FeedFinality, FeedTarget,
    FreshnessStatus, InjectedFeedSource, InstrumentId, MarketTypeError, RawFeedEnvelope, Sequence,
    SequenceRange,
};

// Paired Solana fixtures
const FIXTURE_SOLANA_SNAPSHOT: &str =
    include_str!("fixtures/conformance/solana/valid_snapshot.json");
const FIXTURE_SOLANA_DELTA_101: &str =
    include_str!("fixtures/conformance/solana/valid_delta_101.json");
const FIXTURE_SOLANA_DELTA_102: &str =
    include_str!("fixtures/conformance/solana/valid_delta_102.json");
const FIXTURE_SOLANA_GAP_DELTA: &str = include_str!("fixtures/conformance/solana/gap_delta.json");
const FIXTURE_SOLANA_OVERLAP_DELTA: &str =
    include_str!("fixtures/conformance/solana/overlap_delta.json");
const FIXTURE_SOLANA_RECOVERY_SNAPSHOT: &str =
    include_str!("fixtures/conformance/solana/snapshot_recovery.json");
const FIXTURE_SOLANA_MALFORMED: &str =
    include_str!("fixtures/conformance/solana/malformed_envelope.json");
const FIXTURE_SOLANA_NEGATIVE_PRICE: &str =
    include_str!("fixtures/conformance/solana/snapshot_negative_price.json");
const FIXTURE_SOLANA_NEGATIVE_QTY: &str =
    include_str!("fixtures/conformance/solana/delta_negative_quantity.json");

// Paired EVM fixtures
const FIXTURE_EVM_SNAPSHOT: &str = include_str!("fixtures/conformance/evm/valid_snapshot.json");
const FIXTURE_EVM_DELTA_101: &str = include_str!("fixtures/conformance/evm/valid_delta_101.json");
const FIXTURE_EVM_DELTA_102: &str = include_str!("fixtures/conformance/evm/valid_delta_102.json");
const FIXTURE_EVM_GAP_DELTA: &str = include_str!("fixtures/conformance/evm/gap_delta.json");
const FIXTURE_EVM_OVERLAP_DELTA: &str = include_str!("fixtures/conformance/evm/overlap_delta.json");
const FIXTURE_EVM_RECOVERY_SNAPSHOT: &str =
    include_str!("fixtures/conformance/evm/snapshot_recovery.json");
const FIXTURE_EVM_MALFORMED: &str =
    include_str!("fixtures/conformance/evm/malformed_envelope.json");
const FIXTURE_EVM_NEGATIVE_PRICE: &str =
    include_str!("fixtures/conformance/evm/snapshot_negative_price.json");
const FIXTURE_EVM_NEGATIVE_QTY: &str =
    include_str!("fixtures/conformance/evm/delta_negative_quantity.json");

fn load_envelope(json_str: &str) -> RawFeedEnvelope {
    serde_json::from_str(json_str).expect("failed to deserialize raw feed envelope fixture")
}

fn solana_conformance_target() -> FeedTarget {
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

fn evm_conformance_target() -> FeedTarget {
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

// ---------------------------------------------------------------------------
// 1. Semantic Equivalence & Normalization Conformance
// ---------------------------------------------------------------------------

#[test]
fn test_paired_conformance_snapshot_and_deltas_normalize_identically() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol.clone())
        .expect("mapper initialization for Solana target should succeed");
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm.clone())
        .expect("mapper initialization for EVM target should succeed");

    // Both mappers start uninitialized
    assert_eq!(mapper_sol.current_sequence(), None);
    assert_eq!(mapper_evm.current_sequence(), None);
    assert_eq!(mapper_sol.last_timestamp_ms(), None);
    assert_eq!(mapper_evm.last_timestamp_ms(), None);
    assert!(!mapper_sol.is_resync_required());
    assert!(!mapper_evm.is_resync_required());

    // Caller-injected deterministic evaluation timestamp
    let eval_snap_ms = 1_700_000_000_500i64;

    // --- Phase 1: Paired Snapshot Normalization ---
    let raw_snap_sol = load_envelope(FIXTURE_SOLANA_SNAPSHOT);
    let raw_snap_evm = load_envelope(FIXTURE_EVM_SNAPSHOT);

    let canon_snap_sol = mapper_sol
        .map_envelope(raw_snap_sol.clone(), eval_snap_ms)
        .expect("Solana snapshot should normalize cleanly");
    let canon_snap_evm = mapper_evm
        .map_envelope(raw_snap_evm.clone(), eval_snap_ms)
        .expect("EVM snapshot should normalize cleanly");

    // 1a. Depth Payload Conformance:
    // Extract DepthSnapshot from both canonical payloads and verify identical contents
    let (sol_depth_snap, evm_depth_snap) = match (&canon_snap_sol.payload, &canon_snap_evm.payload)
    {
        (
            CanonicalFeedPayload::OrderBookSnapshot(sol_snap),
            CanonicalFeedPayload::OrderBookSnapshot(evm_snap),
        ) => (sol_snap, evm_snap),
        _ => panic!("both payloads must be OrderBookSnapshot"),
    };

    assert_eq!(
        sol_depth_snap.bids, evm_depth_snap.bids,
        "canonical snapshot bids must be semantically identical"
    );
    assert_eq!(
        sol_depth_snap.asks, evm_depth_snap.asks,
        "canonical snapshot asks must be semantically identical"
    );
    assert_eq!(
        sol_depth_snap.sequence, evm_depth_snap.sequence,
        "canonical snapshot sequence must be identical"
    );
    assert_eq!(sol_depth_snap.sequence, Sequence(100));
    assert_eq!(
        sol_depth_snap.timestamp_ms, evm_depth_snap.timestamp_ms,
        "canonical snapshot timestamp_ms must be identical"
    );
    assert_eq!(sol_depth_snap.timestamp_ms, 1_700_000_000_000);

    // 1b. Maintained OrderBook Depth State Conformance:
    let book_sol = mapper_sol
        .order_book()
        .expect("Solana book must be initialized");
    let book_evm = mapper_evm
        .order_book()
        .expect("EVM book must be initialized");

    assert_eq!(
        book_sol.bids(),
        book_evm.bids(),
        "orderbook bids must be identical across feeds"
    );
    assert_eq!(
        book_sol.asks(),
        book_evm.asks(),
        "orderbook asks must be identical across feeds"
    );
    assert_eq!(
        book_sol.best_bid(),
        book_evm.best_bid(),
        "best bid must match exactly"
    );
    assert_eq!(
        book_sol.best_ask(),
        book_evm.best_ask(),
        "best ask must match exactly"
    );
    assert_eq!(
        book_sol.spread(),
        book_evm.spread(),
        "spread must match exactly"
    );
    assert_eq!(book_sol.spread(), Some(1.0));
    assert_eq!(book_sol.sequence(), book_evm.sequence());
    assert_eq!(book_sol.sequence(), Sequence(100));
    assert_eq!(book_sol.timestamp_ms(), book_evm.timestamp_ms());
    assert_eq!(book_sol.timestamp_ms(), 1_700_000_000_000);

    // 1c. Sequence and Timestamp Transition Conformance:
    assert_eq!(mapper_sol.current_sequence(), mapper_evm.current_sequence());
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(100)));
    assert_eq!(
        mapper_sol.last_timestamp_ms(),
        mapper_evm.last_timestamp_ms()
    );
    assert_eq!(mapper_sol.last_timestamp_ms(), Some(1_700_000_000_000));

    // 1d. Freshness Semantics Conformance:
    assert_eq!(
        canon_snap_sol.freshness.status, canon_snap_evm.freshness.status,
        "freshness status must match"
    );
    assert_eq!(canon_snap_sol.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(
        canon_snap_sol.freshness.age_ms, canon_snap_evm.freshness.age_ms,
        "freshness age_ms must match"
    );
    assert_eq!(canon_snap_sol.freshness.age_ms, 500);
    assert_eq!(
        canon_snap_sol.freshness.observed_at_ms,
        canon_snap_evm.freshness.observed_at_ms
    );
    assert_eq!(
        canon_snap_sol.freshness.evaluated_at_ms,
        canon_snap_evm.freshness.evaluated_at_ms
    );
    assert_eq!(canon_snap_sol.freshness.evaluated_at_ms, eval_snap_ms);
    assert_eq!(
        canon_snap_sol.freshness.sequence,
        canon_snap_evm.freshness.sequence
    );
    assert_eq!(canon_snap_sol.freshness.sequence, Sequence(100));

    // 1e. Intentionally Distinct Source Chain / Finality / Block Metadata Preserved:
    // Solana context assertions:
    assert_eq!(canon_snap_sol.context.source_family, ChainFamily::Solana);
    assert_eq!(
        canon_snap_sol.context.source_label.as_str(),
        "solana-conformance-feed"
    );
    assert_eq!(canon_snap_sol.context.finality, FeedFinality::Confirmed);
    assert_eq!(canon_snap_sol.context.slot_or_block, Some(250_000_100));
    assert_eq!(sol_depth_snap.target, target_sol);

    // EVM context assertions:
    assert_eq!(canon_snap_evm.context.source_family, ChainFamily::Evm);
    assert_eq!(
        canon_snap_evm.context.source_label.as_str(),
        "evm-conformance-feed"
    );
    assert_eq!(canon_snap_evm.context.finality, FeedFinality::Finalized);
    assert_eq!(canon_snap_evm.context.slot_or_block, Some(19_500_100));
    assert_eq!(evm_depth_snap.target, target_evm);

    // Explicit cross-feed distinction proofs (no metadata blending):
    assert_ne!(
        canon_snap_sol.context.source_family,
        canon_snap_evm.context.source_family
    );
    assert_ne!(
        canon_snap_sol.context.source_label,
        canon_snap_evm.context.source_label
    );
    assert_ne!(
        canon_snap_sol.context.finality,
        canon_snap_evm.context.finality
    );
    assert_ne!(
        canon_snap_sol.context.slot_or_block,
        canon_snap_evm.context.slot_or_block
    );
    assert_ne!(sol_depth_snap.target, evm_depth_snap.target);

    // --- Phase 2: Paired Contiguous Delta 101 Normalization ---
    let eval_delta_101_ms = 1_700_000_000_600i64;
    let raw_d101_sol = load_envelope(FIXTURE_SOLANA_DELTA_101);
    let raw_d101_evm = load_envelope(FIXTURE_EVM_DELTA_101);

    let canon_d101_sol = mapper_sol
        .map_envelope(raw_d101_sol, eval_delta_101_ms)
        .expect("Solana delta 101 should normalize cleanly");
    let canon_d101_evm = mapper_evm
        .map_envelope(raw_d101_evm, eval_delta_101_ms)
        .expect("EVM delta 101 should normalize cleanly");

    let (sol_depth_d101, evm_depth_d101) = match (&canon_d101_sol.payload, &canon_d101_evm.payload)
    {
        (
            CanonicalFeedPayload::OrderBookDelta(sol_d),
            CanonicalFeedPayload::OrderBookDelta(evm_d),
        ) => (sol_d, evm_d),
        _ => panic!("both payloads must be OrderBookDelta"),
    };

    assert_eq!(
        sol_depth_d101.bids, evm_depth_d101.bids,
        "delta 101 bids must be semantically identical"
    );
    assert_eq!(
        sol_depth_d101.asks, evm_depth_d101.asks,
        "delta 101 asks must be semantically identical"
    );
    assert_eq!(
        sol_depth_d101.sequence_range, evm_depth_d101.sequence_range,
        "delta 101 sequence_range must be identical"
    );
    assert_eq!(
        sol_depth_d101.sequence_range,
        SequenceRange::point(Sequence(101)).unwrap()
    );
    assert_eq!(
        sol_depth_d101.timestamp_ms, evm_depth_d101.timestamp_ms,
        "delta 101 timestamp_ms must be identical"
    );
    assert_eq!(sol_depth_d101.timestamp_ms, 1_700_000_000_100);

    // Orderbook state after delta 101:
    let book_sol_101 = mapper_sol.order_book().unwrap();
    let book_evm_101 = mapper_evm.order_book().unwrap();
    assert_eq!(book_sol_101.bids(), book_evm_101.bids());
    assert_eq!(book_sol_101.asks(), book_evm_101.asks());
    assert_eq!(book_sol_101.best_bid(), book_evm_101.best_bid());
    assert_eq!(book_sol_101.best_ask(), book_evm_101.best_ask());
    assert_eq!(book_sol_101.spread(), book_evm_101.spread());
    assert_eq!(book_sol_101.spread(), Some(1.5));
    assert_eq!(book_sol_101.sequence(), Sequence(101));
    assert_eq!(book_evm_101.sequence(), Sequence(101));

    // Transitions after delta 101:
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(101)));
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(101)));
    assert_eq!(mapper_sol.last_timestamp_ms(), Some(1_700_000_000_100));
    assert_eq!(mapper_evm.last_timestamp_ms(), Some(1_700_000_000_100));

    // Freshness after delta 101:
    assert_eq!(
        canon_d101_sol.freshness.status,
        canon_d101_evm.freshness.status
    );
    assert_eq!(canon_d101_sol.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(
        canon_d101_sol.freshness.age_ms,
        canon_d101_evm.freshness.age_ms
    );
    assert_eq!(canon_d101_sol.freshness.age_ms, 500); // 600 - 100
    assert_eq!(
        canon_d101_sol.freshness.sequence,
        canon_d101_evm.freshness.sequence
    );
    assert_eq!(canon_d101_sol.freshness.sequence, Sequence(101));

    // Metadata preservation across delta 101:
    assert_eq!(canon_d101_sol.context.slot_or_block, Some(250_000_101));
    assert_eq!(canon_d101_evm.context.slot_or_block, Some(19_500_101));

    // --- Phase 3: Paired Contiguous Delta 102 Normalization ---
    let eval_delta_102_ms = 1_700_000_000_700i64;
    let raw_d102_sol = load_envelope(FIXTURE_SOLANA_DELTA_102);
    let raw_d102_evm = load_envelope(FIXTURE_EVM_DELTA_102);

    let canon_d102_sol = mapper_sol
        .map_envelope(raw_d102_sol, eval_delta_102_ms)
        .expect("Solana delta 102 should normalize cleanly");
    let canon_d102_evm = mapper_evm
        .map_envelope(raw_d102_evm, eval_delta_102_ms)
        .expect("EVM delta 102 should normalize cleanly");

    let (sol_depth_d102, evm_depth_d102) = match (&canon_d102_sol.payload, &canon_d102_evm.payload)
    {
        (
            CanonicalFeedPayload::OrderBookDelta(sol_d),
            CanonicalFeedPayload::OrderBookDelta(evm_d),
        ) => (sol_d, evm_d),
        _ => panic!("both payloads must be OrderBookDelta"),
    };

    assert_eq!(sol_depth_d102.bids, evm_depth_d102.bids);
    assert_eq!(sol_depth_d102.asks, evm_depth_d102.asks);
    assert_eq!(
        sol_depth_d102.sequence_range,
        SequenceRange::point(Sequence(102)).unwrap()
    );
    assert_eq!(sol_depth_d102.sequence_range, evm_depth_d102.sequence_range);
    assert_eq!(sol_depth_d102.timestamp_ms, 1_700_000_000_200);
    assert_eq!(sol_depth_d102.timestamp_ms, evm_depth_d102.timestamp_ms);

    // Orderbook state after delta 102:
    let book_sol_102 = mapper_sol.order_book().unwrap();
    let book_evm_102 = mapper_evm.order_book().unwrap();
    assert_eq!(book_sol_102.bids(), book_evm_102.bids());
    assert_eq!(book_sol_102.asks(), book_evm_102.asks());
    assert_eq!(book_sol_102.best_bid(), book_evm_102.best_bid());
    assert_eq!(book_sol_102.best_ask(), book_evm_102.best_ask());
    assert_eq!(book_sol_102.spread(), book_evm_102.spread());
    assert_eq!(book_sol_102.spread(), Some(1.0));
    assert_eq!(book_sol_102.sequence(), Sequence(102));
    assert_eq!(book_evm_102.sequence(), Sequence(102));

    // Transitions after delta 102:
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(102)));
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(102)));
    assert_eq!(mapper_sol.last_timestamp_ms(), Some(1_700_000_000_200));
    assert_eq!(mapper_evm.last_timestamp_ms(), Some(1_700_000_000_200));

    // Freshness after delta 102:
    assert_eq!(
        canon_d102_sol.freshness.status,
        canon_d102_evm.freshness.status
    );
    assert_eq!(canon_d102_sol.freshness.status, FreshnessStatus::Fresh);
    assert_eq!(
        canon_d102_sol.freshness.age_ms,
        canon_d102_evm.freshness.age_ms
    );
    assert_eq!(canon_d102_sol.freshness.age_ms, 500); // 700 - 200
    assert_eq!(
        canon_d102_sol.freshness.sequence,
        canon_d102_evm.freshness.sequence
    );
    assert_eq!(canon_d102_sol.freshness.sequence, Sequence(102));

    // Metadata preservation across delta 102:
    assert_eq!(canon_d102_sol.context.slot_or_block, Some(250_000_102));
    assert_eq!(canon_d102_evm.context.slot_or_block, Some(19_500_102));
}

// ---------------------------------------------------------------------------
// 2. Caller-Injected Evaluation Timestamp & Deterministic Freshness Sweeps
// ---------------------------------------------------------------------------

#[test]
fn test_paired_conformance_freshness_sweep_semantics() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let raw_snap_sol = load_envelope(FIXTURE_SOLANA_SNAPSHOT);
    let raw_snap_evm = load_envelope(FIXTURE_EVM_SNAPSHOT);
    let observed_at_ms = raw_snap_sol.context.observed_at_ms; // 1_700_000_000_000
    assert_eq!(raw_snap_evm.context.observed_at_ms, observed_at_ms);

    // Test cases: (evaluated_at_ms, expected_status, expected_age)
    let test_cases = [
        // Exact zero age
        (observed_at_ms, FreshnessStatus::Fresh, 0),
        // Normal fresh latency
        (observed_at_ms + 100, FreshnessStatus::Fresh, 100),
        (observed_at_ms + 1_500, FreshnessStatus::Fresh, 1_500),
        // Exact threshold boundary (default staleness threshold is 10_000 ms)
        (observed_at_ms + 10_000, FreshnessStatus::Fresh, 10_000),
        // Stale past threshold
        (observed_at_ms + 10_001, FreshnessStatus::Stale, 10_001),
        (observed_at_ms + 60_000, FreshnessStatus::Stale, 60_000),
        // Future skew within tolerance (default tolerance is 2_000 ms)
        (observed_at_ms - 1_000, FreshnessStatus::Fresh, 0),
        (observed_at_ms - 2_000, FreshnessStatus::Fresh, 0),
    ];

    for (eval_time, expected_status, expected_age) in test_cases {
        let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol.clone()).unwrap();
        let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm.clone()).unwrap();

        let canon_sol = mapper_sol
            .map_envelope(raw_snap_sol.clone(), eval_time)
            .expect("Solana map_envelope should succeed");
        let canon_evm = mapper_evm
            .map_envelope(raw_snap_evm.clone(), eval_time)
            .expect("EVM map_envelope should succeed");

        // Freshness semantics must be identical between Solana and EVM
        assert_eq!(
            canon_sol.freshness.status, canon_evm.freshness.status,
            "status mismatch at eval_time {eval_time}"
        );
        assert_eq!(
            canon_sol.freshness.status, expected_status,
            "status mismatch for expected at eval_time {eval_time}"
        );
        assert_eq!(
            canon_sol.freshness.age_ms, canon_evm.freshness.age_ms,
            "age_ms mismatch at eval_time {eval_time}"
        );
        assert_eq!(
            canon_sol.freshness.age_ms, expected_age,
            "age_ms mismatch for expected at eval_time {eval_time}"
        );
        assert_eq!(
            canon_sol.freshness.evaluated_at_ms,
            canon_evm.freshness.evaluated_at_ms
        );
        assert_eq!(canon_sol.freshness.evaluated_at_ms, eval_time);
        assert_eq!(
            canon_sol.freshness.observed_at_ms,
            canon_evm.freshness.observed_at_ms
        );
        assert_eq!(canon_sol.freshness.observed_at_ms, observed_at_ms);
        assert_eq!(canon_sol.freshness.sequence, canon_evm.freshness.sequence);
        assert_eq!(canon_sol.freshness.sequence, Sequence(100));
    }

    // Future skew exceeding tolerance: both must yield ResyncRequired and latch resync
    let skew_exceeded_time = observed_at_ms - 2_001;
    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm).unwrap();

    let canon_sol = mapper_sol
        .map_envelope(raw_snap_sol, skew_exceeded_time)
        .unwrap();
    let canon_evm = mapper_evm
        .map_envelope(raw_snap_evm, skew_exceeded_time)
        .unwrap();

    assert_eq!(canon_sol.freshness.status, FreshnessStatus::ResyncRequired);
    assert_eq!(canon_evm.freshness.status, FreshnessStatus::ResyncRequired);
    assert!(mapper_sol.is_resync_required());
    assert!(mapper_evm.is_resync_required());
}

// ---------------------------------------------------------------------------
// 3. Bounded Batch Ingestion Conformance via InjectedFeedSource
// ---------------------------------------------------------------------------

#[test]
fn test_paired_conformance_batch_ingestion_via_injected_source() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol.clone()).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm.clone()).unwrap();

    let stream_sol = vec![
        load_envelope(FIXTURE_SOLANA_SNAPSHOT),
        load_envelope(FIXTURE_SOLANA_DELTA_101),
        load_envelope(FIXTURE_SOLANA_DELTA_102),
    ];
    let stream_evm = vec![
        load_envelope(FIXTURE_EVM_SNAPSHOT),
        load_envelope(FIXTURE_EVM_DELTA_101),
        load_envelope(FIXTURE_EVM_DELTA_102),
    ];

    let mut source_sol = InjectedFeedSource::from_envelopes(stream_sol).unwrap();
    let mut source_evm = InjectedFeedSource::from_envelopes(stream_evm).unwrap();

    let eval_batch_ms = 1_700_000_000_800i64;

    let batch_sol = mapper_sol
        .process_all_from_source(&mut source_sol, eval_batch_ms)
        .expect("Solana batch processing should succeed");
    let batch_evm = mapper_evm
        .process_all_from_source(&mut source_evm, eval_batch_ms)
        .expect("EVM batch processing should succeed");

    assert_eq!(batch_sol.len(), batch_evm.len());
    assert_eq!(batch_sol.len(), 3);

    for (i, (event_sol, event_evm)) in batch_sol.iter().zip(batch_evm.iter()).enumerate() {
        // Freshness conformance:
        assert_eq!(
            event_sol.freshness.status, event_evm.freshness.status,
            "batch index {i} freshness status mismatch"
        );
        assert_eq!(
            event_sol.freshness.age_ms, event_evm.freshness.age_ms,
            "batch index {i} freshness age_ms mismatch"
        );
        assert_eq!(
            event_sol.freshness.sequence, event_evm.freshness.sequence,
            "batch index {i} freshness sequence mismatch"
        );

        // Context preservation:
        assert_eq!(event_sol.context.source_family, ChainFamily::Solana);
        assert_eq!(event_evm.context.source_family, ChainFamily::Evm);
        assert_ne!(
            event_sol.context.slot_or_block,
            event_evm.context.slot_or_block
        );

        // Payload semantic equivalence:
        match (&event_sol.payload, &event_evm.payload) {
            (
                CanonicalFeedPayload::OrderBookSnapshot(s_sol),
                CanonicalFeedPayload::OrderBookSnapshot(s_evm),
            ) => {
                assert_eq!(s_sol.bids, s_evm.bids);
                assert_eq!(s_sol.asks, s_evm.asks);
                assert_eq!(s_sol.sequence, s_evm.sequence);
                assert_eq!(s_sol.timestamp_ms, s_evm.timestamp_ms);
            }
            (
                CanonicalFeedPayload::OrderBookDelta(d_sol),
                CanonicalFeedPayload::OrderBookDelta(d_evm),
            ) => {
                assert_eq!(d_sol.bids, d_evm.bids);
                assert_eq!(d_sol.asks, d_evm.asks);
                assert_eq!(d_sol.sequence_range, d_evm.sequence_range);
                assert_eq!(d_sol.timestamp_ms, d_evm.timestamp_ms);
            }
            _ => panic!("payload variant mismatch at index {i}"),
        }
    }

    // Final orderbook state across mappers must be identical
    let book_sol = mapper_sol.order_book().unwrap();
    let book_evm = mapper_evm.order_book().unwrap();
    assert_eq!(book_sol.bids(), book_evm.bids());
    assert_eq!(book_sol.asks(), book_evm.asks());
    assert_eq!(book_sol.spread(), book_evm.spread());
    assert_eq!(book_sol.sequence(), book_evm.sequence());
    assert_eq!(book_sol.timestamp_ms(), book_evm.timestamp_ms());

    // Both sources are now exhausted
    assert!(source_sol.is_empty());
    assert!(source_evm.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Fail-Closed Paired Sequence Gap Regression & State Preservation
// ---------------------------------------------------------------------------

#[test]
fn test_regression_paired_gap_delta_latches_resync_and_preserves_state() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm).unwrap();

    let eval_base_ms = 1_700_000_000_500i64;

    // Apply valid baseline snapshots (seq 100)
    mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_SNAPSHOT), eval_base_ms)
        .unwrap();
    mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_SNAPSHOT), eval_base_ms)
        .unwrap();

    // Capture baseline state
    let base_seq_sol = mapper_sol.current_sequence();
    let base_seq_evm = mapper_evm.current_sequence();
    let base_time_sol = mapper_sol.last_timestamp_ms();
    let base_time_evm = mapper_evm.last_timestamp_ms();
    let base_book_sol = mapper_sol.order_book().unwrap().clone();
    let base_book_evm = mapper_evm.order_book().unwrap().clone();

    assert_eq!(base_seq_sol, Some(Sequence(100)));
    assert_eq!(base_seq_evm, Some(Sequence(100)));
    assert_eq!(base_time_sol, Some(1_700_000_000_000));
    assert_eq!(base_time_evm, Some(1_700_000_000_000));

    // Apply paired gap deltas (seq 105 when 101 is expected)
    let eval_gap_ms = 1_700_000_000_600i64;
    let err_sol = mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_GAP_DELTA), eval_gap_ms)
        .expect_err("Solana gap delta must fail closed");
    let err_evm = mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_GAP_DELTA), eval_gap_ms)
        .expect_err("EVM gap delta must fail closed");

    // Both mappers fail with identical SequenceGap error
    assert_eq!(
        err_sol,
        MarketTypeError::SequenceGap {
            expected: 101,
            received: 105,
        }
    );
    assert_eq!(
        err_evm,
        MarketTypeError::SequenceGap {
            expected: 101,
            received: 105,
        }
    );

    // Both mappers latch resync
    assert!(mapper_sol.is_resync_required());
    assert!(mapper_evm.is_resync_required());

    // Both mappers preserve baseline state (no partial advancement)
    assert_eq!(mapper_sol.current_sequence(), base_seq_sol);
    assert_eq!(mapper_evm.current_sequence(), base_seq_evm);
    assert_eq!(mapper_sol.last_timestamp_ms(), base_time_sol);
    assert_eq!(mapper_evm.last_timestamp_ms(), base_time_evm);
    assert_eq!(
        mapper_sol.order_book().unwrap().bids(),
        base_book_sol.bids()
    );
    assert_eq!(
        mapper_sol.order_book().unwrap().asks(),
        base_book_sol.asks()
    );
    assert_eq!(
        mapper_evm.order_book().unwrap().bids(),
        base_book_evm.bids()
    );
    assert_eq!(
        mapper_evm.order_book().unwrap().asks(),
        base_book_evm.asks()
    );

    // Sticky latch rejects subsequent valid delta 101
    let err_next_sol = mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_DELTA_101), eval_gap_ms)
        .expect_err("delta must be rejected while resync latched");
    let err_next_evm = mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_DELTA_101), eval_gap_ms)
        .expect_err("delta must be rejected while resync latched");

    assert!(matches!(
        err_next_sol,
        MarketTypeError::ResyncRequired { .. }
    ));
    assert!(matches!(
        err_next_evm,
        MarketTypeError::ResyncRequired { .. }
    ));

    // Recovery snapshot (seq 200) unlatches both mappers and restores identical state
    let eval_rec_ms = 1_700_000_001_500i64;
    let rec_sol = mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_RECOVERY_SNAPSHOT), eval_rec_ms)
        .expect("Solana recovery snapshot must succeed");
    let rec_evm = mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_RECOVERY_SNAPSHOT), eval_rec_ms)
        .expect("EVM recovery snapshot must succeed");

    assert!(!mapper_sol.is_resync_required());
    assert!(!mapper_evm.is_resync_required());
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(200)));
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(200)));
    assert_eq!(mapper_sol.last_timestamp_ms(), Some(1_700_000_001_000));
    assert_eq!(mapper_evm.last_timestamp_ms(), Some(1_700_000_001_000));

    // Payload and book state equivalence post-recovery:
    let (s_rec_sol, s_rec_evm) = match (&rec_sol.payload, &rec_evm.payload) {
        (
            CanonicalFeedPayload::OrderBookSnapshot(s1),
            CanonicalFeedPayload::OrderBookSnapshot(s2),
        ) => (s1, s2),
        _ => panic!("expected OrderBookSnapshot payloads"),
    };
    assert_eq!(s_rec_sol.bids, s_rec_evm.bids);
    assert_eq!(s_rec_sol.asks, s_rec_evm.asks);
    assert_eq!(
        mapper_sol.order_book().unwrap().bids(),
        mapper_evm.order_book().unwrap().bids()
    );
    assert_eq!(
        mapper_sol.order_book().unwrap().asks(),
        mapper_evm.order_book().unwrap().asks()
    );
}

// ---------------------------------------------------------------------------
// 5. Fail-Closed Paired Sequence Overlap Regression & State Preservation
// ---------------------------------------------------------------------------

#[test]
fn test_regression_paired_overlap_delta_latches_resync_and_preserves_state() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm).unwrap();

    let eval_base_ms = 1_700_000_000_500i64;

    // Apply baseline snapshots (seq 100)
    mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_SNAPSHOT), eval_base_ms)
        .unwrap();
    mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_SNAPSHOT), eval_base_ms)
        .unwrap();

    let base_seq_sol = mapper_sol.current_sequence();
    let base_seq_evm = mapper_evm.current_sequence();
    let base_book_sol = mapper_sol.order_book().unwrap().clone();
    let base_book_evm = mapper_evm.order_book().unwrap().clone();

    // Apply paired overlap deltas (seq 100 <= current 100)
    let eval_overlap_ms = 1_700_000_000_600i64;
    let err_sol = mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_OVERLAP_DELTA), eval_overlap_ms)
        .expect_err("Solana overlap delta must fail closed");
    let err_evm = mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_OVERLAP_DELTA), eval_overlap_ms)
        .expect_err("EVM overlap delta must fail closed");

    assert_eq!(
        err_sol,
        MarketTypeError::SequenceOverlap {
            start: 100,
            end: 105,
            current: 100,
        }
    );
    assert_eq!(
        err_evm,
        MarketTypeError::SequenceOverlap {
            start: 100,
            end: 105,
            current: 100,
        }
    );

    // Both mappers latch resync and preserve state untouched
    assert!(mapper_sol.is_resync_required());
    assert!(mapper_evm.is_resync_required());
    assert_eq!(mapper_sol.current_sequence(), base_seq_sol);
    assert_eq!(mapper_evm.current_sequence(), base_seq_evm);
    assert_eq!(
        mapper_sol.order_book().unwrap().bids(),
        base_book_sol.bids()
    );
    assert_eq!(
        mapper_sol.order_book().unwrap().asks(),
        base_book_sol.asks()
    );
    assert_eq!(
        mapper_evm.order_book().unwrap().bids(),
        base_book_evm.bids()
    );
    assert_eq!(
        mapper_evm.order_book().unwrap().asks(),
        base_book_evm.asks()
    );
}

// ---------------------------------------------------------------------------
// 6. Fail-Closed Paired Malformed Input Regression & State Preservation
// ---------------------------------------------------------------------------

#[test]
fn test_regression_paired_malformed_inputs_fail_closed_and_preserve_state() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm).unwrap();

    let eval_ms = 1_700_000_000_500i64;

    // Apply baseline snapshots
    mapper_sol
        .map_envelope(load_envelope(FIXTURE_SOLANA_SNAPSHOT), eval_ms)
        .unwrap();
    mapper_evm
        .map_envelope(load_envelope(FIXTURE_EVM_SNAPSHOT), eval_ms)
        .unwrap();

    let base_seq_sol = mapper_sol.current_sequence();
    let base_seq_evm = mapper_evm.current_sequence();

    // 6a. Malformed serialized JSON fails deserialization before mapper
    assert!(serde_json::from_str::<RawFeedEnvelope>(FIXTURE_SOLANA_MALFORMED).is_err());
    assert!(serde_json::from_str::<RawFeedEnvelope>(FIXTURE_EVM_MALFORMED).is_err());

    // 6b. Paired negative price snapshot fails closed with NegativePrice
    let raw_neg_price_sol = load_envelope(FIXTURE_SOLANA_NEGATIVE_PRICE);
    let raw_neg_price_evm = load_envelope(FIXTURE_EVM_NEGATIVE_PRICE);

    let err_price_sol = mapper_sol
        .map_envelope(raw_neg_price_sol, eval_ms + 100)
        .expect_err("negative price must fail closed");
    let err_price_evm = mapper_evm
        .map_envelope(raw_neg_price_evm, eval_ms + 100)
        .expect_err("negative price must fail closed");

    assert_eq!(err_price_sol, MarketTypeError::NegativePrice);
    assert_eq!(err_price_evm, MarketTypeError::NegativePrice);
    assert_eq!(mapper_sol.current_sequence(), base_seq_sol);
    assert_eq!(mapper_evm.current_sequence(), base_seq_evm);

    // 6c. Paired negative quantity delta fails closed with NegativeQuantity
    let raw_neg_qty_sol = load_envelope(FIXTURE_SOLANA_NEGATIVE_QTY);
    let raw_neg_qty_evm = load_envelope(FIXTURE_EVM_NEGATIVE_QTY);

    let err_qty_sol = mapper_sol
        .map_envelope(raw_neg_qty_sol, eval_ms + 100)
        .expect_err("negative quantity must fail closed");
    let err_qty_evm = mapper_evm
        .map_envelope(raw_neg_qty_evm, eval_ms + 100)
        .expect_err("negative quantity must fail closed");

    assert_eq!(err_qty_sol, MarketTypeError::NegativeQuantity);
    assert_eq!(err_qty_evm, MarketTypeError::NegativeQuantity);
    assert_eq!(mapper_sol.current_sequence(), base_seq_sol);
    assert_eq!(mapper_evm.current_sequence(), base_seq_evm);
}

// ---------------------------------------------------------------------------
// 7. Rejection of Cross-Feed Identity Coercion & State Immutability
// ---------------------------------------------------------------------------

#[test]
fn test_regression_no_cross_feed_identity_coercion() {
    let target_sol = solana_conformance_target();
    let target_evm = evm_conformance_target();

    let mut mapper_sol = CanonicalMarketFeedMapper::new(target_sol.clone()).unwrap();
    let mut mapper_evm = CanonicalMarketFeedMapper::new(target_evm.clone()).unwrap();

    let eval_ms = 1_700_000_000_500i64;

    // Load paired raw envelopes
    let env_snap_sol = load_envelope(FIXTURE_SOLANA_SNAPSHOT);
    let env_snap_evm = load_envelope(FIXTURE_EVM_SNAPSHOT);
    let env_d101_sol = load_envelope(FIXTURE_SOLANA_DELTA_101);
    let env_d101_evm = load_envelope(FIXTURE_EVM_DELTA_101);

    // Vector 1: Attempt to map Solana snapshot envelope through EVM mapper
    let err_cross_sol_to_evm = mapper_evm
        .map_envelope(env_snap_sol.clone(), eval_ms)
        .expect_err("EVM mapper must reject Solana envelope");
    assert_eq!(err_cross_sol_to_evm, MarketTypeError::TargetMismatch);
    assert_eq!(mapper_evm.current_sequence(), None);
    assert_eq!(mapper_evm.last_timestamp_ms(), None);
    assert!(!mapper_evm.is_resync_required());
    assert!(mapper_evm.order_book().is_none());

    // Vector 2: Attempt to map EVM snapshot envelope through Solana mapper
    let err_cross_evm_to_sol = mapper_sol
        .map_envelope(env_snap_evm.clone(), eval_ms)
        .expect_err("Solana mapper must reject EVM envelope");
    assert_eq!(err_cross_evm_to_sol, MarketTypeError::TargetMismatch);
    assert_eq!(mapper_sol.current_sequence(), None);
    assert_eq!(mapper_sol.last_timestamp_ms(), None);
    assert!(!mapper_sol.is_resync_required());
    assert!(mapper_sol.order_book().is_none());

    // Vector 3: Initialize both mappers normally to sequence 100
    mapper_sol.map_envelope(env_snap_sol, eval_ms).unwrap();
    mapper_evm.map_envelope(env_snap_evm, eval_ms).unwrap();

    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(100)));
    let baseline_sol_book = mapper_sol.order_book().unwrap().clone();
    let baseline_evm_book = mapper_evm.order_book().unwrap().clone();

    // Vector 4: Attempt to feed Solana delta 101 to initialized EVM mapper
    let err_delta_sol_to_evm = mapper_evm
        .map_envelope(env_d101_sol, eval_ms + 100)
        .expect_err("EVM mapper must reject Solana delta");
    assert_eq!(err_delta_sol_to_evm, MarketTypeError::TargetMismatch);
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper_evm.last_timestamp_ms(), Some(1_700_000_000_000));
    assert_eq!(mapper_evm.order_book().unwrap(), &baseline_evm_book);
    assert!(!mapper_evm.is_resync_required());

    // Vector 5: Attempt to feed EVM delta 101 to initialized Solana mapper
    let err_delta_evm_to_sol = mapper_sol
        .map_envelope(env_d101_evm, eval_ms + 100)
        .expect_err("Solana mapper must reject EVM delta");
    assert_eq!(err_delta_evm_to_sol, MarketTypeError::TargetMismatch);
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(100)));
    assert_eq!(mapper_sol.last_timestamp_ms(), Some(1_700_000_000_000));
    assert_eq!(mapper_sol.order_book().unwrap(), &baseline_sol_book);
    assert!(!mapper_sol.is_resync_required());

    // Vector 6: Forged envelope with EVM target but Solana chain family
    let mut forged_evm_target_sol_family = load_envelope(FIXTURE_EVM_SNAPSHOT);
    forged_evm_target_sol_family.context.source_family = ChainFamily::Solana;
    let err_forged_evm = mapper_evm
        .map_envelope(forged_evm_target_sol_family, eval_ms + 200)
        .expect_err("EVM mapper must reject forged Solana source_family");
    assert_eq!(
        err_forged_evm,
        MarketTypeError::SourceChainFamilyMismatch {
            source_family: "solana",
            target_chain: "ethereum",
        }
    );
    assert_eq!(mapper_evm.current_sequence(), Some(Sequence(100)));

    // Vector 7: Forged envelope with Solana target but EVM chain family
    let mut forged_sol_target_evm_family = load_envelope(FIXTURE_SOLANA_SNAPSHOT);
    forged_sol_target_evm_family.context.source_family = ChainFamily::Evm;
    let err_forged_sol = mapper_sol
        .map_envelope(forged_sol_target_evm_family, eval_ms + 200)
        .expect_err("Solana mapper must reject forged EVM source_family");
    assert_eq!(
        err_forged_sol,
        MarketTypeError::SourceChainFamilyMismatch {
            source_family: "evm",
            target_chain: "solana",
        }
    );
    assert_eq!(mapper_sol.current_sequence(), Some(Sequence(100)));
}
