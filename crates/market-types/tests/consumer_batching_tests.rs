//! Focused deterministic unit and property tests for consumer batching, backpressure, and resync contract.
//!
//! Covers:
//! 1. Ordering across deterministic batch boundaries (FIFO progression, boundary continuity).
//! 2. Explicit acknowledgement/consumption semantics proving no reordering or duplicate delivery.
//! 3. Bounded queue and batch capacity with validated configuration and checked arithmetic.
//! 4. Fail-closed overflow without drops, coalescing, or eviction.
//! 5. Stale and duplicate classification propagation and queue immutability.
//! 6. Sequence gap/overlap sticky resync latching and validated recovery snapshot contract.
//! 7. State immutability under rejected malformed/oversized/overflow/resync inputs.
//! 8. Coordinated `MarketConsumerBatcher` lifecycle with atomic fail-closed aggregation.
//! 9. Deterministic replay invariance across independent consumer batchers.

use chain_types::{AssetId, ChainId};
use market_types::{
    AggregationOutput, CandleTimeframe, CanonicalFeedEnvelope, CanonicalFeedPayload, ChainFamily,
    ConsumerBatchConfig, ConsumerBatchItem, ConsumerBatchQueue, DeltaClassification, DepthDelta,
    DepthLevel, DepthSnapshot, FeedFinality, FeedObservationContext, FeedSourceLabel, FeedTarget,
    FreshnessStatus, InstrumentId, MarketAggregator, MarketConsumerBatcher, MarketTypeError,
    NormalizedPrice, NormalizedQuantity, SafeFreshnessMeta, Sequence, SequenceRange,
    SnapshotClassification, MAX_CONSUMER_BATCH_SIZE, MAX_CONSUMER_QUEUE_CAPACITY,
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

fn other_target() -> FeedTarget {
    FeedTarget::Instrument(other_instrument())
}

fn price(v: f64) -> NormalizedPrice {
    NormalizedPrice::new(v).unwrap()
}

fn qty(v: f64) -> NormalizedQuantity {
    NormalizedQuantity::new(v).unwrap()
}

fn sample_snapshot(seq: u64, ts: i64) -> DepthSnapshot {
    DepthSnapshot {
        target: sample_target(),
        sequence: Sequence(seq),
        timestamp_ms: ts,
        bids: vec![
            DepthLevel::new(price(150.0), qty(10.0)),
            DepthLevel::new(price(149.0), qty(20.0)),
        ],
        asks: vec![
            DepthLevel::new(price(151.0), qty(10.0)),
            DepthLevel::new(price(152.0), qty(20.0)),
        ],
    }
}

fn sample_delta(start: u64, end: u64, ts: i64) -> DepthDelta {
    DepthDelta {
        target: sample_target(),
        sequence_range: SequenceRange::new(Sequence(start), Sequence(end)).unwrap(),
        timestamp_ms: ts,
        bids: vec![DepthLevel::new(price(150.0), qty(15.0))],
        asks: vec![DepthLevel::new(price(151.0), qty(25.0))],
    }
}

fn make_envelope(payload: CanonicalFeedPayload, seq: u64, ts: i64) -> CanonicalFeedEnvelope {
    CanonicalFeedEnvelope {
        context: FeedObservationContext {
            source_family: ChainFamily::Solana,
            source_label: FeedSourceLabel::new("solana-direct").unwrap(),
            finality: FeedFinality::Confirmed,
            slot_or_block: Some(100),
            observed_at_ms: ts,
        },
        freshness: SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: ts,
            evaluated_at_ms: ts + 10,
            age_ms: 10,
            sequence: Sequence(seq),
        },
        payload,
    }
}

// =========================================================================
// 1. Ordering Across Deterministic Batch Boundaries
// =========================================================================

#[test]
fn test_ordering_across_deterministic_boundaries() {
    let config = ConsumerBatchConfig::new(20, 3).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    // Establish baseline at sequence 1
    let snap = sample_snapshot(1, 1_000);
    let snap_item = ConsumerBatchItem::from_depth_snapshot(snap).unwrap();
    let snap_class = queue.enqueue_snapshot(snap_item).unwrap();
    assert_eq!(
        snap_class,
        SnapshotClassification::Accepted {
            new_sequence: Sequence(1)
        }
    );

    // Enqueue 9 contiguous deltas (sequences 2..=10)
    for s in 2..=10 {
        let delta = sample_delta(s, s, 1_000 + s as i64 * 10);
        let item = ConsumerBatchItem::from_depth_delta(delta).unwrap();
        let class = queue.enqueue_item(item).unwrap();
        assert_eq!(
            class,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(s)
            }
        );
    }

    assert_eq!(queue.queue_len(), 10);
    assert_eq!(queue.current_sequence(), Some(Sequence(10)));

    // Pull Batch 1: items [1, 2, 3]
    let b1 = queue.pull_batch().unwrap().expect("batch 1 should exist");
    assert_eq!(b1.batch_id(), 1);
    assert_eq!(b1.len(), 3);
    assert_eq!(
        b1.sequence_range(),
        SequenceRange::new(Sequence(1), Sequence(3)).unwrap()
    );
    assert_eq!(b1.items[0].sequence_range.start, Sequence(1));
    assert_eq!(b1.items[1].sequence_range.start, Sequence(2));
    assert_eq!(b1.items[2].sequence_range.start, Sequence(3));
    let ack1 = queue.acknowledge(b1.batch_id()).unwrap();
    assert_eq!(ack1.batch_id, 1);
    assert_eq!(ack1.item_count, 3);
    assert_eq!(queue.last_acknowledged_sequence(), Some(Sequence(3)));

    // Pull Batch 2: items [4, 5, 6]
    let b2 = queue.pull_batch().unwrap().expect("batch 2 should exist");
    assert_eq!(b2.batch_id(), 2);
    assert_eq!(b2.len(), 3);
    assert_eq!(
        b2.sequence_range(),
        SequenceRange::new(Sequence(4), Sequence(6)).unwrap()
    );
    assert_eq!(b2.items[0].sequence_range.start, Sequence(4));
    assert_eq!(b2.items[1].sequence_range.start, Sequence(5));
    assert_eq!(b2.items[2].sequence_range.start, Sequence(6));
    queue.acknowledge(b2.batch_id()).unwrap();
    assert_eq!(queue.last_acknowledged_sequence(), Some(Sequence(6)));

    // Pull Batch 3: items [7, 8, 9]
    let b3 = queue.pull_batch().unwrap().expect("batch 3 should exist");
    assert_eq!(b3.batch_id(), 3);
    assert_eq!(b3.len(), 3);
    assert_eq!(
        b3.sequence_range(),
        SequenceRange::new(Sequence(7), Sequence(9)).unwrap()
    );
    queue.acknowledge(b3.batch_id()).unwrap();

    // Pull Batch 4: item [10] (partial batch boundary)
    let b4 = queue.pull_batch().unwrap().expect("batch 4 should exist");
    assert_eq!(b4.batch_id(), 4);
    assert_eq!(b4.len(), 1);
    assert_eq!(
        b4.sequence_range(),
        SequenceRange::new(Sequence(10), Sequence(10)).unwrap()
    );
    queue.acknowledge(b4.batch_id()).unwrap();
    assert_eq!(queue.last_acknowledged_sequence(), Some(Sequence(10)));

    // Pull Batch 5: empty queue
    let b5 = queue.pull_batch().unwrap();
    assert!(b5.is_none());
    assert_eq!(queue.queue_len(), 0);
    assert_eq!(queue.total_delivered_items(), 10);
    assert_eq!(queue.total_acknowledged_items(), 10);
}

// =========================================================================
// 2. Explicit Acknowledgement & No Reordering or Duplicate Delivery
// =========================================================================

#[test]
fn test_explicit_acknowledgement_and_no_reordering_or_duplicate_delivery() {
    let config = ConsumerBatchConfig::new(10, 2).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(1, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    for s in 2..=4 {
        let delta = sample_delta(s, s, 1_000 + s as i64);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();
    }

    // Pull Batch 1
    let b1 = queue.pull_batch().unwrap().unwrap();
    assert_eq!(b1.batch_id(), 1);
    assert_eq!(b1.len(), 2);
    assert!(queue.has_in_flight_batch());

    // Attempting to pull another batch while Batch 1 is unacknowledged MUST fail closed
    let pull_err = queue.pull_batch().unwrap_err();
    assert_eq!(
        pull_err,
        MarketTypeError::UnacknowledgedBatchPending { batch_id: 1 }
    );

    // Attempting to consume directly while Batch 1 is unacknowledged MUST fail closed
    let consume_err = queue.consume_batch().unwrap_err();
    assert_eq!(
        consume_err,
        MarketTypeError::UnacknowledgedBatchPending { batch_id: 1 }
    );

    // Attempting to acknowledge with wrong batch ID MUST fail closed and keep batch in flight
    let ack_err = queue.acknowledge(99).unwrap_err();
    assert_eq!(
        ack_err,
        MarketTypeError::InvalidBatchAcknowledgement {
            expected: 1,
            received: 99
        }
    );
    assert!(queue.has_in_flight_batch());

    // Acknowledge Batch 1 successfully
    let ack1 = queue.acknowledge(1).unwrap();
    assert_eq!(ack1.batch_id, 1);
    assert!(!queue.has_in_flight_batch());

    // Attempting to re-acknowledge Batch 1 MUST fail closed
    let re_ack_err = queue.acknowledge(1).unwrap_err();
    assert_eq!(re_ack_err, MarketTypeError::NoPendingBatchToAcknowledge);

    // Now Batch 2 can be pulled
    let b2 = queue.pull_batch().unwrap().unwrap();
    assert_eq!(b2.batch_id(), 2);
    assert_eq!(
        b2.sequence_range(),
        SequenceRange::new(Sequence(3), Sequence(4)).unwrap()
    );
    queue.acknowledge(2).unwrap();

    assert_eq!(queue.total_acknowledged_items(), 4);
}

// =========================================================================
// 3. Queue and Batch Limits & Config Validation
// =========================================================================

#[test]
fn test_queue_and_batch_limits_and_configuration_validation() {
    // Zero queue capacity rejected
    let err = ConsumerBatchConfig::new(0, 10).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::InvalidConsumerConfig {
            reason: "queue capacity must be greater than zero"
        }
    );

    // Exceed MAX_CONSUMER_QUEUE_CAPACITY rejected
    let err = ConsumerBatchConfig::new(MAX_CONSUMER_QUEUE_CAPACITY + 1, 10).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::ConsumerQueueCapacityExceeded {
            count: MAX_CONSUMER_QUEUE_CAPACITY + 1,
            max: MAX_CONSUMER_QUEUE_CAPACITY
        }
    );

    // Zero batch size rejected
    let err = ConsumerBatchConfig::new(100, 0).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::InvalidConsumerConfig {
            reason: "batch size must be greater than zero"
        }
    );

    // Exceed MAX_CONSUMER_BATCH_SIZE rejected
    let err = ConsumerBatchConfig::new(2_000, MAX_CONSUMER_BATCH_SIZE + 1).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::ConsumerBatchSizeExceeded {
            size: MAX_CONSUMER_BATCH_SIZE + 1,
            max: MAX_CONSUMER_BATCH_SIZE
        }
    );

    // Batch size > queue capacity rejected
    let err = ConsumerBatchConfig::new(5, 10).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::InvalidConsumerConfig {
            reason: "batch size cannot exceed queue capacity"
        }
    );

    // Exact bounds succeed
    let valid =
        ConsumerBatchConfig::new(MAX_CONSUMER_QUEUE_CAPACITY, MAX_CONSUMER_BATCH_SIZE).unwrap();
    assert_eq!(valid.max_queue_capacity, MAX_CONSUMER_QUEUE_CAPACITY);
    assert_eq!(valid.max_batch_size, MAX_CONSUMER_BATCH_SIZE);
}

// =========================================================================
// 4. Fail-Closed Overflow Without Drops
// =========================================================================

#[test]
fn test_fail_closed_overflow_without_lossy_drops() {
    let capacity = 3;
    let config = ConsumerBatchConfig::new(capacity, 2).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(1, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    for s in 2..=3 {
        let delta = sample_delta(s, s, 1_000 + s as i64);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();
    }

    assert_eq!(queue.queue_len(), 3);
    assert_eq!(queue.remaining_capacity().unwrap(), 0);

    // Attempting to enqueue 4th item MUST fail closed with ConsumerQueueCapacityExceeded
    let delta4 = sample_delta(4, 4, 1_004);
    let item4 = ConsumerBatchItem::from_depth_delta(delta4).unwrap();
    let err = queue.enqueue_item(item4).unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::ConsumerQueueCapacityExceeded {
            count: 4,
            max: capacity
        }
    );

    // Crucial check: PRD forbids lossy drop policy!
    // Item 1 must NOT be dropped, sequence cursor must NOT advance to 4
    assert_eq!(queue.queue_len(), 3);
    assert_eq!(queue.current_sequence(), Some(Sequence(3)));

    // Pull batch 1: must yield original item 1 and item 2 without loss
    let b1 = queue.pull_batch().unwrap().unwrap();
    assert_eq!(b1.items[0].sequence_range.start, Sequence(1));
    assert_eq!(b1.items[1].sequence_range.start, Sequence(2));
}

// =========================================================================
// 5. Backpressure: In-Flight Batch Retains Buffer Capacity
// =========================================================================

#[test]
fn test_in_flight_batch_backpressure_retention() {
    let config = ConsumerBatchConfig::new(4, 2).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(1, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    for s in 2..=4 {
        queue
            .enqueue_item(
                ConsumerBatchItem::from_depth_delta(sample_delta(s, s, 1_000 + s as i64)).unwrap(),
            )
            .unwrap();
    }

    // Buffer is full (4 items). Pull batch 1 (2 items).
    let b1 = queue.pull_batch().unwrap().unwrap();
    assert_eq!(queue.queue_len(), 2);
    assert_eq!(queue.in_flight_len(), 2);
    assert_eq!(queue.allocated_capacity().unwrap(), 4);
    assert_eq!(queue.remaining_capacity().unwrap(), 0);

    // Enqueue must fail because in-flight batch still occupies capacity
    let delta5 = sample_delta(5, 5, 1_005);
    let err = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(delta5.clone()).unwrap())
        .unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::ConsumerQueueCapacityExceeded { count: 5, max: 4 }
    );

    // Acknowledge batch 1: frees 2 capacity slots
    queue.acknowledge(b1.batch_id()).unwrap();
    assert_eq!(queue.allocated_capacity().unwrap(), 2);
    assert_eq!(queue.remaining_capacity().unwrap(), 2);

    // Now delta 5 and delta 6 succeed
    queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(delta5).unwrap())
        .unwrap();
    let delta6 = sample_delta(6, 6, 1_006);
    queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(delta6).unwrap())
        .unwrap();
    assert_eq!(queue.allocated_capacity().unwrap(), 4);
}

// =========================================================================
// 6. Stale and Duplicate Behavior
// =========================================================================

#[test]
fn test_stale_and_duplicate_behavior() {
    let config = ConsumerBatchConfig::new(10, 5).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(10, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    assert_eq!(queue.current_sequence(), Some(Sequence(10)));
    assert_eq!(queue.queue_len(), 1);

    // Stale delta (seq 9 < 10)
    let stale_delta = sample_delta(9, 9, 1_001);
    let class = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(stale_delta).unwrap())
        .unwrap();
    assert_eq!(
        class,
        DeltaClassification::Stale {
            sequence: Sequence(9),
            current: Sequence(10)
        }
    );
    // Queue length and sequence unchanged
    assert_eq!(queue.queue_len(), 1);
    assert_eq!(queue.current_sequence(), Some(Sequence(10)));

    // Duplicate delta (seq 10 == 10)
    let dup_delta = sample_delta(10, 10, 1_002);
    let class_dup = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(dup_delta).unwrap())
        .unwrap();
    assert_eq!(
        class_dup,
        DeltaClassification::Duplicate {
            sequence: Sequence(10)
        }
    );
    assert_eq!(queue.queue_len(), 1);
    assert_eq!(queue.current_sequence(), Some(Sequence(10)));
}

// =========================================================================
// 7. Gap & Overlap Sticky Resync and Validated Recovery Snapshot
// =========================================================================

#[test]
fn test_gap_and_overlap_sticky_resync_and_validated_recovery() {
    let config = ConsumerBatchConfig::new(10, 5).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(5, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();
    assert_eq!(queue.current_sequence(), Some(Sequence(5)));
    assert!(!queue.is_resync_required());

    // 1. Sequence Gap (seq 7 when expected is 6)
    let gap_delta = sample_delta(7, 7, 1_001);
    let class = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(gap_delta).unwrap())
        .unwrap();
    assert_eq!(
        class,
        DeltaClassification::ResyncRequired {
            expected: Sequence(6),
            received: Sequence(7)
        }
    );

    // Resync latch is sticky
    assert!(queue.is_resync_required());
    assert_eq!(queue.queue_len(), 1); // gap item was NOT enqueued
    assert_eq!(queue.current_sequence(), Some(Sequence(5)));

    // While resync is latched, normal dequeue is PREVENTED
    let pull_err = queue.pull_batch().unwrap_err();
    assert_eq!(
        pull_err,
        MarketTypeError::ResyncRequired {
            reason: "consumer queue latched in resync mode; recovery snapshot required"
        }
    );

    // While resync is latched, normal delta enqueue returns ResyncRequired
    let next_delta = sample_delta(6, 6, 1_002);
    let class_resync = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(next_delta).unwrap())
        .unwrap();
    assert_eq!(
        class_resync,
        DeltaClassification::ResyncRequired {
            expected: Sequence(6),
            received: Sequence(6)
        }
    );

    // 2. Recovery attempts:
    // Stale snapshot rejected fail-closed; resync remains sticky
    let stale_snap = sample_snapshot(4, 1_003);
    let stale_err = queue.reset_with_snapshot(&stale_snap).unwrap_err();
    assert_eq!(
        stale_err,
        MarketTypeError::StaleSequence {
            sequence: 4,
            current: 5
        }
    );
    assert!(queue.is_resync_required());

    // Duplicate snapshot rejected fail-closed; resync remains sticky
    let dup_snap = sample_snapshot(5, 1_004);
    let dup_err = queue.reset_with_snapshot(&dup_snap).unwrap_err();
    assert_eq!(dup_err, MarketTypeError::DuplicateSequence(5));
    assert!(queue.is_resync_required());

    // Target mismatch snapshot rejected fail-closed; resync remains sticky
    let mut wrong_target_snap = sample_snapshot(10, 1_005);
    wrong_target_snap.target = other_target();
    let mismatch_err = queue.reset_with_snapshot(&wrong_target_snap).unwrap_err();
    assert_eq!(mismatch_err, MarketTypeError::TargetMismatch);
    assert!(queue.is_resync_required());

    // 3. Validated fresh snapshot clears resync latch cleanly
    let recovery_snap = sample_snapshot(10, 1_006);
    queue.reset_with_snapshot(&recovery_snap).unwrap();

    assert!(!queue.is_resync_required());
    assert_eq!(queue.current_sequence(), Some(Sequence(10)));
    assert_eq!(queue.queue_len(), 1);

    // Dequeue is now unblocked and delivers the recovery snapshot
    let b = queue.pull_batch().unwrap().unwrap();
    assert_eq!(b.items[0].sequence_range.start, Sequence(10));
    queue.acknowledge(b.batch_id()).unwrap();

    // Contiguous deltas now flow normally
    let delta11 = sample_delta(11, 11, 1_011);
    let class11 = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(delta11).unwrap())
        .unwrap();
    assert_eq!(
        class11,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(11)
        }
    );
}

#[test]
fn test_sequence_overlap_latches_resync_fail_closed() {
    let config = ConsumerBatchConfig::new(10, 5).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(5, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    // Sequence overlap: delta covering [4, 6] overlaps current sequence 5
    let overlap_delta = sample_delta(4, 6, 1_001);
    let class = queue
        .enqueue_item(ConsumerBatchItem::from_depth_delta(overlap_delta).unwrap())
        .unwrap();

    assert_eq!(
        class,
        DeltaClassification::ResyncRequired {
            expected: Sequence(6),
            received: Sequence(4)
        }
    );
    assert!(queue.is_resync_required());
}

// =========================================================================
// 8. Rejected Input State Immutability
// =========================================================================

#[test]
fn test_rejected_input_state_immutability() {
    let config = ConsumerBatchConfig::new(10, 5).unwrap();
    let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

    let snap = sample_snapshot(1, 1_000);
    queue
        .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
        .unwrap();

    let pre_state = queue.clone();

    // 1. Target mismatch
    let mut bad_target_delta = sample_delta(2, 2, 1_001);
    bad_target_delta.target = other_target();
    let err = queue
        .enqueue_item(ConsumerBatchItem {
            target: other_target(),
            sequence_range: SequenceRange::new(Sequence(2), Sequence(2)).unwrap(),
            timestamp_ms: 1_001,
            payload: AggregationOutput::DepthDelta(bad_target_delta),
        })
        .unwrap_err();
    assert_eq!(err, MarketTypeError::TargetMismatch);
    assert_eq!(queue, pre_state);

    // 2. Non-positive timestamp
    let err = queue
        .enqueue_item(ConsumerBatchItem {
            target: sample_target(),
            sequence_range: SequenceRange::new(Sequence(2), Sequence(2)).unwrap(),
            timestamp_ms: -1,
            payload: AggregationOutput::DepthDelta(sample_delta(2, 2, 1_001)),
        })
        .unwrap_err();
    assert_eq!(err, MarketTypeError::InvalidTimestamp(-1));
    assert_eq!(queue, pre_state);

    // 3. Invalid sequence range
    let err = ConsumerBatchItem::new(
        sample_target(),
        SequenceRange {
            start: Sequence(5),
            end: Sequence(3),
        },
        1_001,
        AggregationOutput::DepthDelta(sample_delta(2, 2, 1_001)),
    )
    .unwrap_err();
    assert_eq!(
        err,
        MarketTypeError::InvalidSequenceRange { start: 5, end: 3 }
    );
    assert_eq!(queue, pre_state);

    // 4. Batch atomic rollback: second item has target mismatch
    let item_valid = ConsumerBatchItem::from_depth_delta(sample_delta(2, 2, 1_002)).unwrap();
    let item_invalid = ConsumerBatchItem {
        target: other_target(),
        sequence_range: SequenceRange::new(Sequence(3), Sequence(3)).unwrap(),
        timestamp_ms: 1_003,
        payload: AggregationOutput::DepthDelta(sample_delta(3, 3, 1_003)),
    };

    let batch_err = queue
        .enqueue_batch(vec![item_valid, item_invalid])
        .unwrap_err();
    assert_eq!(batch_err, MarketTypeError::TargetMismatch);
    // Crucial: item_valid must NOT remain enqueued after batch failure!
    assert_eq!(queue, pre_state);
}

// =========================================================================
// 9. Coordinated MarketConsumerBatcher Lifecycle
// =========================================================================

#[test]
fn test_market_consumer_batcher_coordinated_lifecycle() {
    let instrument = sample_instrument();
    let target = FeedTarget::Instrument(instrument.clone());
    let aggregator =
        MarketAggregator::for_instrument(instrument.clone(), CandleTimeframe::M1, 100, 100)
            .unwrap();
    let config = ConsumerBatchConfig::new(10, 2).unwrap();
    let mut batcher = MarketConsumerBatcher::new(aggregator, config).unwrap();

    assert_eq!(batcher.target(), &target);
    assert!(!batcher.is_resync_required());

    // Feed initial snapshot envelope
    let snap_env = make_envelope(
        CanonicalFeedPayload::OrderBookSnapshot(sample_snapshot(1, 1_700_000_000_000)),
        1,
        1_700_000_000_000,
    );
    let class = batcher.apply_envelope(&snap_env).unwrap();
    assert_eq!(
        class,
        DeltaClassification::Contiguous {
            new_sequence: Sequence(1)
        }
    );
    assert_eq!(batcher.queue().queue_len(), 1);

    // Feed contiguous delta envelopes
    for s in 2..=4 {
        let delta_env = make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(
                s,
                s,
                1_700_000_000_000 + s as i64 * 10,
            )),
            s,
            1_700_000_000_000 + s as i64 * 10,
        );
        let c = batcher.apply_envelope(&delta_env).unwrap();
        assert_eq!(
            c,
            DeltaClassification::Contiguous {
                new_sequence: Sequence(s)
            }
        );
    }
    assert_eq!(batcher.queue().queue_len(), 4);

    // Pull Batch 1 and acknowledge
    let b1 = batcher.pull_batch().unwrap().unwrap();
    assert_eq!(b1.batch_id(), 1);
    assert_eq!(b1.len(), 2);
    batcher.acknowledge(1).unwrap();

    // Feed gap delta (seq 6 when 5 expected)
    let gap_env = make_envelope(
        CanonicalFeedPayload::OrderBookDelta(sample_delta(6, 6, 1_700_000_000_060)),
        6,
        1_700_000_000_060,
    );
    let class_gap = batcher.apply_envelope(&gap_env).unwrap();
    assert_eq!(
        class_gap,
        DeltaClassification::ResyncRequired {
            expected: Sequence(5),
            received: Sequence(6)
        }
    );

    // Both aggregator and queue must be latched in resync
    assert!(batcher.is_resync_required());
    assert!(batcher.aggregator().is_resync_required());
    assert!(batcher.queue().is_resync_required());

    // Dequeue prevented while resync latched
    let pull_err = batcher.pull_batch().unwrap_err();
    assert_eq!(
        pull_err,
        MarketTypeError::ResyncRequired {
            reason: "consumer queue latched in resync mode; recovery snapshot required"
        }
    );

    // Recovery via reset_with_snapshot clears resync on both components
    let recovery_snap = sample_snapshot(10, 1_700_000_000_100);
    batcher.reset_with_snapshot(&recovery_snap).unwrap();

    assert!(!batcher.is_resync_required());
    assert!(!batcher.aggregator().is_resync_required());
    assert!(!batcher.queue().is_resync_required());

    // Consumer can now dequeue the recovery snapshot
    let rec_b = batcher.pull_batch().unwrap().unwrap();
    assert_eq!(rec_b.items[0].sequence_range.start, Sequence(10));
    batcher.acknowledge(rec_b.batch_id()).unwrap();
}

// =========================================================================
// 10. Deterministic Replay Invariance Across Consumers
// =========================================================================

#[test]
fn test_property_deterministic_replay_invariance() {
    let instrument = sample_instrument();
    let config = ConsumerBatchConfig::new(50, 4).unwrap();

    let mut batcher_a = MarketConsumerBatcher::new(
        MarketAggregator::for_instrument(instrument.clone(), CandleTimeframe::M1, 100, 100)
            .unwrap(),
        config,
    )
    .unwrap();

    let mut batcher_b = MarketConsumerBatcher::new(
        MarketAggregator::for_instrument(instrument, CandleTimeframe::M1, 100, 100).unwrap(),
        config,
    )
    .unwrap();

    let envelopes = vec![
        make_envelope(
            CanonicalFeedPayload::OrderBookSnapshot(sample_snapshot(1, 1_000)),
            1,
            1_000,
        ),
        make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(2, 2, 1_010)),
            2,
            1_010,
        ),
        make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(3, 3, 1_020)),
            3,
            1_020,
        ),
        make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(4, 4, 1_030)),
            4,
            1_030,
        ),
        make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(5, 5, 1_040)),
            5,
            1_040,
        ),
    ];

    for env in &envelopes {
        let res_a = batcher_a.apply_envelope(env).unwrap();
        let res_b = batcher_b.apply_envelope(env).unwrap();
        assert_eq!(res_a, res_b);
    }

    // Pull and acknowledge all batches on both; assert identical results
    loop {
        let b_a = batcher_a.pull_batch().unwrap();
        let b_b = batcher_b.pull_batch().unwrap();
        assert_eq!(b_a.is_some(), b_b.is_some());

        match (b_a, b_b) {
            (Some(ba), Some(bb)) => {
                assert_eq!(ba.batch_id(), bb.batch_id());
                assert_eq!(ba.sequence_range(), bb.sequence_range());
                assert_eq!(ba.len(), bb.len());
                for (ia, ib) in ba.items.iter().zip(bb.items.iter()) {
                    assert_eq!(ia.sequence_range, ib.sequence_range);
                    assert_eq!(ia.timestamp_ms, ib.timestamp_ms);
                    assert_eq!(ia.target, ib.target);
                }
                let ack_a = batcher_a.acknowledge(ba.batch_id()).unwrap();
                let ack_b = batcher_b.acknowledge(bb.batch_id()).unwrap();
                assert_eq!(ack_a, ack_b);
            }
            (None, None) => break,
            _ => unreachable!(),
        }
    }

    assert_eq!(
        batcher_a.queue().total_acknowledged_items(),
        batcher_b.queue().total_acknowledged_items()
    );
}
