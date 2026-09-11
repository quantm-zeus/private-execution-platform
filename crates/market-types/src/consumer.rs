//! Pure deterministic consumer-side batching, backpressure, and resync contract.
//!
//! Provides bounded queueing, deterministic batch boundaries, explicit acknowledgement
//! semantics, fail-closed backpressure without drops, and sticky resync tracking
//! over canonical market aggregation outputs.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::aggregation::{AggregatedDepthSnapshot, MarketAggregator};
use crate::error::MarketTypeError;
use crate::feed::{CanonicalFeedEnvelope, CanonicalFeedPayload};
use crate::identity::FeedTarget;
use crate::ohlcv::Candle;
use crate::orderbook::{DepthDelta, DepthSnapshot};
use crate::primitives::Sequence;
use crate::sequence::{
    DeltaClassification, SequenceRange, SequencedStreamTracker, SnapshotClassification,
};

/// Maximum allowed consumer queue capacity.
pub const MAX_CONSUMER_QUEUE_CAPACITY: usize = 10_000;

/// Maximum allowed consumer batch size.
pub const MAX_CONSUMER_BATCH_SIZE: usize = 1_000;

// =========================================================================
// Configuration
// =========================================================================

/// Configuration for deterministic consumer batching and queue bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerBatchConfig {
    /// Maximum number of unconsumed + in-flight items held in buffer.
    pub max_queue_capacity: usize,
    /// Maximum number of items delivered in a single batch.
    pub max_batch_size: usize,
}

impl ConsumerBatchConfig {
    /// Validates and constructs consumer batch configuration.
    pub fn new(max_queue_capacity: usize, max_batch_size: usize) -> Result<Self, MarketTypeError> {
        let config = Self {
            max_queue_capacity,
            max_batch_size,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration parameters against hard bounds and relational constraints.
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if self.max_queue_capacity == 0 {
            return Err(MarketTypeError::InvalidConsumerConfig {
                reason: "queue capacity must be greater than zero",
            });
        }
        if self.max_queue_capacity > MAX_CONSUMER_QUEUE_CAPACITY {
            return Err(MarketTypeError::ConsumerQueueCapacityExceeded {
                count: self.max_queue_capacity,
                max: MAX_CONSUMER_QUEUE_CAPACITY,
            });
        }
        if self.max_batch_size == 0 {
            return Err(MarketTypeError::InvalidConsumerConfig {
                reason: "batch size must be greater than zero",
            });
        }
        if self.max_batch_size > MAX_CONSUMER_BATCH_SIZE {
            return Err(MarketTypeError::ConsumerBatchSizeExceeded {
                size: self.max_batch_size,
                max: MAX_CONSUMER_BATCH_SIZE,
            });
        }
        if self.max_batch_size > self.max_queue_capacity {
            return Err(MarketTypeError::InvalidConsumerConfig {
                reason: "batch size cannot exceed queue capacity",
            });
        }
        Ok(())
    }
}

// =========================================================================
// Aggregation Output Envelope & Items
// =========================================================================

/// Canonical aggregation output event emitted by market aggregation pipeline.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AggregationOutput {
    /// Canonical depth snapshot baseline.
    DepthSnapshot(DepthSnapshot),
    /// Enriched aggregated depth snapshot with cumulative liquidity and pricing metrics.
    AggregatedDepthSnapshot(AggregatedDepthSnapshot),
    /// Incremental depth delta update covering a sequence range.
    DepthDelta(DepthDelta),
    /// Completed aggregated OHLCV candle window.
    Candle(Candle),
}

impl AggregationOutput {
    /// Returns the target for this aggregation output.
    pub fn target(&self) -> FeedTarget {
        match self {
            Self::DepthSnapshot(snap) => snap.target.clone(),
            Self::AggregatedDepthSnapshot(snap) => snap.target.clone(),
            Self::DepthDelta(delta) => delta.target.clone(),
            Self::Candle(candle) => FeedTarget::Instrument(candle.instrument.clone()),
        }
    }

    /// Returns the primary timestamp (ms) for this aggregation output.
    pub fn timestamp_ms(&self) -> i64 {
        match self {
            Self::DepthSnapshot(snap) => snap.timestamp_ms,
            Self::AggregatedDepthSnapshot(snap) => snap.timestamp_ms,
            Self::DepthDelta(delta) => delta.timestamp_ms,
            Self::Candle(candle) => candle.close_time_ms,
        }
    }
}

/// Bounded queue envelope for sequenced market items consumed in batches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerBatchItem<T> {
    /// Target instrument or pool for this item.
    pub target: FeedTarget,
    /// Sequence range covered by this item.
    pub sequence_range: SequenceRange,
    /// Caller-injected timestamp in epoch milliseconds.
    pub timestamp_ms: i64,
    /// Wrapped item payload.
    pub payload: T,
}

impl<T> ConsumerBatchItem<T> {
    /// Constructs a validated consumer batch item envelope.
    pub fn new(
        target: FeedTarget,
        sequence_range: SequenceRange,
        timestamp_ms: i64,
        payload: T,
    ) -> Result<Self, MarketTypeError> {
        let item = Self {
            target,
            sequence_range,
            timestamp_ms,
            payload,
        };
        item.validate()?;
        Ok(item)
    }

    /// Validates the item's metadata envelopes.
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.target.validate()?;
        self.sequence_range.validate()?;
        if self.timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.timestamp_ms));
        }
        Ok(())
    }
}

impl ConsumerBatchItem<AggregationOutput> {
    /// Constructs a consumer batch item from a canonical depth snapshot.
    pub fn from_depth_snapshot(snapshot: DepthSnapshot) -> Result<Self, MarketTypeError> {
        snapshot.validate()?;
        let sequence_range = SequenceRange::point(snapshot.sequence)?;
        Ok(Self {
            target: snapshot.target.clone(),
            sequence_range,
            timestamp_ms: snapshot.timestamp_ms,
            payload: AggregationOutput::DepthSnapshot(snapshot),
        })
    }

    /// Constructs a consumer batch item from an aggregated depth snapshot.
    pub fn from_aggregated_snapshot(
        snapshot: AggregatedDepthSnapshot,
    ) -> Result<Self, MarketTypeError> {
        self_validate_aggregated_snapshot(&snapshot)?;
        let sequence_range = SequenceRange::point(snapshot.sequence)?;
        Ok(Self {
            target: snapshot.target.clone(),
            sequence_range,
            timestamp_ms: snapshot.timestamp_ms,
            payload: AggregationOutput::AggregatedDepthSnapshot(snapshot),
        })
    }

    /// Constructs a consumer batch item from an incremental depth delta.
    pub fn from_depth_delta(delta: DepthDelta) -> Result<Self, MarketTypeError> {
        delta.validate()?;
        Ok(Self {
            target: delta.target.clone(),
            sequence_range: delta.sequence_range,
            timestamp_ms: delta.timestamp_ms,
            payload: AggregationOutput::DepthDelta(delta),
        })
    }

    /// Constructs a consumer batch item from an aggregated OHLCV candle.
    pub fn from_candle(
        target: FeedTarget,
        sequence: Sequence,
        candle: Candle,
    ) -> Result<Self, MarketTypeError> {
        target.validate()?;
        candle.validate()?;
        let sequence_range = SequenceRange::point(sequence)?;
        Ok(Self {
            target,
            sequence_range,
            timestamp_ms: candle.close_time_ms,
            payload: AggregationOutput::Candle(candle),
        })
    }
}

fn self_validate_aggregated_snapshot(
    snap: &AggregatedDepthSnapshot,
) -> Result<(), MarketTypeError> {
    snap.target.validate()?;
    snap.sequence.validate()?;
    if snap.timestamp_ms <= 0 {
        return Err(MarketTypeError::InvalidTimestamp(snap.timestamp_ms));
    }
    if snap.bids.is_empty() && snap.asks.is_empty() {
        return Err(MarketTypeError::EmptyDepthLevels);
    }
    Ok(())
}

// =========================================================================
// Delivered Batch & Acknowledgement
// =========================================================================

/// Delivered consumer batch containing items with deterministic boundaries and sequence range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerBatch<T> {
    /// Monotonically increasing batch identifier.
    pub batch_id: u64,
    /// Target instrument or pool for this batch.
    pub target: FeedTarget,
    /// Bounded sequence range covered by all items in this batch.
    pub sequence_range: SequenceRange,
    /// Bounded list of items in strict FIFO order.
    pub items: Vec<ConsumerBatchItem<T>>,
}

impl<T> ConsumerBatch<T> {
    /// Number of items in this batch.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if this batch contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the batch ID.
    pub fn batch_id(&self) -> u64 {
        self.batch_id
    }

    /// Returns the sequence range.
    pub fn sequence_range(&self) -> SequenceRange {
        self.sequence_range
    }

    /// Returns the target.
    pub fn target(&self) -> &FeedTarget {
        &self.target
    }
}

/// Explicit acknowledgement receipt proving commit of a delivered batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerBatchAck {
    /// ID of the acknowledged batch.
    pub batch_id: u64,
    /// Target for the acknowledged batch.
    pub target: FeedTarget,
    /// Sequence range covered by the committed batch.
    pub sequence_range: SequenceRange,
    /// Number of items committed.
    pub item_count: usize,
    /// Timestamp of the last item in the committed batch.
    pub timestamp_ms: i64,
}

// =========================================================================
// Bounded Deterministic Consumer Queue
// =========================================================================

/// Pure deterministic consumer queue enforcing bounds, FIFO ordering, explicit acks,
/// fail-closed backpressure, and sticky resync tracking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerBatchQueue<T> {
    target: FeedTarget,
    config: ConsumerBatchConfig,
    queue: VecDeque<ConsumerBatchItem<T>>,
    stream_tracker: SequencedStreamTracker,
    next_batch_id: u64,
    in_flight_batch: Option<ConsumerBatch<T>>,
    last_acknowledged_batch_id: Option<u64>,
    last_acknowledged_sequence: Option<Sequence>,
    total_enqueued_items: u64,
    total_delivered_items: u64,
    total_acknowledged_items: u64,
}

impl<T: Clone> ConsumerBatchQueue<T> {
    /// Constructs a bounded consumer queue for a target with validated configuration.
    pub fn new(target: FeedTarget, config: ConsumerBatchConfig) -> Result<Self, MarketTypeError> {
        target.validate()?;
        config.validate()?;

        let stream_tracker = SequencedStreamTracker::new(target.clone());

        Ok(Self {
            target,
            config,
            queue: VecDeque::new(),
            stream_tracker,
            next_batch_id: 1,
            in_flight_batch: None,
            last_acknowledged_batch_id: None,
            last_acknowledged_sequence: None,
            total_enqueued_items: 0,
            total_delivered_items: 0,
            total_acknowledged_items: 0,
        })
    }

    /// Returns the target instrument or pool.
    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    /// Returns the active batching configuration.
    pub fn config(&self) -> &ConsumerBatchConfig {
        &self.config
    }

    /// Returns true if consumer resync is latched.
    pub fn is_resync_required(&self) -> bool {
        self.stream_tracker.is_resync_required()
    }

    /// Explicitly triggers sticky resync.
    pub fn trigger_resync(&mut self) {
        self.stream_tracker.trigger_resync();
    }

    /// Returns current contiguous sequence.
    pub fn current_sequence(&self) -> Option<Sequence> {
        self.stream_tracker.current_sequence()
    }

    /// Returns baseline sequence if established.
    pub fn baseline_sequence(&self) -> Option<Sequence> {
        self.stream_tracker.baseline_sequence()
    }

    /// Returns number of items currently waiting in queue (excluding in-flight).
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Returns number of items in the currently in-flight unacknowledged batch.
    pub fn in_flight_len(&self) -> usize {
        self.in_flight_batch.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    /// Returns total allocated buffer usage (queued items + unacknowledged in-flight items).
    pub fn allocated_capacity(&self) -> Result<usize, MarketTypeError> {
        self.queue.len().checked_add(self.in_flight_len()).ok_or(
            MarketTypeError::ArithmeticOverflow("allocated capacity overflow"),
        )
    }

    /// Returns remaining buffer capacity before backpressure overflow.
    pub fn remaining_capacity(&self) -> Result<usize, MarketTypeError> {
        let allocated = self.allocated_capacity()?;
        Ok(self.config.max_queue_capacity.saturating_sub(allocated))
    }

    /// Returns true if an unacknowledged batch is currently in flight.
    pub fn has_in_flight_batch(&self) -> bool {
        self.in_flight_batch.is_some()
    }

    /// Returns a reference to the currently in-flight batch, if any.
    pub fn in_flight_batch(&self) -> Option<&ConsumerBatch<T>> {
        self.in_flight_batch.as_ref()
    }

    /// Returns ID of the last acknowledged batch, if any.
    pub fn last_acknowledged_batch_id(&self) -> Option<u64> {
        self.last_acknowledged_batch_id
    }

    /// Returns sequence cursor of the last acknowledged item, if any.
    pub fn last_acknowledged_sequence(&self) -> Option<Sequence> {
        self.last_acknowledged_sequence
    }

    /// Total items enqueued since creation.
    pub fn total_enqueued_items(&self) -> u64 {
        self.total_enqueued_items
    }

    /// Total items delivered in batches since creation.
    pub fn total_delivered_items(&self) -> u64 {
        self.total_delivered_items
    }

    /// Total items explicitly acknowledged since creation.
    pub fn total_acknowledged_items(&self) -> u64 {
        self.total_acknowledged_items
    }

    /// Enqueues a baseline snapshot item into the queue.
    ///
    /// Clears sticky resync if accepted and establishes the new baseline.
    /// Fail-closed: on target mismatch, invalid envelope, or capacity overflow,
    /// existing queue and sequence state remain unchanged.
    pub fn enqueue_snapshot(
        &mut self,
        item: ConsumerBatchItem<T>,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        item.validate()?;
        if item.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        let allocated = self.allocated_capacity()?;
        if allocated >= self.config.max_queue_capacity {
            return Err(MarketTypeError::ConsumerQueueCapacityExceeded {
                count: allocated
                    .checked_add(1)
                    .ok_or(MarketTypeError::ArithmeticOverflow(
                        "overflow incrementing count",
                    ))?,
                max: self.config.max_queue_capacity,
            });
        }

        let mut staged_tracker = self.stream_tracker.clone();
        let classification =
            staged_tracker.apply_snapshot_sequence(item.sequence_range.end, item.timestamp_ms);

        match classification {
            SnapshotClassification::Accepted { .. } => {
                self.stream_tracker = staged_tracker;
                self.queue.push_back(item);
                self.total_enqueued_items = self.total_enqueued_items.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
                )?;
                Ok(classification)
            }
            SnapshotClassification::Duplicate { .. } | SnapshotClassification::Stale { .. } => {
                // Stale or duplicate snapshots do not mutate queue or tracker.
                Ok(classification)
            }
        }
    }

    /// Enqueues an incremental item into the queue.
    ///
    /// Propagates `Contiguous`, `Stale`, `Duplicate`, and `ResyncRequired` classifications.
    /// A sequence gap, overlap, or upstream resync latches consumer resync, does not enqueue
    /// the item, and leaves queue and sequence state intact.
    /// Overflow fails closed without mutating state or dropping items.
    pub fn enqueue_item(
        &mut self,
        item: ConsumerBatchItem<T>,
    ) -> Result<DeltaClassification, MarketTypeError> {
        item.validate()?;
        if item.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        // If resync is already latched, fail closed to normal enqueue
        if self.stream_tracker.is_resync_required() {
            let expected = self
                .stream_tracker
                .current_sequence()
                .map(|s| s.next())
                .unwrap_or(Sequence(1));
            return Ok(DeltaClassification::ResyncRequired {
                expected,
                received: item.sequence_range.start,
            });
        }

        // Classify delta range against stream tracker first
        let classification = self
            .stream_tracker
            .classify_delta_range(item.sequence_range);

        match classification {
            DeltaClassification::Contiguous { .. } => {
                // Check buffer capacity against combined queued + in-flight count
                let allocated = self.allocated_capacity()?;
                if allocated >= self.config.max_queue_capacity {
                    return Err(MarketTypeError::ConsumerQueueCapacityExceeded {
                        count: allocated.checked_add(1).ok_or(
                            MarketTypeError::ArithmeticOverflow("overflow incrementing count"),
                        )?,
                        max: self.config.max_queue_capacity,
                    });
                }

                // Advance tracker and enqueue item
                self.stream_tracker
                    .apply_delta_range(item.sequence_range, item.timestamp_ms);
                self.queue.push_back(item);
                self.total_enqueued_items = self.total_enqueued_items.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
                )?;
                Ok(classification)
            }
            DeltaClassification::ResyncRequired { expected, received } => {
                // Latch resync fail-closed: queue and cursor remain strictly unchanged
                self.stream_tracker.trigger_resync();
                Ok(DeltaClassification::ResyncRequired { expected, received })
            }
            DeltaClassification::Duplicate { .. } | DeltaClassification::Stale { .. } => {
                // Stale/duplicate items are rejected without mutating queue or cursor
                Ok(classification)
            }
        }
    }

    /// Enqueues multiple items atomically.
    ///
    /// All items must be valid and fit within remaining queue capacity.
    /// If any item overflows or fails, all items are rejected and pre-call state is preserved.
    pub fn enqueue_batch(
        &mut self,
        items: Vec<ConsumerBatchItem<T>>,
    ) -> Result<Vec<DeltaClassification>, MarketTypeError> {
        let mut staged_queue = self.clone();
        let mut classifications = Vec::with_capacity(items.len());

        for item in items {
            let class = staged_queue.enqueue_item(item)?;
            classifications.push(class);
            if matches!(class, DeltaClassification::ResyncRequired { .. }) {
                // If a gap/overlap occurred, latch was set on staged; break early
                break;
            }
        }

        *self = staged_queue;
        Ok(classifications)
    }

    /// Pulls the next deterministic batch from the head of the queue.
    ///
    /// Semantics:
    /// - Fails closed if resync is latched (`ResyncRequired`).
    /// - Fails closed if an unacknowledged batch is already in flight (`UnacknowledgedBatchPending`),
    ///   strictly preventing out-of-order delivery or duplicate delivery.
    /// - If the queue is empty, returns `Ok(None)`.
    /// - Dequeues up to `max_batch_size` items in strict FIFO order.
    /// - Retains in-flight batch until explicitly acknowledged.
    pub fn pull_batch(&mut self) -> Result<Option<ConsumerBatch<T>>, MarketTypeError> {
        if self.is_resync_required() {
            return Err(MarketTypeError::ResyncRequired {
                reason: "consumer queue latched in resync mode; recovery snapshot required",
            });
        }

        if let Some(ref in_flight) = self.in_flight_batch {
            return Err(MarketTypeError::UnacknowledgedBatchPending {
                batch_id: in_flight.batch_id,
            });
        }

        if self.queue.is_empty() {
            return Ok(None);
        }

        let batch_size = std::cmp::min(self.queue.len(), self.config.max_batch_size);
        let items: Vec<ConsumerBatchItem<T>> = self.queue.drain(0..batch_size).collect();

        let start_seq = items
            .first()
            .expect("batch cannot be empty")
            .sequence_range
            .start;
        let end_seq = items
            .last()
            .expect("batch cannot be empty")
            .sequence_range
            .end;
        let sequence_range = SequenceRange::new(start_seq, end_seq)?;

        let batch_id = self.next_batch_id;
        self.next_batch_id = self
            .next_batch_id
            .checked_add(1)
            .ok_or(MarketTypeError::ArithmeticOverflow("batch_id overflow"))?;

        let batch = ConsumerBatch {
            batch_id,
            target: self.target.clone(),
            sequence_range,
            items,
        };

        self.in_flight_batch = Some(batch.clone());
        self.total_delivered_items = self
            .total_delivered_items
            .checked_add(batch_size as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_delivered_items overflow",
            ))?;

        Ok(Some(batch))
    }

    /// Explicitly acknowledges a delivered in-flight batch by batch ID.
    ///
    /// Semantics:
    /// - Fails closed if no batch is in flight (`NoPendingBatchToAcknowledge`).
    /// - Fails closed if `batch_id` does not match the in-flight batch
    ///   (`InvalidBatchAcknowledgement`), preserving the in-flight batch.
    /// - Upon match, commits the batch, clears in-flight retention, advances the acknowledged
    ///   cursor, and returns `ConsumerBatchAck`.
    pub fn acknowledge(&mut self, batch_id: u64) -> Result<ConsumerBatchAck, MarketTypeError> {
        let Some(in_flight) = self.in_flight_batch.take() else {
            return Err(MarketTypeError::NoPendingBatchToAcknowledge);
        };

        if in_flight.batch_id != batch_id {
            // Restore in-flight batch on ID mismatch
            self.in_flight_batch = Some(in_flight);
            return Err(MarketTypeError::InvalidBatchAcknowledgement {
                expected: self
                    .in_flight_batch
                    .as_ref()
                    .map(|b| b.batch_id)
                    .unwrap_or(0),
                received: batch_id,
            });
        }

        self.last_acknowledged_batch_id = Some(batch_id);
        self.last_acknowledged_sequence = Some(in_flight.sequence_range.end);
        self.total_acknowledged_items = self
            .total_acknowledged_items
            .checked_add(in_flight.items.len() as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow",
            ))?;

        let ack = ConsumerBatchAck {
            batch_id,
            target: self.target.clone(),
            sequence_range: in_flight.sequence_range,
            item_count: in_flight.items.len(),
            timestamp_ms: in_flight.items.last().map(|i| i.timestamp_ms).unwrap_or(0),
        };

        Ok(ack)
    }

    /// Atomic pull and acknowledgement in a single deterministic step.
    ///
    /// Fails closed if an unacknowledged batch is already in flight or if resync is latched.
    pub fn consume_batch(&mut self) -> Result<Option<ConsumerBatch<T>>, MarketTypeError> {
        let batch = self.pull_batch()?;
        if let Some(ref b) = batch {
            self.acknowledge(b.batch_id)?;
        }
        Ok(batch)
    }

    /// Resets queue baseline and clears sticky resync with explicit sequence and optional baseline item.
    pub fn reset_with_baseline(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        baseline_item: Option<ConsumerBatchItem<T>>,
    ) -> Result<(), MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }

        if let Some(ref item) = baseline_item {
            item.validate()?;
            if item.target != self.target {
                return Err(MarketTypeError::TargetMismatch);
            }
        }

        let mut staged_tracker = SequencedStreamTracker::new(self.target.clone());
        let _ = staged_tracker.apply_snapshot_sequence(sequence, timestamp_ms);

        self.stream_tracker = staged_tracker;
        self.queue.clear();
        self.in_flight_batch = None;
        self.last_acknowledged_sequence = Some(sequence);

        if let Some(item) = baseline_item {
            self.queue.push_back(item);
            self.total_enqueued_items = self.total_enqueued_items.checked_add(1).ok_or(
                MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
            )?;
        }

        Ok(())
    }
}

impl ConsumerBatchQueue<AggregationOutput> {
    /// Explicitly resets consumer queue with a validated fresh snapshot, clearing sticky resync.
    ///
    /// The fresh snapshot is placed at the front of the queue as the new baseline item.
    pub fn reset_with_snapshot(&mut self, snapshot: &DepthSnapshot) -> Result<(), MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        if let Some(curr) = self.stream_tracker.current_sequence() {
            if snapshot.sequence < curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: snapshot.sequence.0,
                    current: curr.0,
                });
            }
            if snapshot.sequence == curr {
                return Err(MarketTypeError::DuplicateSequence(snapshot.sequence.0));
            }
        }

        let item = ConsumerBatchItem::from_depth_snapshot(snapshot.clone())?;
        self.reset_with_baseline(snapshot.sequence, snapshot.timestamp_ms, Some(item))
    }

    /// Explicitly resets consumer queue with a validated aggregated depth snapshot, clearing sticky resync.
    pub fn reset_with_aggregated_snapshot(
        &mut self,
        snapshot: &AggregatedDepthSnapshot,
    ) -> Result<(), MarketTypeError> {
        self_validate_aggregated_snapshot(snapshot)?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        if let Some(curr) = self.stream_tracker.current_sequence() {
            if snapshot.sequence < curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: snapshot.sequence.0,
                    current: curr.0,
                });
            }
            if snapshot.sequence == curr {
                return Err(MarketTypeError::DuplicateSequence(snapshot.sequence.0));
            }
        }

        let item = ConsumerBatchItem::from_aggregated_snapshot(snapshot.clone())?;
        self.reset_with_baseline(snapshot.sequence, snapshot.timestamp_ms, Some(item))
    }
}

// =========================================================================
// Coordinated Market Consumer Batcher
// =========================================================================

/// Coordinated aggregator and consumer batching engine over canonical market feeds.
///
/// Encapsulates atomic staged mutations across `MarketAggregator` and `ConsumerBatchQueue`,
/// ensuring synchronized sticky resync and fail-closed backpressure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MarketConsumerBatcher {
    aggregator: MarketAggregator,
    queue: ConsumerBatchQueue<AggregationOutput>,
}

impl MarketConsumerBatcher {
    /// Constructs a coordinated market consumer batcher for an aggregator with validated config.
    pub fn new(
        aggregator: MarketAggregator,
        config: ConsumerBatchConfig,
    ) -> Result<Self, MarketTypeError> {
        let queue = ConsumerBatchQueue::new(aggregator.target().clone(), config)?;
        Ok(Self { aggregator, queue })
    }

    /// Returns the target instrument or pool.
    pub fn target(&self) -> &FeedTarget {
        self.aggregator.target()
    }

    /// Returns reference to internal aggregator.
    pub fn aggregator(&self) -> &MarketAggregator {
        &self.aggregator
    }

    /// Returns mutable reference to internal aggregator.
    pub fn aggregator_mut(&mut self) -> &mut MarketAggregator {
        &mut self.aggregator
    }

    /// Returns reference to internal consumer queue.
    pub fn queue(&self) -> &ConsumerBatchQueue<AggregationOutput> {
        &self.queue
    }

    /// Returns mutable reference to internal consumer queue.
    pub fn queue_mut(&mut self) -> &mut ConsumerBatchQueue<AggregationOutput> {
        &mut self.queue
    }

    /// Returns true if either aggregator or consumer queue requires resync.
    pub fn is_resync_required(&self) -> bool {
        self.aggregator.is_resync_required() || self.queue.is_resync_required()
    }

    /// Explicitly triggers sticky resync across both aggregator and consumer queue.
    pub fn trigger_resync(&mut self) {
        self.aggregator.trigger_resync();
        self.queue.trigger_resync();
    }

    /// Applies a canonical feed envelope through aggregation and enqueues the output.
    ///
    /// Atomic & Fail-Closed:
    /// - If resync is latched, returns `ResyncRequired` without mutating aggregator or queue.
    /// - If consumer queue capacity would overflow, returns `ConsumerQueueCapacityExceeded`
    ///   without mutating aggregator or queue.
    /// - Aggregation classification (`Contiguous`, `Stale`, `Duplicate`, `ResyncRequired`)
    ///   is explicitly propagated.
    /// - Any sequence gap or overlap latches sticky resync in both components.
    pub fn apply_envelope(
        &mut self,
        envelope: &CanonicalFeedEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.is_resync_required() {
            let expected = self
                .aggregator
                .depth()
                .sequence()
                .map(|s| s.next())
                .unwrap_or(Sequence(1));
            let received = match &envelope.payload {
                CanonicalFeedPayload::OrderBookDelta(d) => d.sequence_range.start,
                CanonicalFeedPayload::OrderBookSnapshot(s) => s.sequence,
                CanonicalFeedPayload::Candle(_) => envelope.freshness.sequence,
                CanonicalFeedPayload::PoolState(_) => {
                    return Err(MarketTypeError::UnsupportedPayloadForTarget("pool state"));
                }
            };
            return Ok(DeltaClassification::ResyncRequired { expected, received });
        }

        // Fail-closed backpressure check before staging mutations
        let allocated = self.queue.allocated_capacity()?;
        if allocated >= self.queue.config().max_queue_capacity {
            return Err(MarketTypeError::ConsumerQueueCapacityExceeded {
                count: allocated
                    .checked_add(1)
                    .ok_or(MarketTypeError::ArithmeticOverflow(
                        "overflow incrementing count",
                    ))?,
                max: self.queue.config().max_queue_capacity,
            });
        }

        // Stage both components
        let mut staged_agg = self.aggregator.clone();
        let mut staged_queue = self.queue.clone();

        let class = staged_agg.apply_envelope(envelope)?;
        match class {
            DeltaClassification::Contiguous { .. } => match &envelope.payload {
                CanonicalFeedPayload::OrderBookSnapshot(snap) => {
                    let output_item = ConsumerBatchItem::from_depth_snapshot(snap.clone())?;
                    let snap_class = staged_queue.enqueue_snapshot(output_item)?;
                    match snap_class {
                        SnapshotClassification::Accepted { new_sequence } => {
                            self.aggregator = staged_agg;
                            self.queue = staged_queue;
                            Ok(DeltaClassification::Contiguous { new_sequence })
                        }
                        SnapshotClassification::Duplicate { sequence } => {
                            Ok(DeltaClassification::Duplicate { sequence })
                        }
                        SnapshotClassification::Stale { sequence, current } => {
                            Ok(DeltaClassification::Stale { sequence, current })
                        }
                    }
                }
                CanonicalFeedPayload::OrderBookDelta(delta) => {
                    let output_item = ConsumerBatchItem::from_depth_delta(delta.clone())?;
                    let q_class = staged_queue.enqueue_item(output_item)?;
                    if matches!(q_class, DeltaClassification::ResyncRequired { .. }) {
                        self.trigger_resync();
                        return Ok(q_class);
                    }
                    self.aggregator = staged_agg;
                    self.queue = staged_queue;
                    Ok(class)
                }
                CanonicalFeedPayload::Candle(candle) => {
                    let output_item = ConsumerBatchItem::from_candle(
                        self.target().clone(),
                        envelope.freshness.sequence,
                        candle.clone(),
                    )?;
                    let q_class = staged_queue.enqueue_item(output_item)?;
                    if matches!(q_class, DeltaClassification::ResyncRequired { .. }) {
                        self.trigger_resync();
                        return Ok(q_class);
                    }
                    self.aggregator = staged_agg;
                    self.queue = staged_queue;
                    Ok(class)
                }
                CanonicalFeedPayload::PoolState(_) => {
                    Err(MarketTypeError::UnsupportedPayloadForTarget("pool state"))
                }
            },
            DeltaClassification::ResyncRequired { expected, received } => {
                // Aggregator gap/overlap: latch both
                self.trigger_resync();
                Ok(DeltaClassification::ResyncRequired { expected, received })
            }
            DeltaClassification::Stale { .. } | DeltaClassification::Duplicate { .. } => {
                // No state change
                Ok(class)
            }
        }
    }

    /// Resets both aggregator and consumer queue with a validated fresh snapshot, clearing sticky resync.
    pub fn reset_with_snapshot(&mut self, snapshot: &DepthSnapshot) -> Result<(), MarketTypeError> {
        let mut staged_agg = self.aggregator.clone();
        let mut staged_queue = self.queue.clone();

        staged_agg.reset_with_snapshot(snapshot)?;
        staged_queue.reset_with_snapshot(snapshot)?;

        self.aggregator = staged_agg;
        self.queue = staged_queue;
        Ok(())
    }

    /// Pulls the next deterministic batch from the consumer queue.
    pub fn pull_batch(
        &mut self,
    ) -> Result<Option<ConsumerBatch<AggregationOutput>>, MarketTypeError> {
        self.queue.pull_batch()
    }

    /// Explicitly acknowledges a delivered batch by ID.
    pub fn acknowledge(&mut self, batch_id: u64) -> Result<ConsumerBatchAck, MarketTypeError> {
        self.queue.acknowledge(batch_id)
    }

    /// Atomic pull and acknowledge.
    pub fn consume_batch(
        &mut self,
    ) -> Result<Option<ConsumerBatch<AggregationOutput>>, MarketTypeError> {
        self.queue.consume_batch()
    }
}
