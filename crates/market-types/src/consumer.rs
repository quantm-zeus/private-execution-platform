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
                let next_total_enqueued = self.total_enqueued_items.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
                )?;
                self.stream_tracker = staged_tracker;
                self.queue.push_back(item);
                self.total_enqueued_items = next_total_enqueued;
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

                let next_total_enqueued = self.total_enqueued_items.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
                )?;

                let mut staged_tracker = self.stream_tracker.clone();
                staged_tracker.apply_delta_range(item.sequence_range, item.timestamp_ms);

                self.stream_tracker = staged_tracker;
                self.queue.push_back(item);
                self.total_enqueued_items = next_total_enqueued;
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
    /// If an item triggers sticky resync, sticky resync is latched fail-closed but queue items,
    /// tracker cursor, and counters from the batch are not committed.
    pub fn enqueue_batch(
        &mut self,
        items: Vec<ConsumerBatchItem<T>>,
    ) -> Result<Vec<DeltaClassification>, MarketTypeError> {
        let mut staged_queue = self.clone();
        let mut classifications = Vec::with_capacity(items.len());
        let mut resync_encountered = false;

        for item in items {
            let class = staged_queue.enqueue_item(item)?;
            classifications.push(class);
            if matches!(class, DeltaClassification::ResyncRequired { .. }) {
                // If a gap/overlap occurred, break early without committing partial items
                resync_encountered = true;
                break;
            }
        }

        if resync_encountered {
            self.trigger_resync();
            return Ok(classifications);
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

        // Preflight arithmetic and sequence range before draining queue or modifying any state
        let next_batch_id = self
            .next_batch_id
            .checked_add(1)
            .ok_or(MarketTypeError::ArithmeticOverflow("batch_id overflow"))?;

        let next_delivered = self
            .total_delivered_items
            .checked_add(batch_size as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_delivered_items overflow",
            ))?;

        let start_seq = self
            .queue
            .front()
            .expect("batch cannot be empty")
            .sequence_range
            .start;
        let end_seq = self
            .queue
            .get(batch_size - 1)
            .expect("batch_size <= queue.len()")
            .sequence_range
            .end;
        let sequence_range = SequenceRange::new(start_seq, end_seq)?;

        // All fallible checks succeeded; execute atomic state transition
        let batch_id = self.next_batch_id;
        let items: Vec<ConsumerBatchItem<T>> = self.queue.drain(0..batch_size).collect();

        let batch = ConsumerBatch {
            batch_id,
            target: self.target.clone(),
            sequence_range,
            items,
        };

        self.next_batch_id = next_batch_id;
        self.in_flight_batch = Some(batch.clone());
        self.total_delivered_items = next_delivered;

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
        let Some(in_flight) = self.in_flight_batch.as_ref() else {
            return Err(MarketTypeError::NoPendingBatchToAcknowledge);
        };

        if in_flight.batch_id != batch_id {
            return Err(MarketTypeError::InvalidBatchAcknowledgement {
                expected: in_flight.batch_id,
                received: batch_id,
            });
        }

        let next_acknowledged = self
            .total_acknowledged_items
            .checked_add(in_flight.items.len() as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow",
            ))?;

        let in_flight = self
            .in_flight_batch
            .take()
            .expect("in_flight_batch verified is_some");

        self.last_acknowledged_batch_id = Some(batch_id);
        self.last_acknowledged_sequence = Some(in_flight.sequence_range.end);
        self.total_acknowledged_items = next_acknowledged;

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
    /// Transactional: preflights all fallible batch-id, delivered, and acknowledged counter
    /// arithmetic as well as sequence range validation before modifying any state.
    /// If any error occurs, all queue, stream tracker, in-flight, batch ID, acknowledgement,
    /// and counter state remains exactly identical to the pre-call state.
    pub fn consume_batch(&mut self) -> Result<Option<ConsumerBatch<T>>, MarketTypeError> {
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

        // Preflight all fallible arithmetic and sequence range checks before modifying any state
        let next_batch_id = self
            .next_batch_id
            .checked_add(1)
            .ok_or(MarketTypeError::ArithmeticOverflow("batch_id overflow"))?;

        let next_delivered = self
            .total_delivered_items
            .checked_add(batch_size as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_delivered_items overflow",
            ))?;

        let next_acknowledged = self
            .total_acknowledged_items
            .checked_add(batch_size as u64)
            .ok_or(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow",
            ))?;

        let start_seq = self
            .queue
            .front()
            .expect("batch cannot be empty")
            .sequence_range
            .start;
        let end_seq = self
            .queue
            .get(batch_size - 1)
            .expect("batch_size <= queue.len()")
            .sequence_range
            .end;
        let sequence_range = SequenceRange::new(start_seq, end_seq)?;

        // All checks succeeded; commit state once
        let batch_id = self.next_batch_id;
        let items: Vec<ConsumerBatchItem<T>> = self.queue.drain(0..batch_size).collect();

        let batch = ConsumerBatch {
            batch_id,
            target: self.target.clone(),
            sequence_range,
            items,
        };

        self.next_batch_id = next_batch_id;
        self.total_delivered_items = next_delivered;
        self.total_acknowledged_items = next_acknowledged;
        self.last_acknowledged_batch_id = Some(batch_id);
        self.last_acknowledged_sequence = Some(sequence_range.end);
        self.in_flight_batch = None;

        Ok(Some(batch))
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

        let next_total_enqueued =
            if let Some(ref item) = baseline_item {
                item.validate()?;
                if item.target != self.target {
                    return Err(MarketTypeError::TargetMismatch);
                }
                self.total_enqueued_items.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("total_enqueued_items overflow"),
                )?
            } else {
                self.total_enqueued_items
            };

        let mut staged_tracker = SequencedStreamTracker::new(self.target.clone());
        let _ = staged_tracker.apply_snapshot_sequence(sequence, timestamp_ms);

        self.stream_tracker = staged_tracker;
        self.queue.clear();
        self.in_flight_batch = None;
        self.last_acknowledged_sequence = Some(sequence);
        self.total_enqueued_items = next_total_enqueued;

        if let Some(item) = baseline_item {
            self.queue.push_back(item);
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

    /// Returns reference to internal consumer queue.
    pub fn queue(&self) -> &ConsumerBatchQueue<AggregationOutput> {
        &self.queue
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandleTimeframe, CanonicalFeedEnvelope, CanonicalFeedPayload, ChainFamily, DepthDelta,
        DepthLevel, DepthSnapshot, FeedFinality, FeedObservationContext, FeedSourceLabel,
        FreshnessStatus, InstrumentId, MarketAggregator, NormalizedPrice, NormalizedQuantity,
        SafeFreshnessMeta, SequenceRange,
    };
    use chain_types::{AssetId, ChainId};

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

    fn sample_target() -> FeedTarget {
        FeedTarget::Instrument(sample_instrument())
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

    #[test]
    fn test_regression_enqueue_snapshot_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        queue.total_enqueued_items = u64::MAX;
        let initial_state = queue.clone();

        let snap = sample_snapshot(1, 1_000);
        let item = ConsumerBatchItem::from_depth_snapshot(snap).unwrap();

        let res = queue.enqueue_snapshot(item);
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_enqueued_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 0);
        assert_eq!(queue.current_sequence(), None);
        assert_eq!(queue.baseline_sequence(), None);
        assert_eq!(queue.in_flight_len(), 0);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.last_acknowledged_batch_id(), None);
        assert_eq!(queue.last_acknowledged_sequence(), None);
        assert_eq!(queue.total_enqueued_items(), u64::MAX);
        assert_eq!(queue.total_delivered_items(), 0);
        assert_eq!(queue.total_acknowledged_items(), 0);
        assert!(!queue.is_resync_required());
    }

    #[test]
    fn test_regression_enqueue_item_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        assert_eq!(queue.queue_len(), 1);
        assert_eq!(queue.current_sequence(), Some(Sequence(1)));

        queue.total_enqueued_items = u64::MAX;
        let initial_state = queue.clone();

        let delta = sample_delta(2, 2, 1_010);
        let delta_item = ConsumerBatchItem::from_depth_delta(delta).unwrap();

        let res = queue.enqueue_item(delta_item);
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_enqueued_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 1);
        assert_eq!(queue.current_sequence(), Some(Sequence(1)));
        assert_eq!(queue.baseline_sequence(), Some(Sequence(1)));
        assert_eq!(queue.in_flight_len(), 0);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.total_enqueued_items(), u64::MAX);
        assert_eq!(queue.total_delivered_items(), 0);
        assert_eq!(queue.total_acknowledged_items(), 0);
        assert!(!queue.is_resync_required());
    }

    #[test]
    fn test_regression_reset_with_baseline_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        let delta = sample_delta(2, 2, 1_010);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();

        let b1 = queue.pull_batch().unwrap().unwrap();
        assert_eq!(b1.batch_id(), 1);
        assert!(queue.has_in_flight_batch());
        assert_eq!(queue.queue_len(), 0);
        assert_eq!(queue.in_flight_len(), 2);

        queue.total_enqueued_items = u64::MAX;
        let initial_state = queue.clone();

        let recov_snap = sample_snapshot(5, 5_000);
        let recov_item = ConsumerBatchItem::from_depth_snapshot(recov_snap).unwrap();

        let res = queue.reset_with_baseline(Sequence(5), 5_000, Some(recov_item));
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_enqueued_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert!(queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_batch().unwrap().batch_id(), 1);
        assert_eq!(queue.in_flight_len(), 2);
        assert_eq!(queue.queue_len(), 0);
        assert_eq!(queue.current_sequence(), Some(Sequence(2)));
        assert_eq!(queue.total_enqueued_items(), u64::MAX);
    }

    #[test]
    fn test_regression_pull_batch_batch_id_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        let delta = sample_delta(2, 2, 1_010);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();

        queue.next_batch_id = u64::MAX;
        let initial_state = queue.clone();

        let res = queue.pull_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow("batch_id overflow"))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 2);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(queue.total_delivered_items(), 0);
        assert_eq!(queue.current_sequence(), Some(Sequence(2)));
        assert_eq!(queue.last_acknowledged_batch_id(), None);
    }

    #[test]
    fn test_regression_pull_batch_delivery_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        let delta = sample_delta(2, 2, 1_010);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();

        queue.total_delivered_items = u64::MAX;
        let initial_state = queue.clone();

        let res = queue.pull_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_delivered_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 2);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(queue.total_delivered_items(), u64::MAX);
        assert_eq!(queue.current_sequence(), Some(Sequence(2)));
        assert_eq!(queue.last_acknowledged_batch_id(), None);
    }

    #[test]
    fn test_regression_acknowledge_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        let delta = sample_delta(2, 2, 1_010);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta).unwrap())
            .unwrap();

        let b1 = queue.pull_batch().unwrap().unwrap();
        assert_eq!(b1.batch_id(), 1);
        assert!(queue.has_in_flight_batch());

        queue.total_acknowledged_items = u64::MAX;
        let initial_state = queue.clone();

        let res = queue.acknowledge(1);
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert!(queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_batch().unwrap().batch_id(), 1);
        assert_eq!(queue.last_acknowledged_batch_id(), None);
        assert_eq!(queue.last_acknowledged_sequence(), None);
        assert_eq!(queue.total_acknowledged_items(), u64::MAX);
    }

    #[test]
    fn test_regression_consume_batch_acknowledged_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();
        let delta2 = sample_delta(2, 2, 1_010);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta2).unwrap())
            .unwrap();
        let delta3 = sample_delta(3, 3, 1_020);
        queue
            .enqueue_item(ConsumerBatchItem::from_depth_delta(delta3).unwrap())
            .unwrap();

        assert_eq!(queue.queue_len(), 3);
        assert_eq!(queue.current_sequence(), Some(Sequence(3)));
        assert_eq!(queue.total_enqueued_items(), 3);
        assert_eq!(queue.total_delivered_items(), 0);
        assert_eq!(queue.total_acknowledged_items(), 0);
        assert_eq!(queue.next_batch_id, 1);
        assert!(!queue.has_in_flight_batch());

        // Force total_acknowledged_items to u64::MAX
        queue.total_acknowledged_items = u64::MAX;
        let initial_state = queue.clone();

        // Attempt consume_batch: MUST fail on total_acknowledged_items overflow
        let res = queue.consume_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow"
            ))
        );

        // Transactional guarantee: queue, tracker/cursor, in-flight, next batch id,
        // acknowledgement fields, and all counters must exactly equal the pre-call state.
        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 3);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(queue.next_batch_id, 1);
        assert_eq!(queue.last_acknowledged_batch_id(), None);
        assert_eq!(queue.last_acknowledged_sequence(), None);
        assert_eq!(queue.total_enqueued_items(), 3);
        assert_eq!(queue.total_delivered_items(), 0);
        assert_eq!(queue.total_acknowledged_items(), u64::MAX);
        assert_eq!(queue.current_sequence(), Some(Sequence(3)));
        assert!(!queue.is_resync_required());

        // Restore acknowledged counter to 0 to verify normal FIFO and successful consumption
        queue.total_acknowledged_items = 0;

        // Batch 1: consumes 2 items (seq 1, seq 2)
        let batch1 = queue.consume_batch().unwrap().expect("batch 1 exists");
        assert_eq!(batch1.batch_id(), 1);
        assert_eq!(batch1.len(), 2);
        assert_eq!(
            batch1.sequence_range(),
            SequenceRange::new(Sequence(1), Sequence(2)).unwrap()
        );
        assert_eq!(
            batch1.items[0].sequence_range,
            SequenceRange::point(Sequence(1)).unwrap()
        );
        assert_eq!(
            batch1.items[1].sequence_range,
            SequenceRange::point(Sequence(2)).unwrap()
        );

        assert_eq!(queue.queue_len(), 1);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(queue.next_batch_id, 2);
        assert_eq!(queue.last_acknowledged_batch_id(), Some(1));
        assert_eq!(queue.last_acknowledged_sequence(), Some(Sequence(2)));
        assert_eq!(queue.total_delivered_items(), 2);
        assert_eq!(queue.total_acknowledged_items(), 2);

        // Batch 2: consumes remaining 1 item (seq 3)
        let batch2 = queue.consume_batch().unwrap().expect("batch 2 exists");
        assert_eq!(batch2.batch_id(), 2);
        assert_eq!(batch2.len(), 1);
        assert_eq!(
            batch2.sequence_range(),
            SequenceRange::point(Sequence(3)).unwrap()
        );
        assert_eq!(
            batch2.items[0].sequence_range,
            SequenceRange::point(Sequence(3)).unwrap()
        );

        assert_eq!(queue.queue_len(), 0);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(queue.next_batch_id, 3);
        assert_eq!(queue.last_acknowledged_batch_id(), Some(2));
        assert_eq!(queue.last_acknowledged_sequence(), Some(Sequence(3)));
        assert_eq!(queue.total_delivered_items(), 3);
        assert_eq!(queue.total_acknowledged_items(), 3);

        // Batch 3: queue is empty, returns Ok(None)
        let batch3 = queue.consume_batch().unwrap();
        assert_eq!(batch3, None);
    }

    #[test]
    fn test_regression_consume_batch_delivery_counter_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();

        queue.total_delivered_items = u64::MAX;
        let initial_state = queue.clone();

        let res = queue.consume_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_delivered_items overflow"
            ))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 1);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.total_delivered_items(), u64::MAX);
    }

    #[test]
    fn test_regression_consume_batch_batch_id_overflow_preserves_state() {
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut queue = ConsumerBatchQueue::new(sample_target(), config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        queue
            .enqueue_snapshot(ConsumerBatchItem::from_depth_snapshot(snap).unwrap())
            .unwrap();

        queue.next_batch_id = u64::MAX;
        let initial_state = queue.clone();

        let res = queue.consume_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow("batch_id overflow"))
        );

        assert_eq!(queue, initial_state);
        assert_eq!(queue.queue_len(), 1);
        assert!(!queue.has_in_flight_batch());
        assert_eq!(queue.next_batch_id, u64::MAX);
    }

    #[test]
    fn test_regression_market_consumer_batcher_consume_batch_overflow_preserves_state() {
        let instrument = sample_instrument();
        let aggregator =
            MarketAggregator::for_instrument(instrument.clone(), CandleTimeframe::M1, 100, 100)
                .unwrap();
        let config = ConsumerBatchConfig::new(10, 2).unwrap();
        let mut batcher = MarketConsumerBatcher::new(aggregator, config).unwrap();

        let snap = sample_snapshot(1, 1_000);
        batcher.reset_with_snapshot(&snap).unwrap();

        let delta_env = make_envelope(
            CanonicalFeedPayload::OrderBookDelta(sample_delta(2, 2, 1_010)),
            2,
            1_010,
        );
        batcher.apply_envelope(&delta_env).unwrap();

        batcher.queue.total_acknowledged_items = u64::MAX;
        let initial_state = batcher.clone();

        let res = batcher.consume_batch();
        assert_eq!(
            res,
            Err(MarketTypeError::ArithmeticOverflow(
                "total_acknowledged_items overflow"
            ))
        );

        assert_eq!(batcher, initial_state);
        assert_eq!(batcher.queue().queue_len(), 2);
        assert!(!batcher.queue().has_in_flight_batch());
        assert_eq!(batcher.queue().total_acknowledged_items(), u64::MAX);
    }
}
