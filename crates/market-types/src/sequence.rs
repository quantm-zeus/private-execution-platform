//! Sequenced market snapshots, deltas, and stream synchronization contracts.

use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::identity::FeedTarget;
use crate::primitives::Sequence;

/// Bounded contiguous range of sequence numbers for an incremental delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SequenceRange {
    pub start: Sequence,
    pub end: Sequence,
}

impl SequenceRange {
    pub fn new(start: Sequence, end: Sequence) -> Result<Self, MarketTypeError> {
        if start.0 == 0 || end.0 == 0 {
            return Err(MarketTypeError::ZeroSequence);
        }
        if start.0 > end.0 {
            return Err(MarketTypeError::InvalidSequenceRange {
                start: start.0,
                end: end.0,
            });
        }
        Ok(Self { start, end })
    }

    pub fn point(sequence: Sequence) -> Result<Self, MarketTypeError> {
        Self::new(sequence, sequence)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if self.start.0 == 0 || self.end.0 == 0 {
            return Err(MarketTypeError::ZeroSequence);
        }
        if self.start.0 > self.end.0 {
            return Err(MarketTypeError::InvalidSequenceRange {
                start: self.start.0,
                end: self.end.0,
            });
        }
        Ok(())
    }

    pub const fn len(&self) -> u64 {
        self.end.0 - self.start.0 + 1
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub const fn contains(&self, seq: Sequence) -> bool {
        seq.0 >= self.start.0 && seq.0 <= self.end.0
    }
}

/// Generic envelope for a sequenced baseline snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencedSnapshot<T> {
    pub target: FeedTarget,
    pub sequence: Sequence,
    pub timestamp_ms: i64,
    pub payload: T,
}

impl<T> SequencedSnapshot<T> {
    pub fn new(
        target: FeedTarget,
        sequence: Sequence,
        timestamp_ms: i64,
        payload: T,
    ) -> Result<Self, MarketTypeError> {
        let snap = Self {
            target,
            sequence,
            timestamp_ms,
            payload,
        };
        snap.validate_envelope()?;
        Ok(snap)
    }

    pub fn validate_envelope(&self) -> Result<(), MarketTypeError> {
        self.target.validate()?;
        self.sequence.validate()?;
        if self.timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.timestamp_ms));
        }
        Ok(())
    }
}

/// Generic envelope for a sequenced incremental delta covering a sequence range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencedDelta<T> {
    pub target: FeedTarget,
    pub sequence_range: SequenceRange,
    pub timestamp_ms: i64,
    pub payload: T,
}

impl<T> SequencedDelta<T> {
    pub fn new(
        target: FeedTarget,
        sequence_range: SequenceRange,
        timestamp_ms: i64,
        payload: T,
    ) -> Result<Self, MarketTypeError> {
        let delta = Self {
            target,
            sequence_range,
            timestamp_ms,
            payload,
        };
        delta.validate_envelope()?;
        Ok(delta)
    }

    pub fn validate_envelope(&self) -> Result<(), MarketTypeError> {
        self.target.validate()?;
        self.sequence_range.validate()?;
        if self.timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.timestamp_ms));
        }
        Ok(())
    }
}

/// Classification outcome when evaluating an incoming delta sequence against a stream state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaClassification {
    /// Delta is contiguously next in sequence; advances state sequence to `new_sequence`.
    Contiguous { new_sequence: Sequence },
    /// Delta sequence range is entirely duplicate with current state; state is unchanged.
    Duplicate { sequence: Sequence },
    /// Delta sequence range is older than current state; state is unchanged.
    Stale {
        sequence: Sequence,
        current: Sequence,
    },
    /// A sequence gap or missing baseline was detected; state transitions to fail-closed resync.
    ResyncRequired {
        expected: Sequence,
        received: Sequence,
    },
}

/// Classification outcome when evaluating an incoming snapshot sequence against a stream state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotClassification {
    /// Snapshot advances baseline sequence.
    Accepted { new_sequence: Sequence },
    /// Snapshot sequence matches current sequence exactly.
    Duplicate { sequence: Sequence },
    /// Snapshot sequence is strictly older than current sequence.
    Stale {
        sequence: Sequence,
        current: Sequence,
    },
}

/// Deterministic, fail-closed stream state tracker.
/// Enforces monotonic contiguous sequencing and guards against gap interpolation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencedStreamTracker {
    target: FeedTarget,
    baseline_sequence: Option<Sequence>,
    current_sequence: Option<Sequence>,
    last_timestamp_ms: Option<i64>,
    resync_required: bool,
}

impl SequencedStreamTracker {
    pub fn new(target: FeedTarget) -> Self {
        Self {
            target,
            baseline_sequence: None,
            current_sequence: None,
            last_timestamp_ms: None,
            resync_required: false,
        }
    }

    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    pub fn baseline_sequence(&self) -> Option<Sequence> {
        self.baseline_sequence
    }

    pub fn current_sequence(&self) -> Option<Sequence> {
        self.current_sequence
    }

    pub fn last_timestamp_ms(&self) -> Option<i64> {
        self.last_timestamp_ms
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    /// Classify a delta range against the current stream sequence without mutating state.
    pub fn classify_delta_range(&self, range: SequenceRange) -> DeltaClassification {
        if self.resync_required {
            let expected = self
                .current_sequence
                .map(|s| s.next())
                .unwrap_or(Sequence(1));
            return DeltaClassification::ResyncRequired {
                expected,
                received: range.start,
            };
        }

        let Some(curr) = self.current_sequence else {
            // Cannot apply deltas without a snapshot baseline!
            return DeltaClassification::ResyncRequired {
                expected: Sequence(1),
                received: range.start,
            };
        };

        if range.end < curr {
            DeltaClassification::Stale {
                sequence: range.end,
                current: curr,
            }
        } else if range.end == curr {
            DeltaClassification::Duplicate { sequence: curr }
        } else if range.start == curr.next() {
            DeltaClassification::Contiguous {
                new_sequence: range.end,
            }
        } else {
            // Either range.start > curr.next() (gap), or range.start <= curr < range.end (unaligned overlap).
            // Both are classified fail-closed as ResyncRequired.
            DeltaClassification::ResyncRequired {
                expected: curr.next(),
                received: range.start,
            }
        }
    }

    /// Evaluates and applies a delta range to the tracker.
    /// If a gap is encountered, sets resync_required = true and returns ResyncRequired.
    pub fn apply_delta_range(
        &mut self,
        range: SequenceRange,
        timestamp_ms: i64,
    ) -> DeltaClassification {
        let classification = self.classify_delta_range(range);
        match classification {
            DeltaClassification::Contiguous { new_sequence } => {
                self.current_sequence = Some(new_sequence);
                self.last_timestamp_ms = Some(timestamp_ms);
            }
            DeltaClassification::ResyncRequired { .. } => {
                self.resync_required = true;
            }
            DeltaClassification::Duplicate { .. } | DeltaClassification::Stale { .. } => {
                // Idempotent: state sequence does not regress.
            }
        }
        classification
    }

    /// Applies a snapshot sequence to establish or advance the stream baseline.
    /// A valid newer snapshot clears the resync_required flag.
    pub fn apply_snapshot_sequence(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
    ) -> SnapshotClassification {
        if let Some(curr) = self.current_sequence {
            if sequence < curr {
                return SnapshotClassification::Stale {
                    sequence,
                    current: curr,
                };
            }
            if sequence == curr {
                return SnapshotClassification::Duplicate { sequence: curr };
            }
        }

        self.baseline_sequence = Some(sequence);
        self.current_sequence = Some(sequence);
        self.last_timestamp_ms = Some(timestamp_ms);
        self.resync_required = false;
        SnapshotClassification::Accepted {
            new_sequence: sequence,
        }
    }
}
