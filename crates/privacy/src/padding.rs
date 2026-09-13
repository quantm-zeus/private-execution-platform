//! Deterministic traffic-length padding.
//!
//! Padding hides the exact byte length of a private frame by rounding it up to
//! one of a fixed ladder of sizes. It is deterministic (no randomness, no
//! clock), so the same frame always pads to the same size and tests are stable.

use crate::error::PrivacyError;

/// A padded frame size decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaddedFrame {
    /// The size to actually send (always `>= real_len`).
    pub padded_len: usize,
    /// Bytes of padding added.
    pub padding_len: usize,
    /// Whether a ladder bucket covered the frame.
    ///
    /// When `false`, the frame exceeded the largest bucket and is sent at its
    /// real length rather than being truncated, so the caller can split it.
    pub padded: bool,
}

/// A fixed, validated padding ladder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaddingPolicy {
    ladder: Vec<usize>,
}

impl PaddingPolicy {
    /// Builds a policy from a strictly-ascending ladder of positive sizes.
    pub fn new(ladder: Vec<usize>) -> Result<Self, PrivacyError> {
        if ladder.is_empty() {
            return Err(PrivacyError::EmptyLadder);
        }
        if ladder.contains(&0) {
            return Err(PrivacyError::ZeroBucket);
        }
        if ladder.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PrivacyError::NotAscending);
        }
        Ok(Self { ladder })
    }

    /// The configured ladder.
    pub fn ladder(&self) -> &[usize] {
        &self.ladder
    }

    /// Rounds `real_len` up to the next ladder bucket, or reports that it does
    /// not fit within the largest bucket.
    pub fn pad(&self, real_len: usize) -> PaddedFrame {
        // The first bucket at least as large as the frame; `partition_point`
        // keeps this O(log n) and allocation-free.
        let index = self.ladder.partition_point(|bucket| *bucket < real_len);
        match self.ladder.get(index) {
            Some(bucket) => PaddedFrame {
                padded_len: *bucket,
                padding_len: bucket.saturating_sub(real_len),
                padded: true,
            },
            // No bucket covers the frame: never truncate.
            None => PaddedFrame {
                padded_len: real_len,
                padding_len: 0,
                padded: false,
            },
        }
    }
}
