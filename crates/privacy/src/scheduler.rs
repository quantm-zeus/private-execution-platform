//! Bounded, deterministic artifact-rotation scheduling.
//!
//! [`RotationPolicy`] decides *whether* a single artifact is due. This module
//! turns that predicate into one bounded pass over a caller-supplied set of
//! artifacts: it selects at most `max_per_pass` due artifacts and reports when
//! the caller should look again. It owns no registry, performs no I/O, reads no
//! clock, and uses no randomness — the caller supplies `now_ms` and persists
//! the resulting plan.
//!
//! ## Boundaries
//! - **Pure and deterministic.** The same inputs always yield the same plan;
//!   ordering is by `artifact_id`, so a caller can drive it from any registry
//!   order without flakes.
//! - **Redacted.** Manual [`Debug`] implementations never render ids, key ids,
//!   times, or counts, so a plan can be logged without leaking metadata.

use core::fmt;

use crate::error::PrivacyError;
use crate::rotation::RotationPolicy;

/// One artifact's rotation state, supplied by the caller's registry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ArtifactRotation {
    /// Opaque caller-defined artifact id (never a key/secret).
    pub artifact_id: u64,
    /// Creation time in milliseconds.
    pub created_at_ms: i64,
    /// Number of uses the artifact has served.
    pub uses: u64,
    /// Opaque current key id (never a secret).
    pub key_id: u32,
}

impl fmt::Debug for ArtifactRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted on purpose: no id, key id, timestamp, or use count.
        f.debug_struct("ArtifactRotation").finish_non_exhaustive()
    }
}

/// A bounded deterministic rotation pass.
#[derive(Clone, PartialEq, Eq)]
pub struct RotationPlan {
    /// Artifact ids to rotate now, ascending (bounded by `max_per_pass`).
    pub rotate: Vec<u64>,
    /// Whether further artifacts are due but were deferred by the bound.
    pub deferred: bool,
    /// Earliest time the caller should run the next pass: `Some(now_ms)` when
    /// `deferred`, else the minimum age-based due time (`created_at_ms +
    /// max_age_ms`) over the artifacts that were NOT scheduled, or `None` when
    /// there is nothing left.
    pub next_deadline_ms: Option<i64>,
}

impl fmt::Debug for RotationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted on purpose: no ids, deadline, or counts.
        f.debug_struct("RotationPlan").finish_non_exhaustive()
    }
}

/// Plans one bounded rotation pass.
///
/// An artifact is due when
/// [`RotationPolicy::should_rotate`]`(now_ms - created_at_ms, uses)` holds
/// (with saturating subtraction, so extreme clocks cannot wrap). The due
/// artifacts are sorted ascending by [`ArtifactRotation::artifact_id`] and the
/// first `max_per_pass` are scheduled; the rest are deferred.
///
/// Returns [`PrivacyError::InvalidRotationBounds`] when `max_per_pass == 0`,
/// failing closed rather than scheduling an unbounded pass.
pub fn plan_rotations(
    artifacts: &[ArtifactRotation],
    policy: &RotationPolicy,
    now_ms: i64,
    max_per_pass: usize,
) -> Result<RotationPlan, PrivacyError> {
    if max_per_pass == 0 {
        return Err(PrivacyError::InvalidRotationBounds);
    }

    // Track the *element index* of each due artifact so the deadline can exclude
    // exactly the entries that were scheduled, even when two entries share an
    // `artifact_id` (ids are caller-defined and need not be unique).
    let mut due: Vec<(u64, usize)> = artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| {
            policy.should_rotate(now_ms.saturating_sub(artifact.created_at_ms), artifact.uses)
        })
        .map(|(index, artifact)| (artifact.artifact_id, index))
        .collect();
    // Ascending by id, then by registry index, so the plan is deterministic
    // regardless of the registry order.
    due.sort_unstable();

    let deferred = due.len() > max_per_pass;
    let scheduled = &due[..due.len().min(max_per_pass)];
    let rotate: Vec<u64> = scheduled
        .iter()
        .map(|(artifact_id, _)| *artifact_id)
        .collect();

    let next_deadline_ms = if deferred {
        // More work is already due; the caller should run again immediately.
        Some(now_ms)
    } else {
        // Scheduled entries get a fresh creation time, so only the untouched ones
        // carry the next deadline. The deadline is the exact age bound
        // (`created_at_ms + max_age_ms`), never the nominal `window_ms`: a
        // `window_ms` below the age bound could report a deadline at or before
        // `now_ms` and spin the caller, and one above it could report a deadline
        // after the artifact is already due. A `uses`-based rotation may still
        // become due sooner, so callers re-plan after each use.
        let scheduled_indices: Vec<usize> = scheduled.iter().map(|(_, index)| *index).collect();
        let max_age_ms = policy.config().max_age_ms;
        artifacts
            .iter()
            .enumerate()
            .filter(|(index, _)| !scheduled_indices.contains(index))
            .map(|(_, artifact)| artifact.created_at_ms.saturating_add(max_age_ms))
            .min()
    };

    Ok(RotationPlan {
        rotate,
        deferred,
        next_deadline_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::RotationConfig;

    fn policy() -> RotationPolicy {
        RotationPolicy::new(RotationConfig {
            max_age_ms: 1_000,
            max_uses: 10,
            window_ms: 500,
        })
        .expect("valid policy")
    }

    fn artifact(artifact_id: u64, created_at_ms: i64, uses: u64) -> ArtifactRotation {
        ArtifactRotation {
            artifact_id,
            created_at_ms,
            uses,
            key_id: 1,
        }
    }

    #[test]
    fn empty_set_yields_an_empty_plan() {
        let plan = plan_rotations(&[], &policy(), 10_000, 4).expect("valid bounds");
        assert_eq!(
            plan,
            RotationPlan {
                rotate: Vec::new(),
                deferred: false,
                next_deadline_ms: None,
            }
        );
    }

    #[test]
    fn more_due_than_the_bound_is_deferred() {
        let artifacts = [
            artifact(9, 8_000, 0),
            artifact(2, 8_000, 0),
            artifact(5, 8_000, 0),
        ];
        let plan = plan_rotations(&artifacts, &policy(), 10_000, 2).expect("valid bounds");
        assert_eq!(plan.rotate, vec![2, 5]);
        assert!(plan.deferred);
        assert_eq!(plan.next_deadline_ms, Some(10_000));
    }

    #[test]
    fn age_and_use_bounds_are_inclusive() {
        let p = policy();
        let due_at_age = [artifact(1, 9_000, 0)];
        let not_due_at_age = [artifact(1, 9_001, 0)];
        let due_at_uses = [artifact(1, 10_000, 10)];
        let not_due_at_uses = [artifact(1, 10_000, 9)];

        assert_eq!(
            plan_rotations(&due_at_age, &p, 10_000, 1)
                .expect("valid bounds")
                .rotate,
            vec![1]
        );
        assert!(plan_rotations(&not_due_at_age, &p, 10_000, 1)
            .expect("valid bounds")
            .rotate
            .is_empty());
        assert_eq!(
            plan_rotations(&due_at_uses, &p, 10_000, 1)
                .expect("valid bounds")
                .rotate,
            vec![1]
        );
        assert!(plan_rotations(&not_due_at_uses, &p, 10_000, 1)
            .expect("valid bounds")
            .rotate
            .is_empty());
    }

    #[test]
    fn zero_bound_fails_closed() {
        assert_eq!(
            plan_rotations(&[], &policy(), 10_000, 0),
            Err(PrivacyError::InvalidRotationBounds)
        );
    }

    #[test]
    fn debug_is_redacted() {
        let artifact = ArtifactRotation {
            artifact_id: 987_654_321,
            created_at_ms: 123_456_789,
            uses: 42,
            key_id: 65_535,
        };
        let debug = format!("{artifact:?}");
        assert!(!debug.contains("987654321"), "{debug}");
        assert!(!debug.contains("123456789"), "{debug}");
        assert!(!debug.contains("65535"), "{debug}");
    }
}
