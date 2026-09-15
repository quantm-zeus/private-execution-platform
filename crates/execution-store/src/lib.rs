//! Durable exactly-once execution attempt store (remediation D5).
//!
//! This crate supplies the concrete production persistence adapter for
//! [`execution_relay::AttemptReservationStore`]: a Postgres/Timescale-backed
//! attempt ledger that persists the full lifecycle
//!
//! `RESERVED -> SIGN_REQUESTED -> SIGNED -> SUBMISSION_UNKNOWN/SUBMITTED -> CONFIRMED/REJECTED`
//!
//! **before** each consequential boundary, so a crash anywhere between reserve,
//! sign, persist, submit, and receipt can be reconciled on restart instead of
//! duplicated. The table is defined by
//! `infra/postgres/migrations/0003_execution_attempts.sql`.
//!
//! # Security posture
//! - Ciphertext/key material is **never** stored. The row carries stable
//!   execution reference data only: the canonical request digest, the provider
//!   signing idempotency identifier, the opaque signed reference, and the bound
//!   signed payload bytes needed to reconcile.
//! - Every record is validated before database contact; unique-constraint and
//!   CAS failures map to opaque [`execution_relay::RelayError`]s with no row
//!   content and no DSN in errors.
//! - No logging.
//!
//! The deterministic reference implementation
//! [`execution_relay::DeterministicDurableStore`] is the behavioral spec this
//! adapter matches; the crash/restart tests exercise that spec without a
//! database.

#![forbid(unsafe_code)]

pub mod postgres;

pub use postgres::PostgresExecutionAttemptStore;

use storage::{ComponentHealth, HealthProbe};

/// Default coarse bucket width, in milliseconds, for created/updated buckets.
///
/// Buckets are caller-library-supplied coarse time, matching the repository's
/// storage convention that physical rows never observe exact wall-clock time.
pub const DEFAULT_BUCKET_MS: i64 = 86_400_000;

/// Injected clock used to stamp coarse buckets and the health probe.
///
/// The store never reads the database clock and never derives a bucket from a
/// row; the injected clock keeps tests deterministic.
pub trait AttemptClock: Send + Sync {
    /// Current wall-clock time in milliseconds.
    fn now_ms(&self) -> i64;
}

/// Wall-clock clock for production composition.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl AttemptClock for SystemClock {
    fn now_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            Err(_) => i64::MIN,
        }
    }
}

/// Connection/configuration error for a Postgres attempt store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionStoreError {
    /// The pool size was zero or a connection could not be established.
    #[error("execution store unavailable")]
    Unavailable,
    /// The pool size or bucket width was invalid.
    #[error("execution store configuration invalid")]
    InvalidConfig,
}

/// Maps a millisecond instant onto its non-negative coarse bucket.
///
/// Saturates at zero for non-positive instants (a pre-epoch clock is not a valid
/// bucket) so the `created_bucket >= 0` table constraint can never be violated
/// by a caller-supplied clock.
pub fn bucket_for(now_ms: i64, bucket_ms: i64) -> i64 {
    if bucket_ms <= 0 {
        return 0;
    }
    match now_ms.div_euclid(bucket_ms) {
        bucket if bucket < 0 => 0,
        bucket => bucket,
    }
}

/// Health probe helper shared by the adapter.
pub(crate) fn healthy_probe(component: &'static str, now_ms: i64) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Healthy,
        observed_at_ms: now_ms,
    }
}

/// Unavailable health probe helper.
pub(crate) fn unavailable_probe(component: &'static str, now_ms: i64) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Unavailable,
        observed_at_ms: now_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_is_non_negative_and_coarse() {
        assert_eq!(bucket_for(0, DEFAULT_BUCKET_MS), 0);
        assert_eq!(bucket_for(DEFAULT_BUCKET_MS - 1, DEFAULT_BUCKET_MS), 0);
        assert_eq!(bucket_for(DEFAULT_BUCKET_MS, DEFAULT_BUCKET_MS), 1);
        assert_eq!(bucket_for(-5, DEFAULT_BUCKET_MS), 0);
        assert_eq!(bucket_for(5, 0), 0);
        assert_eq!(bucket_for(5, -1), 0);
    }
}
