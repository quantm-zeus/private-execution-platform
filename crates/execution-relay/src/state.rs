//! Reservation state machine and attempt-outcome types.
//!
//! The reservation store is the authoritative exactly-once guard for a running
//! relay: the relay claims an attempt before signing and refuses to sign, fetch,
//! or submit again for the same `(idempotency_key, request_digest)`. The shipped
//! implementations are process-local; durable storage is deferred.

use std::fmt;

use domain::{IdempotencyKey, OrderStatus};
use privy::RequestDigest;

use crate::error::RelayError;

/// Whether an acknowledged submission is already known on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionState {
    /// The adapter acknowledged the submission but its chain state is unknown.
    Unknown,
    /// The adapter reports the submission is still pending.
    Pending,
}

/// Realized amounts a chain adapter observed for a confirmed attempt.
///
/// This is the *observational* companion to a [`RelayOutcome::Confirmed`]:
/// amounts reported by authoritative chain state (for example a mined
/// transaction receipt). It is deliberately bare-atomic: the relay carries no
/// asset binding, and the consumer (the limit engine) binds the amounts to the
/// attempt's `token_in`/`token_out` and validates them against the sealed bound
/// context before any ledger mutation. An adapter that cannot observe exact
/// amounts must report `None` rather than guess.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObservedFill {
    /// Net input actually consumed on chain, in `token_in` atomic units.
    pub net_input: u128,
    /// Net output actually received on chain, in `token_out` atomic units.
    pub net_output: u128,
}

impl fmt::Debug for ObservedFill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: realized amounts are private execution economics.
        formatter.write_str("ObservedFill { .. }")
    }
}

/// Terminal or in-flight outcome of an execution attempt.
///
/// `Display`/`Debug` never reveal the opaque reference or adapter reason.
/// `Prepared`/`Reserved`/`Signed` are transient journal states; `Unknown`
/// means the submission state could not be determined and must be reconciled,
/// never blindly retried.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// The attempt is understood but not yet reserved.
    Prepared,
    /// The attempt has been claimed in the reservation store.
    Reserved,
    /// The signing boundary produced a signed reference.
    Signed,
    /// The adapter acknowledged the submission; this is not confirmation.
    Submitted {
        reference: String,
        state: SubmissionState,
    },
    /// The chain state of the attempt is unknown and requires reconciliation.
    Unknown,
    /// The chain confirmed the submission.
    ///
    /// `fill` is the exact realized amounts when the adapter observed them;
    /// `None` means the confirmation is real but the amounts are not yet known,
    /// which a consumer must treat as unresolved (`Unknown`) rather than infer.
    Confirmed {
        reference: String,
        fill: Option<ObservedFill>,
    },
    /// The chain definitively rejected the submission.
    Rejected { final_reason: String },
    /// The attempt failed before any chain submission occurred.
    FailedBeforeSubmit,
}

impl RelayOutcome {
    /// Maps the relay outcome onto the canonical order status.
    ///
    /// No new [`OrderStatus`] variant is introduced: an explicit later requote
    /// is what moves `FailedBeforeSubmit` back onto a retryable path.
    pub fn order_status(&self) -> OrderStatus {
        match self {
            Self::Prepared
            | Self::Reserved
            | Self::Signed
            | Self::Submitted { .. }
            | Self::Unknown => OrderStatus::Executing,
            Self::Confirmed { .. } => OrderStatus::Filled,
            Self::Rejected { .. } => OrderStatus::FailedFinal,
            Self::FailedBeforeSubmit => OrderStatus::FailedRetryable,
        }
    }
}

impl fmt::Debug for RelayOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit the opaque chain reference and the adapter final reason.
        match self {
            Self::Prepared => formatter.write_str("Prepared"),
            Self::Reserved => formatter.write_str("Reserved"),
            Self::Signed => formatter.write_str("Signed"),
            Self::Submitted { state, .. } => formatter
                .debug_struct("Submitted")
                .field("state", state)
                .finish_non_exhaustive(),
            Self::Unknown => formatter.write_str("Unknown"),
            Self::Confirmed { .. } => formatter.write_str("Confirmed"),
            Self::Rejected { .. } => formatter.write_str("Rejected"),
            Self::FailedBeforeSubmit => formatter.write_str("FailedBeforeSubmit"),
        }
    }
}

/// Result of claiming an attempt for an idempotency key + request digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The attempt was claimed for the first time; the caller may continue.
    Reserved,
    /// The same key + digest already exists; return the stored outcome.
    AlreadyReserved(RelayOutcome),
    /// The key exists with a different request digest.
    Conflict,
}

/// Exactly-once reservation store.
///
/// The shipped implementation is process-local (durable storage is deferred),
/// but implementations must be deterministic for a given input sequence and must
/// never permit a second reservation of the same `(key, digest)` to be treated
/// as a fresh attempt.
pub trait AttemptReservationStore: Send + Sync {
    /// Claims `(key, digest)`, returning the existing outcome when present.
    fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError>;

    /// Records that the signing boundary produced a reference for `(key, digest)`.
    fn record_signed(&self, key: &IdempotencyKey, digest: &RequestDigest)
        -> Result<(), RelayError>;

    /// Records the terminal/in-flight outcome for `(key, digest)`.
    fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError>;
}

impl<T: AttemptReservationStore + ?Sized> AttemptReservationStore for std::sync::Arc<T> {
    fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        (**self).reserve(key, digest)
    }

    fn record_signed(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        (**self).record_signed(key, digest)
    }

    fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        (**self).record_outcome(key, digest, outcome)
    }
}
