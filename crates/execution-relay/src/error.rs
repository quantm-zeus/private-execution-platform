//! Redacted, payload-free relay errors.
//!
//! Every variant is a unit value with a static message, so neither
//! [`Display`](std::fmt::Display) nor [`Debug`] can leak amounts, assets,
//! addresses, references, endpoints, or digests.

use thiserror::Error;

/// Fail-closed relay error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RelayError {
    /// The live policy kill switch is off.
    #[error("trading disabled")]
    TradingDisabled,
    /// The chain health breaker is open or the adapter is unavailable.
    #[error("chain health unavailable")]
    ChainHealthUnavailable,
    /// The signing-failure breaker is open; new execution is halted.
    #[error("signing unavailable")]
    SigningUnavailable,
    /// The signing boundary rejected or failed the request.
    #[error("signing failed")]
    SigningFailed,
    /// A signed reference does not match its signing request.
    #[error("signing request mismatch")]
    SigningRequestMismatch,
    /// The requested chain does not match the signed request chain.
    #[error("chain mismatch")]
    ChainMismatch,
    /// The signed payload source could not provide a payload.
    #[error("missing signed payload")]
    MissingSignedPayload,
    /// The signed payload is empty.
    #[error("signed payload empty")]
    SignedPayloadEmpty,
    /// The signed payload exceeds the supported bound.
    #[error("signed payload too large")]
    SignedPayloadTooLarge,
    /// The signed payload digest does not match the signing request digest.
    #[error("signed payload digest mismatch")]
    SignedPayloadDigestMismatch,
    /// The attempt reservation store is unavailable.
    #[error("attempt reservation unavailable")]
    ReservationUnavailable,
    /// The idempotency key is already bound to a different request.
    #[error("idempotency conflict")]
    IdempotencyConflict,
    /// The chain submission adapter is unavailable.
    #[error("chain adapter unavailable")]
    AdapterUnavailable,
    /// The chain adapter definitively rejected the submission.
    #[error("chain adapter rejected submission")]
    AdapterRejected,
    /// The chain adapter timed out; the submission state is unknown.
    #[error("chain adapter timed out")]
    AdapterTimeout,
    /// The submission state could not be determined.
    #[error("unknown submission state")]
    UnknownSubmissionState,
    /// The requested operation is invalid for the current relay state.
    #[error("invalid transition")]
    InvalidTransition,
    /// The reservation store failed.
    #[error("reservation store unavailable")]
    StoreUnavailable,
}
