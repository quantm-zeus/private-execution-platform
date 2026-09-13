//! Payload-free audit errors.
//!
//! Every variant renders without digits, amounts, assets, addresses,
//! references, key ids, or digests. Callers get a stable classification; the
//! offending data never crosses an error boundary.

use thiserror::Error;

/// Fail-closed audit error taxonomy.
///
/// `Display` and `Debug` are deliberately content-free: the only carried data is
/// a static, human-readable reason string for [`AuditError::EventValidationFailed`]
/// that callers choose from a fixed, redaction-safe set.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    /// No audit key material is configured or reachable.
    #[error("audit key unavailable")]
    KeyUnavailable,
    /// The record's key id is not known to the provider.
    #[error("unknown audit key identifier")]
    UnknownKeyId,
    /// The provider returned key material whose id does not match the request.
    #[error("audit key identifier mismatch")]
    KeyIdMismatch,
    /// Sealing failed; nothing may be persisted.
    #[error("audit seal failed")]
    SealFailed,
    /// Authentication or decryption failed; no plaintext is produced.
    #[error("audit open failed")]
    OpenFailed,
    /// The stored record is structurally invalid.
    #[error("audit record malformed")]
    RecordMalformed,
    /// The event sequence does not advance the stream.
    #[error("audit sequence not monotonic")]
    SequenceNotMonotonic,
    /// The stream sequence is not contiguous during replay.
    #[error("audit sequence gap")]
    SequenceGap,
    /// The backing store is unavailable.
    #[error("audit storage unavailable")]
    StorageUnavailable,
    /// The backing store rejected the append as a conflict.
    #[error("audit storage conflict")]
    StorageConflict,
    /// The event failed semantic validation; the static reason is redaction-safe.
    #[error("audit event invalid: {0}")]
    EventValidationFailed(&'static str),
}
