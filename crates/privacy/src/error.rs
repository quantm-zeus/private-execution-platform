//! Redacted privacy-policy validation errors.

/// A rejected privacy policy configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyError {
    /// The padding ladder was empty.
    #[error("padding ladder must not be empty")]
    EmptyLadder,
    /// A padding bucket was zero.
    #[error("padding bucket must be non-zero")]
    ZeroBucket,
    /// The padding ladder was not strictly ascending.
    #[error("padding ladder must be strictly ascending")]
    NotAscending,
    /// A rotation bound was zero or negative.
    #[error("rotation bounds must be positive")]
    InvalidRotationBounds,
}
