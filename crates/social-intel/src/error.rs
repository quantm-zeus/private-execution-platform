//! Redacted social-provider failure classes.

/// A redacted paid-social provider failure.
///
/// Payload-free by construction: no query, token, endpoint, or credential can
/// reach a log through this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SocialProviderError {
    /// No provider transport is installed (the fail-closed default).
    #[error("social provider unavailable")]
    Unavailable,
    /// The provider refused the request.
    #[error("social provider rejected the request")]
    Rejected,
    /// The provider returned a response that could not be used.
    #[error("social provider returned a malformed response")]
    Malformed,
}
