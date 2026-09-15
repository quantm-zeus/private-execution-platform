//! Fail-closed, payload-free OKX client error taxonomy.
//!
//! Every variant is a structural class: no variant, `Display`, or `Debug`
//! implementation may disclose credentials, API keys, signatures, request
//! parameters, token addresses, amounts, calldata, or raw provider payloads.

use std::fmt;

use thiserror::Error;

/// Redacted OKX client failure classes.
#[derive(Clone, Copy, PartialEq, Eq, Error)]
pub enum OkxClientError {
    /// A locally built request failed structural validation.
    #[error("invalid okx request")]
    InvalidRequest,
    /// The requested chain has no configured OKX chain index.
    #[error("unsupported okx chain")]
    UnsupportedChain,
    /// Credentials were missing, empty, malformed, or over-long.
    #[error("invalid okx credentials")]
    InvalidCredentials,
    /// The injected transport is not available.
    #[error("okx transport unavailable")]
    TransportUnavailable,
    /// The injected transport failed or timed out.
    #[error("okx transport failure")]
    TransportFailure,
    /// The provider response exceeded the configured byte bound.
    #[error("oversized okx response")]
    OversizedResponse,
    /// The provider response was not the expected typed shape.
    #[error("malformed okx response")]
    MalformedResponse,
    /// The provider returned a non-success envelope code or HTTP status.
    #[error("okx provider error")]
    ProviderError,
    /// The provider quote did not match the requested binding.
    #[error("okx quote mismatch")]
    QuoteMismatch,
    /// A normalized quote could not be projected into a PEP provider model.
    #[error("okx normalization failed")]
    NormalizationFailed,
}

impl fmt::Debug for OkxClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Display` is static text only, so this cannot leak a payload.
        write!(formatter, "OkxClientError({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_renders_without_payload() {
        let errors = [
            OkxClientError::InvalidRequest,
            OkxClientError::UnsupportedChain,
            OkxClientError::InvalidCredentials,
            OkxClientError::TransportUnavailable,
            OkxClientError::TransportFailure,
            OkxClientError::OversizedResponse,
            OkxClientError::MalformedResponse,
            OkxClientError::ProviderError,
            OkxClientError::QuoteMismatch,
            OkxClientError::NormalizationFailed,
        ];
        for error in errors {
            let display = format!("{error}");
            let debug = format!("{error:?}");
            assert!(!display.is_empty());
            assert!(debug.starts_with("OkxClientError("));
            assert!(!display.contains("0x"));
            assert!(!debug.contains("0x"));
        }
    }
}
