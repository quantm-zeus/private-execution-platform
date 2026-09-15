//! Injected provider-quote source boundary.
//!
//! The service never performs I/O itself: a caller injects a
//! [`ProviderQuoteSource`]. The production default
//! ([`UnavailableProviderQuoteSource`]) fails closed, so a service built without
//! a real source degrades to "skip" rather than fabricating a provider quote.

use std::fmt;

use chain_types::{AssetId, ChainId};
use routing::ProviderQuote;

/// Exact basis for one provider quote request.
///
/// Every field is private execution economics, so `Debug` renders no payload.
pub struct ProviderQuoteRequest {
    /// Chain the quote is requested on.
    pub chain: ChainId,
    /// Input asset offered to the provider route.
    pub token_in: AssetId,
    /// Output asset expected from the provider route.
    pub token_out: AssetId,
    /// Input basis in `token_in` atomic units.
    pub amount_in: u128,
    /// Caller reference time for the request, in milliseconds.
    pub observed_at_ms: i64,
}

impl fmt::Debug for ProviderQuoteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: never render chain, assets, or amounts.
        formatter
            .debug_struct("ProviderQuoteRequest")
            .finish_non_exhaustive()
    }
}

/// Redacted provider-quote source failure taxonomy.
///
/// Every variant is fieldless, so neither `Display` nor `Debug` can leak a
/// provider payload, endpoint, or credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderQuoteSourceError {
    /// The source (or its transport) is unavailable.
    #[error("provider quote source unavailable")]
    Unavailable,
    /// The source structurally rejected the request.
    #[error("provider quote source rejected the request")]
    Rejected,
}

/// Injected, read-only provider-quote source.
///
/// Implementations must be deterministic for identical requests and must return
/// an error rather than a quote for a basis they cannot faithfully serve; the
/// service re-validates every returned quote's binding before it is compared or
/// cached.
#[async_trait::async_trait]
pub trait ProviderQuoteSource: Send + Sync + 'static {
    /// Fetches one provider quote for `request`.
    async fn fetch_quote(
        &self,
        request: &ProviderQuoteRequest,
    ) -> Result<ProviderQuote, ProviderQuoteSourceError>;
}

/// Fail-closed default: no provider is configured, so every fetch is unavailable.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableProviderQuoteSource;

#[async_trait::async_trait]
impl ProviderQuoteSource for UnavailableProviderQuoteSource {
    async fn fetch_quote(
        &self,
        _request: &ProviderQuoteRequest,
    ) -> Result<ProviderQuote, ProviderQuoteSourceError> {
        Err(ProviderQuoteSourceError::Unavailable)
    }
}
