//! Injected OKX quote source port for the agent backend (P84B).
//!
//! The hybrid router selects OKX by default, so the backend needs one narrow,
//! read-only seam that can fetch a normalized OKX quote from an injected
//! transport. This module defines that seam ([`OkxQuoteSource`]) plus the
//! fail-closed default ([`UnavailableOkxQuoteSource`]) and a blanket adapter for
//! [`okx_client::OkxClient`].
//!
//! ## Boundaries
//! - **Read-only quoting.** No signing, submission, relay, or wallet-key surface
//!   is named here; `okx-client` is itself a quote-only boundary.
//! - **Fail closed.** The default source always returns
//!   [`OkxQuoteError::Unavailable`]; a caller must explicitly install a source
//!   with [`crate::TradingAgentBackend::with_okx_quote_source`]. A provider
//!   outage is surfaced as unavailability and never silently falls back to the
//!   local router.
//! - **Redacted errors.** [`OkxQuoteError`] carries no asset, amount, address,
//!   credential, or provider payload, and its `Debug` renders only the
//!   payload-free `Display` text.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::fmt;

use chain_types::{AssetId, ChainId};
use market_types::{AtomicAmount, Bps};
use okx_client::{OkxClient, OkxClientError, OkxNormalizedQuote, OkxQuoteRequest, OkxTransport};

/// Redacted OKX quote-source failure taxonomy.
///
/// `Unavailable` is a transport outage (requote / visible unavailability);
/// `Rejected` is any structural/provider rejection. Neither carries a payload.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OkxQuoteError {
    /// The OKX transport or provider is not reachable.
    #[error("okx quote source unavailable")]
    Unavailable,
    /// The OKX request or provider response was structurally rejected.
    #[error("okx quote rejected")]
    Rejected,
}

impl fmt::Debug for OkxQuoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Display` is static text only, so this cannot leak a payload.
        write!(formatter, "OkxQuoteError({self})")
    }
}

/// Injected, read-only source of one normalized OKX exact-input quote.
///
/// Implementations must be deterministic for identical inputs (the `now_ms`
/// reference instant is supplied by the caller) and must never sign, submit, or
/// mutate state.
#[async_trait::async_trait]
pub trait OkxQuoteSource: Send + Sync {
    /// Fetches a normalized exact-input OKX quote at `now_ms`.
    async fn fetch_quote(
        &self,
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: AtomicAmount,
        slippage_bps: Option<Bps>,
        now_ms: i64,
    ) -> Result<OkxNormalizedQuote, OkxQuoteError>;
}

/// Fail-closed default: no OKX transport is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableOkxQuoteSource;

#[async_trait::async_trait]
impl OkxQuoteSource for UnavailableOkxQuoteSource {
    async fn fetch_quote(
        &self,
        _chain: ChainId,
        _token_in: AssetId,
        _token_out: AssetId,
        _amount_in: AtomicAmount,
        _slippage_bps: Option<Bps>,
        _now_ms: i64,
    ) -> Result<OkxNormalizedQuote, OkxQuoteError> {
        Err(OkxQuoteError::Unavailable)
    }
}

#[async_trait::async_trait]
impl<T: OkxTransport + 'static> OkxQuoteSource for OkxClient<T> {
    async fn fetch_quote(
        &self,
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: AtomicAmount,
        slippage_bps: Option<Bps>,
        now_ms: i64,
    ) -> Result<OkxNormalizedQuote, OkxQuoteError> {
        let request = OkxQuoteRequest::new(chain, token_in, token_out, amount_in, slippage_bps)
            .map_err(|_| OkxQuoteError::Rejected)?;
        // Call the inherent method explicitly to avoid recursing into this trait
        // method of the same name.
        OkxClient::quote(self, &request, now_ms)
            .await
            .map_err(|error| match error {
                OkxClientError::TransportUnavailable | OkxClientError::TransportFailure => {
                    OkxQuoteError::Unavailable
                }
                _ => OkxQuoteError::Rejected,
            })
    }
}
