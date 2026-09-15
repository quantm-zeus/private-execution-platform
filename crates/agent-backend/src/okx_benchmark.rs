//! Additive adapter from the read-only OKX quote seam to the provider-benchmark
//! quote-source seam (P92).
//!
//! [`crate::OkxQuoteSource`] produces a normalized
//! [`okx_client::OkxNormalizedQuote`]; the P87 provider-benchmark service
//! consumes a [`provider_benchmark::ProviderQuoteSource`]. This module bridges
//! the two without touching either crate: it binds a
//! [`routing::BenchmarkSource`] label onto every quote the underlying source
//! returns and projects that quote into the benchmark model.
//!
//! ## Boundaries
//! - **Read-only.** The adapter only forwards a fetch and maps errors; it never
//!   signs, submits, relays, mutates, or logs.
//! - **Fail closed.** Underlying unavailability maps to
//!   [`provider_benchmark::ProviderQuoteSourceError::Unavailable`]; every other
//!   failure (including a projection that cannot be formed) maps to
//!   `Rejected`. A quote is never fabricated.
//! - **Redacted.** [`OkxBenchmarkQuoteSource`] has a manual payload-free `Debug`
//!   that renders neither the source label nor any chain/asset/amount.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::fmt;

use market_types::AtomicAmount;
use provider_benchmark::{ProviderQuoteRequest, ProviderQuoteSource, ProviderQuoteSourceError};
use routing::{BenchmarkSource, ProviderQuote};

use crate::okx::{OkxQuoteError, OkxQuoteSource};

/// Adapts an [`OkxQuoteSource`] to the provider-benchmark [`ProviderQuoteSource`]
/// seam, binding `label` onto every quote it returns.
pub struct OkxBenchmarkQuoteSource<S> {
    source: S,
    label: BenchmarkSource,
}

impl<S> OkxBenchmarkQuoteSource<S> {
    /// Builds the adapter with the benchmark source label bound onto every quote.
    pub fn new(source: S, label: BenchmarkSource) -> Self {
        Self { source, label }
    }
}

impl<S> fmt::Debug for OkxBenchmarkQuoteSource<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: neither the wrapped source nor the benchmark label is a
        // renderable payload.
        formatter
            .debug_struct("OkxBenchmarkQuoteSource")
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<S: OkxQuoteSource + 'static> ProviderQuoteSource for OkxBenchmarkQuoteSource<S> {
    async fn fetch_quote(
        &self,
        request: &ProviderQuoteRequest,
    ) -> Result<ProviderQuote, ProviderQuoteSourceError> {
        let normalized = self
            .source
            .fetch_quote(
                request.chain.clone(),
                request.token_in.clone(),
                request.token_out.clone(),
                AtomicAmount::new(request.amount_in),
                None,
                request.observed_at_ms,
            )
            .await
            .map_err(|error| match error {
                OkxQuoteError::Unavailable => ProviderQuoteSourceError::Unavailable,
                OkxQuoteError::Rejected => ProviderQuoteSourceError::Rejected,
            })?;
        normalized
            .to_provider_quote(self.label.clone())
            .map_err(|_| ProviderQuoteSourceError::Rejected)
    }
}
