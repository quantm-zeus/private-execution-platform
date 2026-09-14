//! The OKX quote client: credentials + injected transport + normalization.
//!
//! The client performs exactly one signed physical request per quote, parses the
//! bounded response, validates it against the request binding, and returns a
//! redacted [`OkxNormalizedQuote`]. It never signs a transaction, never submits,
//! and holds no wallet key material.

use std::fmt;

use crate::auth::sign_request;
use crate::credentials::OkxCredentials;
use crate::error::OkxClientError;
use crate::quote::{
    normalize_quote, OkxApiConfig, OkxNormalizedQuote, OkxQuoteEnvelope, OkxQuoteRequest,
};
use crate::transport::OkxTransport;

/// OKX quote client over an injected transport.
pub struct OkxClient<T> {
    transport: T,
    credentials: OkxCredentials,
    config: OkxApiConfig,
}

impl<T: OkxTransport> OkxClient<T> {
    /// Builds a client with the default API configuration.
    pub fn new(transport: T, credentials: OkxCredentials) -> Self {
        Self {
            transport,
            credentials,
            config: OkxApiConfig::default(),
        }
    }

    /// Builds a client with an explicit API configuration.
    pub fn with_config(transport: T, credentials: OkxCredentials, config: OkxApiConfig) -> Self {
        Self {
            transport,
            credentials,
            config,
        }
    }

    /// Returns the effective API configuration.
    pub fn config(&self) -> &OkxApiConfig {
        &self.config
    }

    /// Returns the injected transport (read-only).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Fetches and normalizes one exact-input quote at `now_ms`.
    ///
    /// Fail-closed: a transport failure, a non-200 status, an oversized or
    /// malformed body, a provider error envelope, or a quote that does not match
    /// the requested chain/pair/amount is rejected with a redacted
    /// [`OkxClientError`]. The response body is checked against the configured
    /// bound before parsing.
    ///
    /// That client-side bound is defense in depth only, because the body has
    /// already been materialized by the injected transport. A production
    /// [`OkxTransport`] implementation MUST bound or stream the provider
    /// response before materializing it in memory.
    pub async fn quote(
        &self,
        request: &OkxQuoteRequest,
        now_ms: i64,
    ) -> Result<OkxNormalizedQuote, OkxClientError> {
        let http = request.to_http(&self.config)?;
        let auth = sign_request(
            &self.credentials,
            http.method().as_str(),
            &http.signed_path(),
            http.body(),
            now_ms,
        )?;
        let response = self
            .transport
            .send(http, &auth)
            .await
            .map_err(|error| error.into_client_error())?;
        if response.status() != 200 {
            return Err(OkxClientError::ProviderError);
        }
        if response.body().len() > self.config.max_response_bytes() {
            return Err(OkxClientError::OversizedResponse);
        }
        let envelope: OkxQuoteEnvelope = serde_json::from_slice(response.body())
            .map_err(|_| OkxClientError::MalformedResponse)?;
        normalize_quote(request, envelope, now_ms)
    }
}

impl<T> fmt::Debug for OkxClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OkxClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
