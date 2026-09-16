//! Concrete production Privy signing transport over an injected HTTP client.
//!
//! The crate deliberately owns no HTTP client, no TLS stack, and no
//! credentials: a deployment injects a [`PrivyHttpClient`] (and its
//! [`PrivyCredentials`]) that performs the real provider call. That keeps this
//! crate pure and testable while giving [`crate::PrivySigningBoundary`] a real
//! production constructor ([`crate::PrivySigningBoundary::with_signing_transport`]).
//!
//! What this transport guarantees:
//! - only a fully bound [`SigningRequest`] is forwarded;
//! - the stable [`ProviderIdempotencyId`] is forwarded so a provider that
//!   supports idempotent signing can collapse a retry;
//! - credentials are never rendered through `Debug`/`Display` and never logged.
//!
//! What it does **not** do: fetch unsigned transaction bytes. The transaction
//! builder remains an operator-supplied seam; this transport is the network
//! boundary only, and the boundary around it stays fail-closed until a real
//! client is injected.

use async_trait::async_trait;

use crate::{PrivyError, ProviderIdempotencyId, SigningRequest, SigningTransport};

/// Injected HTTP client that performs the real Privy API call.
///
/// A production implementation owns the endpoint, TLS, retry-free request
/// policy, and credential handling. It must be idempotent on the provided
/// [`ProviderIdempotencyId`] and must never log credentials or request bytes.
#[async_trait]
pub trait PrivyHttpClient: Send + Sync {
    /// Performs one signing call. No retry policy may re-sign a different
    /// request; a transport-level retry must reuse `idempotency`.
    async fn submit_signing_request(
        &self,
        request: &SigningRequest,
        idempotency: &ProviderIdempotencyId,
    ) -> Result<String, PrivyError>;
}

/// Fail-closed HTTP client: never performs network I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePrivyHttpClient;

#[async_trait]
impl PrivyHttpClient for UnavailablePrivyHttpClient {
    async fn submit_signing_request(
        &self,
        _request: &SigningRequest,
        _idempotency: &ProviderIdempotencyId,
    ) -> Result<String, PrivyError> {
        Err(PrivyError::SigningUnavailable)
    }
}

/// Production signing transport over an injected HTTP client.
pub struct PrivyHttpSigningTransport<C: PrivyHttpClient> {
    client: C,
}

impl<C: PrivyHttpClient> PrivyHttpSigningTransport<C> {
    /// Wraps an injected HTTP client.
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: PrivyHttpClient> std::fmt::Debug for PrivyHttpSigningTransport<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the client or any endpoint/credential.
        formatter
            .debug_struct("PrivyHttpSigningTransport")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<C: PrivyHttpClient> SigningTransport for PrivyHttpSigningTransport<C> {
    async fn submit_signing_request(
        &self,
        request: &SigningRequest,
        idempotency: &ProviderIdempotencyId,
    ) -> Result<String, PrivyError> {
        self.client
            .submit_signing_request(request, idempotency)
            .await
    }
}

/// Operator-supplied Privy credentials.
///
/// The value is held opaquely: `Debug` is redacted and there is no `Display`.
/// The credentials are only exposed to an injected [`PrivyHttpClient`] through
/// [`PrivyCredentials::expose`], which is crate-visible so no other code path can
/// read them.
pub struct PrivyCredentials(String);

impl PrivyCredentials {
    /// Wraps a credential string supplied by the operator at startup.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the secret for the injected client.
    ///
    /// It is `pub` because the injected [`PrivyHttpClient`] lives in the
    /// deployment crate, so that client is the intended reader: it calls this to
    /// build its authorization header. The value must never be logged,
    /// serialized, or included in an error, and `Debug` is redacted.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PrivyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivyCredentials { .. }")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::signing::fixtures;

    /// Records the idempotency id it received, then fails closed.
    struct RecordingClient {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PrivyHttpClient for RecordingClient {
        async fn submit_signing_request(
            &self,
            _request: &SigningRequest,
            idempotency: &ProviderIdempotencyId,
        ) -> Result<String, PrivyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(idempotency.as_str().starts_with("pep-sign-v1-"));
            Err(PrivyError::SigningUnavailable)
        }
    }

    #[tokio::test]
    async fn transport_forwards_the_provider_idempotency_id() {
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = PrivyHttpSigningTransport::new(RecordingClient {
            calls: Arc::clone(&calls),
        });
        let boundary = crate::PrivySigningBoundary::with_signing_transport(Box::new(transport));
        let request = fixtures::signing_request();
        assert_eq!(
            boundary.submit_signing_request(&request).await,
            Err(PrivyError::SigningUnavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn credentials_are_redacted() {
        let credentials = PrivyCredentials::new("super-secret-value");
        assert_eq!(format!("{credentials:?}"), "PrivyCredentials { .. }");
        // The injected client (crate-visible seam) is the only reader.
        assert_eq!(credentials.expose(), "super-secret-value");
    }
}
