//! Narrow Privy signing boundary. No generic signing/transfer/withdraw surface exists.
//!
//! Callers can only submit a fully bound [`SigningRequest`]. There is no method
//! that signs arbitrary bytes or calldata, and this crate never receives raw
//! transaction bytes. Production construction always installs an unavailable
//! transport, so the boundary fails closed until a real signer is wired in
//! under review.

pub mod signing;

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use domain::{IdempotencyKey, IntentId};
use thiserror::Error;

pub use signing::{PayloadDigest, RequestDigest, SignedExecutionRef, SigningRequest};

/// Opaque reference to a prepared execution. This is not a signing capability;
/// it only carries the policy intent/idempotency binding for later validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedExecutionRef {
    reference: String,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
}

impl PreparedExecutionRef {
    pub fn new(
        reference: impl Into<String>,
        intent_id: IntentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, PrivyError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(PrivyError::InvalidExecutionReference);
        }
        Ok(Self {
            reference,
            intent_id,
            idempotency_key,
        })
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

/// Crate-private signing transport. Test doubles live in [`signing::test_support`].
#[async_trait]
pub(crate) trait SigningTransport: Send + Sync {
    async fn submit_signing_request(&self, request: &SigningRequest) -> Result<String, PrivyError>;
}

/// Production transport: no live signer is wired in, so every request fails closed.
#[derive(Debug, Default)]
struct UnavailableTransport;

#[async_trait]
impl SigningTransport for UnavailableTransport {
    async fn submit_signing_request(
        &self,
        _request: &SigningRequest,
    ) -> Result<String, PrivyError> {
        Err(PrivyError::SigningUnavailable)
    }
}

/// Concrete, non-heritable signing boundary.
///
/// It enforces exactly-once submission per idempotency key and holds the only
/// transport handle. Production code can only build the unavailable transport;
/// there is no public constructor that installs a real one.
pub struct PrivySigningBoundary {
    transport: Box<dyn SigningTransport>,
    seen: Mutex<HashMap<IdempotencyKey, RequestDigest>>,
}

impl std::fmt::Debug for PrivySigningBoundary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the transport or endpoints.
        f.debug_struct("PrivySigningBoundary")
            .finish_non_exhaustive()
    }
}

impl Default for PrivySigningBoundary {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivySigningBoundary {
    /// Builds the production boundary, which is always fail-closed.
    pub fn new() -> Self {
        Self {
            transport: Box::new(UnavailableTransport),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Test-only seam for installing an in-crate transport double.
    #[cfg(test)]
    fn with_transport(transport: Box<dyn SigningTransport>) -> Self {
        Self {
            transport,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Submits a bound signing request at most once per idempotency key.
    ///
    /// - same key + same request digest -> [`PrivyError::DuplicateSigningRequest`]
    ///   (the transport is not called);
    /// - same key + different digest -> [`PrivyError::IdempotencyConflict`];
    /// - otherwise the key is recorded *before* the transport runs and kept
    ///   regardless of the outcome, so a timeout can never cause a double-sign.
    ///
    /// There is no automatic retry anywhere on this path.
    pub async fn submit_signing_request(
        &self,
        request: &SigningRequest,
    ) -> Result<SignedExecutionRef, PrivyError> {
        {
            let mut seen = self
                .seen
                .lock()
                // Poison recovery is safe here: the guarded value is a plain
                // `HashMap`, so a panicking holder cannot leave a torn state (at
                // worst a key is inserted or not). The guard is dropped at the end
                // of this block, before any `.await`, so no lock is held across a
                // suspension point.
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match seen.get(request.idempotency_key()) {
                Some(existing) if existing == request.request_digest() => {
                    return Err(PrivyError::DuplicateSigningRequest);
                }
                Some(_) => return Err(PrivyError::IdempotencyConflict),
                None => {
                    seen.insert(request.idempotency_key().clone(), *request.request_digest());
                }
            }
        }

        let reference = self.transport.submit_signing_request(request).await?;
        SignedExecutionRef::new(
            reference,
            *request.request_digest(),
            request.intent_id().clone(),
            request.idempotency_key().clone(),
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivyError {
    #[error("Privy signing boundary unavailable")]
    SigningUnavailable,
    #[error("invalid execution reference")]
    InvalidExecutionReference,
    #[error("execution does not match policy approval")]
    ApprovalBindingMismatch,
    #[error("unsupported chain")]
    UnsupportedChain,
    #[error("policy approval expired")]
    ApprovalExpired,
    #[error("trading disabled")]
    TradingDisabled,
    #[error("execution preview revalidation failed")]
    PreviewRevalidationFailed,
    #[error("payload digest missing")]
    MissingPayloadDigest,
    #[error("duplicate signing request")]
    DuplicateSigningRequest,
    #[error("idempotency key conflict")]
    IdempotencyConflict,
    #[error("signer rejected request")]
    SignerRejected,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::signing::fixtures;
    use crate::signing::test_support::{CountingTransport, EmptyRefTransport, RejectingTransport};

    fn counting_boundary() -> (PrivySigningBoundary, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let boundary = PrivySigningBoundary::with_transport(Box::new(CountingTransport::new(
            Arc::clone(&calls),
        )));
        (boundary, calls)
    }

    #[tokio::test]
    async fn production_boundary_fails_closed() {
        let boundary = PrivySigningBoundary::default();
        let request = fixtures::signing_request();
        assert_eq!(
            boundary.submit_signing_request(&request).await,
            Err(PrivyError::SigningUnavailable)
        );
    }

    #[test]
    fn empty_reference_is_rejected() {
        let intent = fixtures::intent();
        assert_eq!(
            PreparedExecutionRef::new(" ", intent.id.clone(), intent.idempotency_key.clone(),),
            Err(PrivyError::InvalidExecutionReference)
        );
    }

    #[tokio::test]
    async fn duplicate_request_is_rejected_without_second_transport_call() {
        let (boundary, calls) = counting_boundary();
        let request = fixtures::signing_request();
        let signed = boundary
            .submit_signing_request(&request)
            .await
            .expect("first submit succeeds");
        assert_eq!(signed.request_digest(), request.request_digest());
        assert_eq!(signed.intent_id(), request.intent_id());
        assert_eq!(signed.idempotency_key(), request.idempotency_key());
        assert!(!signed.reference().is_empty());
        assert_eq!(
            boundary.submit_signing_request(&request).await,
            Err(PrivyError::DuplicateSigningRequest)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn same_key_different_digest_conflicts_without_second_transport_call() {
        let (boundary, calls) = counting_boundary();
        let request = fixtures::signing_request();

        let mut other_intent = fixtures::intent();
        other_intent.nonce = 8;
        let engine = fixtures::engine();
        let approved = fixtures::approved(&engine, &other_intent);
        let prepared = fixtures::prepared(&other_intent);
        let route = fixtures::route();
        let preview = fixtures::execution_preview(&other_intent, &route);
        let conflict_request = SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &other_intent,
            &route,
            &preview,
            fixtures::payload(),
            fixtures::NOW_MS,
        )
        .expect("conflicting request binds");
        assert_ne!(
            request.request_digest(),
            conflict_request.request_digest(),
            "nonce change must change the request digest"
        );

        assert!(boundary.submit_signing_request(&request).await.is_ok());
        assert_eq!(
            boundary.submit_signing_request(&conflict_request).await,
            Err(PrivyError::IdempotencyConflict)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejection_and_empty_reference_fail_closed() {
        let request = fixtures::signing_request();
        let rejecting = PrivySigningBoundary::with_transport(Box::new(RejectingTransport));
        assert_eq!(
            rejecting.submit_signing_request(&request).await,
            Err(PrivyError::SignerRejected)
        );
        let empty = PrivySigningBoundary::with_transport(Box::new(EmptyRefTransport));
        assert_eq!(
            empty.submit_signing_request(&request).await,
            Err(PrivyError::InvalidExecutionReference)
        );
    }

    /// Fixture-derived substrings that must never leak through `Display`/`Debug`.
    const FORBIDDEN_SUBSTRINGS: &[&str] = &[
        // amounts
        "1000",
        "250",
        "240",
        // asset addresses
        "USDC",
        "USDCX",
        "TOKEN",
        // wallet / intent / idempotency / prepared strings
        "wallet-1",
        "intent-1",
        "idem-1",
        "prepared-1",
        // endpoint-like substrings
        "http",
        "://",
        "grpc",
        "tcp",
        "unix",
        "0x",
    ];

    /// Detects a run of at least `min_len` ASCII hex digits, i.e. leaked digest bytes.
    fn has_hex_run(value: &str, min_len: usize) -> bool {
        let mut run = 0usize;
        for ch in value.chars() {
            if ch.is_ascii_hexdigit() {
                run += 1;
                if run >= min_len {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    fn assert_redacted(label: &str, value: &str) {
        for forbidden in FORBIDDEN_SUBSTRINGS {
            assert!(
                !value.contains(forbidden),
                "redaction leak in `{label}`: `{value}` contains `{forbidden}`"
            );
        }
        assert!(
            !has_hex_run(value, 8),
            "redaction leak in `{label}`: `{value}` contains a hex run of length >= 8"
        );
    }

    #[tokio::test]
    async fn every_rendered_surface_is_redacted() {
        let errors = [
            PrivyError::SigningUnavailable,
            PrivyError::InvalidExecutionReference,
            PrivyError::ApprovalBindingMismatch,
            PrivyError::UnsupportedChain,
            PrivyError::ApprovalExpired,
            PrivyError::TradingDisabled,
            PrivyError::PreviewRevalidationFailed,
            PrivyError::MissingPayloadDigest,
            PrivyError::DuplicateSigningRequest,
            PrivyError::IdempotencyConflict,
            PrivyError::SignerRejected,
        ];
        for error in errors {
            assert_redacted("PrivyError Display", &error.to_string());
            assert_redacted("PrivyError Debug", &format!("{error:?}"));
        }

        let (boundary, _calls) = counting_boundary();
        let request = fixtures::signing_request();
        assert_redacted("SigningRequest Debug", &format!("{request:?}"));
        assert_redacted(
            "PayloadDigest Debug",
            &format!("{:?}", request.payload_digest()),
        );
        assert_redacted(
            "RequestDigest Debug",
            &format!("{:?}", request.request_digest()),
        );

        let signed = boundary
            .submit_signing_request(&request)
            .await
            .expect("submit succeeds");
        assert_redacted("SignedExecutionRef Debug", &format!("{signed:?}"));
    }
}
