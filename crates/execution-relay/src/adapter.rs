//! Injected chain submission and signing adapters.
//!
//! No production adapter in this module performs network I/O or real broadcast:
//! [`UnavailableChainAdapter`] always fails closed, and
//! [`PrivySigningBoundaryAdapter`] wraps the real P40 boundary whose only public
//! constructor installs an always-unavailable transport.

use std::sync::Arc;

use async_trait::async_trait;
use privy::{PrivySigningBoundary, SigningRequest};
use serde::{Deserialize, Serialize};

use crate::error::RelayError;
use crate::health::ChainHealth;
use crate::plan::{SignedExecutionRef, SubmitRequest};

/// Observation of an attempt's actual chain state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainObservation {
    /// The chain confirmed the attempt.
    Confirmed { reference: String },
    /// The attempt is still pending on-chain.
    Pending,
    /// The chain definitively rejected the attempt.
    Rejected { final_reason: String },
    /// The chain state could not be determined.
    Unknown,
}

/// Acknowledgement returned by a successful submission.
///
/// This is an acknowledgement only, NOT confirmation: confirmation requires a
/// subsequent [`ChainSubmissionAdapter::reconcile`] observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionReceipt {
    /// Opaque chain acknowledgement reference.
    pub reference: String,
}

impl SubmissionReceipt {
    /// Builds a receipt, rejecting an empty reference.
    pub fn new(reference: impl Into<String>) -> Result<Self, RelayError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(RelayError::AdapterUnavailable);
        }
        Ok(Self { reference })
    }
}

/// Injected chain submission adapter. Production implementations are expected
/// to be idempotent on the request's idempotency key.
#[async_trait]
pub trait ChainSubmissionAdapter: Send + Sync {
    /// Submits at most once per request; acknowledgement only.
    async fn submit(&self, request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError>;

    /// Queries the chain state of a previously submitted request.
    async fn query(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError>;

    /// Reconciles a previously submitted request against authoritative chain
    /// state. Must not submit.
    async fn reconcile(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError>;

    /// Reports the adapter's view of chain health at `now_ms`.
    fn health(&self, now_ms: i64) -> ChainHealth;
}

#[async_trait]
impl<T: ChainSubmissionAdapter + ?Sized> ChainSubmissionAdapter for Arc<T> {
    async fn submit(&self, request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError> {
        (**self).submit(request).await
    }

    async fn query(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        (**self).query(request, now_ms).await
    }

    async fn reconcile(
        &self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        (**self).reconcile(request, now_ms).await
    }

    fn health(&self, now_ms: i64) -> ChainHealth {
        (**self).health(now_ms)
    }
}

/// Production default chain adapter: everything fails closed.
#[derive(Debug, Default)]
pub struct UnavailableChainAdapter;

impl UnavailableChainAdapter {
    /// Builds the fail-closed adapter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ChainSubmissionAdapter for UnavailableChainAdapter {
    async fn submit(&self, _request: &SubmitRequest) -> Result<SubmissionReceipt, RelayError> {
        Err(RelayError::AdapterUnavailable)
    }

    async fn query(
        &self,
        _request: &SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        Err(RelayError::AdapterUnavailable)
    }

    async fn reconcile(
        &self,
        _request: &SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        Err(RelayError::AdapterUnavailable)
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        ChainHealth::Unavailable
    }
}

/// Injected signing boundary.
///
/// The production wrapper below converts the real P40
/// `PrivySigningBoundary` output into the relay's own
/// [`SignedExecutionRef`]. Any signing failure is collapsed to the redacted
/// [`RelayError::SigningFailed`].
#[async_trait]
pub trait SigningBoundary: Send + Sync {
    /// Signs a fully bound request at most once.
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError>;
}

#[async_trait]
impl<T: SigningBoundary + ?Sized> SigningBoundary for Arc<T> {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        (**self).sign(request).await
    }
}

/// Production signing adapter over the real Privy signing boundary.
pub struct PrivySigningBoundaryAdapter {
    inner: PrivySigningBoundary,
}

impl PrivySigningBoundaryAdapter {
    /// Builds the production adapter. Its transport is unavailable until a real
    /// signer is wired in under review, so it fails closed.
    pub fn new() -> Self {
        Self {
            inner: PrivySigningBoundary::new(),
        }
    }
}

impl Default for PrivySigningBoundaryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PrivySigningBoundaryAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivySigningBoundaryAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SigningBoundary for PrivySigningBoundaryAdapter {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        let signed = self
            .inner
            .submit_signing_request(request)
            .await
            .map_err(|_| RelayError::SigningFailed)?;
        SignedExecutionRef::new(
            signed.reference().to_string(),
            *signed.request_digest(),
            signed.intent_id().clone(),
            signed.idempotency_key().clone(),
        )
        .map_err(|_| RelayError::SigningFailed)
    }
}
