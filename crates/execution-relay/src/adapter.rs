//! Injected chain submission and signing adapters.
//!
//! No production adapter in this module performs network I/O or real broadcast:
//! [`UnavailableChainAdapter`] always fails closed, and
//! [`PrivySigningBoundaryAdapter`] wraps the real P40 boundary whose only public
//! constructor installs an always-unavailable transport.

use std::sync::Arc;

use async_trait::async_trait;
use privy::{PrivySigningBoundary, SigningRequest};

use crate::error::RelayError;
use crate::health::ChainHealth;
use crate::plan::{SignedExecutionRef, SubmitRequest};
use crate::state::ObservedFill;

/// Observation of an attempt's actual chain state.
///
/// Deliberately not serializable: serializing it would write the opaque chain
/// `reference` (on `Confirmed`) or the adapter `final_reason` (on `Rejected`)
/// into logs or wire payloads. The manual `Debug` below is redacted, so these
/// fields never leave the process through either channel.
#[derive(Clone, PartialEq, Eq)]
pub enum ChainObservation {
    /// The chain confirmed the attempt.
    ///
    /// `fill` is the exact realized amounts when the adapter can observe them
    /// (for example from a mined receipt); `None` means the confirmation is real
    /// but the amounts are unknown, and the consumer must resolve it rather than
    /// infer a fill.
    Confirmed {
        reference: String,
        fill: Option<ObservedFill>,
    },
    /// The attempt is still pending on-chain.
    Pending,
    /// The chain definitively rejected the attempt.
    Rejected { final_reason: String },
    /// The chain state could not be determined.
    Unknown,
}

impl std::fmt::Debug for ChainObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit the opaque chain reference and the adapter final reason.
        match self {
            Self::Confirmed { .. } => formatter.write_str("Confirmed"),
            Self::Pending => formatter.write_str("Pending"),
            Self::Rejected { .. } => formatter.write_str("Rejected"),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
}

/// Acknowledgement returned by a successful submission.
///
/// This is an acknowledgement only, NOT confirmation: confirmation requires a
/// subsequent [`ChainSubmissionAdapter::reconcile`] observation.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmissionReceipt {
    /// Opaque chain acknowledgement reference.
    pub reference: String,
}

impl std::fmt::Debug for SubmissionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit the opaque acknowledgement reference.
        formatter
            .debug_struct("SubmissionReceipt")
            .finish_non_exhaustive()
    }
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
///
/// # Security
///
/// This trait is a test/integration seam. A caller that can supply a signer
/// here can bypass Privy's exactly-once backstop, so production wiring MUST use
/// [`PrivySigningBoundaryAdapter`] (installed by
/// [`ExecutionRelay::production`](crate::ExecutionRelay::production)) rather
/// than a custom implementation.
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
