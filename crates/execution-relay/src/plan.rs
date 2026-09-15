//! Bound submission plan: signed payload, signed reference, and submit request.
//!
//! `SubmitRequest::bind` re-verifies every binding fail-closed before a request
//! can reach a [`ChainSubmissionAdapter`](crate::adapter::ChainSubmissionAdapter):
//! the signed reference must attest to the exact signing request, the target
//! chain must match, and the payload must be non-empty with a digest equal to
//! the digest committed inside the signing request.

use std::sync::Arc;

use async_trait::async_trait;
use chain_types::ChainId;
use domain::{IdempotencyKey, IntentId};
use privy::{PayloadDigest, RequestDigest, SigningRequest};
use sha2::{Digest, Sha256};

use crate::error::RelayError;

/// Upper bound on a signed payload accepted by the relay (1 MiB).
///
/// The bound is a defensive sanity limit, not a chain rule: it keeps an
/// injected payload source from handing the relay an unbounded buffer.
pub const MAX_SIGNED_PAYLOAD_BYTES: usize = 1 << 20;

/// A signed payload plus its canonical SHA-256 digest.
///
/// The digest is an internal binding token, not the chain's own signature hash.
/// Construction rejects empty and oversize payloads; the bytes are never
/// rendered through `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedPayload {
    bytes: Vec<u8>,
    digest: PayloadDigest,
}

impl SignedPayload {
    /// Hashes `bytes` with SHA-256, rejecting an empty or oversize payload.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RelayError> {
        if bytes.is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        if bytes.len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(RelayError::SignedPayloadTooLarge);
        }
        let digest = PayloadDigest::from_bytes(Sha256::digest(&bytes).into());
        Ok(Self { bytes, digest })
    }

    /// Borrows the raw payload bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest bound at construction.
    pub fn digest(&self) -> &PayloadDigest {
        &self.digest
    }
}

impl std::fmt::Debug for SignedPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit the payload bytes and digest.
        formatter
            .debug_struct("SignedPayload")
            .finish_non_exhaustive()
    }
}

/// P41-owned attestation that a signing boundary signed a [`SigningRequest`].
///
/// It mirrors `privy::SignedExecutionRef`, which is intentionally not
/// constructible outside `privy`. The production signing adapter converts the
/// real Privy reference into this type; the relay only ever trusts the
/// re-verified copy.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedExecutionRef {
    reference: String,
    request_digest: RequestDigest,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
}

impl SignedExecutionRef {
    /// Builds an attestation, rejecting an empty reference.
    ///
    /// This is a raw test seam: it attests to a signing request without proof
    /// that Privy signed it, so production code must obtain this type from
    /// [`PrivySigningBoundaryAdapter`](crate::PrivySigningBoundaryAdapter)
    /// instead of constructing it directly.
    #[doc(hidden)]
    pub fn new(
        reference: impl Into<String>,
        request_digest: RequestDigest,
        intent_id: IntentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, RelayError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(RelayError::SigningFailed);
        }
        Ok(Self {
            reference,
            request_digest,
            intent_id,
            idempotency_key,
        })
    }

    /// Opaque signing reference. Never rendered through `Debug`.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// The canonical signing request digest this reference attests to.
    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    /// The intent the signing request was bound to.
    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// The idempotency key the signing request was bound to.
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

impl std::fmt::Debug for SignedExecutionRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit the reference, identifiers, and digest bytes.
        formatter
            .debug_struct("SignedExecutionRef")
            .finish_non_exhaustive()
    }
}

/// A fully bound, adapter-facing chain submission request.
///
/// It can only be produced by [`SubmitRequest::bind`], which proves the signed
/// reference, signing request, chain, and payload all agree.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmitRequest {
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
    chain: ChainId,
    request_digest: RequestDigest,
    payload_digest: PayloadDigest,
    signed_reference: String,
    /// Broadcast/chain reference observed after a successful submission.
    ///
    /// Absent before submission and on a freshly bound request. After a
    /// successful submit the relay (and the durable store) record the chain
    /// acknowledgement here so reconciliation queries the chain by its own
    /// reference rather than by the signer's opaque reference.
    chain_reference: Option<String>,
    payload: Vec<u8>,
}

impl SubmitRequest {
    /// Binds a signing request, signed reference, signed payload, and chain.
    ///
    /// Fails closed (redacted errors) when the signed reference does not attest
    /// to `signing`, the chain differs, the payload is empty/oversize, or the
    /// payload digest differs from the digest committed in `signing`.
    pub fn bind(
        signing: &SigningRequest,
        signed: &SignedExecutionRef,
        payload: &SignedPayload,
        chain: &ChainId,
    ) -> Result<Self, RelayError> {
        if signed.request_digest() != signing.request_digest()
            || signed.intent_id() != signing.intent_id()
            || signed.idempotency_key() != signing.idempotency_key()
        {
            return Err(RelayError::SigningRequestMismatch);
        }
        if chain != signing.chain() {
            return Err(RelayError::ChainMismatch);
        }
        if payload.bytes().is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        if payload.bytes().len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(RelayError::SignedPayloadTooLarge);
        }
        if payload.digest() != signing.payload_digest() {
            return Err(RelayError::SignedPayloadDigestMismatch);
        }

        Ok(Self {
            intent_id: signing.intent_id().clone(),
            idempotency_key: signing.idempotency_key().clone(),
            chain: chain.clone(),
            request_digest: *signing.request_digest(),
            payload_digest: *signing.payload_digest(),
            signed_reference: signed.reference().to_string(),
            chain_reference: None,
            payload: payload.bytes().to_vec(),
        })
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    pub fn payload_digest(&self) -> &PayloadDigest {
        &self.payload_digest
    }

    /// Opaque signing reference the adapter may forward.
    pub fn signed_reference(&self) -> &str {
        &self.signed_reference
    }

    /// The chain acknowledgement reference, once a submission succeeded.
    ///
    /// `None` before submission. A reconciling adapter MUST prefer this over
    /// [`Self::signed_reference`] when present, because the signer reference is
    /// not necessarily the chain transaction hash.
    pub fn chain_reference(&self) -> Option<&str> {
        self.chain_reference.as_deref()
    }

    /// The reference an adapter should use to query/reconcile this submission:
    /// the chain reference when known, otherwise the signer reference.
    pub fn reconciliation_reference(&self) -> &str {
        self.chain_reference
            .as_deref()
            .unwrap_or(&self.signed_reference)
    }

    /// Records the chain acknowledgement reference on this request.
    #[must_use]
    pub fn with_chain_reference(mut self, reference: impl Into<String>) -> Self {
        let reference = reference.into();
        if !reference.trim().is_empty() {
            self.chain_reference = Some(reference);
        }
        self
    }

    /// The exact payload bytes to submit.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Rebuilds a bound submit request from a durably persisted
    /// [`DurableSubmission`](crate::DurableSubmission).
    ///
    /// This is the restart-reconciliation seam: a durable store persists the
    /// stable binding data before submission, and on restart the relay uses this
    /// constructor to hand the same request to the adapter's read-only
    /// `query`/`reconcile`. It re-validates the payload length and digest so a
    /// corrupt or tampered row fails closed rather than reconciling a different
    /// transaction. It performs no signing and no submission.
    #[doc(hidden)]
    pub fn restore(submission: &crate::state::DurableSubmission) -> Result<Self, RelayError> {
        let payload = submission.payload();
        if payload.is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        if payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(RelayError::SignedPayloadTooLarge);
        }
        let recomputed = PayloadDigest::from_bytes(Sha256::digest(payload).into());
        if recomputed != *submission.payload_digest() {
            return Err(RelayError::SignedPayloadDigestMismatch);
        }
        Ok(Self {
            intent_id: submission.intent_id().clone(),
            idempotency_key: submission.idempotency_key().clone(),
            chain: submission.chain().clone(),
            request_digest: *submission.request_digest(),
            payload_digest: *submission.payload_digest(),
            signed_reference: submission.signed_reference().to_string(),
            chain_reference: submission.chain_reference().map(str::to_string),
            payload: payload.to_vec(),
        })
    }
}

impl std::fmt::Debug for SubmitRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit identifiers, references, digests, chain, and payload bytes.
        formatter
            .debug_struct("SubmitRequest")
            .finish_non_exhaustive()
    }
}

/// Injected source of the payload bound into a signing request and the payload
/// attested by the resulting signed reference.
#[async_trait]
pub trait SignedPayloadSource: Send + Sync {
    /// Returns the payload whose digest is bound into the signing request,
    /// before any signed reference exists.
    ///
    /// This is the P41 adaptation that breaks the digest circularity: the real
    /// [`SigningRequest::bind`] needs a payload digest before the signing
    /// boundary can produce a reference, while the post-sign retrieval method
    /// below needs that reference.
    async fn payload_to_sign(
        &self,
        key: &IdempotencyKey,
        intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError>;

    /// Returns the payload attested by a signed reference. Its digest must equal
    /// the digest committed in the corresponding signing request.
    async fn signed_payload(
        &self,
        signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError>;
}

#[async_trait]
impl<T: SignedPayloadSource + ?Sized> SignedPayloadSource for Arc<T> {
    async fn payload_to_sign(
        &self,
        key: &IdempotencyKey,
        intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        (**self).payload_to_sign(key, intent_id).await
    }

    async fn signed_payload(
        &self,
        signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        (**self).signed_payload(signed).await
    }
}
