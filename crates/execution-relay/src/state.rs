//! Reservation state machine and attempt-outcome types.
//!
//! The reservation store is the authoritative exactly-once guard for a running
//! relay: the relay claims an attempt before signing and refuses to sign, fetch,
//! or submit again for the same `(idempotency_key, request_digest)`. The shipped
//! [`InMemoryReservationStore`](crate::InMemoryReservationStore) is process-local
//! and exists for unit tests; [`DurableAttemptStore`] is the marker a store must
//! implement before the relay's production constructor accepts it, and
//! [`DeterministicDurableStore`](crate::DeterministicDurableStore) is a
//! deterministic reference implementation of that durable lifecycle.

use std::fmt;

use async_trait::async_trait;
use chain_types::ChainId;
use domain::{IdempotencyKey, IntentId, OrderStatus, TradeIntent, UserId, WalletRef};
use privy::{PayloadDigest, ProviderIdempotencyId, RequestDigest};
use sha2::{Digest, Sha256};

use crate::error::RelayError;
use crate::plan::{SubmitRequest, MAX_SIGNED_PAYLOAD_BYTES};

/// Whether an acknowledged submission is already known on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionState {
    /// The adapter acknowledged the submission but its chain state is unknown.
    Unknown,
    /// The adapter reports the submission is still pending.
    Pending,
}

/// Realized amounts a chain adapter observed for a confirmed attempt.
///
/// This is the *observational* companion to a [`RelayOutcome::Confirmed`]:
/// amounts reported by authoritative chain state (for example a mined
/// transaction receipt). It is deliberately bare-atomic: the relay carries no
/// asset binding, and the consumer (the limit engine) binds the amounts to the
/// attempt's `token_in`/`token_out` and validates them against the sealed bound
/// context before any ledger mutation. An adapter that cannot observe exact
/// amounts must report `None` rather than guess.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObservedFill {
    /// Net input actually consumed on chain, in `token_in` atomic units.
    pub net_input: u128,
    /// Net output actually received on chain, in `token_out` atomic units.
    pub net_output: u128,
}

impl fmt::Debug for ObservedFill {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: realized amounts are private execution economics.
        formatter.write_str("ObservedFill { .. }")
    }
}

/// Immutable identity that uniquely binds a durable execution attempt.
///
/// The pair `(owner, workspace)` plus the intent's idempotency key is the
/// durable uniqueness key: the same key under a different owner/workspace is a
/// distinct attempt, and the request digest recorded with it is what makes a
/// replay of the *same* attempt safe. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct AttemptBinding {
    owner: UserId,
    workspace: WalletRef,
    idempotency_key: IdempotencyKey,
    intent_id: IntentId,
    chain: ChainId,
}

impl AttemptBinding {
    /// Binds an owner, workspace, idempotency key, intent, and chain.
    pub fn new(
        owner: UserId,
        workspace: WalletRef,
        idempotency_key: IdempotencyKey,
        intent_id: IntentId,
        chain: ChainId,
    ) -> Self {
        Self {
            owner,
            workspace,
            idempotency_key,
            intent_id,
            chain,
        }
    }

    /// The owner/principal the attempt belongs to.
    pub fn owner(&self) -> &UserId {
        &self.owner
    }

    /// The wallet/workspace the attempt is executed from.
    pub fn workspace(&self) -> &WalletRef {
        &self.workspace
    }

    /// The idempotency key bound into the intent.
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// The intent identifier (stable chain reference data).
    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// The chain the attempt is bound to (stable chain reference data).
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }

    /// Builds the full owner/workspace binding for a trade intent.
    ///
    /// This is the canonical way a caller (relay, executor, reconciler) derives
    /// the exact durable identity, so every transition and read predicates the
    /// same `(owner, workspace, idempotency_key)` primary key rather than a bare
    /// key that two tenants could share.
    pub fn from_intent(intent: &TradeIntent) -> Self {
        Self::new(
            intent.user_id.clone(),
            intent.wallet_ref.clone(),
            intent.idempotency_key.clone(),
            intent.id.clone(),
            intent.chain.clone(),
        )
    }
}

impl fmt::Debug for AttemptBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit owner, workspace, and idempotency key.
        formatter.write_str("AttemptBinding { .. }")
    }
}

/// Durable attempt lifecycle status.
///
/// The canonical spelling ([`Self::as_str`]) is the value persisted by a durable
/// store; [`Self::parse`] is the fail-closed inverse for rows read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStatus {
    /// The attempt identity + digest were claimed; no signer call is recorded.
    Reserved,
    /// A signer call was durably requested (with a provider idempotency id)
    /// before the signing boundary was invoked.
    SignRequested,
    /// The signing boundary returned a reference for this attempt.
    Signed,
    /// A submission was attempted and its chain state could not be determined.
    SubmissionUnknown,
    /// The chain adapter acknowledged the submission (not yet confirmed).
    Submitted,
    /// The chain confirmed the attempt.
    Confirmed,
    /// The chain definitively rejected the attempt.
    Rejected,
    /// The attempt failed before any chain submission occurred.
    FailedBeforeSubmit,
}

impl AttemptStatus {
    /// Canonical uppercase storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "RESERVED",
            Self::SignRequested => "SIGN_REQUESTED",
            Self::Signed => "SIGNED",
            Self::SubmissionUnknown => "SUBMISSION_UNKNOWN",
            Self::Submitted => "SUBMITTED",
            Self::Confirmed => "CONFIRMED",
            Self::Rejected => "REJECTED",
            Self::FailedBeforeSubmit => "FAILED_BEFORE_SUBMIT",
        }
    }

    /// Parses a persisted status spelling, returning `None` for any unknown
    /// value so a corrupt row fails closed.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "RESERVED" => Some(Self::Reserved),
            "SIGN_REQUESTED" => Some(Self::SignRequested),
            "SIGNED" => Some(Self::Signed),
            "SUBMISSION_UNKNOWN" => Some(Self::SubmissionUnknown),
            "SUBMITTED" => Some(Self::Submitted),
            "CONFIRMED" => Some(Self::Confirmed),
            "REJECTED" => Some(Self::Rejected),
            "FAILED_BEFORE_SUBMIT" => Some(Self::FailedBeforeSubmit),
            _ => None,
        }
    }

    /// True when no further transition may occur.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Rejected | Self::FailedBeforeSubmit
        )
    }
}

/// Durable record of a fully bound submission.
///
/// It carries exactly the stable data needed to rebuild a [`SubmitRequest`] for
/// restart reconciliation: the bound identifiers, the chain, the signed
/// provider reference, and the signed payload bytes. It never carries private
/// key material. Construction recomputes the payload digest and fails closed on
/// an empty, oversize, or mismatched payload.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableSubmission {
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
    chain: ChainId,
    request_digest: RequestDigest,
    payload_digest: PayloadDigest,
    signed_reference: String,
    chain_reference: Option<String>,
    payload: Vec<u8>,
}

impl DurableSubmission {
    /// Builds a durable submission, validating the payload digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: IntentId,
        idempotency_key: IdempotencyKey,
        chain: ChainId,
        request_digest: RequestDigest,
        payload_digest: PayloadDigest,
        signed_reference: impl Into<String>,
        chain_reference: Option<String>,
        payload: Vec<u8>,
    ) -> Result<Self, RelayError> {
        let signed_reference = signed_reference.into();
        if signed_reference.trim().is_empty() {
            return Err(RelayError::SigningFailed);
        }
        if payload.is_empty() {
            return Err(RelayError::SignedPayloadEmpty);
        }
        if payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
            return Err(RelayError::SignedPayloadTooLarge);
        }
        let actual = PayloadDigest::from_bytes(Sha256::digest(&payload).into());
        if actual != payload_digest {
            return Err(RelayError::SignedPayloadDigestMismatch);
        }
        Ok(Self {
            intent_id,
            idempotency_key,
            chain,
            request_digest,
            payload_digest,
            signed_reference,
            chain_reference,
            payload,
        })
    }

    /// Builds a durable submission directly from a bound submit request.
    pub fn from_request(request: &SubmitRequest) -> Result<Self, RelayError> {
        Self::new(
            request.intent_id().clone(),
            request.idempotency_key().clone(),
            request.chain().clone(),
            *request.request_digest(),
            *request.payload_digest(),
            request.signed_reference(),
            request.chain_reference().map(str::to_string),
            request.payload().to_vec(),
        )
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

    pub fn signed_reference(&self) -> &str {
        &self.signed_reference
    }

    /// The chain acknowledgement reference observed after submission, if any.
    pub fn chain_reference(&self) -> Option<&str> {
        self.chain_reference.as_deref()
    }

    /// Records the chain acknowledgement reference after a successful submit.
    pub(crate) fn set_chain_reference(&mut self, reference: impl Into<String>) {
        let reference = reference.into();
        if !reference.trim().is_empty() {
            self.chain_reference = Some(reference);
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for DurableSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit identifiers, chain, references, digests, and payload bytes.
        formatter.write_str("DurableSubmission { .. }")
    }
}

/// Terminal or in-flight outcome of an execution attempt.
///
/// `Display`/`Debug` never reveal the opaque reference or adapter reason.
/// `Prepared`/`Reserved`/`Signed` are transient journal states; `Unknown`
/// means the submission state could not be determined and must be reconciled,
/// never blindly retried.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// The attempt is understood but not yet reserved.
    Prepared,
    /// The attempt has been claimed in the reservation store.
    Reserved,
    /// The signing boundary produced a signed reference.
    Signed,
    /// The adapter acknowledged the submission; this is not confirmation.
    Submitted {
        reference: String,
        state: SubmissionState,
    },
    /// The chain state of the attempt is unknown and requires reconciliation.
    Unknown,
    /// The chain confirmed the submission.
    ///
    /// `fill` is the exact realized amounts when the adapter observed them;
    /// `None` means the confirmation is real but the amounts are not yet known,
    /// which a consumer must treat as unresolved (`Unknown`) rather than infer.
    Confirmed {
        reference: String,
        fill: Option<ObservedFill>,
    },
    /// The chain definitively rejected the submission.
    Rejected { final_reason: String },
    /// The attempt failed before any chain submission occurred.
    FailedBeforeSubmit,
}

impl RelayOutcome {
    /// Maps the relay outcome onto the canonical order status.
    ///
    /// No new [`OrderStatus`] variant is introduced: an explicit later requote
    /// is what moves `FailedBeforeSubmit` back onto a retryable path.
    pub fn order_status(&self) -> OrderStatus {
        match self {
            Self::Prepared
            | Self::Reserved
            | Self::Signed
            | Self::Submitted { .. }
            | Self::Unknown => OrderStatus::Executing,
            Self::Confirmed { .. } => OrderStatus::Filled,
            Self::Rejected { .. } => OrderStatus::FailedFinal,
            Self::FailedBeforeSubmit => OrderStatus::FailedRetryable,
        }
    }

    /// Maps the relay outcome onto the durable attempt status a store persists.
    ///
    /// `Unknown` maps to [`AttemptStatus::SubmissionUnknown`] (reconcile, never
    /// retry); a `Submitted` acknowledgement maps to [`AttemptStatus::Submitted`]
    /// and is **not** a confirmation.
    pub fn attempt_status(&self) -> AttemptStatus {
        match self {
            Self::Prepared | Self::Reserved => AttemptStatus::Reserved,
            Self::Signed => AttemptStatus::Signed,
            Self::Submitted { .. } => AttemptStatus::Submitted,
            Self::Unknown => AttemptStatus::SubmissionUnknown,
            Self::Confirmed { .. } => AttemptStatus::Confirmed,
            Self::Rejected { .. } => AttemptStatus::Rejected,
            Self::FailedBeforeSubmit => AttemptStatus::FailedBeforeSubmit,
        }
    }
}

impl fmt::Debug for RelayOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Omit the opaque chain reference and the adapter final reason.
        match self {
            Self::Prepared => formatter.write_str("Prepared"),
            Self::Reserved => formatter.write_str("Reserved"),
            Self::Signed => formatter.write_str("Signed"),
            Self::Submitted { state, .. } => formatter
                .debug_struct("Submitted")
                .field("state", state)
                .finish_non_exhaustive(),
            Self::Unknown => formatter.write_str("Unknown"),
            Self::Confirmed { .. } => formatter.write_str("Confirmed"),
            Self::Rejected { .. } => formatter.write_str("Rejected"),
            Self::FailedBeforeSubmit => formatter.write_str("FailedBeforeSubmit"),
        }
    }
}

/// Result of claiming an attempt for an idempotency key + request digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The attempt was claimed for the first time; the caller may continue.
    Reserved,
    /// The same key + digest already exists; return the stored outcome.
    AlreadyReserved(RelayOutcome),
    /// The key exists with a different request digest.
    Conflict,
}

/// Exactly-once reservation store.
///
/// The shipped [`InMemoryReservationStore`](crate::InMemoryReservationStore) is
/// process-local. Implementations must be deterministic for a given input
/// sequence and must never permit a second reservation of the same
/// `(key, digest)` to be treated as a fresh attempt.
///
/// # Durable lifecycle (additive)
///
/// The default bodies of the transition methods below are no-ops so that
/// process-local unit-test stores keep compiling. A production store implements
/// them and additionally implements the [`DurableAttemptStore`] marker, which is
/// what the relay's production constructor requires. Every transition is
/// persisted *before* the corresponding consequential boundary: `RESERVED`
/// before signing, `SIGN_REQUESTED` before the signer call, `SIGNED` before the
/// payload is fetched, the bound submission before `submit`, and the terminal
/// outcome after.
#[async_trait]
pub trait AttemptReservationStore: Send + Sync {
    /// Claims `(key, digest)`, returning the existing outcome when present.
    async fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError>;

    /// Claims the full `(owner, workspace, idempotency_key)` identity.
    ///
    /// The default delegates to [`Self::reserve`] so process-local stores keep
    /// working; a durable store overrides this to enforce the owner/workspace
    /// scoping and returns [`Reservation::Conflict`] when the key exists with a
    /// different request digest.
    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        self.reserve(binding.idempotency_key(), digest).await
    }

    /// Durably records the `SIGN_REQUESTED` transition before the signer is
    /// called, together with the stable provider idempotency identifier.
    ///
    /// The default is a no-op. A durable store must persist this **before** the
    /// signing boundary is invoked; a store error must abort the attempt
    /// fail-closed without signing. The full owner/workspace binding is carried
    /// so the transition can only ever land on the caller's own attempt.
    async fn record_sign_requested(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        let _ = (binding, digest, provider_idempotency);
        Ok(())
    }

    /// Records that the signing boundary produced a reference for `binding`.
    async fn record_signed(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<(), RelayError>;

    /// Records `SIGNED` together with the opaque signed reference.
    ///
    /// The default forwards to [`Self::record_signed`] so existing stores keep
    /// working; a durable store persists the reference for reconciliation.
    async fn record_signed_reference(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        let _ = signed_reference;
        self.record_signed(binding, digest).await
    }

    /// Durably persists the fully bound submission **before** the chain adapter
    /// is called, so a restart can reconcile it instead of resubmitting.
    ///
    /// The default is a no-op (process-local tests keep an in-memory journal). A
    /// durable store error must abort before any submit.
    async fn record_submission(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        request: &SubmitRequest,
    ) -> Result<(), RelayError> {
        let _ = (binding, digest, request);
        Ok(())
    }

    /// Loads the durable submission for restart reconciliation.
    ///
    /// The lookup is scoped to the full `(owner, workspace, idempotency_key)`
    /// binding, so a caller can never select another tenant's attempt. Returns
    /// `Ok(None)` when no durable submission exists (the default), and fails
    /// closed if the store is unavailable.
    async fn load_submission(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        let _ = binding;
        Ok(None)
    }

    /// Loads the durable outcome for restart reconciliation and monotonicity.
    ///
    /// Returns `Ok(None)` when no outcome is stored (the default). A terminal
    /// outcome ([`AttemptStatus::is_terminal`]) lets `reconcile` return it
    /// directly, so a later ambiguous chain read can never downgrade a confirmed,
    /// rejected, or definitively pre-send-failed attempt.
    async fn load_outcome(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<RelayOutcome>, RelayError> {
        let _ = binding;
        Ok(None)
    }

    /// Records the terminal/in-flight outcome for `binding`.
    async fn record_outcome(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError>;
}

/// Marker for a store that claims durable persistence of the full attempt
/// lifecycle.
///
/// Only stores implementing this marker can be passed to the relay's production
/// constructors ([`ExecutionRelay::production`](crate::ExecutionRelay::production),
/// `production_with_chain`). The shipped durable adapter is
/// `execution_store::PostgresExecutionAttemptStore`; the relay's default
/// composition installs a fail-closed unavailable durable store rather than an
/// in-memory one.
///
/// # Honest scope
///
/// This is a type-level claim, not a proof: [`AttemptReservationStore`] keeps
/// no-op defaults for the durable transitions so the process-local test seam
/// (`ExecutionRelay::new_with_seams`) stays usable, and a malicious or careless
/// implementor could satisfy the marker without real durability. Production
/// composition must inject the Postgres adapter; the default is fail-closed.
pub trait DurableAttemptStore: AttemptReservationStore {}

#[async_trait]
impl<T: AttemptReservationStore + ?Sized> AttemptReservationStore for std::sync::Arc<T> {
    async fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        (**self).reserve(key, digest).await
    }

    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        (**self).reserve_bound(binding, digest).await
    }

    async fn record_sign_requested(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        (**self)
            .record_sign_requested(binding, digest, provider_idempotency)
            .await
    }

    async fn record_signed(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        (**self).record_signed(binding, digest).await
    }

    async fn record_signed_reference(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        (**self)
            .record_signed_reference(binding, digest, signed_reference)
            .await
    }

    async fn record_submission(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        request: &SubmitRequest,
    ) -> Result<(), RelayError> {
        (**self).record_submission(binding, digest, request).await
    }

    async fn load_submission(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        (**self).load_submission(binding).await
    }

    async fn load_outcome(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<RelayOutcome>, RelayError> {
        (**self).load_outcome(binding).await
    }

    async fn record_outcome(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        (**self).record_outcome(binding, digest, outcome).await
    }
}

impl<T: DurableAttemptStore + ?Sized> DurableAttemptStore for std::sync::Arc<T> {}
