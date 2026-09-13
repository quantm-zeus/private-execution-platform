//! P57 — concrete `AttemptExecutor` over the Privy signing boundary and the
//! execution relay.
//!
//! This module closes the last Phase-5 gap: it adapts the landed
//! [`execution_relay::ExecutionRelay`] (which owns the reserve-before-sign,
//! exactly-once sign+submit path over `privy::PrivySigningBoundary`) to the
//! orchestrator's injected [`AttemptExecutor`] seam. It performs no I/O of its
//! own and reads no clock: every instant is the explicit `now_ms`, and the relay
//! owns the only capabilities that can reach a signer or a chain.
//!
//! # Outcome mapping (invariant RE-2)
//!
//! The relay's [`RelayOutcome`] is *observational*, not a realized fill. Its
//! `Confirmed` variant carries only an opaque chain reference; it does **not**
//! carry the amounts actually swapped. Because
//! [`AttemptResolution::Filled`](crate::AttemptResolution::Filled) requires a
//! [`RealizedFill`](crate::RealizedFill), a `Confirmed` observation **must not**
//! be turned into a fill by guessing the bound chunk. This executor therefore
//! fails closed:
//!
//! | Relay observation / error | `AttemptResolution` | Why |
//! |---|---|---|
//! | `Confirmed` | `Unknown` | No observed amounts; reconcile for evidence. |
//! | `Submitted` / `Unknown` / `Reserved` / `Signed` / `Prepared` | `Unknown` | Possibly in flight; never re-execute. |
//! | `Rejected` | `Rejected` | Definitive chain rejection. |
//! | `FailedBeforeSubmit` | `FailedBeforeSubmit` | Definitive pre-send failure. |
//! | `Err` definitive pre-send | `FailedBeforeSubmit` | No submission occurred. |
//! | `Err` ambiguous | `Unknown` | Could have been sent; never a blind retry. |
//!
//! # Definitive vs ambiguous relay errors
//!
//! A relay error is **definitive pre-send** when the relay could not have
//! reached `ChainSubmissionAdapter::submit`: the live kill switch is off
//! (`TradingDisabled`), chain health blocked the attempt before submission
//! (`ChainHealthUnavailable`), the payload or signed reference failed to bind
//! (`MissingSignedPayload`, `SignedPayloadEmpty`, `SignedPayloadTooLarge`,
//! `SignedPayloadDigestMismatch`, `SigningRequestMismatch`, `ChainMismatch`),
//! signing failed or the reservation store refused the claim (`SigningFailed`,
//! `ReservationUnavailable`, `StoreUnavailable`, `IdempotencyConflict`).
//!
//! Every other relay error is treated as **ambiguous** and mapped to `Unknown`,
//! because it cannot prove that no bytes were sent: `AdapterUnavailable`,
//! `AdapterTimeout` and an unexpected `AdapterRejected` can all follow a
//! transport that failed after sending, and `InvalidTransition` (no journal
//! entry) is especially unsafe — the relay journal is process-local, so after a
//! restart it is empty even for an attempt that *was* submitted. Mapping that to
//! a retryable `FailedBeforeSubmit` would authorize a double-send, so this
//! executor maps it to `Unknown`: fail closed, reconcile only, never retry.
//!
//! The same mapping is shared by `execute` and `reconcile`, so a live tick and a
//! restart reconciliation cannot drift.
//!
//! # Fail-closed production wiring (RE-5)
//!
//! [`RelayAttemptExecutor::production`] composes the relay over
//! `UnavailableChainAdapter` and `PrivySigningBoundaryAdapter`: the adapter
//! rejects every submission and the Privy boundary installs an always-unavailable
//! transport. No live signer, key material, network, or chain broadcast exists on
//! this path until a real adapter is installed under review.

use async_trait::async_trait;
use domain::TradeIntent;
use execution_relay::{
    AttemptReservationStore, ChainHealthBreaker, ChainSubmissionAdapter, ExecutionRelay,
    PrivySigningBoundaryAdapter, RelayError, RelayExecutionInput, RelayOutcome,
    SignedPayloadSource, SigningBoundary, UnavailableChainAdapter,
};
use policy::{PolicyContext, PolicyEngine};
use privy::PreparedExecutionRef;

use crate::attempt::BoundAttempt;
use crate::error::LimitEngineError;
use crate::orchestrator::{AttemptExecutor, AttemptResolution};
use crate::prepare::PreparedAttempt;

/// Concrete executor over the landed Privy signing boundary + execution relay.
///
/// It holds the relay (the only sign/submit capability) and the trusted
/// [`PolicyContext`] the relay records as audit provenance. `Debug` is redacted:
/// it never renders the relay's configuration, the policy context, or any
/// intent/route/amount/reference.
pub struct RelayAttemptExecutor<S, A, P, G>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    relay: ExecutionRelay<S, A, P, G>,
    policy_context: PolicyContext,
}

impl<S, A, P, G> RelayAttemptExecutor<S, A, P, G>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    /// Wires the executor from a relay and the trusted policy context.
    pub fn new(relay: ExecutionRelay<S, A, P, G>, policy_context: PolicyContext) -> Self {
        Self {
            relay,
            policy_context,
        }
    }
}

impl<S, P> RelayAttemptExecutor<S, UnavailableChainAdapter, P, PrivySigningBoundaryAdapter>
where
    S: AttemptReservationStore,
    P: SignedPayloadSource,
{
    /// **Production entry point**: relay over `UnavailableChainAdapter` +
    /// `PrivySigningBoundaryAdapter` (no network, no key material).
    ///
    /// Fail-closed until a real chain adapter and Privy transport are installed
    /// under review: the adapter reports `Unavailable`, so every `execute` fails
    /// before a reservation is claimed, and the Privy boundary's transport is
    /// always unavailable.
    pub fn production(
        policy: PolicyEngine,
        store: S,
        payload_source: P,
        breaker: ChainHealthBreaker,
        policy_context: PolicyContext,
    ) -> RelayAttemptExecutor<S, UnavailableChainAdapter, P, PrivySigningBoundaryAdapter> {
        Self::new(
            ExecutionRelay::production(policy, store, payload_source, breaker),
            policy_context,
        )
    }
}

impl<S, A, P, G> std::fmt::Debug for RelayAttemptExecutor<S, A, P, G>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the relay's injected components, the policy context, or
        // any payload-derived value.
        formatter
            .debug_struct("RelayAttemptExecutor")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S, A, P, G> AttemptExecutor for RelayAttemptExecutor<S, A, P, G>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    /// Returns the exact digest the relay binds for `intent`.
    ///
    /// It resolves the payload through the relay's additive
    /// `payload_digest_for` accessor — the *same* `payload_to_sign` lookup
    /// `execute` performs — and never signs or submits. The digest is therefore
    /// stable for the same intent and byte-identical to the digest committed
    /// inside the signing request (RE-3).
    async fn payload_digest(&self, intent: &TradeIntent) -> Result<[u8; 32], LimitEngineError> {
        self.relay
            .payload_digest_for(&intent.idempotency_key, &intent.id)
            .await
            .map(|digest| *digest.as_bytes())
            .map_err(|_| LimitEngineError::PersistenceUnavailable)
    }

    /// Signs and submits `attempt` at most once through the relay.
    ///
    /// The durable [`BoundAttempt`] supplies the opaque prepared reference and
    /// the bound intent; the live [`PreparedAttempt`] supplies the opaque
    /// `policy::ApprovedExecution`, the route, and the validated preview that the
    /// relay re-verifies inside `SigningRequest::bind`. Building the
    /// [`PreparedExecutionRef`] can only fail on an empty reference, which is a
    /// definitive pre-send failure.
    async fn execute(
        &self,
        prepared: &PreparedAttempt,
        attempt: &BoundAttempt,
        now_ms: i64,
    ) -> AttemptResolution {
        let prepared_ref = match PreparedExecutionRef::new(
            attempt.prepared_reference.clone(),
            attempt.intent.id.clone(),
            attempt.intent.idempotency_key.clone(),
        ) {
            Ok(prepared_ref) => prepared_ref,
            Err(_) => return AttemptResolution::FailedBeforeSubmit,
        };

        let input = RelayExecutionInput {
            intent: &attempt.intent,
            policy_context: &self.policy_context,
            prepared: &prepared_ref,
            approved: &prepared.approval,
            route: &prepared.route,
            preview: &prepared.preview,
            now_ms,
        };
        map_outcome(self.relay.execute(input).await)
    }

    /// Reconciles an already-reserved attempt through the relay.
    ///
    /// This never signs and never submits; the relay only queries/reconciles the
    /// chain adapter for the `attempt.attempt_key` it journaled at execute time.
    /// A `Confirmed` observation still carries no realized amounts, so it maps to
    /// `Unknown` (RE-1, RE-2).
    async fn reconcile(&self, attempt: &BoundAttempt, now_ms: i64) -> AttemptResolution {
        map_outcome(self.relay.reconcile(&attempt.attempt_key, now_ms).await)
    }
}

/// Shared relay-outcome -> attempt-resolution mapping.
///
/// See the module docs for the definitive/ambiguous error split; both `execute`
/// and `reconcile` use this one function so their behavior cannot drift.
fn map_outcome(result: Result<RelayOutcome, RelayError>) -> AttemptResolution {
    match result {
        // A `Confirmed` relay observation carries only an opaque chain reference,
        // never realized amounts. Turning it into `Filled` would fabricate the
        // bound chunk as an actual fill (RE-2), so it fails closed to `Unknown`
        // and the orchestrator reconciles for evidence it does not yet have.
        //
        // TODO(P57-followup): map a future chain adapter that observes realized
        // net input/output amounts into `AttemptResolution::Filled`; the relay
        // observation type itself does not carry them today.
        Ok(RelayOutcome::Confirmed { .. }) => AttemptResolution::Unknown,
        // Possibly in flight: reconcile, never re-execute.
        Ok(RelayOutcome::Submitted { .. })
        | Ok(RelayOutcome::Unknown)
        | Ok(RelayOutcome::Reserved)
        | Ok(RelayOutcome::Signed)
        | Ok(RelayOutcome::Prepared) => AttemptResolution::Unknown,
        // Definitive chain rejection.
        Ok(RelayOutcome::Rejected { .. }) => AttemptResolution::Rejected,
        // Definitive pre-send failure.
        Ok(RelayOutcome::FailedBeforeSubmit) => AttemptResolution::FailedBeforeSubmit,
        // Definitive pre-send errors: the relay could not have reached `submit`.
        Err(RelayError::TradingDisabled)
        | Err(RelayError::ChainHealthUnavailable)
        | Err(RelayError::SigningFailed)
        | Err(RelayError::SigningRequestMismatch)
        | Err(RelayError::ChainMismatch)
        | Err(RelayError::MissingSignedPayload)
        | Err(RelayError::SignedPayloadEmpty)
        | Err(RelayError::SignedPayloadTooLarge)
        | Err(RelayError::SignedPayloadDigestMismatch)
        | Err(RelayError::ReservationUnavailable)
        | Err(RelayError::StoreUnavailable)
        | Err(RelayError::IdempotencyConflict) => AttemptResolution::FailedBeforeSubmit,
        // Ambiguous errors: cannot prove no bytes were sent, so fail closed to
        // `Unknown`. `InvalidTransition` (no journal entry) is ambiguous because
        // the relay journal is process-local and empty after a restart even for
        // an attempt that was actually submitted.
        Err(RelayError::AdapterUnavailable)
        | Err(RelayError::AdapterTimeout)
        | Err(RelayError::AdapterRejected)
        | Err(RelayError::UnknownSubmissionState)
        | Err(RelayError::InvalidTransition) => AttemptResolution::Unknown,
    }
}
