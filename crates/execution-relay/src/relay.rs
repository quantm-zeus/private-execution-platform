//! The deterministic execution relay state machine.
//!
//! `execute` checks the kill switch, checks chain health, claims an attempt in
//! the reservation store, signs the bound request, binds the signed payload,
//! and submits at most once. `reconcile` only queries/reconciles; it can never
//! submit.

use std::collections::HashMap;
use std::sync::Mutex;

use domain::{IdempotencyKey, RoutePlan, TradeIntent, ValidatedExecutionPreview};
use policy::{ApprovedExecution, PolicyContext, PolicyEngine};
use privy::{PreparedExecutionRef, RequestDigest, SigningRequest};

use crate::adapter::{
    ChainObservation, ChainSubmissionAdapter, PrivySigningBoundaryAdapter, SigningBoundary,
    UnavailableChainAdapter,
};
use crate::error::RelayError;
use crate::health::{ChainHealth, ChainHealthBreaker};
use crate::plan::{SignedPayloadSource, SubmitRequest};
use crate::state::{AttemptReservationStore, RelayOutcome, Reservation, SubmissionState};

/// Trusted inputs for a single relay execution attempt.
///
/// Every field is borrowed and never mutated. `policy_context` is carried for
/// caller provenance; the approval it produced is supplied as `approved` and is
/// re-verified by `SigningRequest::bind` against the live policy engine.
pub struct RelayExecutionInput<'a> {
    pub intent: &'a TradeIntent,
    pub policy_context: &'a PolicyContext,
    pub prepared: &'a PreparedExecutionRef,
    pub approved: &'a ApprovedExecution,
    pub route: &'a RoutePlan,
    pub preview: &'a ValidatedExecutionPreview,
    pub now_ms: i64,
}

/// Single-chain transaction relay.
///
/// The injected components are held by value so the relay is usable from any
/// runner/worker (`Send + Sync`). The reservation store and journal supply the
/// exactly-once guarantee; the breaker supplies deterministic chain gating.
pub struct ExecutionRelay<S, A, P, G> {
    policy: PolicyEngine,
    store: S,
    adapter: A,
    payload_source: P,
    signing: G,
    breaker: ChainHealthBreaker,
    journal: Mutex<HashMap<IdempotencyKey, SubmitRequest>>,
}

impl<S, A, P, G> ExecutionRelay<S, A, P, G>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    /// Wires the relay from its trusted policy engine and injected seams.
    pub fn new(
        policy: PolicyEngine,
        store: S,
        adapter: A,
        payload_source: P,
        signing: G,
        breaker: ChainHealthBreaker,
    ) -> Self {
        Self {
            policy,
            store,
            adapter,
            payload_source,
            signing,
            breaker,
            journal: Mutex::new(HashMap::new()),
        }
    }

    /// Executes one attempt, fail-closed and with no blind retry.
    ///
    /// The reservation is claimed before signing, so a duplicate attempt never
    /// reaches the signing boundary or the chain adapter.
    pub async fn execute(
        &self,
        input: RelayExecutionInput<'_>,
    ) -> Result<RelayOutcome, RelayError> {
        // 1. Live kill switch.
        if !self.policy.is_trading_enabled() {
            return Err(RelayError::TradingDisabled);
        }

        // 2. Chain health. The adapter's own reading feeds the breaker, and an
        //    explicitly unavailable adapter blocks immediately.
        let chain = &input.intent.chain;
        let adapter_health = self.adapter.health(input.now_ms);
        self.breaker.observe(chain, adapter_health, input.now_ms);
        if adapter_health == ChainHealth::Unavailable
            || !self.breaker.check_allowed(chain, input.now_ms)
        {
            return Err(RelayError::ChainHealthUnavailable);
        }

        // 3. Payload whose digest is committed into the signing request.
        let payload_to_sign = self
            .payload_source
            .payload_to_sign(&input.intent.idempotency_key, &input.intent.id)
            .await
            .map_err(|_| RelayError::MissingSignedPayload)?;

        // 4. Build the fully bound signing request (pure; no signing yet).
        let signing_request = SigningRequest::bind(
            &self.policy,
            input.approved,
            input.prepared,
            input.intent,
            input.route,
            input.preview,
            *payload_to_sign.digest(),
            input.now_ms,
        )
        .map_err(|_| RelayError::SigningFailed)?;
        let request_digest = *signing_request.request_digest();
        let key = &input.intent.idempotency_key;

        // 5. Claim the attempt BEFORE signing. Duplicates return their stored
        //    outcome and never sign; a conflicting digest is rejected.
        match self.store.reserve(key, &request_digest) {
            Ok(Reservation::Reserved) => {}
            Ok(Reservation::AlreadyReserved(outcome)) => return Ok(outcome),
            Ok(Reservation::Conflict) => return Err(RelayError::IdempotencyConflict),
            Err(_) => return Err(RelayError::ReservationUnavailable),
        }

        // 6. Sign once. Any failure is recorded and never retried here.
        let signed = match self.signing.sign(&signing_request).await {
            Ok(signed) => signed,
            Err(_) => {
                self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
                return Err(RelayError::SigningFailed);
            }
        };
        if signed.request_digest() != signing_request.request_digest()
            || signed.intent_id() != signing_request.intent_id()
            || signed.idempotency_key() != signing_request.idempotency_key()
        {
            self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
            return Err(RelayError::SigningRequestMismatch);
        }

        // 7. Mark the signing success durably.
        if self.store.record_signed(key, &request_digest).is_err() {
            self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
            return Ok(RelayOutcome::FailedBeforeSubmit);
        }

        // 8. Fetch the payload the signed reference attests to.
        let signed_payload = match self.payload_source.signed_payload(&signed).await {
            Ok(payload) => payload,
            Err(_) => {
                self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
                return Err(RelayError::MissingSignedPayload);
            }
        };

        // 9. Re-verify every binding before anything can be submitted.
        let request = match SubmitRequest::bind(&signing_request, &signed, &signed_payload, chain) {
            Ok(request) => request,
            Err(error) => {
                self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
                return Err(error);
            }
        };
        self.journal_insert(key, &request);

        // 10. Submit at most once. There is no retry loop anywhere.
        match self.adapter.submit(&request).await {
            Ok(receipt) => {
                self.breaker.record_success(chain);
                if receipt.reference.trim().is_empty() {
                    self.record_outcome(key, &request_digest, RelayOutcome::Unknown);
                    return Ok(RelayOutcome::Unknown);
                }
                let outcome = RelayOutcome::Submitted {
                    reference: receipt.reference,
                    state: SubmissionState::Unknown,
                };
                self.record_outcome(key, &request_digest, outcome.clone());
                Ok(outcome)
            }
            Err(RelayError::AdapterRejected) => {
                self.breaker.record_success(chain);
                let outcome = RelayOutcome::Rejected {
                    final_reason: "adapter rejected submission".to_string(),
                };
                self.record_outcome(key, &request_digest, outcome.clone());
                Ok(outcome)
            }
            Err(RelayError::AdapterUnavailable) => {
                self.breaker.record_failure(chain, input.now_ms);
                self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
                Ok(RelayOutcome::FailedBeforeSubmit)
            }
            Err(_) => {
                // Timeout or any other ambiguous failure: the send may have
                // happened, so the safe terminal state is Unknown.
                self.breaker.record_failure(chain, input.now_ms);
                self.record_outcome(key, &request_digest, RelayOutcome::Unknown);
                Ok(RelayOutcome::Unknown)
            }
        }
    }

    /// Reconciles a previously executed attempt. NEVER submits.
    pub async fn reconcile(
        &self,
        key: &IdempotencyKey,
        now_ms: i64,
    ) -> Result<RelayOutcome, RelayError> {
        let request = self.journal_get(key).ok_or(RelayError::InvalidTransition)?;

        let observation = match self.adapter.query(&request, now_ms).await {
            Ok(ChainObservation::Unknown) | Err(_) => self
                .adapter
                .reconcile(&request, now_ms)
                .await
                .map_err(|_| RelayError::AdapterUnavailable)?,
            Ok(observation) => observation,
        };

        let outcome = match observation {
            ChainObservation::Confirmed { reference } => RelayOutcome::Confirmed { reference },
            ChainObservation::Rejected { final_reason } => RelayOutcome::Rejected { final_reason },
            ChainObservation::Pending | ChainObservation::Unknown => RelayOutcome::Unknown,
        };
        self.record_outcome(key, request.request_digest(), outcome.clone());
        Ok(outcome)
    }

    fn record_outcome(&self, key: &IdempotencyKey, digest: &RequestDigest, outcome: RelayOutcome) {
        let _ = self.store.record_outcome(key, digest, outcome);
    }

    fn journal_insert(&self, key: &IdempotencyKey, request: &SubmitRequest) {
        let mut journal = crate::lock(&self.journal);
        journal.insert(key.clone(), request.clone());
    }

    fn journal_get(&self, key: &IdempotencyKey) -> Option<SubmitRequest> {
        let journal = crate::lock(&self.journal);
        journal.get(key).cloned()
    }
}

impl<S, P> ExecutionRelay<S, UnavailableChainAdapter, P, PrivySigningBoundaryAdapter>
where
    S: AttemptReservationStore,
    P: SignedPayloadSource,
{
    /// Production composition: fail-closed chain adapter and the real
    /// (currently unavailable) Privy signing boundary.
    pub fn production(
        policy: PolicyEngine,
        store: S,
        payload_source: P,
        breaker: ChainHealthBreaker,
    ) -> Self {
        Self::new(
            policy,
            store,
            UnavailableChainAdapter::new(),
            payload_source,
            PrivySigningBoundaryAdapter::new(),
            breaker,
        )
    }
}
