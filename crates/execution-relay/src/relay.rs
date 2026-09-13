//! The deterministic execution relay state machine.
//!
//! `execute` checks the kill switch, checks chain health, claims an attempt in
//! the reservation store, signs the bound request, binds the signed payload,
//! and submits at most once. `reconcile` only queries/reconciles; it can never
//! submit.

use std::collections::HashMap;
use std::sync::Mutex;

use domain::{IdempotencyKey, IntentId, RoutePlan, TradeIntent, ValidatedExecutionPreview};
use policy::{ApprovedExecution, PolicyContext, PolicyEngine};
use privy::{PayloadDigest, PreparedExecutionRef, RequestDigest, SigningRequest};

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
/// Every field is borrowed and never mutated. `policy_context` is retained as
/// caller/audit provenance only: the relay does **not** re-run turnover, size,
/// or venue limits at relay time. The only policy checks on this path are the
/// live kill switch (`PolicyEngine::is_trading_enabled`) and the deterministic
/// approval/preview binding re-verified inside `SigningRequest::bind`.
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
    /// Wires the relay from a caller-supplied signing seam.
    ///
    /// # Security
    ///
    /// This is a test/integration seam, not a production constructor. A caller
    /// with a valid approval can inject an arbitrary [`SigningBoundary`], which
    /// **bypasses Privy's exactly-once signing backstop**. Production wiring
    /// MUST use [`ExecutionRelay::production`] (or explicitly install
    /// [`PrivySigningBoundaryAdapter`]) so the real Privy boundary owns signing.
    /// This constructor exists only so integration tests can drive the relay
    /// state machine without a live signer.
    #[doc(hidden)]
    pub fn new_with_seams(
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

        // 10. Admit the submit exactly once. `check_allowed` above is a
        //     read-only gate, so any failure before this point leaves the
        //     half-open probe untouched; only this admission consumes it. The
        //     returned guard releases the probe as a failure if this future is
        //     dropped before the submission resolves (cancellation safety).
        let probe = match self.breaker.admit_probe(chain, input.now_ms) {
            Some(probe) => probe,
            None => {
                // A concurrent attempt consumed the probe between the gate and
                // the submit: fail closed without sending. No chain call
                // occurred, so this is a definitive pre-send failure.
                self.record_outcome(key, &request_digest, RelayOutcome::FailedBeforeSubmit);
                return Err(RelayError::ChainHealthUnavailable);
            }
        };

        // 11. Submit at most once. There is no retry loop anywhere. The probe is
        //     resolved explicitly once `submit` returns; if the await is
        //     cancelled the guard's `Drop` resolves it as a failure.
        match self.adapter.submit(&request).await {
            Ok(receipt) => {
                probe.success();
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
                probe.success();
                let outcome = RelayOutcome::Rejected {
                    final_reason: "adapter rejected submission".to_string(),
                };
                self.record_outcome(key, &request_digest, outcome.clone());
                Ok(outcome)
            }
            Err(_) => {
                // Any other transport-level failure (`AdapterUnavailable`,
                // `AdapterTimeout`, or an undocumented error) may have sent
                // before failing, so the relay cannot assume "no send". Store
                // and return Unknown: reconciliation is required, never a retry.
                probe.failure(input.now_ms);
                self.record_outcome(key, &request_digest, RelayOutcome::Unknown);
                Ok(RelayOutcome::Unknown)
            }
        }
    }

    /// Resolves the payload digest the relay would bind into a signing request
    /// for `(idempotency_key, intent_id)`.
    ///
    /// This is an additive, non-invasive accessor: it performs the *same*
    /// `payload_to_sign` lookup `execute` performs at step 3 and returns the
    /// digest without signing, reserving, or submitting anything. A caller (for
    /// example a limit-order `AttemptExecutor`) can therefore expose the exact
    /// digest the relay will commit to, deterministically and without a signer.
    pub async fn payload_digest_for(
        &self,
        idempotency_key: &IdempotencyKey,
        intent_id: &IntentId,
    ) -> Result<PayloadDigest, RelayError> {
        self.payload_source
            .payload_to_sign(idempotency_key, intent_id)
            .await
            .map(|payload| *payload.digest())
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
            ChainObservation::Confirmed { reference, fill } => {
                RelayOutcome::Confirmed { reference, fill }
            }
            ChainObservation::Rejected { final_reason } => RelayOutcome::Rejected { final_reason },
            ChainObservation::Pending | ChainObservation::Unknown => RelayOutcome::Unknown,
        };
        self.record_outcome(key, request.request_digest(), outcome.clone());
        Ok(outcome)
    }

    /// Borrows the chain health breaker (diagnostics and tests only).
    #[doc(hidden)]
    pub fn breaker(&self) -> &ChainHealthBreaker {
        &self.breaker
    }

    /// Persists the terminal/in-flight outcome, best-effort.
    ///
    /// A store write failure is deliberately swallowed: `record_outcome` runs
    /// after the submission (or after a definitive pre-send failure) and a
    /// transient journal error must not turn a completed attempt into an error a
    /// caller might retry. The at-most-once submit invariant is unaffected — the
    /// reservation claimed *before* signing still blocks any resubmission for the
    /// same `(key, digest)`. A duplicate may therefore observe a stale in-memory
    /// outcome, but it can never reach the signing boundary or the chain adapter
    /// again.
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
    /// **Production entry point.**
    ///
    /// Fail-closed composition: [`UnavailableChainAdapter`] performs no network
    /// I/O and rejects every submission, and [`PrivySigningBoundaryAdapter`]
    /// wraps the real P40 Privy boundary (whose public constructor installs an
    /// always-unavailable transport). Use this rather than
    /// [`ExecutionRelay::new_with_seams`] for any non-test wiring.
    pub fn production(
        policy: PolicyEngine,
        store: S,
        payload_source: P,
        breaker: ChainHealthBreaker,
    ) -> Self {
        Self::new_with_seams(
            policy,
            store,
            UnavailableChainAdapter::new(),
            payload_source,
            PrivySigningBoundaryAdapter::new(),
            breaker,
        )
    }
}
