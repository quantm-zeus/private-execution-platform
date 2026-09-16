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
use crate::signing_health::SigningFailureBreaker;
use crate::state::{
    AttemptBinding, AttemptReservationStore, DurableAttemptStore, RelayOutcome, Reservation,
    SubmissionState,
};

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
    signing_breaker: SigningFailureBreaker,
    /// Process-local submission cache for the current process. Keyed by the full
    /// `(owner, workspace, idempotency_key)` identity so two owners reusing a key
    /// can never overwrite each other's entry; `reconcile` fails closed on an
    /// ambiguous key rather than reconciling the wrong attempt.
    journal: Mutex<HashMap<(String, String, IdempotencyKey), SubmitRequest>>,
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
            signing_breaker: SigningFailureBreaker::default_policy(),
            journal: Mutex::new(HashMap::new()),
        }
    }

    /// Overrides the signing-failure breaker policy (additive; test/integration
    /// seam). The default is [`SigningFailureBreaker::default_policy`].
    pub fn with_signing_breaker(mut self, breaker: SigningFailureBreaker) -> Self {
        self.signing_breaker = breaker;
        self
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
        let binding = AttemptBinding::new(
            input.intent.user_id.clone(),
            input.intent.wallet_ref.clone(),
            input.intent.idempotency_key.clone(),
            input.intent.id.clone(),
            input.intent.chain.clone(),
        );

        // 5. Claim the attempt BEFORE signing. Duplicates return their stored
        //    outcome and never sign; a conflicting digest is rejected. The claim
        //    is bound to the full owner/workspace/idempotency-key identity so a
        //    durable store can enforce the unique constraint.
        match self.store.reserve_bound(&binding, &request_digest).await {
            Ok(Reservation::Reserved) => {}
            Ok(Reservation::AlreadyReserved(outcome)) => return Ok(outcome),
            Ok(Reservation::Conflict) => return Err(RelayError::IdempotencyConflict),
            Err(_) => return Err(RelayError::ReservationUnavailable),
        }

        // 5b. Durably record SIGN_REQUESTED, with a stable provider idempotency
        //     identifier, BEFORE the signing boundary is invoked. A store failure
        //     aborts fail-closed with no signer call.
        let provider_idempotency = signing_request.provider_idempotency_id();
        if self
            .store
            .record_sign_requested(&binding, &request_digest, &provider_idempotency)
            .await
            .is_err()
        {
            self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                .await;
            return Err(RelayError::StoreUnavailable);
        }

        // 6. Admit a signing attempt through the signing-failure breaker, then
        //    sign once. The breaker gate is additive: the kill switch (step 1)
        //    and chain-health gate (step 2) still run first and can never be
        //    bypassed. The reservation is already claimed, so a blocked
        //    admission is a definitive pre-send failure. A signer failure or a
        //    mismatched reference is recorded and never retried here. The guard
        //    resolves the half-open probe explicitly; if this future is dropped
        //    mid-sign its `Drop` resolves it as a failure (cancellation safety).
        let guard = match self.signing_breaker.admit_probe(input.now_ms) {
            Some(guard) => guard,
            None => {
                self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                    .await;
                return Err(RelayError::SigningUnavailable);
            }
        };
        let signed = match self.signing.sign(&signing_request).await {
            Ok(signed) => signed,
            Err(_) => {
                guard.failure(input.now_ms);
                self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                    .await;
                return Err(RelayError::SigningFailed);
            }
        };
        if signed.request_digest() != signing_request.request_digest()
            || signed.intent_id() != signing_request.intent_id()
            || signed.idempotency_key() != signing_request.idempotency_key()
        {
            guard.failure(input.now_ms);
            self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                .await;
            return Err(RelayError::SigningRequestMismatch);
        }
        guard.success();

        // 7. Mark the signing success durably, including the opaque signed
        //    reference, so a restart can reconcile without re-signing.
        if self
            .store
            .record_signed_reference(&binding, &request_digest, signed.reference())
            .await
            .is_err()
        {
            self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                .await;
            return Ok(RelayOutcome::FailedBeforeSubmit);
        }

        // 8. Fetch the payload the signed reference attests to.
        let signed_payload = match self.payload_source.signed_payload(&signed).await {
            Ok(payload) => payload,
            Err(_) => {
                self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                    .await;
                return Err(RelayError::MissingSignedPayload);
            }
        };

        // 9. Re-verify every binding before anything can be submitted.
        let request = match SubmitRequest::bind(&signing_request, &signed, &signed_payload, chain) {
            Ok(request) => request,
            Err(error) => {
                self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                    .await;
                return Err(error);
            }
        };
        self.journal_insert(&binding, &request);

        // 9b. Durably persist the fully bound submission BEFORE any submit, so a
        //     crash after broadcast but before the receipt is persisted can be
        //     reconciled from storage on restart instead of resubmitted. A
        //     persistence failure aborts before the adapter is called.
        if self
            .store
            .record_submission(&binding, &request_digest, &request)
            .await
            .is_err()
        {
            self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                .await;
            return Err(RelayError::StoreUnavailable);
        }

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
                self.record_outcome(&binding, &request_digest, RelayOutcome::FailedBeforeSubmit)
                    .await;
                return Err(RelayError::ChainHealthUnavailable);
            }
        };

        // 11. Submit at most once. There is no retry loop anywhere. The probe is
        //     resolved explicitly once `submit` returns; if the await is
        //     cancelled the guard's `Drop` resolves it as a failure.
        match self.adapter.submit(&request).await {
            Ok(receipt) => {
                probe.success();
                if !receipt.reference.trim().is_empty() {
                    // Cache the broadcast reference so an in-process reconcile
                    // queries the chain by its own hash, not the signer ref.
                    self.journal_set_chain_reference(&binding, &receipt.reference);
                }
                if receipt.reference.trim().is_empty() {
                    self.record_outcome(&binding, &request_digest, RelayOutcome::Unknown)
                        .await;
                    return Ok(RelayOutcome::Unknown);
                }
                let outcome = RelayOutcome::Submitted {
                    reference: receipt.reference,
                    state: SubmissionState::Unknown,
                };
                self.record_outcome(&binding, &request_digest, outcome.clone())
                    .await;
                Ok(outcome)
            }
            Err(RelayError::AdapterRejected) => {
                probe.success();
                let outcome = RelayOutcome::Rejected {
                    final_reason: "adapter rejected submission".to_string(),
                };
                self.record_outcome(&binding, &request_digest, outcome.clone())
                    .await;
                Ok(outcome)
            }
            Err(_) => {
                // Any other transport-level failure (`AdapterUnavailable`,
                // `AdapterTimeout`, or an undocumented error) may have sent
                // before failing, so the relay cannot assume "no send". Store
                // and return Unknown: reconciliation is required, never a retry.
                probe.failure(input.now_ms);
                self.record_outcome(&binding, &request_digest, RelayOutcome::Unknown)
                    .await;
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
    ///
    /// The full `(owner, workspace, idempotency_key)` binding is required, so a
    /// caller without its own row can never select another tenant's attempt. The
    /// bound submission is taken from the in-process journal when present, and
    /// otherwise rehydrated from the durable store, so a restart that lost the
    /// process-local journal can still reconcile a broadcast attempt. An absent
    /// durable submission is [`RelayError::InvalidTransition`] (which callers
    /// treat as ambiguous: never retry); a store failure is
    /// [`RelayError::StoreUnavailable`].
    pub async fn reconcile(
        &self,
        binding: &AttemptBinding,
        now_ms: i64,
    ) -> Result<RelayOutcome, RelayError> {
        // A terminal outcome is never downgraded by a later ambiguous chain read.
        if let Ok(Some(outcome)) = self.store.load_outcome(binding).await {
            if outcome.attempt_status().is_terminal() {
                return Ok(outcome);
            }
        }
        let request = match self.journal_get(binding)? {
            Some(request) => request,
            None => match self.store.load_submission(binding).await {
                Ok(Some(submission)) => SubmitRequest::restore(&submission)?,
                Ok(None) => return Err(RelayError::InvalidTransition),
                Err(_) => return Err(RelayError::StoreUnavailable),
            },
        };

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
        self.record_outcome(binding, request.request_digest(), outcome.clone())
            .await;
        Ok(outcome)
    }

    /// Borrows the chain health breaker (diagnostics and tests only).
    #[doc(hidden)]
    pub fn breaker(&self) -> &ChainHealthBreaker {
        &self.breaker
    }

    /// Borrows the signing-failure breaker (diagnostics and tests only).
    #[doc(hidden)]
    pub fn signing_breaker(&self) -> &SigningFailureBreaker {
        &self.signing_breaker
    }

    /// Borrows the policy engine that gates this relay (diagnostics/composition only).
    ///
    /// This is the same engine `execute` consults for the live kill switch and
    /// that `SigningRequest::bind` re-verifies. A composition layer (for example
    /// the market-execution port) uses it to run the authority check on the
    /// *same* engine that will gate the relay, rather than on a second engine
    /// that could drift.
    ///
    /// The borrow is read-only as an API matter (callers cannot replace the
    /// engine), but [`PolicyEngine`] deliberately exposes the one-way
    /// `disable_trading` kill switch through interior mutability; the engine
    /// owner already controls that gate.
    #[doc(hidden)]
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Persists the terminal/in-flight outcome, best-effort.
    ///
    /// A store write failure is deliberately swallowed: `record_outcome` runs
    /// after the submission (or after a definitive pre-send failure) and a
    /// transient journal error must not turn a completed attempt into an error a
    /// caller might retry. The at-most-once submit invariant is unaffected — the
    /// reservation claimed *before* signing still blocks any resubmission for the
    /// same `(owner, workspace, key, digest)`. A duplicate may therefore observe
    /// a stale in-memory outcome, but it can never reach the signing boundary or
    /// the chain adapter again.
    async fn record_outcome(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) {
        let _ = self.store.record_outcome(binding, digest, outcome).await;
    }

    fn journal_key(binding: &AttemptBinding) -> (String, String, IdempotencyKey) {
        (
            binding.owner().as_str().to_string(),
            binding.workspace().as_str().to_string(),
            binding.idempotency_key().clone(),
        )
    }

    fn journal_insert(&self, binding: &AttemptBinding, request: &SubmitRequest) {
        let mut journal = crate::lock(&self.journal);
        journal.insert(Self::journal_key(binding), request.clone());
    }

    fn journal_set_chain_reference(&self, binding: &AttemptBinding, reference: &str) {
        let mut journal = crate::lock(&self.journal);
        if let Some(request) = journal.get_mut(&Self::journal_key(binding)) {
            *request = request.clone().with_chain_reference(reference.to_string());
        }
    }

    /// Looks up the journaled submission by the full attempt binding.
    ///
    /// The lookup is exact on `(owner, workspace, idempotency_key)`, so a caller
    /// can never reconcile another owner's attempt that happens to share the
    /// same idempotency key.
    fn journal_get(&self, binding: &AttemptBinding) -> Result<Option<SubmitRequest>, RelayError> {
        let journal = crate::lock(&self.journal);
        Ok(journal.get(&Self::journal_key(binding)).cloned())
    }
}

impl<S, P> ExecutionRelay<S, UnavailableChainAdapter, P, PrivySigningBoundaryAdapter>
where
    S: DurableAttemptStore,
    P: SignedPayloadSource,
{
    /// **Production entry point.**
    ///
    /// Fail-closed composition: [`UnavailableChainAdapter`] performs no network
    /// I/O and rejects every submission, and [`PrivySigningBoundaryAdapter`]
    /// wraps the real P40 Privy boundary (whose public constructor installs an
    /// always-unavailable transport). Use this rather than
    /// [`ExecutionRelay::new_with_seams`] for any non-test wiring.
    ///
    /// # Durable requirement
    ///
    /// The store must implement [`DurableAttemptStore`], so the exactly-once
    /// guarantee does not depend on process-local bookkeeping: the reservation,
    /// the `SIGN_REQUESTED` record, the signed reference, the bound submission,
    /// and every outcome are persisted before the corresponding consequential
    /// boundary. Process-local stores ([`InMemoryReservationStore`]) are rejected
    /// at compile time on this path.
    ///
    /// [`InMemoryReservationStore`]: crate::InMemoryReservationStore
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

impl<S, A, P> ExecutionRelay<S, A, P, PrivySigningBoundaryAdapter>
where
    S: DurableAttemptStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
{
    /// **Production path with an injected chain adapter and Privy transport.**
    ///
    /// This is the one-chain live composition constructor: a real chain
    /// adapter is injected, and signing still flows through the real
    /// [`PrivySigningBoundaryAdapter`] over an operator-supplied
    /// [`privy::SigningTransport`]. The store must be durable, so the
    /// exactly-once lifecycle is persisted before every consequential boundary.
    /// Nothing here enables trading: capability remains [`TRADING_ENABLED`]
    /// gated by the policy engine.
    ///
    /// [`TRADING_ENABLED`]: PolicyEngine
    pub fn production_with_chain(
        policy: PolicyEngine,
        store: S,
        adapter: A,
        payload_source: P,
        privy_transport: Box<dyn privy::SigningTransport>,
        breaker: ChainHealthBreaker,
    ) -> Self {
        Self::new_with_seams(
            policy,
            store,
            adapter,
            payload_source,
            PrivySigningBoundaryAdapter::with_transport(privy_transport),
            breaker,
        )
    }
}
