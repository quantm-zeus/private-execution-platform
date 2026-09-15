//! D5 — deterministic crash/fault/restart tests for durable exactly-once
//! execution.
//!
//! Every test drives the real relay state machine over
//! [`execution_relay::DeterministicDurableStore`] with deterministic adapters
//! from `support`. No database, network, signer, or chain is involved: faults are
//! injected through a store wrapper that fails one transition, and a "restart" is
//! a brand-new `ExecutionRelay` over the **same** store, so its process-local
//! journal is empty and it must recover from durable state.
//!
//! Asserted invariants:
//! - a crash after reservation never reaches the signer;
//! - a crash after signer acceptance never signs a second time;
//! - a crash before submission persistence never submits;
//! - a submission timeout is `UNKNOWN`, reconciled (never resubmitted);
//! - a broadcast-before-receipt crash reconciles the exact submitted request;
//! - restart reconciliation reads the durable submission, not the journal;
//! - a conflicting request digest fails closed.

mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use domain::{IdempotencyKey, RoutePlan, TradeIntent, ValidatedExecutionPreview};
use execution_relay::{
    AttemptBinding, AttemptReservationStore, AttemptStatus, ChainHealthBreaker, ChainObservation,
    DeterministicDurableStore, DurableAttemptStore, DurableSubmission, ExecutionRelay, RelayError,
    RelayExecutionInput, RelayOutcome, Reservation, SubmitRequest,
};
use policy::{ApprovedExecution, PolicyContext};
use privy::{PreparedExecutionRef, ProviderIdempotencyId, RequestDigest};

use support::{MockAdapter, MockBehavior, MockSigning, MockSource};

/// One injected transition failure point.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailPoint {
    None,
    SignRequested,
    SignedReference,
    Submission,
    Outcome,
}

/// Wraps a durable store and fails exactly one transition on demand.
struct FaultStore {
    inner: Arc<DeterministicDurableStore>,
    fail: Mutex<FailPoint>,
}

impl FaultStore {
    fn new(inner: Arc<DeterministicDurableStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail: Mutex::new(FailPoint::None),
        })
    }

    fn set(&self, fail: FailPoint) {
        *self.fail.lock().expect("fail lock") = fail;
    }

    fn current(&self) -> FailPoint {
        *self.fail.lock().expect("fail lock")
    }
}

#[async_trait]
impl AttemptReservationStore for FaultStore {
    async fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        self.inner.reserve(key, digest).await
    }

    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        self.inner.reserve_bound(binding, digest).await
    }

    async fn record_sign_requested(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        if self.current() == FailPoint::SignRequested {
            return Err(RelayError::StoreUnavailable);
        }
        self.inner
            .record_sign_requested(key, digest, provider_idempotency)
            .await
    }

    async fn record_signed(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        self.inner.record_signed(key, digest).await
    }

    async fn record_signed_reference(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        if self.current() == FailPoint::SignedReference {
            return Err(RelayError::StoreUnavailable);
        }
        self.inner
            .record_signed_reference(key, digest, signed_reference)
            .await
    }

    async fn record_submission(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        request: &SubmitRequest,
    ) -> Result<(), RelayError> {
        if self.current() == FailPoint::Submission {
            return Err(RelayError::StoreUnavailable);
        }
        self.inner.record_submission(key, digest, request).await
    }

    async fn load_submission(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        self.inner.load_submission(key).await
    }

    async fn load_outcome(&self, key: &IdempotencyKey) -> Result<Option<RelayOutcome>, RelayError> {
        self.inner.load_outcome(key).await
    }

    async fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        if self.current() == FailPoint::Outcome {
            return Err(RelayError::StoreUnavailable);
        }
        self.inner.record_outcome(key, digest, outcome).await
    }
}

impl DurableAttemptStore for FaultStore {}

type TestRelay =
    ExecutionRelay<Arc<FaultStore>, Arc<MockAdapter>, Arc<MockSource>, Arc<MockSigning>>;

struct Harness {
    relay: TestRelay,
    durable: Arc<DeterministicDurableStore>,
    fault: Arc<FaultStore>,
    adapter: Arc<MockAdapter>,
    source: Arc<MockSource>,
    signing: Arc<MockSigning>,
    intent: TradeIntent,
    context: PolicyContext,
    prepared: PreparedExecutionRef,
    approved: ApprovedExecution,
    route: RoutePlan,
    preview: ValidatedExecutionPreview,
}

impl Harness {
    fn input(&self) -> RelayExecutionInput<'_> {
        RelayExecutionInput {
            intent: &self.intent,
            policy_context: &self.context,
            prepared: &self.prepared,
            approved: &self.approved,
            route: &self.route,
            preview: &self.preview,
            now_ms: support::NOW_MS,
        }
    }

    fn binding(&self) -> AttemptBinding {
        AttemptBinding::new(
            self.intent.user_id.clone(),
            self.intent.wallet_ref.clone(),
            self.intent.idempotency_key.clone(),
            self.intent.id.clone(),
            self.intent.chain.clone(),
        )
    }
}

/// Builds a relay plus its durable state and togglable fault wrapper.
fn harness_over(
    durable: Arc<DeterministicDurableStore>,
    behavior: MockBehavior,
    observation: ChainObservation,
) -> Harness {
    let adapter = MockAdapter::new(behavior, observation);
    let source = MockSource::standard();
    let signing = MockSigning::ok();
    let fault = FaultStore::new(Arc::clone(&durable));
    let relay = ExecutionRelay::new_with_seams(
        support::engine(true),
        Arc::clone(&fault),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signing),
        ChainHealthBreaker::new(2, 5_000),
    );
    let creator = support::engine(true);
    let intent = support::intent();
    let context = support::policy_context();
    let approved = support::approved(&creator, &intent);
    let prepared = support::prepared(&intent);
    let route = support::route();
    let preview = support::preview(&intent, &route);
    Harness {
        relay,
        durable,
        fault,
        adapter,
        source,
        signing,
        intent,
        context,
        prepared,
        approved,
        route,
        preview,
    }
}

fn harness(behavior: MockBehavior, observation: ChainObservation) -> Harness {
    harness_over(
        Arc::new(DeterministicDurableStore::new()),
        behavior,
        observation,
    )
}

/// Rebuilds a fresh relay over the same durable state (a process restart).
fn restarted(h: &Harness, behavior: MockBehavior, observation: ChainObservation) -> Harness {
    harness_over(Arc::clone(&h.durable), behavior, observation)
}

#[tokio::test]
async fn crash_after_reservation_never_reaches_signer() {
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    h.fault.set(FailPoint::SignRequested);

    let result = h.relay.execute(h.input()).await;
    assert_eq!(result, Err(RelayError::StoreUnavailable));
    assert_eq!(
        h.signing.calls.load(Ordering::SeqCst),
        0,
        "a failed SIGN_REQUESTED persistence must abort before the signer"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.durable.status(&h.binding()),
        Some(AttemptStatus::FailedBeforeSubmit)
    );

    // Restart and replay: no sign, no submit.
    h.fault.set(FailPoint::None);
    let after = restarted(&h, MockBehavior::Accept, ChainObservation::Unknown);
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(replay, Ok(RelayOutcome::FailedBeforeSubmit)));
    assert_eq!(after.signing.calls.load(Ordering::SeqCst), 0);
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn crash_after_signer_acceptance_does_not_double_sign() {
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    h.fault.set(FailPoint::SignedReference);

    let result = h.relay.execute(h.input()).await;
    assert_eq!(result, Ok(RelayOutcome::FailedBeforeSubmit));
    assert_eq!(
        h.signing.calls.load(Ordering::SeqCst),
        1,
        "the signer was invoked once before persistence failed"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);

    // Restart: the replay must not sign again (duplicate sign count = 0).
    h.fault.set(FailPoint::None);
    let after = restarted(&h, MockBehavior::Accept, ChainObservation::Unknown);
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(replay, Ok(RelayOutcome::FailedBeforeSubmit)));
    assert_eq!(
        after.signing.calls.load(Ordering::SeqCst),
        0,
        "a restart replay must not issue a second signing request"
    );
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn crash_before_submission_persistence_never_submits() {
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    h.fault.set(FailPoint::Submission);

    let result = h.relay.execute(h.input()).await;
    assert_eq!(result, Err(RelayError::StoreUnavailable));
    assert_eq!(h.signing.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        0,
        "a failed submission persistence must abort before the adapter"
    );

    h.fault.set(FailPoint::None);
    let after = restarted(&h, MockBehavior::Accept, ChainObservation::Unknown);
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(replay, Ok(RelayOutcome::FailedBeforeSubmit)));
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn submission_timeout_is_unknown_and_reconciles_without_resubmit() {
    let h = harness(MockBehavior::Timeout, ChainObservation::Unknown);
    let outcome = h.relay.execute(h.input()).await;
    assert_eq!(
        outcome,
        Ok(RelayOutcome::Unknown),
        "an ambiguous submission error must be UNKNOWN, never success"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.durable.status(&h.binding()),
        Some(AttemptStatus::SubmissionUnknown)
    );

    // Restart with a confirming adapter: reconcile via the durable submission.
    let after = restarted(
        &h,
        MockBehavior::Accept,
        ChainObservation::Confirmed {
            reference: "confirmed-after-restart".to_string(),
            fill: None,
        },
    );
    let reconciled = after
        .relay
        .reconcile(&after.intent.idempotency_key, support::NOW_MS)
        .await;
    assert!(matches!(reconciled, Ok(RelayOutcome::Confirmed { .. })));
    assert_eq!(
        after.adapter.submits.load(Ordering::SeqCst),
        0,
        "reconciliation must never submit"
    );
    assert_eq!(
        after.adapter.queries.load(Ordering::SeqCst),
        1,
        "reconciliation must query the durable submission"
    );
    assert_eq!(after.signing.calls.load(Ordering::SeqCst), 0);

    // A duplicate execute after the restart must not resubmit.
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(
        replay,
        Ok(RelayOutcome::Confirmed { .. }) | Ok(RelayOutcome::Unknown)
    ));
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn broadcast_before_receipt_reconciles_the_exact_submission() {
    // The adapter acknowledges the submission, but the receipt outcome write is
    // lost (crash after broadcast, before persistence).
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    h.fault.set(FailPoint::Outcome);

    let result = h.relay.execute(h.input()).await;
    assert!(matches!(result, Ok(RelayOutcome::Submitted { .. })));
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
    // The outcome write was lost; the persisted state is ambiguous, so a replay
    // must reconcile rather than resubmit.
    assert_eq!(
        h.durable.status(&h.binding()),
        Some(AttemptStatus::SubmissionUnknown)
    );

    let after = restarted(
        &h,
        MockBehavior::Accept,
        ChainObservation::Confirmed {
            reference: "confirmed-after-restart".to_string(),
            fill: None,
        },
    );
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(replay, Ok(RelayOutcome::Unknown)));
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);

    let reconciled = after
        .relay
        .reconcile(&after.intent.idempotency_key, support::NOW_MS)
        .await;
    assert!(matches!(reconciled, Ok(RelayOutcome::Confirmed { .. })));
    assert_eq!(after.adapter.queries.load(Ordering::SeqCst), 1);
    assert_eq!(
        after.durable.status(&after.binding()),
        Some(AttemptStatus::Confirmed)
    );
}

#[tokio::test]
async fn restart_reconcile_reads_the_durable_submission_not_the_journal() {
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    assert!(matches!(
        h.relay.execute(h.input()).await,
        Ok(RelayOutcome::Submitted { .. })
    ));
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);

    // A brand-new relay has an empty process-local journal.
    let after = restarted(
        &h,
        MockBehavior::Accept,
        ChainObservation::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        },
    );
    let reconciled = after
        .relay
        .reconcile(&after.intent.idempotency_key, support::NOW_MS)
        .await;
    assert!(matches!(reconciled, Ok(RelayOutcome::Confirmed { .. })));
    assert_eq!(
        after.adapter.queries.load(Ordering::SeqCst),
        1,
        "the restarted relay must query the durable submission"
    );
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn conflicting_request_digest_fails_closed() {
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    assert!(matches!(
        h.relay.execute(h.input()).await,
        Ok(RelayOutcome::Submitted { .. })
    ));
    let signs_after_first = h.signing.calls.load(Ordering::SeqCst);
    assert_eq!(signs_after_first, 1);

    // Same owner/workspace/idempotency key, different nonce => different digest.
    let mutated = support::intent_with_idempotency("idem-1", 8);
    let creator = support::engine(true);
    let approved = support::approved(&creator, &mutated);
    let prepared = support::prepared(&mutated);
    let route = support::route();
    let preview = support::preview(&mutated, &route);
    let input = RelayExecutionInput {
        intent: &mutated,
        policy_context: &h.context,
        prepared: &prepared,
        approved: &approved,
        route: &route,
        preview: &preview,
        now_ms: support::NOW_MS,
    };
    let result = h.relay.execute(input).await;
    assert_eq!(result, Err(RelayError::IdempotencyConflict));
    assert_eq!(
        h.signing.calls.load(Ordering::SeqCst),
        signs_after_first,
        "a conflicting digest must not reach the signer"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signed_reference_persisted_then_payload_failure_replays_signed() {
    // SIGNED is persisted, then the process dies before the payload is fetched
    // and before any outcome write.
    let h = harness(MockBehavior::Accept, ChainObservation::Unknown);
    h.source.set_fail_post(true);
    h.fault.set(FailPoint::Outcome);

    let result = h.relay.execute(h.input()).await;
    assert_eq!(result, Err(RelayError::MissingSignedPayload));
    assert_eq!(h.signing.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.durable.status(&h.binding()), Some(AttemptStatus::Signed));

    // Restart: replaying the SIGNED attempt must not sign or submit again.
    h.fault.set(FailPoint::None);
    let after = restarted(&h, MockBehavior::Accept, ChainObservation::Unknown);
    let replay = after.relay.execute(after.input()).await;
    assert!(matches!(replay, Ok(RelayOutcome::Signed)));
    assert_eq!(after.signing.calls.load(Ordering::SeqCst), 0);
    assert_eq!(after.adapter.submits.load(Ordering::SeqCst), 0);
}
