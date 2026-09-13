//! End-to-end relay flow tests: exactly-once, fail-closed, and reconciliation.

mod support;

use std::sync::atomic::Ordering;

use chain_types::ChainId;
use domain::{IdempotencyKey, OrderStatus};
use execution_relay::{RelayError, RelayOutcome, SubmissionState};
use support::{
    other_payload, payload, MockAdapter, MockBehavior, MockSigning, MockSource, MockStore,
    RelayHarness, NOW_MS,
};

#[tokio::test]
async fn happy_path_submits_once_then_reconciles_to_confirmed() {
    let harness = RelayHarness::standard();

    let outcome = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    match &outcome {
        RelayOutcome::Submitted { reference, state } => {
            assert_eq!(reference, "receipt-ref");
            assert_eq!(*state, SubmissionState::Unknown);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(outcome.order_status(), OrderStatus::Executing);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(harness.signing.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.store.record_signed_calls.load(Ordering::SeqCst), 1);

    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string()
        }
    );
    assert_eq!(confirmed.order_status(), OrderStatus::Filled);

    // Repeated reconciliation is idempotent and never submits.
    let again = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(again, confirmed);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn duplicate_execute_returns_stored_outcome_without_resigning() {
    let harness = RelayHarness::standard();

    let first = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("first");
    let second = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("second");

    assert_eq!(first, second);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.signing.calls.load(Ordering::SeqCst),
        1,
        "a duplicate must not reach the signing boundary again"
    );
    // The pre-sign payload lookup may run again, but nothing is signed/sent.
    assert_eq!(harness.source.pre_calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.source.post_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn same_key_different_digest_conflicts_without_submit() {
    let source = MockSource::with_sequence(vec![payload(), other_payload()]);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        MockAdapter::accepting(),
        source,
        MockSigning::ok(),
    );

    let first = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("first");
    assert!(matches!(first, RelayOutcome::Submitted { .. }));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);

    let conflict = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(conflict, Err(RelayError::IdempotencyConflict));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.signing.calls.load(Ordering::SeqCst),
        1,
        "a conflict must not sign"
    );
}

#[tokio::test]
async fn timeout_yields_unknown_and_repeated_reconcile_never_submits() {
    let adapter = MockAdapter::new(
        MockBehavior::Timeout,
        execution_relay::ChainObservation::Confirmed {
            reference: "confirmed-ref".to_string(),
        },
    );
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let outcome = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert_eq!(outcome, RelayOutcome::Unknown);
    assert_eq!(outcome.order_status(), OrderStatus::Executing);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);

    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string()
        }
    );
    let again = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(again, confirmed);
    assert_eq!(
        harness.adapter.submits.load(Ordering::SeqCst),
        1,
        "reconcile must never submit"
    );
}

#[tokio::test]
async fn rejected_maps_to_failed_final_and_never_retries() {
    let adapter = MockAdapter::new(
        MockBehavior::Reject,
        execution_relay::ChainObservation::Unknown,
    );
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let outcome = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert!(matches!(outcome, RelayOutcome::Rejected { .. }));
    assert_eq!(outcome.order_status(), OrderStatus::FailedFinal);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);

    let duplicate = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("duplicate");
    assert!(matches!(duplicate, RelayOutcome::Rejected { .. }));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn trading_disabled_blocks_before_reservation() {
    let harness = RelayHarness::build(
        support::engine(false),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::TradingDisabled));
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(harness.signing.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn record_signed_failure_yields_failed_before_submit() {
    let store = MockStore::failing_record_signed();
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        store,
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let outcome = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert_eq!(outcome, RelayOutcome::FailedBeforeSubmit);
    assert_eq!(outcome.order_status(), OrderStatus::FailedRetryable);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn payload_digest_mismatch_fails_before_submit() {
    let source = MockSource::standard();
    source.set_post_override(other_payload());
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        MockAdapter::accepting(),
        source,
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::SignedPayloadDigestMismatch));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_signed_payload_fails_before_submit() {
    let source = MockSource::standard();
    source.set_fail_post(true);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        MockAdapter::accepting(),
        source,
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::MissingSignedPayload));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signing_failure_is_redacted_and_sticks_as_failed_before_submit() {
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::failing(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::SigningFailed));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);

    let duplicate = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("duplicate");
    assert_eq!(duplicate, RelayOutcome::FailedBeforeSubmit);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mismatched_signed_reference_fails_before_submit() {
    let other = support::other_signing_request();
    let harness = RelayHarness::standard();
    harness.signing.set_override_digest(*other.request_digest());

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::SigningRequestMismatch));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unavailable_adapter_blocks_without_submit() {
    let adapter = MockAdapter::new(
        MockBehavior::Unavailable,
        execution_relay::ChainObservation::Unknown,
    );
    adapter.set_health(execution_relay::ChainHealth::Unavailable);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::ChainHealthUnavailable));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_unknown_key_is_invalid_transition() {
    let harness = RelayHarness::standard();
    let missing = IdempotencyKey::new("never-executed").unwrap();
    let result = harness.relay.reconcile(&missing, NOW_MS).await;
    assert_eq!(result, Err(RelayError::InvalidTransition));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pre_tripped_breaker_blocks_execution() {
    let breaker = execution_relay::ChainHealthBreaker::new(2, 5_000);
    breaker.record_failure(&ChainId::Base, 100);
    breaker.record_failure(&ChainId::Base, 200);
    let harness = RelayHarness::build(
        support::engine(true),
        breaker,
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;
    assert_eq!(result, Err(RelayError::ChainHealthUnavailable));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 0);
}
