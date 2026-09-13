//! End-to-end relay flow tests: exactly-once, fail-closed, and reconciliation.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use chain_types::ChainId;
use domain::{IdempotencyKey, OrderStatus};
use execution_relay::{
    ChainHealth, ObservedFill, RelayError, RelayExecutionInput, RelayOutcome, SubmissionState,
};
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
            reference: "confirmed-ref".to_string(),
            fill: None,
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
async fn reconcile_carries_an_observed_fill_through_to_the_outcome() {
    let harness = RelayHarness::standard();
    harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");

    harness
        .adapter
        .set_query_observation(execution_relay::ChainObservation::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 7,
                net_output: 11,
            }),
        });
    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 7,
                net_output: 11,
            }),
        }
    );
    assert_eq!(confirmed.order_status(), OrderStatus::Filled);
    // The realized amounts never appear in the redacted outcome Debug.
    let rendered = format!("{confirmed:?}");
    assert!(!rendered.contains('7'));
    assert!(!rendered.contains("11"));
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
            fill: None,
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
            reference: "confirmed-ref".to_string(),
            fill: None,
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

#[tokio::test]
async fn pre_submit_failure_does_not_burn_half_open_probe() {
    let breaker = execution_relay::ChainHealthBreaker::new(2, 5_000);
    breaker.record_failure(&ChainId::Base, 100);
    breaker.record_failure(&ChainId::Base, 200);
    let source = MockSource::standard();
    source.set_fail_pre(true);
    let harness = RelayHarness::build(
        support::engine(true),
        breaker,
        MockStore::new(),
        MockAdapter::accepting(),
        source,
        MockSigning::ok(),
    );

    let blocked = harness.relay.execute(harness.input(5_300)).await;
    assert_eq!(blocked, Err(RelayError::MissingSignedPayload));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);

    // The failed attempt never reached the adapter, so the probe is intact and
    // a later attempt can still consume it.
    harness.source.set_fail_pre(false);
    let outcome = harness
        .relay
        .execute(harness.input(5_300))
        .await
        .expect("probe execution");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn duplicate_reservation_does_not_burn_half_open_probe() {
    let breaker = execution_relay::ChainHealthBreaker::new(2, 5_000);
    let harness = RelayHarness::build(
        support::engine(true),
        breaker,
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let first = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("first");
    assert!(matches!(first, RelayOutcome::Submitted { .. }));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);

    // Open the breaker after the successful attempt.
    let chain = ChainId::Base;
    harness.relay.breaker().record_failure(&chain, 100);
    harness.relay.breaker().record_failure(&chain, 200);

    // The duplicate returns its stored outcome before probe admission.
    let duplicate = harness
        .relay
        .execute(harness.input(5_300))
        .await
        .expect("duplicate");
    assert_eq!(duplicate, first);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert!(
        harness.relay.breaker().admit_probe(&chain, 5_300).is_some(),
        "a duplicate reservation must not consume the half-open probe"
    );
}

#[tokio::test]
async fn half_open_probe_success_closes_breaker() {
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

    let outcome = harness
        .relay
        .execute(harness.input(5_300))
        .await
        .expect("probe");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.relay.breaker().health(&ChainId::Base, 5_301),
        ChainHealth::Healthy
    );
}

#[tokio::test]
async fn half_open_probe_failure_reopens_breaker() {
    let breaker = execution_relay::ChainHealthBreaker::new(2, 5_000);
    breaker.record_failure(&ChainId::Base, 100);
    breaker.record_failure(&ChainId::Base, 200);
    let adapter = MockAdapter::new(
        MockBehavior::Timeout,
        execution_relay::ChainObservation::Unknown,
    );
    let harness = RelayHarness::build(
        support::engine(true),
        breaker,
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let outcome = harness
        .relay
        .execute(harness.input(5_300))
        .await
        .expect("probe");
    assert_eq!(outcome, RelayOutcome::Unknown);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.relay.breaker().health(&ChainId::Base, 5_301),
        ChainHealth::Unavailable
    );
    assert!(!harness
        .relay
        .breaker()
        .check_allowed(&ChainId::Base, 10_000));
}

#[tokio::test]
async fn transport_unavailable_yields_unknown_not_failed_before_submit() {
    // The adapter reports itself healthy, so the relay reaches `submit`; the
    // transport-level error must still be treated as an unknown outcome.
    let adapter = MockAdapter::new(
        MockBehavior::Unavailable,
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
    assert_eq!(outcome, RelayOutcome::Unknown);
    assert_eq!(outcome.order_status(), OrderStatus::Executing);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);

    // The unknown outcome is sticky and never resubmits.
    let duplicate = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("duplicate");
    assert_eq!(duplicate, RelayOutcome::Unknown);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconcile_falls_through_when_query_returns_unknown() {
    let adapter = MockAdapter::accepting();
    adapter.set_query_observation(execution_relay::ChainObservation::Unknown);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let submitted = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert!(matches!(submitted, RelayOutcome::Submitted { .. }));

    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        }
    );
    assert_eq!(harness.adapter.queries.load(Ordering::SeqCst), 1);
    assert_eq!(harness.adapter.reconcilers.load(Ordering::SeqCst), 1);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconcile_falls_through_when_query_errors() {
    let adapter = MockAdapter::accepting();
    adapter.set_fail_query(true);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let submitted = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert!(matches!(submitted, RelayOutcome::Submitted { .. }));

    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        }
    );
    assert_eq!(harness.adapter.queries.load(Ordering::SeqCst), 1);
    assert_eq!(harness.adapter.reconcilers.load(Ordering::SeqCst), 1);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn production_composition_fails_closed_without_submit() {
    let store = MockStore::new();
    let source = MockSource::standard();
    let relay = execution_relay::ExecutionRelay::production(
        support::engine(true),
        Arc::clone(&store),
        Arc::clone(&source),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    );

    let creator = support::engine(true);
    let intent = support::intent();
    let context = support::policy_context();
    let approved = support::approved(&creator, &intent);
    let prepared = support::prepared(&intent);
    let route = support::route();
    let preview = support::preview(&intent, &route);
    let input = RelayExecutionInput {
        intent: &intent,
        policy_context: &context,
        prepared: &prepared,
        approved: &approved,
        route: &route,
        preview: &preview,
        now_ms: NOW_MS,
    };

    // `UnavailableChainAdapter::health` is always `Unavailable`, so production
    // composition blocks before any reservation, sign, or submit.
    let result = relay.execute(input).await;
    assert_eq!(result, Err(RelayError::ChainHealthUnavailable));
    assert_eq!(store.reserve_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_submit_releases_half_open_probe_and_allows_reprobe() {
    use std::time::Duration;

    let breaker = execution_relay::ChainHealthBreaker::new(2, 1_000);
    breaker.record_failure(&ChainId::Base, 100);
    breaker.record_failure(&ChainId::Base, 200);
    let adapter = MockAdapter::new(
        MockBehavior::Hang,
        execution_relay::ChainObservation::Unknown,
    );
    let harness = RelayHarness::build(
        support::engine(true),
        breaker,
        MockStore::new(),
        Arc::clone(&adapter),
        MockSource::standard(),
        MockSigning::ok(),
    );

    // An outer timeout cancels `execute` while it awaits a submit that never
    // completes. The admitted half-open probe must not be stranded by that.
    let cancelled = tokio::time::timeout(
        Duration::from_millis(10),
        harness.relay.execute(harness.input(1_300)),
    )
    .await;
    assert!(cancelled.is_err(), "the hung submit must be cancelled");
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);

    // The guard resolved the probe as a failure, so the breaker re-opened with
    // a fresh cooldown instead of blocking the chain forever.
    assert_eq!(
        harness.relay.breaker().health(&ChainId::Base, 1_300),
        ChainHealth::Unavailable
    );
    assert!(!harness.relay.breaker().check_allowed(&ChainId::Base, 2_299));
    assert!(harness.relay.breaker().check_allowed(&ChainId::Base, 2_300));

    // A fresh, independent attempt can probe again once the cooldown elapses.
    adapter.set_behavior(MockBehavior::Accept);
    let intent = support::intent_with_idempotency("idem-2", 8);
    let context = support::policy_context();
    let engine = support::engine(true);
    let approved = support::approved(&engine, &intent);
    let prepared = support::prepared(&intent);
    let route = support::route();
    let preview = support::preview(&intent, &route);
    let input = RelayExecutionInput {
        intent: &intent,
        policy_context: &context,
        prepared: &prepared,
        approved: &approved,
        route: &route,
        preview: &preview,
        now_ms: 2_300,
    };
    let recovered = harness
        .relay
        .execute(input)
        .await
        .expect("recovered execute");
    assert!(matches!(recovered, RelayOutcome::Submitted { .. }));
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 2);
    assert_eq!(
        harness.relay.breaker().health(&ChainId::Base, 2_301),
        ChainHealth::Healthy
    );
}

#[tokio::test]
async fn definitive_query_observation_wins_and_reconcile_is_not_called() {
    let adapter = MockAdapter::accepting();
    adapter.set_query_observation(execution_relay::ChainObservation::Confirmed {
        reference: "query-confirmed-ref".to_string(),
        fill: None,
    });
    adapter.set_reconcile_observation(execution_relay::ChainObservation::Unknown);
    let harness = RelayHarness::build(
        support::engine(true),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        MockSigning::ok(),
    );

    let submitted = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");
    assert!(matches!(submitted, RelayOutcome::Submitted { .. }));

    // `query` is definitive, so its result must win and `reconcile` (which
    // would have returned `Unknown`) must not even be called.
    let confirmed = harness
        .relay
        .reconcile(&harness.intent.idempotency_key, NOW_MS)
        .await
        .expect("reconcile");
    assert_eq!(
        confirmed,
        RelayOutcome::Confirmed {
            reference: "query-confirmed-ref".to_string(),
            fill: None,
        }
    );
    assert_eq!(harness.adapter.queries.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.adapter.reconcilers.load(Ordering::SeqCst),
        0,
        "a definitive query observation must skip reconcile"
    );
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 1);
}
