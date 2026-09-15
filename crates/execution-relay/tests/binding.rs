//! Binding, redaction, and trait-object invariant tests for P41.

mod support;

use std::sync::Arc;

use chain_types::ChainId;
use execution_relay::{
    AttemptReservationStore, ChainHealth, ChainObservation, ChainSubmissionAdapter, ExecutionRelay,
    RelayError, SignedPayload, SignedPayloadSource, SigningBoundary, SubmissionReceipt,
    SubmitRequest, UnavailableChainAdapter, MAX_SIGNED_PAYLOAD_BYTES,
};
use sha2::{Digest, Sha256};

use support::{
    other_payload, payload, signed_ref_for, signing_request, signing_request_with, MapStore,
    MockAdapter, MockSigning, MockSource, MockStore,
};

#[test]
fn signed_payload_rejects_empty_and_oversize_and_hashes_bytes() {
    assert_eq!(
        SignedPayload::new(Vec::new()),
        Err(RelayError::SignedPayloadEmpty)
    );

    let oversize = vec![0u8; MAX_SIGNED_PAYLOAD_BYTES + 1];
    assert_eq!(
        SignedPayload::new(oversize),
        Err(RelayError::SignedPayloadTooLarge)
    );

    let bytes = b"exactly-bound-payload".to_vec();
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    let signed = SignedPayload::new(bytes).expect("payload");
    assert_eq!(signed.digest().as_bytes(), &expected);
}

#[test]
fn submit_request_bind_rejects_each_binding_failure() {
    let request = signing_request();
    let signed = signed_ref_for(&request, "signed-ref");
    let good = payload();

    // Signed reference attests to a different signing request.
    let other_request = support::other_signing_request();
    let wrong_signed = signed_ref_for(&other_request, "signed-ref");
    assert_eq!(
        SubmitRequest::bind(&request, &wrong_signed, &good, &ChainId::Base),
        Err(RelayError::SigningRequestMismatch)
    );

    // Chain mismatch.
    assert_eq!(
        SubmitRequest::bind(&request, &signed, &good, &ChainId::Ethereum),
        Err(RelayError::ChainMismatch)
    );

    // Payload digest mismatch: the request committed to a different payload.
    let other = other_payload();
    let other_request = signing_request_with(&other, 7);
    let other_signed = signed_ref_for(&other_request, "signed-ref");
    assert_eq!(
        SubmitRequest::bind(&other_request, &other_signed, &good, &ChainId::Base),
        Err(RelayError::SignedPayloadDigestMismatch)
    );

    // The valid binding succeeds and exposes the bound fields.
    let bound =
        SubmitRequest::bind(&request, &signed, &good, &ChainId::Base).expect("valid binding");
    assert_eq!(bound.request_digest(), request.request_digest());
    assert_eq!(bound.payload_digest(), good.digest());
    assert_eq!(bound.intent_id(), request.intent_id());
    assert_eq!(bound.idempotency_key(), request.idempotency_key());
    assert_eq!(bound.chain(), &ChainId::Base);
    assert_eq!(bound.payload(), good.bytes());
}

#[test]
fn submit_request_binding_is_stable_and_field_sensitive() {
    let request = signing_request();
    let same_request = signing_request();
    let signed = signed_ref_for(&request, "signed-ref");
    let same_signed = signed_ref_for(&same_request, "signed-ref");
    let good = payload();

    let first = SubmitRequest::bind(&request, &signed, &good, &ChainId::Base).expect("bind");
    let second =
        SubmitRequest::bind(&same_request, &same_signed, &good, &ChainId::Base).expect("bind");
    assert_eq!(first, second, "identical inputs must bind identically");

    // A changed signed reference is a different bound request.
    let renamed = signed_ref_for(&request, "another-signed-ref");
    let renamed_request =
        SubmitRequest::bind(&request, &renamed, &good, &ChainId::Base).expect("bind");
    assert_ne!(first, renamed_request);

    // A changed nonce (and thus request digest) is a different bound request.
    let other_nonce = signing_request_with(&good, 8);
    let other_nonce_signed = signed_ref_for(&other_nonce, "signed-ref");
    let other_nonce_request =
        SubmitRequest::bind(&other_nonce, &other_nonce_signed, &good, &ChainId::Base)
            .expect("bind");
    assert_ne!(first, other_nonce_request);
}

/// Fixture-derived substrings that must never leak through `Display`/`Debug`.
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "1000",
    "250",
    "240",
    "USDC",
    "TOKEN",
    "wallet-1",
    "intent-1",
    "idem-1",
    "prepared-1",
    "uniswap",
    "0x",
    "http",
    "://",
    "receipt-ref",
    "confirmed-ref",
    "signed-ref",
];

fn has_hex_run(value: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn assert_redacted(label: &str, value: &str) {
    for forbidden in FORBIDDEN_SUBSTRINGS {
        assert!(
            !value.contains(forbidden),
            "redaction leak in `{label}`: `{value}` contains `{forbidden}`"
        );
    }
    assert!(
        !has_hex_run(value, 8),
        "redaction leak in `{label}`: `{value}` contains a hex run of length >= 8"
    );
}

#[test]
fn every_relay_error_variant_is_redacted() {
    let errors = [
        RelayError::TradingDisabled,
        RelayError::ChainHealthUnavailable,
        RelayError::SigningUnavailable,
        RelayError::SigningFailed,
        RelayError::SigningRequestMismatch,
        RelayError::ChainMismatch,
        RelayError::MissingSignedPayload,
        RelayError::SignedPayloadEmpty,
        RelayError::SignedPayloadTooLarge,
        RelayError::SignedPayloadDigestMismatch,
        RelayError::ReservationUnavailable,
        RelayError::IdempotencyConflict,
        RelayError::AdapterUnavailable,
        RelayError::AdapterRejected,
        RelayError::AdapterTimeout,
        RelayError::UnknownSubmissionState,
        RelayError::InvalidTransition,
        RelayError::StoreUnavailable,
    ];
    for error in errors {
        assert_redacted("RelayError Display", &error.to_string());
        assert_redacted("RelayError Debug", &format!("{error:?}"));
    }
}

#[test]
fn payload_reference_and_request_debug_are_redacted() {
    let good = payload();
    assert_redacted("SignedPayload Debug", &format!("{good:?}"));

    let request = signing_request();
    let signed = signed_ref_for(&request, "signed-1");
    assert_redacted("SignedExecutionRef Debug", &format!("{signed:?}"));

    let bound = SubmitRequest::bind(&request, &signed, &good, &ChainId::Base).expect("bind");
    assert_redacted("SubmitRequest Debug", &format!("{bound:?}"));

    let confirmation = execution_relay::RelayOutcome::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: None,
    };
    assert_redacted("RelayOutcome Debug", &format!("{confirmation:?}"));
    let rejected = execution_relay::RelayOutcome::Rejected {
        final_reason: "adapter rejected submission".to_string(),
    };
    assert_redacted("RelayOutcome Debug", &format!("{rejected:?}"));
}

#[test]
fn receipt_and_observation_debug_are_redacted() {
    let receipt = SubmissionReceipt::new("receipt-ref").expect("receipt");
    assert_redacted("SubmissionReceipt Debug", &format!("{receipt:?}"));

    let confirmed = ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: None,
    };
    assert_redacted("ChainObservation Debug", &format!("{confirmed:?}"));

    let observed = execution_relay::ObservedFill {
        net_input: 1_234,
        net_output: 5_678,
    };
    let rendered = format!("{observed:?}");
    assert_redacted("ObservedFill Debug", &rendered);
    assert!(!rendered.contains("1234"));
    assert!(!rendered.contains("5678"));

    let rejected = ChainObservation::Rejected {
        final_reason: "rejected-final-reason".to_string(),
    };
    assert_redacted("ChainObservation Debug", &format!("{rejected:?}"));
}

#[tokio::test]
async fn unavailable_chain_adapter_fails_closed_on_every_method() {
    let request = signing_request();
    let signed = signed_ref_for(&request, "signed-ref");
    let good = payload();
    let bound =
        SubmitRequest::bind(&request, &signed, &good, &ChainId::Base).expect("valid binding");

    let adapter = UnavailableChainAdapter::new();
    assert_eq!(
        adapter.submit(&bound).await,
        Err(RelayError::AdapterUnavailable)
    );
    assert_eq!(
        adapter.query(&bound, 0).await,
        Err(RelayError::AdapterUnavailable)
    );
    assert_eq!(
        adapter.reconcile(&bound, 0).await,
        Err(RelayError::AdapterUnavailable)
    );
    assert_eq!(adapter.health(0), ChainHealth::Unavailable);
}

#[test]
fn relay_and_traits_are_send_sync_and_object_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<
        ExecutionRelay<
            Arc<dyn AttemptReservationStore>,
            Arc<dyn ChainSubmissionAdapter>,
            Arc<dyn SignedPayloadSource>,
            Arc<dyn SigningBoundary>,
        >,
    >();

    let store: Arc<dyn AttemptReservationStore> = Arc::new(MapStore::new());
    let adapter: Arc<dyn ChainSubmissionAdapter> = MockAdapter::accepting();
    let source: Arc<dyn SignedPayloadSource> = MockSource::standard();
    let signing: Arc<dyn SigningBoundary> = MockSigning::ok();
    let _relay = ExecutionRelay::new_with_seams(
        support::engine(true),
        store,
        adapter,
        source,
        signing,
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    );

    // The concrete mock components can also be shared.
    let _store = MockStore::new();
}
