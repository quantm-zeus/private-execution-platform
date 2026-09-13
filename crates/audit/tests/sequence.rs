//! Sequence monotonicity, conflict surfacing, and contiguity on replay.

mod support;

use std::sync::Arc;

use audit::{AuditError, AuditLookup, AuditWriter, ExecutionAuditEvent};
use crypto_envelope::{seal_at_rest, SealKey};
use storage::{OpaqueEventRecord, StorageError};
use support::{
    base, bucket, fixture_stream, intent_id, lifecycle_event, CountingStore, FixedProvider, INTENT,
    SEAL_A,
};

fn sealed_record(event: &ExecutionAuditEvent, stream: &[u8]) -> OpaqueEventRecord {
    let payload = serde_json::to_vec(event).expect("payload");
    let ciphertext = seal_at_rest(
        &SealKey::from_bytes(SEAL_A),
        &support::KID_A,
        event.sequence,
        event.schema_version,
        stream,
        &payload,
    );
    OpaqueEventRecord {
        stream_blind_index: stream.to_vec(),
        sequence: event.sequence,
        schema_version: event.schema_version,
        ciphertext,
        created_bucket: bucket(),
    }
}

#[tokio::test]
async fn reappend_same_sequence_is_not_monotonic_without_store_write() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    writer
        .append(&lifecycle_event(1), bucket())
        .await
        .expect("first append");
    assert_eq!(store.append_calls(), 1);

    let error = writer
        .append(&lifecycle_event(1), bucket())
        .await
        .expect_err("second append");
    assert_eq!(error, AuditError::SequenceNotMonotonic);
    assert_eq!(
        store.append_calls(),
        1,
        "a rejected sequence must not reach the store"
    );
}

#[tokio::test]
async fn store_conflict_maps_to_storage_conflict() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    store.fail_next_append(StorageError::Conflict);

    let error = writer
        .append(&lifecycle_event(1), bucket())
        .await
        .expect_err("append");
    assert_eq!(error, AuditError::StorageConflict);
}

#[tokio::test]
async fn same_plaintext_different_sequence_differs_in_nonce_and_ciphertext() {
    let event = lifecycle_event(1);
    let mut later = event.clone();
    later.sequence = 2;
    let stream = support::fixture_stream(&FixedProvider::single());
    let seal = SealKey::from_bytes(SEAL_A);

    let first = seal_at_rest(
        &seal,
        &support::KID_A,
        event.sequence,
        event.schema_version,
        &stream,
        &serde_json::to_vec(&event).expect("payload"),
    );
    let second = seal_at_rest(
        &seal,
        &support::KID_A,
        later.sequence,
        later.schema_version,
        &stream,
        &serde_json::to_vec(&later).expect("payload"),
    );

    let first_nonce = &first[17..41];
    let second_nonce = &second[17..41];
    assert_ne!(first_nonce, second_nonce, "nonces must differ by sequence");
    assert_ne!(first, second, "ciphertexts must differ by sequence");
}

#[tokio::test]
async fn sequence_gap_is_detected_on_replay() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    store.seed(vec![
        sealed_record(&lifecycle_event(1), &stream),
        sealed_record(&lifecycle_event(3), &stream),
    ]);

    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(provider));
    let error = writer
        .replay(AuditLookup::Intent {
            chain: base(),
            intent_id: intent_id(INTENT),
        })
        .await
        .expect_err("replay");
    assert_eq!(error, AuditError::SequenceGap);
}
