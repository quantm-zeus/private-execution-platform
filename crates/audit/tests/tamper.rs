//! Tamper, substitution, and key-selection failures must fail closed.

mod support;

use std::sync::Arc;

use audit::{AuditError, AuditLookup, AuditWriter, ExecutionAuditEvent};
use crypto_envelope::{seal_at_rest, SealKey};
use storage::OpaqueEventRecord;
use support::{
    base, bucket, fixture_stream, intent_id, lifecycle_event, CountingStore, FixedProvider,
    MismatchedKidProvider, StickyKidProvider, INTENT, KID_B, SEAL_A, SEAL_B,
};

fn sealed_record(
    event: &ExecutionAuditEvent,
    kid: [u8; 16],
    seal: [u8; 32],
    stream: &[u8],
) -> OpaqueEventRecord {
    let payload = serde_json::to_vec(event).expect("payload");
    let ciphertext = seal_at_rest(
        &SealKey::from_bytes(seal),
        &kid,
        event.sequence,
        event.schema_version,
        stream,
        &payload,
    )
    .expect("seal");
    assert!(ciphertext.len() > 57, "wire must be well formed");
    OpaqueEventRecord {
        stream_blind_index: stream.to_vec(),
        sequence: event.sequence,
        schema_version: event.schema_version,
        ciphertext,
        created_bucket: bucket(),
    }
}

fn writer(store: Arc<CountingStore>, provider: FixedProvider) -> AuditWriter<CountingStore> {
    AuditWriter::new(store, Arc::new(provider))
}

/// Seals `event`'s payload under caller-chosen outer sequence/schema values,
/// so the inner event can disagree with the record envelope.
fn sealed_record_with_outer(
    event: &ExecutionAuditEvent,
    kid: [u8; 16],
    seal: [u8; 32],
    stream: &[u8],
    outer_sequence: u64,
    outer_schema_version: u16,
) -> OpaqueEventRecord {
    let payload = serde_json::to_vec(event).expect("payload");
    let ciphertext = seal_at_rest(
        &SealKey::from_bytes(seal),
        &kid,
        outer_sequence,
        outer_schema_version,
        stream,
        &payload,
    )
    .expect("seal");
    OpaqueEventRecord {
        stream_blind_index: stream.to_vec(),
        sequence: outer_sequence,
        schema_version: outer_schema_version,
        ciphertext,
        created_bucket: bucket(),
    }
}

async fn replay_error(writer: &AuditWriter<CountingStore>, intent: &str) -> AuditError {
    writer
        .replay_current(AuditLookup::Intent {
            chain: base(),
            intent_id: intent_id(intent),
        })
        .await
        .expect_err("replay must fail")
}

#[tokio::test]
async fn ciphertext_body_tamper_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    let last = record.ciphertext.len() - 1;
    record.ciphertext[last] ^= 0xFF;
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn nonce_tamper_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    record.ciphertext[17] ^= 0xFF;
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn version_tamper_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    record.ciphertext[0] ^= 0x01;
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn kid_tamper_to_known_key_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::rotatable();
    let stream = fixture_stream(&provider);
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    record.ciphertext[1..17].copy_from_slice(&KID_B);
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn unknown_kid_is_unknown_key_id() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    record.ciphertext[1..17].copy_from_slice(&KID_B);
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(
        replay_error(&writer, INTENT).await,
        AuditError::UnknownKeyId
    );
}

#[tokio::test]
async fn wrong_key_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let sealing_provider = FixedProvider::single();
    let stream = fixture_stream(&sealing_provider);
    store.seed(vec![sealed_record(
        &lifecycle_event(1),
        support::KID_A,
        SEAL_A,
        &stream,
    )]);

    // Replay under the same kid and blind key but a different seal key.
    let writer = writer(Arc::clone(&store), FixedProvider::wrong_key());
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn swapped_ciphertext_between_sequences_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let first = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    let second = sealed_record(&lifecycle_event(2), support::KID_A, SEAL_A, &stream);

    let mut swapped_first = first.clone();
    swapped_first.ciphertext = second.ciphertext.clone();
    let mut swapped_second = second;
    swapped_second.ciphertext = first.ciphertext;
    store.seed(vec![swapped_first, swapped_second]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(replay_error(&writer, INTENT).await, AuditError::OpenFailed);
}

#[tokio::test]
async fn foreign_stream_ciphertext_is_open_failed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let other_stream = support::stream_for(&provider, "other-intent");
    assert_ne!(stream, other_stream);

    // Ciphertext authenticates the real stream, but the record claims another.
    let mut record = sealed_record(&lifecycle_event(1), support::KID_A, SEAL_A, &stream);
    record.stream_blind_index = other_stream.clone();
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(
        replay_error(&writer, "other-intent").await,
        AuditError::OpenFailed
    );
}

#[tokio::test]
async fn inner_outer_sequence_mismatch_is_record_malformed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    // The outer record claims sequence 1 (contiguous for replay) while the
    // sealed payload carries sequence 2.
    let record =
        sealed_record_with_outer(&lifecycle_event(2), support::KID_A, SEAL_A, &stream, 1, 1);
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(
        replay_error(&writer, INTENT).await,
        AuditError::RecordMalformed
    );
}

#[tokio::test]
async fn inner_outer_schema_mismatch_is_record_malformed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    let mut inner = lifecycle_event(1);
    inner.schema_version = 2;
    let record = sealed_record_with_outer(&inner, support::KID_A, SEAL_A, &stream, 1, 1);
    store.seed(vec![record]);

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(
        replay_error(&writer, INTENT).await,
        AuditError::RecordMalformed
    );
}

#[tokio::test]
async fn provider_kid_mismatch_is_key_id_mismatch_without_reading() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(MismatchedKidProvider));
    let error = writer
        .replay_with_index_key(
            AuditLookup::Intent {
                chain: base(),
                intent_id: intent_id(INTENT),
            },
            support::KID_A,
        )
        .await
        .expect_err("provider returned a different kid");
    assert_eq!(error, AuditError::KeyIdMismatch);
    assert_eq!(store.read_calls(), 0, "mismatch must fail before any read");
}

#[tokio::test]
async fn wire_kid_mismatch_is_key_id_mismatch() {
    let store = Arc::new(CountingStore::new());
    // The stream is addressed with KID_A's blind index, but the record's wire
    // header claims KID_B while the provider keeps returning KID_A material.
    let stream = support::stream_for_kid(&FixedProvider::single(), support::KID_A, INTENT);
    let record = sealed_record(&lifecycle_event(1), KID_B, SEAL_B, &stream);
    store.seed(vec![record]);

    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(StickyKidProvider));
    let error = writer
        .replay_with_index_key(
            AuditLookup::Intent {
                chain: base(),
                intent_id: intent_id(INTENT),
            },
            support::KID_A,
        )
        .await
        .expect_err("wire kid does not match provider material");
    assert_eq!(error, AuditError::KeyIdMismatch);
}

#[tokio::test]
async fn misreported_stream_index_is_record_malformed() {
    let store = Arc::new(CountingStore::new());
    let provider = FixedProvider::single();
    let stream = fixture_stream(&provider);
    store.seed(vec![sealed_record(
        &lifecycle_event(1),
        support::KID_A,
        SEAL_A,
        &stream,
    )]);
    // The store hands back a matching row under a foreign stream index.
    store.corrupt_stream_index();

    let writer = writer(Arc::clone(&store), provider);
    assert_eq!(
        replay_error(&writer, INTENT).await,
        AuditError::RecordMalformed
    );
}
