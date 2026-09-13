//! The persisted record and raw ciphertext must not reveal trading semantics.

mod support;

use std::sync::Arc;

use audit::AuditWriter;
use support::{bucket, lifecycle_event, CountingStore, FixedProvider};

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

const FORBIDDEN: &[&str] = &[
    "1000000000",
    "2500000000",
    "2250000000",
    "5000000",
    "250000000",
    "USDC",
    "TOKEN",
    "wallet-alpha",
    "intent-alpha",
    "idem-alpha",
    "user-alpha",
    "venue-alpha",
    "pool-alpha",
    "ref-alpha",
    "relay-ref-alpha",
    "exec-alpha",
    "0x",
    "http",
    "://",
    "grpc",
];

#[tokio::test]
async fn outer_record_and_raw_ciphertext_leak_no_plaintext() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    let event = lifecycle_event(1);
    writer.append(&event, bucket()).await.expect("append");

    let records = store.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];

    let json = serde_json::to_string(record).expect("serialize record");
    for token in FORBIDDEN {
        assert!(!json.contains(token), "serialized record leaked `{token}`");
        assert!(
            !contains_bytes(&record.ciphertext, token.as_bytes()),
            "ciphertext leaked `{token}`"
        );
    }

    // The full plaintext payload must not be recoverable from the ciphertext.
    let plaintext = serde_json::to_vec(&event).expect("plaintext");
    assert!(!contains_bytes(&record.ciphertext, &plaintext));
    assert!(record.ciphertext.len() > plaintext.len());
}
