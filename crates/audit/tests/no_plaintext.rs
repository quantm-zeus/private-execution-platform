//! The persisted record and raw ciphertext must not reveal trading semantics.

mod support;

use std::sync::Arc;

use audit::AuditWriter;
use support::{bucket, lifecycle_event, CountingStore, FixedProvider};

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
    assert!(
        !has_hex_run(&json, 8),
        "serialized record contained a long hex run"
    );
    let lossy = String::from_utf8_lossy(&record.ciphertext);
    // The wire header embeds raw key-id bytes; the fixture uses non-hex digits
    // so this check targets an accidental hex encoding of a digest, not the
    // protocol header itself.
    assert!(
        !has_hex_run(&lossy, 8),
        "raw ciphertext contained a long hex run"
    );

    // The full plaintext payload must not be recoverable from the ciphertext.
    let plaintext = serde_json::to_vec(&event).expect("plaintext");
    assert!(!contains_bytes(&record.ciphertext, &plaintext));
    assert!(record.ciphertext.len() > plaintext.len());
}
