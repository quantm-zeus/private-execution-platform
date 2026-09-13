//! A production key provider must fail closed and touch no store.

mod support;

use std::sync::Arc;

use audit::{AuditError, AuditLookup, AuditWriter};
use support::{base, bucket, intent_id, lifecycle_event, CountingStore, FixedProvider, INTENT};

#[tokio::test]
async fn unavailable_provider_blocks_append_without_store_calls() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::unavailable()));

    let error = writer
        .append(&lifecycle_event(1), bucket())
        .await
        .expect_err("append must fail");
    assert_eq!(error, AuditError::KeyUnavailable);
    assert_eq!(store.append_calls(), 0, "no write may reach the store");
}

#[tokio::test]
async fn unavailable_provider_blocks_replay_without_store_calls() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::unavailable()));

    let error = writer
        .replay(AuditLookup::Intent {
            chain: base(),
            intent_id: intent_id(INTENT),
        })
        .await
        .expect_err("replay must fail");
    assert_eq!(error, AuditError::KeyUnavailable);
    assert_eq!(store.read_calls(), 0, "no read may reach the store");
}
