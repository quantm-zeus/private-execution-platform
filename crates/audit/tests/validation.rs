//! Lifecycle ordering validation.

mod support;

use std::sync::Arc;

use audit::{AuditError, AuditWriter};
use support::{bucket, event_without_signing, lifecycle_event, CountingStore, FixedProvider};

#[tokio::test]
async fn relay_outcome_before_signing_is_rejected() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));

    let error = writer
        .append(&event_without_signing(1), bucket())
        .await
        .expect_err("append must fail");
    assert_eq!(
        error,
        AuditError::EventValidationFailed("relay outcome before signing")
    );
    assert_eq!(store.append_calls(), 0);
}

#[tokio::test]
async fn valid_lifecycle_event_passes_validation() {
    lifecycle_event(1).validate().expect("fixture validates");
}
