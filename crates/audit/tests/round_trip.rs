//! Full-lifecycle round trip and replay ordering.

mod support;

use std::sync::Arc;

use audit::{AuditLookup, AuditRecordRef, AuditWriter};
use support::{
    base, bucket, execution_id, idempotency_key, intent_id, lifecycle_event, user_id,
    CountingStore, FixedProvider, EXECUTION, IDEMPOTENCY, INTENT, USER,
};

#[tokio::test]
async fn full_lifecycle_round_trips_in_order() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    let events: Vec<_> = (1..=5).map(lifecycle_event).collect();

    writer
        .append_lifecycle(&events, bucket())
        .await
        .expect("append lifecycle");
    assert_eq!(store.append_calls(), 5);

    let replayed = writer
        .replay_current(AuditLookup::Intent {
            chain: base(),
            intent_id: intent_id(INTENT),
        })
        .await
        .expect("replay intent");
    assert!(replayed == events);
}

#[tokio::test]
async fn append_returns_sequence_and_bucket_and_updates_replay() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));

    let reference: AuditRecordRef = writer
        .append(&lifecycle_event(1), bucket())
        .await
        .expect("append");
    assert_eq!(reference.sequence, 1);
    assert_eq!(reference.created_bucket, bucket());

    let replayed = writer
        .replay_current(AuditLookup::Intent {
            chain: base(),
            intent_id: intent_id(INTENT),
        })
        .await
        .expect("replay");
    assert_eq!(replayed.len(), 1);
    assert!(replayed[0] == lifecycle_event(1));
}

#[tokio::test]
async fn execution_and_idempotency_lookups_filter_the_stream() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    let events: Vec<_> = (1..=3).map(lifecycle_event).collect();
    writer
        .append_lifecycle(&events, bucket())
        .await
        .expect("append");

    let by_execution = writer
        .replay_current(AuditLookup::Execution {
            chain: base(),
            intent_id: intent_id(INTENT),
            execution_id: execution_id(EXECUTION),
        })
        .await
        .expect("replay execution");
    assert!(by_execution == events);

    let by_idempotency = writer
        .replay_current(AuditLookup::Idempotency {
            chain: base(),
            intent_id: intent_id(INTENT),
            idempotency_key: idempotency_key(IDEMPOTENCY),
        })
        .await
        .expect("replay idempotency");
    assert!(by_idempotency == events);

    let other_idempotency = writer
        .replay_current(AuditLookup::Idempotency {
            chain: base(),
            intent_id: intent_id(INTENT),
            idempotency_key: idempotency_key("other-idem"),
        })
        .await
        .expect("replay filtered");
    assert!(other_idempotency.is_empty());
}

#[tokio::test]
async fn owner_lookup_is_authenticated_by_the_owner_blind_index() {
    let store = Arc::new(CountingStore::new());
    let writer = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    let events: Vec<_> = (1..=3).map(lifecycle_event).collect();
    writer
        .append_lifecycle(&events, bucket())
        .await
        .expect("append");

    let by_owner = writer
        .replay_current(AuditLookup::Owner {
            chain: base(),
            intent_id: intent_id(INTENT),
            user_id: user_id(USER),
        })
        .await
        .expect("replay owner");
    assert!(by_owner == events);

    // A different owner id derives a different keyed token, so no event matches
    // even though the stream is the same.
    let other_owner = writer
        .replay_current(AuditLookup::Owner {
            chain: base(),
            intent_id: intent_id(INTENT),
            user_id: user_id("other-user"),
        })
        .await
        .expect("replay other owner");
    assert!(other_owner.is_empty());
}
