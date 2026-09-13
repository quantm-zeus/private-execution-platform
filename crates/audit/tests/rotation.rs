//! Blind-index key rotation: replay must select the index key explicitly.
//!
//! Records written under an older blind-index key live on a different stream
//! than records written after rotation. `replay_with_index_key` resolves the
//! requested key id through `by_id`, so an old stream is reachable and an
//! unknown id fails closed instead of silently returning zero rows.

mod support;

use std::sync::Arc;

use audit::{AuditError, AuditLookup, AuditWriter};
use support::{
    base, bucket, intent_id, lifecycle_event, CountingStore, FixedProvider, INTENT, KID_A, KID_B,
    UNKNOWN_KID,
};

fn intent_lookup() -> AuditLookup {
    AuditLookup::Intent {
        chain: base(),
        intent_id: intent_id(INTENT),
    }
}

#[tokio::test]
async fn rotation_replays_old_stream_only_with_explicit_old_index_key() {
    let store = Arc::new(CountingStore::new());
    let events: Vec<_> = (1..=3).map(lifecycle_event).collect();

    // Records are written while KID_A is the current key.
    let before = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::single()));
    before
        .append_lifecycle(&events, bucket())
        .await
        .expect("append under old key");

    // Rotate: KID_B is current, KID_A is still reachable through `by_id`.
    let after = AuditWriter::new(Arc::clone(&store), Arc::new(FixedProvider::rotated()));

    let old = after
        .replay_with_index_key(intent_lookup(), KID_A)
        .await
        .expect("old index key replay");
    assert!(old == events, "old index key must see the old stream");

    let new = after
        .replay_with_index_key(intent_lookup(), KID_B)
        .await
        .expect("new index key replay");
    assert!(new.is_empty(), "the rotated stream is genuinely empty");

    let error = after
        .replay_with_index_key(intent_lookup(), UNKNOWN_KID)
        .await
        .expect_err("unknown index key must not be a silent empty success");
    assert_eq!(error, AuditError::UnknownKeyId);

    // The convenience method deliberately sees only the current stream.
    let current = after
        .replay_current(intent_lookup())
        .await
        .expect("current replay");
    assert!(current.is_empty());
}

#[tokio::test]
async fn old_and_new_index_keys_address_distinct_streams() {
    let provider = FixedProvider::rotated();
    let old = support::stream_for_kid(&provider, KID_A, INTENT);
    let new = support::stream_for_kid(&provider, KID_B, INTENT);
    assert_ne!(old, new, "rotation must change the stream blind index");
}
