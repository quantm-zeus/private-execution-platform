//! Integration tests for the Postgres OpaqueStore implementation (P0-14).
//!
//! These tests run against a REAL Postgres/Timescale instance via
//! `STORAGE_TEST_DSN` (see infra/docker-compose.yml). They use the actual
//! production migration (infra/postgres/migrations/0001_opaque_storage.sql)
//! and prove the full contract matrix: versioning conflicts, contiguous
//! event sequencing, snapshot selection, fail-closed row decoding, and
//! health/unavailable behavior.
//!
//! Setup SQL runs over a dedicated test-only connection, never through the
//! production store surface. This target is feature-gated by
//! `postgres-integration`; default package/workspace tests need no database.
//! When enabled, `STORAGE_TEST_DSN` must point at the dedicated test database.

use storage::pg::PostgresStore;
use storage::{
    ComponentHealth, CreatedBucket, OpaqueObject, OpaqueStore, StorageError, StorageValidationError,
};

const MIGRATION: &str = include_str!("../../../infra/postgres/migrations/0001_opaque_storage.sql");
const DB_TEST_ADVISORY_LOCK: i64 = 0x5047_4f50_4151_5545;

fn test_dsn() -> String {
    std::env::var("STORAGE_TEST_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .expect("STORAGE_TEST_DSN must point at the compose Postgres for integration tests")
}

fn object(id: &str, version: u64) -> OpaqueObject {
    OpaqueObject {
        id: id.to_string(),
        owner_blind_index: vec![1u8; 32],
        class_blind_index: vec![2u8; 32],
        version,
        ciphertext: vec![0xC1; 64],
        created_bucket: CreatedBucket::new(86_400_000).unwrap(),
    }
}

/// Connects the store under test plus a DEDICATED setup connection used only
/// for test SQL (TRUNCATE/seed/corruption). Returns both.
async fn fresh_store() -> (PostgresStore, tokio_postgres::Client) {
    let dsn = test_dsn();
    let store = PostgresStore::connect(&dsn, 2)
        .await
        .expect("connect to test database");
    let (setup, setup_conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .expect("test setup connection");
    tokio::spawn(async move {
        let _ = setup_conn.await;
    });
    // A session-level advisory lock serializes destructive setup across all
    // tests (and even concurrent test processes) while preserving normal
    // cargo test threading. The lock is released when `setup` is dropped.
    setup
        .query_one("SELECT pg_advisory_lock($1)", &[&DB_TEST_ADVISORY_LOCK])
        .await
        .expect("acquire integration-test database lock");
    setup
        .batch_execute(MIGRATION)
        .await
        .expect("apply production opaque-storage migration");
    setup
        .simple_query("TRUNCATE snapshots, events, objects")
        .await
        .expect("truncate tables");
    (store, setup)
}

fn assert_conflict(result: Result<(), StorageError>) {
    assert_eq!(result, Err(StorageError::Conflict));
}

#[tokio::test]
async fn put_and_get_latest_version_round_trip() {
    let (store, _setup) = fresh_store().await;

    store.put_object(object("obj-a", 1)).await.expect("v1 put");
    store.put_object(object("obj-a", 2)).await.expect("v2 put");

    let latest = store
        .get_object("obj-a")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(latest.version, 2);
    assert_eq!(latest.ciphertext, vec![0xC1; 64]);
    assert_eq!(latest.owner_blind_index, vec![1u8; 32]);
}

#[tokio::test]
async fn duplicate_stale_and_gap_versions_conflict() {
    let (store, _setup) = fresh_store().await;

    store.put_object(object("obj-b", 1)).await.expect("v1 put");

    // Duplicate v1.
    assert_conflict(store.put_object(object("obj-b", 1)).await);
    // Stale (below max+1).
    store.put_object(object("obj-b", 2)).await.expect("v2");
    assert_conflict(store.put_object(object("obj-b", 2)).await);
    // Gap (skip 3 -> try 4).
    assert_conflict(store.put_object(object("obj-b", 4)).await);
    // Version 1 on an existing id is a duplicate.
    assert_conflict(store.put_object(object("obj-b", 1)).await);

    // Next exact version succeeds.
    store.put_object(object("obj-b", 3)).await.expect("v3");
}

#[tokio::test]
async fn concurrent_next_version_race_allows_exactly_one_writer() {
    let (store, _setup) = fresh_store().await;
    store
        .put_object(object("obj-race", 1))
        .await
        .expect("seed v1");

    let (left, right) = tokio::join!(
        store.put_object(object("obj-race", 2)),
        store.put_object(object("obj-race", 2))
    );
    assert!(
        (left.is_ok() && right == Err(StorageError::Conflict))
            || (right.is_ok() && left == Err(StorageError::Conflict)),
        "exactly one concurrent next-version writer must win"
    );

    let latest = store
        .get_object("obj-race")
        .await
        .expect("get latest")
        .expect("race object exists");
    assert_eq!(latest.version, 2);
}

#[tokio::test]
async fn get_missing_object_returns_none() {
    let (store, _setup) = fresh_store().await;
    assert!(store
        .get_object("no-such-object")
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn events_must_be_contiguous_per_stream() {
    let (store, _setup) = fresh_store().await;
    let event = |seq: u64| storage::OpaqueEventRecord {
        stream_blind_index: vec![7u8; 32],
        sequence: seq,
        schema_version: 1,
        ciphertext: vec![0xE7; 32],
        created_bucket: CreatedBucket::new(0).unwrap(),
    };

    // First event must be sequence 1.
    assert_conflict(store.append_event(event(2)).await);
    store.append_event(event(1)).await.expect("first event");
    // Duplicate.
    assert_conflict(store.append_event(event(1)).await);
    // Gap.
    assert_conflict(store.append_event(event(3)).await);
    // Contiguous continuation.
    store.append_event(event(2)).await.expect("second event");
    store.append_event(event(3)).await.expect("third event");

    // Independent streams number from 1 independently.
    let mut other = event(1);
    other.stream_blind_index = vec![8u8; 32];
    store.append_event(other).await.expect("other stream first");
}

#[tokio::test]
async fn latest_snapshot_selects_highest_sequence_then_version() {
    let (store, setup) = fresh_store().await;
    let index: Vec<u8> = vec![9u8; 32];
    // Seed snapshots directly: the Phase 0 trait has no snapshot writer.
    async fn seed(
        setup: &tokio_postgres::Client,
        index: &Vec<u8>,
        seq: i64,
        ver: i64,
    ) -> Result<(), tokio_postgres::Error> {
        let ciphertext: Vec<u8> = vec![0x5A; 48];
        let bucket = 0i64;
        setup
            .execute(
                "INSERT INTO snapshots (stream_blind_index, sequence, version, ciphertext, created_bucket)
                 VALUES ($1, $2, $3, $4, $5)",
                &[index, &seq, &ver, &ciphertext, &bucket],
            )
            .await
            .map(|_| ())
    }
    seed(&setup, &index, 3, 1).await.expect("seed 3/1");
    seed(&setup, &index, 2, 9).await.expect("seed 2/9");
    seed(&setup, &index, 3, 2).await.expect("seed 3/2");

    let latest = store
        .latest_snapshot(&index)
        .await
        .expect("latest_snapshot")
        .expect("exists");
    assert_eq!(latest.sequence, 3);
    assert_eq!(latest.version, 2);
    assert_eq!(latest.ciphertext, vec![0x5A; 48]);

    assert!(store
        .latest_snapshot(&[1u8; 32])
        .await
        .expect("latest_snapshot other stream")
        .is_none());
}

#[tokio::test]
async fn invalid_records_are_rejected_before_database_contact() {
    let (store, _setup) = fresh_store().await;
    let mut bad = object("obj-c", 1);
    bad.ciphertext.clear();
    assert!(matches!(
        store.put_object(bad).await,
        Err(StorageError::Invalid(
            StorageValidationError::EmptyCiphertext
        ))
    ));
    // The empty-ciphertext record was rejected client-side; nothing leaked in.
    assert!(store.get_object("obj-c").await.expect("get").is_none());

    let mut bad_event = storage::OpaqueEventRecord {
        stream_blind_index: vec![],
        sequence: 1,
        schema_version: 1,
        ciphertext: vec![1],
        created_bucket: CreatedBucket::new(0).unwrap(),
    };
    assert!(matches!(
        store.append_event(bad_event.clone()).await,
        Err(StorageError::Invalid(
            StorageValidationError::EmptyStreamIndex
        ))
    ));
    bad_event.stream_blind_index = vec![1u8; 32];
    bad_event.sequence = 0;
    assert_eq!(
        store.append_event(bad_event).await,
        Err(StorageError::Invalid(StorageValidationError::ZeroSequence))
    );
}

#[tokio::test]
async fn malformed_persisted_row_fails_closed() {
    let (store, setup) = fresh_store().await;
    store.put_object(object("obj-d", 1)).await.expect("put");

    // Plant a row that satisfies the SQL schema but violates the production
    // storage boundary's bounded blind-index contract. No schema mutation is
    // needed, so repeated runs leave the production migration intact.
    let bad_id = "obj-d-bad";
    let oversized_owner = vec![0xAAu8; 4097];
    let class_index = vec![0x02u8; 32];
    let ciphertext = vec![0xC1u8; 16];
    let version = 1i64;
    let bucket = 0i64;
    setup
        .execute(
            "INSERT INTO objects (id, owner_blind_index, class_blind_index, version, ciphertext, created_bucket)\n             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &bad_id,
                &oversized_owner,
                &class_index,
                &version,
                &ciphertext,
                &bucket,
            ],
        )
        .await
        .expect("plant malformed row");

    assert_eq!(store.get_object(bad_id).await, Err(StorageError::Backend));
    assert!(store
        .get_object("obj-d")
        .await
        .expect("healthy row")
        .is_some());
}

#[tokio::test]
async fn health_reports_healthy_and_unavailable() {
    let (store, _setup) = fresh_store().await;
    let healthy = store.health().await;
    assert_eq!(healthy.status, ComponentHealth::Healthy);

    // Unreachable DSN: connect fails closed, never panics, and the error is
    // the opaque storage error (no DSN text forwarded).
    let bad_dsn = "host=127.0.0.1 port=1 user=x password=x dbname=x";
    let err = PostgresStore::connect(bad_dsn, 1).await.unwrap_err();
    assert_eq!(err, StorageError::Backend);
}
