//! Production Postgres/Timescale implementation of the opaque contracts.
//!
//! Security posture:
//! - This layer is ciphertext-only. It never sees plaintext, never derives
//!   blind indexes, and never computes time (callers supply buckets).
//! - Every record is validated BEFORE any database contact; database
//!   constraint violations and out-of-range decoded values fail closed to
//!   opaque [`StorageError`]s (no row content in errors).
//! - Version/sequence contention is resolved atomically inside single SQL
//!   statements (INSERT..SELECT with next-version/next-sequence gates),
//!   so duplicate, stale, or gapped writes map to
//!   [`StorageError::Conflict`] without check-then-act races.
//! - Nothing about the data (ids, blind indexes, ciphertext) is ever logged;
//!   this module performs no logging at all.
//! - DSNs are provided by the operator through [`PostgresStore::connect`]
//!   and are never serialized into errors.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio_postgres::{error::SqlState, NoTls};

use crate::{
    ComponentHealth, CreatedBucket, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    StorageError, StorageValidationError,
};

/// Upper bound for blind-index / id byte sizes accepted by this layer.
const MAX_INDEX_BYTES: usize = 4096;

/// Connection pool (round-robin over a fixed set of established
/// connections). Phase 0 keeps this deliberately small and dependency-free;
/// a dedicated pool crate can replace the acquisition strategy without
/// changing the trait surface.
pub struct PostgresStore {
    connections: Vec<tokio_postgres::Client>,
    next: AtomicUsize,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore")
            .field("connections", &self.connections.len())
            .finish()
    }
}

fn map_error(error: tokio_postgres::Error) -> StorageError {
    // Preserve the contract-level conflict class without forwarding any DB
    // detail. All other database errors stay opaque.
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        StorageError::Conflict
    } else {
        StorageError::Backend
    }
}

fn validate_index(index: &[u8], what: StorageValidationError) -> Result<(), StorageError> {
    if index.is_empty() || index.len() > MAX_INDEX_BYTES {
        return Err(StorageError::Invalid(what));
    }
    Ok(())
}

fn validate_object(object: &OpaqueObject) -> Result<(), StorageError> {
    object.validate()?;
    validate_index(
        &object.owner_blind_index,
        StorageValidationError::EmptyOwnerIndex,
    )?;
    validate_index(
        &object.class_blind_index,
        StorageValidationError::EmptyClassIndex,
    )?;
    if object.id.len() > MAX_INDEX_BYTES {
        return Err(StorageError::Invalid(StorageValidationError::EmptyId));
    }
    Ok(())
}

fn validate_stream_index(index: &[u8]) -> Result<(), StorageError> {
    validate_index(index, StorageValidationError::EmptyStreamIndex)
}

/// i64 -> u64 conversion that fails closed on negative DB values instead of
/// wrapping.
fn db_u64(raw: i64) -> Result<u64, StorageError> {
    u64::try_from(raw).map_err(|_| StorageError::Backend)
}

impl PostgresStore {
    /// Opens `pool_size` connections to the given DSN. Fails closed if any
    /// connection cannot be established; the store never degrades to a
    /// partial pool. The DSN is consumed here and never stored.
    pub async fn connect(dsn: &str, pool_size: usize) -> Result<Self, StorageError> {
        if pool_size == 0 {
            return Err(StorageError::Unavailable);
        }
        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let (client, connection) = tokio_postgres::connect(dsn, NoTls)
                .await
                .map_err(map_error)?;
            tokio::spawn(async move {
                // Drive the connection until error/close; failures surface
                // through subsequent queries, never through logging here.
                let _ = connection.await;
            });
            connections.push(client);
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
        })
    }

    fn next_client(&self) -> &tokio_postgres::Client {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        &self.connections[index]
    }

    /// Health probe over one pooled connection. `SELECT 1` only; no data
    /// leaves the database through this path.
    pub async fn health(&self) -> HealthProbe {
        let (status, observed_at_ms) = match self.next_client().simple_query("SELECT 1").await {
            Ok(_) => (ComponentHealth::Healthy, 0),
            Err(_) => (ComponentHealth::Unavailable, 0),
        };
        HealthProbe {
            component: "storage.postgres",
            status,
            observed_at_ms,
        }
    }
}

#[async_trait::async_trait]
impl crate::OpaqueStore for PostgresStore {
    async fn put_object(&self, object: OpaqueObject) -> Result<(), StorageError> {
        validate_object(&object)?;
        let version = i64::try_from(object.version)
            .map_err(|_| StorageError::Invalid(StorageValidationError::VersionOutOfRange))?;
        let bucket = object.created_bucket.get();
        // Atomic versioning: the requested `version` is the NEXT version.
        // Version 1 is accepted only when the id is absent; any other version
        // only when it is exactly max(version)+1. The gate compares inside
        // the INSERT..SELECT, and the (id, version) primary key backstops
        // concurrent same-version writers; duplicate/stale/gap all surface
        // as Conflict with no DB text forwarded.
        let inserted = self
            .next_client()
            .execute(
                "WITH gate AS (
                     SELECT CASE
                         WHEN (SELECT max(version) FROM objects WHERE id = $1) IS NULL
                             THEN 1
                         ELSE (SELECT max(version) FROM objects WHERE id = $1) + 1
                     END AS expected
                 )
                 INSERT INTO objects (id, owner_blind_index, class_blind_index, version, ciphertext, created_bucket)
                 SELECT $1, $2, $3, (SELECT expected FROM gate), $4, $5
                 WHERE (SELECT expected FROM gate) = $6
                 ON CONFLICT (id, version) DO NOTHING",
                &[
                    &object.id,
                    &object.owner_blind_index,
                    &object.class_blind_index,
                    &object.ciphertext,
                    &bucket,
                    &version,
                ],
            )
            .await
            .map_err(map_error)?;
        if inserted == 0 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn get_object(&self, id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        if id.trim().is_empty() {
            return Err(StorageError::Invalid(StorageValidationError::EmptyId));
        }
        if id.len() > MAX_INDEX_BYTES {
            return Err(StorageError::Invalid(StorageValidationError::EmptyId));
        }
        let row = self
            .next_client()
            .query_opt(
                "SELECT id, owner_blind_index, class_blind_index, version, ciphertext, created_bucket
                 FROM objects
                 WHERE id = $1
                 ORDER BY version DESC
                 LIMIT 1",
                &[&id],
            )
            .await
            .map_err(map_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: String = row.try_get(0).map_err(|_| StorageError::Backend)?;
        let owner_blind_index: Vec<u8> = row.try_get(1).map_err(|_| StorageError::Backend)?;
        let class_blind_index: Vec<u8> = row.try_get(2).map_err(|_| StorageError::Backend)?;
        let version: i64 = row.try_get(3).map_err(|_| StorageError::Backend)?;
        let ciphertext: Vec<u8> = row.try_get(4).map_err(|_| StorageError::Backend)?;
        let bucket: i64 = row.try_get(5).map_err(|_| StorageError::Backend)?;
        let object = OpaqueObject {
            id,
            owner_blind_index,
            class_blind_index,
            version: db_u64(version)?,
            ciphertext,
            created_bucket: CreatedBucket::new(bucket).ok_or(StorageError::Backend)?,
        };
        // Fail closed on persisted rows that no longer satisfy the contract.
        // A row that fails contract validation is a CORRUPT/foreign row, not
        // caller input, so it maps to the opaque Backend error rather than a
        // validation error that would imply the caller sent bad data.
        validate_object(&object).map_err(|_| StorageError::Backend)?;
        Ok(Some(object))
    }

    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError> {
        event.validate()?;
        validate_stream_index(&event.stream_blind_index)?;
        let sequence = i64::try_from(event.sequence)
            .map_err(|_| StorageError::Invalid(StorageValidationError::SequenceOutOfRange))?;
        let schema_version = i16::try_from(event.schema_version)
            .map_err(|_| StorageError::Invalid(StorageValidationError::ZeroSchemaVersion))?;
        let bucket = event.created_bucket.get();
        // Contiguity gate: each stream receives exactly max(sequence)+1
        // (1 for the first event), enforced atomically against the
        // (stream_blind_index, sequence) primary key.
        let inserted = self
            .next_client()
            .execute(
                "WITH gate AS (
                     SELECT CASE
                         WHEN (SELECT max(sequence) FROM events WHERE stream_blind_index = $1)
                             IS NULL THEN 1
                         ELSE (SELECT max(sequence) FROM events WHERE stream_blind_index = $1) + 1
                     END AS expected
                 )
                 INSERT INTO events (stream_blind_index, sequence, schema_version, ciphertext, created_bucket)
                 SELECT $1, (SELECT expected FROM gate), $2, $3, $4
                 WHERE (SELECT expected FROM gate) = $5
                 ON CONFLICT (stream_blind_index, sequence) DO NOTHING",
                &[
                    &event.stream_blind_index,
                    &schema_version,
                    &event.ciphertext,
                    &bucket,
                    &sequence,
                ],
            )
            .await
            .map_err(map_error)?;
        if inserted == 0 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn read_events(
        &self,
        stream_blind_index: &[u8],
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        validate_stream_index(stream_blind_index)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let from_sequence = i64::try_from(from_sequence)
            .map_err(|_| StorageError::Invalid(StorageValidationError::SequenceOutOfRange))?;
        // A `usize` limit above `i64::MAX` can only mean "unbounded"; clamp to
        // the largest representable row count instead of failing.
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = self
            .next_client()
            .query(
                "SELECT stream_blind_index, sequence, schema_version, ciphertext, created_bucket
                 FROM events
                 WHERE stream_blind_index = $1 AND sequence >= $2
                 ORDER BY sequence ASC
                 LIMIT $3",
                &[&stream_blind_index, &from_sequence, &limit],
            )
            .await
            .map_err(map_error)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let stored_index: Vec<u8> = row.try_get(0).map_err(|_| StorageError::Backend)?;
            let sequence: i64 = row.try_get(1).map_err(|_| StorageError::Backend)?;
            let schema_version: i16 = row.try_get(2).map_err(|_| StorageError::Backend)?;
            let ciphertext: Vec<u8> = row.try_get(3).map_err(|_| StorageError::Backend)?;
            let bucket: i64 = row.try_get(4).map_err(|_| StorageError::Backend)?;
            let record = OpaqueEventRecord {
                stream_blind_index: stored_index,
                sequence: db_u64(sequence)?,
                schema_version: u16::try_from(schema_version).map_err(|_| StorageError::Backend)?,
                ciphertext,
                created_bucket: CreatedBucket::new(bucket).ok_or(StorageError::Backend)?,
            };
            // Corrupt/foreign rows are Backend, not caller-validation errors.
            record.validate().map_err(|_| StorageError::Backend)?;
            validate_stream_index(&record.stream_blind_index).map_err(|_| StorageError::Backend)?;
            // The SQL predicate already restricts `stream_blind_index`, but a
            // decoded row that cannot belong to the requested stream is a
            // corrupt/foreign row and must fail closed rather than be returned.
            debug_assert_eq!(record.stream_blind_index.as_slice(), stream_blind_index);
            if record.stream_blind_index.as_slice() != stream_blind_index {
                return Err(StorageError::Backend);
            }
            records.push(record);
        }
        Ok(records)
    }

    async fn latest_snapshot(
        &self,
        stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        validate_stream_index(stream_blind_index)?;
        let row = self
            .next_client()
            .query_opt(
                "SELECT stream_blind_index, sequence, version, ciphertext, created_bucket
                 FROM snapshots
                 WHERE stream_blind_index = $1
                 ORDER BY sequence DESC, version DESC
                 LIMIT 1",
                &[&stream_blind_index],
            )
            .await
            .map_err(map_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_index: Vec<u8> = row.try_get(0).map_err(|_| StorageError::Backend)?;
        let sequence: i64 = row.try_get(1).map_err(|_| StorageError::Backend)?;
        let version: i64 = row.try_get(2).map_err(|_| StorageError::Backend)?;
        let ciphertext: Vec<u8> = row.try_get(3).map_err(|_| StorageError::Backend)?;
        let bucket: i64 = row.try_get(4).map_err(|_| StorageError::Backend)?;
        let snapshot = OpaqueSnapshot {
            stream_blind_index: stored_index,
            sequence: db_u64(sequence)?,
            version: db_u64(version)?,
            ciphertext,
            created_bucket: CreatedBucket::new(bucket).ok_or(StorageError::Backend)?,
        };
        // Corrupt/foreign rows are Backend, not caller-validation errors.
        snapshot.validate().map_err(|_| StorageError::Backend)?;
        validate_stream_index(&snapshot.stream_blind_index).map_err(|_| StorageError::Backend)?;
        Ok(Some(snapshot))
    }

    async fn health(&self) -> HealthProbe {
        PostgresStore::health(self).await
    }
}
