//! Crate-local in-memory [`OpaqueStore`] used by unit tests.
//!
//! Integration tests under `tests/` cannot see `cfg(test)` items in the
//! library, so they carry an equivalent fake in `tests/support/mod.rs`. This
//! module exists so the crate itself has a `#[cfg(test)]` fake exactly as the
//! P42 deliverable requires.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use storage::{
    ComponentHealth, CreatedBucket, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    OpaqueStore, StorageError, StorageValidationError,
};

use crate::key::{AuditKeyMaterial, AuditKeyProvider, BlindIndexKey};
use crate::AuditError;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Minimal in-memory event store with a call counter and injectable failure.
#[derive(Default)]
pub(crate) struct InMemoryOpaqueStore {
    events: Mutex<Vec<OpaqueEventRecord>>,
    append_calls: AtomicUsize,
    fail_next: Mutex<Option<StorageError>>,
}

impl InMemoryOpaqueStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn append_calls(&self) -> usize {
        self.append_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn fail_next_append(&self, error: StorageError) {
        *lock(&self.fail_next) = Some(error);
    }
}

#[async_trait]
impl OpaqueStore for InMemoryOpaqueStore {
    async fn put_object(&self, _object: OpaqueObject) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn get_object(&self, _id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        Ok(None)
    }

    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError> {
        self.append_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = lock(&self.fail_next).take() {
            return Err(error);
        }
        event.validate()?;
        let mut events = lock(&self.events);
        let expected = events
            .iter()
            .filter(|stored| stored.stream_blind_index == event.stream_blind_index)
            .map(|stored| stored.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        if event.sequence != expected {
            return Err(StorageError::Conflict);
        }
        events.push(event);
        Ok(())
    }

    async fn read_events(
        &self,
        stream_blind_index: &[u8],
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        if stream_blind_index.is_empty() {
            return Err(StorageError::Invalid(
                StorageValidationError::EmptyStreamIndex,
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let events = lock(&self.events);
        let mut records: Vec<OpaqueEventRecord> = events
            .iter()
            .filter(|stored| {
                stored.stream_blind_index == stream_blind_index && stored.sequence >= from_sequence
            })
            .cloned()
            .collect();
        records.sort_by_key(|record| record.sequence);
        records.truncate(limit);
        Ok(records)
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Ok(None)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "audit.test.memory",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

/// Single-key provider for unit tests.
pub(crate) struct FixedKeyProvider {
    kid: [u8; 16],
    seal: [u8; 32],
    blind_index: [u8; 32],
}

impl FixedKeyProvider {
    pub(crate) fn new(kid: [u8; 16], seal: [u8; 32], blind_index: [u8; 32]) -> Self {
        Self {
            kid,
            seal,
            blind_index,
        }
    }
}

impl AuditKeyProvider for FixedKeyProvider {
    fn current(&self) -> Result<AuditKeyMaterial, AuditError> {
        Ok(AuditKeyMaterial {
            kid: self.kid,
            seal: crypto_envelope::SealKey::from_bytes(self.seal),
            blind_index: BlindIndexKey::from_bytes(self.blind_index),
        })
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<AuditKeyMaterial, AuditError> {
        if kid == &self.kid {
            self.current()
        } else {
            Err(AuditError::UnknownKeyId)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(stream: u8, sequence: u64) -> OpaqueEventRecord {
        OpaqueEventRecord {
            stream_blind_index: vec![stream],
            sequence,
            schema_version: 1,
            ciphertext: vec![0xAA],
            created_bucket: CreatedBucket::new(1).expect("bucket"),
        }
    }

    #[tokio::test]
    async fn fake_enforces_contiguous_sequences_per_stream() {
        let store = InMemoryOpaqueStore::new();
        assert!(store.append_event(record(1, 1)).await.is_ok());
        assert_eq!(
            store.append_event(record(1, 3)).await,
            Err(StorageError::Conflict)
        );
        assert_eq!(
            store.append_event(record(1, 1)).await,
            Err(StorageError::Conflict)
        );
        // A distinct stream restarts at one.
        assert!(store.append_event(record(2, 1)).await.is_ok());
    }

    #[tokio::test]
    async fn fake_reads_in_order_and_honors_limit() {
        let store = InMemoryOpaqueStore::new();
        for sequence in 1..=3 {
            store
                .append_event(record(1, sequence))
                .await
                .expect("append");
        }
        let batch = store.read_events(&[1], 2, 5).await.expect("read");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].sequence, 2);
        assert_eq!(batch[1].sequence, 3);
        assert!(store
            .read_events(&[1], 1, 0)
            .await
            .expect("empty limit")
            .is_empty());
    }

    #[tokio::test]
    async fn fake_counts_appends_and_injects_failure() {
        let store = InMemoryOpaqueStore::new();
        store.fail_next_append(StorageError::Conflict);
        assert_eq!(
            store.append_event(record(1, 1)).await,
            Err(StorageError::Conflict)
        );
        assert_eq!(store.append_calls(), 1);
    }

    #[test]
    fn fixed_provider_returns_current_and_rejects_unknown() {
        let provider = FixedKeyProvider::new([1u8; 16], [2u8; 32], [3u8; 32]);
        assert!(provider.current().is_ok());
        assert!(provider.by_id(&[1u8; 16]).is_ok());
        assert_eq!(
            provider.by_id(&[9u8; 16]).err(),
            Some(AuditError::UnknownKeyId)
        );
    }
}
