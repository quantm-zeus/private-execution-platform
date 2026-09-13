//! Encrypting audit writer built on [`storage::OpaqueStore`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chain_types::ChainId;
use crypto_envelope::at_rest::{open_at_rest, seal_at_rest, wire_kid, AT_REST_MIN_LEN};
use domain::{ExecutionId, IdempotencyKey, IntentId};
use storage::{CreatedBucket, OpaqueEventRecord, OpaqueStore, StorageError};

use crate::blind_index;
use crate::error::AuditError;
use crate::event::ExecutionAuditEvent;
use crate::key::AuditKeyProvider;

/// Maximum records fetched per `read_events` round during replay.
const REPLAY_BATCH: usize = 256;

/// Reference to a record that was appended successfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRecordRef {
    /// Sequence within the intent stream.
    pub sequence: u64,
    /// Caller-supplied creation bucket.
    pub created_bucket: CreatedBucket,
}

/// Selects which audit stream to replay and, optionally, which events to keep.
///
/// Every variant carries the chain-scoped intent that owns the persisted stream;
/// see the crate docs for why the single-component sketch cannot address a
/// stream. `Debug` is redacted because the variants hold identifiers.
#[derive(Clone, PartialEq, Eq)]
pub enum AuditLookup {
    /// Every event on the intent stream.
    Intent {
        /// Chain scope of the stream.
        chain: ChainId,
        /// Intent that owns the stream.
        intent_id: IntentId,
    },
    /// Events on the intent stream that carry this execution id.
    Execution {
        /// Chain scope of the stream.
        chain: ChainId,
        /// Intent that owns the stream.
        intent_id: IntentId,
        /// Execution id to match.
        execution_id: ExecutionId,
    },
    /// Events on the intent stream that carry this idempotency key.
    Idempotency {
        /// Chain scope of the stream.
        chain: ChainId,
        /// Intent that owns the stream.
        intent_id: IntentId,
        /// Idempotency key to match.
        idempotency_key: IdempotencyKey,
    },
}

impl AuditLookup {
    /// Returns the chain-scoped stream this lookup reads.
    fn stream_scope(&self) -> (&ChainId, &IntentId) {
        match self {
            Self::Intent { chain, intent_id }
            | Self::Execution {
                chain, intent_id, ..
            }
            | Self::Idempotency {
                chain, intent_id, ..
            } => (chain, intent_id),
        }
    }

    /// Whether a decrypted event belongs to this lookup's filtered view.
    fn matches(&self, event: &ExecutionAuditEvent) -> bool {
        match self {
            Self::Intent { .. } => true,
            Self::Execution { execution_id, .. } => {
                event.execution_id.as_ref() == Some(execution_id)
            }
            Self::Idempotency {
                idempotency_key, ..
            } => &event.idempotency_key == idempotency_key,
        }
    }
}

impl std::fmt::Debug for AuditLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Intent { .. } => f.write_str("AuditLookup::Intent([REDACTED])"),
            Self::Execution { .. } => f.write_str("AuditLookup::Execution([REDACTED])"),
            Self::Idempotency { .. } => f.write_str("AuditLookup::Idempotency([REDACTED])"),
        }
    }
}

/// Encrypting audit writer.
///
/// Holds the store and key provider and a process-local per-stream high-water
/// mark to reject non-increasing sequences cheaply. The store remains the
/// authority: its CAS contiguity gate backstops concurrent or restarted writers.
pub struct AuditWriter<S: OpaqueStore> {
    store: Arc<S>,
    keys: Arc<dyn AuditKeyProvider>,
    last_sequence: Mutex<HashMap<Vec<u8>, u64>>,
}

impl<S: OpaqueStore> std::fmt::Debug for AuditWriter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriter").finish_non_exhaustive()
    }
}

impl<S: OpaqueStore> AuditWriter<S> {
    /// Builds a writer over `store` with `keys`.
    pub fn new(store: Arc<S>, keys: Arc<dyn AuditKeyProvider>) -> Self {
        Self {
            store,
            keys,
            last_sequence: Mutex::new(HashMap::new()),
        }
    }

    /// Validates, seals, and appends one lifecycle event.
    ///
    /// A non-increasing per-stream sequence is rejected before any store write;
    /// a store conflict is surfaced as [`AuditError::StorageConflict`] and never
    /// silently skipped or retried.
    pub async fn append(
        &self,
        event: &ExecutionAuditEvent,
        bucket: CreatedBucket,
    ) -> Result<AuditRecordRef, AuditError> {
        event.validate()?;
        // Key availability is checked before any store contact: no key means
        // nothing is persisted and no ciphertext is fabricated.
        let material = self.keys.current()?;
        let stream =
            blind_index::stream_blind_index(&material.blind_index, &event.chain, &event.intent_id)?
                .to_vec();
        {
            let last = lock(&self.last_sequence);
            if let Some(previous) = last.get(&stream) {
                if event.sequence <= *previous {
                    return Err(AuditError::SequenceNotMonotonic);
                }
            }
        }

        let payload = serde_json::to_vec(event)
            .map_err(|_| AuditError::EventValidationFailed("event serialization failed"))?;
        let ciphertext = seal_at_rest(
            &material.seal,
            &material.kid,
            event.sequence,
            event.schema_version,
            &stream,
            &payload,
        );
        if ciphertext.len() < AT_REST_MIN_LEN {
            return Err(AuditError::SealFailed);
        }
        let record = OpaqueEventRecord {
            stream_blind_index: stream.clone(),
            sequence: event.sequence,
            schema_version: event.schema_version,
            ciphertext,
            created_bucket: bucket,
        };
        record.validate().map_err(|_| AuditError::RecordMalformed)?;

        match self.store.append_event(record).await {
            Ok(()) => {
                lock(&self.last_sequence).insert(stream, event.sequence);
                Ok(AuditRecordRef {
                    sequence: event.sequence,
                    created_bucket: bucket,
                })
            }
            Err(StorageError::Conflict) => Err(AuditError::StorageConflict),
            Err(error) => Err(map_storage(error)),
        }
    }

    /// Validates the whole lifecycle up front, then appends each event in order.
    pub async fn append_lifecycle(
        &self,
        events: &[ExecutionAuditEvent],
        bucket: CreatedBucket,
    ) -> Result<(), AuditError> {
        for event in events {
            event.validate()?;
        }
        for event in events {
            self.append(event, bucket).await?;
        }
        Ok(())
    }

    /// Authenticates and decrypts every record in the lookup's stream.
    ///
    /// Enforces contiguous sequences starting at one and requires the inner
    /// event's sequence/schema to equal the outer record's. Any tamper, unknown
    /// key id, gap, or malformed record fails closed with no partial plaintext
    /// returned.
    pub async fn replay(
        &self,
        lookup: AuditLookup,
    ) -> Result<Vec<ExecutionAuditEvent>, AuditError> {
        let (chain, intent_id) = lookup.stream_scope();
        let material = self.keys.current()?;
        let stream = blind_index::stream_blind_index(&material.blind_index, chain, intent_id)?;
        let events = self.read_and_open(&stream).await?;
        Ok(events
            .into_iter()
            .filter(|event| lookup.matches(event))
            .collect())
    }

    /// Reads, authenticates, and decodes a contiguous stream from sequence one.
    async fn read_and_open(&self, stream: &[u8]) -> Result<Vec<ExecutionAuditEvent>, AuditError> {
        let mut expected: u64 = 1;
        let mut events = Vec::new();
        loop {
            let batch = self
                .store
                .read_events(stream, expected, REPLAY_BATCH)
                .await
                .map_err(map_storage)?;
            let batch_len = batch.len();
            if batch_len == 0 {
                break;
            }
            for record in batch {
                if record.stream_blind_index != stream {
                    return Err(AuditError::RecordMalformed);
                }
                if record.sequence != expected {
                    return Err(AuditError::SequenceGap);
                }
                let kid = wire_kid(&record.ciphertext).map_err(|_| AuditError::OpenFailed)?;
                let material = self.keys.by_id(&kid)?;
                if material.kid != kid {
                    return Err(AuditError::KeyIdMismatch);
                }
                let plaintext = open_at_rest(
                    &material.seal,
                    &kid,
                    record.sequence,
                    record.schema_version,
                    stream,
                    &record.ciphertext,
                )
                .map_err(|_| AuditError::OpenFailed)?;
                let event: ExecutionAuditEvent =
                    serde_json::from_slice(&plaintext).map_err(|_| AuditError::RecordMalformed)?;
                if event.sequence != record.sequence
                    || event.schema_version != record.schema_version
                {
                    return Err(AuditError::RecordMalformed);
                }
                event.validate().map_err(|_| AuditError::RecordMalformed)?;
                events.push(event);
                expected = expected.checked_add(1).ok_or(AuditError::SequenceGap)?;
            }
            if batch_len < REPLAY_BATCH {
                break;
            }
        }
        Ok(events)
    }
}

/// Acquires a mutex, recovering from poisoning. The guarded value is a plain
/// `HashMap`, so a panicking holder cannot leave torn state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Maps a storage failure onto the redacted audit taxonomy.
fn map_storage(error: StorageError) -> AuditError {
    match error {
        StorageError::Conflict => AuditError::StorageConflict,
        StorageError::Invalid(_) => AuditError::RecordMalformed,
        StorageError::Unavailable | StorageError::NotFound | StorageError::Backend => {
            AuditError::StorageUnavailable
        }
    }
}
