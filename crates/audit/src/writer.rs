//! Encrypting audit writer built on [`storage::OpaqueStore`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chain_types::ChainId;
use crypto_envelope::at_rest::{open_at_rest, seal_at_rest, wire_kid};
use domain::{ExecutionId, IdempotencyKey, IntentId, UserId};
use storage::{CreatedBucket, OpaqueEventRecord, OpaqueStore, StorageError};
use zeroize::Zeroizing;

use crate::blind_index;
use crate::error::AuditError;
use crate::event::ExecutionAuditEvent;
use crate::key::{AuditKeyMaterial, AuditKeyProvider, BlindIndexKey};

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
    /// Events on the intent stream that carry this owner.
    Owner {
        /// Chain scope of the stream.
        chain: ChainId,
        /// Intent that owns the stream.
        intent_id: IntentId,
        /// Owner to match.
        user_id: UserId,
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
            | Self::Owner {
                chain, intent_id, ..
            }
            | Self::Execution {
                chain, intent_id, ..
            }
            | Self::Idempotency {
                chain, intent_id, ..
            } => (chain, intent_id),
        }
    }

    /// Whether the decrypted event belongs to this lookup's filtered view.
    ///
    /// Matching is done on the keyed blind-index tokens, not on the plaintext
    /// identifiers: the event's own class token must equal the token derived
    /// from the requested identifier under the same blind-index key. A token
    /// can only match when both were produced by the same key, class domain,
    /// and identifier, so the lookup is authenticated by the same PRF that
    /// addresses the stream.
    fn authenticates(
        &self,
        event: &ExecutionAuditEvent,
        key: &BlindIndexKey,
    ) -> Result<bool, AuditError> {
        match self {
            Self::Intent { .. } => Ok(true),
            Self::Owner { user_id, .. } => Ok(blind_index::owner_blind_index(key, user_id)?
                == blind_index::owner_blind_index(key, &event.user_id)?),
            Self::Execution { execution_id, .. } => {
                let requested = blind_index::execution_blind_index(key, execution_id)?;
                match &event.execution_id {
                    Some(stored) => {
                        Ok(blind_index::execution_blind_index(key, stored)? == requested)
                    }
                    None => Ok(false),
                }
            }
            Self::Idempotency {
                idempotency_key, ..
            } => Ok(blind_index::idempotency_blind_index(key, idempotency_key)?
                == blind_index::idempotency_blind_index(key, &event.idempotency_key)?),
        }
    }
}

impl std::fmt::Debug for AuditLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Intent { .. } => f.write_str("AuditLookup::Intent([REDACTED])"),
            Self::Owner { .. } => f.write_str("AuditLookup::Owner([REDACTED])"),
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

        let payload = Zeroizing::new(
            serde_json::to_vec(event)
                .map_err(|_| AuditError::EventValidationFailed("event serialization failed"))?,
        );
        let ciphertext = seal_at_rest(
            &material.seal,
            &material.kid,
            event.sequence,
            event.schema_version,
            &stream,
            &payload,
        )
        .map_err(|_| AuditError::SealFailed)?;
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

    /// Authenticates and decrypts every record in the lookup's stream using the
    /// blind-index key identified by `blind_index_kid`.
    ///
    /// The key id is explicit because a rotated blind-index key addresses a
    /// different stream. Resolving the id through [`AuditKeyProvider::by_id`]
    /// lets a caller replay records written under an older index key, while an
    /// unknown id fails with [`AuditError::UnknownKeyId`] instead of silently
    /// returning an empty stream. Callers that only care about the current
    /// stream should use [`AuditWriter::replay_current`].
    ///
    /// Enforces contiguous sequences starting at one and requires the inner
    /// event's sequence/schema to equal the outer record's. Any tamper, unknown
    /// key id, gap, or malformed record fails closed with no partial plaintext
    /// returned.
    pub async fn replay_with_index_key(
        &self,
        lookup: AuditLookup,
        blind_index_kid: [u8; 16],
    ) -> Result<Vec<ExecutionAuditEvent>, AuditError> {
        let material = self.keys.by_id(&blind_index_kid)?;
        if material.kid != blind_index_kid {
            return Err(AuditError::KeyIdMismatch);
        }
        self.replay_with_material(lookup, &material).await
    }

    /// Convenience wrapper over [`AuditWriter::replay_with_index_key`] that uses
    /// the provider's current key.
    ///
    /// This only sees streams written under the current blind-index key. After a
    /// rotation, records written under an older index key are addressed with
    /// [`AuditWriter::replay_with_index_key`] and that older key id; using this
    /// method alone would read a different, empty stream.
    pub async fn replay_current(
        &self,
        lookup: AuditLookup,
    ) -> Result<Vec<ExecutionAuditEvent>, AuditError> {
        let material = self.keys.current()?;
        self.replay_with_material(lookup, &material).await
    }

    /// Shared replay body once key material (and therefore the stream index) is
    /// resolved.
    async fn replay_with_material(
        &self,
        lookup: AuditLookup,
        material: &AuditKeyMaterial,
    ) -> Result<Vec<ExecutionAuditEvent>, AuditError> {
        let (chain, intent_id) = lookup.stream_scope();
        let stream = blind_index::stream_blind_index(&material.blind_index, chain, intent_id)?;
        let events = self.read_and_open(&stream).await?;
        let mut filtered = Vec::with_capacity(events.len());
        for event in events {
            if lookup.authenticates(&event, &material.blind_index)? {
                filtered.push(event);
            }
        }
        Ok(filtered)
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
                let plaintext = Zeroizing::new(
                    open_at_rest(
                        &material.seal,
                        &kid,
                        record.sequence,
                        record.schema_version,
                        stream,
                        &record.ciphertext,
                    )
                    .map_err(|_| AuditError::OpenFailed)?,
                );
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
