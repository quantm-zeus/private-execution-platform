//! In-memory `OpaqueStore` fake and deterministic order keys for the P46
//! journal/recovery tests. No live database is involved.

use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chain_types::ChainId;
use crypto_envelope::at_rest::SealKey;
use domain::{IdempotencyKey, IntentId, OrderId, OrderStatus};
use limit_engine::journal::{
    order_id_for_creation, BlindIndexKey, DurableLimitOrderStore, OrderKeyMaterial,
    OrderKeyProvider,
};
use limit_engine::{LimitEngineError, StoredLimitOrder, DEFAULT_SCHEMA_VERSION};
use market_types::AtomicAmount;
use storage::{
    ClassListCursor, ComponentHealth, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    OpaqueStore, StorageError, StorageValidationError,
};

use super::{idempotency_key, limit_order};

/// Acquires a mutex, recovering from poisoning (the guarded value is plain
/// data, so a panicking holder cannot leave torn state).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Default)]
struct Inner {
    objects: Vec<OpaqueObject>,
    events: Vec<OpaqueEventRecord>,
    /// Every `put_object` call, including those rejected as conflicts. A seal
    /// attempt is visible here even when the CAS discards it.
    put_attempts: Vec<OpaqueObject>,
    /// Every `append_event` call, including conflicting ones.
    event_attempts: Vec<OpaqueEventRecord>,
    put_conflicts: u32,
    /// When set, `get_object` yields once after reading, forcing a racing
    /// writer to interleave between read and write.
    yield_reads: bool,
}

/// Minimal in-memory [`OpaqueStore`] with CAS semantics and injectable
/// object-write conflicts.
#[derive(Default)]
pub struct InMemoryOpaqueStore {
    inner: Mutex<Inner>,
}

impl InMemoryOpaqueStore {
    /// Creates an empty fake.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forces the next `n` object writes to report a CAS conflict.
    pub fn inject_put_conflicts(&self, n: u32) {
        lock(&self.inner).put_conflicts = n;
    }

    /// Every stored object version, in insertion order.
    pub fn objects(&self) -> Vec<OpaqueObject> {
        lock(&self.inner).objects.clone()
    }

    /// Every stored event record, in insertion order.
    pub fn events(&self) -> Vec<OpaqueEventRecord> {
        lock(&self.inner).events.clone()
    }

    /// Every `put_object` attempt, including CAS-rejected ones.
    pub fn put_attempts(&self) -> Vec<OpaqueObject> {
        lock(&self.inner).put_attempts.clone()
    }

    /// Every `append_event` attempt, including conflicted ones.
    pub fn event_attempts(&self) -> Vec<OpaqueEventRecord> {
        lock(&self.inner).event_attempts.clone()
    }

    /// Makes `get_object` yield once after reading, so a racing writer can
    /// interleave between the read and the subsequent write.
    pub fn enable_read_yield(&self) {
        lock(&self.inner).yield_reads = true;
    }

    /// The newest version of each object in `class`, ordered by the
    /// deterministic class listing order.
    fn newest_by_class(&self, class_blind_index: &[u8]) -> Result<Vec<OpaqueObject>, StorageError> {
        if class_blind_index.is_empty() {
            return Err(StorageError::Invalid(
                StorageValidationError::EmptyClassIndex,
            ));
        }
        let inner = lock(&self.inner);
        let mut newest: Vec<OpaqueObject> = Vec::new();
        for object in inner
            .objects
            .iter()
            .filter(|object| object.class_blind_index == class_blind_index)
        {
            match newest.iter_mut().find(|stored| stored.id == object.id) {
                Some(stored) if object.version > stored.version => *stored = object.clone(),
                Some(_) => {}
                None => newest.push(object.clone()),
            }
        }
        newest.sort_by(|left, right| {
            right
                .created_bucket
                .get()
                .cmp(&left.created_bucket.get())
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(newest)
    }

    /// The newest version of `id`, if present.
    pub fn latest_object(&self, id: &str) -> Option<OpaqueObject> {
        lock(&self.inner)
            .objects
            .iter()
            .filter(|object| object.id == id)
            .max_by_key(|object| object.version)
            .cloned()
    }

    /// Replaces every stored version of `object.id` with `object` (test tamper
    /// seam; the real backend is append-only).
    pub fn replace_object(&self, object: OpaqueObject) {
        let mut inner = lock(&self.inner);
        inner.objects.retain(|stored| stored.id != object.id);
        inner.objects.push(object);
    }

    /// Drops every stored version of `id` above `keep_max`, simulating a
    /// materialized object that lags its authoritative event stream.
    pub fn truncate_object_versions(&self, id: &str, keep_max: u64) {
        lock(&self.inner)
            .objects
            .retain(|object| object.id != id || object.version <= keep_max);
    }
}

#[async_trait]
impl OpaqueStore for InMemoryOpaqueStore {
    async fn put_object(&self, object: OpaqueObject) -> Result<(), StorageError> {
        object.validate()?;
        let mut inner = lock(&self.inner);
        inner.put_attempts.push(object.clone());
        if inner.put_conflicts > 0 {
            inner.put_conflicts -= 1;
            return Err(StorageError::Conflict);
        }
        let expected = inner
            .objects
            .iter()
            .filter(|stored| stored.id == object.id)
            .map(|stored| stored.version)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StorageError::Conflict)?;
        if object.version != expected {
            return Err(StorageError::Conflict);
        }
        inner.objects.push(object);
        Ok(())
    }

    async fn get_object(&self, id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        if id.trim().is_empty() {
            return Err(StorageError::Invalid(StorageValidationError::EmptyId));
        }
        let (found, yield_reads) = {
            let inner = lock(&self.inner);
            (
                inner
                    .objects
                    .iter()
                    .filter(|object| object.id == id)
                    .max_by_key(|object| object.version)
                    .cloned(),
                inner.yield_reads,
            )
        };
        if yield_reads {
            tokio::task::yield_now().await;
        }
        Ok(found)
    }

    async fn list_objects_by_class(
        &self,
        class_blind_index: &[u8],
        limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut newest = self.newest_by_class(class_blind_index)?;
        newest.truncate(limit);
        Ok(newest)
    }

    async fn list_objects_by_class_page(
        &self,
        class_blind_index: &[u8],
        cursor: Option<&ClassListCursor>,
        limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut newest = self.newest_by_class(class_blind_index)?;
        if let Some(cursor) = cursor {
            let cursor_bucket = cursor.created_bucket.get();
            newest.retain(|object| {
                let bucket = object.created_bucket.get();
                bucket < cursor_bucket
                    || (bucket == cursor_bucket && object.id.as_str() > cursor.id.as_str())
            });
        }
        newest.truncate(limit);
        Ok(newest)
    }

    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError> {
        event.validate()?;
        let mut inner = lock(&self.inner);
        inner.event_attempts.push(event.clone());
        let expected = inner
            .events
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
        inner.events.push(event);
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
        let inner = lock(&self.inner);
        let mut records: Vec<OpaqueEventRecord> = inner
            .events
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
            component: "test.opaque",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

/// Deterministic order key material for tests.
pub struct TestOrderKeys {
    kid: [u8; 16],
    seal: [u8; 32],
    blind: [u8; 32],
}

impl TestOrderKeys {
    /// Builds a deterministic key set from a single tag byte.
    pub fn deterministic(tag: u8) -> Self {
        Self {
            kid: [tag; 16],
            seal: [tag.wrapping_add(1); 32],
            blind: [tag.wrapping_add(2); 32],
        }
    }

    /// A copy with a different seal key but the same id and blind-index key.
    pub fn with_seal(&self, seal: [u8; 32]) -> Self {
        Self {
            kid: self.kid,
            seal,
            blind: self.blind,
        }
    }

    /// Fresh blind-index key material.
    pub fn blind_key(&self) -> BlindIndexKey {
        BlindIndexKey::from_bytes(self.blind)
    }

    /// The provider's material for the current key id.
    pub fn material(&self) -> OrderKeyMaterial {
        OrderKeyMaterial {
            kid: self.kid,
            seal: SealKey::from_bytes(self.seal),
            blind_index: self.blind_key(),
        }
    }
}

impl OrderKeyProvider for TestOrderKeys {
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError> {
        Ok(self.material())
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError> {
        if kid != &self.kid {
            return Err(LimitEngineError::UnknownKeyId);
        }
        Ok(self.material())
    }
}

/// Builds a durable store over the fake for the Base chain.
pub fn durable_store(
    store: &Arc<InMemoryOpaqueStore>,
    keys: &Arc<TestOrderKeys>,
) -> DurableLimitOrderStore<InMemoryOpaqueStore> {
    DurableLimitOrderStore::new(store.clone(), keys.clone(), ChainId::Base)
}

/// Builds a stored limit order whose id is derived from `creation` exactly as
/// [`order_id_for_creation`] requires.
pub fn durable_order(
    keys: &TestOrderKeys,
    creation: &str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
) -> StoredLimitOrder {
    let creation_key: IdempotencyKey = idempotency_key(creation);
    let derived: OrderId = order_id_for_creation(&keys.blind_key(), &creation_key)
        .expect("derive deterministic order id");
    let order = limit_order(derived.as_str(), status, max, remaining);
    StoredLimitOrder {
        schema_version: DEFAULT_SCHEMA_VERSION,
        version: 1,
        order,
        order_intent_id: IntentId::new(format!("intent-{creation}")).expect("valid intent"),
        order_idempotency_key: creation_key,
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(filled),
        last_transition_seq: 0,
        next_eligible_at_ms: None,
    }
}
