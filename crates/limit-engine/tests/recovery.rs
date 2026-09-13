//! P46 recovery: enumerate open orders, repair lagging objects, no double fill.

mod support;

use std::sync::Arc;

use async_trait::async_trait;
use chain_types::ChainId;
use domain::OrderStatus;
use limit_engine::journal::{RECOVERY_LIST_LIMIT, RECOVERY_MAX_OBJECTS};
use limit_engine::{
    apply_transition, conservation_holds, object_id, recover_open, AppendOutcome,
    DurableLimitOrderStore, FillDelta, LimitEngineError, LimitOrderStore, OrderTransition,
    StoredLimitOrder,
};
use market_types::AtomicAmount;
use storage::{
    ClassListCursor, ComponentHealth, CreatedBucket, HealthProbe, OpaqueEventRecord, OpaqueObject,
    OpaqueSnapshot, OpaqueStore, StorageError,
};
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

type Fake = InMemoryOpaqueStore;
type Store = DurableLimitOrderStore<Fake>;

fn keys() -> Arc<TestOrderKeys> {
    Arc::new(TestOrderKeys::deterministic(11))
}

fn fake() -> Arc<Fake> {
    Arc::new(Fake::new())
}

fn fill(input: u128, output: u128, remaining_after: u128) -> FillDelta {
    FillDelta {
        simulated_net_input: AtomicAmount::new(input),
        simulated_net_output: AtomicAmount::new(output),
        remaining_after: AtomicAmount::new(remaining_after),
    }
}

async fn step(
    store: &Store,
    order: &StoredLimitOrder,
    to: OrderStatus,
    fill: Option<FillDelta>,
    at_ms: i64,
) -> StoredLimitOrder {
    let current = store
        .load(&order.order.id)
        .await
        .expect("load")
        .expect("present");
    let next = apply_transition(&current, to, fill.as_ref(), at_ms).expect("valid transition");
    let transition = OrderTransition {
        order_id: current.order.id.clone(),
        from: current.order.status,
        to,
        transition_seq: current.last_transition_seq + 1,
        fill,
        at_ms,
    };
    match store
        .append_transition(current.version, &transition, &next)
        .await
        .expect("append")
    {
        AppendOutcome::Applied(state) => state,
        other => panic!("expected Applied, got {other:?}"),
    }
}

fn object_id_for(keys: &TestOrderKeys, order: &StoredLimitOrder) -> String {
    object_id(&keys.blind_key(), &ChainId::Base, &order.order.id).expect("object id")
}

#[tokio::test]
async fn recover_open_returns_only_non_terminal_orders() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let open = durable_order(&keys, "rec-open", OrderStatus::Created, 1_000, 1_000, 0);
    let closed = durable_order(&keys, "rec-closed", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(open.clone()).await.expect("create open");
    store.create(closed.clone()).await.expect("create closed");
    step(&store, &closed, OrderStatus::Cancelled, None, 10).await;

    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.open.len(), 1);
    assert_eq!(outcome.open[0].order.id, open.order.id);
    assert!(outcome.quarantined.is_empty());
    assert!(!outcome.truncated);
}

#[tokio::test]
async fn recover_open_repairs_a_lagging_object() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "rec-lag", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    step(&store, &order, OrderStatus::Active, None, 10).await;
    let candidate = step(&store, &order, OrderStatus::TriggerCandidate, None, 20).await;

    let object_id = object_id_for(&keys, &order);
    fake.truncate_object_versions(&object_id, 1);
    assert_eq!(
        fake.latest_object(&object_id).map(|object| object.version),
        Some(1)
    );

    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.open.len(), 1);
    assert_eq!(outcome.open[0], candidate);
    // The lagging object was repaired up to the authoritative stream head.
    assert_eq!(
        fake.latest_object(&object_id).map(|object| object.version),
        Some(candidate.version)
    );
}

#[tokio::test]
async fn recover_open_never_double_applies_a_fill() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "rec-fill", OrderStatus::Executing, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    let partial = step(
        &store,
        &order,
        OrderStatus::PartiallyFilled,
        Some(fill(400, 95, 600)),
        10,
    )
    .await;
    assert_eq!(partial.filled_input, AtomicAmount::new(400));

    let object_id = object_id_for(&keys, &order);
    fake.truncate_object_versions(&object_id, 1);

    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.open.len(), 1);
    assert_eq!(outcome.open[0].filled_input, AtomicAmount::new(400));
    assert_eq!(
        outcome.open[0].order.remaining_input,
        AtomicAmount::new(600)
    );
    assert!(conservation_holds(&outcome.open[0]));
}

#[tokio::test]
async fn recover_open_repairs_terminal_orders_without_returning_them() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "rec-terminal", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    step(&store, &order, OrderStatus::Active, None, 10).await;
    step(&store, &order, OrderStatus::TriggerCandidate, None, 20).await;
    step(&store, &order, OrderStatus::Quoting, None, 30).await;
    step(&store, &order, OrderStatus::Simulating, None, 40).await;
    step(&store, &order, OrderStatus::Executing, None, 50).await;
    let filled = step(
        &store,
        &order,
        OrderStatus::Filled,
        Some(fill(1_000, 250, 0)),
        60,
    )
    .await;

    let object_id = object_id_for(&keys, &order);
    fake.truncate_object_versions(&object_id, 1);
    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert!(outcome.open.is_empty(), "terminal orders are not open");
    assert_eq!(
        fake.latest_object(&object_id).map(|object| object.version),
        Some(filled.version)
    );
}

#[tokio::test]
async fn recover_open_is_idempotent() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "rec-idem", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    step(&store, &order, OrderStatus::Active, None, 10).await;

    let object_id = object_id_for(&keys, &order);
    fake.truncate_object_versions(&object_id, 1);

    let first = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("first recover");
    let objects_after_first = fake.objects().len();
    let second = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("second recover");
    assert_eq!(first, second);
    assert_eq!(fake.objects().len(), objects_after_first);
}

#[tokio::test]
async fn recover_open_quarantines_a_tampered_order_and_recovers_healthy_ones() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let healthy = durable_order(&keys, "rec-healthy", OrderStatus::Created, 1_000, 1_000, 0);
    let tampered = durable_order(&keys, "rec-tampered", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(healthy.clone()).await.expect("create healthy");
    store
        .create(tampered.clone())
        .await
        .expect("create tampered");

    let tampered_id = object_id_for(&keys, &tampered);
    let mut object = fake.latest_object(&tampered_id).expect("tampered object");
    let last = object.ciphertext.len() - 1;
    object.ciphertext[last] ^= 0xFF;
    fake.replace_object(object);

    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recovery must not abort on one bad order");
    assert_eq!(outcome.open.len(), 1);
    assert_eq!(outcome.open[0].order.id, healthy.order.id);
    assert_eq!(outcome.quarantined.len(), 1);
    assert_eq!(outcome.quarantined[0].object_id, tampered_id);
    assert_eq!(outcome.quarantined[0].reason, LimitEngineError::OpenFailed);
    assert!(!outcome.truncated);
}

#[tokio::test]
async fn recover_open_pages_beyond_one_listing_page() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let total = RECOVERY_LIST_LIMIT + 1;
    let mut expected = Vec::new();
    for index in 0..total {
        let order = durable_order(
            &keys,
            &format!("rec-page-{index:05}"),
            OrderStatus::Created,
            1_000,
            1_000,
            0,
        );
        store.create(order.clone()).await.expect("create");
        expected.push(order.order.id.as_str().to_string());
    }

    let outcome = recover_open(fake.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.open.len(), total, "every page must be recovered");
    assert!(outcome.quarantined.is_empty());
    assert!(!outcome.truncated);

    let mut got: Vec<String> = outcome
        .open
        .iter()
        .map(|o| o.order.id.as_str().to_string())
        .collect();
    got.sort_unstable();
    expected.sort_unstable();
    assert_eq!(got, expected);
}

/// A hostile store that ignores the cursor and always returns a full page, so
/// enumeration only stops at the hard cap. It lets the truncation path be
/// exercised without persisting `RECOVERY_MAX_OBJECTS` real orders.
struct EndlessListingStore;

#[async_trait]
impl OpaqueStore for EndlessListingStore {
    async fn put_object(&self, _object: OpaqueObject) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn get_object(&self, _id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        Ok(None)
    }

    async fn list_objects_by_class_page(
        &self,
        class_blind_index: &[u8],
        _cursor: Option<&ClassListCursor>,
        limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        Ok((0..limit)
            .map(|index| OpaqueObject {
                id: format!("endless-{index:08}"),
                owner_blind_index: vec![0x11],
                class_blind_index: class_blind_index.to_vec(),
                version: 1,
                ciphertext: vec![0u8; 64],
                created_bucket: CreatedBucket::new(0).expect("bucket"),
            })
            .collect())
    }

    async fn append_event(&self, _event: OpaqueEventRecord) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn read_events(
        &self,
        _stream_blind_index: &[u8],
        _from_sequence: u64,
        _limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        Ok(Vec::new())
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Ok(None)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "test.endless-listing",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

#[tokio::test]
async fn recover_open_reports_truncation_at_the_hard_cap() {
    let keys = keys();
    let endless = Arc::new(EndlessListingStore);
    let outcome = recover_open(endless.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert!(outcome.open.is_empty());
    assert!(
        outcome.truncated,
        "reaching the hard cap must be surfaced, never silent"
    );
    assert_eq!(outcome.quarantined.len(), RECOVERY_MAX_OBJECTS);
}

#[tokio::test]
async fn list_open_fails_closed_at_the_hard_cap() {
    let keys = keys();
    let endless = Arc::new(EndlessListingStore);
    let store = DurableLimitOrderStore::new(endless, keys, ChainId::Base);
    // `list_open` cannot return a truncation flag, so it fails closed instead
    // of silently omitting orders beyond the cap.
    assert_eq!(
        store.list_open().await,
        Err(LimitEngineError::RecoveryFailed)
    );
}
