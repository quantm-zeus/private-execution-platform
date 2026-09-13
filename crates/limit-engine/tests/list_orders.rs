//! P58 read model: bounded, owner-scoped order listing over the durable store.

mod support;

use std::sync::Arc;

use domain::{OrderStatus, UserId};
use limit_engine::{CreateOutcome, LimitOrderStore, MAX_OWNER_ORDERS};
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

fn owner() -> UserId {
    UserId::new("u1").expect("valid owner")
}

fn other_owner() -> UserId {
    UserId::new("u2").expect("valid owner")
}

async fn seed(
    store: &limit_engine::DurableLimitOrderStore<InMemoryOpaqueStore>,
    records: impl IntoIterator<Item = limit_engine::StoredLimitOrder>,
) {
    for record in records {
        match store.create(record).await.expect("create") {
            CreateOutcome::Created(_) => {}
            CreateOutcome::Existing(_) => panic!("unexpected existing order"),
        }
    }
}

#[tokio::test]
async fn lists_only_the_owners_orders() {
    let fake = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let store = durable_store(&fake, &keys);

    let active = durable_order(&keys, "a", OrderStatus::Active, 100, 100, 0);
    let filled = durable_order(&keys, "b", OrderStatus::Filled, 50, 0, 50);
    let mut foreign = durable_order(&keys, "c", OrderStatus::Active, 10, 10, 0);
    foreign.order.owner = other_owner();
    seed(&store, [active.clone(), filled.clone(), foreign.clone()]).await;

    let mut all = store
        .list_orders_for_owner(&owner(), None, 10)
        .await
        .expect("list");
    all.sort_by(|left, right| left.order.id.as_str().cmp(right.order.id.as_str()));
    let mut expected = vec![active.order.id.clone(), filled.order.id.clone()];
    expected.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(
        all.iter()
            .map(|record| record.order.id.clone())
            .collect::<Vec<_>>(),
        expected
    );

    // Status filter is exact.
    let only_active = store
        .list_orders_for_owner(&owner(), Some(OrderStatus::Active), 10)
        .await
        .expect("list");
    assert_eq!(only_active.len(), 1);
    assert_eq!(only_active[0].order.id, active.order.id);

    let only_filled = store
        .list_orders_for_owner(&owner(), Some(OrderStatus::Filled), 10)
        .await
        .expect("list");
    assert_eq!(only_filled.len(), 1);
    assert_eq!(only_filled[0].order.id, filled.order.id);

    // A different owner sees exactly their own order.
    let theirs = store
        .list_orders_for_owner(&other_owner(), None, 10)
        .await
        .expect("list");
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].order.id, foreign.order.id);

    // An unknown owner sees nothing.
    let nobody = UserId::new("u3").expect("valid owner");
    assert!(store
        .list_orders_for_owner(&nobody, None, 10)
        .await
        .expect("list")
        .is_empty());
}

#[tokio::test]
async fn limit_zero_is_a_noop_and_the_cap_is_enforced() {
    let fake = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(9));
    let store = durable_store(&fake, &keys);

    // Strictly more orders than the hard cap, so the clamp is exercised rather
    // than merely satisfied.
    let records: Vec<_> = (0..MAX_OWNER_ORDERS + 16)
        .map(|index| {
            durable_order(
                &keys,
                &format!("k{index}"),
                OrderStatus::Active,
                100,
                100,
                0,
            )
        })
        .collect();
    seed(&store, records).await;

    assert!(store
        .list_orders_for_owner(&owner(), None, 0)
        .await
        .expect("list")
        .is_empty());

    let capped = store
        .list_orders_for_owner(&owner(), None, usize::MAX)
        .await
        .expect("list");
    assert_eq!(capped.len(), MAX_OWNER_ORDERS);

    let explicit = store
        .list_orders_for_owner(&owner(), None, 5)
        .await
        .expect("list");
    assert_eq!(explicit.len(), 5);
}

/// A single corrupt object in the owner's class/owner index is skipped, and the
/// healthy orders are still listed.
#[tokio::test]
async fn a_corrupt_object_is_skipped_not_fatal() {
    use limit_engine::{class_blind_index, owner_blind_index};
    use storage::{CreatedBucket, OpaqueObject, OpaqueStore};

    let fake = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(11));
    let store = durable_store(&fake, &keys);
    let healthy = durable_order(&keys, "healthy", OrderStatus::Active, 100, 100, 0);
    seed(&store, [healthy.clone()]).await;

    // An object that matches the class and owner blind indexes but cannot be
    // opened (garbage ciphertext) must not hide the healthy order.
    let material = keys.material();
    let class = class_blind_index(&material.blind_index).expect("class index");
    let owner_index = owner_blind_index(&material.blind_index, &owner()).expect("owner index");
    fake.put_object(OpaqueObject {
        id: "corrupt-object".to_string(),
        owner_blind_index: owner_index.to_vec(),
        class_blind_index: class.to_vec(),
        version: 1,
        ciphertext: vec![0u8; 96],
        created_bucket: CreatedBucket::new(0).expect("bucket"),
    })
    .await
    .expect("put corrupt object");

    // Confirm the corrupt object really passes both blind-index filters, so the
    // skip below can only come from `open_record` failing (not a filter drop).
    let stored = fake.objects();
    assert!(stored.iter().any(|object| {
        object.id == "corrupt-object"
            && object.class_blind_index == class.to_vec()
            && object.owner_blind_index == owner_index.to_vec()
    }));

    let listed = store
        .list_orders_for_owner(&owner(), None, 10)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].order.id, healthy.order.id);
}

/// A key provider that has no material cannot list (fail closed).
#[tokio::test]
async fn unavailable_keys_fail_closed() {
    let fake = Arc::new(InMemoryOpaqueStore::new());
    let store = limit_engine::DurableLimitOrderStore::new(
        fake,
        Arc::new(limit_engine::UnavailableOrderKeyProvider),
        chain_types::ChainId::Base,
    );
    assert!(matches!(
        store.list_orders_for_owner(&owner(), None, 10).await,
        Err(limit_engine::LimitEngineError::KeyUnavailable)
    ));
}
