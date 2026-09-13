//! Persistence contract: idempotent create, CAS append, replay, and listing.

mod support;

use domain::OrderStatus;
use limit_engine::{
    apply_transition, AppendOutcome, CreateOutcome, FillDelta, InMemoryLimitOrderStore,
    LimitEngineError, LimitOrderStore, OrderTransition, StoredLimitOrder,
};
use market_types::AtomicAmount;
use support::{apply_and_append_for, idempotency_key, order_id, stored};

fn fill(input: u128, output: u128, remaining_after: u128) -> FillDelta {
    FillDelta {
        simulated_net_input: AtomicAmount::new(input),
        simulated_net_output: AtomicAmount::new(output),
        remaining_after: AtomicAmount::new(remaining_after),
    }
}

#[tokio::test]
async fn duplicate_create_returns_existing_and_keeps_one_order() {
    let store = InMemoryLimitOrderStore::new();
    let order = stored("o1", OrderStatus::Created, 1_000, 1_000, 0);

    assert_eq!(
        store.create(order.clone()).await.expect("first create"),
        CreateOutcome::Created(order.clone())
    );
    assert_eq!(
        store.create(order.clone()).await.expect("second create"),
        CreateOutcome::Existing(order)
    );
    let open = store.list_open().await.expect("list open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].order.id, order_id("o1"));
}

#[tokio::test]
async fn same_id_with_a_different_key_conflicts() {
    let store = InMemoryLimitOrderStore::new();
    let order = stored("o1", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let mut other = order;
    other.order_idempotency_key = idempotency_key("different");
    assert_eq!(
        store.create(other).await,
        Err(LimitEngineError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn append_is_version_and_sequence_checked() {
    let store = InMemoryLimitOrderStore::new();
    store
        .create(stored("o1", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create");

    let active = apply_and_append_for(&store, "o1", OrderStatus::Active, None, 10).await;
    assert_eq!(active.order.status, OrderStatus::Active);
    assert_eq!(active.version, 2);
    assert_eq!(active.last_transition_seq, 1);

    // Replaying the same sequence is a no-op and does not re-apply anything.
    let replay = OrderTransition {
        order_id: order_id("o1"),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    let current = store
        .load(&order_id("o1"))
        .await
        .expect("load")
        .expect("present");
    assert_eq!(
        store.append_transition(1, &replay, &active).await,
        Ok(AppendOutcome::AlreadyApplied(current.clone()))
    );

    // A stale expected version with a fresh sequence is a conflict.
    let next = apply_transition(&current, OrderStatus::TriggerCandidate, None, 20).expect("derive");
    let forward = OrderTransition {
        order_id: order_id("o1"),
        from: OrderStatus::Active,
        to: OrderStatus::TriggerCandidate,
        transition_seq: 2,
        fill: None,
        at_ms: 20,
    };
    assert_eq!(
        store.append_transition(99, &forward, &next).await,
        Err(LimitEngineError::PersistenceConflict)
    );
    assert_eq!(
        store
            .append_transition(current.version, &forward, &next)
            .await
            .expect("append"),
        AppendOutcome::Applied(next.clone())
    );
    assert_eq!(store.load(&order_id("o1")).await.expect("load"), Some(next));
}

#[tokio::test]
async fn duplicate_fill_append_does_not_double_decrement() {
    let store = InMemoryLimitOrderStore::new();
    store
        .create(stored("o1", OrderStatus::Executing, 1_000, 1_000, 0))
        .await
        .expect("create");

    let delta = fill(400, 95, 600);
    let partial = apply_and_append_for(
        &store,
        "o1",
        OrderStatus::PartiallyFilled,
        Some(delta.clone()),
        10,
    )
    .await;
    assert_eq!(partial.order.remaining_input, AtomicAmount::new(600));

    let transition = OrderTransition {
        order_id: order_id("o1"),
        from: OrderStatus::Executing,
        to: OrderStatus::PartiallyFilled,
        transition_seq: 1,
        fill: Some(delta),
        at_ms: 10,
    };
    let outcome = store
        .append_transition(1, &transition, &partial)
        .await
        .expect("duplicate append");
    match outcome {
        AppendOutcome::AlreadyApplied(state) => {
            assert_eq!(state.order.remaining_input, AtomicAmount::new(600));
            assert_eq!(state.filled_input, AtomicAmount::new(400));
        }
        other => panic!("expected AlreadyApplied, got {other:?}"),
    }

    let loaded = store
        .load(&order_id("o1"))
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.order.remaining_input, AtomicAmount::new(600));
    assert_eq!(loaded.filled_input, AtomicAmount::new(400));
    assert_eq!(loaded.version, 2);
}

#[tokio::test]
async fn replay_from_rebuilds_the_same_state() {
    let store = InMemoryLimitOrderStore::new();
    let filled = drive_to_filled(&store).await;

    for from_seq in [0, 1, 2, 9] {
        assert_eq!(
            store
                .replay_from(&order_id("o1"), from_seq)
                .await
                .unwrap_or_else(|err| panic!("replay from {from_seq} failed: {err:?}")),
            filled,
            "replay from {from_seq}"
        );
    }
}

#[tokio::test]
async fn replay_from_unknown_order_is_store_invalid() {
    let store = InMemoryLimitOrderStore::new();
    assert_eq!(
        store.replay_from(&order_id("missing"), 1).await,
        Err(LimitEngineError::StoreInvalid)
    );
}

#[tokio::test]
async fn replay_beyond_the_log_is_inconsistent() {
    let store = InMemoryLimitOrderStore::new();
    store
        .create(stored("o1", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create");
    apply_and_append_for(&store, "o1", OrderStatus::Active, None, 10).await;
    // The log holds sequence 1; from_seq 3 has no predecessor state.
    assert_eq!(
        store.replay_from(&order_id("o1"), 3).await,
        Err(LimitEngineError::RecoveryInconsistent)
    );
}

#[tokio::test]
async fn terminal_state_never_resurrects() {
    let store = InMemoryLimitOrderStore::new();
    let filled = drive_to_filled(&store).await;
    assert_eq!(filled.order.status, OrderStatus::Filled);

    assert_eq!(
        apply_transition(&filled, OrderStatus::Active, None, 200),
        Err(LimitEngineError::InvalidTransition)
    );

    let illegal = OrderTransition {
        order_id: order_id("o1"),
        from: OrderStatus::Filled,
        to: OrderStatus::Active,
        transition_seq: 9,
        fill: None,
        at_ms: 200,
    };
    let mut bogus = filled.clone();
    bogus.order.status = OrderStatus::Active;
    bogus.version = filled.version + 1;
    bogus.last_transition_seq = 9;
    assert_eq!(
        store
            .append_transition(filled.version, &illegal, &bogus)
            .await,
        Err(LimitEngineError::StoreInvalid)
    );
    assert_eq!(
        store.load(&order_id("o1")).await.expect("load"),
        Some(filled)
    );
}

#[tokio::test]
async fn list_open_excludes_terminal_and_sorts_by_order_id() {
    let store = InMemoryLimitOrderStore::new();
    store
        .create(stored("b", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create b");
    store
        .create(stored("a", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create a");
    apply_and_append_for(&store, "b", OrderStatus::Cancelled, None, 10).await;

    let open = store.list_open().await.expect("list open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].order.id, order_id("a"));
}

#[tokio::test]
async fn mismatched_from_field_is_store_invalid() {
    let store = InMemoryLimitOrderStore::new();
    store
        .create(stored("o1", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create");
    let current = store
        .load(&order_id("o1"))
        .await
        .expect("load")
        .expect("present");
    let next = apply_transition(&current, OrderStatus::Active, None, 10).expect("derive");
    let transition = OrderTransition {
        order_id: order_id("o1"),
        from: OrderStatus::Executing,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    assert_eq!(
        store
            .append_transition(current.version, &transition, &next)
            .await,
        Err(LimitEngineError::StoreInvalid)
    );
    assert_eq!(
        store.load(&order_id("o1")).await.expect("load"),
        Some(current)
    );
}

async fn drive_to_filled(store: &InMemoryLimitOrderStore) -> StoredLimitOrder {
    store
        .create(stored("o1", OrderStatus::Created, 1_000, 1_000, 0))
        .await
        .expect("create");
    apply_and_append_for(store, "o1", OrderStatus::Active, None, 10).await;
    apply_and_append_for(store, "o1", OrderStatus::TriggerCandidate, None, 20).await;
    apply_and_append_for(store, "o1", OrderStatus::Quoting, None, 30).await;
    apply_and_append_for(store, "o1", OrderStatus::Simulating, None, 40).await;
    apply_and_append_for(store, "o1", OrderStatus::Executing, None, 50).await;
    let partial = apply_and_append_for(
        store,
        "o1",
        OrderStatus::PartiallyFilled,
        Some(fill(400, 95, 600)),
        60,
    )
    .await;
    assert_eq!(partial.order.remaining_input, AtomicAmount::new(600));
    apply_and_append_for(store, "o1", OrderStatus::Executing, None, 70).await;
    apply_and_append_for(
        store,
        "o1",
        OrderStatus::Filled,
        Some(fill(600, 150, 0)),
        80,
    )
    .await
}
