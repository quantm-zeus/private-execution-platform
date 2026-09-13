//! P46 durable encrypted order store: sealing, idempotency, CAS, and replay.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chain_types::ChainId;
use crypto_envelope::at_rest::{AT_REST_HEADER_LEN, AT_REST_KID_LEN, AT_REST_NONCE_LEN};
use domain::{
    LimitOrder, LimitPrice, OrderId, OrderStatus, RiskConstraints, TradeSide, UserId, WalletRef,
};
use limit_engine::journal::{order_id_for_creation, BlindIndexKey};
use limit_engine::{
    apply_transition, conservation_holds, AppendOutcome, CreateOutcome, DurableLimitOrderStore,
    FillDelta, LimitEngineError, LimitOrderStore, OrderKeyProvider, OrderTransition,
    StoredLimitOrder,
};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};
use support::{asset, idempotency_key, EXPIRY_MS};

type Fake = InMemoryOpaqueStore;
type Store = DurableLimitOrderStore<Fake>;

fn keys() -> Arc<TestOrderKeys> {
    Arc::new(TestOrderKeys::deterministic(7))
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
    order: &str,
    to: OrderStatus,
    fill: Option<FillDelta>,
    at_ms: i64,
) -> StoredLimitOrder {
    let current = store
        .load(&order_id_for_test(order))
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

fn order_id_for_test(order: &str) -> OrderId {
    OrderId::new(order).expect("valid order id")
}

async fn drive_to_filled(store: &Store, id: &str) -> StoredLimitOrder {
    step(store, id, OrderStatus::Active, None, 10).await;
    step(store, id, OrderStatus::TriggerCandidate, None, 20).await;
    step(store, id, OrderStatus::Quoting, None, 30).await;
    step(store, id, OrderStatus::Simulating, None, 40).await;
    step(store, id, OrderStatus::Executing, None, 50).await;
    step(
        store,
        id,
        OrderStatus::PartiallyFilled,
        Some(fill(400, 95, 600)),
        60,
    )
    .await;
    step(store, id, OrderStatus::Executing, None, 70).await;
    step(store, id, OrderStatus::Filled, Some(fill(600, 150, 0)), 80).await
}

#[tokio::test]
async fn create_then_load_round_trips() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "round-trip", OrderStatus::Created, 1_000, 1_000, 0);

    assert_eq!(
        store.create(order.clone()).await.expect("create"),
        CreateOutcome::Created(order.clone())
    );
    assert_eq!(
        store.load(&order.order.id).await.expect("load"),
        Some(order.clone())
    );
}

#[tokio::test]
async fn duplicate_create_is_idempotent() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "idem", OrderStatus::Created, 1_000, 1_000, 0);

    store.create(order.clone()).await.expect("first create");
    assert_eq!(
        store.create(order.clone()).await.expect("second create"),
        CreateOutcome::Existing(order.clone())
    );
    assert_eq!(store.list_open().await.expect("list open").len(), 1);
}

#[tokio::test]
async fn same_key_with_different_content_conflicts() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "same-key", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let mut different = order.clone();
    different.order.max_input.amount = AtomicAmount::new(2_000);
    different.order.remaining_input = AtomicAmount::new(2_000);
    assert_eq!(
        store.create(different).await,
        Err(LimitEngineError::IdempotencyConflict)
    );

    // The original payload still maps to the one stored order.
    assert_eq!(
        store.create(order.clone()).await.expect("retry"),
        CreateOutcome::Existing(order)
    );
}

#[tokio::test]
async fn create_rejects_a_non_derived_order_id() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    // `support::stored` uses an arbitrary id, not the creation-key derivation.
    let arbitrary = support::stored("o1", OrderStatus::Created, 1_000, 1_000, 0);
    assert_eq!(
        store.create(arbitrary).await,
        Err(LimitEngineError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn create_rejects_an_inconsistent_ledger() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let bad = durable_order(&keys, "bad", OrderStatus::Executing, 1_000, 900, 0);
    assert_eq!(store.create(bad).await, Err(LimitEngineError::InvalidOrder));
    assert!(store.list_open().await.expect("list open").is_empty());
}

#[tokio::test]
async fn append_is_version_and_sequence_checked() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "cas", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let active = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;
    assert_eq!(active.order.status, OrderStatus::Active);
    assert_eq!(active.version, 2);
    assert_eq!(active.last_transition_seq, 1);
    assert!(conservation_holds(&active));

    // A stale expected version with a fresh sequence is a conflict.
    let next = apply_transition(&active, OrderStatus::TriggerCandidate, None, 20).expect("derive");
    let forward = OrderTransition {
        order_id: active.order.id.clone(),
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
            .append_transition(active.version, &forward, &next)
            .await
            .expect("append"),
        AppendOutcome::Applied(next)
    );
}

#[tokio::test]
async fn gapped_transition_sequence_is_store_invalid() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "gap", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let next = apply_transition(&order, OrderStatus::Active, None, 10).expect("derive");
    let gapped = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 2,
        fill: None,
        at_ms: 10,
    };
    assert_eq!(
        store.append_transition(1, &gapped, &next).await,
        Err(LimitEngineError::StoreInvalid)
    );
    assert_eq!(
        store.load(&order.order.id).await.expect("load"),
        Some(order)
    );
}

#[tokio::test]
async fn duplicate_transition_is_idempotent() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "dup", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let active = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;
    let replay = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    assert_eq!(
        store.append_transition(1, &replay, &active).await,
        Ok(AppendOutcome::AlreadyApplied(active.clone()))
    );
    // The event stream did not grow.
    assert_eq!(fake.events().len(), 1);
}

#[tokio::test]
async fn duplicate_fill_does_not_double_decrement() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "fill-once", OrderStatus::Executing, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let delta = fill(400, 95, 600);
    let partial = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::PartiallyFilled,
        Some(delta.clone()),
        10,
    )
    .await;
    assert_eq!(partial.order.remaining_input, AtomicAmount::new(600));
    assert_eq!(partial.filled_input, AtomicAmount::new(400));

    let replay = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Executing,
        to: OrderStatus::PartiallyFilled,
        transition_seq: 1,
        fill: Some(delta),
        at_ms: 10,
    };
    assert_eq!(
        store.append_transition(1, &replay, &partial).await,
        Ok(AppendOutcome::AlreadyApplied(partial.clone()))
    );
    let loaded = store
        .load(&order.order.id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.order.remaining_input, AtomicAmount::new(600));
    assert_eq!(loaded.filled_input, AtomicAmount::new(400));
}

#[tokio::test]
async fn object_cas_conflict_retries_and_succeeds() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "cas-retry", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    fake.inject_put_conflicts(1);
    let active = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;
    assert_eq!(active.order.status, OrderStatus::Active);
    assert_eq!(active.version, 2);
    assert_eq!(
        store.load(&order.order.id).await.expect("load"),
        Some(active)
    );
}

#[tokio::test]
async fn event_conflict_with_identical_transition_is_repaired() {
    // The event stream is authoritative: an object that lags must catch up on
    // the next append even though the event already exists.
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "lag", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let active = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;
    let object_id = limit_engine::object_id(&keys.blind_key(), &ChainId::Base, &order.order.id)
        .expect("object id");
    fake.truncate_object_versions(&object_id, 1);

    let transition = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    let outcome = store
        .append_transition(1, &transition, &active)
        .await
        .expect("append");
    assert!(
        matches!(outcome, AppendOutcome::Applied(_)),
        "a lagging object must be repaired: {outcome:?}"
    );
    assert_eq!(
        store.load(&order.order.id).await.expect("load"),
        Some(active)
    );
}

#[tokio::test]
async fn replay_from_rebuilds_the_same_state() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "replay", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    let filled = drive_to_filled(&store, order.order.id.as_str()).await;
    assert_eq!(filled.order.status, OrderStatus::Filled);

    for from_seq in [0, 1, 2, 9] {
        assert_eq!(
            store
                .replay_from(&order.order.id, from_seq)
                .await
                .unwrap_or_else(|error| panic!("replay from {from_seq} failed: {error:?}")),
            filled,
            "replay from {from_seq}"
        );
    }
}

#[tokio::test]
async fn replay_from_beyond_the_log_is_inconsistent() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "beyond", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;

    assert_eq!(
        store.replay_from(&order.order.id, 3).await,
        Err(LimitEngineError::RecoveryInconsistent)
    );
}

#[tokio::test]
async fn list_open_excludes_terminal_and_sorts_by_order_id() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let a = durable_order(&keys, "open-a", OrderStatus::Created, 1_000, 1_000, 0);
    let b = durable_order(&keys, "open-b", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(a.clone()).await.expect("create a");
    store.create(b.clone()).await.expect("create b");
    step(
        &store,
        b.order.id.as_str(),
        OrderStatus::Cancelled,
        None,
        10,
    )
    .await;

    let open = store.list_open().await.expect("list open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].order.id, a.order.id);
}

#[tokio::test]
async fn terminal_state_never_resurrects() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "terminal", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    let filled = drive_to_filled(&store, order.order.id.as_str()).await;

    let next = apply_transition(&filled, OrderStatus::Active, None, 200);
    assert_eq!(next, Err(LimitEngineError::InvalidTransition));
}

fn marker_order(keys: &TestOrderKeys) -> StoredLimitOrder {
    let creation_key = idempotency_key("marker-creation");
    let derived = order_id_for_creation(&keys.blind_key(), &creation_key).expect("derive id");
    let token_in = asset("TOKENINMARKER000000000000000000000000000001");
    let token_out = asset("TOKENOUTMARKER00000000000000000000000000002");
    let amount = 9_007_199_254_740_993;
    let order = LimitOrder {
        id: derived,
        owner: UserId::new("OWNERMARKER").expect("owner"),
        wallet_ref: WalletRef::new("WALLETMARKER").expect("wallet"),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        max_input: AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(amount),
        },
        remaining_input: AtomicAmount::new(amount),
        limit_price: LimitPrice {
            numerator_asset: token_in,
            denominator_asset: token_out,
            ratio: PriceRatio::new(100, 25).expect("ratio"),
        },
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        min_fill: AtomicAmount::new(1),
        expires_at_ms: EXPIRY_MS,
        status: OrderStatus::Created,
    };
    StoredLimitOrder {
        schema_version: limit_engine::DEFAULT_SCHEMA_VERSION,
        version: 1,
        order,
        order_intent_id: domain::IntentId::new("intent-marker").expect("intent"),
        order_idempotency_key: creation_key,
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(0),
        last_transition_seq: 0,
        next_eligible_at_ms: None,
    }
}

#[tokio::test]
async fn outer_records_never_expose_plaintext_semantics() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = marker_order(&keys);
    store.create(order.clone()).await.expect("create");
    step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;

    let markers = [
        "TOKENINMARKER",
        "TOKENOUTMARKER",
        "OWNERMARKER",
        "WALLETMARKER",
        "9007199254740993",
    ];
    for object in fake.objects() {
        let json = serde_json::to_string(&object).expect("object json");
        assert!(
            !markers.iter().any(|marker| json.contains(marker)),
            "outer object leaked plaintext: {json}"
        );
        let raw = String::from_utf8_lossy(&object.ciphertext);
        assert!(
            !markers.iter().any(|marker| raw.contains(marker)),
            "ciphertext bytes leaked plaintext"
        );
    }
    for event in fake.events() {
        let json = serde_json::to_string(&event).expect("event json");
        assert!(
            !markers.iter().any(|marker| json.contains(marker)),
            "outer event leaked plaintext: {json}"
        );
    }
}

#[tokio::test]
async fn tampered_ciphertext_fails_closed() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "tamper", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let mut object = fake.objects().into_iter().next().expect("stored object");
    let last = object.ciphertext.len() - 1;
    object.ciphertext[last] ^= 0xFF;
    fake.replace_object(object);

    assert_eq!(
        store.load(&order.order.id).await,
        Err(LimitEngineError::OpenFailed)
    );
}

#[tokio::test]
async fn wrong_key_fails_closed() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "wrong-key", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let wrong = Arc::new(keys.with_seal([0xEE; 32]));
    let wrong_store = durable_store(&fake, &wrong);
    assert_eq!(
        wrong_store.load(&order.order.id).await,
        Err(LimitEngineError::OpenFailed)
    );
}

#[tokio::test]
async fn unknown_kid_fails_closed() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "unknown-kid", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");

    let mut object = fake.objects().into_iter().next().expect("stored object");
    object.ciphertext[AT_REST_KID_LEN] ^= 0xFF;
    fake.replace_object(object);

    assert_eq!(
        store.load(&order.order.id).await,
        Err(LimitEngineError::UnknownKeyId)
    );
}

#[tokio::test]
async fn deterministic_nonces_are_never_reused_across_scopes() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    for name in ["nonce-a", "nonce-b"] {
        let order = durable_order(&keys, name, OrderStatus::Created, 1_000, 1_000, 0);
        store.create(order.clone()).await.expect("create");
        step(
            &store,
            order.order.id.as_str(),
            OrderStatus::Active,
            None,
            10,
        )
        .await;
    }

    let mut seen: HashSet<[u8; AT_REST_NONCE_LEN]> = HashSet::new();
    let mut records = 0usize;
    for wire in fake
        .objects()
        .iter()
        .map(|object| &object.ciphertext)
        .chain(fake.events().iter().map(|event| &event.ciphertext))
    {
        let mut nonce = [0u8; AT_REST_NONCE_LEN];
        nonce.copy_from_slice(&wire[AT_REST_HEADER_LEN - AT_REST_NONCE_LEN..AT_REST_HEADER_LEN]);
        assert!(seen.insert(nonce), "nonce reused across (scope, sequence)");
        records += 1;
    }
    assert!(records >= 4, "expected object and event records");
}

#[test]
fn key_material_debug_is_redacted() {
    let blind = BlindIndexKey::from_bytes([0xAB; 32]);
    let debug = format!("{blind:?}");
    assert_eq!(debug, "BlindIndexKey([REDACTED])");
    assert!(!debug.contains("171"));

    let keys = TestOrderKeys::deterministic(3);
    let material = keys.material();
    let debug = format!("{material:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("171"));
}

#[test]
fn unavailable_provider_fails_closed() {
    let provider = limit_engine::UnavailableOrderKeyProvider;
    assert_eq!(
        provider.current().err(),
        Some(LimitEngineError::KeyUnavailable)
    );
    assert_eq!(
        provider.by_id(&[0u8; 16]).err(),
        Some(LimitEngineError::KeyUnavailable)
    );
}

/// Asserts that no two seal attempts target the same `(scope, sequence)` with
/// different ciphertext. The deterministic nonce makes that pair a nonce, so
/// any disagreement is a nonce-reuse defect even if the CAS later discards one.
fn assert_no_conflicting_seals(fake: &Fake) {
    let mut events: HashMap<(Vec<u8>, u64), Vec<u8>> = HashMap::new();
    for attempt in fake.event_attempts() {
        let key = (attempt.stream_blind_index.clone(), attempt.sequence);
        if let Some(existing) = events.get(&key) {
            assert_eq!(
                existing, &attempt.ciphertext,
                "two event seal attempts share one (scope, sequence) with different plaintext"
            );
        } else {
            events.insert(key, attempt.ciphertext);
        }
    }
    let mut objects: HashMap<(String, u64), Vec<u8>> = HashMap::new();
    for attempt in fake.put_attempts() {
        let key = (attempt.id.clone(), attempt.version);
        if let Some(existing) = objects.get(&key) {
            assert_eq!(
                existing, &attempt.ciphertext,
                "two object seal attempts share one (scope, sequence) with different plaintext"
            );
        } else {
            objects.insert(key, attempt.ciphertext);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_writers_never_seal_conflicting_plaintext_at_one_sequence() {
    let fake = fake();
    let keys = keys();
    let store = Arc::new(durable_store(&fake, &keys));
    let order = durable_order(&keys, "race-seal", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    // Force an interleaving point between every internal read and its write.
    fake.enable_read_yield();

    let active = apply_transition(&order, OrderStatus::Active, None, 10).expect("active");
    let cancelled = apply_transition(&order, OrderStatus::Cancelled, None, 10).expect("cancelled");
    let transition_active = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    let transition_cancelled = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Cancelled,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (transition, next) in [
        (transition_active, active.clone()),
        (transition_cancelled, cancelled.clone()),
    ] {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            store.append_transition(1, &transition, &next).await
        }));
    }
    let mut outcomes = Vec::new();
    for handle in handles {
        outcomes.push(handle.await.expect("join"));
    }

    let applied = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(AppendOutcome::Applied(_))))
        .count();
    assert_eq!(
        applied, 1,
        "exactly one racing writer may apply: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Err(LimitEngineError::PersistenceConflict))),
        "the loser must fail fast with the existing conflict path: {outcomes:?}"
    );

    assert_no_conflicting_seals(&fake);

    let object_id =
        limit_engine::object_id(&keys.blind_key(), &ChainId::Base, &order.order.id).expect("id");
    assert_eq!(
        fake.latest_object(&object_id).map(|object| object.version),
        Some(2)
    );
    assert_eq!(fake.events().len(), 1, "exactly one event persists");

    let expected = outcomes
        .into_iter()
        .find_map(|outcome| match outcome {
            Ok(AppendOutcome::Applied(state)) => Some(state),
            _ => None,
        })
        .expect("one applied state");
    assert_eq!(
        store.load(&order.order.id).await.expect("load"),
        Some(expected)
    );
}

#[tokio::test]
async fn already_applied_returns_the_authoritative_stream_head() {
    let fake = fake();
    let keys = keys();
    let store = durable_store(&fake, &keys);
    let order = durable_order(&keys, "auth-head", OrderStatus::Created, 1_000, 1_000, 0);
    store.create(order.clone()).await.expect("create");
    let active = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::Active,
        None,
        10,
    )
    .await;
    let candidate = step(
        &store,
        order.order.id.as_str(),
        OrderStatus::TriggerCandidate,
        None,
        20,
    )
    .await;
    assert_eq!(candidate.order.status, OrderStatus::TriggerCandidate);

    // Materialize the object only up to the first transition, so it lags the
    // authoritative event stream by one step.
    let object_id =
        limit_engine::object_id(&keys.blind_key(), &ChainId::Base, &order.order.id).expect("id");
    fake.truncate_object_versions(&object_id, active.version);

    let replay = OrderTransition {
        order_id: order.order.id.clone(),
        from: OrderStatus::Created,
        to: OrderStatus::Active,
        transition_seq: 1,
        fill: None,
        at_ms: 10,
    };
    assert_eq!(
        store
            .append_transition(active.version, &replay, &active)
            .await
            .expect("replay"),
        AppendOutcome::AlreadyApplied(candidate),
        "an in-range replay must return the replayed head, not the lagging object"
    );
}
