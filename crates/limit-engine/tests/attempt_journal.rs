//! P48 — durable limit attempt journal and in-flight recovery.
//!
//! Every test drives the real `DurableLimitOrderStore` over the in-memory
//! `OpaqueStore` fake; no live database, signer, or chain is involved.

mod support;

use std::sync::Arc;

use chain_types::ChainId;
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IntentId, LimitPrice, OrderId,
    OrderStatus, OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, UserId,
    WalletRef,
};
use limit_engine::{
    attempt_intent_id, attempt_key, attempt_stream_blind_index, object_id, order_id_for_creation,
    stream_blind_index, ApprovalSnapshot, AttemptAppendOutcome, AttemptPhase, BoundAttempt,
    DurableLimitOrderStore, LimitEngineError, LimitOrderStore, OrderAttemptEvent, OrderKeyMaterial,
    OrderKeyProvider, StoredLimitOrder,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessStatus, PriceRatio, Sequence,
};

use crypto_envelope::at_rest::SealKey;
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};
use support::{asset, idempotency_key, EXPIRY_MS};

fn keys() -> Arc<TestOrderKeys> {
    Arc::new(TestOrderKeys::deterministic(7))
}

fn stream_for(keys: &TestOrderKeys, order: &OrderId) -> [u8; 32] {
    attempt_stream_blind_index(&keys.blind_key(), &ChainId::Base, order).expect("stream index")
}

fn attempt_intent(keys: &TestOrderKeys, order: &OrderId, attempt_seq: u64) -> TradeIntent {
    let token_in = asset("USDC");
    let token_out = asset("SECRETTOKEN");
    TradeIntent {
        id: attempt_intent_id(&keys.blind_key(), &ChainId::Base, order, attempt_seq)
            .expect("intent id"),
        source: domain::TradeSource::Web,
        user_id: UserId::new("user-secret").expect("user"),
        wallet_ref: WalletRef::new("wallet-secret").expect("wallet"),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000 + u128::from(attempt_seq)),
        order_type: OrderType::Limit,
        limit_price: Some(LimitPrice {
            numerator_asset: token_in.clone(),
            denominator_asset: token_out.clone(),
            ratio: PriceRatio::new(100, 25).expect("ratio"),
        }),
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: Some(EXPIRY_MS),
        nonce: attempt_seq,
        idempotency_key: attempt_key(&keys.blind_key(), &ChainId::Base, order, attempt_seq)
            .expect("attempt key"),
    }
}

fn attempt_route(attempt_seq: u64) -> RoutePlan {
    let token_in = asset("USDC");
    let token_out = asset("SECRETTOKEN");
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "pool-secret".to_string(),
            token_in,
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(1_000 + u128::from(attempt_seq)),
            expected_amount_out: AtomicAmount::new(250),
        }],
        expected_net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(240),
        },
        state: Freshness {
            observed_at_ms: EXPIRY_MS - 1_000,
            chain_height: 10,
            sequence: Sequence(1),
        },
    }
}

fn attempt_preview(intent: &TradeIntent, attempt_seq: u64) -> ExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: ChainId::Base,
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: TradeSide::Buy,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(1_000 + u128::from(attempt_seq)),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(240),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(250),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: FreshnessStatus::Fresh,
    }
}

fn bound_attempt(keys: &TestOrderKeys, order: &OrderId, attempt_seq: u64) -> BoundAttempt {
    let intent = attempt_intent(keys, order, attempt_seq);
    BoundAttempt {
        route: attempt_route(attempt_seq),
        preview: attempt_preview(&intent, attempt_seq),
        approval: ApprovalSnapshot {
            intent_id: intent.id.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: ChainId::Base,
            idempotency_key: intent.idempotency_key.clone(),
            expires_at_ms: Some(EXPIRY_MS),
            approved_trade_usd: 500_000,
            approved_at_ms: 1,
        },
        prepared_reference: format!("prepared-{attempt_seq}"),
        payload_digest: [u8::try_from(attempt_seq).unwrap_or(1); 32],
        attempt_key: intent.idempotency_key.clone(),
        attempt_seq,
        nonce: attempt_seq,
        intent,
    }
}

fn bound_event(keys: &TestOrderKeys, order: &OrderId, at_ms: i64) -> OrderAttemptEvent {
    OrderAttemptEvent::bound(bound_attempt(keys, order, 1), order.clone(), at_ms)
}

fn phase_event(
    keys: &TestOrderKeys,
    order: &OrderId,
    attempt_seq: u64,
    phase: AttemptPhase,
    at_ms: i64,
) -> OrderAttemptEvent {
    OrderAttemptEvent::phase(
        order.clone(),
        attempt_seq,
        attempt_key(&keys.blind_key(), &ChainId::Base, order, attempt_seq).expect("attempt key"),
        phase,
        None,
        at_ms,
    )
}

async fn create_order(
    store: &DurableLimitOrderStore<InMemoryOpaqueStore>,
    keys: &TestOrderKeys,
    creation: &str,
) -> StoredLimitOrder {
    let order = durable_order(keys, creation, OrderStatus::Executing, 10_000, 10_000, 0);
    store.create(order.clone()).await.expect("create order");
    order
}

#[tokio::test]
async fn appends_and_reads_a_full_attempt_lifecycle() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "a").await;

    let bound = bound_event(&keys, &order.order.id, 0);
    let signed = phase_event(&keys, &order.order.id, 1, AttemptPhase::Signed, 1);
    let confirmed = phase_event(&keys, &order.order.id, 1, AttemptPhase::Confirmed, 2);

    assert!(matches!(
        store.append_attempt(&bound).await.expect("bound"),
        AttemptAppendOutcome::Applied(_)
    ));
    assert!(matches!(
        store.append_attempt(&signed).await.expect("signed"),
        AttemptAppendOutcome::Applied(_)
    ));
    assert!(matches!(
        store.append_attempt(&confirmed).await.expect("confirmed"),
        AttemptAppendOutcome::Applied(_)
    ));

    let events = store.read_attempts(&order.order.id).await.expect("read");
    assert_eq!(events.len(), 3);
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(events[0].phase, AttemptPhase::Bound);
    assert!(events[0].bound.is_some());
    assert_eq!(events[1].phase, AttemptPhase::Signed);
    assert!(events[1].bound.is_none());
    assert_eq!(events[2].phase, AttemptPhase::Confirmed);

    let latest = store
        .latest_attempt(&order.order.id)
        .await
        .expect("latest")
        .expect("present");
    assert_eq!(latest.phase, AttemptPhase::Confirmed);
    assert!(!latest.phase.is_in_flight());
    assert!(latest.phase.is_terminal());
}

#[tokio::test]
async fn reappending_an_identical_phase_is_idempotent() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "b").await;
    let bound = bound_event(&keys, &order.order.id, 0);

    let first = store.append_attempt(&bound).await.expect("first");
    assert!(matches!(first, AttemptAppendOutcome::Applied(_)));
    let second = store.append_attempt(&bound).await.expect("second");
    assert!(matches!(second, AttemptAppendOutcome::AlreadyApplied(_)));

    let events = store.read_attempts(&order.order.id).await.expect("read");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 1);
}

#[tokio::test]
async fn conflicting_payload_for_the_same_phase_is_rejected() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "c").await;
    let bound = bound_event(&keys, &order.order.id, 0);
    store.append_attempt(&bound).await.expect("first");

    let mut conflicting = bound_attempt(&keys, &order.order.id, 1);
    conflicting.prepared_reference = "prepared-other".to_string();
    let conflicting = OrderAttemptEvent::bound(conflicting, order.order.id.clone(), 0);

    assert_eq!(
        store.append_attempt(&conflicting).await,
        Err(LimitEngineError::PersistenceConflict)
    );
    assert_eq!(
        store
            .read_attempts(&order.order.id)
            .await
            .expect("read")
            .len(),
        1
    );
}

#[tokio::test]
async fn a_new_attempt_cannot_start_before_the_previous_is_terminal() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "d").await;

    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound 1");

    // A second attempt while attempt 1 is non-terminal must fail closed.
    let second = OrderAttemptEvent::bound(
        bound_attempt(&keys, &order.order.id, 2),
        order.order.id.clone(),
        1,
    );
    assert_eq!(
        store.append_attempt(&second).await,
        Err(LimitEngineError::StoreInvalid)
    );

    // Continuing attempt 1 is allowed.
    store
        .append_attempt(&phase_event(
            &keys,
            &order.order.id,
            1,
            AttemptPhase::Signed,
            1,
        ))
        .await
        .expect("signed");
    // Still non-terminal: no new attempt.
    assert_eq!(
        store.append_attempt(&second).await,
        Err(LimitEngineError::StoreInvalid)
    );
    store
        .append_attempt(&phase_event(
            &keys,
            &order.order.id,
            1,
            AttemptPhase::Confirmed,
            2,
        ))
        .await
        .expect("confirmed");
    // Attempt 1 is terminal: attempt 2 may now bind.
    assert!(matches!(
        store.append_attempt(&second).await.expect("bound 2"),
        AttemptAppendOutcome::Applied(_)
    ));
    let events = store.read_attempts(&order.order.id).await.expect("read");
    assert_eq!(events.len(), 4);
    assert_eq!(events[3].attempt_seq, 2);
    assert_eq!(events[3].phase, AttemptPhase::Bound);
}

#[tokio::test]
async fn unknown_attempt_phase_never_permits_a_fresh_attempt() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "e").await;

    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");
    store
        .append_attempt(&phase_event(
            &keys,
            &order.order.id,
            1,
            AttemptPhase::Unknown,
            1,
        ))
        .await
        .expect("unknown");

    let fresh = OrderAttemptEvent::bound(
        bound_attempt(&keys, &order.order.id, 2),
        order.order.id.clone(),
        2,
    );
    assert_eq!(
        store.append_attempt(&fresh).await,
        Err(LimitEngineError::StoreInvalid)
    );
}

#[tokio::test]
async fn first_event_must_be_a_bound_first_attempt() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "f").await;

    let signed = phase_event(&keys, &order.order.id, 1, AttemptPhase::Signed, 0);
    assert_eq!(
        store.append_attempt(&signed).await,
        Err(LimitEngineError::StoreInvalid)
    );
    let bound_two = OrderAttemptEvent::bound(
        bound_attempt(&keys, &order.order.id, 2),
        order.order.id.clone(),
        0,
    );
    assert_eq!(
        store.append_attempt(&bound_two).await,
        Err(LimitEngineError::StoreInvalid)
    );
}

#[tokio::test]
async fn attempt_streams_are_per_order() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let first = create_order(&store, &keys, "g").await;
    let second = create_order(&store, &keys, "h").await;

    store
        .append_attempt(&bound_event(&keys, &first.order.id, 0))
        .await
        .expect("first bound");
    store
        .append_attempt(&bound_event(&keys, &second.order.id, 0))
        .await
        .expect("second bound");

    let first_events = store.read_attempts(&first.order.id).await.expect("read");
    let second_events = store.read_attempts(&second.order.id).await.expect("read");
    assert_eq!(first_events.len(), 1);
    assert_eq!(second_events.len(), 1);
    assert_eq!(first_events[0].order_id, first.order.id);
    assert_eq!(second_events[0].order_id, second.order.id);
}

#[tokio::test]
async fn unknown_order_has_no_attempts_and_cannot_append() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let orphan = OrderId::new("orphan").expect("order id");

    assert!(store
        .read_attempts(&orphan)
        .await
        .expect("read empty")
        .is_empty());
    assert_eq!(
        store.append_attempt(&bound_event(&keys, &orphan, 0)).await,
        Err(LimitEngineError::StoreInvalid)
    );
}

#[tokio::test]
async fn tampered_attempt_ciphertext_fails_closed() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "i").await;
    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");

    let stream = stream_for(&keys, &order.order.id);
    assert!(backend.tamper_event(&stream, 1));
    assert_eq!(
        store.read_attempts(&order.order.id).await,
        Err(LimitEngineError::OpenFailed)
    );
}

#[tokio::test]
async fn a_missing_attempt_sequence_is_inconsistent() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "j").await;
    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");
    store
        .append_attempt(&phase_event(
            &keys,
            &order.order.id,
            1,
            AttemptPhase::Signed,
            1,
        ))
        .await
        .expect("signed");

    let stream = stream_for(&keys, &order.order.id);
    backend.drop_event(&stream, 1);
    // The remaining record is sequence 2 with no sequence 1: contiguity fails.
    assert!(matches!(
        store.read_attempts(&order.order.id).await,
        Err(LimitEngineError::RecoveryInconsistent)
    ));
}

#[tokio::test]
async fn recovery_classifies_in_flight_attempts_and_skips_terminal_ones() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let pending = create_order(&store, &keys, "k").await;
    let done = create_order(&store, &keys, "l").await;

    store
        .append_attempt(&bound_event(&keys, &pending.order.id, 0))
        .await
        .expect("pending bound");
    store
        .append_attempt(&bound_event(&keys, &done.order.id, 0))
        .await
        .expect("done bound");
    store
        .append_attempt(&phase_event(
            &keys,
            &done.order.id,
            1,
            AttemptPhase::Confirmed,
            1,
        ))
        .await
        .expect("done confirmed");

    let outcome = limit_engine::recover_in_flight(backend.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.open.len(), 2);
    assert_eq!(outcome.in_flight.len(), 1);
    assert!(outcome.quarantined.is_empty());
    assert!(!outcome.truncated);
    let attempt = &outcome.in_flight[0];
    assert_eq!(attempt.attempt.phase, AttemptPhase::Bound);
    assert!(!attempt.attempt.phase.may_have_reached_chain());
    assert_eq!(attempt.order.order.id, pending.order.id);
    assert_eq!(
        attempt.object_id,
        object_id(&keys.blind_key(), &ChainId::Base, &pending.order.id).expect("object id")
    );
}

#[tokio::test]
async fn recovery_quarantines_a_corrupt_attempt_stream_without_aborting() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let corrupt = create_order(&store, &keys, "m").await;
    let healthy = create_order(&store, &keys, "n").await;

    store
        .append_attempt(&bound_event(&keys, &corrupt.order.id, 0))
        .await
        .expect("corrupt bound");
    store
        .append_attempt(&bound_event(&keys, &healthy.order.id, 0))
        .await
        .expect("healthy bound");

    let stream = stream_for(&keys, &corrupt.order.id);
    assert!(backend.tamper_event(&stream, 1));

    let outcome = limit_engine::recover_in_flight(backend.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    assert_eq!(outcome.quarantined.len(), 1);
    assert_eq!(outcome.in_flight.len(), 1);
    assert_eq!(outcome.in_flight[0].order.order.id, healthy.order.id);
}

#[test]
fn derivations_are_deterministic_and_domain_separated() {
    let keys = keys();
    let order = OrderId::new("order-1").expect("order");

    let key_a = attempt_key(&keys.blind_key(), &ChainId::Base, &order, 1).expect("key");
    let key_b = attempt_key(&keys.blind_key(), &ChainId::Base, &order, 1).expect("key");
    let key_c = attempt_key(&keys.blind_key(), &ChainId::Base, &order, 2).expect("key");
    assert_eq!(key_a, key_b);
    assert_ne!(key_a, key_c);

    let stream = attempt_stream_blind_index(&keys.blind_key(), &ChainId::Base, &order).expect("s");
    let transition = stream_blind_index(&keys.blind_key(), &ChainId::Base, &order).expect("t");
    assert_ne!(stream, transition);
    let object = object_id(&keys.blind_key(), &ChainId::Base, &order).expect("o");
    assert_ne!(hex_of(&stream), object);

    // The chain is part of the identity: a different chain derives a different
    // stream, key, and intent id for the same order id.
    let other_chain = attempt_stream_blind_index(&keys.blind_key(), &ChainId::Ethereum, &order)
        .expect("chain stream");
    assert_ne!(stream, other_chain);
    assert_ne!(
        attempt_key(&keys.blind_key(), &ChainId::Base, &order, 1).expect("base"),
        attempt_key(&keys.blind_key(), &ChainId::Ethereum, &order, 1).expect("eth")
    );
    assert_ne!(
        attempt_intent_id(&keys.blind_key(), &ChainId::Base, &order, 1).expect("base"),
        attempt_intent_id(&keys.blind_key(), &ChainId::Ethereum, &order, 1).expect("eth")
    );

    let intent = attempt_intent_id(&keys.blind_key(), &ChainId::Base, &order, 1).expect("intent");
    assert_eq!(
        intent,
        attempt_intent_id(&keys.blind_key(), &ChainId::Base, &order, 1).expect("intent")
    );
    assert_ne!(
        intent,
        attempt_intent_id(&keys.blind_key(), &ChainId::Base, &order, 2).expect("intent")
    );

    let creation = idempotency_key("creation");
    let derived_order = order_id_for_creation(&keys.blind_key(), &creation).expect("order id");
    assert_ne!(derived_order, order);
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn phase_bindings_are_enforced() {
    let keys = keys();
    let order = OrderId::new("order-2").expect("order");

    let mut bound = bound_event(&keys, &order, 0);
    // A non-Bound phase must not carry a bound context.
    bound.phase = AttemptPhase::Signed;
    assert_eq!(bound.validate(), Err(LimitEngineError::RecordMalformed));

    // A Bound phase must carry one.
    let mut missing = phase_event(&keys, &order, 1, AttemptPhase::Bound, 0);
    missing.attempt_seq = 1;
    missing.sequence = 1;
    assert_eq!(missing.validate(), Err(LimitEngineError::RecordMalformed));

    // A zero payload digest is not a bindable context.
    let mut zero = bound_event(&keys, &order, 0);
    if let Some(context) = zero.bound.as_mut() {
        context.payload_digest = [0u8; 32];
    }
    assert_eq!(zero.validate(), Err(LimitEngineError::RecordMalformed));
}

#[tokio::test]
async fn stored_attempt_records_carry_no_plaintext_semantics() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "o").await;
    let event = bound_event(&keys, &order.order.id, 0);
    store.append_attempt(&event).await.expect("append");

    let rendered = format!("{event:?}");
    assert!(!rendered.contains("SECRETTOKEN"));
    assert!(!rendered.contains("user-secret"));
    assert!(!rendered.contains("wallet-secret"));
    assert!(!rendered.contains("pool-secret"));
    assert!(!rendered.contains(&order.order.id.as_str().to_string()));

    let forbidden = [
        "SECRETTOKEN",
        "USDC",
        "user-secret",
        "wallet-secret",
        "pool-secret",
        "prepared-1",
    ];
    for record in backend.events() {
        let json = serde_json::to_string(&record).expect("serialize record");
        assert!(
            !has_hex_run(&json, 8),
            "outer record carries a long hex run: {json}"
        );
        for needle in forbidden {
            assert!(
                !json.contains(needle),
                "outer record leaked `{needle}`: {json}"
            );
        }
        let haystack = format!("{:?} {:?}", record.ciphertext, record.stream_blind_index);
        for needle in forbidden {
            assert!(!haystack.contains(needle), "stored bytes leaked `{needle}`");
        }
    }
}

/// Detects a run of at least `min_len` ASCII hex digits.
fn has_hex_run(value: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[tokio::test]
async fn later_phase_with_a_foreign_attempt_key_is_rejected() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "q").await;
    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");

    let mut foreign = phase_event(&keys, &order.order.id, 1, AttemptPhase::Signed, 1);
    foreign.attempt_key =
        attempt_key(&keys.blind_key(), &ChainId::Base, &order.order.id, 99).expect("foreign key");
    assert_eq!(
        store.append_attempt(&foreign).await,
        Err(LimitEngineError::RecordMalformed)
    );
    assert_eq!(
        store
            .read_attempts(&order.order.id)
            .await
            .expect("read")
            .len(),
        1
    );
}

#[tokio::test]
async fn bound_with_a_foreign_intent_identity_is_rejected() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "r").await;

    let mut foreign_intent = bound_attempt(&keys, &order.order.id, 1);
    foreign_intent.intent.id = IntentId::new("foreign-intent").expect("intent");
    let event = OrderAttemptEvent::bound(foreign_intent, order.order.id.clone(), 0);
    assert_eq!(
        store.append_attempt(&event).await,
        Err(LimitEngineError::RecordMalformed)
    );

    let mut foreign_key = bound_attempt(&keys, &order.order.id, 1);
    foreign_key.intent.idempotency_key = idempotency_key("foreign-key");
    let event = OrderAttemptEvent::bound(foreign_key, order.order.id.clone(), 0);
    assert_eq!(
        store.append_attempt(&event).await,
        Err(LimitEngineError::RecordMalformed)
    );
    assert!(store
        .read_attempts(&order.order.id)
        .await
        .expect("read")
        .is_empty());
}

#[tokio::test]
async fn bound_on_a_terminal_order_is_rejected() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let terminal = durable_order(&keys, "terminal", OrderStatus::Filled, 10_000, 0, 10_000);
    store.create(terminal.clone()).await.expect("create");

    assert_eq!(
        store
            .append_attempt(&bound_event(&keys, &terminal.order.id, 0))
            .await,
        Err(LimitEngineError::InvalidTransition)
    );
}

#[tokio::test]
async fn cross_order_ciphertext_swap_fails_closed() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let first = create_order(&store, &keys, "s").await;
    let second = create_order(&store, &keys, "t").await;
    store
        .append_attempt(&bound_event(&keys, &first.order.id, 0))
        .await
        .expect("first bound");
    store
        .append_attempt(&bound_event(&keys, &second.order.id, 0))
        .await
        .expect("second bound");

    assert!(backend.swap_event_ciphertexts(
        &stream_for(&keys, &first.order.id),
        1,
        &stream_for(&keys, &second.order.id),
        1,
    ));
    assert_eq!(
        store.read_attempts(&first.order.id).await,
        Err(LimitEngineError::OpenFailed)
    );
    assert_eq!(
        store.read_attempts(&second.order.id).await,
        Err(LimitEngineError::OpenFailed)
    );
}

/// A key provider that serves the same blind-index key under a different id, so
/// stored records are addressed correctly but their key id is unknown.
struct ShadowKidProvider {
    keys: TestOrderKeys,
    kid: [u8; 16],
}

impl OrderKeyProvider for ShadowKidProvider {
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError> {
        Ok(OrderKeyMaterial {
            kid: self.kid,
            seal: SealKey::from_bytes(self.keys.seal_bytes()),
            blind_index: self.keys.blind_key(),
        })
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError> {
        if *kid == self.keys.kid_bytes() {
            return Err(LimitEngineError::UnknownKeyId);
        }
        self.current()
    }
}

#[tokio::test]
async fn unknown_stored_key_id_fails_closed() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "u").await;
    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");

    let shadow = Arc::new(ShadowKidProvider {
        keys: TestOrderKeys::deterministic(7),
        kid: [0x55u8; 16],
    });
    let shadow_store = DurableLimitOrderStore::new(backend.clone(), shadow, ChainId::Base);
    assert_eq!(
        shadow_store.read_attempts(&order.order.id).await,
        Err(LimitEngineError::UnknownKeyId)
    );
}

#[tokio::test]
async fn recovery_debug_output_is_redacted() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let store = durable_store(&backend, &keys);
    let order = create_order(&store, &keys, "v").await;
    store
        .append_attempt(&bound_event(&keys, &order.order.id, 0))
        .await
        .expect("bound");

    let outcome = limit_engine::recover_in_flight(backend.as_ref(), keys.as_ref())
        .await
        .expect("recover");
    let rendered = format!("{outcome:?}");
    for needle in [
        "user",
        "wallet",
        "TOKEN",
        "USDC",
        "10000",
        "order.v",
        "idempotency",
    ] {
        assert!(
            !rendered.contains(needle),
            "recovery Debug leaked `{needle}`: {rendered}"
        );
    }
    assert_eq!(
        format!("{:?}", outcome.in_flight[0]),
        "InFlightAttempt { phase: Bound, .. }"
    );
}

#[tokio::test]
async fn attempt_stream_survives_a_read_after_restart_like_reopen() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = keys();
    let order = create_order(&durable_store(&backend, &keys), &keys, "p").await;
    {
        let store = durable_store(&backend, &keys);
        store
            .append_attempt(&bound_event(&keys, &order.order.id, 0))
            .await
            .expect("bound");
    }
    // A brand-new store over the same backend reconstructs the attempt log.
    let reopened = durable_store(&backend, &keys);
    let events = reopened.read_attempts(&order.order.id).await.expect("read");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].phase, AttemptPhase::Bound);
    assert!(events[0].bound.is_some());
}
