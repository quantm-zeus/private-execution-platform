//! P54 — durable order-event outbox publication.
//!
//! Every test drives the real `DurableLimitOrderStore` over the in-memory
//! `OpaqueStore` fake and a recording, failure-injectable in-memory `EventBus`.
//! The orchestrator tests reuse a deterministic quote provider and a scripted
//! execution seam, so no live signer, chain, bus, or database is involved.
//!
//! Invariants under test:
//! - OE-1: an event is published only after its transition is durable;
//! - OE-2: publication failure never fails or rolls back the state machine;
//! - OE-3: each `(order, transition_seq)` maps to one deterministic `event_id`;
//! - OE-4: the envelope payload is the sealed ciphertext (no plaintext leaks);
//! - OE-5: the watermark never advances past an unpublished sequence.

mod support;

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderId, OrderStatus, OrderType, RouteLeg, RoutePlan,
    TaxObservation, TradeIntent, TradeSource, WalletRef,
};
use execution_preview::{AllowanceObservation, NetDelta, WalletBalance};
use limit_engine::journal::MAX_OBJECT_CAS_ATTEMPTS;
use limit_engine::{
    apply_transition, event_subject, object_id, order_event_id, stream_blind_index, AppendOutcome,
    AttemptExecutor, AttemptLimits, AttemptResolution, AttemptTrust, BoundAttempt,
    DurableLimitOrderStore, LimitEngineError, LimitOrderStore, Orchestrator, OrderTransition,
    PreparedAttempt, QuoteOutcome, QuoteProvider, RealizedFill, StoredLimitOrder, TickInput,
    TickOutcome,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use storage::{
    ComponentHealth, EventBus, HealthProbe, InternalEventEnvelope, OpaqueEventRecord, StorageError,
};
use tax_engine::TaxAssessment;

use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

const NOW: i64 = 100_000;
const NET_OUTPUT: u128 = 240;
/// A deadline well past every transition instant used here.
const LATE_EXPIRY_MS: i64 = 1_000_000_000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// In-memory EventBus fake.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BusInner {
    published: Vec<InternalEventEnvelope>,
    attempts: u64,
    /// 0-based publish ordinals that fail once.
    fail_at: HashSet<u64>,
}

/// Recording in-memory bus with injectable failures. `publish` fails before
/// recording, so a failed attempt leaves no envelope behind.
#[derive(Default)]
struct RecordingBus {
    inner: Mutex<BusInner>,
}

impl RecordingBus {
    fn new() -> Self {
        Self::default()
    }

    /// Makes the 0-based publish ordinal `attempt` fail.
    fn fail_attempt(&self, attempt: u64) {
        lock(&self.inner).fail_at.insert(attempt);
    }

    /// Every accepted envelope, in publish order.
    fn envelopes(&self) -> Vec<InternalEventEnvelope> {
        lock(&self.inner).published.clone()
    }

    /// Total publish attempts, including failed ones.
    fn attempts(&self) -> u64 {
        lock(&self.inner).attempts
    }
}

#[async_trait]
impl EventBus for RecordingBus {
    async fn publish(&self, event: InternalEventEnvelope) -> Result<(), StorageError> {
        let mut inner = lock(&self.inner);
        let attempt = inner.attempts;
        inner.attempts += 1;
        if inner.fail_at.contains(&attempt) {
            return Err(StorageError::Backend);
        }
        inner.published.push(event);
        Ok(())
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "test.event_bus",
            status: ComponentHealth::Healthy,
            observed_at_ms: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Store-level fixtures.
// ---------------------------------------------------------------------------

type Store = DurableLimitOrderStore<InMemoryOpaqueStore>;

fn transition_stream(keys: &TestOrderKeys, order_id: &OrderId) -> Vec<u8> {
    stream_blind_index(&keys.blind_key(), &ChainId::Base, order_id)
        .expect("stream index")
        .to_vec()
}

fn transition_records(backend: &Arc<InMemoryOpaqueStore>, stream: &[u8]) -> Vec<OpaqueEventRecord> {
    let mut records: Vec<OpaqueEventRecord> = backend
        .events()
        .into_iter()
        .filter(|record| record.stream_blind_index == stream)
        .collect();
    records.sort_by_key(|record| record.sequence);
    records
}

/// Creates a `Created` order that can walk the full pre-execution chain.
async fn seeded_store(
    creation: &str,
) -> (Arc<InMemoryOpaqueStore>, Arc<TestOrderKeys>, OrderId, Store) {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(11));
    let mut order = durable_order(&keys, creation, OrderStatus::Created, 1000, 1000, 0);
    order.order.expires_at_ms = LATE_EXPIRY_MS;
    let order_id = order.order.id.clone();
    let store = durable_store(&backend, &keys);
    store.create(order).await.expect("create");
    (backend, keys, order_id, store)
}

/// Applies one fill-less transition through the real durable store.
async fn drive(store: &Store, order_id: &OrderId, to: OrderStatus, at_ms: i64) -> StoredLimitOrder {
    let current = store.load(order_id).await.expect("load").expect("present");
    let next = apply_transition(&current, to, None, at_ms).expect("apply transition");
    let transition = OrderTransition {
        order_id: current.order.id.clone(),
        from: current.order.status,
        to,
        transition_seq: current.last_transition_seq + 1,
        fill: None,
        at_ms,
    };
    match store
        .append_transition(current.version, &transition, &next)
        .await
        .expect("append")
    {
        AppendOutcome::Applied(applied) => applied,
        AppendOutcome::AlreadyApplied(authoritative) => authoritative,
    }
}

/// Walks `Created -> Active -> TriggerCandidate -> Quoting -> Simulating ->
/// Executing`, one coarse bucket apart, and returns the five `at_ms` instants.
async fn drive_five(store: &Store, order_id: &OrderId) -> Vec<i64> {
    let instants = [
        90_000_000,
        180_000_000,
        270_000_000,
        350_000_000,
        440_000_000,
    ];
    let targets = [
        OrderStatus::Active,
        OrderStatus::TriggerCandidate,
        OrderStatus::Quoting,
        OrderStatus::Simulating,
        OrderStatus::Executing,
    ];
    for (target, at_ms) in targets.into_iter().zip(instants) {
        drive(store, order_id, target, at_ms).await;
    }
    instants.to_vec()
}

fn distinct_event_ids(envelopes: &[InternalEventEnvelope]) -> HashSet<String> {
    envelopes
        .iter()
        .map(|event| event.event_id.clone())
        .collect()
}

/// Whether two records carry the same order state, ignoring the store CAS
/// version and the outbox watermark (the two fields publication may advance).
fn same_order_state(left: &StoredLimitOrder, right: &StoredLimitOrder) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.version = 0;
    right.version = 0;
    left.published_seq = 0;
    right.published_seq = 0;
    left == right
}

// ---------------------------------------------------------------------------
// Deliverable A — watermark field.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_stamps_zero_and_apply_transition_preserves_watermark() {
    let (_, _, order_id, store) = seeded_store("p54-watermark").await;
    assert_eq!(
        store.load(&order_id).await.unwrap().unwrap().published_seq,
        0
    );

    let advanced = drive(&store, &order_id, OrderStatus::Active, NOW).await;
    assert_eq!(advanced.published_seq, 0);
    assert_eq!(load(&store, &order_id).await.published_seq, 0);
}

#[tokio::test]
async fn legacy_record_without_published_seq_decodes_as_zero() {
    let (_, _, order_id, store) = seeded_store("p54-legacy").await;
    let order = load(&store, &order_id).await;
    let mut value = serde_json::to_value(&order).expect("encode");
    value
        .as_object_mut()
        .expect("object")
        .remove("published_seq");
    let decoded: StoredLimitOrder = serde_json::from_value(value).expect("decode");
    assert_eq!(decoded.published_seq, 0);
}

// ---------------------------------------------------------------------------
// Deliverable B — pending_events / publish_pending / mark_published.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_events_are_byte_equal_ciphertext_with_subject_and_coarse_time() {
    let (backend, keys, order_id, store) = seeded_store("p54-shape").await;
    drive_five(&store, &order_id).await;
    let stream = transition_stream(&keys, &order_id);
    let records = transition_records(&backend, &stream);
    assert_eq!(records.len(), 5);

    let pending = store.pending_events(&order_id, 32).await.expect("pending");
    assert_eq!(pending.len(), 5);

    let expected_statuses = [
        OrderStatus::Active,
        OrderStatus::TriggerCandidate,
        OrderStatus::Quoting,
        OrderStatus::Simulating,
        OrderStatus::Executing,
    ];
    for (index, event) in pending.iter().enumerate() {
        let record = &records[index];
        assert_eq!(event.transition_seq, record.sequence);
        assert_eq!(
            event.envelope.event_id,
            order_event_id(&keys.blind_key(), &stream, record.sequence).expect("id")
        );
        assert_eq!(
            event.envelope.subject,
            event_subject(expected_statuses[index])
        );
        assert_eq!(
            event.envelope.occurred_at_ms,
            record.created_bucket.get(),
            "coarse bucket, not the exact transition time"
        );
        assert_eq!(event.envelope.payload, record.ciphertext);
        assert_eq!(event.envelope.schema_version, 1);
    }
}

#[tokio::test]
async fn publish_pending_advances_watermark_once_and_never_appends() {
    let (backend, keys, order_id, store) = seeded_store("p54-advance").await;
    drive_five(&store, &order_id).await;
    let stream = transition_stream(&keys, &order_id);
    let records_before = transition_records(&backend, &stream).len();

    let bus = RecordingBus::new();
    let before = load(&store, &order_id).await;

    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 5);
    assert_eq!(bus.envelopes().len(), 5);
    assert_eq!(load(&store, &order_id).await.published_seq, 5);
    // The watermark write is object-only: the transition stream is untouched.
    assert_eq!(transition_records(&backend, &stream).len(), records_before);

    // A second pump is a no-op; the order state is identical.
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 0);
    assert_eq!(bus.envelopes().len(), 5);
    assert!(same_order_state(&load(&store, &order_id).await, &before));
}

#[tokio::test]
async fn event_id_is_stable_across_reads_and_distinct_per_sequence() {
    let (_, keys, order_id, store) = seeded_store("p54-id").await;
    drive_five(&store, &order_id).await;
    let stream = transition_stream(&keys, &order_id);

    let first = store.pending_events(&order_id, 32).await.unwrap();
    let second = store.pending_events(&order_id, 32).await.unwrap();
    assert_eq!(
        first
            .iter()
            .map(|e| e.envelope.event_id.clone())
            .collect::<Vec<_>>(),
        second
            .iter()
            .map(|e| e.envelope.event_id.clone())
            .collect::<Vec<_>>()
    );

    let direct = order_event_id(&keys.blind_key(), &stream, 3).unwrap();
    assert_eq!(first[2].envelope.event_id, direct);
    assert_eq!(
        order_event_id(&keys.blind_key(), &stream, 3).unwrap(),
        order_event_id(&keys.blind_key(), &stream, 3).unwrap()
    );
    assert_ne!(
        order_event_id(&keys.blind_key(), &stream, 3).unwrap(),
        order_event_id(&keys.blind_key(), &stream, 4).unwrap()
    );
}

#[tokio::test]
async fn bus_failure_stops_pump_and_preserves_state_then_retry_completes() {
    let (_, _keys, order_id, store) = seeded_store("p54-bus-failure").await;
    drive_five(&store, &order_id).await;
    let before = load(&store, &order_id).await;

    // The bus rejects the 2nd publish (ordinal 1).
    let failing = RecordingBus::new();
    failing.fail_attempt(1);
    assert_eq!(
        store
            .publish_pending(&order_id, &failing, 32)
            .await
            .unwrap(),
        1
    );
    assert_eq!(failing.envelopes().len(), 1);
    let first_id = failing.envelopes()[0].event_id.clone();
    // OE-2: the order state is untouched and the watermark stopped at 1.
    assert!(same_order_state(&load(&store, &order_id).await, &before));
    assert_eq!(load(&store, &order_id).await.published_seq, 1);

    // A healthy retry publishes the remaining four from the watermark.
    let healthy = RecordingBus::new();
    assert_eq!(
        store
            .publish_pending(&order_id, &healthy, 32)
            .await
            .unwrap(),
        4
    );
    assert_eq!(load(&store, &order_id).await.published_seq, 5);

    // The consumer deduped the union by deterministic event_id: five distinct.
    let mut all = failing.envelopes();
    all.extend(healthy.envelopes());
    assert_eq!(all.len(), 5);
    assert_eq!(distinct_event_ids(&all).len(), 5);
    assert_eq!(all.iter().filter(|e| e.event_id == first_id).count(), 1);
}

#[tokio::test]
async fn watermark_write_failure_republishes_from_old_watermark() {
    let (backend, keys, order_id, store) = seeded_store("p54-crash").await;
    drive_five(&store, &order_id).await;
    let stream = transition_stream(&keys, &order_id);

    // Exhaust the bounded CAS retry budget: the events are delivered but the
    // watermark write cannot land (crash between publish and watermark).
    backend.inject_put_conflicts(MAX_OBJECT_CAS_ATTEMPTS);
    let bus = RecordingBus::new();
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 5);
    assert_eq!(bus.envelopes().len(), 5);
    assert_eq!(load(&store, &order_id).await.published_seq, 0);

    // The next pump republishes from the old watermark and advances it.
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 5);
    assert_eq!(load(&store, &order_id).await.published_seq, 5);
    assert_eq!(transition_records(&backend, &stream).len(), 5);

    // At-least-once delivery with no duplicate *distinct* event.
    let all = bus.envelopes();
    assert_eq!(all.len(), 10);
    assert_eq!(distinct_event_ids(&all).len(), 5);
}

#[tokio::test]
async fn max_events_zero_is_an_io_free_noop() {
    let (backend, _, order_id, store) = seeded_store("p54-zero").await;
    drive_five(&store, &order_id).await;
    let records_before = backend.events().len();
    let writes_before = backend.put_attempts().len();

    assert!(store.pending_events(&order_id, 0).await.unwrap().is_empty());
    let bus = RecordingBus::new();
    assert_eq!(store.publish_pending(&order_id, &bus, 0).await.unwrap(), 0);
    assert_eq!(bus.attempts(), 0);
    assert_eq!(load(&store, &order_id).await.published_seq, 0);
    assert_eq!(backend.events().len(), records_before);
    assert_eq!(backend.put_attempts().len(), writes_before);
}

#[tokio::test]
async fn lagging_object_head_caps_the_batch_until_repaired() {
    let (backend, keys, order_id, store) = seeded_store("p54-lag").await;
    drive(&store, &order_id, OrderStatus::Active, NOW).await;
    let object_id_hex = object_id(&keys.blind_key(), &ChainId::Base, &order_id).expect("object id");

    // Simulate a crash between the durable event append and its object
    // materialization: the stream holds seq 1 but the object lags at v1.
    backend.truncate_object_versions(&object_id_hex, 1);

    // The watermark lives on the object, so it must not advance over an event
    // the object has not applied (OE-5).
    assert!(store
        .pending_events(&order_id, 32)
        .await
        .unwrap()
        .is_empty());
    let bus = RecordingBus::new();
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 0);
    assert_eq!(bus.envelopes().len(), 0);
    assert_eq!(load(&store, &order_id).await.published_seq, 0);

    // Recovery repairs the object from the authoritative stream, after which
    // the event publishes normally.
    store.recover().await.expect("recover");
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 1);
    assert_eq!(load(&store, &order_id).await.published_seq, 1);
    assert_eq!(
        bus.envelopes()[0].subject,
        event_subject(OrderStatus::Active)
    );
}

#[tokio::test]
async fn publish_before_materialization_then_recover_repairs_without_quarantine() {
    let (backend, keys, order_id, store) = seeded_store("p54-lag-pub").await;
    let object_id_hex = object_id(&keys.blind_key(), &ChainId::Base, &order_id).expect("object id");

    // Materialize two transitions, then rewind the object to seq 1: event 2 is
    // durable in the authoritative stream but not materialized.
    drive(&store, &order_id, OrderStatus::Active, NOW).await;
    drive(&store, &order_id, OrderStatus::TriggerCandidate, NOW + 1).await;
    backend.truncate_object_versions(&object_id_hex, 2);

    // Publishing event 1 advances the object version while event 2's sealed
    // payload still carries the pre-publication version and watermark.
    let bus = RecordingBus::new();
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 1);
    assert_eq!(load(&store, &order_id).await.published_seq, 1);

    // Recovery must repair the lagging object, not quarantine a healthy order.
    let recovered = store.recover().await.expect("recover");
    assert!(
        recovered.quarantined.is_empty(),
        "healthy order quarantined: {recovered:?}"
    );

    // The repaired object is at the stream head; full replay returns it exactly
    // even though event 2's payload omits the publication bump.
    let repaired = load(&store, &order_id).await;
    assert_eq!(repaired.order.status, OrderStatus::TriggerCandidate);
    assert_eq!(repaired.published_seq, 1);
    assert_eq!(store.replay_from(&order_id, 0).await.unwrap(), repaired);

    // The owed event 2 is now publishable.
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 1);
    assert_eq!(bus.envelopes().len(), 2);
}

#[tokio::test]
async fn replay_from_after_publication_returns_the_current_head() {
    let (_, _, order_id, store) = seeded_store("p54-replay-pub").await;
    drive(&store, &order_id, OrderStatus::Active, NOW).await;
    let bus = RecordingBus::new();
    assert_eq!(store.publish_pending(&order_id, &bus, 32).await.unwrap(), 1);

    // Event 2 is sealed while the object watermark is already 1, so its payload
    // omits the publication that followed event 1.
    drive(&store, &order_id, OrderStatus::TriggerCandidate, NOW + 1).await;
    let current = load(&store, &order_id).await;
    assert_eq!(current.published_seq, 1);
    assert_eq!(current.order.status, OrderStatus::TriggerCandidate);

    // Full replay and a near-head replay both return the current object rather
    // than failing on the out-of-band watermark/version difference.
    assert_eq!(store.replay_from(&order_id, 0).await.unwrap(), current);
    assert_eq!(store.replay_from(&order_id, 2).await.unwrap(), current);
}

#[tokio::test]
async fn mark_published_rejects_a_watermark_past_the_materialized_head() {
    let (_, _, order_id, store) = seeded_store("p54-guard").await;
    let record = load(&store, &order_id).await;
    assert_eq!(
        store.mark_published(&order_id, record.version, 1).await,
        Err(LimitEngineError::StoreInvalid)
    );
    // The object is still readable and unchanged.
    assert_eq!(load(&store, &order_id).await, record);
}

#[tokio::test]
async fn large_backlog_is_batched_in_order() {
    let (_, _, order_id, store) = seeded_store("p54-batch").await;
    drive_five(&store, &order_id).await;
    let bus = RecordingBus::new();

    assert_eq!(store.publish_pending(&order_id, &bus, 2).await.unwrap(), 2);
    assert_eq!(load(&store, &order_id).await.published_seq, 2);
    assert_eq!(store.publish_pending(&order_id, &bus, 2).await.unwrap(), 2);
    assert_eq!(load(&store, &order_id).await.published_seq, 4);
    assert_eq!(store.publish_pending(&order_id, &bus, 2).await.unwrap(), 1);
    assert_eq!(load(&store, &order_id).await.published_seq, 5);
    assert_eq!(store.publish_pending(&order_id, &bus, 2).await.unwrap(), 0);

    let envelopes = bus.envelopes();
    assert_eq!(
        envelopes.len(),
        5,
        "every event published exactly once across batches"
    );
}

#[tokio::test]
async fn envelope_carries_no_plaintext_semantics() {
    let (backend, keys, order_id, store) = seeded_store("p54-noplaintext").await;
    drive_five(&store, &order_id).await;
    let stream = transition_stream(&keys, &order_id);
    let records = transition_records(&backend, &stream);
    let envelopes = store.pending_events(&order_id, 32).await.unwrap();

    let order = load(&store, &order_id).await;
    let plaintext_markers = [
        order.order.id.as_str(),
        order.order.owner.as_str(),
        order.order.wallet_ref.as_str(),
        "USDC",
        "TOKEN",
        "u1",
        "w1",
    ];

    for (event, record) in envelopes.iter().zip(records.iter()) {
        // OE-4: the payload is exactly the sealed ciphertext.
        assert_eq!(event.envelope.payload, record.ciphertext);
        // The event id is opaque lowercase hex.
        assert_eq!(event.envelope.event_id.len(), 64);
        assert!(event
            .envelope
            .event_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));

        let encoded = String::from_utf8(serde_json::to_vec(&event.envelope).unwrap()).unwrap();
        for marker in plaintext_markers {
            assert!(
                !encoded.contains(marker),
                "envelope leaked plaintext marker {marker:?}"
            );
        }
        // The serialized plaintext transition event is not recoverable from the
        // envelope either.
        assert!(!encoded.contains("transition_seq"));
        assert!(!encoded.contains("remaining_input"));
    }
}

// ---------------------------------------------------------------------------
// Deliverable C — orchestrator tick/recover wiring.
// ---------------------------------------------------------------------------

async fn load(store: &Store, order_id: &OrderId) -> StoredLimitOrder {
    store.load(order_id).await.expect("load").expect("present")
}

fn usdc() -> AssetId {
    support::asset("USDC")
}

fn token() -> AssetId {
    support::asset("TOKEN")
}

fn wallet_ref() -> WalletRef {
    WalletRef::new("w1").expect("wallet")
}

fn freshness(observed_at_ms: i64) -> Freshness {
    Freshness {
        observed_at_ms,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

/// Deterministic, injected quote provider: always reports a fresh 240-net plan.
struct ConstantProvider;

impl QuoteProvider for ConstantProvider {
    fn quote(
        &self,
        order: &StoredLimitOrder,
        amount_in: AtomicAmount,
        now_ms: i64,
    ) -> QuoteOutcome {
        QuoteOutcome::Quoted(Box::new(build_attempt(order, amount_in.get(), now_ms)))
    }
}

/// Deterministic quote provider that never serves a quote (recover never asks).
struct NoQuoteProvider;

impl QuoteProvider for NoQuoteProvider {
    fn quote(
        &self,
        _order: &StoredLimitOrder,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> QuoteOutcome {
        QuoteOutcome::Unavailable
    }
}

/// Copies `tests/orchestrator.rs::build_attempt` (test binaries do not share).
fn build_attempt(
    order: &StoredLimitOrder,
    amount: u128,
    now_ms: i64,
) -> limit_engine::QuotedAttempt {
    let token_in = order.order.token_in.clone();
    let token_out = order.order.token_out.clone();
    let intent = TradeIntent {
        id: IntentId::new(format!("intent-{}", order.order.id.as_str())).expect("intent id"),
        source: TradeSource::Web,
        user_id: order.order.owner.clone(),
        wallet_ref: order.order.wallet_ref.clone(),
        chain: order.order.chain.clone(),
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: order.order.side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
        order_type: OrderType::Limit,
        limit_price: Some(order.order.limit_price.clone()),
        risk: order.order.risk.clone(),
        allow_partial_fill: order.order.allow_partial_fill,
        expiry_ms: Some(order.order.expires_at_ms),
        nonce: order.nonce + order.attempt_seq,
        idempotency_key: IdempotencyKey::new(format!("idem-{}", order.order.id.as_str()))
            .expect("idempotency key"),
    };
    let net_delta = NetDelta {
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        net_input: AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(amount),
        },
        gross_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        dex_fee: None,
        tax_cost: None,
    };
    let route = RoutePlan {
        legs: vec![RouteLeg {
            venue: "synthetic".to_string(),
            pool_ref: "pool-1".to_string(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(amount),
            expected_amount_out: AtomicAmount::new(NET_OUTPUT),
        }],
        expected_net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        state: freshness(now_ms),
    };
    let assessment = TaxAssessment::new(
        token_out,
        order.order.chain.clone(),
        Bps::new(0).expect("buy tax"),
        Bps::new(0).expect("sell tax"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: now_ms,
            evaluated_at_ms: now_ms,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    );
    limit_engine::QuotedAttempt {
        intent,
        route,
        net_delta,
        assessment,
    }
}

fn policy_limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(5_000_000),
        max_daily_turnover_usd: UsdMicros::new(20_000_000),
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        allowed_chains: [ChainId::Base].into_iter().collect(),
        allowed_venues: ["synthetic".to_string()].into_iter().collect(),
    }
}

fn policy(enabled: bool) -> PolicyEngine {
    let gate = TradingGate::from_trusted_startup(Some(if enabled { "true" } else { "false" }))
        .expect("gate");
    PolicyEngine::new(gate, policy_limits()).expect("policy")
}

fn tax_observation(now_ms: i64) -> TaxObservation {
    TaxObservation {
        chain: ChainId::Base,
        token: token(),
        pool_ref: "pool-1".to_string(),
        router_ref: "synthetic".to_string(),
        wallet_ref: wallet_ref(),
        amount: AtomicAmount::new(1_000),
        block_or_slot: 1,
        buy_tax: Bps::new(0).expect("bps"),
        sell_tax: Bps::new(0).expect("bps"),
        buy_succeeds: true,
        sell_succeeds: true,
        sellable: true,
        confidence: Bps::new(9_000).expect("bps"),
        observed_at_ms: now_ms - 1_000,
        expires_at_ms: now_ms + 60_000,
    }
}

fn trust(now_ms: i64) -> AttemptTrust {
    AttemptTrust {
        policy_context: PolicyContext::from_trusted_backend_state(
            now_ms,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("synthetic".to_string()),
        )
        .expect("policy context"),
        wallet_balance: WalletBalance {
            wallet_ref: wallet_ref(),
            chain: ChainId::Base,
            asset: usdc(),
            available: AtomicAmount::new(1_000_000),
            freshness: freshness(now_ms - 1_000),
        },
        allowance: AllowanceObservation::NotRequired,
        tax_observation: tax_observation(now_ms),
        allowed_programs: HashSet::new(),
        freshness_policy: FreshnessPolicy::default(),
    }
}

/// Scripted execution seam; never signs, returns the queued resolution.
struct FakeExecutor {
    resolutions: Mutex<VecDeque<AttemptResolution>>,
    calls: AtomicU64,
}

impl FakeExecutor {
    fn new(resolutions: Vec<AttemptResolution>) -> Self {
        Self {
            resolutions: Mutex::new(VecDeque::from(resolutions)),
            calls: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl AttemptExecutor for FakeExecutor {
    async fn payload_digest(&self, _intent: &TradeIntent) -> Result<[u8; 32], LimitEngineError> {
        Ok([0xAB; 32])
    }

    async fn execute(
        &self,
        _prepared: &PreparedAttempt,
        _attempt: &BoundAttempt,
        _now_ms: i64,
    ) -> AttemptResolution {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.resolutions)
            .pop_front()
            .expect("scripted resolution")
    }

    async fn reconcile(&self, _attempt: &BoundAttempt, _now_ms: i64) -> AttemptResolution {
        AttemptResolution::Unknown
    }
}

fn realized(input: u128, output: u128) -> AttemptResolution {
    AttemptResolution::Filled(RealizedFill {
        net_input: AtomicAmount::new(input),
        net_output: AtomicAmount::new(output),
    })
}

/// A `Created` order that is created directly in `status`, with a ratio that
/// makes a 1000 input / 240 net output click.
async fn create_order(
    backend: &Arc<InMemoryOpaqueStore>,
    keys: &Arc<TestOrderKeys>,
    creation: &str,
    status: OrderStatus,
) -> OrderId {
    let mut order = durable_order(keys, creation, status, 1000, 1000, 0);
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    order.order.expires_at_ms = support::EXPIRY_MS;
    let order_id = order.order.id.clone();
    durable_store(backend, keys)
        .create(order)
        .await
        .expect("create order");
    order_id
}

#[tokio::test]
async fn tick_publishes_one_envelope_per_transition_in_order() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let order_id = create_order(&backend, &keys, "p54-tick", OrderStatus::Active).await;
    let bus = Arc::new(RecordingBus::new());
    let orchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        ConstantProvider,
        FakeExecutor::new(vec![realized(1000, 240)]),
        policy(true),
        AttemptLimits {
            max_attempts_per_order: 4,
        },
    )
    .with_event_bus(Some(bus.clone()));

    let trust = trust(NOW);
    let outcome = orchestrator
        .tick(TickInput {
            order_id: &order_id,
            signal: true,
            source: TradeSource::Web,
            trust: &trust,
            now_ms: NOW,
        })
        .await
        .expect("tick");
    assert!(
        matches!(outcome, TickOutcome::Filled { attempt_seq: 1, .. }),
        "got {outcome:?}"
    );

    let stream = transition_stream(&keys, &order_id);
    let records = transition_records(&backend, &stream);
    let envelopes = bus.envelopes();
    assert_eq!(envelopes.len(), records.len());
    assert_eq!(records.len(), 5);

    for (index, (envelope, record)) in envelopes.iter().zip(records.iter()).enumerate() {
        assert_eq!(
            envelope.event_id,
            order_event_id(&keys.blind_key(), &stream, record.sequence).expect("id")
        );
        assert_eq!(envelope.occurred_at_ms, record.created_bucket.get());
        assert_eq!(envelope.payload, record.ciphertext);
        assert_eq!(
            envelope.subject,
            event_subject(record_status(index)),
            "transition {index} subject"
        );
    }
    // The deterministic id is also stable across a re-read of the same stream.
    assert_eq!(distinct_event_ids(&envelopes).len(), 5);
}

/// Post-state status of the `index`th transition produced by a happy-path tick.
fn record_status(index: usize) -> OrderStatus {
    match index {
        0 => OrderStatus::TriggerCandidate,
        1 => OrderStatus::Quoting,
        2 => OrderStatus::Simulating,
        3 => OrderStatus::Executing,
        4 => OrderStatus::Filled,
        other => panic!("unexpected transition index {other}"),
    }
}

#[tokio::test]
async fn recover_republishes_pending_events() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let order_id = create_order(&backend, &keys, "p54-recover", OrderStatus::Created).await;
    // One durable transition, never published.
    drive(
        &durable_store(&backend, &keys),
        &order_id,
        OrderStatus::Active,
        NOW,
    )
    .await;

    let bus = Arc::new(RecordingBus::new());
    let orchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        NoQuoteProvider,
        FakeExecutor::new(Vec::new()),
        policy(true),
        AttemptLimits {
            max_attempts_per_order: 4,
        },
    )
    .with_event_bus(Some(bus.clone()));

    let report = orchestrator.recover(NOW).await.expect("recover");
    assert!(report.open >= 1);

    let envelopes = bus.envelopes();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].subject, event_subject(OrderStatus::Active));
    assert_eq!(
        durable_store(&backend, &keys)
            .load(&order_id)
            .await
            .unwrap()
            .unwrap()
            .published_seq,
        1
    );
}

#[tokio::test]
async fn publish_events_is_a_transport_free_seam() {
    let (_, _, order_id, store) = seeded_store("p54-seam").await;
    drive_five(&store, &order_id).await;

    let orchestrator = Orchestrator::new(
        store,
        NoQuoteProvider,
        FakeExecutor::new(Vec::new()),
        policy(true),
        AttemptLimits {
            max_attempts_per_order: 4,
        },
    );
    let bus = RecordingBus::new();
    assert_eq!(
        orchestrator
            .publish_events(&order_id, &bus, 3)
            .await
            .unwrap(),
        3
    );
    assert_eq!(bus.envelopes().len(), 3);
}
