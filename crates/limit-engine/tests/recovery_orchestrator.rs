//! P52 — startup recovery and crash-injection for the limit orchestrator.
//!
//! Every test drives the real `DurableLimitOrderStore` over the in-memory
//! `OpaqueStore` fake with a deterministic quote provider and a scripted,
//! counting fake execution seam. Crashes are simulated by constructing the
//! durable state exactly as the process would have left it at each window, then
//! running a fresh `Orchestrator::recover` on that state.
//!
//! The invariants under test (RC-1..RC-7):
//! - recovery never calls `execute` (never signs or submits);
//! - a possibly-sent attempt is reconciled, never re-signed;
//! - a confirmed fill is applied at most once and a second `recover` is a no-op;
//! - a fill outside `net_input == chunk` / `min_out` fails final with no ledger
//!   mutation;
//! - `Executing` with no attempt is a definitive pre-send failure;
//! - a disabled trading gate defers every write and executor call.

mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chain_types::ChainId;
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, LimitPrice, OrderId,
    OrderStatus, OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, UserId,
    WalletRef,
};
use limit_engine::{
    attempt_intent_id, attempt_key, attempt_prepared_reference, conservation_holds, object_id,
    ApprovalSnapshot, AttemptExecutor, AttemptLimits, AttemptPhase, AttemptResolution,
    BoundAttempt, DurableLimitOrderStore, LimitEngineError, LimitOrderStore, Orchestrator,
    OrderAttemptEvent, PreparedAttempt, QuoteOutcome, QuoteProvider, RealizedFill, RecoveryReport,
    StoredLimitOrder,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessStatus, PriceRatio, Sequence,
};
use policy::{PolicyEngine, PolicyLimits, TradingGate, UsdMicros};

use support::asset;
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

const NOW: i64 = 100_000;
const EXPIRY_MS: i64 = 1_000_000;
/// Bound chunk for every attempt fixture.
const CHUNK: u128 = 1_000;
/// Route expected net output (and the exact min-out for a 1000/24 buy).
const NET_OUTPUT: u128 = 240;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wallet_ref() -> WalletRef {
    WalletRef::new("w1").expect("wallet")
}

/// Deterministic quote provider that counts (and never serves) calls.
struct NoQuoteProvider {
    calls: Arc<AtomicU64>,
}

impl QuoteProvider for NoQuoteProvider {
    fn quote(
        &self,
        _order: &StoredLimitOrder,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> QuoteOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        QuoteOutcome::Unavailable
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

/// Scripted fake seam. `execute` is the signing/submission path and must never
/// be reached by recovery; `reconcile` is scripted and counted.
struct ScriptedExecutor {
    execute_calls: Arc<AtomicU64>,
    reconcile_calls: Arc<AtomicU64>,
    digest_calls: Arc<AtomicU64>,
    reconcile_results: Arc<Mutex<VecDeque<AttemptResolution>>>,
    reconciled: Arc<Mutex<Vec<BoundAttempt>>>,
}

/// Assertion handles shared with [`ScriptedExecutor`].
#[derive(Clone)]
struct ExecutorHandles {
    execute_calls: Arc<AtomicU64>,
    reconcile_calls: Arc<AtomicU64>,
    digest_calls: Arc<AtomicU64>,
    reconciled: Arc<Mutex<Vec<BoundAttempt>>>,
}

impl ScriptedExecutor {
    fn new(results: Vec<AttemptResolution>) -> (Self, ExecutorHandles) {
        let execute_calls = Arc::new(AtomicU64::new(0));
        let reconcile_calls = Arc::new(AtomicU64::new(0));
        let digest_calls = Arc::new(AtomicU64::new(0));
        let reconcile_results = Arc::new(Mutex::new(VecDeque::from(results)));
        let reconciled = Arc::new(Mutex::new(Vec::new()));
        let handles = ExecutorHandles {
            execute_calls: execute_calls.clone(),
            reconcile_calls: reconcile_calls.clone(),
            digest_calls: digest_calls.clone(),
            reconciled: reconciled.clone(),
        };
        (
            Self {
                execute_calls,
                reconcile_calls,
                digest_calls,
                reconcile_results,
                reconciled,
            },
            handles,
        )
    }
}

#[async_trait]
impl AttemptExecutor for ScriptedExecutor {
    async fn payload_digest(&self, _intent: &TradeIntent) -> Result<[u8; 32], LimitEngineError> {
        self.digest_calls.fetch_add(1, Ordering::SeqCst);
        Ok([0xAB; 32])
    }

    async fn execute(
        &self,
        _prepared: &PreparedAttempt,
        _attempt: &BoundAttempt,
        _now_ms: i64,
    ) -> AttemptResolution {
        // Recovery must never reach the signing path.
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        AttemptResolution::FailedBeforeSubmit
    }

    async fn reconcile(&self, attempt: &BoundAttempt, _now_ms: i64) -> AttemptResolution {
        self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.reconciled).push(attempt.clone());
        lock(&self.reconcile_results)
            .pop_front()
            .unwrap_or(AttemptResolution::Unknown)
    }
}

/// A crash-state fixture description.
struct Spec {
    creation: &'static str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
    expires_at_ms: i64,
    enabled: bool,
    max_attempts: u32,
}

fn spec(
    creation: &'static str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
) -> Spec {
    Spec {
        creation,
        status,
        max,
        remaining,
        filled,
        expires_at_ms: EXPIRY_MS,
        enabled: true,
        max_attempts: 4,
    }
}

impl Spec {
    fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    fn with_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    fn expiring_at(mut self, expires_at_ms: i64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }
}

struct Harness {
    backend: Arc<InMemoryOpaqueStore>,
    keys: Arc<TestOrderKeys>,
    store: DurableLimitOrderStore<InMemoryOpaqueStore>,
    order_id: OrderId,
    handles: ExecutorHandles,
    quote_calls: Arc<AtomicU64>,
    orchestrator: Orchestrator<InMemoryOpaqueStore, NoQuoteProvider, ScriptedExecutor>,
}

/// Builds the durable crash state: one order created directly in `spec.status`
/// (no transitions), an injected store, and a fresh orchestrator over the same
/// backend.
async fn build(spec: Spec, reconcile_results: Vec<AttemptResolution>) -> Harness {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let mut order = durable_order(
        &keys,
        spec.creation,
        spec.status,
        spec.max,
        spec.remaining,
        spec.filled,
    );
    order.order.expires_at_ms = spec.expires_at_ms;
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let order_id = order.order.id.clone();
    let store = durable_store(&backend, &keys);
    store.create(order).await.expect("create order");

    let (executor, handles) = ScriptedExecutor::new(reconcile_results);
    let quote_calls = Arc::new(AtomicU64::new(0));
    let orchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        NoQuoteProvider {
            calls: quote_calls.clone(),
        },
        executor,
        policy(spec.enabled),
        AttemptLimits {
            max_attempts_per_order: spec.max_attempts,
        },
    );
    Harness {
        backend,
        keys,
        store,
        order_id,
        handles,
        quote_calls,
        orchestrator,
    }
}

async fn load(h: &Harness) -> StoredLimitOrder {
    h.store
        .load(&h.order_id)
        .await
        .expect("load")
        .expect("present")
}

async fn load_id(h: &Harness, order_id: &OrderId) -> StoredLimitOrder {
    h.store
        .load(order_id)
        .await
        .expect("load")
        .expect("present")
}

async fn attempts(h: &Harness) -> Vec<OrderAttemptEvent> {
    h.store
        .read_attempts(&h.order_id)
        .await
        .expect("read attempts")
}

async fn recover(h: &Harness) -> RecoveryReport {
    h.orchestrator.recover(NOW).await.expect("recover")
}

fn realized(input: u128, output: u128) -> RealizedFill {
    RealizedFill {
        net_input: AtomicAmount::new(input),
        net_output: AtomicAmount::new(output),
    }
}

fn bound_intent(h: &Harness, order_id: &OrderId, attempt_seq: u64) -> TradeIntent {
    let token_in = asset("USDC");
    let token_out = asset("TOKEN");
    TradeIntent {
        id: attempt_intent_id(&h.keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("intent id"),
        source: domain::TradeSource::Web,
        user_id: UserId::new("u1").expect("user"),
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(CHUNK),
        order_type: OrderType::Limit,
        limit_price: Some(LimitPrice {
            numerator_asset: token_in,
            denominator_asset: token_out.clone(),
            ratio: PriceRatio::new(100, 24).expect("ratio"),
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
        idempotency_key: attempt_key(&h.keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("attempt key"),
    }
}

fn bound_route() -> RoutePlan {
    let token_in = asset("USDC");
    let token_out = asset("TOKEN");
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "synthetic".to_string(),
            pool_ref: "pool-1".to_string(),
            token_in,
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(CHUNK),
            expected_amount_out: AtomicAmount::new(NET_OUTPUT),
        }],
        expected_net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        state: Freshness {
            observed_at_ms: NOW - 1_000,
            chain_height: 10,
            sequence: Sequence(1),
        },
    }
}

fn bound_preview(intent: &TradeIntent) -> ExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: ChainId::Base,
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: TradeSide::Buy,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(CHUNK),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(NET_OUTPUT),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: FreshnessStatus::Fresh,
    }
}

fn bound_attempt(h: &Harness, order_id: &OrderId, attempt_seq: u64) -> BoundAttempt {
    let intent = bound_intent(h, order_id, attempt_seq);
    BoundAttempt {
        route: bound_route(),
        preview: bound_preview(&intent),
        approval: ApprovalSnapshot {
            intent_id: intent.id.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: ChainId::Base,
            idempotency_key: intent.idempotency_key.clone(),
            expires_at_ms: Some(EXPIRY_MS),
            approved_trade_usd: 500_000,
            approved_at_ms: 1,
        },
        prepared_reference: attempt_prepared_reference(
            &h.keys.blind_key(),
            &ChainId::Base,
            order_id,
            attempt_seq,
        )
        .expect("prepared reference"),
        payload_digest: [0xAB; 32],
        attempt_key: intent.idempotency_key.clone(),
        attempt_seq,
        nonce: attempt_seq,
        intent,
    }
}

async fn append_bound(h: &Harness, order_id: &OrderId, attempt_seq: u64) {
    let event = OrderAttemptEvent::bound(
        bound_attempt(h, order_id, attempt_seq),
        order_id.clone(),
        NOW,
    );
    h.store.append_attempt(&event).await.expect("append bound");
}

async fn append_confirmed(h: &Harness, order_id: &OrderId, attempt_seq: u64, fill: RealizedFill) {
    let event = OrderAttemptEvent::confirmed(
        order_id.clone(),
        attempt_seq,
        attempt_key(&h.keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("attempt key"),
        fill,
        NOW,
    );
    h.store
        .append_attempt(&event)
        .await
        .expect("append confirmed");
}

async fn append_phase(h: &Harness, order_id: &OrderId, attempt_seq: u64, phase: AttemptPhase) {
    let event = OrderAttemptEvent::phase(
        order_id.clone(),
        attempt_seq,
        attempt_key(&h.keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("attempt key"),
        phase,
        None,
        NOW,
    );
    h.store.append_attempt(&event).await.expect("append phase");
}

/// Asserts the signing/submission path was never reached.
fn assert_never_executed(h: &Harness) {
    assert_eq!(
        h.handles.execute_calls.load(Ordering::SeqCst),
        0,
        "recovery must never call execute"
    );
}

#[tokio::test]
async fn crash_after_executing_before_bound_closes_retryable() {
    let h = build(
        spec("p52-before-bound", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![],
    )
    .await;
    assert!(attempts(&h).await.is_empty());

    let report = recover(&h).await;

    assert_eq!(report.open, 1);
    assert_eq!(report.in_flight, 0);
    assert_eq!(report.reconciled, 0);
    assert_eq!(report.fills_applied, 0);
    assert_eq!(report.finalized, 0);
    assert_eq!(report.retryable, 1);
    assert_eq!(report.quarantined, 0);
    assert!(!report.kill_switch_deferred);

    assert_eq!(load(&h).await.order.status, OrderStatus::FailedRetryable);
    assert_never_executed(&h);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.quote_calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn crash_after_bound_reconciles_fill_exactly_once() {
    let h = build(
        spec("p52-after-bound", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![AttemptResolution::Filled(realized(1_000, 240))],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    let report = recover(&h).await;

    assert_eq!(report.reconciled, 1);
    assert_eq!(report.fills_applied, 1);
    assert_eq!(report.finalized, 0);
    assert_never_executed(&h);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), 1_000);
    assert_eq!(stored.order.remaining_input.get(), 0);
    assert!(conservation_holds(&stored));

    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].phase, AttemptPhase::Bound);
    assert_eq!(events[1].phase, AttemptPhase::Confirmed);
    let sealed = events[1].realized_fill.clone().expect("sealed fill");
    assert_eq!(sealed.net_input.get(), 1_000);
    assert_eq!(sealed.net_output.get(), 240);

    // A second pass is a no-op: the order is terminal, no fill is re-applied,
    // and no phase is duplicated.
    let second = recover(&h).await;
    assert_eq!(second.open, 0);
    assert_eq!(second.fills_applied, 0);
    assert_eq!(second.reconciled, 0);
    assert_eq!(second.finalized, 0);
    assert_never_executed(&h);
    assert_eq!(attempts(&h).await.len(), 2);
}

#[tokio::test]
async fn crash_after_sign_only_reconciles_never_signs() {
    // The signature may already have reached the chain but the `Signed` phase
    // never landed: the durable state is `Executing` + `[Bound(1)]`. Recovery
    // must reconcile it and must never touch the signing seam.
    let h = build(
        spec("p52-after-sign", OrderStatus::Executing, 2_000, 2_000, 0),
        vec![AttemptResolution::Filled(realized(1_000, 240))],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    let report = recover(&h).await;

    assert_eq!(report.reconciled, 1);
    assert_eq!(report.fills_applied, 1);
    assert_never_executed(&h);
    assert_eq!(h.handles.digest_calls.load(Ordering::SeqCst), 0);

    {
        let reconciled = lock(&h.handles.reconciled);
        assert_eq!(reconciled.len(), 1);
        assert_eq!(reconciled[0].attempt_seq, 1);
        assert_eq!(reconciled[0].payload_digest, [0xAB; 32]);
        assert_eq!(reconciled[0].intent.amount.get(), CHUNK);
    }

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::PartiallyFilled);
    assert_eq!(stored.filled_input.get(), 1_000);
    assert_eq!(stored.order.remaining_input.get(), 1_000);
    assert!(conservation_holds(&stored));
}

#[tokio::test]
async fn crash_after_confirmed_before_fill_applies_fill_once() {
    let h = build(
        spec(
            "p52-after-confirmed",
            OrderStatus::Executing,
            1_000,
            1_000,
            0,
        ),
        vec![],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    append_confirmed(&h, &h.order_id, 1, realized(1_000, 240)).await;

    let report = recover(&h).await;

    assert_eq!(report.fills_applied, 1);
    assert_eq!(report.finalized, 0);
    assert_eq!(report.reconciled, 0);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_never_executed(&h);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), 1_000);
    assert!(conservation_holds(&stored));

    // Idempotent on re-run: no new fill, no duplicated phase.
    let second = recover(&h).await;
    assert_eq!(second.fills_applied, 0);
    assert_eq!(second.open, 0);
    assert_never_executed(&h);
    assert_eq!(attempts(&h).await.len(), 2);
}

#[tokio::test]
async fn stale_confirmed_from_prior_attempt_is_never_replayed() {
    // Regression (P52 review, High): an order that partially filled can re-enter
    // `Executing` for a new attempt and crash before its `Bound`, leaving the
    // *previous* attempt's terminal `Confirmed` at the head of the stream.
    // Recovery must not replay that already-applied fill (RC-3); the current
    // window is a definitive pre-send failure.
    let h = build(
        spec(
            "p52-stale-confirmed",
            OrderStatus::Executing,
            2_000,
            1_000,
            1_000,
        ),
        vec![AttemptResolution::Filled(realized(1_000, 240))],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    append_confirmed(&h, &h.order_id, 1, realized(1_000, 240)).await;

    let report = recover(&h).await;

    assert_eq!(report.fills_applied, 0, "the applied fill must not replay");
    assert_eq!(report.retryable, 1);
    assert_eq!(report.finalized, 0);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_never_executed(&h);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedRetryable);
    assert_eq!(stored.filled_input.get(), 1_000);
    assert_eq!(stored.order.remaining_input.get(), 1_000);
    assert!(conservation_holds(&stored));
    assert_eq!(attempts(&h).await.len(), 2);

    // A second pass is a no-op.
    let second = recover(&h).await;
    assert_eq!(second.fills_applied, 0);
    assert_eq!(stored.filled_input.get(), 1_000);
    assert_eq!(attempts(&h).await.len(), 2);
}

#[tokio::test]
async fn stale_confirmed_beyond_remaining_does_not_abort_the_pass() {
    // Blast-radius variant: a stale fill whose amount still matches the bound
    // chunk but exceeds the new window's remaining input. Before the fix this
    // reached `RemainingUnderflow` and aborted the whole recovery pass; now the
    // ledger proves the fill was already applied, so recovery closes pre-send
    // with no mutation.
    let h = build(
        spec(
            "p52-stale-confirmed-overflow",
            OrderStatus::Executing,
            2_000,
            500,
            1_500,
        ),
        vec![],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    // `net_input` equals the bound chunk (1000) so the pre-fix path passes the
    // fill validation and reaches the ledger subtraction with remaining 500.
    append_confirmed(&h, &h.order_id, 1, realized(1_000, 240)).await;

    let report = recover(&h).await;

    assert_eq!(report.fills_applied, 0);
    assert_eq!(report.retryable, 1);
    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedRetryable);
    assert_eq!(stored.filled_input.get(), 1_500);
    assert_eq!(stored.order.remaining_input.get(), 500);
    assert!(conservation_holds(&stored));
    assert_never_executed(&h);
}

#[tokio::test]
async fn durable_signed_and_submitted_phases_reconcile() {
    // The in-flight phases that may already have reached the chain are all
    // reconciled through the same mapping, never re-signed.
    for phase in [AttemptPhase::Signed, AttemptPhase::Submitted] {
        let h = build(
            spec(
                "p52-inflight-phase",
                OrderStatus::Executing,
                1_000,
                1_000,
                0,
            ),
            vec![AttemptResolution::Filled(realized(1_000, 240))],
        )
        .await;
        append_bound(&h, &h.order_id, 1).await;
        append_phase(&h, &h.order_id, 1, phase).await;

        let report = recover(&h).await;

        assert_eq!(report.reconciled, 1, "phase {phase:?}");
        assert_eq!(report.fills_applied, 1, "phase {phase:?}");
        assert_never_executed(&h);
        assert_eq!(load(&h).await.order.status, OrderStatus::Filled);
        assert_eq!(attempts(&h).await.len(), 3, "phase {phase:?}");
    }
}

#[tokio::test]
async fn unknown_reconcile_stays_executing_and_is_idempotent() {
    let h = build(
        spec("p52-unknown", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![AttemptResolution::Unknown],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    let first = recover(&h).await;
    assert_eq!(first.reconciled, 1);
    assert_eq!(first.fills_applied, 0);
    assert_eq!(first.finalized, 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);
    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].phase, AttemptPhase::Unknown);

    // The second pass reconciles again but never duplicates the phase.
    let second = recover(&h).await;
    assert_eq!(second.reconciled, 1);
    assert_eq!(second.fills_applied, 0);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 2);
    assert_never_executed(&h);
    assert_eq!(attempts(&h).await.len(), 2);
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);
}

#[tokio::test]
async fn reconcile_rejected_is_final() {
    let h = build(
        spec("p52-rejected", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![AttemptResolution::Rejected],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    let report = recover(&h).await;

    assert_eq!(report.reconciled, 1);
    assert_eq!(report.finalized, 1);
    assert_eq!(report.fills_applied, 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedFinal);
    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].phase, AttemptPhase::Rejected);
    assert_never_executed(&h);
}

#[tokio::test]
async fn reconcile_failed_before_submit_is_bounded_by_attempt_limit() {
    // Retries remain -> retryable.
    let retryable = build(
        spec("p52-fbs-retry", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![AttemptResolution::FailedBeforeSubmit],
    )
    .await;
    append_bound(&retryable, &retryable.order_id, 1).await;
    let report = recover(&retryable).await;
    assert_eq!(report.reconciled, 1);
    assert_eq!(report.retryable, 1);
    assert_eq!(report.finalized, 0);
    assert_eq!(
        load(&retryable).await.order.status,
        OrderStatus::FailedRetryable
    );
    let events = attempts(&retryable).await;
    assert_eq!(events[1].phase, AttemptPhase::FailedBeforeSubmit);
    assert_never_executed(&retryable);

    // The attempt cap is reached -> final.
    let exhausted = build(
        spec("p52-fbs-final", OrderStatus::Executing, 1_000, 1_000, 0).with_attempts(1),
        vec![AttemptResolution::FailedBeforeSubmit],
    )
    .await;
    append_bound(&exhausted, &exhausted.order_id, 1).await;
    let report = recover(&exhausted).await;
    assert_eq!(report.finalized, 1);
    assert_eq!(report.retryable, 0);
    assert_eq!(
        load(&exhausted).await.order.status,
        OrderStatus::FailedFinal
    );
    assert_never_executed(&exhausted);
}

#[tokio::test]
async fn latest_failed_before_submit_advances_without_reconcile() {
    // Crash after the phase was appended but before the order transition:
    // recovery advances the order but does not reconcile or re-append.
    let h = build(
        spec("p52-latest-fbs", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    append_phase(&h, &h.order_id, 1, AttemptPhase::FailedBeforeSubmit).await;

    let report = recover(&h).await;

    assert_eq!(report.reconciled, 0);
    assert_eq!(report.retryable, 1);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedRetryable);
    assert_eq!(attempts(&h).await.len(), 2);
    assert_never_executed(&h);
}

#[tokio::test]
async fn confirmed_without_realized_fill_fails_final_without_mutation() {
    let h = build(
        spec(
            "p52-legacy-confirmed",
            OrderStatus::Executing,
            1_000,
            1_000,
            0,
        ),
        vec![],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    append_phase(&h, &h.order_id, 1, AttemptPhase::Confirmed).await;

    let report = recover(&h).await;

    assert_eq!(report.finalized, 1);
    assert_eq!(report.fills_applied, 0);
    assert_eq!(report.reconciled, 0);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedFinal);
    assert_eq!(stored.filled_input.get(), 0);
    assert_eq!(stored.order.remaining_input.get(), 1_000);
    assert!(conservation_holds(&stored));
    assert_never_executed(&h);
}

#[tokio::test]
async fn confirmed_fill_below_min_out_fails_final_without_mutation() {
    let h = build(
        spec(
            "p52-violating-confirmed",
            OrderStatus::Executing,
            1_000,
            1_000,
            0,
        ),
        vec![],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    append_confirmed(&h, &h.order_id, 1, realized(1_000, 239)).await;

    let report = recover(&h).await;

    assert_eq!(report.finalized, 1);
    assert_eq!(report.fills_applied, 0);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedFinal);
    assert_eq!(stored.filled_input.get(), 0);
    assert_eq!(stored.order.remaining_input.get(), 1_000);
    assert!(conservation_holds(&stored));
    assert_never_executed(&h);
}

#[tokio::test]
async fn kill_switch_off_defers_all_recovery_work() {
    let h = build(
        spec("p52-killswitch", OrderStatus::Executing, 1_000, 1_000, 0).disabled(),
        vec![AttemptResolution::Filled(realized(1_000, 240))],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;
    let events_before = h.backend.events().len();
    let puts_before = h.backend.put_attempts().len();

    let report = recover(&h).await;

    assert!(report.kill_switch_deferred);
    assert_eq!(report.open, 1);
    assert_eq!(report.in_flight, 1);
    assert_eq!(report.reconciled, 0);
    assert_eq!(report.fills_applied, 0);
    assert_eq!(report.finalized, 0);

    assert_never_executed(&h);
    assert_eq!(h.handles.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.quote_calls.load(Ordering::SeqCst), 0);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Executing);
    assert_eq!(stored.version, 1);
    assert_eq!(h.backend.events().len(), events_before);
    assert_eq!(h.backend.put_attempts().len(), puts_before);
    assert_eq!(attempts(&h).await.len(), 1);
}

#[tokio::test]
async fn recovery_is_idempotent_over_a_healthy_mix() {
    let h = build(
        spec("p52-idem-partial", OrderStatus::Executing, 2_000, 2_000, 0),
        vec![
            AttemptResolution::Filled(realized(1_000, 240)),
            AttemptResolution::Filled(realized(1_000, 240)),
        ],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    // A second, independent healthy order in the same durable store.
    let mut full = durable_order(
        &h.keys,
        "p52-idem-full",
        OrderStatus::Executing,
        1_000,
        1_000,
        0,
    );
    full.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let full_id = full.order.id.clone();
    h.store.create(full).await.expect("create full");
    append_bound(&h, &full_id, 1).await;

    let first = recover(&h).await;
    assert_eq!(first.fills_applied, 2);
    assert_eq!(first.reconciled, 2);
    assert_eq!(load(&h).await.order.status, OrderStatus::PartiallyFilled);
    assert_eq!(
        load_id(&h, &full_id).await.order.status,
        OrderStatus::Filled
    );
    let events_after_first = attempts(&h).await.len();

    let second = recover(&h).await;
    assert_eq!(second.fills_applied, 0);
    assert_eq!(second.finalized, 0);
    assert_eq!(second.reconciled, 0);
    assert_never_executed(&h);
    assert_eq!(attempts(&h).await.len(), events_after_first);
    assert_eq!(load(&h).await.order.status, OrderStatus::PartiallyFilled);
}

#[tokio::test]
async fn quarantine_does_not_block_healthy_recovery() {
    let h = build(
        spec(
            "p52-quarantine-healthy",
            OrderStatus::Executing,
            1_000,
            1_000,
            0,
        ),
        vec![AttemptResolution::Filled(realized(1_000, 240))],
    )
    .await;
    append_bound(&h, &h.order_id, 1).await;

    let corrupt = durable_order(
        &h.keys,
        "p52-quarantine-corrupt",
        OrderStatus::Executing,
        1_000,
        1_000,
        0,
    );
    let corrupt_id = corrupt.order.id.clone();
    h.store.create(corrupt).await.expect("create corrupt");
    let object_id = object_id(&h.keys.blind_key(), &ChainId::Base, &corrupt_id).expect("object id");
    let mut object = h.backend.latest_object(&object_id).expect("corrupt object");
    let last = object.ciphertext.len() - 1;
    object.ciphertext[last] ^= 0xFF;
    h.backend.replace_object(object);

    let report = recover(&h).await;

    assert_eq!(report.quarantined, 1);
    assert_eq!(report.open, 1);
    assert_eq!(report.fills_applied, 1);
    assert_eq!(report.reconciled, 1);
    assert_eq!(load(&h).await.order.status, OrderStatus::Filled);
    assert_never_executed(&h);
}

#[tokio::test]
async fn expired_executing_without_attempt_closes_expired() {
    // No attempt and past the deadline: the definitive pre-send failure cannot
    // be retryable, so it closes `Expired` rather than wedging.
    let h = build(
        spec(
            "p52-before-bound-expired",
            OrderStatus::Executing,
            1_000,
            1_000,
            0,
        )
        .expiring_at(NOW - 1),
        vec![],
    )
    .await;

    let report = recover(&h).await;

    assert_eq!(report.finalized, 1);
    assert_eq!(report.retryable, 0);
    assert_eq!(report.reconciled, 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::Expired);
    assert_never_executed(&h);
}

#[test]
fn recovery_report_and_confirmed_event_debug_are_redacted() {
    let report = RecoveryReport {
        open: 3,
        in_flight: 2,
        reconciled: 1,
        fills_applied: 1,
        finalized: 1,
        retryable: 0,
        quarantined: 1,
        truncated: false,
        kill_switch_deferred: false,
    };
    let rendered = format!("{report:?}");
    assert!(rendered.contains("RecoveryReport"));
    for needle in ["USDC", "TOKEN", "order-secret", "key-secret", "0x"] {
        assert!(
            !rendered.contains(needle),
            "RecoveryReport Debug leaked `{needle}`: {rendered}"
        );
    }

    let event = OrderAttemptEvent::confirmed(
        OrderId::new("order-secret").expect("order"),
        1,
        IdempotencyKey::new("key-secret").expect("key"),
        realized(12_345, 67_890),
        7,
    );
    let rendered = format!("{event:?}");
    for needle in [
        "order-secret",
        "key-secret",
        "12345",
        "67890",
        "RealizedFill",
    ] {
        assert!(
            !rendered.contains(needle),
            "OrderAttemptEvent Debug leaked `{needle}`: {rendered}"
        );
    }
}

#[test]
fn legacy_confirmed_event_without_realized_fill_decodes() {
    // A `Confirmed` record written before the field existed must still decode
    // and validate; recovery fails it closed rather than guessing a fill.
    let mut event = OrderAttemptEvent::phase(
        OrderId::new("legacy-order").expect("order"),
        1,
        IdempotencyKey::new("legacy-key").expect("key"),
        AttemptPhase::Confirmed,
        None,
        5,
    );
    event.sequence = 2;
    let mut json = serde_json::to_value(&event).expect("encode");
    json.as_object_mut()
        .expect("object")
        .remove("realized_fill");
    let decoded: OrderAttemptEvent = serde_json::from_value(json).expect("legacy decode");
    assert_eq!(decoded.phase, AttemptPhase::Confirmed);
    assert!(decoded.realized_fill.is_none());
    decoded.validate().expect("legacy record validates");
}
