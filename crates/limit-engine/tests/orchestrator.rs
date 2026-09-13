//! P51 — deterministic limit-order orchestrator tick.
//!
//! Every test drives the real `DurableLimitOrderStore` over the in-memory
//! `OpaqueStore` fake with a deterministic, clock-free quote provider and a
//! scripted fake execution seam. No live signer, chain, or database is involved.

mod support;

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderId, OrderStatus, OrderType, RouteLeg, RoutePlan,
    TaxObservation, TradeIntent, TradeSource, WalletRef,
};
use execution_preview::{AllowanceObservation, NetDelta, RevalidationReason, WalletBalance};
use limit_engine::{
    attempt_intent_id, attempt_key, attempt_prepared_reference, conservation_holds,
    AttemptExecutor, AttemptLimits, AttemptPhase, AttemptResolution, BoundAttempt,
    DurableLimitOrderStore, LimitEngineError, LimitOrderStore, Orchestrator, PreparedAttempt,
    QuoteOutcome, QuoteProvider, RealizedFill, StoredLimitOrder, TickInput, TickOutcome,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use tax_engine::TaxAssessment;

use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

const NOW: i64 = 100_000;
const NET_OUTPUT: u128 = 240;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
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

/// Synthetic economics a provider reports for one probe.
#[derive(Clone, Copy)]
struct QuotePlan {
    net_output: u128,
    gross_output: u128,
    tax: Option<u128>,
    buy_tax_bps: u16,
    /// When set, the route snapshot is dated at this instant instead of `now_ms`.
    route_observed_at_ms: Option<i64>,
}

fn fresh_plan() -> QuotePlan {
    QuotePlan {
        net_output: NET_OUTPUT,
        gross_output: NET_OUTPUT,
        tax: None,
        buy_tax_bps: 0,
        route_observed_at_ms: None,
    }
}

/// Deterministic, injected quote provider keyed by call ordinal.
struct ModelProvider {
    plan: Box<dyn Fn(u64) -> Option<QuotePlan> + Send + Sync>,
    calls: AtomicU64,
}

impl ModelProvider {
    fn new(plan: impl Fn(u64) -> Option<QuotePlan> + Send + Sync + 'static) -> Self {
        Self {
            plan: Box::new(plan),
            calls: AtomicU64::new(0),
        }
    }
}

impl QuoteProvider for ModelProvider {
    fn quote(
        &self,
        order: &StoredLimitOrder,
        amount_in: AtomicAmount,
        now_ms: i64,
    ) -> QuoteOutcome {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        match (self.plan)(call) {
            None => QuoteOutcome::Unavailable,
            Some(plan) => QuoteOutcome::Quoted(Box::new(build_attempt(
                order,
                amount_in.get(),
                plan,
                now_ms,
            ))),
        }
    }
}

/// Constant 240 net-output, zero-tax, always-fresh provider.
fn constant_provider() -> ModelProvider {
    ModelProvider::new(|_call| Some(fresh_plan()))
}

/// Provider that cannot quote any chunk.
fn unavailable_provider() -> ModelProvider {
    ModelProvider::new(|_call| None)
}

/// Provider that is fresh for the trigger probe but stale for the re-quote.
fn stale_on_requote_provider() -> ModelProvider {
    ModelProvider::new(|call| {
        Some(if call == 0 {
            fresh_plan()
        } else {
            QuotePlan {
                route_observed_at_ms: Some(NOW - 20_000),
                ..fresh_plan()
            }
        })
    })
}

/// Copies `tests/trigger.rs::build_attempt` (do not reference that test binary).
fn build_attempt(
    order: &StoredLimitOrder,
    amount: u128,
    plan: QuotePlan,
    now_ms: i64,
) -> limit_engine::QuotedAttempt {
    let token_in = order.order.token_in.clone();
    let token_out = order.order.token_out.clone();
    let observed_at_ms = plan.route_observed_at_ms.unwrap_or(now_ms);
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
            amount: AtomicAmount::new(plan.gross_output),
        },
        net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(plan.net_output),
        },
        dex_fee: None,
        tax_cost: plan.tax.map(|t| AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(t),
        }),
    };
    let route = RoutePlan {
        legs: vec![RouteLeg {
            venue: "synthetic".to_string(),
            pool_ref: "pool-1".to_string(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(amount),
            expected_amount_out: AtomicAmount::new(plan.gross_output),
        }],
        expected_net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(plan.net_output),
        },
        state: Freshness {
            observed_at_ms,
            chain_height: 1,
            sequence: Sequence(1),
        },
    };
    let assessment = TaxAssessment::new(
        token_out,
        order.order.chain.clone(),
        Bps::new(plan.buy_tax_bps).expect("buy tax"),
        Bps::new(0).expect("sell tax"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms,
            evaluated_at_ms: observed_at_ms,
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

fn trust(now_ms: i64) -> limit_engine::AttemptTrust {
    limit_engine::AttemptTrust {
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

/// Assertion handles shared with the fake executor.
#[derive(Clone)]
struct ExecutorHandles {
    calls: Arc<AtomicU64>,
    prepared_calls: Arc<AtomicU64>,
    recorded: Arc<Mutex<Vec<BoundAttempt>>>,
    reserved_before_execute: Arc<AtomicBool>,
    attempt_events_at_execute: Arc<AtomicU64>,
}

/// Scripted fake execution seam. Never signs; records the durable binding it
/// was handed and verifies the reserve-before-sign WAL is already durable.
struct FakeExecutor {
    digest: Result<[u8; 32], LimitEngineError>,
    calls: Arc<AtomicU64>,
    prepared_calls: Arc<AtomicU64>,
    resolutions: Arc<Mutex<VecDeque<AttemptResolution>>>,
    recorded: Arc<Mutex<Vec<BoundAttempt>>>,
    reserved_before_execute: Arc<AtomicBool>,
    attempt_events_at_execute: Arc<AtomicU64>,
    backend: Arc<InMemoryOpaqueStore>,
    keys: Arc<TestOrderKeys>,
    order_id: OrderId,
}

impl FakeExecutor {
    fn new(
        resolutions: Vec<AttemptResolution>,
        backend: Arc<InMemoryOpaqueStore>,
        keys: Arc<TestOrderKeys>,
        order_id: OrderId,
    ) -> (Self, ExecutorHandles) {
        let calls = Arc::new(AtomicU64::new(0));
        let prepared_calls = Arc::new(AtomicU64::new(0));
        let resolutions = Arc::new(Mutex::new(VecDeque::from(resolutions)));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let reserved_before_execute = Arc::new(AtomicBool::new(false));
        let attempt_events_at_execute = Arc::new(AtomicU64::new(0));
        let handles = ExecutorHandles {
            calls: calls.clone(),
            prepared_calls: prepared_calls.clone(),
            recorded: recorded.clone(),
            reserved_before_execute: reserved_before_execute.clone(),
            attempt_events_at_execute: attempt_events_at_execute.clone(),
        };
        (
            Self {
                digest: Ok([0xAB; 32]),
                calls,
                prepared_calls,
                resolutions,
                recorded,
                reserved_before_execute,
                attempt_events_at_execute,
                backend,
                keys,
                order_id,
            },
            handles,
        )
    }

    /// Overrides the digest the fake seam reports (success, zero, or error).
    fn with_digest(mut self, digest: Result<[u8; 32], LimitEngineError>) -> Self {
        self.digest = digest;
        self
    }
}

#[async_trait]
impl AttemptExecutor for FakeExecutor {
    async fn payload_digest(&self, _intent: &TradeIntent) -> Result<[u8; 32], LimitEngineError> {
        self.digest
    }

    async fn execute(
        &self,
        _prepared: &PreparedAttempt,
        attempt: &BoundAttempt,
        _now_ms: i64,
    ) -> AttemptResolution {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.prepared_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.recorded).push(attempt.clone());

        // Read the real durable attempt stream at execute time: the `Bound`
        // event must already be there (OR-1).
        let store =
            DurableLimitOrderStore::new(self.backend.clone(), self.keys.clone(), ChainId::Base);
        let events = store
            .read_attempts(&self.order_id)
            .await
            .expect("read attempts at execute");
        let reserved = events.iter().any(|event| {
            event.phase == AttemptPhase::Bound && event.attempt_seq == attempt.attempt_seq
        });
        self.reserved_before_execute
            .store(reserved, Ordering::SeqCst);
        self.attempt_events_at_execute
            .store(events.len() as u64, Ordering::SeqCst);

        lock(&self.resolutions)
            .pop_front()
            .expect("scripted resolution")
    }
}

/// Order shape for a harness fixture.
struct OrderSpec<'a> {
    creation: &'a str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
    expires_at_ms: i64,
}

impl<'a> OrderSpec<'a> {
    fn new(
        creation: &'a str,
        status: OrderStatus,
        max: u128,
        remaining: u128,
        filled: u128,
    ) -> Self {
        Self {
            creation,
            status,
            max,
            remaining,
            filled,
            expires_at_ms: support::EXPIRY_MS,
        }
    }

    fn with_expiry(mut self, expires_at_ms: i64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }
}

struct Harness {
    backend: Arc<InMemoryOpaqueStore>,
    keys: Arc<TestOrderKeys>,
    order_id: OrderId,
    reader: DurableLimitOrderStore<InMemoryOpaqueStore>,
    handles: ExecutorHandles,
    orchestrator: Orchestrator<InMemoryOpaqueStore, ModelProvider, FakeExecutor>,
}

async fn harness(
    spec: OrderSpec<'_>,
    resolutions: Vec<AttemptResolution>,
    provider: ModelProvider,
    enabled: bool,
    max_attempts: u32,
) -> Harness {
    harness_with_digest(
        spec,
        resolutions,
        provider,
        enabled,
        max_attempts,
        Ok([0xAB; 32]),
    )
    .await
}

async fn harness_with_digest(
    spec: OrderSpec<'_>,
    resolutions: Vec<AttemptResolution>,
    provider: ModelProvider,
    enabled: bool,
    max_attempts: u32,
    digest: Result<[u8; 32], LimitEngineError>,
) -> Harness {
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
    // BUY limit 100/24: chunk 1000 with 240 net output is exactly executable.
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let order_id = order.order.id.clone();
    let reader = durable_store(&backend, &keys);
    reader.create(order).await.expect("create order");
    let (executor, handles) =
        FakeExecutor::new(resolutions, backend.clone(), keys.clone(), order_id.clone());
    let orchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        provider,
        executor.with_digest(digest),
        policy(enabled),
        AttemptLimits {
            max_attempts_per_order: max_attempts,
        },
    );
    Harness {
        backend,
        keys,
        order_id,
        reader,
        handles,
        orchestrator,
    }
}

async fn tick(harness: &Harness, signal: bool) -> Result<TickOutcome, LimitEngineError> {
    let trust = trust(NOW);
    harness
        .orchestrator
        .tick(TickInput {
            order_id: &harness.order_id,
            signal,
            source: TradeSource::Web,
            trust: &trust,
            now_ms: NOW,
        })
        .await
}

async fn load(harness: &Harness) -> StoredLimitOrder {
    harness
        .reader
        .load(&harness.order_id)
        .await
        .expect("load")
        .expect("order present")
}

async fn attempts(harness: &Harness) -> Vec<limit_engine::OrderAttemptEvent> {
    harness
        .reader
        .read_attempts(&harness.order_id)
        .await
        .expect("read attempts")
}

fn realized(input: u128, output: u128) -> AttemptResolution {
    AttemptResolution::Filled(RealizedFill {
        net_input: AtomicAmount::new(input),
        net_output: AtomicAmount::new(output),
    })
}

#[tokio::test]
async fn happy_path_fills_and_persists_bound_before_execute() {
    let h = harness(
        OrderSpec::new("p51-happy", OrderStatus::Active, 1000, 1000, 0),
        vec![realized(1000, 240)],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Filled { attempt_seq: 1, .. }),
        "got {outcome:?}"
    );

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), 1000);
    assert_eq!(stored.order.remaining_input.get(), 0);

    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|event| (event.attempt_seq, event.phase))
            .collect::<Vec<_>>(),
        vec![(1, AttemptPhase::Bound), (1, AttemptPhase::Confirmed)]
    );

    let bound = events[0].bound.clone().expect("bound context");
    let blind = h.keys.blind_key();
    assert_eq!(
        bound.intent.id,
        attempt_intent_id(&blind, &ChainId::Base, &h.order_id, 1).expect("intent id")
    );
    assert_eq!(
        bound.intent.idempotency_key,
        attempt_key(&blind, &ChainId::Base, &h.order_id, 1).expect("attempt key")
    );
    assert_eq!(bound.attempt_key, bound.intent.idempotency_key);
    assert_eq!(
        bound.prepared_reference,
        attempt_prepared_reference(&blind, &ChainId::Base, &h.order_id, 1).expect("reference")
    );
    assert_eq!(bound.intent.amount.get(), 1000);
    assert_eq!(bound.nonce, 1);
    assert_eq!(bound.payload_digest, [0xAB; 32]);

    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.handles.prepared_calls.load(Ordering::SeqCst), 1);
    assert!(
        h.handles.reserved_before_execute.load(Ordering::SeqCst),
        "the Bound event must be durable before execute runs"
    );
    assert_eq!(
        h.handles.attempt_events_at_execute.load(Ordering::SeqCst),
        1
    );
    let recorded = lock(&h.handles.recorded);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].intent.amount.get(), 1000);
}

#[tokio::test]
async fn payload_digest_error_reverts_to_active_without_attempt() {
    // A failing digest must be resolved *before* the `Quoting -> Simulating ->
    // Executing` chain is durably persisted, so the order cannot wedge in
    // `Executing` with no `Bound` WAL. The `TriggerCandidate` state the trigger
    // persisted is reverted to `Active`.
    let h = harness_with_digest(
        OrderSpec::new("p51-digest-err", OrderStatus::Active, 1000, 1000, 0),
        vec![realized(1000, 240)],
        constant_provider(),
        true,
        4,
        Err(LimitEngineError::KeyUnavailable),
    )
    .await;

    let outcome = tick(&h, true).await;
    assert_eq!(outcome.err(), Some(LimitEngineError::KeyUnavailable));

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Active);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn zero_payload_digest_reverts_to_active_without_attempt() {
    // A zero digest is an un-bindable payload: fail `RecordMalformed` before the
    // execution chain is persisted, reverting to `Active`.
    let h = harness_with_digest(
        OrderSpec::new("p51-digest-zero", OrderStatus::Active, 1000, 1000, 0),
        vec![realized(1000, 240)],
        constant_provider(),
        true,
        4,
        Ok([0u8; 32]),
    )
    .await;

    let outcome = tick(&h, true).await;
    assert_eq!(outcome.err(), Some(LimitEngineError::RecordMalformed));

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Active);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn partial_fill_leaves_viable_remainder_then_completes() {
    let h = harness(
        OrderSpec::new("p51-partial", OrderStatus::Active, 2000, 2000, 0),
        vec![realized(1000, 240), realized(1000, 240)],
        constant_provider(),
        true,
        4,
    )
    .await;

    let first = tick(&h, true).await.expect("tick 1");
    match &first {
        TickOutcome::PartiallyFilled {
            attempt_seq,
            realized,
            remaining,
        } => {
            assert_eq!(*attempt_seq, 1);
            assert_eq!(realized.net_input.get(), 1000);
            assert_eq!(realized.net_output.get(), 240);
            assert_eq!(remaining.get(), 1000);
        }
        other => panic!("expected PartiallyFilled, got {other:?}"),
    }
    let after_first = load(&h).await;
    assert_eq!(after_first.order.status, OrderStatus::PartiallyFilled);
    assert_eq!(after_first.filled_input.get(), 1000);
    assert_eq!(after_first.order.remaining_input.get(), 1000);
    assert!(conservation_holds(&after_first));

    let second = tick(&h, true).await.expect("tick 2");
    assert!(
        matches!(&second, TickOutcome::Filled { attempt_seq: 2, .. }),
        "got {second:?}"
    );

    let events = attempts(&h).await;
    assert_eq!(
        events
            .iter()
            .map(|event| (event.attempt_seq, event.phase))
            .collect::<Vec<_>>(),
        vec![
            (1, AttemptPhase::Bound),
            (1, AttemptPhase::Confirmed),
            (2, AttemptPhase::Bound),
            (2, AttemptPhase::Confirmed),
        ]
    );
    let after_second = load(&h).await;
    assert_eq!(after_second.order.status, OrderStatus::Filled);
    assert_eq!(after_second.filled_input.get(), 2000);
    assert_eq!(after_second.order.remaining_input.get(), 0);
    assert!(conservation_holds(&after_second));
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_is_in_flight_and_never_re_executed() {
    let h = harness(
        OrderSpec::new("p51-unknown", OrderStatus::Active, 1000, 1000, 0),
        vec![AttemptResolution::Unknown],
        constant_provider(),
        true,
        4,
    )
    .await;

    let first = tick(&h, true).await.expect("tick 1");
    assert!(
        matches!(&first, TickOutcome::InFlight { attempt_seq: 1 }),
        "got {first:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);

    let second = tick(&h, true).await.expect("tick 2");
    assert!(
        matches!(&second, TickOutcome::InFlight { attempt_seq: 1 }),
        "got {second:?}"
    );
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 1);

    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].phase, AttemptPhase::Unknown);
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);
}

#[tokio::test]
async fn failed_before_submit_is_bounded_and_then_final() {
    let h = harness(
        OrderSpec::new("p51-retry", OrderStatus::Active, 1000, 1000, 0),
        vec![
            AttemptResolution::FailedBeforeSubmit,
            AttemptResolution::FailedBeforeSubmit,
        ],
        constant_provider(),
        true,
        2,
    )
    .await;

    let first = tick(&h, true).await.expect("tick 1");
    assert!(
        matches!(
            &first,
            TickOutcome::FailedBeforeSubmit {
                attempt_seq: 1,
                retryable: true
            }
        ),
        "got {first:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedRetryable);

    let second = tick(&h, true).await.expect("tick 2");
    assert!(
        matches!(
            &second,
            TickOutcome::FailedBeforeSubmit {
                attempt_seq: 2,
                retryable: false
            }
        ),
        "got {second:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedFinal);

    let third = tick(&h, true).await.expect("tick 3");
    assert!(
        matches!(
            &third,
            TickOutcome::Terminal {
                status: OrderStatus::FailedFinal
            }
        ),
        "got {third:?}"
    );
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rejected_is_final() {
    let h = harness(
        OrderSpec::new("p51-rejected", OrderStatus::Active, 1000, 1000, 0),
        vec![AttemptResolution::Rejected],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Rejected { attempt_seq: 1 }),
        "got {outcome:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedFinal);

    let events = attempts(&h).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].phase, AttemptPhase::Rejected);
}

#[tokio::test]
async fn realized_fill_violating_min_out_fails_final_without_applying() {
    let h = harness(
        OrderSpec::new("p51-violation", OrderStatus::Active, 1000, 1000, 0),
        vec![realized(1000, 239)],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Violation { attempt_seq: 1 }),
        "got {outcome:?}"
    );

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedFinal);
    assert_eq!(stored.filled_input.get(), 0);
    assert_eq!(stored.order.remaining_input.get(), 1000);
}

#[tokio::test]
async fn expired_order_is_terminal_without_executor() {
    let h = harness(
        OrderSpec::new("p51-expired", OrderStatus::Active, 1000, 1000, 0).with_expiry(NOW - 1),
        vec![],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(
            &outcome,
            TickOutcome::Terminal {
                status: OrderStatus::Expired
            }
        ),
        "got {outcome:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::Expired);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn expired_crash_left_order_terminates_without_executor() {
    // A crash-left pre-sign order past its deadline must become a persisted
    // `Expired` terminal, never wedge the tick in `Err(Expired)`.
    for status in [
        OrderStatus::Created,
        OrderStatus::Quoting,
        OrderStatus::Simulating,
    ] {
        let h = harness(
            OrderSpec::new("p51-expired-crash", status, 1000, 1000, 0).with_expiry(NOW - 1),
            vec![],
            constant_provider(),
            true,
            4,
        )
        .await;

        let outcome = tick(&h, true).await.expect("tick");
        assert!(
            matches!(
                &outcome,
                TickOutcome::Terminal {
                    status: OrderStatus::Expired
                }
            ),
            "got {outcome:?} for {status:?}"
        );
        assert_eq!(load(&h).await.order.status, OrderStatus::Expired);
        assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
        assert!(attempts(&h).await.is_empty());
    }
}

#[tokio::test]
async fn no_signal_leaves_order_active() {
    let h = harness(
        OrderSpec::new("p51-nosignal", OrderStatus::Active, 1000, 1000, 0),
        vec![],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, false).await.expect("tick");
    assert!(matches!(&outcome, TickOutcome::NoSignal), "got {outcome:?}");

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Active);
    assert_eq!(stored.version, 1);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn not_executable_stays_active() {
    let h = harness(
        OrderSpec::new("p51-notexec", OrderStatus::Active, 1000, 1000, 0),
        vec![],
        unavailable_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::NotExecutable),
        "got {outcome:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::Active);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn stale_route_requotes_and_reverts_to_active() {
    let h = harness(
        OrderSpec::new("p51-requote", OrderStatus::Active, 1000, 1000, 0),
        vec![],
        stale_on_requote_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(
            &outcome,
            TickOutcome::Requote(RevalidationReason::StaleState)
        ),
        "got {outcome:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::Active);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn trading_disabled_is_policy_rejected_without_attempt() {
    let h = harness(
        OrderSpec::new("p51-disabled", OrderStatus::Active, 1000, 1000, 0),
        vec![realized(1000, 240)],
        constant_provider(),
        false,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::PolicyRejected),
        "got {outcome:?}"
    );
    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Active);
    assert_eq!(stored.version, 1);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
    assert!(h.backend.event_attempts().is_empty());

    // A disabled gate must leave a crash-left pre-sign state untouched too:
    // normalization is an execution-path write and must not run.
    for status in [OrderStatus::Created, OrderStatus::Quoting] {
        let h = harness(
            OrderSpec::new("p51-disabled-crash", status, 1000, 1000, 0),
            vec![],
            constant_provider(),
            false,
            4,
        )
        .await;
        let outcome = tick(&h, true).await.expect("tick");
        assert!(
            matches!(&outcome, TickOutcome::PolicyRejected),
            "got {outcome:?}"
        );
        let stored = load(&h).await;
        assert_eq!(stored.order.status, status);
        assert_eq!(stored.version, 1);
        assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
        assert!(h.backend.event_attempts().is_empty());
    }

    // A disabled gate must NOT mask an already-reserved in-flight attempt: the
    // `Executing` check runs first, so the tick reports `InFlight` and writes
    // nothing.
    let h = harness(
        OrderSpec::new(
            "p51-disabled-executing",
            OrderStatus::Executing,
            1000,
            1000,
            0,
        ),
        vec![],
        constant_provider(),
        false,
        4,
    )
    .await;
    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::InFlight { attempt_seq: 0 }),
        "got {outcome:?}"
    );
    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Executing);
    assert_eq!(stored.version, 1);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(h.backend.event_attempts().is_empty());
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn terminal_order_is_terminal() {
    let h = harness(
        OrderSpec::new("p51-terminal", OrderStatus::Filled, 1000, 0, 1000),
        vec![],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(
            &outcome,
            TickOutcome::Terminal {
                status: OrderStatus::Filled
            }
        ),
        "got {outcome:?}"
    );
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn executing_order_is_in_flight() {
    let h = harness(
        OrderSpec::new("p51-executing", OrderStatus::Executing, 1000, 1000, 0),
        vec![],
        constant_provider(),
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::InFlight { attempt_seq: 0 }),
        "got {outcome:?}"
    );
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    assert!(attempts(&h).await.is_empty());
}

#[tokio::test]
async fn second_attempt_has_new_identity() {
    let h = harness(
        OrderSpec::new("p51-identity", OrderStatus::Active, 2000, 2000, 0),
        vec![realized(1000, 240), realized(1000, 240)],
        constant_provider(),
        true,
        4,
    )
    .await;

    tick(&h, true).await.expect("tick 1");
    tick(&h, true).await.expect("tick 2");

    let recorded = lock(&h.handles.recorded);
    assert_eq!(recorded.len(), 2);
    let blind = h.keys.blind_key();

    assert_eq!(
        recorded[0].intent.id,
        attempt_intent_id(&blind, &ChainId::Base, &h.order_id, 1).expect("intent 1")
    );
    assert_eq!(
        recorded[1].intent.id,
        attempt_intent_id(&blind, &ChainId::Base, &h.order_id, 2).expect("intent 2")
    );
    assert_eq!(
        recorded[0].attempt_key,
        attempt_key(&blind, &ChainId::Base, &h.order_id, 1).expect("key 1")
    );
    assert_eq!(
        recorded[1].attempt_key,
        attempt_key(&blind, &ChainId::Base, &h.order_id, 2).expect("key 2")
    );
    assert_ne!(recorded[0].intent.id, recorded[1].intent.id);
    assert_ne!(recorded[0].attempt_key, recorded[1].attempt_key);
    assert_eq!(recorded[0].nonce, 1);
    assert_eq!(recorded[1].nonce, 2);
    assert_ne!(recorded[0].nonce, recorded[1].nonce);
}

#[tokio::test]
async fn debug_is_redacted() {
    let fill = RealizedFill {
        net_input: AtomicAmount::new(1000),
        net_output: AtomicAmount::new(240),
    };
    let rendered = format!("{fill:?}");
    assert_eq!(rendered, "RealizedFill { .. }");
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));

    let outcome = TickOutcome::Filled {
        attempt_seq: 1,
        realized: fill.clone(),
    };
    let rendered = format!("{outcome:?}");
    for needle in ["1000", "240", "USDC", "TOKEN"] {
        assert!(
            !rendered.contains(needle),
            "TickOutcome Debug leaked `{needle}`: {rendered}"
        );
    }
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));

    let resolution = AttemptResolution::Filled(fill);
    let rendered = format!("{resolution:?}");
    for needle in ["1000", "240", "USDC", "TOKEN"] {
        assert!(
            !rendered.contains(needle),
            "AttemptResolution Debug leaked `{needle}`: {rendered}"
        );
    }
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));
}
