//! P88 — actual-execution analytics wired into the realized-fill path.
//!
//! These tests exercise the pure [`limit_engine::fill_analytics`] mapping and
//! the observational sink seam on the real `DurableLimitOrderStore` over the
//! in-memory `OpaqueStore` fake, with a deterministic quote provider and a
//! scripted execution seam. No signer, chain, clock, or database is involved.
//!
//! The invariants under test:
//! - a compliant full or partial fill emits exactly one derived analytics record;
//! - a `Violation`, `Unknown`, `FailedBeforeSubmit`, `Rejected`, or a disabled
//!   kill switch never emits a record;
//! - recovery applies a sealed fill once and emits exactly one record, and a
//!   second recovery emits none;
//! - the mapped record and the sink types never render amounts.

mod support;

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use adaptive_exec::{Delta, DeltaDirection, ExecutionAnalytics};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, LimitPrice,
    OrderId, OrderStatus, OrderType, RiskConstraints, RouteLeg, RoutePlan, TaxObservation,
    TradeIntent, TradeSource, UserId, WalletRef,
};
use execution_preview::{AllowanceObservation, NetDelta, WalletBalance};
use limit_engine::{
    attempt_intent_id, attempt_key, attempt_prepared_reference, conservation_holds, fill_analytics,
    ApprovalSnapshot, AttemptExecutor, AttemptLimits, AttemptPhase, AttemptResolution,
    BoundAttempt, DurableLimitOrderStore, ExecutionAnalyticsSink, LimitEngineError,
    LimitOrderStore, NoopExecutionAnalyticsSink, Orchestrator, OrderAttemptEvent, PreparedAttempt,
    QuoteOutcome, QuoteProvider, RealizedFill, StoredLimitOrder, TickInput, TickOutcome,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use tax_engine::TaxAssessment;

use support::asset;
use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

const NOW: i64 = 100_000;
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

fn usdc() -> AssetId {
    asset("USDC")
}

fn token() -> AssetId {
    asset("TOKEN")
}

fn wallet_ref() -> WalletRef {
    WalletRef::new("w1").expect("wallet")
}

/// A recording sink: counts every record and stores the derivations.
#[derive(Default)]
struct RecordingSink {
    count: AtomicUsize,
    records: Mutex<Vec<ExecutionAnalytics>>,
}

impl RecordingSink {
    fn new() -> Self {
        Self::default()
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn records(&self) -> Vec<ExecutionAnalytics> {
        lock(&self.records).clone()
    }
}

impl ExecutionAnalyticsSink for RecordingSink {
    fn record(&self, analytics: &ExecutionAnalytics) {
        self.count.fetch_add(1, Ordering::SeqCst);
        lock(&self.records).push(*analytics);
    }
}

// ---------------------------------------------------------------------------
// Pure mapping unit vectors.
// ---------------------------------------------------------------------------

fn mapping_intent(amount: u128) -> TradeIntent {
    let token_in = usdc();
    let token_out = token();
    TradeIntent {
        id: IntentId::new("intent-p88").expect("intent id"),
        source: TradeSource::Web,
        user_id: UserId::new("u1").expect("user"),
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: domain::TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
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
        expiry_ms: Some(support::EXPIRY_MS),
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-p88").expect("idempotency key"),
    }
}

/// A bound attempt whose preview carries `net_in`/`net_out` but whose asset
/// fields are supplied explicitly (so binding can be probed).
fn bound_with(
    net_in: u128,
    net_out: u128,
    preview_in: AssetId,
    preview_out: AssetId,
) -> BoundAttempt {
    let intent = mapping_intent(net_in);
    BoundAttempt {
        route: RoutePlan {
            legs: vec![RouteLeg {
                venue: "synthetic".to_string(),
                pool_ref: "pool-1".to_string(),
                token_in: intent.token_in.clone(),
                token_out: intent.token_out.clone(),
                amount_in: AtomicAmount::new(net_in),
                expected_amount_out: AtomicAmount::new(net_out),
            }],
            expected_net_output: AssetAmount {
                asset: intent.token_out.clone(),
                amount: AtomicAmount::new(net_out),
            },
            state: Freshness {
                observed_at_ms: NOW - 1_000,
                chain_height: 10,
                sequence: Sequence(1),
            },
        },
        preview: ExecutionPreview {
            intent_id: intent.id.clone(),
            chain: ChainId::Base,
            token_in: intent.token_in.clone(),
            token_out: intent.token_out.clone(),
            side: domain::TradeSide::Buy,
            simulated_net_input: AssetAmount {
                asset: preview_in,
                amount: AtomicAmount::new(net_in),
            },
            simulated_net_output: AssetAmount {
                asset: preview_out,
                amount: AtomicAmount::new(net_out),
            },
            gross_output: AssetAmount {
                asset: intent.token_out.clone(),
                amount: AtomicAmount::new(net_out),
            },
            cost_components: ExecutionCostComponents::default(),
            local_state_freshness: FreshnessStatus::Fresh,
        },
        approval: ApprovalSnapshot {
            intent_id: intent.id.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: ChainId::Base,
            idempotency_key: intent.idempotency_key.clone(),
            expires_at_ms: Some(support::EXPIRY_MS),
            approved_trade_usd: 500_000,
            approved_at_ms: 1,
        },
        prepared_reference: "prepared-p88".to_string(),
        payload_digest: [0xAB; 32],
        attempt_key: intent.idempotency_key.clone(),
        attempt_seq: 1,
        nonce: 1,
        intent,
    }
}

fn bound_fixture(net_in: u128, net_out: u128) -> BoundAttempt {
    bound_with(net_in, net_out, usdc(), token())
}

fn realized_fill(net_in: u128, net_out: u128) -> RealizedFill {
    RealizedFill {
        net_input: AtomicAmount::new(net_in),
        net_output: AtomicAmount::new(net_out),
    }
}

#[test]
fn mapping_exact_full_fill_is_zero_deviation() {
    let bound = bound_fixture(1_000, 250);
    let fill = realized_fill(1_000, 250);

    let analytics = fill_analytics(&bound, &fill).expect("defined comparison");

    assert_eq!(analytics.output_deviation_bps, 0);
    assert_eq!(analytics.output_direction, DeltaDirection::Exact);
    assert_eq!(
        analytics.input_delta,
        Delta {
            direction: DeltaDirection::Exact,
            magnitude: 0,
        }
    );
    assert_eq!(analytics.gas_delta, None);
    assert_eq!(analytics.tax_delta, None);
}

#[test]
fn mapping_partial_fill_worse_output_is_expected_bps() {
    // expected 250, realized 240: |10| / 250 == 400 bps worse.
    let bound = bound_fixture(1_000, 250);
    let fill = realized_fill(1_000, 240);

    let analytics = fill_analytics(&bound, &fill).expect("defined comparison");

    assert_eq!(analytics.output_deviation_bps, 400);
    assert_eq!(analytics.output_direction, DeltaDirection::RealizedWorse);
    assert_eq!(analytics.input_delta.direction, DeltaDirection::Exact);
}

#[test]
fn mapping_better_output_is_expected_bps() {
    // expected 250, realized 260: |10| / 250 == 400 bps better.
    let bound = bound_fixture(1_000, 250);
    let fill = realized_fill(1_000, 260);

    let analytics = fill_analytics(&bound, &fill).expect("defined comparison");

    assert_eq!(analytics.output_deviation_bps, 400);
    assert_eq!(analytics.output_direction, DeltaDirection::RealizedBetter);
}

#[test]
fn mapping_records_input_delta_magnitude() {
    // Spending 100 more than the estimate is worse by 100 atomic units.
    let bound = bound_fixture(1_000, 250);
    let fill = realized_fill(1_100, 250);

    let analytics = fill_analytics(&bound, &fill).expect("defined comparison");

    assert_eq!(
        analytics.input_delta.direction,
        DeltaDirection::RealizedWorse
    );
    assert_eq!(analytics.input_delta.magnitude, 100);
    assert_eq!(analytics.output_deviation_bps, 0);
}

#[test]
fn mapping_zero_expected_output_returns_none_without_panic() {
    let bound = bound_fixture(1_000, 0);
    let fill = realized_fill(1_000, 0);

    assert_eq!(fill_analytics(&bound, &fill), None);
}

#[test]
fn mapping_binds_to_intent_assets_not_preview_assets() {
    // The preview deliberately names a different asset pair; because both the
    // estimate and the realized sides bind to the intent's pair, the comparison
    // is still defined. A mapping that read the preview assets would mismatch
    // and return `None`.
    let bound = bound_with(1_000, 250, asset("DAI"), asset("WETH"));
    let fill = realized_fill(1_000, 250);

    let analytics = fill_analytics(&bound, &fill).expect("intent assets bind");

    assert_eq!(analytics.output_deviation_bps, 0);
    assert_eq!(analytics.output_direction, DeltaDirection::Exact);
}

#[test]
fn new_types_debug_do_not_render_amounts() {
    let noop = format!("{NoopExecutionAnalyticsSink:?}");
    assert_eq!(noop, "NoopExecutionAnalyticsSink");

    let bound = bound_fixture(123_456_789, 987_654);
    let fill = realized_fill(123_456_789, 987_654);
    let analytics = fill_analytics(&bound, &fill).expect("defined comparison");
    let rendered = format!("{analytics:?}");

    for needle in ["123456789", "987654"] {
        assert!(
            !rendered.contains(needle),
            "analytics Debug leaked `{needle}`: {rendered}"
        );
    }
    assert!(
        rendered.contains("<redacted>"),
        "delta magnitude should be redacted: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Orchestrator integration harness.
// ---------------------------------------------------------------------------

fn freshness(observed_at_ms: i64) -> Freshness {
    Freshness {
        observed_at_ms,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

#[derive(Clone, Copy)]
struct QuotePlan {
    net_output: u128,
    gross_output: u128,
    tax: Option<u128>,
    buy_tax_bps: u16,
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

fn constant_provider() -> ModelProvider {
    ModelProvider::new(|_call| Some(fresh_plan()))
}

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

/// Scripted fake execution seam. Never signs; counts calls and pops resolutions.
struct FakeExecutor {
    calls: Arc<AtomicU64>,
    resolutions: Arc<Mutex<VecDeque<AttemptResolution>>>,
    recorded: Arc<Mutex<Vec<BoundAttempt>>>,
}

#[derive(Clone)]
struct ExecutorHandles {
    calls: Arc<AtomicU64>,
    recorded: Arc<Mutex<Vec<BoundAttempt>>>,
}

impl FakeExecutor {
    fn new(resolutions: Vec<AttemptResolution>) -> (Self, ExecutorHandles) {
        let calls = Arc::new(AtomicU64::new(0));
        let resolutions = Arc::new(Mutex::new(VecDeque::from(resolutions)));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let handles = ExecutorHandles {
            calls: calls.clone(),
            recorded: recorded.clone(),
        };
        (
            Self {
                calls,
                resolutions,
                recorded,
            },
            handles,
        )
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
        attempt: &BoundAttempt,
        _now_ms: i64,
    ) -> AttemptResolution {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.recorded).push(attempt.clone());
        lock(&self.resolutions)
            .pop_front()
            .expect("scripted resolution")
    }

    async fn reconcile(&self, _attempt: &BoundAttempt, _now_ms: i64) -> AttemptResolution {
        AttemptResolution::Unknown
    }
}

struct OrderSpec<'a> {
    creation: &'a str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
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
        }
    }
}

struct Harness {
    keys: Arc<TestOrderKeys>,
    order_id: OrderId,
    reader: DurableLimitOrderStore<InMemoryOpaqueStore>,
    handles: ExecutorHandles,
    sink: Arc<RecordingSink>,
    orchestrator: Orchestrator<InMemoryOpaqueStore, ModelProvider, FakeExecutor>,
}

async fn harness_opts(
    spec: OrderSpec<'_>,
    resolutions: Vec<AttemptResolution>,
    enabled: bool,
    max_attempts: u32,
    attach_sink: bool,
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
    // BUY limit 100/24: chunk 1000 with 240 net output is exactly executable.
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let order_id = order.order.id.clone();
    let reader = durable_store(&backend, &keys);
    reader.create(order).await.expect("create order");

    let (executor, handles) = FakeExecutor::new(resolutions);
    let sink = Arc::new(RecordingSink::new());
    let mut orchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        constant_provider(),
        executor,
        policy(enabled),
        AttemptLimits {
            max_attempts_per_order: max_attempts,
        },
    );
    if attach_sink {
        orchestrator = orchestrator.with_analytics_sink(Some(sink.clone()));
    }
    Harness {
        keys,
        order_id,
        reader,
        handles,
        sink,
        orchestrator,
    }
}

async fn harness(
    spec: OrderSpec<'_>,
    resolutions: Vec<AttemptResolution>,
    enabled: bool,
    max_attempts: u32,
) -> Harness {
    harness_opts(spec, resolutions, enabled, max_attempts, true).await
}

async fn load(h: &Harness) -> StoredLimitOrder {
    h.reader
        .load(&h.order_id)
        .await
        .expect("load")
        .expect("order present")
}

async fn attempts(h: &Harness) -> Vec<OrderAttemptEvent> {
    h.reader
        .read_attempts(&h.order_id)
        .await
        .expect("read attempts")
}

async fn tick(h: &Harness, signal: bool) -> Result<TickOutcome, LimitEngineError> {
    let trust = trust(NOW);
    h.orchestrator
        .tick(TickInput {
            order_id: &h.order_id,
            signal,
            source: TradeSource::Web,
            trust: &trust,
            now_ms: NOW,
        })
        .await
}

// ---------------------------------------------------------------------------
// Recovery fixture helpers.
// ---------------------------------------------------------------------------

fn recovery_intent(keys: &TestOrderKeys, order_id: &OrderId, attempt_seq: u64) -> TradeIntent {
    let token_in = usdc();
    let token_out = token();
    TradeIntent {
        id: attempt_intent_id(&keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("intent id"),
        source: TradeSource::Web,
        user_id: UserId::new("u1").expect("user"),
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: domain::TradeSide::Buy,
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
        expiry_ms: Some(support::EXPIRY_MS),
        nonce: attempt_seq,
        idempotency_key: attempt_key(&keys.blind_key(), &ChainId::Base, order_id, attempt_seq)
            .expect("attempt key"),
    }
}

fn recovery_bound(keys: &TestOrderKeys, order_id: &OrderId, attempt_seq: u64) -> BoundAttempt {
    let intent = recovery_intent(keys, order_id, attempt_seq);
    BoundAttempt {
        route: RoutePlan {
            legs: vec![RouteLeg {
                venue: "synthetic".to_string(),
                pool_ref: "pool-1".to_string(),
                token_in: intent.token_in.clone(),
                token_out: intent.token_out.clone(),
                amount_in: AtomicAmount::new(CHUNK),
                expected_amount_out: AtomicAmount::new(NET_OUTPUT),
            }],
            expected_net_output: AssetAmount {
                asset: intent.token_out.clone(),
                amount: AtomicAmount::new(NET_OUTPUT),
            },
            state: Freshness {
                observed_at_ms: NOW - 1_000,
                chain_height: 10,
                sequence: Sequence(1),
            },
        },
        preview: ExecutionPreview {
            intent_id: intent.id.clone(),
            chain: ChainId::Base,
            token_in: intent.token_in.clone(),
            token_out: intent.token_out.clone(),
            side: domain::TradeSide::Buy,
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
        },
        approval: ApprovalSnapshot {
            intent_id: intent.id.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: ChainId::Base,
            idempotency_key: intent.idempotency_key.clone(),
            expires_at_ms: Some(support::EXPIRY_MS),
            approved_trade_usd: 500_000,
            approved_at_ms: 1,
        },
        prepared_reference: attempt_prepared_reference(
            &keys.blind_key(),
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

async fn append_bound(h: &Harness, attempt_seq: u64) {
    let event = OrderAttemptEvent::bound(
        recovery_bound(&h.keys, &h.order_id, attempt_seq),
        h.order_id.clone(),
        NOW,
    );
    h.reader.append_attempt(&event).await.expect("append bound");
}

async fn append_confirmed(h: &Harness, attempt_seq: u64, fill: RealizedFill) {
    let event = OrderAttemptEvent::confirmed(
        h.order_id.clone(),
        attempt_seq,
        attempt_key(
            &h.keys.blind_key(),
            &ChainId::Base,
            &h.order_id,
            attempt_seq,
        )
        .expect("attempt key"),
        fill,
        NOW,
    );
    h.reader
        .append_attempt(&event)
        .await
        .expect("append confirmed");
}

// ---------------------------------------------------------------------------
// Emission tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_fill_emits_exactly_one_record() {
    let h = harness(
        OrderSpec::new("p88-full", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Filled(realized_fill(CHUNK, NET_OUTPUT))],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Filled { attempt_seq: 1, .. }),
        "got {outcome:?}"
    );

    assert_eq!(h.sink.count(), 1, "one record per compliant full fill");
    let records = h.sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_deviation_bps, 0);
    assert_eq!(records[0].output_direction, DeltaDirection::Exact);
    assert_eq!(records[0].input_delta.direction, DeltaDirection::Exact);
    assert_eq!(records[0].gas_delta, None);
    assert_eq!(records[0].tax_delta, None);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), CHUNK);
    assert!(conservation_holds(&stored));

    // The record was derived from this attempt's exact bound estimate.
    let recorded = lock(&h.handles.recorded);
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].preview.simulated_net_output.amount.get(),
        NET_OUTPUT
    );
}

#[tokio::test]
async fn partial_fill_emits_exactly_one_record() {
    // Order has room for two chunks, so one compliant fill leaves a remainder.
    let h = harness(
        OrderSpec::new("p88-partial", OrderStatus::Active, 2_000, 2_000, 0),
        vec![AttemptResolution::Filled(realized_fill(CHUNK, NET_OUTPUT))],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(
            &outcome,
            TickOutcome::PartiallyFilled { attempt_seq: 1, .. }
        ),
        "got {outcome:?}"
    );

    assert_eq!(h.sink.count(), 1, "one record per compliant partial fill");
    assert_eq!(h.sink.records()[0].output_direction, DeltaDirection::Exact);

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::PartiallyFilled);
    assert_eq!(stored.filled_input.get(), CHUNK);
    assert_eq!(stored.order.remaining_input.get(), CHUNK);
}

#[tokio::test]
async fn no_sink_is_a_silent_noop() {
    // The default (no sink attached) must fill exactly as before and emit
    // nothing anywhere.
    let h = harness_opts(
        OrderSpec::new("p88-no-sink", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Filled(realized_fill(CHUNK, NET_OUTPUT))],
        true,
        4,
        false,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Filled { attempt_seq: 1, .. }),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::Filled);
}

#[tokio::test]
async fn violation_emits_no_record_and_mutates_no_ledger() {
    let h = harness(
        OrderSpec::new("p88-violation", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Filled(realized_fill(
            CHUNK,
            NET_OUTPUT - 1,
        ))],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Violation { attempt_seq: 1 }),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0, "a violation never emits analytics");

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::FailedFinal);
    assert_eq!(stored.filled_input.get(), 0);
    assert_eq!(stored.order.remaining_input.get(), CHUNK);
}

#[tokio::test]
async fn unknown_emits_no_record() {
    let h = harness(
        OrderSpec::new("p88-unknown", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Unknown],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::InFlight { attempt_seq: 1 }),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::Executing);
    assert_eq!(attempts(&h).await[1].phase, AttemptPhase::Unknown);
}

#[tokio::test]
async fn failed_before_submit_emits_no_record() {
    let h = harness(
        OrderSpec::new("p88-failed", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::FailedBeforeSubmit],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::FailedBeforeSubmit { .. }),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedRetryable);
}

#[tokio::test]
async fn rejected_emits_no_record() {
    let h = harness(
        OrderSpec::new("p88-rejected", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Rejected],
        true,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::Rejected { attempt_seq: 1 }),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0);
    assert_eq!(load(&h).await.order.status, OrderStatus::FailedFinal);
}

#[tokio::test]
async fn kill_switch_off_emits_no_record_and_calls_no_executor() {
    let h = harness(
        OrderSpec::new("p88-disabled", OrderStatus::Active, 1_000, 1_000, 0),
        vec![AttemptResolution::Filled(realized_fill(CHUNK, NET_OUTPUT))],
        false,
        4,
    )
    .await;

    let outcome = tick(&h, true).await.expect("tick");
    assert!(
        matches!(&outcome, TickOutcome::PolicyRejected),
        "got {outcome:?}"
    );
    assert_eq!(h.sink.count(), 0);
    assert_eq!(h.handles.calls.load(Ordering::SeqCst), 0);
    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Active);
    assert!(attempts(&h).await.is_empty());
}

// ---------------------------------------------------------------------------
// Recovery.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_applies_sealed_fill_once_and_emits_exactly_one() {
    let h = harness(
        OrderSpec::new("p88-recover", OrderStatus::Executing, 1_000, 1_000, 0),
        vec![],
        true,
        4,
    )
    .await;
    append_bound(&h, 1).await;
    append_confirmed(&h, 1, realized_fill(CHUNK, NET_OUTPUT)).await;

    let first = h.orchestrator.recover(NOW).await.expect("recover");
    assert_eq!(first.reconciled, 0);
    assert_eq!(first.fills_applied, 1);
    assert_eq!(
        h.sink.count(),
        1,
        "the sealed fill emits exactly one record"
    );

    let stored = load(&h).await;
    assert_eq!(stored.order.status, OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), CHUNK);
    assert!(conservation_holds(&stored));

    // A second recovery sees a terminal order, so it neither replays the fill
    // nor emits a second record.
    let second = h.orchestrator.recover(NOW).await.expect("recover 2");
    assert_eq!(second.fills_applied, 0);
    assert_eq!(h.sink.count(), 1, "a second recovery emits no record");
}
