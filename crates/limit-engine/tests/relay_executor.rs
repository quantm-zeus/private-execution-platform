//! P57 — concrete `limit_engine::RelayAttemptExecutor` over the landed Privy
//! signing boundary + execution relay.
//!
//! Every test wires the relay with the `#[doc(hidden)] ExecutionRelay::new_with_seams`
//! test seam over deterministic fakes (a counting signer, a scripted chain
//! adapter, a constant in-memory payload source, `InMemoryReservationStore`) and
//! an explicit `now_ms`. No live signer, chain, RPC, database, or key material is
//! involved.

mod support;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, OrderType,
    RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId,
    ValidatedExecutionPreview, WalletRef,
};
use execution_preview::{AllowanceObservation, NetDelta, WalletBalance};
use execution_relay::{
    ChainHealth, ChainHealthBreaker, ChainObservation, ChainSubmissionAdapter,
    DeterministicDurableStore, ExecutionRelay, InMemoryReservationStore, ObservedFill, RelayError,
    SignedExecutionRef, SignedPayload, SignedPayloadSource, SigningBoundary, SubmissionReceipt,
};
use limit_engine::{
    attempt_intent_id, attempt_key, attempt_prepared_reference, AttemptExecutor, AttemptLimits,
    AttemptPhase, AttemptResolution, BoundAttempt, DurableLimitOrderStore, LimitOrderStore,
    Orchestrator, OrderAttemptEvent, PreparedAttempt, QuoteOutcome, QuoteProvider,
    RelayAttemptExecutor, TickInput, TickOutcome,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use privy::SigningRequest;
use tax_engine::TaxAssessment;

use support::opaque::{durable_order, durable_store, InMemoryOpaqueStore, TestOrderKeys};

const NOW_MS: i64 = 1_000;
const PAYLOAD_BYTES: &[u8] = b"unsigned-transaction-payload";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("intent id"),
        source: TradeSource::Web,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        token_in: asset("USDC"),
        token_out: asset("TOKEN"),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(100).expect("bps"),
            max_sell_tax: Bps::new(100).expect("bps"),
            max_price_impact: Bps::new(100).expect("bps"),
            max_slippage: Bps::new(100).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: Some(10_000),
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn route() -> RoutePlan {
    let token_in = asset("USDC");
    let token_out = asset("TOKEN");
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "0xpool1".to_string(),
            token_in,
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(1_000),
            expected_amount_out: AtomicAmount::new(250),
        }],
        expected_net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(240),
        },
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 100,
            sequence: Sequence(1),
        },
    }
}

fn policy_limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        allowed_chains: [ChainId::Base].into_iter().collect(),
        allowed_venues: ["uniswap".to_string()].into_iter().collect(),
    }
}

fn policy(enabled: bool) -> PolicyEngine {
    let gate = TradingGate::from_trusted_startup(Some(if enabled { "true" } else { "false" }))
        .expect("gate");
    PolicyEngine::new(gate, policy_limits()).expect("policy")
}

fn context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("policy context")
}

fn preview(intent: &TradeIntent, route: &RoutePlan) -> ValidatedExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: intent.chain.clone(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: intent.side,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(1_000),
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
    .validate(intent, route, NOW_MS)
    .expect("validated preview")
}

fn net_delta() -> NetDelta {
    NetDelta {
        token_in: asset("USDC"),
        token_out: asset("TOKEN"),
        net_input: AssetAmount {
            asset: asset("USDC"),
            amount: AtomicAmount::new(1_000),
        },
        gross_output: AssetAmount {
            asset: asset("TOKEN"),
            amount: AtomicAmount::new(250),
        },
        net_output: AssetAmount {
            asset: asset("TOKEN"),
            amount: AtomicAmount::new(240),
        },
        dex_fee: None,
        tax_cost: None,
    }
}

fn payload() -> SignedPayload {
    SignedPayload::new(PAYLOAD_BYTES.to_vec()).expect("payload")
}

/// Builds a live `PreparedAttempt` whose approval was issued by an enabled
/// engine. The relay's own engine may be enabled or disabled independently.
fn prepared_attempt() -> PreparedAttempt {
    let engine = policy(true);
    let intent = intent();
    let approved = engine
        .authorize_trade(&intent, &context())
        .expect("approval");
    let route = route();
    let preview = preview(&intent, &route);
    PreparedAttempt {
        intent,
        route,
        net_delta: net_delta(),
        preview,
        approval: approved,
        min_out: AssetAmount {
            asset: asset("TOKEN"),
            amount: AtomicAmount::new(240),
        },
    }
}

/// Builds the durable binding the orchestrator would have persisted.
fn bound_attempt(prepared: &PreparedAttempt) -> BoundAttempt {
    BoundAttempt {
        intent: prepared.intent.clone(),
        route: prepared.route.clone(),
        preview: prepared.preview.preview().clone(),
        approval: limit_engine::ApprovalSnapshot {
            intent_id: prepared.intent.id.clone(),
            wallet_ref: prepared.intent.wallet_ref.clone(),
            chain: prepared.intent.chain.clone(),
            idempotency_key: prepared.intent.idempotency_key.clone(),
            expires_at_ms: prepared.intent.expiry_ms,
            approved_trade_usd: 500_000,
            approved_at_ms: NOW_MS,
        },
        prepared_reference: "prepared-1".to_string(),
        payload_digest: *payload().digest().as_bytes(),
        attempt_key: prepared.intent.idempotency_key.clone(),
        attempt_seq: 1,
        nonce: prepared.intent.nonce,
    }
}

// ---------------------------------------------------------------------------
// Deterministic fakes
// ---------------------------------------------------------------------------

/// Counting signing boundary. Records the payload digest it was asked to bind
/// (for the digest-equality assertion) and never fails unless configured.
struct CountingSigner {
    calls: Arc<AtomicUsize>,
    fail: bool,
    last_payload_digest: Arc<Mutex<Option<[u8; 32]>>>,
}

impl CountingSigner {
    fn new(fail: bool) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail,
            last_payload_digest: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for CountingSigner {
    fn default() -> Self {
        Self::new(false)
    }
}

#[async_trait]
impl SigningBoundary for CountingSigner {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_payload_digest.lock().expect("digest lock") =
            Some(*request.payload_digest().as_bytes());
        if self.fail {
            return Err(RelayError::SigningFailed);
        }
        SignedExecutionRef::new(
            "signed-ref",
            *request.request_digest(),
            request.intent_id().clone(),
            request.idempotency_key().clone(),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Accept,
    Reject,
    Timeout,
}

/// Scripted chain adapter with counting submit/query/reconcile calls.
struct ScriptedAdapter {
    submits: Arc<AtomicUsize>,
    queries: Arc<AtomicUsize>,
    reconcilers: Arc<AtomicUsize>,
    behavior: Mutex<Behavior>,
    observation: Mutex<ChainObservation>,
}

impl ScriptedAdapter {
    fn new(behavior: Behavior, observation: ChainObservation) -> Self {
        Self {
            submits: Arc::new(AtomicUsize::new(0)),
            queries: Arc::new(AtomicUsize::new(0)),
            reconcilers: Arc::new(AtomicUsize::new(0)),
            behavior: Mutex::new(behavior),
            observation: Mutex::new(observation),
        }
    }

    fn accepting() -> Self {
        Self::new(
            Behavior::Accept,
            ChainObservation::Confirmed {
                reference: "confirmed-ref".to_string(),
                fill: None,
            },
        )
    }

    fn set_observation(&self, observation: ChainObservation) {
        *self.observation.lock().expect("observation lock") = observation;
    }
}

#[async_trait]
impl ChainSubmissionAdapter for ScriptedAdapter {
    async fn submit(
        &self,
        _request: &execution_relay::SubmitRequest,
    ) -> Result<SubmissionReceipt, RelayError> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        match *self.behavior.lock().expect("behavior lock") {
            Behavior::Accept => SubmissionReceipt::new("receipt-ref"),
            Behavior::Reject => Err(RelayError::AdapterRejected),
            Behavior::Timeout => Err(RelayError::AdapterTimeout),
        }
    }

    async fn query(
        &self,
        _request: &execution_relay::SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        Ok(self.observation.lock().expect("observation lock").clone())
    }

    async fn reconcile(
        &self,
        _request: &execution_relay::SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        self.reconcilers.fetch_add(1, Ordering::SeqCst);
        Ok(self.observation.lock().expect("observation lock").clone())
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        ChainHealth::Healthy
    }
}

/// In-memory payload source returning one constant payload and counting the
/// pre/post lookups.
struct CountingSource {
    payload: SignedPayload,
    pre_calls: Arc<AtomicUsize>,
    post_calls: Arc<AtomicUsize>,
    fail_pre: bool,
}

impl CountingSource {
    fn new() -> Self {
        Self {
            payload: payload(),
            pre_calls: Arc::new(AtomicUsize::new(0)),
            post_calls: Arc::new(AtomicUsize::new(0)),
            fail_pre: false,
        }
    }
}

impl Default for CountingSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignedPayloadSource for CountingSource {
    async fn payload_to_sign(
        &self,
        _key: &IdempotencyKey,
        _intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        self.pre_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_pre {
            return Err(RelayError::MissingSignedPayload);
        }
        Ok(self.payload.clone())
    }

    async fn signed_payload(
        &self,
        _signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        self.post_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.payload.clone())
    }
}

type TestAdapter = Arc<ScriptedAdapter>;
type TestSource = Arc<CountingSource>;
type TestSigner = Arc<CountingSigner>;
type TestExecutor =
    RelayAttemptExecutor<InMemoryReservationStore, TestAdapter, TestSource, TestSigner>;

/// Wires a relay-backed executor over fresh fakes with an independent relay
/// policy gate.
fn executor(
    relay_enabled: bool,
    behavior: Behavior,
    observation: ChainObservation,
) -> (TestExecutor, TestAdapter, TestSource, TestSigner) {
    let adapter = Arc::new(ScriptedAdapter::new(behavior, observation));
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner::new(false));
    let relay = ExecutionRelay::new_with_seams(
        policy(relay_enabled),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    (
        RelayAttemptExecutor::new(relay, context()),
        adapter,
        source,
        signer,
    )
}

fn unknown_observation() -> ChainObservation {
    ChainObservation::Unknown
}

// ---------------------------------------------------------------------------
// Direct executor tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn payload_digest_is_stable_and_equals_the_digest_the_relay_binds() {
    let (executor, _adapter, _source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let first = executor
        .payload_digest(&prepared.intent)
        .await
        .expect("digest");
    let second = executor
        .payload_digest(&prepared.intent)
        .await
        .expect("digest");
    assert_eq!(first, second, "the digest must be stable across calls");
    assert_eq!(first, bound.payload_digest);
    assert_eq!(first, *payload().digest().as_bytes());

    // The relay binds the exact digest the executor reported into the signing
    // request if it ever signs. Observe it through the counting signer.
    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;
    assert_eq!(resolution, AttemptResolution::Unknown);
    assert_eq!(
        *signer.last_payload_digest.lock().expect("digest lock"),
        Some(first),
        "the relay must bind the digest returned by payload_digest"
    );
}

#[tokio::test]
async fn successful_submit_maps_to_unknown_and_signs_and_submits_once() {
    let (executor, adapter, source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    // A `Submitted` acknowledgement is not confirmation and carries no amounts:
    // the executor must not invent a realized fill.
    assert_eq!(resolution, AttemptResolution::Unknown);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);
    assert!(source.pre_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(source.post_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn timeout_maps_to_unknown() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Timeout, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::Unknown);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn duplicate_execute_does_not_resign_or_resubmit() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let first = executor.execute(&prepared, &bound, NOW_MS).await;
    let second = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(first, AttemptResolution::Unknown);
    assert_eq!(second, AttemptResolution::Unknown);
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        1,
        "a duplicate must not reach the signing boundary again"
    );
    assert_eq!(
        adapter.submits.load(Ordering::SeqCst),
        1,
        "a duplicate must not re-submit"
    );
}

#[tokio::test]
async fn rejected_maps_to_rejected() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Reject, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::Rejected);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn definitive_pre_send_signing_failure_maps_to_failed_before_submit() {
    // A signing failure is a definitive pre-send error: nothing reached the
    // adapter, so the orchestrator may retry under the attempt limit.
    let adapter = Arc::new(ScriptedAdapter::accepting());
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner::new(true));
    let relay = ExecutionRelay::new_with_seams(
        policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let executor = RelayAttemptExecutor::new(relay, context());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::FailedBeforeSubmit);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_payload_maps_to_failed_before_submit() {
    let adapter = Arc::new(ScriptedAdapter::accepting());
    let source = Arc::new(CountingSource {
        fail_pre: true,
        ..CountingSource::new()
    });
    let signer = Arc::new(CountingSigner::new(false));
    let relay = ExecutionRelay::new_with_seams(
        policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let executor = RelayAttemptExecutor::new(relay, context());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::FailedBeforeSubmit);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn trading_disabled_maps_to_failed_before_submit_without_signer_or_adapter_calls() {
    let (executor, adapter, source, signer) =
        executor(false, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::FailedBeforeSubmit);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(
        source.pre_calls.load(Ordering::SeqCst),
        0,
        "the kill switch must block before the payload is even fetched"
    );
}

#[tokio::test]
async fn production_wiring_fails_closed_before_signer_or_adapter() {
    // The production constructor installs `UnavailableChainAdapter` and the real
    // (always-unavailable transport) Privy boundary. The digest is still
    // resolvable without a signer, but `execute` must fail closed at the chain
    // health gate before any reservation, sign, or submit.
    let source = Arc::new(CountingSource::new());
    let executor = RelayAttemptExecutor::production(
        policy(true),
        DeterministicDurableStore::new(),
        Arc::clone(&source),
        ChainHealthBreaker::new(2, 5_000),
        context(),
    );
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let digest = executor
        .payload_digest(&prepared.intent)
        .await
        .expect("digest");
    assert_ne!(digest, [0u8; 32]);

    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;
    assert_eq!(resolution, AttemptResolution::FailedBeforeSubmit);
}

#[tokio::test]
async fn reconcile_never_signs_and_maps_confirmed_to_unknown_then_rejected() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let submitted = executor.execute(&prepared, &bound, NOW_MS).await;
    assert_eq!(submitted, AttemptResolution::Unknown);
    let signs_after_execute = signer.calls.load(Ordering::SeqCst);

    // A `Confirmed` observation with no realized amounts must not become a
    // fabricated `Filled`.
    adapter.set_observation(ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: None,
    });
    let confirmed = executor.reconcile(&bound, NOW_MS).await;
    assert_eq!(confirmed, AttemptResolution::Unknown);
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        signs_after_execute,
        "reconcile must never sign"
    );
    assert_eq!(
        adapter.submits.load(Ordering::SeqCst),
        1,
        "reconcile must not submit"
    );

    adapter.set_observation(ChainObservation::Rejected {
        final_reason: "chain rejected".to_string(),
    });
    let rejected = executor.reconcile(&bound, NOW_MS).await;
    assert_eq!(rejected, AttemptResolution::Rejected);
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        signs_after_execute,
        "reconcile must never sign"
    );
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reconcile_maps_an_observed_fill_to_filled_without_side_effects() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    let submitted = executor.execute(&prepared, &bound, NOW_MS).await;
    assert_eq!(submitted, AttemptResolution::Unknown);
    let signs_after_execute = signer.calls.load(Ordering::SeqCst);
    let submits_after_execute = adapter.submits.load(Ordering::SeqCst);

    // A chain adapter that observed the realized amounts now yields a fill. The
    // executor maps the observation verbatim; the orchestrator re-validates it
    // against the sealed bound context (`net_input == chunk`, `net_output >=
    // min_out`) before any ledger mutation.
    adapter.set_observation(ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: Some(ObservedFill {
            net_input: 1_000,
            net_output: 240,
        }),
    });
    let confirmed = executor.reconcile(&bound, NOW_MS).await;
    match confirmed {
        AttemptResolution::Filled(fill) => {
            assert_eq!(fill.net_input.get(), 1_000);
            assert_eq!(fill.net_output.get(), 240);
        }
        other => panic!("expected Filled, got {other:?}"),
    }
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        signs_after_execute,
        "reconcile must never sign"
    );
    assert_eq!(
        adapter.submits.load(Ordering::SeqCst),
        submits_after_execute,
        "reconcile must not submit"
    );
}

#[tokio::test]
async fn reconcile_on_unknown_key_fails_closed_without_side_effects() {
    let (executor, adapter, _source, signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    // No `execute` ran, so the relay's process-local journal has no request for
    // this attempt key. Absence cannot prove the attempt was never sent (the
    // journal is lost on restart), so the executor fails closed to `Unknown`
    // rather than a retryable pre-send failure.
    let resolution = executor.reconcile(&bound, NOW_MS).await;

    assert_eq!(resolution, AttemptResolution::Unknown);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn executor_debug_is_redacted() {
    let (executor, _adapter, _source, _signer) =
        executor(true, Behavior::Accept, unknown_observation());
    let prepared = prepared_attempt();
    let bound = bound_attempt(&prepared);

    // A real execute so the debug surfaces are exercised with populated inputs.
    let resolution = executor.execute(&prepared, &bound, NOW_MS).await;

    let surfaces = [
        format!("{executor:?}"),
        format!("{resolution:?}"),
        format!("{:?}", AttemptResolution::FailedBeforeSubmit),
        format!("{:?}", AttemptResolution::Rejected),
    ];
    let forbidden = [
        "prepared-1",
        "USDC",
        "TOKEN",
        "wallet-1",
        "intent-1",
        "idem-1",
        "uniswap",
        "1000",
        "240",
        "signed-ref",
        "confirmed-ref",
        "http",
        "://",
        "0x",
    ];
    for surface in &surfaces {
        for needle in &forbidden {
            assert!(
                !surface.contains(needle),
                "redaction leak: `{surface}` contains `{needle}`"
            );
        }
        assert!(
            !has_hex_run(surface, 8),
            "redaction leak: `{surface}` contains a hex run of length >= 8"
        );
    }
}

/// Detects a run of at least `min_len` ASCII hex digits (leaked digest bytes).
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

// ---------------------------------------------------------------------------
// Frozen-script orchestrator integration test
// ---------------------------------------------------------------------------

const ORCH_NOW: i64 = 100_000;
const NET_OUTPUT: u128 = 240;

fn orchestrator_policy_limits() -> PolicyLimits {
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

fn orchestrator_policy(enabled: bool) -> PolicyEngine {
    let gate = TradingGate::from_trusted_startup(Some(if enabled { "true" } else { "false" }))
        .expect("gate");
    PolicyEngine::new(gate, orchestrator_policy_limits()).expect("policy")
}

/// Deterministic quote provider keyed by call ordinal.
struct ModelProvider {
    calls: AtomicUsize,
}

impl ModelProvider {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl QuoteProvider for ModelProvider {
    fn quote(
        &self,
        order: &limit_engine::StoredLimitOrder,
        amount_in: AtomicAmount,
        now_ms: i64,
    ) -> QuoteOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        QuoteOutcome::Quoted(Box::new(build_quoted(order, amount_in.get(), now_ms)))
    }
}

/// Copies the orchestrator test's synthetic quote builder (test binaries cannot
/// import one another).
fn build_quoted(
    order: &limit_engine::StoredLimitOrder,
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
        state: Freshness {
            observed_at_ms: now_ms,
            chain_height: 1,
            sequence: Sequence(1),
        },
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

fn orchestrator_trust(now_ms: i64) -> limit_engine::AttemptTrust {
    limit_engine::AttemptTrust {
        policy_context: PolicyContext::from_trusted_backend_state(
            now_ms,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("synthetic".to_string()),
        )
        .expect("policy context"),
        wallet_balance: WalletBalance {
            wallet_ref: WalletRef::new("w1").expect("wallet"),
            chain: ChainId::Base,
            asset: asset("USDC"),
            available: AtomicAmount::new(1_000_000),
            freshness: Freshness {
                observed_at_ms: now_ms - 1_000,
                chain_height: 100,
                sequence: Sequence(1),
            },
        },
        allowance: AllowanceObservation::NotRequired,
        tax_observation: domain::TaxObservation {
            chain: ChainId::Base,
            token: asset("TOKEN"),
            pool_ref: "pool-1".to_string(),
            router_ref: "synthetic".to_string(),
            wallet_ref: WalletRef::new("w1").expect("wallet"),
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
        },
        allowed_programs: HashSet::new(),
        freshness_policy: FreshnessPolicy::default(),
    }
}

type FrozenOrchestrator = Orchestrator<
    InMemoryOpaqueStore,
    ModelProvider,
    RelayAttemptExecutor<InMemoryReservationStore, TestAdapter, TestSource, TestSigner>,
>;

#[tokio::test]
async fn orchestrator_tick_maps_relay_submission_to_in_flight_without_unearned_fill() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let mut order = durable_order(
        &keys,
        "p57-frozen",
        domain::OrderStatus::Active,
        1_000,
        1_000,
        0,
    );
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let order_id = order.order.id.clone();
    let reader: DurableLimitOrderStore<InMemoryOpaqueStore> = durable_store(&backend, &keys);
    reader.create(order).await.expect("create order");

    let adapter = Arc::new(ScriptedAdapter::accepting());
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner::new(false));
    let relay = ExecutionRelay::new_with_seams(
        orchestrator_policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let executor = RelayAttemptExecutor::new(relay, context());

    let orchestrator: FrozenOrchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        ModelProvider::new(),
        executor,
        orchestrator_policy(true),
        AttemptLimits {
            max_attempts_per_order: 4,
        },
    );

    let trust = orchestrator_trust(ORCH_NOW);
    let outcome = orchestrator
        .tick(TickInput {
            order_id: &order_id,
            signal: true,
            source: TradeSource::Web,
            trust: &trust,
            now_ms: ORCH_NOW,
        })
        .await
        .expect("tick");

    // Submitted -> Unknown: the order stays in flight and no fill is applied.
    match outcome {
        TickOutcome::InFlight { attempt_seq } => assert_eq!(attempt_seq, 1),
        other => panic!("expected InFlight, got {other:?}"),
    }

    let stored = reader
        .load(&order_id)
        .await
        .expect("load")
        .expect("order present");
    assert_eq!(stored.order.status, domain::OrderStatus::Executing);
    assert_eq!(
        stored.filled_input.get(),
        0,
        "no unearned fill may be applied"
    );
    assert_eq!(stored.order.remaining_input.get(), 1_000);

    let events: Vec<OrderAttemptEvent> = reader
        .read_attempts(&order_id)
        .await
        .expect("read attempts");
    assert_eq!(
        events
            .iter()
            .map(|event| event.phase)
            .collect::<Vec<AttemptPhase>>(),
        vec![AttemptPhase::Bound, AttemptPhase::Unknown]
    );
    assert!(
        events
            .iter()
            .all(|event| event.phase != AttemptPhase::Confirmed),
        "no Confirmed event may be fabricated"
    );

    // Exactly one sign + one submit for the whole tick.
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 1);

    // The durable binding matches the deterministic per-attempt identity.
    let bound = events[0].bound.clone().expect("bound context");
    let blind = keys.blind_key();
    assert_eq!(
        bound.intent.id,
        attempt_intent_id(&blind, &ChainId::Base, &order_id, 1).expect("intent")
    );
    assert_eq!(
        bound.attempt_key,
        attempt_key(&blind, &ChainId::Base, &order_id, 1).expect("key")
    );
    assert_eq!(
        bound.prepared_reference,
        attempt_prepared_reference(&blind, &ChainId::Base, &order_id, 1).expect("reference")
    );
    assert_eq!(bound.payload_digest, *payload().digest().as_bytes());
}

#[tokio::test]
async fn orchestrator_recover_applies_an_observed_relay_fill_exactly_once() {
    let backend = Arc::new(InMemoryOpaqueStore::new());
    let keys = Arc::new(TestOrderKeys::deterministic(7));
    let mut order = durable_order(
        &keys,
        "p69-observed-fill",
        domain::OrderStatus::Active,
        1_000,
        1_000,
        0,
    );
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let order_id = order.order.id.clone();
    let reader: DurableLimitOrderStore<InMemoryOpaqueStore> = durable_store(&backend, &keys);
    reader.create(order).await.expect("create order");

    let adapter = Arc::new(ScriptedAdapter::accepting());
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner::new(false));
    let relay = ExecutionRelay::new_with_seams(
        orchestrator_policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let executor = RelayAttemptExecutor::new(relay, context());
    let orchestrator: FrozenOrchestrator = Orchestrator::new(
        durable_store(&backend, &keys),
        ModelProvider::new(),
        executor,
        orchestrator_policy(true),
        AttemptLimits {
            max_attempts_per_order: 4,
        },
    );

    let trust = orchestrator_trust(ORCH_NOW);
    let outcome = orchestrator
        .tick(TickInput {
            order_id: &order_id,
            signal: true,
            source: TradeSource::Web,
            trust: &trust,
            now_ms: ORCH_NOW,
        })
        .await
        .expect("tick");
    assert!(matches!(outcome, TickOutcome::InFlight { .. }));

    // The sealed bound context supplies the exact chunk and the exact simulated
    // output, so the adapter observes a fill that satisfies OR-4/OR-5 instead of
    // a guessed amount.
    let events: Vec<OrderAttemptEvent> = reader
        .read_attempts(&order_id)
        .await
        .expect("read attempts");
    let bound = events[0].bound.clone().expect("bound context");
    let expected_input = bound.intent.amount.get();
    let expected_output = bound.preview.simulated_net_output.amount.get();
    assert!(expected_input > 0 && expected_output > 0);

    adapter.set_observation(ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: Some(ObservedFill {
            net_input: expected_input,
            net_output: expected_output,
        }),
    });

    let report = orchestrator.recover(ORCH_NOW + 1).await.expect("recover");
    assert_eq!(report.fills_applied, 1);

    let stored = reader
        .load(&order_id)
        .await
        .expect("load")
        .expect("order present");
    assert_eq!(stored.order.status, domain::OrderStatus::Filled);
    assert_eq!(stored.filled_input.get(), expected_input);
    assert!(stored.order.remaining_input.is_zero());

    // Re-running recovery cannot apply the same observed fill twice.
    let report = orchestrator
        .recover(ORCH_NOW + 2)
        .await
        .expect("recover again");
    assert_eq!(report.fills_applied, 0);
    let stored = reader
        .load(&order_id)
        .await
        .expect("load")
        .expect("order present");
    assert_eq!(stored.filled_input.get(), expected_input);
}
