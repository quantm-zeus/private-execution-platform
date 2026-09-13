//! Shared fixtures and deterministic test doubles for the execution-relay
//! integration tests. None of this performs I/O or real broadcast.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, OrderType,
    RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId, ValidatedExecutionPreview,
    WalletRef,
};
use execution_relay::{
    AttemptReservationStore, ChainHealth, ChainObservation, ChainSubmissionAdapter, ExecutionRelay,
    InMemoryReservationStore, RelayError, RelayExecutionInput, RelayOutcome, Reservation,
    SignedExecutionRef, SignedPayload, SignedPayloadSource, SigningBoundary, SubmissionReceipt,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
use policy::{
    ApprovedExecution, PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot,
    UsdMicros,
};
use privy::{PayloadDigest, PreparedExecutionRef, RequestDigest, SigningRequest};

pub const NOW_MS: i64 = 1_000;
pub const PAYLOAD_BYTES: &[u8] = b"unsigned-transaction-payload";

pub fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-1").unwrap(),
        wallet_ref: WalletRef::new("wallet-1").unwrap(),
        chain: ChainId::Base,
        token_in: AssetId::new(ChainId::Base, "USDC").unwrap(),
        token_out: AssetId::new(ChainId::Base, "TOKEN").unwrap(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: domain::RiskConstraints {
            max_buy_tax: Bps::new(100).unwrap(),
            max_sell_tax: Bps::new(100).unwrap(),
            max_price_impact: Bps::new(100).unwrap(),
            max_slippage: Bps::new(100).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: Some(10_000),
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
    }
}

pub fn route() -> RoutePlan {
    let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
    let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
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

pub fn engine(enabled: bool) -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some(if enabled { "true" } else { "false" })).unwrap(),
        PolicyLimits {
            max_trade_usd: UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: UsdMicros::new(10_000_000),
            max_daily_turnover_usd: UsdMicros::new(50_000_000),
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            allowed_chains: std::collections::HashSet::from([ChainId::Base]),
            allowed_venues: std::collections::HashSet::from(["uniswap".to_string()]),
        },
    )
    .unwrap()
}

pub fn policy_context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .unwrap()
}

pub fn approved(engine: &PolicyEngine, intent: &TradeIntent) -> ApprovedExecution {
    engine
        .authorize_trade(intent, &policy_context())
        .expect("approval")
}

pub fn prepared(intent: &TradeIntent) -> PreparedExecutionRef {
    PreparedExecutionRef::new(
        "prepared-1",
        intent.id.clone(),
        intent.idempotency_key.clone(),
    )
    .unwrap()
}

pub fn preview(intent: &TradeIntent, route: &RoutePlan) -> ValidatedExecutionPreview {
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
        local_state_freshness: market_types::FreshnessStatus::Fresh,
    }
    .validate(intent, route, NOW_MS)
    .expect("validated preview")
}

pub fn payload() -> SignedPayload {
    SignedPayload::new(PAYLOAD_BYTES.to_vec()).expect("payload")
}

pub fn other_payload() -> SignedPayload {
    SignedPayload::new(b"a-different-unsigned-transaction".to_vec()).expect("payload")
}

/// Builds a signing request for a payload and nonce directly from the fixtures.
pub fn signing_request_with(payload: &SignedPayload, nonce: u64) -> SigningRequest {
    let mut intent = intent();
    intent.nonce = nonce;
    let engine = engine(true);
    let route = route();
    let approved = approved(&engine, &intent);
    let prepared = prepared(&intent);
    let preview = preview(&intent, &route);
    SigningRequest::bind(
        &engine,
        &approved,
        &prepared,
        &intent,
        &route,
        &preview,
        *payload.digest(),
        NOW_MS,
    )
    .expect("signing request")
}

/// Builds a signing request directly from the fixture inputs.
pub fn signing_request() -> SigningRequest {
    signing_request_with(&payload(), 7)
}

/// Builds a distinct signing request (different nonce) so a signed reference
/// can be deliberately mismatched in binding tests.
pub fn other_signing_request() -> SigningRequest {
    signing_request_with(&payload(), 8)
}

/// Signs a request with the given opaque reference string.
pub fn signed_ref_for(request: &SigningRequest, reference: &str) -> SignedExecutionRef {
    SignedExecutionRef::new(
        reference,
        *request.request_digest(),
        request.intent_id().clone(),
        request.idempotency_key().clone(),
    )
    .expect("signed ref")
}

/// Deterministic in-memory reservation store with call counters.
pub struct MockStore {
    inner: InMemoryReservationStore,
    pub reserve_calls: Arc<AtomicUsize>,
    pub record_signed_calls: Arc<AtomicUsize>,
    fail_record_signed: bool,
}

impl MockStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: InMemoryReservationStore::new(),
            reserve_calls: Arc::new(AtomicUsize::new(0)),
            record_signed_calls: Arc::new(AtomicUsize::new(0)),
            fail_record_signed: false,
        })
    }

    pub fn failing_record_signed() -> Arc<Self> {
        Arc::new(Self {
            inner: InMemoryReservationStore::new(),
            reserve_calls: Arc::new(AtomicUsize::new(0)),
            record_signed_calls: Arc::new(AtomicUsize::new(0)),
            fail_record_signed: true,
        })
    }
}

impl AttemptReservationStore for MockStore {
    fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        self.reserve_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.reserve(key, digest)
    }

    fn record_signed(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        self.record_signed_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_record_signed {
            return Err(RelayError::StoreUnavailable);
        }
        self.inner.record_signed(key, digest)
    }

    fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        self.inner.record_outcome(key, digest, outcome)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MockBehavior {
    Accept,
    Reject,
    Timeout,
    Unavailable,
}

pub struct MockAdapter {
    pub submits: Arc<AtomicUsize>,
    pub queries: Arc<AtomicUsize>,
    pub reconcilers: Arc<AtomicUsize>,
    behavior: Mutex<MockBehavior>,
    observation: Mutex<ChainObservation>,
    health: Mutex<ChainHealth>,
}

impl MockAdapter {
    pub fn new(behavior: MockBehavior, observation: ChainObservation) -> Arc<Self> {
        Arc::new(Self {
            submits: Arc::new(AtomicUsize::new(0)),
            queries: Arc::new(AtomicUsize::new(0)),
            reconcilers: Arc::new(AtomicUsize::new(0)),
            behavior: Mutex::new(behavior),
            observation: Mutex::new(observation),
            health: Mutex::new(ChainHealth::Healthy),
        })
    }

    /// A healthy adapter that acknowledges a submission and later confirms it.
    pub fn accepting() -> Arc<Self> {
        Self::new(
            MockBehavior::Accept,
            ChainObservation::Confirmed {
                reference: "confirmed-ref".to_string(),
            },
        )
    }

    pub fn set_behavior(&self, behavior: MockBehavior) {
        *self.behavior.lock().expect("behavior lock") = behavior;
    }

    pub fn set_observation(&self, observation: ChainObservation) {
        *self.observation.lock().expect("observation lock") = observation;
    }

    pub fn set_health(&self, health: ChainHealth) {
        *self.health.lock().expect("health lock") = health;
    }
}

#[async_trait]
impl ChainSubmissionAdapter for MockAdapter {
    async fn submit(
        &self,
        _request: &execution_relay::SubmitRequest,
    ) -> Result<SubmissionReceipt, RelayError> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        match *self.behavior.lock().expect("behavior lock") {
            MockBehavior::Accept => SubmissionReceipt::new("receipt-ref"),
            MockBehavior::Reject => Err(RelayError::AdapterRejected),
            MockBehavior::Timeout => Err(RelayError::AdapterTimeout),
            MockBehavior::Unavailable => Err(RelayError::AdapterUnavailable),
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
        *self.health.lock().expect("health lock")
    }
}

pub struct MockSource {
    default_payload: SignedPayload,
    queue: Mutex<VecDeque<SignedPayload>>,
    post_override: Mutex<Option<SignedPayload>>,
    fail_post: Mutex<bool>,
    pub pre_calls: Arc<AtomicUsize>,
    pub post_calls: Arc<AtomicUsize>,
}

impl MockSource {
    pub fn new(default_payload: SignedPayload) -> Arc<Self> {
        Arc::new(Self {
            default_payload,
            queue: Mutex::new(VecDeque::new()),
            post_override: Mutex::new(None),
            fail_post: Mutex::new(false),
            pre_calls: Arc::new(AtomicUsize::new(0)),
            post_calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn standard() -> Arc<Self> {
        Self::new(payload())
    }

    /// Queues payloads returned by successive `payload_to_sign` calls, falling
    /// back to the default once exhausted.
    pub fn with_sequence(payloads: Vec<SignedPayload>) -> Arc<Self> {
        let source = Self::new(payload().clone());
        {
            let mut queue = source.queue.lock().expect("queue lock");
            for item in payloads {
                queue.push_back(item);
            }
        }
        source
    }

    pub fn set_post_override(&self, payload: SignedPayload) {
        *self.post_override.lock().expect("override lock") = Some(payload);
    }

    pub fn set_fail_post(&self, fail: bool) {
        *self.fail_post.lock().expect("fail lock") = fail;
    }
}

#[async_trait]
impl SignedPayloadSource for MockSource {
    async fn payload_to_sign(
        &self,
        _key: &IdempotencyKey,
        _intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        self.pre_calls.fetch_add(1, Ordering::SeqCst);
        let mut queue = self.queue.lock().expect("queue lock");
        Ok(queue
            .pop_front()
            .unwrap_or_else(|| self.default_payload.clone()))
    }

    async fn signed_payload(
        &self,
        _signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        self.post_calls.fetch_add(1, Ordering::SeqCst);
        if *self.fail_post.lock().expect("fail lock") {
            return Err(RelayError::MissingSignedPayload);
        }
        Ok(self
            .post_override
            .lock()
            .expect("override lock")
            .clone()
            .unwrap_or_else(|| self.default_payload.clone()))
    }
}

pub struct MockSigning {
    pub calls: Arc<AtomicUsize>,
    fail: bool,
    reference: String,
    override_digest: Mutex<Option<RequestDigest>>,
}

impl MockSigning {
    pub fn new(fail: bool, reference: &str) -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail,
            reference: reference.to_string(),
            override_digest: Mutex::new(None),
        })
    }

    pub fn ok() -> Arc<Self> {
        Self::new(false, "signed-ref")
    }

    pub fn failing() -> Arc<Self> {
        Self::new(true, "signed-ref")
    }

    pub fn set_override_digest(&self, digest: RequestDigest) {
        *self.override_digest.lock().expect("digest lock") = Some(digest);
    }
}

#[async_trait]
impl SigningBoundary for MockSigning {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(RelayError::SigningFailed);
        }
        let digest = self
            .override_digest
            .lock()
            .expect("digest lock")
            .unwrap_or(*request.request_digest());
        SignedExecutionRef::new(
            self.reference.clone(),
            digest,
            request.intent_id().clone(),
            request.idempotency_key().clone(),
        )
    }
}

pub type HarnessRelay =
    ExecutionRelay<Arc<MockStore>, Arc<MockAdapter>, Arc<MockSource>, Arc<MockSigning>>;

/// A fully wired relay plus the trusted inputs needed to drive it.
pub struct RelayHarness {
    pub relay: HarnessRelay,
    pub store: Arc<MockStore>,
    pub adapter: Arc<MockAdapter>,
    pub source: Arc<MockSource>,
    pub signing: Arc<MockSigning>,
    pub intent: TradeIntent,
    pub context: PolicyContext,
    pub prepared: PreparedExecutionRef,
    pub approved: ApprovedExecution,
    pub route: RoutePlan,
    pub preview: ValidatedExecutionPreview,
}

impl RelayHarness {
    pub fn standard() -> Self {
        Self::build(
            engine(true),
            execution_relay::ChainHealthBreaker::new(2, 5_000),
            MockStore::new(),
            MockAdapter::accepting(),
            MockSource::standard(),
            MockSigning::ok(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        relay_engine: PolicyEngine,
        breaker: execution_relay::ChainHealthBreaker,
        store: Arc<MockStore>,
        adapter: Arc<MockAdapter>,
        source: Arc<MockSource>,
        signing: Arc<MockSigning>,
    ) -> Self {
        let creator = engine(true);
        let intent = intent();
        let context = policy_context();
        let approved = approved(&creator, &intent);
        let prepared = prepared(&intent);
        let route = route();
        let preview = preview(&intent, &route);
        let relay = ExecutionRelay::new(
            relay_engine,
            Arc::clone(&store),
            Arc::clone(&adapter),
            Arc::clone(&source),
            Arc::clone(&signing),
            breaker,
        );
        Self {
            relay,
            store,
            adapter,
            source,
            signing,
            intent,
            context,
            prepared,
            approved,
            route,
            preview,
        }
    }

    pub fn input(&self, now_ms: i64) -> RelayExecutionInput<'_> {
        RelayExecutionInput {
            intent: &self.intent,
            policy_context: &self.context,
            prepared: &self.prepared,
            approved: &self.approved,
            route: &self.route,
            preview: &self.preview,
            now_ms,
        }
    }
}

/// A tiny map-backed store used only to assert trait-object wiring compiles.
pub struct MapStore {
    entries: Mutex<HashMap<IdempotencyKey, [u8; 32]>>,
}

impl MapStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MapStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AttemptReservationStore for MapStore {
    fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let mut entries = self.entries.lock().expect("entries lock");
        match entries.get(key) {
            Some(existing) if existing == digest.as_bytes() => {
                Ok(Reservation::AlreadyReserved(RelayOutcome::Reserved))
            }
            Some(_) => Ok(Reservation::Conflict),
            None => {
                entries.insert(key.clone(), *digest.as_bytes());
                Ok(Reservation::Reserved)
            }
        }
    }

    fn record_signed(
        &self,
        _key: &IdempotencyKey,
        _digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        Ok(())
    }

    fn record_outcome(
        &self,
        _key: &IdempotencyKey,
        _digest: &RequestDigest,
        _outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        Ok(())
    }
}

pub fn unused_payload_digest() -> PayloadDigest {
    PayloadDigest::from_bytes([1u8; 32])
}
