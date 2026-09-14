//! Shared fixtures and deterministic test doubles for the market-execution
//! integration tests. None of this performs I/O, network, or real signing.
#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{MarketExecutionError, MarketExecutionRequest};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, RouteLeg, RoutePlan,
    RouteScore, TaxObservation, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::{AllowanceObservation, WalletBalance};
use execution_relay::{
    AttemptReservationStore, ChainHealth, ChainHealthBreaker, ChainObservation,
    ChainSubmissionAdapter, ExecutionRelay, InMemoryReservationStore, RelayError, RelayOutcome,
    Reservation, SignedExecutionRef, SignedPayload, SignedPayloadSource, SigningBoundary,
    SubmissionReceipt,
};
use market_execution::{
    MarketExecutionTrust, MarketExecutionTrustSource, PreparedExecutionRefSource,
    RelayMarketExecutionPort,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, Sequence};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use privy::{PreparedExecutionRef, RequestDigest, SigningRequest};
use routing::RouteQuote;

pub const NOW_MS: i64 = 1_000_000;
pub const PAYLOAD_BYTES: &[u8] = b"unsigned-transaction-payload";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

pub fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

pub fn usdc() -> AssetId {
    asset("USDC")
}

pub fn token() -> AssetId {
    asset("TOKEN")
}

pub fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("intent id"),
        source: TradeSource::Web,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        token_in: usdc(),
        token_out: token(),
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
        expiry_ms: Some(NOW_MS + 60_000),
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

pub fn route_with(expected_net_output: u128) -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap".to_string(),
            pool_ref: "pool-1".to_string(),
            token_in: usdc(),
            token_out: token(),
            amount_in: AtomicAmount::new(1_000),
            expected_amount_out: AtomicAmount::new(250),
        }],
        expected_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(expected_net_output),
        },
        state: Freshness {
            observed_at_ms: NOW_MS - 1_000,
            chain_height: 100,
            sequence: Sequence(1),
        },
    }
}

pub fn net_delta_with(net_output: u128) -> execution_preview::NetDelta {
    execution_preview::NetDelta {
        token_in: usdc(),
        token_out: token(),
        net_input: AssetAmount {
            asset: usdc(),
            amount: AtomicAmount::new(1_000),
        },
        gross_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(net_output),
        },
        net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(net_output),
        },
        dex_fee: None,
        tax_cost: None,
    }
}

pub fn quote_with(expected_net_output: u128, net_output: u128) -> RouteQuote {
    RouteQuote {
        plan: route_with(expected_net_output),
        net_delta: net_delta_with(net_output),
        hop_quotes: Vec::new(),
        gross_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(net_output),
        },
        net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(net_output),
        },
        tax_cost: None,
        route_impact_bps: None,
    }
}

pub fn score() -> RouteScore {
    RouteScore {
        gross_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(250),
        },
        simulated_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(240),
        },
        tax_cost: None,
        dex_fee: None,
        provider_fee: None,
        gas_cost: None,
        price_impact: Bps::new(20).expect("bps"),
        expected_slippage: Bps::new(20).expect("bps"),
        mev_risk: Bps::new(5).expect("bps"),
        failure_probability: Bps::new(1).expect("bps"),
        state_age_ms: 1_000,
        provider_reliability: Bps::new(9_900).expect("bps"),
        latency_ms: 42,
    }
}

/// A well-formed request: expected net output and delta net output both 240.
pub fn request() -> MarketExecutionRequest {
    request_with(240, 240, 100)
}

/// A request with explicit route expectation, delta net output, and slippage cap.
pub fn request_with(
    expected_net_output: u128,
    net_output: u128,
    max_slippage_bps: u16,
) -> MarketExecutionRequest {
    let mut intent = intent();
    intent.risk.max_slippage = Bps::new(max_slippage_bps).expect("slippage");
    MarketExecutionRequest {
        intent,
        quote: quote_with(expected_net_output, net_output),
        score: score(),
        now_ms: NOW_MS,
    }
}

pub fn context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("policy context")
}

pub fn policy_limits() -> PolicyLimits {
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

pub fn policy(enabled: bool) -> PolicyEngine {
    let gate = TradingGate::from_trusted_startup(Some(if enabled { "true" } else { "false" }))
        .expect("gate");
    PolicyEngine::new(gate, policy_limits()).expect("policy")
}

pub fn tax_observation() -> TaxObservation {
    TaxObservation {
        chain: ChainId::Base,
        token: token(),
        pool_ref: "pool-1".to_string(),
        router_ref: "uniswap".to_string(),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        amount: AtomicAmount::new(1_000),
        block_or_slot: 1,
        buy_tax: Bps::new(0).expect("bps"),
        sell_tax: Bps::new(0).expect("bps"),
        buy_succeeds: true,
        sell_succeeds: true,
        sellable: true,
        confidence: Bps::new(9_000).expect("bps"),
        observed_at_ms: NOW_MS - 1_000,
        expires_at_ms: NOW_MS + 60_000,
    }
}

pub fn wallet_balance() -> WalletBalance {
    WalletBalance {
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        asset: usdc(),
        available: AtomicAmount::new(1_000_000),
        freshness: Freshness {
            observed_at_ms: NOW_MS - 1_000,
            chain_height: 100,
            sequence: Sequence(1),
        },
    }
}

pub fn trust() -> MarketExecutionTrust {
    MarketExecutionTrust {
        policy_context: context(),
        wallet_balance: wallet_balance(),
        allowance: AllowanceObservation::NotRequired,
        tax_observation: tax_observation(),
        allowed_programs: HashSet::new(),
        freshness_policy: FreshnessPolicy::default(),
    }
}

// ---------------------------------------------------------------------------
// Deterministic fakes
// ---------------------------------------------------------------------------

/// Counting signing boundary. Never fails unless configured.
pub struct CountingSigner {
    pub calls: Arc<AtomicUsize>,
    pub fail: bool,
}

#[async_trait]
impl SigningBoundary for CountingSigner {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
pub enum Behavior {
    Accept,
    Reject,
    Timeout,
}

/// Scripted chain adapter with counting submit calls.
pub struct ScriptedAdapter {
    pub submits: Arc<AtomicUsize>,
    pub behavior: Behavior,
}

#[async_trait]
impl ChainSubmissionAdapter for ScriptedAdapter {
    async fn submit(
        &self,
        _request: &execution_relay::SubmitRequest,
    ) -> Result<SubmissionReceipt, RelayError> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
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
        Ok(ChainObservation::Unknown)
    }

    async fn reconcile(
        &self,
        _request: &execution_relay::SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        Ok(ChainObservation::Unknown)
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        ChainHealth::Healthy
    }
}

/// In-memory payload source returning one constant payload and counting the
/// pre/post lookups.
pub struct CountingSource {
    pub payload: SignedPayload,
    pub pre_calls: Arc<AtomicUsize>,
    pub post_calls: Arc<AtomicUsize>,
}

impl CountingSource {
    pub fn new() -> Self {
        Self {
            payload: SignedPayload::new(PAYLOAD_BYTES.to_vec()).expect("payload"),
            pre_calls: Arc::new(AtomicUsize::new(0)),
            post_calls: Arc::new(AtomicUsize::new(0)),
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

/// Trust source that returns one fixed value and counts calls.
pub struct FakeTrust {
    pub trust: MarketExecutionTrust,
    pub calls: Arc<AtomicUsize>,
}

impl MarketExecutionTrustSource for FakeTrust {
    fn trust(
        &self,
        _request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionTrust, MarketExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.trust.clone())
    }
}

/// Prepared-reference source that derives the reference from the intent key.
pub struct FakePreparedRefs {
    pub calls: Arc<AtomicUsize>,
}

impl PreparedExecutionRefSource for FakePreparedRefs {
    fn prepared_ref(
        &self,
        intent: &TradeIntent,
    ) -> Result<PreparedExecutionRef, MarketExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        PreparedExecutionRef::new(
            "prepared-1",
            intent.id.clone(),
            intent.idempotency_key.clone(),
        )
        .map_err(|_| MarketExecutionError::Denied)
    }
}

pub type TestAdapter = Arc<ScriptedAdapter>;
pub type TestSource = Arc<CountingSource>;
pub type TestSigner = Arc<CountingSigner>;
pub type TestPort = RelayMarketExecutionPort<
    InMemoryReservationStore,
    TestAdapter,
    TestSource,
    TestSigner,
    FakeTrust,
    FakePreparedRefs,
>;

pub struct Harness {
    pub port: TestPort,
    pub adapter: TestAdapter,
    pub source: TestSource,
    pub signer: TestSigner,
    pub trust_calls: Arc<AtomicUsize>,
    pub prepared_calls: Arc<AtomicUsize>,
}

pub fn harness(
    enabled: bool,
    behavior: Behavior,
    trust_value: MarketExecutionTrust,
    signer_fail: bool,
) -> Harness {
    let adapter = Arc::new(ScriptedAdapter {
        submits: Arc::new(AtomicUsize::new(0)),
        behavior,
    });
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner {
        calls: Arc::new(AtomicUsize::new(0)),
        fail: signer_fail,
    });
    let relay = ExecutionRelay::new_with_seams(
        policy(enabled),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let trust_calls = Arc::new(AtomicUsize::new(0));
    let prepared_calls = Arc::new(AtomicUsize::new(0));
    let port = RelayMarketExecutionPort::new(
        relay,
        FakeTrust {
            trust: trust_value,
            calls: Arc::clone(&trust_calls),
        },
        FakePreparedRefs {
            calls: Arc::clone(&prepared_calls),
        },
    );
    Harness {
        port,
        adapter,
        source,
        signer,
        trust_calls,
        prepared_calls,
    }
}

/// Reservation store that returns one scripted already-reserved outcome.
pub struct ScriptedStore {
    pub outcome: RelayOutcome,
}

impl AttemptReservationStore for ScriptedStore {
    fn reserve(
        &self,
        _key: &IdempotencyKey,
        _digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        Ok(Reservation::AlreadyReserved(self.outcome.clone()))
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

pub type ScriptedPort = RelayMarketExecutionPort<
    ScriptedStore,
    TestAdapter,
    TestSource,
    TestSigner,
    FakeTrust,
    FakePreparedRefs,
>;

/// Wires a port whose reservation store immediately returns `outcome`, so the
/// observational `map_outcome` arms (`Confirmed`/`Reserved`/...) are reachable.
pub fn scripted_port(
    outcome: RelayOutcome,
    trust_value: MarketExecutionTrust,
) -> (ScriptedPort, TestAdapter, TestSigner) {
    let adapter = Arc::new(ScriptedAdapter {
        submits: Arc::new(AtomicUsize::new(0)),
        behavior: Behavior::Accept,
    });
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner {
        calls: Arc::new(AtomicUsize::new(0)),
        fail: false,
    });
    let relay = ExecutionRelay::new_with_seams(
        policy(true),
        ScriptedStore { outcome },
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let port = RelayMarketExecutionPort::new(
        relay,
        FakeTrust {
            trust: trust_value,
            calls: Arc::new(AtomicUsize::new(0)),
        },
        FakePreparedRefs {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    (port, adapter, signer)
}

// ---------------------------------------------------------------------------
// Reconcile fixtures (P76)
// ---------------------------------------------------------------------------

/// Chain adapter whose `query`/`reconcile` observation is fixed at construction.
///
/// `submit` still acknowledges and counts, so a test can drive one ordinary
/// `execute` to populate the relay's process-local journal and then exercise the
/// read-only reconcile path against a scripted chain observation. Neither
/// `query` nor `reconcile` ever submits.
pub struct ObservingAdapter {
    pub submits: Arc<AtomicUsize>,
    pub observation: ChainObservation,
}

#[async_trait]
impl ChainSubmissionAdapter for ObservingAdapter {
    async fn submit(
        &self,
        _request: &execution_relay::SubmitRequest,
    ) -> Result<SubmissionReceipt, RelayError> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        SubmissionReceipt::new("receipt-ref")
    }

    async fn query(
        &self,
        _request: &execution_relay::SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        Ok(self.observation.clone())
    }

    async fn reconcile(
        &self,
        _request: &execution_relay::SubmitRequest,
        _now_ms: i64,
    ) -> Result<ChainObservation, RelayError> {
        Ok(self.observation.clone())
    }

    fn health(&self, _now_ms: i64) -> ChainHealth {
        ChainHealth::Healthy
    }
}

pub type ObservingAdapterRef = Arc<ObservingAdapter>;
pub type ObservingPort = RelayMarketExecutionPort<
    InMemoryReservationStore,
    ObservingAdapterRef,
    TestSource,
    TestSigner,
    FakeTrust,
    FakePreparedRefs,
>;

pub struct ReconcileHarness {
    pub port: ObservingPort,
    pub adapter: ObservingAdapterRef,
    pub source: TestSource,
    pub signer: TestSigner,
    pub trust_calls: Arc<AtomicUsize>,
    pub prepared_calls: Arc<AtomicUsize>,
}

/// Wires a relay-backed port whose adapter observes `observation` on
/// `query`/`reconcile`. `execute` still signs and submits once so the journal is
/// populated; a test resets the counters before calling `reconcile` to prove the
/// read-only path never signs or submits.
pub fn reconcile_harness(observation: ChainObservation) -> ReconcileHarness {
    let adapter = Arc::new(ObservingAdapter {
        submits: Arc::new(AtomicUsize::new(0)),
        observation,
    });
    let source = Arc::new(CountingSource::new());
    let signer = Arc::new(CountingSigner {
        calls: Arc::new(AtomicUsize::new(0)),
        fail: false,
    });
    let relay = ExecutionRelay::new_with_seams(
        policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&adapter),
        Arc::clone(&source),
        Arc::clone(&signer),
        ChainHealthBreaker::new(2, 5_000),
    );
    let trust_calls = Arc::new(AtomicUsize::new(0));
    let prepared_calls = Arc::new(AtomicUsize::new(0));
    let port = RelayMarketExecutionPort::new(
        relay,
        FakeTrust {
            trust: trust(),
            calls: Arc::clone(&trust_calls),
        },
        FakePreparedRefs {
            calls: Arc::clone(&prepared_calls),
        },
    );
    ReconcileHarness {
        port,
        adapter,
        source,
        signer,
        trust_calls,
        prepared_calls,
    }
}
