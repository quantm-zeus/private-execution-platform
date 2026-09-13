//! P72 — concrete relay-backed `agent_backend::MarketExecutionPort`.
//!
//! Every test wires the port over the `#[doc(hidden)] ExecutionRelay::new_with_seams`
//! test seam with deterministic fakes (a counting signer, a scripted chain
//! adapter, a constant in-memory payload source, `InMemoryReservationStore`) and
//! an explicit `now_ms`. No live signer, chain, RPC, database, or key material is
//! involved.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, RouteLeg, RoutePlan,
    RouteScore, TaxObservation, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::{AllowanceObservation, WalletBalance};
use execution_relay::{
    AttemptReservationStore, ChainHealth, ChainHealthBreaker, ChainObservation,
    ChainSubmissionAdapter, ExecutionRelay, InMemoryReservationStore, ObservedFill,
    PrivySigningBoundaryAdapter, RelayError, RelayOutcome, Reservation, SignedExecutionRef,
    SignedPayload, SignedPayloadSource, SigningBoundary, SubmissionReceipt,
    UnavailableChainAdapter,
};
use market_execution::{
    MarketExecutionTrust, MarketExecutionTrustSource, PreparedExecutionRefSource,
    RelayMarketExecutionPort,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, Sequence};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use privy::{PreparedExecutionRef, RequestDigest, SigningRequest};
use routing::RouteQuote;

const NOW_MS: i64 = 1_000_000;
const PAYLOAD_BYTES: &[u8] = b"unsigned-transaction-payload";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn usdc() -> AssetId {
    asset("USDC")
}

fn token() -> AssetId {
    asset("TOKEN")
}

fn intent() -> TradeIntent {
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

fn route_with(expected_net_output: u128) -> RoutePlan {
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

fn net_delta_with(net_output: u128) -> execution_preview::NetDelta {
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

fn quote_with(expected_net_output: u128, net_output: u128) -> RouteQuote {
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

fn score() -> RouteScore {
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
fn request() -> MarketExecutionRequest {
    request_with(240, 240, 100)
}

/// A request with explicit route expectation, delta net output, and slippage cap.
fn request_with(
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

fn context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("policy context")
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

fn tax_observation() -> TaxObservation {
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

fn wallet_balance() -> WalletBalance {
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

fn trust() -> MarketExecutionTrust {
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
struct CountingSigner {
    calls: Arc<AtomicUsize>,
    fail: bool,
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
enum Behavior {
    Accept,
    Reject,
    Timeout,
}

/// Scripted chain adapter with counting submit calls.
struct ScriptedAdapter {
    submits: Arc<AtomicUsize>,
    behavior: Behavior,
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
struct CountingSource {
    payload: SignedPayload,
    pre_calls: Arc<AtomicUsize>,
    post_calls: Arc<AtomicUsize>,
}

impl CountingSource {
    fn new() -> Self {
        Self {
            payload: SignedPayload::new(PAYLOAD_BYTES.to_vec()).expect("payload"),
            pre_calls: Arc::new(AtomicUsize::new(0)),
            post_calls: Arc::new(AtomicUsize::new(0)),
        }
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
struct FakeTrust {
    trust: MarketExecutionTrust,
    calls: Arc<AtomicUsize>,
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
struct FakePreparedRefs {
    calls: Arc<AtomicUsize>,
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

type TestAdapter = Arc<ScriptedAdapter>;
type TestSource = Arc<CountingSource>;
type TestSigner = Arc<CountingSigner>;
type TestPort = RelayMarketExecutionPort<
    InMemoryReservationStore,
    TestAdapter,
    TestSource,
    TestSigner,
    FakeTrust,
    FakePreparedRefs,
>;

struct Harness {
    port: TestPort,
    adapter: TestAdapter,
    source: TestSource,
    signer: TestSigner,
    trust_calls: Arc<AtomicUsize>,
    prepared_calls: Arc<AtomicUsize>,
}

fn harness(
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
struct ScriptedStore {
    outcome: RelayOutcome,
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

type ScriptedPort = RelayMarketExecutionPort<
    ScriptedStore,
    TestAdapter,
    TestSource,
    TestSigner,
    FakeTrust,
    FakePreparedRefs,
>;

/// Wires a port whose reservation store immediately returns `outcome`, so the
/// observational `map_outcome` arms (`Confirmed`/`Reserved`/...) are reachable.
fn scripted_port(
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
// Required cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trading_disabled_denies_before_signer_or_adapter() {
    let h = harness(false, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        0,
        "the kill switch must block before signing"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.source.pre_calls.load(Ordering::SeqCst),
        0,
        "the kill switch must block before the payload is fetched"
    );
    assert_eq!(
        h.prepared_calls.load(Ordering::SeqCst),
        0,
        "denial must precede the prepared-reference source"
    );
}

#[tokio::test]
async fn policy_trade_size_exceeded_denies() {
    let mut trust_value = trust();
    trust_value.policy_context = PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(2_000_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("policy context");
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_tax_observation_denies_before_sign() {
    let mut trust_value = trust();
    trust_value.tax_observation.observed_at_ms = NOW_MS - 60_000;
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn insufficient_balance_denies_before_sign() {
    let mut trust_value = trust();
    trust_value.wallet_balance.available = AtomicAmount::new(999);
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn confirmed_with_observed_amounts_maps_to_filled() {
    let (port, adapter, signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 1_000,
                net_output: 240,
            }),
        },
        trust(),
    );

    let outcome = port.execute(request()).await;

    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1_000,
            net_output: 240,
        })
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn confirmed_without_amounts_maps_to_unknown() {
    let (port, _adapter, _signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        },
        trust(),
    );

    let outcome = port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Unknown));
}

#[tokio::test]
async fn submitted_maps_to_submitted() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ambiguous_adapter_timeout_maps_to_unknown() {
    let h = harness(true, Behavior::Timeout, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Unknown));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_adapter_maps_to_failed() {
    let h = harness(true, Behavior::Reject, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Failed));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn definitive_signing_failure_maps_to_failed() {
    let h = harness(true, Behavior::Accept, trust(), true);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Failed));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        0,
        "a definitive pre-send failure must never reach the adapter"
    );
}

#[tokio::test]
async fn duplicate_execute_signs_and_submits_once() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let first = h.port.execute(request()).await;
    let second = h.port.execute(request()).await;

    assert_eq!(first, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(second, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        1,
        "a duplicate must not reach the signing boundary again"
    );
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        1,
        "a duplicate must not re-submit"
    );
}

#[tokio::test]
async fn production_wiring_fails_closed_before_signer_or_adapter() {
    let source = Arc::new(CountingSource::new());
    let port = RelayMarketExecutionPort::<
        InMemoryReservationStore,
        UnavailableChainAdapter,
        TestSource,
        PrivySigningBoundaryAdapter,
        FakeTrust,
        FakePreparedRefs,
    >::production(
        policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&source),
        ChainHealthBreaker::new(2, 5_000),
        FakeTrust {
            trust: trust(),
            calls: Arc::new(AtomicUsize::new(0)),
        },
        FakePreparedRefs {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    );

    let outcome = port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Unavailable));
    assert_eq!(
        source.pre_calls.load(Ordering::SeqCst),
        0,
        "the unavailable adapter must block before any payload/sign step"
    );
}

#[tokio::test]
async fn debug_is_redacted() {
    let trust_value = trust();
    let trust_debug = format!("{trust_value:?}");
    let h = harness(true, Behavior::Accept, trust_value, false);
    let outcome = h.port.execute(request()).await.expect("submitted");
    let port_debug = format!("{:?}", h.port);
    let outcome_debug = format!("{outcome:?}");

    assert!(
        trust_debug.contains("..") && port_debug.contains(".."),
        "trust and port must use a non-exhaustive Debug"
    );

    for surface in [&trust_debug, &port_debug, &outcome_debug] {
        for needle in [
            "USDC",
            "TOKEN",
            "wallet-1",
            "intent-1",
            "idem-1",
            "uniswap",
            "pool-1",
            "1000",
            "240",
            "prepared-1",
            "signed-ref",
            "receipt-ref",
            "http",
            "://",
            "0x",
        ] {
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

#[tokio::test]
async fn min_out_is_the_exact_slippage_floor() {
    // With a zero slippage cap the floor is exactly `route.expected_net_output`,
    // and a quote whose net output equals it passes revalidation and, when the
    // relay observes a fill of exactly that amount, maps to `Filled`.
    let (port, _adapter, _signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 1_000,
                net_output: 240,
            }),
        },
        trust(),
    );
    let outcome = port.execute(request_with(240, 240, 0)).await;
    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1_000,
            net_output: 240,
        })
    );

    // A route expectation whose slippage floor sits above the delta net output
    // is denied (`MinOutNotMet`) before any sign/submit.
    let h = harness(true, Behavior::Accept, trust(), false);
    let outcome = h.port.execute(request_with(240, 237, 100)).await;
    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn trust_is_fetched_once_per_execute() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let _ = h.port.execute(request()).await;

    assert_eq!(h.trust_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn trading_disabled_after_preview_denies() {
    // Everything else (trust, balance, tax, route) is valid; only the relay's
    // kill switch is off, and it still denies without reaching the prepared
    // reference or the signer.
    let h = harness(false, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.trust_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
}
