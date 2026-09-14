//! Shared in-memory fakes and helpers for the P78 composition tests.
//!
//! Everything here is test-only: an in-memory [`OpaqueStore`], a fixed
//! [`OrderKeyProvider`], a counting [`MarketExecutionPort`], a counting
//! [`AgentBackend`] wrapper, a recording [`AttemptReservationStore`], and small
//! policy/config/MCP-frame helpers. No live transport, key material, or network
//! is involved.

#![allow(dead_code)]

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
    OrderValuation,
};
use agent_commands::{AgentChannel, AgentCommand, AmountSpec, AssetRef};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use crypto_envelope::at_rest::SealKey;
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, RoutePlan, RouteScore,
    TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::NetDelta;
use execution_relay::{AttemptReservationStore, InMemoryReservationStore, RelayError, Reservation};
use limit_engine::{
    BlindIndexKey, LimitEngineError, OrderKeyMaterial, OrderKeyProvider, RecoveryReport,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
use mcp_server::{AgentBackend, BackendOutcome};
use policy::{PolicyEngine, PolicyLimits, UsdMicros};
use privy::RequestDigest;
use routing::RouteQuote;
use storage::{
    ClassListCursor, ComponentHealth, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot,
    OpaqueStore, StorageError,
};
use trading_core::composition::{
    build_policy, CompositionConfig, LimitRecovery, PendingMarketAttempt,
};

/// Reference instant used by every test.
pub const NOW: i64 = 1_000_000;

/// Fixed order-key id.
pub const KID: [u8; 16] = [3; 16];
/// Fixed seal key bytes.
pub const SEAL: [u8; 32] = [4; 32];
/// Fixed blind-index key bytes.
pub const BLIND: [u8; 32] = [5; 32];

/// Recovers a poisoned mutex over plain test data.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Asset id on Base.
pub fn asset_id(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset id")
}

/// Freshness stamped at [`NOW`].
pub fn freshness() -> Freshness {
    Freshness {
        observed_at_ms: NOW,
        chain_height: 1,
        sequence: Sequence(1),
    }
}

/// Asset-bound amount helper.
pub fn amount_of(asset: AssetId, amount: u128) -> AssetAmount {
    AssetAmount {
        asset,
        amount: AtomicAmount::new(amount),
    }
}

/// Valid BPS helper.
pub fn bps(value: u16) -> Bps {
    Bps::new(value).expect("bps")
}

/// Minimal in-memory [`OpaqueStore`] with newest-version reads and class listing.
#[derive(Default)]
pub struct InMemoryOpaqueStore {
    objects: Mutex<Vec<OpaqueObject>>,
    events: Mutex<Vec<OpaqueEventRecord>>,
}

impl InMemoryOpaqueStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored object versions.
    pub fn object_count(&self) -> usize {
        lock(&self.objects).len()
    }
}

#[async_trait]
impl OpaqueStore for InMemoryOpaqueStore {
    async fn put_object(&self, object: OpaqueObject) -> Result<(), StorageError> {
        object.validate()?;
        lock(&self.objects).push(object);
        Ok(())
    }

    async fn get_object(&self, id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        Ok(lock(&self.objects)
            .iter()
            .filter(|object| object.id == id)
            .max_by_key(|object| object.version)
            .cloned())
    }

    async fn list_objects_by_class_page(
        &self,
        class_blind_index: &[u8],
        _cursor: Option<&ClassListCursor>,
        limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut matching: Vec<OpaqueObject> = lock(&self.objects)
            .iter()
            .filter(|object| object.class_blind_index == class_blind_index)
            .cloned()
            .collect();
        matching.sort_by(|left, right| left.id.cmp(&right.id));
        matching.truncate(limit);
        Ok(matching)
    }

    async fn append_event(&self, event: OpaqueEventRecord) -> Result<(), StorageError> {
        event.validate()?;
        lock(&self.events).push(event);
        Ok(())
    }

    async fn read_events(
        &self,
        _stream_blind_index: &[u8],
        _from_sequence: u64,
        _limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        Ok(Vec::new())
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Ok(None)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "test.in-memory",
            status: ComponentHealth::Healthy,
            observed_at_ms: NOW,
        }
    }
}

fn material() -> OrderKeyMaterial {
    OrderKeyMaterial {
        kid: KID,
        seal: SealKey::from_bytes(SEAL),
        blind_index: BlindIndexKey::from_bytes(BLIND),
    }
}

/// Deterministic order-key provider.
pub struct FixedOrderKeys;

impl OrderKeyProvider for FixedOrderKeys {
    fn current(&self) -> Result<OrderKeyMaterial, LimitEngineError> {
        Ok(material())
    }

    fn by_id(&self, kid: &[u8; 16]) -> Result<OrderKeyMaterial, LimitEngineError> {
        if kid == &KID {
            Ok(material())
        } else {
            Err(LimitEngineError::UnknownKeyId)
        }
    }
}

/// Trusted valuation that prices every asset.
pub struct FixedValuation;

impl OrderValuation for FixedValuation {
    fn usd_micros(&self, _asset: &AssetId, _amount: AtomicAmount) -> Option<u64> {
        Some(1_000)
    }
}

/// Recording market port: counts calls and replays a scripted reconcile.
pub struct CountingMarketPort {
    execute_calls: Arc<AtomicUsize>,
    reconcile_calls: Arc<AtomicUsize>,
    captured_keys: Arc<Mutex<Vec<String>>>,
    script: Mutex<VecDeque<Result<MarketExecutionOutcome, MarketExecutionError>>>,
}

impl CountingMarketPort {
    /// Builds a port whose reconcile replays `script` in order (default
    /// `Unknown`).
    pub fn new(script: Vec<Result<MarketExecutionOutcome, MarketExecutionError>>) -> Self {
        Self {
            execute_calls: Arc::new(AtomicUsize::new(0)),
            reconcile_calls: Arc::new(AtomicUsize::new(0)),
            captured_keys: Arc::new(Mutex::new(Vec::new())),
            script: Mutex::new(script.into()),
        }
    }

    /// Shared execute-call counter.
    pub fn execute_calls(&self) -> Arc<AtomicUsize> {
        self.execute_calls.clone()
    }

    /// Shared reconcile-call counter.
    pub fn reconcile_calls(&self) -> Arc<AtomicUsize> {
        self.reconcile_calls.clone()
    }

    /// Shared list of idempotency keys observed by `reconcile`, in call order.
    pub fn captured_keys(&self) -> Arc<Mutex<Vec<String>>> {
        self.captured_keys.clone()
    }
}

#[async_trait]
impl MarketExecutionPort for CountingMarketPort {
    async fn execute(
        &self,
        _request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        Err(MarketExecutionError::Unavailable)
    }

    async fn reconcile(
        &self,
        idempotency_key: &IdempotencyKey,
        _now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.captured_keys).push(idempotency_key.as_str().to_string());
        lock(&self.script)
            .pop_front()
            .unwrap_or(Ok(MarketExecutionOutcome::Unknown))
    }
}

/// Backend wrapper that counts `execute` calls and forwards everything.
pub struct CountingAgentBackend<B: AgentBackend> {
    inner: Arc<B>,
    execute_calls: Arc<AtomicUsize>,
}

impl<B: AgentBackend> CountingAgentBackend<B> {
    /// Wraps `inner`.
    pub fn new(inner: Arc<B>) -> Self {
        Self {
            inner,
            execute_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Shared execute-call counter.
    pub fn execute_calls(&self) -> Arc<AtomicUsize> {
        self.execute_calls.clone()
    }
}

#[async_trait]
impl<B: AgentBackend> AgentBackend for CountingAgentBackend<B> {
    async fn execute(&self, channel: AgentChannel, command: AgentCommand) -> BackendOutcome {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(channel, command).await
    }

    async fn valuation_usd_micros(&self, command: &AgentCommand) -> Option<u64> {
        self.inner.valuation_usd_micros(command).await
    }
}

/// Reservation store that counts `reserve` calls, delegating to an in-memory store.
pub struct RecordingReservationStore {
    inner: InMemoryReservationStore,
    reserve_calls: Arc<AtomicUsize>,
}

impl Default for RecordingReservationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingReservationStore {
    /// Creates an empty recording store.
    pub fn new() -> Self {
        Self {
            inner: InMemoryReservationStore::new(),
            reserve_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Shared reserve-call counter.
    pub fn reserve_calls(&self) -> Arc<AtomicUsize> {
        self.reserve_calls.clone()
    }
}

impl AttemptReservationStore for RecordingReservationStore {
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
        self.inner.record_signed(key, digest)
    }

    fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: execution_relay::RelayOutcome,
    ) -> Result<(), RelayError> {
        self.inner.record_outcome(key, digest, outcome)
    }
}

/// Minimal positive wallet config bound to Base.
pub fn config() -> CompositionConfig {
    CompositionConfig {
        owner: UserId::new("u1").expect("owner"),
        wallet_ref: WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        risk: RiskConstraints {
            max_buy_tax: bps(1_000),
            max_sell_tax: bps(1_000),
            max_price_impact: bps(300),
            max_slippage: bps(200),
            max_total_cost: None,
        },
        min_fill: AtomicAmount::new(1),
        allowed_chains: HashSet::from([ChainId::Base]),
        max_trade_usd: 1_000_000,
    }
}

/// Minimal positive policy limits.
pub fn limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: bps(1_000),
        max_sell_tax: bps(1_000),
        max_price_impact: bps(300),
        max_slippage: bps(200),
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::new(),
    }
}

/// Enabled policy engine.
pub fn enabled_policy() -> PolicyEngine {
    build_policy(Some("true"), limits()).expect("enabled policy")
}

/// Disabled policy engine.
pub fn disabled_policy() -> PolicyEngine {
    build_policy(Some("false"), limits()).expect("disabled policy")
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("intent id"),
        source: TradeSource::Mcp,
        user_id: UserId::new("u1").expect("owner"),
        wallet_ref: WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        token_in: asset_id("USDC"),
        token_out: asset_id("TOKEN"),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: bps(100),
            max_sell_tax: bps(100),
            max_price_impact: bps(100),
            max_slippage: bps(100),
            max_total_cost: None,
        },
        allow_partial_fill: false,
        expiry_ms: None,
        nonce: 0,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idempotency key"),
    }
}

fn quote() -> RouteQuote {
    let token_in = asset_id("USDC");
    let token_out = asset_id("TOKEN");
    RouteQuote {
        plan: RoutePlan {
            legs: Vec::new(),
            expected_net_output: amount_of(token_out.clone(), 200),
            state: freshness(),
        },
        net_delta: NetDelta {
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            net_input: amount_of(token_in, 1_000),
            gross_output: amount_of(token_out.clone(), 250),
            net_output: amount_of(token_out.clone(), 200),
            dex_fee: None,
            tax_cost: None,
        },
        hop_quotes: Vec::new(),
        gross_output: amount_of(token_out.clone(), 250),
        net_output: amount_of(token_out, 200),
        tax_cost: None,
        route_impact_bps: None,
    }
}

fn score() -> RouteScore {
    let token_out = asset_id("TOKEN");
    RouteScore {
        gross_output: amount_of(token_out.clone(), 250),
        simulated_net_output: amount_of(token_out, 200),
        tax_cost: None,
        dex_fee: None,
        provider_fee: None,
        gas_cost: None,
        price_impact: bps(0),
        expected_slippage: bps(0),
        mev_risk: bps(0),
        failure_probability: bps(0),
        state_age_ms: 0,
        provider_reliability: bps(0),
        latency_ms: 0,
    }
}

/// A structurally valid market-execution request (used only to exercise the
/// fail-closed port, which rejects it before reading it).
pub fn dummy_request() -> MarketExecutionRequest {
    MarketExecutionRequest {
        intent: intent(),
        quote: quote(),
        score: score(),
        now_ms: NOW,
    }
}

/// Builds a pending market attempt on Base (`USDC` -> `TOKEN`, buy).
pub fn attempt(amount: u128) -> PendingMarketAttempt {
    PendingMarketAttempt::new(
        AgentChannel::Mcp,
        AssetRef {
            chain: ChainId::Base,
            address: "USDC".to_string(),
        },
        AssetRef {
            chain: ChainId::Base,
            address: "TOKEN".to_string(),
        },
        TradeSide::Buy,
        AmountSpec::TokenAtomic(amount),
        None,
        None,
    )
}

/// Limit-recovery stub that counts calls and returns an empty report.
pub struct StubLimitRecovery {
    calls: Arc<AtomicUsize>,
}

impl Default for StubLimitRecovery {
    fn default() -> Self {
        Self::new()
    }
}

impl StubLimitRecovery {
    /// Creates a stub with a zero report.
    pub fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Shared call counter.
    pub fn calls(&self) -> Arc<AtomicUsize> {
        self.calls.clone()
    }
}

#[async_trait]
impl LimitRecovery for StubLimitRecovery {
    async fn recover(&self, _now_ms: i64) -> Result<RecoveryReport, LimitEngineError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RecoveryReport {
            open: 0,
            in_flight: 0,
            reconciled: 0,
            fills_applied: 0,
            finalized: 0,
            retryable: 0,
            quarantined: 0,
            truncated: false,
            kill_switch_deferred: false,
        })
    }
}

/// Builds a `tools/call` JSON-RPC frame.
pub fn tools_call(id: u64, name: &str, arguments: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
    .to_string()
}

/// Market-order arguments for `execute_market_order`.
pub fn market_arguments() -> serde_json::Value {
    serde_json::json!({
        "token_in": { "chain": { "kind": "base" }, "address": "USDC" },
        "token_out": { "chain": { "kind": "base" }, "address": "TOKEN" },
        "side": "buy",
        "amount": { "unit": "token_atomic", "value": 1_000 },
        "max_slippage_bps": 100,
        "max_price_impact_bps": 200,
    })
}

/// Parse a JSON-RPC response frame.
pub fn parse(response: &str) -> serde_json::Value {
    serde_json::from_str(response).expect("response is JSON")
}

/// Extract the `result` object from a parsed response.
pub fn result(response: &serde_json::Value) -> &serde_json::Value {
    response.get("result").expect("result present")
}
