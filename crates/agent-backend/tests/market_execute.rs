//! P70 market-order execute delegation: trusted intent/quote hand-off,
//! fail-closed defaults, valuation gating, trading-disabled denial, and
//! redaction.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use agent_backend::{
    AgentReadBackend, FixedClock, MarketExecutionError, MarketExecutionOutcome,
    MarketExecutionPort, MarketExecutionRequest, MarketPreviewError, MarketSnapshot,
    MarketSnapshotSource, OrderReadModel, OrderSummary, TradingAgentBackend, TradingBackendConfig,
    UnavailableOrderValuation, UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentCapabilities, AgentChannel, AgentCommand, AmountSpec, AssetRef, RouterSource, TradeCommand,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{IdempotencyKey, OrderStatus, TradeIntent, TradeSide};
use limit_engine::InMemoryLimitOrderStore;
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessPolicy, FreshnessStatus, PoolId, PoolKindState,
    PoolStateEnvelope, SafeFreshnessMeta, Sequence,
};
use mcp_server::{AgentBackend, BackendOutcome, McpServer};
use routing::{PoolDescriptor, PoolRefLabel, RouteQuote, ScoringInputs, VenueLabel};
use serde_json::Value;
use tax_engine::TaxAssessment;

const NOW: i64 = 1_000_000;
const AMOUNT: u128 = 1_000_000_000;
const BUY_NET: u128 = 1_943_762_414;

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("asset")
}

fn usdc() -> AssetId {
    base_asset("USDC")
}

fn token() -> AssetId {
    base_asset("TOKEN")
}

fn config() -> TradingBackendConfig {
    TradingBackendConfig {
        owner: domain::UserId::new("u1").expect("owner"),
        wallet_ref: domain::WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        risk: domain::RiskConstraints {
            max_buy_tax: Bps::new(1_000).expect("bps"),
            max_sell_tax: Bps::new(1_000).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        min_fill: AtomicAmount::new(1),
    }
}

#[derive(Default)]
struct FakeOrders;

#[async_trait]
impl OrderReadModel for FakeOrders {
    async fn list_orders(
        &self,
        _status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, agent_backend::BackendError> {
        Ok(Vec::new())
    }
}

/// A valuation that knows one asset, so a mutating command can be authorized.
struct OneAssetValuation {
    asset: AssetId,
}

impl agent_backend::OrderValuation for OneAssetValuation {
    fn usd_micros(&self, asset: &AssetId, _amount: AtomicAmount) -> Option<u64> {
        (asset == &self.asset).then_some(7_000_000)
    }
}

fn pool() -> PoolDescriptor {
    PoolDescriptor {
        envelope: PoolStateEnvelope {
            pool_id: PoolId::new(ChainId::Base, "pool-1").expect("pool id"),
            sequence: Sequence(1),
            observed_at_ms: NOW,
            state: PoolKindState::Cpmm(CpmmPoolState {
                token_0: usdc(),
                token_1: token(),
                decimals_0: 6,
                decimals_1: 18,
                reserve_0: AtomicAmount::new(5_000_000_000_000),
                reserve_1: AtomicAmount::new(10_000_000_000_000),
                total_lp_supply: None,
                fee_bps: Bps::new(30).expect("fee"),
            }),
        },
        venue: VenueLabel::new("uniswap").expect("venue"),
        leg_pool_ref: PoolRefLabel::new("pool-1").expect("pool ref"),
        impact_override_bps: None,
    }
}

fn assessment(asset: AssetId, buy_tax: u16, sell_tax: u16) -> TaxAssessment {
    TaxAssessment::new(
        asset,
        ChainId::Base,
        Bps::new(buy_tax).expect("buy"),
        Bps::new(sell_tax).expect("sell"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: NOW,
            evaluated_at_ms: NOW,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    )
}

fn scoring() -> ScoringInputs {
    ScoringInputs {
        expected_slippage_bps: Bps::new(20).expect("bps"),
        mev_risk_bps: Bps::new(5).expect("bps"),
        failure_probability_bps: Bps::new(1).expect("bps"),
        provider_reliability_bps: Bps::new(9_900).expect("bps"),
        latency_ms: 42,
    }
}

fn policy() -> FreshnessPolicy {
    FreshnessPolicy::new(60_000, 2_000).expect("policy")
}

struct StaticSnapshot {
    descriptors: Vec<PoolDescriptor>,
    assessment: TaxAssessment,
}

impl StaticSnapshot {
    fn new(assessment: TaxAssessment) -> Self {
        Self {
            descriptors: vec![pool()],
            assessment,
        }
    }
}

impl MarketSnapshotSource for StaticSnapshot {
    fn snapshot(
        &self,
        _intent: &TradeIntent,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> Result<MarketSnapshot, MarketPreviewError> {
        Ok(MarketSnapshot {
            descriptors: self.descriptors.clone(),
            assessment: self.assessment.clone(),
            scoring: scoring(),
            freshness_policy: policy(),
            max_hops: 1,
            gas_price_in_output: None,
        })
    }
}

/// Records the exact intent/quote handed to the port and returns a scripted result.
struct RecordingExecution {
    result: Result<MarketExecutionOutcome, MarketExecutionError>,
    reconcile_result: Result<MarketExecutionOutcome, MarketExecutionError>,
    seen: Mutex<Vec<(TradeIntent, RouteQuote, i64)>>,
    reconcile_seen: Mutex<Vec<(IdempotencyKey, i64)>>,
}

impl RecordingExecution {
    fn filled(net_input: u128, net_output: u128) -> Self {
        Self::new(
            Ok(MarketExecutionOutcome::Filled {
                net_input,
                net_output,
            }),
            Ok(MarketExecutionOutcome::Unknown),
        )
    }

    fn submitted() -> Self {
        Self::new(
            Ok(MarketExecutionOutcome::Submitted),
            Ok(MarketExecutionOutcome::Unknown),
        )
    }

    fn failed() -> Self {
        Self::new(
            Ok(MarketExecutionOutcome::Failed),
            Ok(MarketExecutionOutcome::Unknown),
        )
    }

    fn failing(error: MarketExecutionError) -> Self {
        Self::new(Err(error), Ok(MarketExecutionOutcome::Unknown))
    }

    fn new(
        result: Result<MarketExecutionOutcome, MarketExecutionError>,
        reconcile_result: Result<MarketExecutionOutcome, MarketExecutionError>,
    ) -> Self {
        Self {
            result,
            reconcile_result,
            seen: Mutex::new(Vec::new()),
            reconcile_seen: Mutex::new(Vec::new()),
        }
    }

    /// Scripts the read-only reconcile result (execute is unchanged).
    fn with_reconcile(
        mut self,
        reconcile_result: Result<MarketExecutionOutcome, MarketExecutionError>,
    ) -> Self {
        self.reconcile_result = reconcile_result;
        self
    }

    fn calls(&self) -> usize {
        self.seen.lock().expect("lock").len()
    }

    fn last(&self) -> (TradeIntent, RouteQuote, i64) {
        self.seen
            .lock()
            .expect("lock")
            .last()
            .expect("call")
            .clone()
    }

    fn reconcile_calls(&self) -> usize {
        self.reconcile_seen.lock().expect("lock").len()
    }

    fn last_reconcile(&self) -> (IdempotencyKey, i64) {
        self.reconcile_seen
            .lock()
            .expect("lock")
            .last()
            .expect("reconcile call")
            .clone()
    }
}

#[async_trait]
impl MarketExecutionPort for RecordingExecution {
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.seen
            .lock()
            .expect("lock")
            .push((request.intent, request.quote, request.now_ms));
        self.result
    }

    async fn reconcile(
        &self,
        idempotency_key: &IdempotencyKey,
        now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.reconcile_seen
            .lock()
            .expect("lock")
            .push((idempotency_key.clone(), now_ms));
        self.reconcile_result
    }
}

type Backend =
    TradingAgentBackend<FakeOrders, UnavailablePortfolioReadModel, InMemoryLimitOrderStore>;

fn backend_with(source: Arc<StaticSnapshot>, execution: Arc<RecordingExecution>) -> Backend {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(OneAssetValuation { asset: usdc() }),
    )
    .with_market_snapshot(source)
    .with_market_execution(execution)
}

fn execute(token_in: &str, token_out: &str, amount: AmountSpec) -> TradeCommand {
    TradeCommand::ExecuteMarketOrder {
        token_in: AssetRef::new(ChainId::Base, token_in).expect("in"),
        token_out: AssetRef::new(ChainId::Base, token_out).expect("out"),
        side: TradeSide::Buy,
        amount,
        max_slippage_bps: None,
        max_price_impact_bps: None,
        // Every pre-P84B test in this file pins the byte-identical Local path.
        router: RouterSource::Local,
    }
}

async fn run(backend: &Backend, command: TradeCommand) -> BackendOutcome {
    backend
        .execute(AgentChannel::Mcp, AgentCommand::Trade(command))
        .await
}

fn amount_at(value: &Value, path: &[&str]) -> u128 {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key).expect("path");
    }
    cursor.as_u64().expect("u64 amount") as u128
}

#[tokio::test]
async fn execute_delegates_the_exact_intent_and_quote() {
    let port = Arc::new(RecordingExecution::filled(AMOUNT, BUY_NET));
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 250, 100))),
        port.clone(),
    );
    let outcome = run(
        &backend,
        execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT)),
    )
    .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected an execution value, got {outcome:?}");
    };
    assert_eq!(
        value["execution"]["state"],
        Value::String("filled".to_string())
    );
    assert_eq!(amount_at(&value, &["execution", "net_input"]), AMOUNT);
    assert_eq!(amount_at(&value, &["execution", "net_output"]), BUY_NET);

    // The port saw the same trusted intent and the exact quoted net delta.
    assert_eq!(port.calls(), 1);
    let (intent, quote, now_ms) = port.last();
    assert_eq!(now_ms, NOW);
    assert_eq!(intent.source, domain::TradeSource::Mcp);
    assert_eq!(intent.side, TradeSide::Buy);
    assert_eq!(intent.order_type, domain::OrderType::Market);
    assert_eq!(intent.amount_type, domain::AmountType::InputAssetAtomic);
    assert_eq!(intent.amount, AtomicAmount::new(AMOUNT));
    assert_eq!(intent.risk.max_price_impact, Bps::new(300).expect("bps"));
    assert_eq!(quote.net_delta.net_input.amount, AtomicAmount::new(AMOUNT));
    assert_eq!(
        quote.net_delta.net_output.amount,
        AtomicAmount::new(BUY_NET)
    );
}

#[tokio::test]
async fn execute_fails_closed_without_an_installed_port() {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(OneAssetValuation { asset: usdc() }),
    )
    .with_market_snapshot(Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))));
    let outcome = run(
        &backend,
        execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT)),
    )
    .await;
    assert_eq!(outcome, BackendOutcome::Unavailable);
}

#[tokio::test]
async fn execute_maps_port_denied_and_unavailable() {
    let denied = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        Arc::new(RecordingExecution::failing(MarketExecutionError::Denied)),
    );
    assert_eq!(
        run(
            &denied,
            execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Denied
    );
    let unavailable = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        Arc::new(RecordingExecution::failing(
            MarketExecutionError::Unavailable,
        )),
    );
    assert_eq!(
        run(
            &unavailable,
            execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Unavailable
    );
}

#[tokio::test]
async fn execute_rejects_structural_denials_before_the_port() {
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        port.clone(),
    );
    // Same asset.
    assert_eq!(
        run(
            &backend,
            execute("USDC", "USDC", AmountSpec::TokenAtomic(1))
        )
        .await,
        BackendOutcome::Denied
    );
    // Zero amount.
    assert_eq!(
        run(
            &backend,
            execute("USDC", "TOKEN", AmountSpec::TokenAtomic(0))
        )
        .await,
        BackendOutcome::Denied
    );
    // A USD amount needs a trusted conversion this layer does not perform.
    assert_eq!(
        run(&backend, execute("USDC", "TOKEN", AmountSpec::UsdMicros(1))).await,
        BackendOutcome::Denied
    );
    // A foreign-chain pair.
    let foreign = TradeCommand::ExecuteMarketOrder {
        token_in: AssetRef::new(ChainId::Solana, "USDC").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: None,
        max_price_impact_bps: None,
        router: RouterSource::Local,
    };
    assert_eq!(run(&backend, foreign).await, BackendOutcome::Denied);
    // A zero (unbounded-sentinel) impact cap is refused by the shared intent
    // builder before the port.
    let zero_cap = TradeCommand::ExecuteMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "USDC").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: None,
        max_price_impact_bps: Some(0),
        router: RouterSource::Local,
    };
    assert_eq!(run(&backend, zero_cap).await, BackendOutcome::Denied);
    assert_eq!(port.calls(), 0, "denied commands must never reach the port");
}

#[tokio::test]
async fn execute_no_route_is_denied_before_the_port() {
    let port = Arc::new(RecordingExecution::submitted());
    let mut source = StaticSnapshot::new(assessment(token(), 0, 0));
    source.descriptors = Vec::new();
    let backend = backend_with(Arc::new(source), port.clone());
    assert_eq!(
        run(
            &backend,
            execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Denied
    );
    assert_eq!(port.calls(), 0);
}

/// Builds an MCP server around a backend with a port and a valuation.
fn server(
    port: Arc<RecordingExecution>,
    trading_enabled: bool,
    valued: bool,
) -> McpServer<Backend> {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let valuation: Arc<dyn agent_backend::OrderValuation> = if valued {
        Arc::new(OneAssetValuation { asset: usdc() })
    } else {
        Arc::new(UnavailableOrderValuation)
    };
    let backend = TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        valuation,
    )
    .with_market_snapshot(Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))))
    .with_market_execution(port);
    let mut chains = HashSet::new();
    chains.insert(ChainId::Base);
    McpServer::new(
        backend,
        AgentCapabilities::new(trading_enabled, chains, 1_000_000_000),
    )
}

const EXECUTE_COMMAND: &str = r#"{"tool":"execute_market_order","token_in":{"chain":{"kind":"base"},"address":"USDC"},"token_out":{"chain":{"kind":"base"},"address":"TOKEN"},"side":"buy","amount":{"unit":"token_atomic","value":1000000000},"router_preference":"local"}"#;

#[tokio::test]
async fn execute_is_denied_while_trading_is_disabled() {
    let port = Arc::new(RecordingExecution::submitted());
    let server = server(port.clone(), false, true);
    let frame = mcp_server::tools_call_frame(EXECUTE_COMMAND).expect("frame");
    let response = server.handle(&frame).await;
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["result"]["isError"], Value::Bool(true));
    assert_eq!(
        parsed["result"]["content"][0]["text"],
        Value::String("TradingDisabled".to_string())
    );
    assert_eq!(port.calls(), 0);
}

#[tokio::test]
async fn execute_requires_a_trusted_valuation() {
    let port = Arc::new(RecordingExecution::submitted());
    let server = server(port.clone(), true, false);
    let frame = mcp_server::tools_call_frame(EXECUTE_COMMAND).expect("frame");
    let response = server.handle(&frame).await;
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["result"]["isError"], Value::Bool(true));
    assert_eq!(
        parsed["result"]["content"][0]["text"],
        Value::String("NotionalExceedsLimit".to_string())
    );
    assert_eq!(port.calls(), 0);
}

#[tokio::test]
async fn execute_is_served_through_mcp_when_enabled_and_wired() {
    let port = Arc::new(RecordingExecution::submitted());
    let server = server(port.clone(), true, true);
    let frame = mcp_server::tools_call_frame(EXECUTE_COMMAND).expect("frame");
    let response = server.handle(&frame).await;
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["result"]["isError"], Value::Bool(false));
    let text: Value = serde_json::from_str(
        parsed["result"]["content"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("inner json");
    assert_eq!(
        text["execution"]["state"],
        Value::String("submitted".to_string())
    );
    assert_eq!(port.calls(), 1);
}

#[tokio::test]
async fn execute_maps_a_definitive_failure_to_an_error_result() {
    // Directly: a definitively failed execution is a typed error, not a value.
    let port = Arc::new(RecordingExecution::failed());
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        port.clone(),
    );
    assert_eq!(
        run(
            &backend,
            execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Failed
    );
    assert_eq!(port.calls(), 1);

    // Through MCP: it renders as an error result, not a successful "failed"
    // value, and the port is still called exactly once.
    let mcp_port = Arc::new(RecordingExecution::failed());
    let server = server(mcp_port.clone(), true, true);
    let frame = mcp_server::tools_call_frame(EXECUTE_COMMAND).expect("frame");
    let response = server.handle(&frame).await;
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["result"]["isError"], Value::Bool(true));
    assert_eq!(
        parsed["result"]["content"][0]["text"],
        Value::String("command failed".to_string())
    );
    assert_eq!(mcp_port.calls(), 1);
}

#[tokio::test]
async fn execution_types_debug_is_payload_free() {
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 250, 100))),
        port.clone(),
    );
    let _ = run(
        &backend,
        execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT)),
    )
    .await;
    let (intent, quote, now_ms) = port.last();
    let request = MarketExecutionRequest {
        intent,
        quote,
        score: domain::RouteScore {
            gross_output: market_types::AssetAmount {
                asset: token(),
                amount: AtomicAmount::new(1),
            },
            simulated_net_output: market_types::AssetAmount {
                asset: token(),
                amount: AtomicAmount::new(1),
            },
            tax_cost: None,
            dex_fee: None,
            provider_fee: None,
            gas_cost: None,
            price_impact: Bps::new(1).expect("bps"),
            expected_slippage: Bps::new(1).expect("bps"),
            mev_risk: Bps::new(1).expect("bps"),
            failure_probability: Bps::new(1).expect("bps"),
            state_age_ms: 0,
            provider_reliability: Bps::new(1).expect("bps"),
            latency_ms: 0,
        },
        now_ms,
        router_source: RouterSource::Local,
    };
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("USDC"));
    assert!(!rendered.contains("1943762414"));
    let filled = MarketExecutionOutcome::Filled {
        net_input: 1_234,
        net_output: 5_678,
    };
    let rendered = format!("{filled:?}");
    assert!(!rendered.contains("1234"));
    assert!(!rendered.contains("5678"));
    assert!(!format!("{:?}", MarketExecutionError::Denied).contains("denied payload"));
}

/// Formats the exact parameters a `reconcile_market_order` call needs for the
/// same command that `execute` used.
fn reconcile_args(
    amount: AmountSpec,
) -> (
    agent_commands::AssetRef,
    agent_commands::AssetRef,
    TradeSide,
    AmountSpec,
    Option<u16>,
    Option<u16>,
    RouterSource,
) {
    (
        AssetRef::new(ChainId::Base, "USDC").expect("in"),
        AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        TradeSide::Buy,
        amount,
        None,
        None,
        // Reconcile parity tests use the Local path of the paired execute.
        RouterSource::Local,
    )
}

#[tokio::test]
async fn reconcile_market_order_uses_the_same_identity_as_execute() {
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        port.clone(),
    );
    let outcome = run(
        &backend,
        execute("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT)),
    )
    .await;
    let BackendOutcome::Value(value) = &outcome else {
        panic!("expected an execution value, got {outcome:?}");
    };
    assert_eq!(value["execution"]["state"], "submitted");
    // BR-10: the result echoes the bound routing source and a stable execution
    // id so the caller can attribute the submission honestly.
    assert_eq!(value["router_source"], "local");
    assert!(value["execution_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));

    let (token_in, token_out, side, amount, slippage, impact, router) =
        reconcile_args(AmountSpec::TokenAtomic(AMOUNT));
    let reconciled = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            token_in,
            token_out,
            side,
            amount,
            slippage,
            impact,
            router,
        )
        .await;

    assert_eq!(
        reconciled,
        BackendOutcome::Value(
            serde_json::json!({ "execution": { "state": "unknown" }, "router_source": "local" })
        )
    );
    assert_eq!(port.calls(), 1);
    assert_eq!(port.reconcile_calls(), 1);
    let (executed_intent, _, executed_now) = port.last();
    let (reconcile_key, reconcile_now) = port.last_reconcile();
    assert_eq!(
        reconcile_key, executed_intent.idempotency_key,
        "reconcile must re-derive the byte-identical deterministic identity"
    );
    assert_eq!(reconcile_now, executed_now);
    assert_eq!(reconcile_now, NOW);
}

#[tokio::test]
async fn reconcile_market_order_default_port_is_unknown() {
    // No `.with_market_execution(...)`: the default `UnavailableMarketExecution`
    // falls through to the trait's default `reconcile`, which fails closed to
    // `Unknown` rather than claiming an observation.
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(OneAssetValuation { asset: usdc() }),
    );
    let (token_in, token_out, side, amount, slippage, impact, router) =
        reconcile_args(AmountSpec::TokenAtomic(AMOUNT));
    let outcome = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            token_in,
            token_out,
            side,
            amount,
            slippage,
            impact,
            router,
        )
        .await;
    assert_eq!(
        outcome,
        BackendOutcome::Value(
            serde_json::json!({ "execution": { "state": "unknown" }, "router_source": "local" })
        )
    );
}

#[tokio::test]
async fn reconcile_market_order_surfaces_a_filled_observation() {
    let port = Arc::new(RecordingExecution::submitted().with_reconcile(Ok(
        MarketExecutionOutcome::Filled {
            net_input: 999,
            net_output: 123,
        },
    )));
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        port.clone(),
    );
    let (token_in, token_out, side, amount, slippage, impact, router) =
        reconcile_args(AmountSpec::TokenAtomic(AMOUNT));
    let outcome = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            token_in,
            token_out,
            side,
            amount,
            slippage,
            impact,
            router,
        )
        .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected an execution value, got {outcome:?}");
    };
    assert_eq!(
        value["execution"]["state"],
        Value::String("filled".to_string())
    );
    assert_eq!(amount_at(&value, &["execution", "net_input"]), 999);
    assert_eq!(amount_at(&value, &["execution", "net_output"]), 123);
    assert_eq!(port.calls(), 0, "reconcile must not require an execute");
}

#[tokio::test]
async fn reconcile_market_order_denies_structural_mismatch_without_the_port() {
    let port = Arc::new(RecordingExecution::submitted());
    let backend = backend_with(
        Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))),
        port.clone(),
    );
    let (token_in, token_out, side, amount, slippage, impact, router) =
        reconcile_args(AmountSpec::TokenAtomic(AMOUNT));

    // Same asset.
    let same_asset = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            token_in.clone(),
            token_in.clone(),
            side,
            amount,
            slippage,
            impact,
            router,
        )
        .await;
    assert_eq!(same_asset, BackendOutcome::Denied);

    // A USD amount needs a trusted conversion this layer does not perform.
    let usd = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            token_in.clone(),
            token_out.clone(),
            side,
            AmountSpec::UsdMicros(1),
            slippage,
            impact,
            router,
        )
        .await;
    assert_eq!(usd, BackendOutcome::Denied);

    // A foreign-chain pair.
    let foreign = backend
        .reconcile_market_order(
            AgentChannel::Mcp,
            AssetRef::new(ChainId::Solana, "USDC").expect("in"),
            token_out,
            side,
            amount,
            slippage,
            impact,
            router,
        )
        .await;
    assert_eq!(foreign, BackendOutcome::Denied);

    assert_eq!(
        port.reconcile_calls(),
        0,
        "denied reconciles must never reach the port"
    );
}
