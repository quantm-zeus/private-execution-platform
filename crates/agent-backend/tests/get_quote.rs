//! P71 `get_quote` delegation: exact buy-direction economics, fail-closed
//! defaults, structural denials, trading-disabled availability, and that the
//! execution port is never touched.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_backend::{
    AgentReadBackend, FixedClock, MarketExecutionError, MarketExecutionOutcome,
    MarketExecutionPort, MarketExecutionRequest, MarketPreviewError, MarketSnapshot,
    MarketSnapshotSource, OrderReadModel, OrderSummary, TradingAgentBackend, TradingBackendConfig,
    UnavailableOrderValuation, UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentCapabilities, AgentChannel, AgentCommand, AmountSpec, AssetRef, ReadCommand,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{OrderStatus, TradeIntent, TradeSide};
use limit_engine::InMemoryLimitOrderStore;
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessPolicy, FreshnessStatus, PoolId, PoolKindState,
    PoolStateEnvelope, SafeFreshnessMeta, Sequence,
};
use mcp_server::{AgentBackend, BackendOutcome, McpServer};
use routing::{PoolDescriptor, PoolRefLabel, ScoringInputs, VenueLabel};
use serde_json::Value;
use tax_engine::TaxAssessment;

const NOW: i64 = 1_000_000;
const AMOUNT: u128 = 1_000_000_000;
const BUY_GROSS: u128 = 1_993_602_475;
const BUY_TAX: u128 = 49_840_061;
const BUY_NET: u128 = 1_943_762_414;
const BUY_FEE: u128 = 3_000_000;

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

fn assessment(asset: AssetId) -> TaxAssessment {
    TaxAssessment::new(
        asset,
        ChainId::Base,
        Bps::new(250).expect("buy"),
        Bps::new(100).expect("sell"),
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
    seen: Mutex<Vec<TradeIntent>>,
}

impl StaticSnapshot {
    fn new(assessment: TaxAssessment) -> Self {
        Self {
            descriptors: vec![pool()],
            assessment,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<TradeIntent> {
        self.seen.lock().expect("lock").clone()
    }
}

impl MarketSnapshotSource for StaticSnapshot {
    fn snapshot(
        &self,
        intent: &TradeIntent,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> Result<MarketSnapshot, MarketPreviewError> {
        self.seen.lock().expect("lock").push(intent.clone());
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

/// An execution port that panics if reached: `get_quote` must never touch it.
struct PanicExecution {
    calls: AtomicUsize,
}

impl PanicExecution {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl MarketExecutionPort for PanicExecution {
    async fn execute(
        &self,
        _request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("get_quote must not touch the execution port");
    }
}

type Backend =
    TradingAgentBackend<FakeOrders, UnavailablePortfolioReadModel, InMemoryLimitOrderStore>;

fn backend_with(source: Arc<StaticSnapshot>, execution: Arc<PanicExecution>) -> Backend {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    )
    .with_market_snapshot(source)
    .with_market_execution(execution)
}

fn get_quote(token_in: &str, token_out: &str, amount: AmountSpec) -> AgentCommand {
    AgentCommand::Read(ReadCommand::GetQuote {
        token_in: AssetRef::new(ChainId::Base, token_in).expect("in"),
        token_out: AssetRef::new(ChainId::Base, token_out).expect("out"),
        amount,
    })
}

async fn run(backend: &Backend, command: AgentCommand) -> BackendOutcome {
    backend.execute(AgentChannel::Mcp, command).await
}

fn amount_at(value: &Value, path: &[&str]) -> u128 {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key).expect("path");
    }
    cursor.as_u64().expect("u64 amount") as u128
}

#[tokio::test]
async fn get_quote_returns_exact_buy_direction_economics() {
    let source = Arc::new(StaticSnapshot::new(assessment(token())));
    let port = Arc::new(PanicExecution::new());
    let backend = backend_with(source.clone(), port.clone());
    let outcome = run(
        &backend,
        get_quote("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT)),
    )
    .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a quote value, got {outcome:?}");
    };
    let quote = &value["quote"];
    assert_eq!(
        amount_at(quote, &["quote", "net_delta", "net_input", "amount"]),
        AMOUNT
    );
    assert_eq!(
        amount_at(quote, &["quote", "net_delta", "gross_output", "amount"]),
        BUY_GROSS
    );
    assert_eq!(
        amount_at(quote, &["quote", "net_delta", "net_output", "amount"]),
        BUY_NET
    );
    assert_eq!(
        amount_at(quote, &["quote", "net_delta", "tax_cost", "amount"]),
        BUY_TAX
    );
    assert_eq!(
        amount_at(quote, &["quote", "net_delta", "dex_fee", "amount"]),
        BUY_FEE
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);

    // The router saw a trusted Buy intent built from the config.
    let seen = source.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].side, TradeSide::Buy);
    assert_eq!(seen[0].source, domain::TradeSource::Mcp);
    assert_eq!(seen[0].amount, AtomicAmount::new(AMOUNT));
    assert_eq!(seen[0].risk.max_price_impact, Bps::new(300).expect("bps"));
}

#[tokio::test]
async fn get_quote_rejects_structural_denials() {
    let source = Arc::new(StaticSnapshot::new(assessment(token())));
    let port = Arc::new(PanicExecution::new());
    let backend = backend_with(source.clone(), port.clone());
    // Same asset.
    assert_eq!(
        run(
            &backend,
            get_quote("USDC", "USDC", AmountSpec::TokenAtomic(1))
        )
        .await,
        BackendOutcome::Denied
    );
    // Zero amount.
    assert_eq!(
        run(
            &backend,
            get_quote("USDC", "TOKEN", AmountSpec::TokenAtomic(0))
        )
        .await,
        BackendOutcome::Denied
    );
    // A USD amount needs a trusted conversion this layer does not perform.
    assert_eq!(
        run(
            &backend,
            get_quote("USDC", "TOKEN", AmountSpec::UsdMicros(1))
        )
        .await,
        BackendOutcome::Denied
    );
    // A foreign-chain pair.
    assert_eq!(
        run(
            &backend,
            AgentCommand::Read(ReadCommand::GetQuote {
                token_in: AssetRef::new(ChainId::Solana, "USDC").expect("in"),
                token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
                amount: AmountSpec::TokenAtomic(AMOUNT),
            })
        )
        .await,
        BackendOutcome::Denied
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn get_quote_fails_closed_without_a_snapshot() {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    );
    assert_eq!(
        run(
            &backend,
            get_quote("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Unavailable
    );
}

#[tokio::test]
async fn get_quote_no_route_is_denied() {
    let mut source = StaticSnapshot::new(assessment(token()));
    source.descriptors = Vec::new();
    let port = Arc::new(PanicExecution::new());
    let backend = backend_with(Arc::new(source), port.clone());
    assert_eq!(
        run(
            &backend,
            get_quote("USDC", "TOKEN", AmountSpec::TokenAtomic(AMOUNT))
        )
        .await,
        BackendOutcome::Denied
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn get_quote_is_available_while_trading_is_disabled() {
    let source = Arc::new(StaticSnapshot::new(assessment(token())));
    let port = Arc::new(PanicExecution::new());
    let backend = backend_with(source, port);
    let mut chains = HashSet::new();
    chains.insert(ChainId::Base);
    let server = McpServer::new(backend, AgentCapabilities::new(false, chains, 0));
    let command = r#"{"tool":"get_quote","token_in":{"chain":{"kind":"base"},"address":"USDC"},"token_out":{"chain":{"kind":"base"},"address":"TOKEN"},"amount":{"unit":"token_atomic","value":1000000000}}"#;
    let frame = mcp_server::tools_call_frame(command).expect("frame");
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
        amount_at(
            &text,
            &["quote", "quote", "net_delta", "net_output", "amount"]
        ),
        BUY_NET
    );
}
