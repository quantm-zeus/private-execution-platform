//! P68 exact market-order preview delegation: full net economics, fail-closed
//! paths, trusted cap binding, redaction, and trading-disabled availability.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use agent_backend::{
    AgentReadBackend, FixedClock, MarketPreviewError, MarketSnapshot, MarketSnapshotSource,
    OrderReadModel, OrderSummary, TradingAgentBackend, TradingBackendConfig,
    UnavailableOrderValuation, UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentCapabilities, AgentChannel, AgentCommand, AmountSpec, AssetRef, RouterSource, TradeCommand,
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
use routing::{
    GasConversion, GasEstimator, PoolDescriptor, PoolRefLabel, RoutingError, ScoringInputs,
    VenueLabel,
};
use serde_json::Value;
use tax_engine::TaxAssessment;

const NOW: i64 = 1_000_000;
const AMOUNT: u128 = 1_000_000_000;
// Buy USDC -> TOKEN: 30 bps fee, 250 bps output tax.
const BUY_FEE: u128 = 3_000_000;
const BUY_GROSS: u128 = 1_993_602_475;
const BUY_TAX: u128 = 49_840_061;
const BUY_NET: u128 = 1_943_762_414;
// Sell TOKEN -> USDC: 30 bps fee, 100 bps input tax.
const SELL_FEE: u128 = 2_970_000;
const SELL_TAX: u128 = 10_000_000;
const SELL_OUT: u128 = 493_466_293;

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

/// A thin CPMM pool where the pinned preview amount has a ~4992 bps impact,
/// well above the trusted 300 bps impact cap. Kept separate from [`pool`] so
/// the pinned-economics tests keep their exact reference state.
fn high_impact_pool() -> PoolDescriptor {
    PoolDescriptor {
        envelope: PoolStateEnvelope {
            pool_id: PoolId::new(ChainId::Base, "pool-2").expect("pool id"),
            sequence: Sequence(1),
            observed_at_ms: NOW,
            state: PoolKindState::Cpmm(CpmmPoolState {
                token_0: usdc(),
                token_1: token(),
                decimals_0: 6,
                decimals_1: 18,
                reserve_0: AtomicAmount::new(1_000_000_000),
                reserve_1: AtomicAmount::new(10_000_000_000_000),
                total_lp_supply: None,
                fee_bps: Bps::new(30).expect("fee"),
            }),
        },
        venue: VenueLabel::new("uniswap").expect("venue"),
        leg_pool_ref: PoolRefLabel::new("pool-2").expect("pool ref"),
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

/// Records every intent it is asked to quote and serves one static snapshot.
struct StaticSnapshot {
    descriptors: Vec<PoolDescriptor>,
    assessment: TaxAssessment,
    max_hops: usize,
    gas_price: Option<GasConversion>,
    seen: Mutex<Vec<TradeIntent>>,
}

impl StaticSnapshot {
    fn new(assessment: TaxAssessment) -> Self {
        Self {
            descriptors: vec![pool()],
            assessment,
            max_hops: 1,
            gas_price: None,
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
            max_hops: self.max_hops,
            gas_price_in_output: self.gas_price.clone(),
        })
    }
}

type Backend =
    TradingAgentBackend<FakeOrders, UnavailablePortfolioReadModel, InMemoryLimitOrderStore>;

fn backend_with(source: Arc<StaticSnapshot>) -> Backend {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    )
    .with_market_snapshot(source)
}

fn preview(token_in: &str, token_out: &str, side: TradeSide, amount: AmountSpec) -> TradeCommand {
    TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Base, token_in).expect("in"),
        token_out: AssetRef::new(ChainId::Base, token_out).expect("out"),
        side,
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
async fn preview_buy_reports_exact_net_economics() {
    let source = Arc::new(StaticSnapshot::new(assessment(token(), 250, 100)));
    let backend = backend_with(source.clone());
    let outcome = run(
        &backend,
        preview(
            "USDC",
            "TOKEN",
            TradeSide::Buy,
            AmountSpec::TokenAtomic(AMOUNT),
        ),
    )
    .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a preview value, got {outcome:?}");
    };
    let preview = &value["preview"];
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_input", "amount"]),
        AMOUNT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "gross_output", "amount"]),
        BUY_GROSS
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_output", "amount"]),
        BUY_NET
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "tax_cost", "amount"]),
        BUY_TAX
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "dex_fee", "amount"]),
        BUY_FEE
    );
    // The score's primary truth is the same simulated net output.
    assert_eq!(
        amount_at(preview, &["score", "simulated_net_output", "amount"]),
        BUY_NET
    );
    assert_eq!(
        preview["quote"]["plan"]["legs"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(preview["truncated"], Value::Bool(false));

    // The router saw a trusted, well-formed intent built from the config.
    let intents = source.seen();
    assert_eq!(intents.len(), 1);
    let intent = &intents[0];
    assert_eq!(intent.source, domain::TradeSource::Mcp);
    assert_eq!(intent.side, TradeSide::Buy);
    assert_eq!(intent.order_type, domain::OrderType::Market);
    assert_eq!(intent.amount_type, domain::AmountType::InputAssetAtomic);
    assert_eq!(intent.amount, AtomicAmount::new(AMOUNT));
    assert_eq!(intent.limit_price, None);
    assert_eq!(intent.risk.max_price_impact, Bps::new(300).expect("bps"));
    assert_eq!(intent.risk.max_slippage, Bps::new(200).expect("bps"));
    assert!(!intent.allow_partial_fill);
}

#[tokio::test]
async fn preview_sell_charges_input_side_tax() {
    let source = Arc::new(StaticSnapshot::new(assessment(token(), 250, 100)));
    let backend = backend_with(source);
    let outcome = run(
        &backend,
        preview(
            "TOKEN",
            "USDC",
            TradeSide::Sell,
            AmountSpec::TokenAtomic(AMOUNT),
        ),
    )
    .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a preview value");
    };
    let preview = &value["preview"];
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_input", "amount"]),
        AMOUNT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "tax_cost", "amount"]),
        SELL_TAX
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "dex_fee", "amount"]),
        SELL_FEE
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "gross_output", "amount"]),
        SELL_OUT
    );
    assert_eq!(
        amount_at(preview, &["quote", "net_delta", "net_output", "amount"]),
        SELL_OUT
    );
}

#[tokio::test]
async fn preview_is_deterministic() {
    let backend = backend_with(Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))));
    let command = || {
        preview(
            "USDC",
            "TOKEN",
            TradeSide::Buy,
            AmountSpec::TokenAtomic(AMOUNT),
        )
    };
    let first = run(&backend, command()).await;
    let second = run(&backend, command()).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn preview_fails_closed_without_a_snapshot() {
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        Arc::new(InMemoryLimitOrderStore::new()),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    );
    let outcome = run(
        &backend,
        preview(
            "USDC",
            "TOKEN",
            TradeSide::Buy,
            AmountSpec::TokenAtomic(AMOUNT),
        ),
    )
    .await;
    assert_eq!(outcome, BackendOutcome::Unavailable);
}

#[tokio::test]
async fn preview_rejects_structural_denials() {
    let backend = backend_with(Arc::new(StaticSnapshot::new(assessment(token(), 0, 0))));
    // Same asset pair.
    assert_eq!(
        run(
            &backend,
            preview("USDC", "USDC", TradeSide::Buy, AmountSpec::TokenAtomic(1))
        )
        .await,
        BackendOutcome::Denied
    );
    // Zero amount.
    assert_eq!(
        run(
            &backend,
            preview("USDC", "TOKEN", TradeSide::Buy, AmountSpec::TokenAtomic(0))
        )
        .await,
        BackendOutcome::Denied
    );
    // A USD amount needs a trusted conversion this layer does not perform.
    assert_eq!(
        run(
            &backend,
            preview("USDC", "TOKEN", TradeSide::Buy, AmountSpec::UsdMicros(1))
        )
        .await,
        BackendOutcome::Denied
    );
    // A foreign-chain token is outside the configured chain.
    let foreign = TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Solana, "USDC").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: None,
        max_price_impact_bps: None,
        router: RouterSource::Local,
    };
    assert_eq!(run(&backend, foreign).await, BackendOutcome::Denied);
}

#[tokio::test]
async fn preview_enforces_trusted_caps() {
    let source = Arc::new(StaticSnapshot::new(assessment(token(), 0, 0)));
    let backend = backend_with(source.clone());
    let capped = |slippage: u16, impact: u16| TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "USDC").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: Some(slippage),
        max_price_impact_bps: Some(impact),
        router: RouterSource::Local,
    };
    // Looser than the wallet hard cap: denied, not clamped.
    assert_eq!(
        run(&backend, capped(201, 300)).await,
        BackendOutcome::Denied
    );
    assert_eq!(
        run(&backend, capped(200, 301)).await,
        BackendOutcome::Denied
    );
    // A requested zero is the router's unbounded-impact sentinel (and is
    // ambiguous for slippage), so it fails closed for both caps.
    assert_eq!(run(&backend, capped(0, 300)).await, BackendOutcome::Denied);
    assert_eq!(run(&backend, capped(200, 0)).await, BackendOutcome::Denied);
    assert_eq!(run(&backend, capped(0, 0)).await, BackendOutcome::Denied);
    // Exactly at and below the cap: honored.
    assert!(matches!(
        run(&backend, capped(200, 300)).await,
        BackendOutcome::Value(_)
    ));
    assert!(matches!(
        run(&backend, capped(100, 50)).await,
        BackendOutcome::Value(_)
    ));
    let seen = source.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].risk.max_slippage, Bps::new(200).expect("bps"));
    assert_eq!(seen[0].risk.max_price_impact, Bps::new(300).expect("bps"));
    assert_eq!(seen[1].risk.max_slippage, Bps::new(100).expect("bps"));
    assert_eq!(seen[1].risk.max_price_impact, Bps::new(50).expect("bps"));
}

#[tokio::test]
async fn preview_zero_impact_cap_cannot_disable_the_trusted_cap() {
    // A high-impact route (~4992 bps) against the trusted 300 bps impact cap.
    let mut source = StaticSnapshot::new(assessment(token(), 0, 0));
    source.descriptors = vec![high_impact_pool()];
    let backend = backend_with(Arc::new(source));
    let capped = |slippage: Option<u16>, impact: Option<u16>| TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "USDC").expect("in"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("out"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(AMOUNT),
        max_slippage_bps: slippage,
        max_price_impact_bps: impact,
        router: RouterSource::Local,
    };

    // The trusted cap alone rejects the route.
    assert_eq!(
        run(&backend, capped(None, None)).await,
        BackendOutcome::Denied
    );
    // An explicit cap at the trusted limit still rejects the route...
    assert_eq!(
        run(&backend, capped(None, Some(300))).await,
        BackendOutcome::Denied
    );
    // ...and a zero request must not be forwarded as "unbounded".
    assert_eq!(
        run(&backend, capped(None, Some(0))).await,
        BackendOutcome::Denied
    );
    // A zero slippage request is likewise rejected before any routing.
    assert_eq!(
        run(&backend, capped(Some(0), None)).await,
        BackendOutcome::Denied
    );
}

#[tokio::test]
async fn preview_maps_router_failures_fail_closed() {
    // A zero hop count is a configuration error -> unavailable.
    let mut source = StaticSnapshot::new(assessment(token(), 0, 0));
    source.max_hops = 0;
    let backend = backend_with(Arc::new(source));
    assert_eq!(
        run(
            &backend,
            preview(
                "USDC",
                "TOKEN",
                TradeSide::Buy,
                AmountSpec::TokenAtomic(AMOUNT)
            )
        )
        .await,
        BackendOutcome::Unavailable
    );

    // An empty pool set is a genuine no-route -> denied.
    let mut empty = StaticSnapshot::new(assessment(token(), 0, 0));
    empty.descriptors = Vec::new();
    let backend = backend_with(Arc::new(empty));
    assert_eq!(
        run(
            &backend,
            preview(
                "USDC",
                "TOKEN",
                TradeSide::Buy,
                AmountSpec::TokenAtomic(AMOUNT)
            )
        )
        .await,
        BackendOutcome::Denied
    );
}

#[tokio::test]
async fn preview_is_available_while_trading_is_disabled() {
    let source = Arc::new(StaticSnapshot::new(assessment(token(), 0, 0)));
    let backend = backend_with(source);
    let mut chains = HashSet::new();
    chains.insert(ChainId::Base);
    let server = McpServer::new(backend, AgentCapabilities::new(false, chains, 0));

    let command = r#"{"tool":"preview_market_order","token_in":{"chain":{"kind":"base"},"address":"USDC"},"token_out":{"chain":{"kind":"base"},"address":"TOKEN"},"side":"buy","amount":{"unit":"token_atomic","value":1000000000},"router_preference":"local"}"#;
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
    assert!(text.get("preview").is_some());

    // A mutating command is still denied while trading is disabled.
    let place = r#"{"tool":"place_limit_order","token_in":{"chain":{"kind":"base"},"address":"USDC"},"token_out":{"chain":{"kind":"base"},"address":"TOKEN"},"side":"buy","amount":{"unit":"token_atomic","value":1000000000},"limit_price":{"numerator_atomic":1,"denominator_atomic":1},"allow_partial_fill":true,"expires_at_ms":2000000}"#;
    let frame = mcp_server::tools_call_frame(place).expect("frame");
    let response = server.handle(&frame).await;
    let parsed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(parsed["result"]["isError"], Value::Bool(true));
    assert_eq!(
        parsed["result"]["content"][0]["text"],
        Value::String("TradingDisabled".to_string())
    );
}

#[tokio::test]
async fn preview_debug_is_payload_free() {
    use domain::{IdempotencyKey, IntentId, RiskConstraints, TradeSource, UserId, WalletRef};

    let source = Arc::new(StaticSnapshot::new(assessment(token(), 250, 100)));
    let intent = TradeIntent {
        id: IntentId::new("i").expect("id"),
        source: TradeSource::Mcp,
        user_id: UserId::new("u1").expect("u"),
        wallet_ref: WalletRef::new("w1").expect("w"),
        chain: ChainId::Base,
        token_in: usdc(),
        token_out: token(),
        side: TradeSide::Buy,
        amount_type: domain::AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(AMOUNT),
        order_type: domain::OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(1_000).expect("bps"),
            max_sell_tax: Bps::new(1_000).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: false,
        expiry_ms: None,
        nonce: 0,
        idempotency_key: IdempotencyKey::new("k").expect("k"),
    };

    // Snapshot Debug must not leak assets, pool refs, or amounts.
    let snapshot = source
        .snapshot(&intent, AtomicAmount::new(AMOUNT), NOW)
        .expect("snapshot");
    let rendered = format!("{snapshot:?}");
    assert!(!rendered.contains("USDC"));
    assert!(!rendered.contains("pool-1"));
    assert!(!rendered.contains("1993602475"));

    // The composed preview Debug is payload-free even though its Serialize form
    // is the authenticated response body.
    let preview = agent_backend::plan_market_preview(
        source.as_ref(),
        None,
        &intent,
        AtomicAmount::new(AMOUNT),
        NOW,
    )
    .expect("preview");
    let rendered = format!("{preview:?}");
    assert!(!rendered.contains("USDC"));
    assert!(!rendered.contains("TOKEN"));
    assert!(!rendered.contains("1993602475"));
    assert!(!rendered.contains("1943762414"));
    assert!(rendered.contains("MarketPreview"));
}

struct FixedGas {
    asset: AssetId,
    per_hop: u128,
}

impl GasEstimator for FixedGas {
    fn estimate_gas(
        &self,
        _chain: &ChainId,
        hop_count: usize,
    ) -> Result<market_types::AssetAmount, RoutingError> {
        Ok(market_types::AssetAmount {
            asset: self.asset.clone(),
            amount: AtomicAmount::new(self.per_hop.saturating_mul(hop_count as u128)),
        })
    }
}

#[tokio::test]
async fn preview_carries_a_gas_view_into_the_score() {
    let mut source = StaticSnapshot::new(assessment(token(), 0, 0));
    // Price gas (USDC) in the route output asset (TOKEN), 1:2.
    source.gas_price = Some(GasConversion {
        gas_asset: usdc(),
        output_asset: token(),
        ratio: market_types::PriceRatio::new(1, 2).expect("ratio"),
    });
    let backend = backend_with(Arc::new(source)).with_gas_estimator(Arc::new(FixedGas {
        asset: usdc(),
        per_hop: 1_000,
    }));
    let outcome = run(
        &backend,
        preview(
            "USDC",
            "TOKEN",
            TradeSide::Buy,
            AmountSpec::TokenAtomic(AMOUNT),
        ),
    )
    .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a gas-aware preview");
    };
    // The gas cost is denominated in the gas asset (USDC) on the score.
    assert_eq!(
        amount_at(&value["preview"], &["score", "gas_cost", "amount"]),
        1_000
    );
}
