//! P58 read-backend mapping, filtering, and fail-closed behavior.

use std::sync::Mutex;

use agent_backend::{
    parse_status_filter, AgentReadBackend, BackendError, BalanceEntry, BalanceProvider,
    ComposedPortfolioReadModel, DurableOrderReadModel, OrderReadModel, OrderSummary,
    PortfolioReadModel, PortfolioSummary,
};
use agent_commands::{AgentChannel, AgentCommand, ReadCommand, TradeCommand};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    LimitOrder, LimitPrice, OrderId, OrderStatus, RiskConstraints, TradeSide, UserId, WalletRef,
};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};
use mcp_server::{AgentBackend, BackendOutcome};

fn sample_summary() -> OrderSummary {
    OrderSummary {
        order_id: "o1".to_string(),
        wallet_ref: "w1".to_string(),
        chain: ChainId::Base,
        token_in: AssetId::new(ChainId::Base, "USDC").expect("asset"),
        token_out: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
        side: TradeSide::Buy,
        status: OrderStatus::Active,
        max_input: AtomicAmount::new(100),
        remaining_input: AtomicAmount::new(100),
        filled_input: AtomicAmount::new(0),
        min_fill: AtomicAmount::new(1),
        allow_partial_fill: true,
        limit_price: LimitPrice {
            numerator_asset: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            denominator_asset: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
            ratio: PriceRatio::new(100, 25).expect("ratio"),
        },
        expires_at_ms: 1_000_000,
        last_transition_seq: 0,
    }
}

#[derive(Default)]
struct FakeOrders {
    seen: Mutex<Vec<Option<OrderStatus>>>,
    result: Option<Result<Vec<OrderSummary>, BackendError>>,
}

impl FakeOrders {
    fn with_result(result: Result<Vec<OrderSummary>, BackendError>) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            result: Some(result),
        }
    }

    fn result(&self) -> Result<Vec<OrderSummary>, BackendError> {
        self.result.clone().unwrap_or(Ok(Vec::new()))
    }
}

#[async_trait]
impl OrderReadModel for FakeOrders {
    async fn list_orders(
        &self,
        status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, BackendError> {
        self.seen.lock().expect("lock").push(status);
        self.result()
    }
}

struct FakePortfolio {
    result: Result<PortfolioSummary, BackendError>,
}

#[async_trait]
impl PortfolioReadModel for FakePortfolio {
    async fn portfolio(&self) -> Result<PortfolioSummary, BackendError> {
        self.result.clone()
    }
}

#[tokio::test]
async fn get_orders_parses_the_filter_and_returns_the_projection() {
    let backend = AgentReadBackend::new(
        FakeOrders::with_result(Ok(vec![sample_summary()])),
        FakePortfolio {
            result: Ok(PortfolioSummary {
                balances: vec![],
                open_orders: 0,
                filled_orders: 0,
                total_orders: 0,
            }),
        },
    );

    let outcome = backend
        .execute(
            AgentChannel::Mcp,
            AgentCommand::Read(ReadCommand::GetOrders {
                status: Some("active".to_string()),
            }),
        )
        .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a value outcome");
    };
    assert_eq!(value["orders"][0]["order_id"], "o1");
    assert_eq!(value["orders"][0]["status"], "active");
    assert_eq!(value["orders"][0]["remaining_input"], 100);

    let outcome = backend
        .execute(
            AgentChannel::Mcp,
            AgentCommand::Read(ReadCommand::GetOrders { status: None }),
        )
        .await;
    assert!(matches!(outcome, BackendOutcome::Value(_)));
}

#[tokio::test]
async fn an_unknown_status_filter_is_denied_without_touching_the_port() {
    let backend = AgentReadBackend::new(
        FakeOrders::with_result(Ok(vec![])),
        FakePortfolio {
            result: Ok(PortfolioSummary {
                balances: vec![],
                open_orders: 0,
                filled_orders: 0,
                total_orders: 0,
            }),
        },
    );
    let outcome = backend
        .execute(
            AgentChannel::Mcp,
            AgentCommand::Read(ReadCommand::GetOrders {
                status: Some("not-a-status".to_string()),
            }),
        )
        .await;
    assert_eq!(outcome, BackendOutcome::Denied);
}

#[tokio::test]
async fn a_store_fault_is_reported_as_unavailable() {
    let backend = AgentReadBackend::new(
        FakeOrders::with_result(Err(BackendError::Unavailable)),
        FakePortfolio {
            result: Err(BackendError::Unavailable),
        },
    );
    assert_eq!(
        backend
            .execute(
                AgentChannel::Mcp,
                AgentCommand::Read(ReadCommand::GetOrders { status: None })
            )
            .await,
        BackendOutcome::Unavailable
    );
    assert_eq!(
        backend
            .execute(
                AgentChannel::Mcp,
                AgentCommand::Read(ReadCommand::GetPortfolio)
            )
            .await,
        BackendOutcome::Unavailable
    );
}

#[tokio::test]
async fn get_portfolio_returns_the_projection() {
    let backend = AgentReadBackend::new(
        FakeOrders::with_result(Ok(vec![])),
        FakePortfolio {
            result: Ok(PortfolioSummary {
                balances: vec![BalanceEntry {
                    asset: AssetId::new(ChainId::Base, "USDC").expect("asset"),
                    amount: AtomicAmount::new(7),
                }],
                open_orders: 2,
                filled_orders: 1,
                total_orders: 3,
            }),
        },
    );
    let outcome = backend
        .execute(
            AgentChannel::Mcp,
            AgentCommand::Read(ReadCommand::GetPortfolio),
        )
        .await;
    let BackendOutcome::Value(value) = outcome else {
        panic!("expected a value outcome");
    };
    assert_eq!(value["portfolio"]["open_orders"], 2);
    assert_eq!(value["portfolio"]["balances"][0]["amount"], 7);
}

#[tokio::test]
async fn unimplemented_reads_and_all_mutations_fail_closed() {
    let backend = AgentReadBackend::new(
        FakeOrders::with_result(Ok(vec![])),
        FakePortfolio {
            result: Ok(PortfolioSummary {
                balances: vec![],
                open_orders: 0,
                filled_orders: 0,
                total_orders: 0,
            }),
        },
    );
    assert_eq!(
        backend
            .execute(
                AgentChannel::Telegram,
                AgentCommand::Read(ReadCommand::SearchToken {
                    query: "anything".to_string()
                })
            )
            .await,
        BackendOutcome::Unavailable
    );
    assert_eq!(
        backend
            .execute(
                AgentChannel::Mcp,
                AgentCommand::Trade(TradeCommand::CancelOrder {
                    order_id: "o1".to_string()
                })
            )
            .await,
        BackendOutcome::Unavailable
    );
}

#[test]
fn status_filter_parsing_is_exact() {
    assert_eq!(parse_status_filter(None), Ok(None));
    assert_eq!(
        parse_status_filter(Some("partially_filled")),
        Ok(Some(OrderStatus::PartiallyFilled))
    );
    assert_eq!(
        parse_status_filter(Some("failed_retryable")),
        Ok(Some(OrderStatus::FailedRetryable))
    );
    assert_eq!(
        parse_status_filter(Some("filled")),
        Ok(Some(OrderStatus::Filled))
    );
    assert_eq!(
        parse_status_filter(Some("Active")),
        Err(BackendError::Denied)
    );
    assert_eq!(parse_status_filter(Some("")), Err(BackendError::Denied));
}

#[test]
fn order_summary_projects_the_durable_record() {
    let order = LimitOrder {
        id: OrderId::new("o1").expect("id"),
        owner: UserId::new("u1").expect("owner"),
        wallet_ref: WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        token_in: AssetId::new(ChainId::Base, "USDC").expect("asset"),
        token_out: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
        side: TradeSide::Buy,
        max_input: AssetAmount {
            asset: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            amount: AtomicAmount::new(100),
        },
        remaining_input: AtomicAmount::new(40),
        limit_price: LimitPrice {
            numerator_asset: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            denominator_asset: AssetId::new(ChainId::Base, "TOKEN").expect("asset"),
            ratio: PriceRatio::new(100, 25).expect("ratio"),
        },
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        min_fill: AtomicAmount::new(1),
        expires_at_ms: 1_000_000,
        status: OrderStatus::PartiallyFilled,
    };
    let record = limit_engine::StoredLimitOrder {
        schema_version: limit_engine::DEFAULT_SCHEMA_VERSION,
        version: 3,
        order,
        order_intent_id: domain::IntentId::new("i1").expect("intent"),
        order_idempotency_key: domain::IdempotencyKey::new("k1").expect("key"),
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(60),
        last_transition_seq: 2,
        published_seq: 2,
        next_eligible_at_ms: None,
    };
    let summary = OrderSummary::from_stored(&record);
    assert_eq!(summary.order_id, "o1");
    assert_eq!(summary.status, OrderStatus::PartiallyFilled);
    assert_eq!(summary.max_input, AtomicAmount::new(100));
    assert_eq!(summary.remaining_input, AtomicAmount::new(40));
    assert_eq!(summary.filled_input, AtomicAmount::new(60));
    assert_eq!(summary.last_transition_seq, 2);
}

#[tokio::test]
async fn composed_portfolio_aggregates_orders_and_balances() {
    let orders = FakeOrders::with_result(Ok(vec![
        sample_summary(),
        OrderSummary {
            status: OrderStatus::Filled,
            ..sample_summary()
        },
        OrderSummary {
            status: OrderStatus::Cancelled,
            ..sample_summary()
        },
    ]));
    let balances = FixedBalances {
        result: Ok(vec![BalanceEntry {
            asset: AssetId::new(ChainId::Base, "USDC").expect("asset"),
            amount: AtomicAmount::new(9),
        }]),
    };
    let portfolio = ComposedPortfolioReadModel::new(orders, balances);
    let summary = portfolio.portfolio().await.expect("portfolio");
    assert_eq!(summary.total_orders, 3);
    assert_eq!(summary.open_orders, 1);
    assert_eq!(summary.filled_orders, 1);
    assert_eq!(summary.balances[0].amount, AtomicAmount::new(9));
}

struct FixedBalances {
    result: Result<Vec<BalanceEntry>, BackendError>,
}

#[async_trait]
impl BalanceProvider for FixedBalances {
    async fn balances(&self) -> Result<Vec<BalanceEntry>, BackendError> {
        self.result.clone()
    }
}

/// The durable read model is a thin projection; it must compile and stay
/// owner-bound without a store fault leaking through.
#[allow(dead_code)]
fn durable_read_model_is_constructible<S: storage::OpaqueStore>(
    store: std::sync::Arc<limit_engine::DurableLimitOrderStore<S>>,
) -> DurableOrderReadModel<S> {
    DurableOrderReadModel::new(store, UserId::new("u1").expect("owner")).with_page(8)
}
