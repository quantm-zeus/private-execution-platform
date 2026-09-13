//! P65 durable limit-order write delegation: placement, idempotency,
//! cancellation, owner isolation, fail-closed paths, and trusted valuation.

use std::sync::Arc;

use agent_backend::{
    AgentReadBackend, BackendError, FixedClock, OrderReadModel, OrderSummary, OrderValuation,
    TradingAgentBackend, TradingBackendConfig, UnavailableOrderValuation,
    UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentChannel, AgentCommand, AmountSpec, AssetRef, LimitPriceSpec, TradeCommand,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    IdempotencyKey, IntentId, LimitOrder, LimitPrice, OrderId, OrderStatus, RiskConstraints,
    TradeSide, UserId, WalletRef,
};
use limit_engine::{
    InMemoryLimitOrderStore, LimitOrderStore, StoredLimitOrder, DEFAULT_SCHEMA_VERSION,
};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};
use mcp_server::{AgentBackend, BackendOutcome};

const NOW: i64 = 1_000_000;

#[derive(Default)]
struct FakeOrders;

#[async_trait]
impl OrderReadModel for FakeOrders {
    async fn list_orders(
        &self,
        _status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, BackendError> {
        Ok(Vec::new())
    }
}

/// A valuation that only knows one asset.
struct OneAssetValuation {
    asset: AssetId,
}

impl OrderValuation for OneAssetValuation {
    fn usd_micros(&self, asset: &AssetId, _amount: AtomicAmount) -> Option<u64> {
        (asset == &self.asset).then_some(7_000_000)
    }
}

fn usdc() -> AssetId {
    AssetId::new(ChainId::Base, "USDC").expect("asset")
}

fn token() -> AssetId {
    AssetId::new(ChainId::Base, "TOKEN").expect("asset")
}

fn config() -> TradingBackendConfig {
    TradingBackendConfig {
        owner: UserId::new("u1").expect("owner"),
        wallet_ref: WalletRef::new("w1").expect("wallet"),
        chain: ChainId::Base,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            max_total_cost: None,
        },
        min_fill: AtomicAmount::new(1),
    }
}

type Backend =
    TradingAgentBackend<FakeOrders, UnavailablePortfolioReadModel, InMemoryLimitOrderStore>;

fn backend() -> (Backend, Arc<InMemoryLimitOrderStore>) {
    let store = Arc::new(InMemoryLimitOrderStore::new());
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        store.clone(),
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(OneAssetValuation { asset: usdc() }),
    );
    (backend, store)
}

#[allow(clippy::too_many_arguments)]
fn place(
    input: &str,
    output: &str,
    side: TradeSide,
    amount: AmountSpec,
    numerator: u128,
    denominator: u128,
    allow_partial_fill: bool,
    expires_at_ms: i64,
) -> TradeCommand {
    TradeCommand::PlaceLimitOrder {
        token_in: AssetRef::new(ChainId::Base, input).expect("asset ref"),
        token_out: AssetRef::new(ChainId::Base, output).expect("asset ref"),
        side,
        amount,
        limit_price: LimitPriceSpec::new(numerator, denominator).expect("limit price"),
        allow_partial_fill,
        expires_at_ms,
    }
}

fn buy(amount: u128) -> TradeCommand {
    place(
        "USDC",
        "TOKEN",
        TradeSide::Buy,
        AmountSpec::TokenAtomic(amount),
        100,
        25,
        true,
        NOW + 60_000,
    )
}

async fn execute(backend: &Backend, command: TradeCommand) -> BackendOutcome {
    backend
        .execute(AgentChannel::Mcp, AgentCommand::Trade(command))
        .await
}

fn value(outcome: BackendOutcome) -> serde_json::Value {
    match outcome {
        BackendOutcome::Value(value) => value,
        other => panic!("expected a value outcome, got {other:?}"),
    }
}

fn order_value(outcome: BackendOutcome) -> serde_json::Value {
    value(outcome)["order"].clone()
}

fn order_id_of(value: &serde_json::Value) -> String {
    value["order_id"].as_str().expect("order id").to_string()
}

fn stored_order(
    owner: &str,
    order_id: &str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
) -> StoredLimitOrder {
    StoredLimitOrder {
        schema_version: DEFAULT_SCHEMA_VERSION,
        version: 1,
        order: LimitOrder {
            id: OrderId::new(order_id).expect("order id"),
            owner: UserId::new(owner).expect("owner"),
            wallet_ref: WalletRef::new("w-foreign").expect("wallet"),
            chain: ChainId::Base,
            token_in: usdc(),
            token_out: token(),
            side: TradeSide::Buy,
            max_input: AssetAmount {
                asset: usdc(),
                amount: AtomicAmount::new(max),
            },
            remaining_input: AtomicAmount::new(remaining),
            limit_price: LimitPrice {
                numerator_asset: usdc(),
                denominator_asset: token(),
                ratio: PriceRatio::new(1, 1).expect("ratio"),
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
            expires_at_ms: NOW + 60_000,
            status,
        },
        order_intent_id: IntentId::new(format!("intent-{order_id}")).expect("intent"),
        order_idempotency_key: IdempotencyKey::new(format!("key-{order_id}")).expect("key"),
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(filled),
        last_transition_seq: 0,
        published_seq: 0,
        next_eligible_at_ms: None,
    }
}

#[tokio::test]
async fn place_creates_a_durable_owner_scoped_created_order() {
    let (backend, store) = backend();
    let response = order_value(execute(&backend, buy(1_000)).await);
    let order_id = order_id_of(&response);
    assert!(order_id.starts_with("ord-"), "derived id: {order_id}");
    assert_eq!(response["status"], "created");
    assert_eq!(response["max_input"], 1_000);
    assert_eq!(response["remaining_input"], 1_000);
    assert_eq!(response["filled_input"], 0);
    assert_eq!(response["allow_partial_fill"], true);
    assert_eq!(response["expires_at_ms"], NOW + 60_000);

    let record = store
        .load(&OrderId::new(order_id).expect("order id"))
        .await
        .expect("load")
        .expect("record exists");
    assert_eq!(record.order.owner.as_str(), "u1");
    assert_eq!(record.order.wallet_ref.as_str(), "w1");
    assert_eq!(record.order.status, OrderStatus::Created);
    assert_eq!(record.order.token_in, usdc());
    assert_eq!(record.order.token_out, token());
    // Buy-side limit price: numerator is the input asset, denominator the output.
    assert_eq!(record.order.limit_price.numerator_asset, usdc());
    assert_eq!(record.order.limit_price.denominator_asset, token());
    assert_eq!(record.version, 1);
    assert_eq!(record.order.max_input.amount, AtomicAmount::new(1_000));
    assert_eq!(record.order.remaining_input, AtomicAmount::new(1_000));
    assert_eq!(record.filled_input, AtomicAmount::ZERO);
    assert!(record.order_idempotency_key.as_str().starts_with("idem-"));
    assert!(record.order_intent_id.as_str().starts_with("intent-"));
}

#[tokio::test]
async fn placing_the_same_command_twice_is_idempotent() {
    let (backend, store) = backend();
    let first = order_id_of(&order_value(execute(&backend, buy(1_000)).await));
    let second = order_id_of(&order_value(execute(&backend, buy(1_000)).await));
    assert_eq!(first, second);
    assert_eq!(store.list_open().await.expect("list").len(), 1);

    // A different amount is a different identity.
    let third = order_id_of(&order_value(execute(&backend, buy(2_000)).await));
    assert_ne!(first, third);
    assert_eq!(store.list_open().await.expect("list").len(), 2);
}

#[tokio::test]
async fn cancel_transitions_and_is_idempotent() {
    let (backend, store) = backend();
    let order_id = order_id_of(&order_value(execute(&backend, buy(1_000)).await));

    let cancelled = order_value(
        execute(
            &backend,
            TradeCommand::CancelOrder {
                order_id: order_id.clone(),
            },
        )
        .await,
    );
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(cancelled["last_transition_seq"], 1);
    let record = store
        .load(&OrderId::new(order_id.clone()).expect("order id"))
        .await
        .expect("load")
        .expect("record");
    assert_eq!(record.order.status, OrderStatus::Cancelled);
    assert_eq!(record.last_transition_seq, 1);

    // A repeated cancel is an idempotent success with no further transition.
    let again = order_value(execute(&backend, TradeCommand::CancelOrder { order_id }).await);
    assert_eq!(again["status"], "cancelled");
    assert_eq!(again["last_transition_seq"], 1);
    assert!(store.list_open().await.expect("list").is_empty());
}

#[tokio::test]
async fn cancel_of_unknown_foreign_or_terminal_orders_is_denied() {
    let (backend, store) = backend();

    assert_eq!(
        execute(
            &backend,
            TradeCommand::CancelOrder {
                order_id: "no-such-order".to_string(),
            },
        )
        .await,
        BackendOutcome::Denied
    );

    // A foreign owner's order is invisible to this backend.
    store
        .create(stored_order(
            "u2",
            "foreign-open",
            OrderStatus::Created,
            100,
            100,
            0,
        ))
        .await
        .expect("seed foreign order");
    assert_eq!(
        execute(
            &backend,
            TradeCommand::CancelOrder {
                order_id: "foreign-open".to_string(),
            },
        )
        .await,
        BackendOutcome::Denied
    );

    // A terminal (fully filled) order of our own cannot be cancelled.
    store
        .create(stored_order(
            "u1",
            "own-filled",
            OrderStatus::Filled,
            100,
            0,
            100,
        ))
        .await
        .expect("seed filled order");
    assert_eq!(
        execute(
            &backend,
            TradeCommand::CancelOrder {
                order_id: "own-filled".to_string(),
            },
        )
        .await,
        BackendOutcome::Denied
    );
}

#[tokio::test]
async fn sell_side_limit_price_orientation_is_inverted() {
    let (backend, store) = backend();
    let command = place(
        "TOKEN",
        "USDC",
        TradeSide::Sell,
        AmountSpec::TokenAtomic(500),
        9,
        2,
        true,
        NOW + 60_000,
    );
    let order_id = order_id_of(&order_value(execute(&backend, command).await));
    let record = store
        .load(&OrderId::new(order_id).expect("order id"))
        .await
        .expect("load")
        .expect("record");
    // Sell-side limit price: numerator is the output asset, denominator the input.
    assert_eq!(record.order.limit_price.numerator_asset, usdc());
    assert_eq!(record.order.limit_price.denominator_asset, token());
}

#[tokio::test]
async fn all_or_nothing_orders_require_the_full_amount() {
    let (backend, store) = backend();
    let command = place(
        "USDC",
        "TOKEN",
        TradeSide::Buy,
        AmountSpec::TokenAtomic(5_000),
        100,
        25,
        false,
        NOW + 60_000,
    );
    let order_id = order_id_of(&order_value(execute(&backend, command).await));
    let record = store
        .load(&OrderId::new(order_id).expect("order id"))
        .await
        .expect("load")
        .expect("record");
    assert!(!record.order.allow_partial_fill);
    assert_eq!(record.order.min_fill, AtomicAmount::new(5_000));
}

#[tokio::test]
async fn fail_closed_on_invalid_commands() {
    let (backend, _store) = backend();

    // Wrong chain.
    let wrong_chain = TradeCommand::PlaceLimitOrder {
        token_in: AssetRef::new(ChainId::Ethereum, "USDC").expect("ref"),
        token_out: AssetRef::new(ChainId::Ethereum, "TOKEN").expect("ref"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(100),
        limit_price: LimitPriceSpec::new(1, 1).expect("price"),
        allow_partial_fill: true,
        expires_at_ms: NOW + 60_000,
    };
    assert_eq!(execute(&backend, wrong_chain).await, BackendOutcome::Denied);

    // Same asset pair.
    assert_eq!(
        execute(
            &backend,
            place(
                "USDC",
                "USDC",
                TradeSide::Buy,
                AmountSpec::TokenAtomic(100),
                1,
                1,
                true,
                NOW + 60_000
            )
        )
        .await,
        BackendOutcome::Denied
    );

    // Zero amount.
    assert_eq!(execute(&backend, buy(0)).await, BackendOutcome::Denied);

    // USD amount has no conversion at this layer.
    assert_eq!(
        execute(
            &backend,
            place(
                "USDC",
                "TOKEN",
                TradeSide::Buy,
                AmountSpec::UsdMicros(1_000),
                1,
                1,
                true,
                NOW + 60_000,
            ),
        )
        .await,
        BackendOutcome::Denied
    );

    // Expired deadline.
    assert_eq!(
        execute(
            &backend,
            place(
                "USDC",
                "TOKEN",
                TradeSide::Buy,
                AmountSpec::TokenAtomic(100),
                1,
                1,
                true,
                NOW
            )
        )
        .await,
        BackendOutcome::Denied
    );

    // A zero ratio is invalid even when constructed directly.
    let zero_ratio = TradeCommand::PlaceLimitOrder {
        token_in: AssetRef::new(ChainId::Base, "USDC").expect("ref"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("ref"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(100),
        limit_price: LimitPriceSpec {
            numerator_atomic: 0,
            denominator_atomic: 0,
        },
        allow_partial_fill: true,
        expires_at_ms: NOW + 60_000,
    };
    assert_eq!(execute(&backend, zero_ratio).await, BackendOutcome::Denied);

    // Invalid order id.
    assert_eq!(
        execute(
            &backend,
            TradeCommand::CancelOrder {
                order_id: "   ".to_string(),
            },
        )
        .await,
        BackendOutcome::Denied
    );
}

#[tokio::test]
async fn market_commands_fail_closed() {
    let (backend, _store) = backend();
    let preview = TradeCommand::PreviewMarketOrder {
        token_in: AssetRef::new(ChainId::Base, "USDC").expect("ref"),
        token_out: AssetRef::new(ChainId::Base, "TOKEN").expect("ref"),
        side: TradeSide::Buy,
        amount: AmountSpec::TokenAtomic(100),
        max_slippage_bps: None,
        max_price_impact_bps: None,
    };
    assert_eq!(
        execute(&backend, preview.clone()).await,
        BackendOutcome::Unavailable
    );
    let execute_market = match preview {
        TradeCommand::PreviewMarketOrder {
            token_in,
            token_out,
            side,
            amount,
            max_slippage_bps,
            max_price_impact_bps,
        } => TradeCommand::ExecuteMarketOrder {
            token_in,
            token_out,
            side,
            amount,
            max_slippage_bps,
            max_price_impact_bps,
        },
        _ => unreachable!(),
    };
    assert_eq!(
        execute(&backend, execute_market).await,
        BackendOutcome::Unavailable
    );
}

#[tokio::test]
async fn valuation_is_trusted_and_fail_closed() {
    let (backend, _store) = backend();
    let known = AgentCommand::Trade(buy(1_000));
    assert_eq!(backend.valuation_usd_micros(&known).await, Some(7_000_000));

    // USD amounts are already valued.
    let usd = AgentCommand::Trade(place(
        "USDC",
        "TOKEN",
        TradeSide::Buy,
        AmountSpec::UsdMicros(123),
        1,
        1,
        true,
        NOW + 60_000,
    ));
    assert_eq!(backend.valuation_usd_micros(&usd).await, Some(123));

    // Cancellation moves no funds.
    let cancel = AgentCommand::Trade(TradeCommand::CancelOrder {
        order_id: "o".to_string(),
    });
    assert_eq!(backend.valuation_usd_micros(&cancel).await, Some(0));

    // An unknown token cannot be valued.
    let unknown = AgentCommand::Trade(place(
        "MYSTERY",
        "TOKEN",
        TradeSide::Buy,
        AmountSpec::TokenAtomic(100),
        1,
        1,
        true,
        NOW + 60_000,
    ));
    assert_eq!(backend.valuation_usd_micros(&unknown).await, None);

    // Reads are never valued.
    let read = AgentCommand::Read(agent_commands::ReadCommand::GetPortfolio);
    assert_eq!(backend.valuation_usd_micros(&read).await, None);
}

#[tokio::test]
async fn unavailable_valuation_port_stays_fail_closed() {
    let store = Arc::new(InMemoryLimitOrderStore::new());
    let reads = AgentReadBackend::new(FakeOrders, UnavailablePortfolioReadModel::new());
    let backend = TradingAgentBackend::new(
        reads,
        store,
        config(),
        Arc::new(FixedClock(NOW)),
        Arc::new(UnavailableOrderValuation),
    );
    let command = AgentCommand::Trade(buy(1_000));
    assert_eq!(backend.valuation_usd_micros(&command).await, None);
}

#[test]
fn debug_output_is_redacted() {
    let (backend, _store) = backend();
    let rendered = format!("{backend:?}");
    assert!(!rendered.contains("u1"));
    assert!(!rendered.contains("w1"));
    assert!(!rendered.contains("USDC"));

    let config = format!("{:?}", config());
    assert!(!config.contains("u1"));
    assert!(!config.contains("w1"));
}

#[tokio::test]
async fn reads_still_delegate_through_the_write_backend() {
    let (backend, _store) = backend();
    // `get_portfolio` is backed by the fail-closed portfolio port here.
    let outcome = backend
        .execute(
            AgentChannel::Telegram,
            AgentCommand::Read(agent_commands::ReadCommand::GetPortfolio),
        )
        .await;
    assert_eq!(outcome, BackendOutcome::Unavailable);
}
