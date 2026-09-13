//! Shared fixtures for the limit-engine integration tests.
#![allow(dead_code)]

use chain_types::{AssetId, ChainId};
use domain::{
    IdempotencyKey, IntentId, LimitOrder, LimitPrice, OrderId, OrderStatus, RiskConstraints,
    TradeSide, UserId, WalletRef,
};
use limit_engine::{
    apply_transition, AppendOutcome, FillDelta, LimitOrderStore, OrderTransition, StoredLimitOrder,
    DEFAULT_SCHEMA_VERSION,
};
use market_types::{AssetAmount, AtomicAmount, Bps, PriceRatio};

/// A deadline far enough in the future for ordinary transitions.
pub const EXPIRY_MS: i64 = 1_000_000;

/// Base-chain asset helper.
pub fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid asset")
}

/// Order id helper.
pub fn order_id(value: &str) -> OrderId {
    OrderId::new(value).expect("valid order id")
}

/// Idempotency-key helper.
pub fn idempotency_key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).expect("valid idempotency key")
}

/// A valid buy-side domain limit order.
pub fn limit_order(order: &str, status: OrderStatus, max: u128, remaining: u128) -> LimitOrder {
    let token_in = asset("USDC");
    let token_out = asset("TOKEN");
    LimitOrder {
        id: order_id(order),
        owner: UserId::new("u1").expect("valid owner"),
        wallet_ref: WalletRef::new("w1").expect("valid wallet"),
        chain: ChainId::Base,
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: TradeSide::Buy,
        max_input: AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(max),
        },
        remaining_input: AtomicAmount::new(remaining),
        limit_price: LimitPrice {
            numerator_asset: token_in,
            denominator_asset: token_out,
            ratio: PriceRatio::new(100, 25).expect("valid ratio"),
        },
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).expect("valid bps"),
            max_sell_tax: Bps::new(500).expect("valid bps"),
            max_price_impact: Bps::new(300).expect("valid bps"),
            max_slippage: Bps::new(200).expect("valid bps"),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        min_fill: AtomicAmount::new(1),
        expires_at_ms: EXPIRY_MS,
        status,
    }
}

/// A stored order with an explicit `filled_input` ledger.
pub fn stored(
    order: &str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    filled: u128,
) -> StoredLimitOrder {
    StoredLimitOrder {
        schema_version: DEFAULT_SCHEMA_VERSION,
        version: 1,
        order: limit_order(order, status, max, remaining),
        order_intent_id: IntentId::new(format!("intent-{order}")).expect("valid intent"),
        order_idempotency_key: idempotency_key(&format!("key-{order}")),
        nonce: 0,
        attempt_seq: 0,
        filled_input: AtomicAmount::new(filled),
        last_transition_seq: 0,
        next_eligible_at_ms: None,
    }
}

/// Builds the next record from the given order's current state, appends the
/// matching transition, and returns the applied record.
pub async fn apply_and_append_for<St: LimitOrderStore>(
    store: &St,
    order: &str,
    to: OrderStatus,
    fill: Option<FillDelta>,
    at_ms: i64,
) -> StoredLimitOrder {
    let current = store
        .load(&order_id(order))
        .await
        .expect("store load")
        .expect("order exists");
    let next = apply_transition(&current, to, fill.as_ref(), at_ms).expect("valid transition");
    let transition = OrderTransition {
        order_id: current.order.id.clone(),
        from: current.order.status,
        to,
        transition_seq: current.last_transition_seq + 1,
        fill,
        at_ms,
    };
    let outcome = store
        .append_transition(current.version, &transition, &next)
        .await
        .expect("append");
    assert!(
        matches!(outcome, AppendOutcome::Applied(_)),
        "expected Applied, got {outcome:?}"
    );
    next
}

/// Every `OrderStatus` variant, in declaration order.
pub const ALL_STATUSES: [OrderStatus; 12] = [
    OrderStatus::Created,
    OrderStatus::Active,
    OrderStatus::TriggerCandidate,
    OrderStatus::Quoting,
    OrderStatus::Simulating,
    OrderStatus::Executing,
    OrderStatus::PartiallyFilled,
    OrderStatus::Filled,
    OrderStatus::Cancelled,
    OrderStatus::Expired,
    OrderStatus::FailedRetryable,
    OrderStatus::FailedFinal,
];

/// The terminal statuses.
pub const TERMINAL_STATUSES: [OrderStatus; 4] = [
    OrderStatus::Filled,
    OrderStatus::Cancelled,
    OrderStatus::Expired,
    OrderStatus::FailedFinal,
];

/// The non-terminal statuses.
pub const OPEN_STATUSES: [OrderStatus; 8] = [
    OrderStatus::Created,
    OrderStatus::Active,
    OrderStatus::TriggerCandidate,
    OrderStatus::Quoting,
    OrderStatus::Simulating,
    OrderStatus::Executing,
    OrderStatus::PartiallyFilled,
    OrderStatus::FailedRetryable,
];
