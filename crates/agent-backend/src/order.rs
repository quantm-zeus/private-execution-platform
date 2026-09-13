//! Owner-scoped order read model and its JSON projection.

use std::sync::Arc;

use async_trait::async_trait;
use chain_types::AssetId;
use domain::{LimitPrice, OrderStatus, TradeSide, UserId};
use limit_engine::{DurableLimitOrderStore, StoredLimitOrder};
use market_types::AtomicAmount;
use serde::Serialize;
use storage::OpaqueStore;

use crate::error::BackendError;

/// Default maximum number of orders one listing returns.
///
/// Kept well under [`limit_engine::MAX_OWNER_ORDERS`]: a chat/MCP response is
/// small, and the store's own cap is the hard ceiling.
pub const DEFAULT_ORDER_PAGE: usize = 64;

/// A user-facing projection of one durable limit order.
///
/// Deliberately omits engine bookkeeping that carries no user meaning (the
/// creation-baseline version, the outbox watermark, the internal intent id).
/// Serializing it is safe only on the authenticated response path; it must never
/// become a telemetry label (PRD line 83).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OrderSummary {
    /// Order identifier.
    pub order_id: String,
    /// Wallet the order trades from.
    pub wallet_ref: String,
    /// Chain the order is bound to.
    pub chain: chain_types::ChainId,
    /// Input asset.
    pub token_in: AssetId,
    /// Output asset.
    pub token_out: AssetId,
    /// Trade direction.
    pub side: TradeSide,
    /// Current lifecycle status.
    pub status: OrderStatus,
    /// Maximum input the order may consume.
    pub max_input: AtomicAmount,
    /// Input still available to fill.
    pub remaining_input: AtomicAmount,
    /// Input already filled.
    pub filled_input: AtomicAmount,
    /// Minimum acceptable partial fill.
    pub min_fill: AtomicAmount,
    /// Whether a partial fill is permitted.
    pub allow_partial_fill: bool,
    /// Locked net limit price.
    pub limit_price: LimitPrice,
    /// Order deadline, in milliseconds.
    pub expires_at_ms: i64,
    /// Sequence of the last applied transition.
    pub last_transition_seq: u64,
}

impl std::fmt::Debug for OrderSummary {
    /// Redacted: an order summary carries order/token/wallet/amount semantics, so
    /// it must never be rendered into a log or telemetry label (PRD line 83). The
    /// JSON projection is gated behind the authenticated response path instead.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OrderSummary { .. }")
    }
}

impl OrderSummary {
    /// Projects a durable record onto the user-facing summary.
    pub fn from_stored(record: &StoredLimitOrder) -> Self {
        Self {
            order_id: record.order.id.as_str().to_string(),
            wallet_ref: record.order.wallet_ref.as_str().to_string(),
            chain: record.order.chain.clone(),
            token_in: record.order.token_in.clone(),
            token_out: record.order.token_out.clone(),
            side: record.order.side,
            status: record.order.status,
            max_input: record.order.max_input.amount,
            remaining_input: record.order.remaining_input,
            filled_input: record.filled_input,
            min_fill: record.order.min_fill,
            allow_partial_fill: record.order.allow_partial_fill,
            limit_price: record.order.limit_price.clone(),
            expires_at_ms: record.order.expires_at_ms,
            last_transition_seq: record.last_transition_seq,
        }
    }
}

/// Read-only port over one owner's orders.
#[async_trait]
pub trait OrderReadModel: Send + Sync {
    /// Lists the owner's orders, optionally filtered by exact status.
    ///
    /// Implementations must be owner-scoped and bounded; they must not accept an
    /// owner argument from the command.
    async fn list_orders(
        &self,
        status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, BackendError>;
}

/// Real [`OrderReadModel`] over the durable encrypted [`limit_engine`] store.
///
/// The listing is owner-scoped at construction and bounded by `page` (clamped by
/// the store to [`limit_engine::MAX_OWNER_ORDERS`]). A cross-owner record is
/// never returned, and an environmental store/key fault collapses to the
/// redacted [`BackendError::Unavailable`]. Like every read of the class
/// enumeration, a single unreadable own-owner record (corrupt or under an
/// unresolvable historical key id) is skipped rather than hiding the healthy
/// orders; see `DurableLimitOrderStore::list_orders_for_owner`.
pub struct DurableOrderReadModel<S: OpaqueStore> {
    store: Arc<DurableLimitOrderStore<S>>,
    owner: UserId,
    page: usize,
}

impl<S: OpaqueStore> DurableOrderReadModel<S> {
    /// Binds the read model to one authenticated owner with the default page.
    pub fn new(store: Arc<DurableLimitOrderStore<S>>, owner: UserId) -> Self {
        Self {
            store,
            owner,
            page: DEFAULT_ORDER_PAGE,
        }
    }

    /// Overrides the page size (still clamped by the durable store).
    pub fn with_page(mut self, page: usize) -> Self {
        self.page = page;
        self
    }
}

impl<S: OpaqueStore> std::fmt::Debug for DurableOrderReadModel<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the owner, the page, or any store-derived value.
        formatter
            .debug_struct("DurableOrderReadModel")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S: OpaqueStore> OrderReadModel for DurableOrderReadModel<S> {
    async fn list_orders(
        &self,
        status: Option<OrderStatus>,
    ) -> Result<Vec<OrderSummary>, BackendError> {
        let records = self
            .store
            .list_orders_for_owner(&self.owner, status, self.page)
            .await
            .map_err(|_| BackendError::Unavailable)?;
        Ok(records.iter().map(OrderSummary::from_stored).collect())
    }
}
