//! Owner-scoped portfolio read model: injected balances plus order aggregates.

use async_trait::async_trait;
use chain_types::AssetId;
use domain::OrderStatus;
use market_types::AtomicAmount;
use serde::Serialize;

use crate::error::BackendError;
use crate::order::OrderReadModel;

/// One token balance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BalanceEntry {
    /// Asset the balance is denominated in.
    pub asset: AssetId,
    /// Atomic balance amount.
    pub amount: AtomicAmount,
}

/// Injected source of authoritative wallet balances.
///
/// The real implementation reads the wallet's on-chain balances. This crate
/// ships no live transport: production wiring must install a reviewed balance
/// source, and the fail-closed [`UnavailablePortfolioReadModel`] is the default.
#[async_trait]
pub trait BalanceProvider: Send + Sync {
    /// Returns the wallet's nonzero balances.
    async fn balances(&self) -> Result<Vec<BalanceEntry>, BackendError>;
}

/// A user-facing portfolio projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortfolioSummary {
    /// Nonzero token balances.
    pub balances: Vec<BalanceEntry>,
    /// Orders in a non-terminal status.
    pub open_orders: u32,
    /// Orders in the `Filled` status.
    pub filled_orders: u32,
    /// Orders examined, across every status.
    pub total_orders: u32,
}

/// Read-only port over one owner's portfolio.
#[async_trait]
pub trait PortfolioReadModel: Send + Sync {
    /// Builds the owner's portfolio projection.
    async fn portfolio(&self) -> Result<PortfolioSummary, BackendError>;
}

/// Fail-closed portfolio default: every read is unavailable.
#[derive(Debug, Default)]
pub struct UnavailablePortfolioReadModel;

impl UnavailablePortfolioReadModel {
    /// Builds the fail-closed default.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PortfolioReadModel for UnavailablePortfolioReadModel {
    async fn portfolio(&self) -> Result<PortfolioSummary, BackendError> {
        Err(BackendError::Unavailable)
    }
}

/// Owner-scoped portfolio composed from an [`OrderReadModel`] and a
/// [`BalanceProvider`].
///
/// Order aggregates come from the same bounded, owner-scoped listing the
/// `get_orders` command uses, so the two surfaces can never disagree about which
/// orders belong to the owner. A fault in either the order listing or the
/// balance source fails the whole portfolio closed rather than returning a
/// half-truth.
pub struct ComposedPortfolioReadModel<O: OrderReadModel, B: BalanceProvider> {
    orders: O,
    balances: B,
}

impl<O: OrderReadModel, B: BalanceProvider> ComposedPortfolioReadModel<O, B> {
    /// Wires the portfolio from its two trusted ports.
    pub fn new(orders: O, balances: B) -> Self {
        Self { orders, balances }
    }
}

impl<O: OrderReadModel, B: BalanceProvider> std::fmt::Debug for ComposedPortfolioReadModel<O, B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComposedPortfolioReadModel")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<O: OrderReadModel, B: BalanceProvider> PortfolioReadModel
    for ComposedPortfolioReadModel<O, B>
{
    async fn portfolio(&self) -> Result<PortfolioSummary, BackendError> {
        let orders = self.orders.list_orders(None).await?;
        let balances = self.balances.balances().await?;

        let total_orders = orders.len().min(u32::MAX as usize) as u32;
        let mut open_orders: u32 = 0;
        let mut filled_orders: u32 = 0;
        for order in &orders {
            match order.status {
                OrderStatus::Filled => filled_orders = filled_orders.saturating_add(1),
                OrderStatus::Cancelled | OrderStatus::Expired | OrderStatus::FailedFinal => {}
                _ => open_orders = open_orders.saturating_add(1),
            }
        }

        Ok(PortfolioSummary {
            balances,
            open_orders,
            filled_orders,
            total_orders,
        })
    }
}
