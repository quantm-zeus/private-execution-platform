//! The [`AgentBackend`] read composition.

use agent_commands::{AgentChannel, AgentCommand, ReadCommand};
use async_trait::async_trait;
use domain::OrderStatus;
use mcp_server::{AgentBackend, BackendOutcome};
use serde_json::json;

use crate::error::BackendError;
use crate::order::OrderReadModel;
use crate::portfolio::PortfolioReadModel;

/// Parses the command's optional status filter into an exact [`OrderStatus`].
///
/// `Ok(None)` means "no filter". An unrecognized value is
/// [`BackendError::Denied`], and the caller must deny rather than silently widen
/// the query to "all statuses".
pub fn parse_status_filter(status: Option<&str>) -> Result<Option<OrderStatus>, BackendError> {
    match status {
        None => Ok(None),
        Some(value) => serde_json::from_value::<OrderStatus>(json!(value))
            .map(Some)
            .map_err(|_| BackendError::Denied),
    }
}

/// A real, owner-scoped read backend over the canonical Trading Core.
///
/// It serves `get_orders` and `get_portfolio`. Every other command — including
/// every mutation — is [`BackendOutcome::Unavailable`], so an unimplemented
/// surface can never execute by accident. The backend holds no signing,
/// transfer, or relay capability.
pub struct AgentReadBackend<O: OrderReadModel, P: PortfolioReadModel> {
    orders: O,
    portfolio: P,
}

impl<O: OrderReadModel, P: PortfolioReadModel> AgentReadBackend<O, P> {
    /// Wires the read backend from its two trusted ports.
    pub fn new(orders: O, portfolio: P) -> Self {
        Self { orders, portfolio }
    }
}

impl<O: OrderReadModel, P: PortfolioReadModel> std::fmt::Debug for AgentReadBackend<O, P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentReadBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<O: OrderReadModel, P: PortfolioReadModel> AgentBackend for AgentReadBackend<O, P> {
    async fn execute(&self, _channel: AgentChannel, command: AgentCommand) -> BackendOutcome {
        match command {
            AgentCommand::Read(ReadCommand::GetOrders { status }) => {
                let filter = match parse_status_filter(status.as_deref()) {
                    Ok(filter) => filter,
                    Err(_) => return BackendOutcome::Denied,
                };
                match self.orders.list_orders(filter).await {
                    Ok(orders) => BackendOutcome::Value(json!({ "orders": orders })),
                    Err(error) => outcome_for(error),
                }
            }
            AgentCommand::Read(ReadCommand::GetPortfolio) => {
                match self.portfolio.portfolio().await {
                    Ok(portfolio) => BackendOutcome::Value(json!({ "portfolio": portfolio })),
                    Err(error) => outcome_for(error),
                }
            }
            // Read commands with no landed port and every mutating command fail
            // closed. A later slice adds trade delegation explicitly.
            AgentCommand::Read(_) | AgentCommand::Trade(_) => BackendOutcome::Unavailable,
        }
    }
}

fn outcome_for(error: BackendError) -> BackendOutcome {
    match error {
        BackendError::Unavailable => BackendOutcome::Unavailable,
        BackendError::Denied => BackendOutcome::Denied,
    }
}
