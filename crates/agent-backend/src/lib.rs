//! # Agent backend (Phase 6 S4/S6/S7/S8)
//!
//! A real [`mcp_server::AgentBackend`] composition over the canonical Trading
//! Core. It serves owner-scoped read projections through injected ports,
//! delegates authorized limit-order placement/cancellation to the durable
//! [`limit_engine`] order store, quotes exact `preview_market_order` economics
//! through the injected market/route ports, and delegates authorized
//! `execute_market_order` to an injected [`MarketExecutionPort`]. The dispatcher
//! never touches the store or the router, and neither knows about MCP.
//!
//! ## Boundaries
//! - **Reads** ([`AgentReadBackend`]) serve the owner-scoped `get_orders` and
//!   `get_portfolio` projections through injected [`OrderReadModel`]/
//!   [`PortfolioReadModel`] ports. Every other read fails closed
//!   [`mcp_server::BackendOutcome::Unavailable`].
//! - **Writes** ([`TradingAgentBackend`]) create a durable `Created` limit order
//!   and append a validated `Cancelled` transition over the injected
//!   [`limit_engine::LimitOrderStore`]. No funds move here: there is no signing,
//!   submission, or relay call.
//! - **Market preview** ([`TradingAgentBackend`] + [`MarketSnapshotSource`])
//!   returns the exact full-net-economics [`MarketPreview`] from the same
//!   bounded single-path router the execution path uses. It moves no funds and
//!   fails closed when no trusted market view exists.
//! - **Market execution** ([`TradingAgentBackend`] + [`MarketExecutionPort`])
//!   delegates `execute_market_order` the exact trusted intent and quote; the
//!   injected port owns pre-sign revalidation/policy/sign/submit. The default
//!   port fails closed, so nothing executes without an explicitly installed
//!   pipeline.
//! - **No signing/transfer/relay capability.** This crate names no signing,
//!   transfer, or relay type and exposes no path that can reach one. (The
//!   `limit-engine` dependency it uses for the durable order store is itself
//!   transitively linked to `privy` and `execution-relay`, but those capabilities
//!   are not reachable through `limit-engine`'s public order surface, and this
//!   crate has no direct edge.)
//! - **Owner-scoped.** A backend instance is bound to one authenticated owner
//!   (one session), so a command carries no user identity and cannot be pointed
//!   at another owner's data.
//! - **Redaction.** Internal failures collapse to the redacted
//!   [`BackendError`]; nothing here logs. User-facing order/portfolio/preview/
//!   execution payloads are returned only through the authenticated channel,
//!   never as telemetry.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod execute;
mod market;
mod order;
mod portfolio;
mod trade;

pub use backend::{parse_status_filter, AgentReadBackend};
pub use error::BackendError;
pub use execute::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
    UnavailableMarketExecution,
};
pub use market::{
    plan_market_preview, MarketPreview, MarketPreviewError, MarketSnapshot, MarketSnapshotSource,
    UnavailableMarketSnapshot,
};
pub use order::{DurableOrderReadModel, OrderReadModel, OrderSummary, DEFAULT_ORDER_PAGE};
pub use portfolio::{
    BalanceEntry, BalanceProvider, ComposedPortfolioReadModel, PortfolioReadModel,
    PortfolioSummary, UnavailablePortfolioReadModel,
};
pub use trade::{
    FixedClock, OrderValuation, SystemClock, TradingAgentBackend, TradingBackendConfig,
    TrustedClock, UnavailableOrderValuation,
};
