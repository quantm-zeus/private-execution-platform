//! # Agent backend (Phase 6 S4)
//!
//! A real [`mcp_server::AgentBackend`] composition over the canonical Trading
//! Core, plus the read models it serves. This crate is the missing wiring
//! between the pure MCP dispatcher ([`mcp_server`]) and the durable
//! [`limit_engine`] order store: the dispatcher never touches the store, and the
//! store never knows about MCP.
//!
//! ## Boundaries
//! - **Read model only in this slice.** [`AgentReadBackend`] serves the
//!   owner-scoped `get_orders` and `get_portfolio` reads through injected
//!   [`OrderReadModel`]/[`PortfolioReadModel`] ports. Every other command —
//!   including every mutating command — returns
//!   [`mcp_server::BackendOutcome::Unavailable`], so an unimplemented surface
//!   fails closed rather than guessing.
//! - **No signing/transfer/relay capability.** This crate names no signing,
//!   transfer, or relay type and exposes no path that can reach one; every
//!   mutating command fails closed here and is handled by a later slice over an
//!   explicit Trading Core seam. (The `limit-engine` dependency it uses for the
//!   durable order read model is itself transitively linked to `privy` and
//!   `execution-relay`, but those capabilities are not reachable through
//!   `limit-engine`'s public read surface, and this crate has no direct edge.)
//! - **Owner-scoped.** A backend instance is bound to one authenticated owner
//!   (one session), so a command carries no user identity and cannot be pointed
//!   at another owner's data.
//! - **Redaction.** Internal failures collapse to the redacted
//!   [`BackendError`]; nothing here logs. User-facing order/portfolio payloads
//!   are returned only through the authenticated channel, never as telemetry.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod order;
mod portfolio;

pub use backend::{parse_status_filter, AgentReadBackend};
pub use error::BackendError;
pub use order::{DurableOrderReadModel, OrderReadModel, OrderSummary, DEFAULT_ORDER_PAGE};
pub use portfolio::{
    BalanceEntry, BalanceProvider, ComposedPortfolioReadModel, PortfolioReadModel,
    PortfolioSummary, UnavailablePortfolioReadModel,
};
