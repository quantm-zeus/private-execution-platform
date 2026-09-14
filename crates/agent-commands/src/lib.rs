//! # Channel-agnostic agent command core (Phase 6 S1)
//!
//! One canonical, channel-agnostic structured command vocabulary and
//! authorization core shared by the future MCP server and Telegram bot, layered
//! over the canonical `TradeIntent` / Trading Core.
//!
//! ## Boundaries
//! - No natural-language parsing: the transport hands in a structured command.
//! - Ambiguity fails closed; a bare amount without an explicit unit is rejected.
//! - Read-only commands stay available while `TRADING_ENABLED=false`; mutations
//!   are denied except the read-only `PreviewMarketOrder`.
//! - Both channels share the identical restriction set (no channel privilege).
//! - The core never signs, transfers, withdraws, or raises security limits, and
//!   has no signing/transfer dependency and performs no I/O.
//!
//! ## Forbidden surface
//! There is deliberately no variant for withdraw, transfer, ownership changes,
//! limit raising, or generic signing. [`AgentCommand::parse`] maps those tool
//! names to [`AgentCommandError::ForbiddenOperation`] so they cannot be smuggled
//! through an unknown-name path. The `#![forbid(unsafe_code)]` crate has no
//! `privy`, `execution-relay`, `limit-engine`, or `policy` dependency.

#![forbid(unsafe_code)]

mod authorize;
mod command;
mod error;

pub use authorize::{authorize, AgentCapabilities, AuthorizedCommand, DenyReason};
pub use command::{
    AgentChannel, AgentCommand, AmountSpec, AssetRef, ChartWindow, LimitPriceSpec, ReadCommand,
    RouterSource, TradeCommand, MAX_ASSET_ADDRESS_LEN,
};
pub use error::AgentCommandError;
