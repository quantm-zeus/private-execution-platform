//! Trusted authorization core shared by MCP and Telegram.
//!
//! Capabilities are built by the backend, never from the request body. The
//! channel argument does not grant privilege: both channels run the identical
//! rule set (invariant AC-4).

use std::collections::HashSet;
use std::fmt;

use chain_types::ChainId;

use crate::{AgentChannel, AgentCommand, ReadCommand, TradeCommand};

/// Trusted capability context; built by the backend, never from the request body.
pub struct AgentCapabilities {
    pub trading_enabled: bool,
    /// Chains this wallet may trade.
    pub allowed_chains: HashSet<ChainId>,
    /// Max notional per trade in USD micros.
    pub max_trade_usd: u64,
}

impl AgentCapabilities {
    /// Builds a capability context from trusted backend configuration.
    pub fn new(
        trading_enabled: bool,
        allowed_chains: HashSet<ChainId>,
        max_trade_usd: u64,
    ) -> Self {
        Self {
            trading_enabled,
            allowed_chains,
            max_trade_usd,
        }
    }
}

impl fmt::Debug for AgentCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: chain identities are capability semantics and stay hidden.
        f.debug_struct("AgentCapabilities")
            .field("trading_enabled", &self.trading_enabled)
            .field("allowed_chains", &self.allowed_chains.len())
            .field("max_trade_usd", &self.max_trade_usd)
            .finish()
    }
}

/// Outcome of routing a structured command.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizedCommand {
    Read(ReadCommand),
    Trade(TradeCommand),
    Denied(DenyReason),
}

impl fmt::Debug for AuthorizedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: never echo the underlying command payload.
        match self {
            Self::Read(_) => f.write_str("AuthorizedCommand::Read"),
            Self::Trade(_) => f.write_str("AuthorizedCommand::Trade"),
            Self::Denied(reason) => write!(f, "AuthorizedCommand::Denied({reason:?})"),
        }
    }
}

/// Fail-closed denial reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// `TRADING_ENABLED=false`: mutations denied, reads allowed.
    TradingDisabled,
    /// The referenced chain is not in the wallet's allowed tradable set.
    ChainNotAllowed,
    /// A mutating trade had no trusted valuation or exceeded the notional cap.
    NotionalExceedsLimit,
    /// A withdraw/transfer/ownership/limit-raising/raw-sign operation.
    ///
    /// `parse` rejects these structurally, so this is only reachable through
    /// direct enum construction; kept as part of the closed denial taxonomy.
    ForbiddenOperation,
}

/// Routes a structured command.
///
/// `valuation_usd_micros` is the trusted backend valuation of `command` when it
/// is a mutating command with an amount; `None` for reads or when unknown (fail
/// closed).
pub fn authorize(
    channel: AgentChannel,
    command: AgentCommand,
    capabilities: &AgentCapabilities,
    valuation_usd_micros: Option<u64>,
) -> AuthorizedCommand {
    // Both channels deliberately share one rule set; the match documents that
    // there is no channel-specific privilege.
    match channel {
        AgentChannel::Mcp | AgentChannel::Telegram => {
            authorize_shared(command, capabilities, valuation_usd_micros)
        }
    }
}

fn authorize_shared(
    command: AgentCommand,
    capabilities: &AgentCapabilities,
    valuation_usd_micros: Option<u64>,
) -> AuthorizedCommand {
    match command {
        // Reads are always authorized: `allowed_chains` is the wallet's
        // *tradable* set, and read-only intelligence must stay available.
        AgentCommand::Read(command) => AuthorizedCommand::Read(command),
        AgentCommand::Trade(command) => {
            let mutating = command.is_mutating();
            if mutating && !capabilities.trading_enabled {
                // AC-1: no mutation while TRADING_ENABLED=false. The read-only
                // preview is intentionally excluded.
                return AuthorizedCommand::Denied(DenyReason::TradingDisabled);
            }
            if !chains_allowed(command.chains(), capabilities) {
                return AuthorizedCommand::Denied(DenyReason::ChainNotAllowed);
            }
            if mutating {
                // AC: a mutating trade with no trusted valuation or above the
                // notional cap is denied (fail closed).
                match valuation_usd_micros {
                    Some(value) if value <= capabilities.max_trade_usd => {}
                    _ => return AuthorizedCommand::Denied(DenyReason::NotionalExceedsLimit),
                }
            }
            AuthorizedCommand::Trade(command)
        }
    }
}

fn chains_allowed<'a>(
    chains: impl IntoIterator<Item = &'a ChainId>,
    capabilities: &AgentCapabilities,
) -> bool {
    chains
        .into_iter()
        .all(|chain| capabilities.allowed_chains.contains(chain))
}
