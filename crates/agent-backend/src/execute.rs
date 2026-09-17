//! Market-order execution delegation for the agent channels (Phase 6 S8).
//!
//! `preview_market_order` (P68) produces the exact net-economics quote; this
//! module turns an already-authorized `execute_market_order` into a delegated
//! execution through an injected [`MarketExecutionPort`]. The backend owns the
//! trusted intent and the exact route, and hands both to the port; the port owns
//! the sign/revalidate/submit composition (the Trading Core wires a relay-backed
//! implementation). The default port fails closed.
//!
//! ## Boundaries
//! - **Delegation, not signing.** This module names no signing, transfer, or
//!   relay capability. Signing stays behind the port and the Trading Core/relay
//!   seam.
//! - **Trusted intent.** The owner, wallet, chain, and risk caps come from
//!   [`crate::TradingBackendConfig`]; the command contributes only the asset
//!   pair, side, and an explicit atomic input amount. The exact route is the
//!   same bounded single-path router the preview uses.
//! - **Fail closed.** A missing port is [`MarketExecutionError::Unavailable`]; a
//!   denied/failed port outcome is redacted. Nothing is guessed.
//! - Redacted `Debug`; no logging; `#![forbid(unsafe_code)]`.

use std::fmt;

use async_trait::async_trait;
use domain::{RouteScore, TradeIntent};
use routing::RouteQuote;

/// A fully quoted market execution handed to the injected execution port.
///
/// `intent` is the trusted `TradeIntent`; `quote` is the exact, contract-validated
/// route and net delta; `score` is the gas-aware score for the same candidate.
/// `router_source` is the additive P84B routing discriminant the quote was
/// produced under; it is bound into the intent identity (see
/// `TradingAgentBackend::preview_parts`) so a Local quote cannot be replayed as
/// an OKX execution or vice versa.
pub struct MarketExecutionRequest {
    /// Trusted market intent (owner/wallet/chain/risk bound).
    pub intent: TradeIntent,
    /// Exact validated route and full-wallet-debit net delta.
    pub quote: RouteQuote,
    /// Gas-aware score of the selected route.
    pub score: RouteScore,
    /// Caller-supplied reference time.
    pub now_ms: i64,
    /// Routing source that produced the quote.
    pub router_source: agent_commands::RouterSource,
}

impl fmt::Debug for MarketExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: assets, amounts, routes, and scores are never rendered.
        formatter
            .debug_struct("MarketExecutionRequest")
            .field("now_ms", &self.now_ms)
            .field("router_source", &self.router_source)
            .finish_non_exhaustive()
    }
}

/// Redacted terminal/in-flight outcome reported by an execution port.
///
/// `Filled` is the only variant that carries economics, and those amounts are
/// user-facing execution results (returned only through the authenticated
/// channel); `Debug` still redacts them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MarketExecutionOutcome {
    /// The attempt was accepted and submitted; chain resolution is pending.
    Submitted,
    /// The chain confirmed the attempt with realized amounts.
    Filled {
        /// Net input actually consumed, in `token_in` atomic units.
        net_input: u128,
        /// Net output actually received, in `token_out` atomic units.
        net_output: u128,
    },
    /// The attempt may be in flight; its state is unresolved.
    Unknown,
    /// The attempt was definitively rejected or failed before submission.
    Failed,
}

impl fmt::Debug for MarketExecutionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted => formatter.write_str("Submitted"),
            Self::Filled { .. } => formatter.write_str("Filled { .. }"),
            Self::Unknown => formatter.write_str("Unknown"),
            Self::Failed => formatter.write_str("Failed"),
        }
    }
}

/// Redacted execution failure taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarketExecutionError {
    /// The injected execution pipeline is not available.
    #[error("market execution is unavailable")]
    Unavailable,
    /// The execution was refused (policy/risk/revalidation); retrying may help.
    #[error("market execution denied")]
    Denied,
}

/// Injected market-execution seam.
///
/// Implementations own the pre-sign revalidation, policy authorization, and
/// sign/submit composition over the exact [`MarketExecutionRequest`]. They must
/// never fabricate a `Filled` outcome: a `Filled` must reflect observed realized
/// amounts, and an unresolved attempt must report [`MarketExecutionOutcome::Unknown`].
#[async_trait]
pub trait MarketExecutionPort: Send + Sync {
    /// Executes the fully quoted market request.
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError>;

    /// Reconciles a previously delegated market attempt by its full durable
    /// `(owner, workspace, idempotency_key)` binding.
    ///
    /// Reconciliation is read-only: an implementation must never sign or submit.
    /// The full binding is required so a caller can never reconcile another
    /// tenant's attempt that happens to share the idempotency key. The default
    /// has no observation capability and fails closed to `Unknown`; a `Filled`
    /// may only be produced from exact observed amounts.
    ///
    /// `reconcile_for` is the source-aware form. A port that composes multiple
    /// sources (see `market_execution::SourceBoundMarketExecutionPort`) must
    /// override it so a binding is only ever queried at the source that owns it;
    /// the default ignores the source and delegates to `reconcile`.
    async fn reconcile(
        &self,
        _binding: &execution_relay::AttemptBinding,
        _now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        Ok(MarketExecutionOutcome::Unknown)
    }

    /// Reconciles a binding at the source that owns it.
    ///
    /// The default ignores `router_source` and delegates to [`Self::reconcile`];
    /// single-source ports therefore need only implement `reconcile`.
    async fn reconcile_for(
        &self,
        _router_source: agent_commands::RouterSource,
        binding: &execution_relay::AttemptBinding,
        now_ms: i64,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.reconcile(binding, now_ms).await
    }
}

/// Fail-closed default: no execution pipeline is installed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableMarketExecution;

#[async_trait]
impl MarketExecutionPort for UnavailableMarketExecution {
    async fn execute(
        &self,
        _request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        Err(MarketExecutionError::Unavailable)
    }
}
