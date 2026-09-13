//! Injected execution backend port and the fail-closed production default.

use agent_commands::{AgentChannel, AgentCommand};
use async_trait::async_trait;

/// A redacted tool result the backend returns for a read/trade command.
#[derive(Clone, Debug, PartialEq)]
pub enum BackendOutcome {
    /// A structured JSON payload (already redacted by the backend).
    Value(serde_json::Value),
    /// The backend could not serve the command (redacted reason).
    Unavailable,
    /// The backend refused (e.g. policy/risk); redacted.
    Denied,
    /// The backend accepted the command but the operation definitively failed
    /// (for example a chain rejection or a definitive pre-submit failure).
    /// Distinct from [`BackendOutcome::Denied`], which is an authorization
    /// refusal.
    Failed,
}

/// Injected execution of an authorized command.
///
/// Implementations perform the real work (market data, preview, order store,
/// orchestrator). They MUST NOT sign or transfer directly; signing stays behind
/// the Trading Core/relay seam.
#[async_trait]
pub trait AgentBackend: Send + Sync {
    /// Executes an already-authorized command. The dispatcher only calls this
    /// after [`agent_commands::authorize`] returned a read or trade command.
    async fn execute(&self, channel: AgentChannel, command: AgentCommand) -> BackendOutcome;

    /// Trusted USD-micros valuation of `command`, or `None` when unknown.
    ///
    /// The dispatcher never derives value from the request body; it forwards
    /// whatever this trusted backend port reports to
    /// [`agent_commands::authorize`]. The default is `None`: a backend that
    /// cannot value a mutating command fails closed.
    async fn valuation_usd_micros(&self, command: &AgentCommand) -> Option<u64> {
        let _ = command;
        None
    }
}

/// Fail-closed production default: every command is [`BackendOutcome::Unavailable`].
pub struct UnavailableBackend;

#[async_trait]
impl AgentBackend for UnavailableBackend {
    async fn execute(&self, _channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
        BackendOutcome::Unavailable
    }
}
