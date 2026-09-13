//! Redacted backend failure classes.

/// A redacted read-model failure.
///
/// `Debug`/`Display` are payload-free enums: a failure never carries an address,
/// amount, order id, or query. A caller maps these onto the MCP
/// [`mcp_server::BackendOutcome`] without exposing more than a fixed class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The underlying read model could not be served (store/key/network).
    #[error("backend unavailable")]
    Unavailable,
    /// The command is refused (for example, an unknown status filter).
    #[error("command denied")]
    Denied,
}
