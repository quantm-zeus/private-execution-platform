//! Redacted, payload-free errors for the channel-agnostic agent command core.
//!
//! Invariants:
//! - No variant carries request data (amounts, assets, identifiers, queries).
//! - `Display` and `Debug` never echo request values, so a malformed command
//!   cannot leak into logs through the error path.

use std::fmt;

use thiserror::Error;

/// Fail-closed classification for a structured agent command.
#[derive(Clone, PartialEq, Eq, Error)]
pub enum AgentCommandError {
    /// The JSON was not a well-formed structured command.
    #[error("malformed agent command")]
    Malformed,

    /// The amount was structurally ambiguous (for example, a unit without a value).
    #[error("ambiguous amount")]
    AmbiguousAmount,

    /// The amount omitted its explicit unit; a bare number is never accepted.
    #[error("amount unit is required")]
    MissingUnit,

    /// The tool name is not part of the closed read/trade vocabulary.
    ///
    /// Kept for API completeness; [`crate::AgentCommand::parse`] deliberately
    /// reports unknown mutating names as [`AgentCommandError::ForbiddenOperation`]
    /// so callers cannot smuggle a capability through a typo.
    #[error("unknown tool")]
    UnknownTool,

    /// The command names a withdraw/transfer/ownership/limit-raising/signing
    /// operation that this core must never expose.
    #[error("forbidden operation")]
    ForbiddenOperation,

    /// An asset reference was empty, malformed, or oversized.
    #[error("invalid asset reference")]
    InvalidAsset,

    /// An amount was zero, non-numeric, or out of range for its unit.
    #[error("invalid amount")]
    InvalidAmount,

    /// A limit price was zero, malformed, or overflowing.
    #[error("invalid limit price")]
    InvalidLimitPrice,

    /// A chart window was not one of the closed set of supported windows.
    #[error("invalid chart window")]
    InvalidWindow,
}

impl fmt::Debug for AgentCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted debug that preserves the zero-request-data invariant.
        write!(f, "AgentCommandError({self})")
    }
}
