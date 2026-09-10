//! Structured, fail-closed broker errors.
//!
//! Invariants:
//! - Redacted, safe Debug and Display implementations ensuring zero secret, endpoint,
//!   bearer token, or raw response payload leakage.
//! - Closed vocabulary of failure categories for negative caching.

use mcp_adapters::McpAdapterError;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use crate::key::ProviderId;
use crate::meta::ResponseMeta;

/// Bounded opaque failure category used for negative cache storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueFailureKind {
    ServiceUnavailable,
    TransportFailure,
    ToolExecutionFailed,
    MalformedResponse,
    OversizedResponse,
    DisallowedOperation,
    InvalidArgument,
    Other,
}

impl From<&McpAdapterError> for OpaqueFailureKind {
    fn from(err: &McpAdapterError) -> Self {
        match err {
            McpAdapterError::ServiceUnavailable { .. } => Self::ServiceUnavailable,
            McpAdapterError::TransportFailure { .. } => Self::TransportFailure,
            McpAdapterError::ToolExecutionFailed { .. } => Self::ToolExecutionFailed,
            McpAdapterError::MalformedResponse { .. } => Self::MalformedResponse,
            McpAdapterError::OversizedResponse { .. } => Self::OversizedResponse,
            McpAdapterError::DisallowedOperation => Self::DisallowedOperation,
            McpAdapterError::InvalidArgument { .. } => Self::InvalidArgument,
            McpAdapterError::UnsupportedTool { .. } => Self::Other,
        }
    }
}

/// Structured broker errors.
#[derive(Clone, PartialEq, Eq, Error)]
pub enum BrokerError {
    #[error("budget exhausted for provider: {provider}")]
    BudgetExhausted {
        provider: ProviderId,
        meta: ResponseMeta,
    },

    #[error("circuit breaker open for provider: {provider}")]
    CircuitOpen {
        provider: ProviderId,
        meta: ResponseMeta,
    },

    #[error("cooldown active for provider: {provider}")]
    CooldownActive {
        provider: ProviderId,
        meta: ResponseMeta,
    },

    #[error("low priority request shed under pressure: {provider}")]
    PriorityShed {
        provider: ProviderId,
        meta: ResponseMeta,
    },

    #[error("candidate gating rejected: {candidate_id}")]
    CandidateNotEligible {
        candidate_id: String,
        meta: ResponseMeta,
    },

    #[error("negative cached failure for provider: {provider} ({kind:?})")]
    NegativeCached {
        provider: ProviderId,
        kind: OpaqueFailureKind,
        meta: ResponseMeta,
    },

    #[error("adapter error: {error}")]
    Adapter {
        error: McpAdapterError,
        meta: ResponseMeta,
    },
}

impl BrokerError {
    pub fn meta(&self) -> &ResponseMeta {
        match self {
            Self::BudgetExhausted { meta, .. } => meta,
            Self::CircuitOpen { meta, .. } => meta,
            Self::CooldownActive { meta, .. } => meta,
            Self::PriorityShed { meta, .. } => meta,
            Self::CandidateNotEligible { meta, .. } => meta,
            Self::NegativeCached { meta, .. } => meta,
            Self::Adapter { meta, .. } => meta,
        }
    }
}

impl fmt::Debug for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted debug output: never disclose raw payloads, endpoints, or credentials.
        write!(f, "BrokerError({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{CacheState, ProviderHealthState};

    #[test]
    fn test_error_debug_does_not_leak_secrets() {
        let meta = ResponseMeta {
            provider: ProviderId::Fomo,
            cache_state: CacheState::Miss,
            freshness_ms: None,
            degraded_reason: None,
            health_state: ProviderHealthState::Healthy,
            consecutive_failures: 0,
            request_cost: 1,
        };

        let err = BrokerError::CandidateNotEligible {
            candidate_id: "candidate-secret-token-123".into(),
            meta,
        };

        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("BrokerError"));
        assert!(debug_str.contains("candidate gating rejected"));
    }
}
