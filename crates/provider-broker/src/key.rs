//! Canonical request keying and candidate/position-aware context.
//!
//! Enforces:
//! - Canonical typed request keys incorporating provider, operation, validated arguments,
//!   and position/candidate contexts.
//! - Strict isolation of position-aware requests to prevent cross-position cache leakage.
//! - Explicit safe candidate context for enrichment gating.
//! - Redacted, safe Debug and Display implementations preventing leak of payloads or endpoints.

use mcp_adapters::McpServiceId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Strongly-typed provider identity, re-exported from `mcp-adapters`.
pub type ProviderId = McpServiceId;

/// Request priority for pressure shedding and queue management.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RequestPriority {
    /// Background exploratory or discovery requests. Shed first under pressure.
    Low = 0,
    /// Normal operational requests (candidate evaluation, routine intelligence).
    #[default]
    Normal = 1,
    /// High-conviction or active-position risk verification. Preserved under pressure.
    High = 2,
}

/// Candidate context for progressive intelligence gating.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateContext {
    pub candidate_id: String,
    pub score: u32,
    pub min_score_threshold: u32,
}

impl CandidateContext {
    pub fn new(candidate_id: impl Into<String>, score: u32, min_score_threshold: u32) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            score,
            min_score_threshold,
        }
    }

    /// Checks if the candidate meets the minimum score threshold required for expensive enrichment.
    pub fn is_eligible(&self) -> bool {
        self.score >= self.min_score_threshold
    }
}

impl fmt::Debug for CandidateContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateContext")
            .field("candidate_id", &self.candidate_id)
            .field("score", &self.score)
            .field("threshold", &self.min_score_threshold)
            .field("eligible", &self.is_eligible())
            .finish()
    }
}

/// Position context for position-aware requests.
///
/// Ensures position-aware requests are separately keyed to prevent cross-position cache leakage.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PositionContext {
    pub position_id: String,
}

impl PositionContext {
    pub fn new(position_id: impl Into<String>) -> Self {
        Self {
            position_id: position_id.into(),
        }
    }
}

impl fmt::Debug for PositionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PositionContext")
            .field("position_id", &self.position_id)
            .finish()
    }
}

/// Request context holding candidate, position, and priority information.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestContext {
    pub candidate: Option<CandidateContext>,
    pub position: Option<PositionContext>,
    pub priority: RequestPriority,
}

impl RequestContext {
    pub fn high_priority() -> Self {
        Self {
            candidate: None,
            position: None,
            priority: RequestPriority::High,
        }
    }

    pub fn low_priority() -> Self {
        Self {
            candidate: None,
            position: None,
            priority: RequestPriority::Low,
        }
    }

    pub fn with_candidate(mut self, candidate: CandidateContext) -> Self {
        self.candidate = Some(candidate);
        self
    }

    pub fn with_position(mut self, position: PositionContext) -> Self {
        self.position = Some(position);
        self
    }

    pub fn with_priority(mut self, priority: RequestPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// Canonical typed request key for cache lookup and singleflight coalescing.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogicalRequestKey {
    pub provider: ProviderId,
    pub operation: &'static str,
    pub canonical_args: String,
    pub candidate_id: Option<String>,
    pub position_id: Option<String>,
}

impl LogicalRequestKey {
    pub fn new(
        provider: ProviderId,
        operation: &'static str,
        canonical_args: String,
        context: &RequestContext,
    ) -> Self {
        Self {
            provider,
            operation,
            canonical_args,
            candidate_id: context.candidate.as_ref().map(|c| c.candidate_id.clone()),
            position_id: context.position.as_ref().map(|p| p.position_id.clone()),
        }
    }
}

impl fmt::Display for LogicalRequestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:pos={:?}:cand={:?}",
            self.provider.as_str(),
            self.operation,
            self.position_id.as_deref().unwrap_or("none"),
            self.candidate_id.as_deref().unwrap_or("none")
        )
    }
}

impl fmt::Debug for LogicalRequestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted debug representation: never dump raw arguments or potential payload data.
        f.debug_struct("LogicalRequestKey")
            .field("provider", &self.provider)
            .field("operation", &self.operation)
            .field("candidate_id", &self.candidate_id)
            .field("position_id", &self.position_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_eligibility() {
        let eligible = CandidateContext::new("cand_1", 80, 75);
        assert!(eligible.is_eligible());

        let ineligible = CandidateContext::new("cand_2", 70, 75);
        assert!(!ineligible.is_eligible());
    }

    #[test]
    fn test_position_isolation_in_keys() {
        let ctx1 = RequestContext::default().with_position(PositionContext::new("pos_1"));
        let ctx2 = RequestContext::default().with_position(PositionContext::new("pos_2"));
        let ctx_none = RequestContext::default();

        let key1 =
            LogicalRequestKey::new(ProviderId::Gmgn, "token_info", "sol:tokenA".into(), &ctx1);
        let key2 =
            LogicalRequestKey::new(ProviderId::Gmgn, "token_info", "sol:tokenA".into(), &ctx2);
        let key_none = LogicalRequestKey::new(
            ProviderId::Gmgn,
            "token_info",
            "sol:tokenA".into(),
            &ctx_none,
        );

        assert_ne!(key1, key2, "different positions must yield different keys");
        assert_ne!(
            key1, key_none,
            "position key must differ from non-position key"
        );
    }

    #[test]
    fn test_key_debug_redaction() {
        let ctx = RequestContext::default();
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            "search_tokens",
            "SENSITIVE_SEARCH_SECRET".into(),
            &ctx,
        );

        let debug_str = format!("{key:?}");
        assert!(!debug_str.contains("SENSITIVE_SEARCH_SECRET"));
        assert!(debug_str.contains("LogicalRequestKey"));
    }
}
