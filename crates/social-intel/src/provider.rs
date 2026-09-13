//! The injected paid-social provider port and its typed, bounded snapshot.

use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use provider_broker::{CandidateContext, PositionContext};
use serde::{Deserialize, Serialize};

use crate::error::SocialProviderError;
use crate::policy::SocialPriority;

/// Bounded semantic class of one social observation.
///
/// Raw upstream text/influencer identities are never carried: the provider maps
/// them onto this closed vocabulary so downstream code cannot treat social media
/// as execution truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocialSignalKind {
    /// A plausible positive catalyst.
    Catalyst,
    /// A plausible negative catalyst (fear/uncertainty/doubt).
    Fud,
    /// A measurable attention surge.
    AttentionSurge,
    /// A notable account mentioned the asset.
    InfluencerMention,
    /// A directional sentiment shift.
    SentimentShift,
}

/// One bounded social observation.
///
/// `weight_bps` is a 0..=10_000 confidence/strength weight, never a token amount
/// or price.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialSignal {
    /// Signal class.
    pub kind: SocialSignalKind,
    /// Bounded 0..=10_000 weight.
    pub weight_bps: u16,
    /// Observation time in milliseconds.
    pub observed_at_ms: i64,
}

/// A typed social intelligence snapshot for one asset.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialSnapshot {
    /// Chain the asset belongs to.
    pub chain: ChainId,
    /// Asset the snapshot describes.
    pub token: AssetId,
    /// Bounded signals (the provider must cap the count).
    pub signals: Vec<SocialSignal>,
    /// Snapshot time in milliseconds.
    pub observed_at_ms: i64,
}

impl std::fmt::Debug for SocialSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the asset or the signal payload: social semantics are
        // private and must not become a telemetry label.
        formatter.write_str("SocialSnapshot { .. }")
    }
}

/// One paid-social intelligence request.
#[derive(Clone)]
pub struct SocialRequest {
    /// Chain the asset belongs to.
    pub chain: ChainId,
    /// Asset to enrich.
    pub token: AssetId,
    /// Why the enrichment is being requested (drives budget/candidate gating).
    pub priority: SocialPriority,
    /// Candidate context for pre-trade gating.
    pub candidate: Option<CandidateContext>,
    /// Position context for active-position risk.
    pub position: Option<PositionContext>,
}

impl std::fmt::Debug for SocialRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocialRequest { .. }")
    }
}

impl SocialRequest {
    /// Builds a candidate-gated pre-trade request.
    pub fn for_candidate(
        chain: ChainId,
        token: AssetId,
        priority: SocialPriority,
        candidate: CandidateContext,
    ) -> Self {
        Self {
            chain,
            token,
            priority,
            candidate: Some(candidate),
            position: None,
        }
    }

    /// Builds an active-position risk request.
    pub fn for_position(chain: ChainId, token: AssetId, position: PositionContext) -> Self {
        Self {
            chain,
            token,
            priority: SocialPriority::ActivePositionRisk,
            candidate: None,
            position: Some(position),
        }
    }
}

/// Injected source of paid social intelligence.
///
/// A production implementation calls a paid provider behind a bounded,
/// credential-holding transport. This crate ships no live transport; the default
/// is the fail-closed [`UnavailableSocialProvider`].
#[async_trait]
pub trait SocialProvider: Send + Sync {
    /// Fetches a bounded snapshot for `request`. Implementations must never
    /// return unbounded text or credentials.
    async fn fetch(&self, request: &SocialRequest) -> Result<SocialSnapshot, SocialProviderError>;
}

/// Fail-closed provider default: every fetch is unavailable.
#[derive(Debug, Default)]
pub struct UnavailableSocialProvider;

impl UnavailableSocialProvider {
    /// Builds the fail-closed provider.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SocialProvider for UnavailableSocialProvider {
    async fn fetch(&self, _request: &SocialRequest) -> Result<SocialSnapshot, SocialProviderError> {
        Err(SocialProviderError::Unavailable)
    }
}
