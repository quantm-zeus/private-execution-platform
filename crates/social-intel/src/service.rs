//! The budgeted, candidate-gated social intelligence service.

use std::sync::Arc;

use provider_broker::{
    CacheLookup, CacheState, DegradedReason, LogicalCache, LogicalRequestKey, OpaqueFailureKind,
    ProviderBudget, ProviderId, RequestContext, RequestPriority,
};

use crate::policy::{SocialPolicy, SocialPriority};
use crate::provider::{SocialProvider, SocialRequest, SocialSnapshot};

/// Canonical cache operation name; isolates social entries from every other
/// broker operation sharing the cache namespace.
const SOCIAL_OPERATION: &str = "social_intel";

/// Bounded metadata attached to every social response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocialMeta {
    /// How the response was satisfied.
    pub cache_state: CacheState,
    /// Why the response is degraded, if it is.
    pub degraded_reason: Option<DegradedReason>,
    /// Age of the served value, when it came from cache.
    pub freshness_ms: Option<u64>,
    /// Budget units charged for this request.
    pub request_cost: u32,
}

/// A social intelligence response.
///
/// The service always returns a response: a gated, budget-exhausted, or
/// degraded call yields an empty snapshot with a [`SocialMeta::degraded_reason`]
/// rather than an error, so a provider outage or exhausted budget can never fail
/// a caller or (transitively) an execution path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocialResponse {
    /// The (possibly empty) snapshot.
    pub value: SocialSnapshot,
    /// Bounded, redacted metadata.
    pub meta: SocialMeta,
}

/// Paid social intelligence service with strict budget and candidate gating.
///
/// # Invariants
/// - **No broad discovery.** Only [`SocialPriority::ActivePositionRisk`],
///   [`SocialPriority::HighConvictionPreTrade`], and
///   [`SocialPriority::PromisingCandidate`] exist; pre-trade priorities require
///   an eligible candidate and position risk requires a position context.
/// - **Budget never disables execution.** The service has no execution
///   dependency and always returns a response; budget exhaustion degrades the
///   snapshot (or serves stale data) and never propagates an error.
/// - **Provider failure degrades only.** A failed fetch is negatively cached and
///   serves a stale fallback when one exists.
/// - **Provider identity.** The broker cache/breaker key space only has
///   `Fomo`/`Gmgn`; the attention-domain `Fomo` namespace is used as the social
///   cache namespace with the distinct `"social_intel"` operation, so entries
///   cannot collide with any other operation.
pub struct SocialIntelService<P: SocialProvider> {
    provider: P,
    budget: ProviderBudget,
    cache: LogicalCache,
    policy: SocialPolicy,
}

impl<P: SocialProvider> SocialIntelService<P> {
    /// Builds the service from a provider, a policy, and the budget epoch.
    pub fn new(provider: P, policy: SocialPolicy, start_ms: u64) -> Self {
        Self {
            provider,
            budget: ProviderBudget::new(
                policy.budget_capacity,
                policy.budget_refill_per_sec,
                start_ms,
            ),
            cache: LogicalCache::new(),
            policy,
        }
    }

    /// Returns social intelligence for `request`, applying candidate gating,
    /// budget gating, the freshness cache, negative caching, and stale fallback.
    pub async fn get_intelligence(
        &mut self,
        request: SocialRequest,
        now_ms: u64,
    ) -> SocialResponse {
        let cost = request.priority.cost_units();

        // Candidate/position gating before any cache or provider work: an
        // ineligible request spends no budget and touches no provider.
        if let Some(reason) = gate(&request) {
            return degraded(&request, now_ms, CacheState::Miss, Some(reason), cost, None);
        }

        let key = cache_key(&request);
        match self.cache.lookup::<SocialSnapshot>(
            &key,
            now_ms,
            self.policy.fresh_ttl_ms,
            self.policy.stale_grace_ms,
        ) {
            CacheLookup::Fresh { value, age_ms } => SocialResponse {
                value: (*value).clone(),
                meta: SocialMeta {
                    cache_state: CacheState::FreshHit,
                    degraded_reason: None,
                    freshness_ms: Some(age_ms),
                    request_cost: cost,
                },
            },
            CacheLookup::Negative(_) => degraded(
                &request,
                now_ms,
                CacheState::NegativeHit,
                Some(DegradedReason::NegativeCached),
                cost,
                None,
            ),
            CacheLookup::Stale { value, age_ms } => {
                self.refresh_or_fallback(request, key, Some((value, Some(age_ms))), now_ms, cost)
                    .await
            }
            CacheLookup::Expired(value) => {
                self.refresh_or_fallback(
                    request,
                    key,
                    value.map(|value| (value, None)),
                    now_ms,
                    cost,
                )
                .await
            }
            CacheLookup::Miss => {
                self.refresh_or_fallback(request, key, None, now_ms, cost)
                    .await
            }
        }
    }

    /// Tries to refresh from the provider within budget; on budget exhaustion or
    /// provider failure, serves `fallback` when present.
    async fn refresh_or_fallback(
        &mut self,
        request: SocialRequest,
        key: LogicalRequestKey,
        fallback: Option<(Arc<SocialSnapshot>, Option<u64>)>,
        now_ms: u64,
        cost: u32,
    ) -> SocialResponse {
        if self.budget.try_consume(now_ms, cost).is_err() {
            return fallback_or_degraded(
                &request,
                now_ms,
                fallback,
                CacheState::Miss,
                Some(DegradedReason::BudgetExhausted),
                cost,
            );
        }
        match self.provider.fetch(&request).await {
            Ok(snapshot) => {
                self.cache
                    .insert_success(key, Arc::new(snapshot.clone()), now_ms);
                SocialResponse {
                    value: snapshot,
                    meta: SocialMeta {
                        cache_state: CacheState::Miss,
                        degraded_reason: None,
                        freshness_ms: None,
                        request_cost: cost,
                    },
                }
            }
            Err(_) => {
                self.cache.insert_negative(
                    key,
                    OpaqueFailureKind::ServiceUnavailable,
                    now_ms.saturating_add(self.policy.negative_ttl_ms),
                );
                fallback_or_degraded(
                    &request,
                    now_ms,
                    fallback,
                    CacheState::NegativeHit,
                    Some(DegradedReason::ProviderUnavailable),
                    cost,
                )
            }
        }
    }
}

impl<P: SocialProvider> std::fmt::Debug for SocialIntelService<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the provider, cache, budget, or policy internals.
        formatter
            .debug_struct("SocialIntelService")
            .finish_non_exhaustive()
    }
}

/// Enforces the permitted priority/context combinations.
fn gate(request: &SocialRequest) -> Option<DegradedReason> {
    match request.priority {
        SocialPriority::ActivePositionRisk => {
            if request.position.is_some() {
                None
            } else {
                Some(DegradedReason::CandidateGatingRejected)
            }
        }
        SocialPriority::HighConvictionPreTrade | SocialPriority::PromisingCandidate => {
            match &request.candidate {
                Some(candidate) if candidate.is_eligible() => None,
                _ => Some(DegradedReason::CandidateGatingRejected),
            }
        }
    }
}

/// Canonical, non-reversible-enough cache key for a request.
fn cache_key(request: &SocialRequest) -> LogicalRequestKey {
    let context = RequestContext {
        candidate: request.candidate.clone(),
        position: request.position.clone(),
        priority: request_priority(request.priority),
    };
    // `LogicalRequestKey` keeps only the candidate/position identity in the key;
    // the asset is bound through `canonical_args`.
    let args = serde_json::to_string(&(&request.chain, &request.token)).unwrap_or_default();
    LogicalRequestKey::new(ProviderId::Fomo, SOCIAL_OPERATION, args, &context)
}

const fn request_priority(priority: SocialPriority) -> RequestPriority {
    match priority {
        SocialPriority::ActivePositionRisk | SocialPriority::HighConvictionPreTrade => {
            RequestPriority::High
        }
        SocialPriority::PromisingCandidate => RequestPriority::Normal,
    }
}

fn fallback_or_degraded(
    request: &SocialRequest,
    now_ms: u64,
    fallback: Option<(Arc<SocialSnapshot>, Option<u64>)>,
    miss_state: CacheState,
    reason: Option<DegradedReason>,
    cost: u32,
) -> SocialResponse {
    match fallback {
        Some((value, age_ms)) => SocialResponse {
            value: (*value).clone(),
            meta: SocialMeta {
                cache_state: CacheState::StaleServed,
                degraded_reason: reason,
                freshness_ms: age_ms,
                request_cost: cost,
            },
        },
        None => degraded(request, now_ms, miss_state, reason, cost, None),
    }
}

fn degraded(
    request: &SocialRequest,
    now_ms: u64,
    cache_state: CacheState,
    reason: Option<DegradedReason>,
    cost: u32,
    freshness_ms: Option<u64>,
) -> SocialResponse {
    SocialResponse {
        value: SocialSnapshot {
            chain: request.chain.clone(),
            token: request.token.clone(),
            signals: Vec::new(),
            observed_at_ms: i64::try_from(now_ms).unwrap_or(i64::MAX),
        },
        meta: SocialMeta {
            cache_state,
            degraded_reason: reason,
            freshness_ms,
            request_cost: cost,
        },
    }
}
