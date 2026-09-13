//! The budgeted, candidate-gated social intelligence service.

use std::sync::Arc;

use provider_broker::{
    CacheLookup, CacheState, DegradedReason, LogicalCache, LogicalRequestKey, OpaqueFailureKind,
    ProviderBudget, ProviderId, RequestContext, RequestPriority,
};

use crate::policy::{SocialPolicy, SocialPriority};
use crate::provider::{SocialProvider, SocialRequest, SocialSnapshot, MAX_SIGNALS, MAX_WEIGHT_BPS};

/// Canonical cache operation name; isolates social entries from every other
/// broker operation sharing the cache namespace.
const SOCIAL_OPERATION: &str = "social_intel";

/// Prune the cache every this many calls (bounded housekeeping).
const PRUNE_INTERVAL_CALLS: u64 = 256;

/// Bounded metadata attached to every social response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocialMeta {
    /// How the response was satisfied.
    pub cache_state: CacheState,
    /// Why the response is degraded, if it is.
    pub degraded_reason: Option<DegradedReason>,
    /// Age of the served value when the cache path exposes it. `None` for a
    /// fresh provider fetch and for a negative-cache stale fallback (whose age is
    /// not recoverable from the lookup).
    pub freshness_ms: Option<u64>,
    /// Cost assigned to this request; charged to the budget only when the
    /// provider is actually called (never on a cache hit or gate rejection).
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
///   serves a stale fallback when one exists. A stale cache entry is revalidated
///   **synchronously** (the caller waits for the paid provider) and, on failure or
///   budget exhaustion, the stale value is served instead.
/// - **Bounded output.** Every snapshot the service caches or returns is
///   truncated to [`MAX_SIGNALS`] signals and each weight clamped to
///   [`MAX_WEIGHT_BPS`], and a snapshot whose chain/token does not match the
///   request is rejected as a provider failure.
/// - **Provider identity.** The broker key space only has `Fomo`/`Gmgn`; this
///   service keeps its own private cache, and uses the distinct `"social_intel"`
///   operation string so its entries can never collide with a broker operation
///   even if a shared cache is introduced later.
pub struct SocialIntelService<P: SocialProvider> {
    provider: P,
    budget: ProviderBudget,
    cache: LogicalCache,
    policy: SocialPolicy,
    calls: u64,
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
            calls: 0,
        }
    }

    /// Returns social intelligence for `request`, applying candidate gating,
    /// budget gating, the freshness cache, negative caching, and stale fallback.
    ///
    /// Never returns an error: every failure path yields a degraded (possibly
    /// empty) snapshot.
    pub async fn get_intelligence(
        &mut self,
        request: SocialRequest,
        now_ms: u64,
    ) -> SocialResponse {
        let cost = request.priority.cost_units();

        // Bounded cache housekeeping: a long-lived service must not accumulate
        // one entry per distinct asset/candidate/position forever.
        self.calls = self.calls.wrapping_add(1);
        if self.calls % PRUNE_INTERVAL_CALLS == 0 {
            self.cache
                .prune_expired(now_ms, self.policy.fresh_ttl_ms, self.policy.stale_grace_ms);
        }

        // Candidate/position gating before any cache or provider work: an
        // ineligible request spends no budget and touches no provider.
        if let Some(reason) = gate(&request) {
            return degraded(&request, now_ms, CacheState::Miss, Some(reason), cost, None);
        }

        let key = match cache_key(&request) {
            Ok(key) => key,
            // The key cannot be derived: fail closed rather than sharing a
            // collapsed key across distinct requests.
            Err(()) => {
                return degraded(
                    &request,
                    now_ms,
                    CacheState::Miss,
                    Some(DegradedReason::ProviderUnavailable),
                    cost,
                    None,
                )
            }
        };
        match self.cache.lookup::<SocialSnapshot>(
            &key,
            now_ms,
            self.policy.fresh_ttl_ms,
            self.policy.stale_grace_ms,
        ) {
            CacheLookup::Fresh { value, age_ms } => SocialResponse {
                value: sanitize((*value).clone()),
                meta: SocialMeta {
                    cache_state: CacheState::FreshHit,
                    degraded_reason: None,
                    freshness_ms: Some(age_ms),
                    request_cost: cost,
                },
            },
            // A negative entry must not hide still-usable stale data: serve the
            // stale fallback (without calling the provider) when one exists.
            CacheLookup::Negative(_) => match self.cache.get_stale_fallback::<SocialSnapshot>(&key)
            {
                Some(value) => SocialResponse {
                    value: sanitize((*value).clone()),
                    meta: SocialMeta {
                        cache_state: CacheState::StaleServed,
                        degraded_reason: Some(DegradedReason::NegativeCached),
                        freshness_ms: None,
                        request_cost: cost,
                    },
                },
                None => degraded(
                    &request,
                    now_ms,
                    CacheState::NegativeHit,
                    Some(DegradedReason::NegativeCached),
                    cost,
                    None,
                ),
            },
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
            // A snapshot that does not describe the requested chain/token is a
            // provider contract violation; fail closed exactly like an outage so
            // it is never cached under this request's key.
            Ok(snapshot) if snapshot.chain == request.chain && snapshot.token == request.token => {
                let snapshot = sanitize(snapshot);
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
            Ok(_) | Err(_) => {
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

/// Canonical cache key for a request.
///
/// Returns `Err(())` when the asset/chain cannot be canonically encoded, so the
/// caller fails closed instead of sharing a collapsed key across distinct
/// requests.
fn cache_key(request: &SocialRequest) -> Result<LogicalRequestKey, ()> {
    let context = RequestContext {
        candidate: request.candidate.clone(),
        position: request.position.clone(),
        priority: request_priority(request.priority),
    };
    // `LogicalRequestKey` keeps only the candidate/position identity in the key;
    // the asset is bound through `canonical_args`.
    let args = serde_json::to_string(&(&request.chain, &request.token)).map_err(|_| ())?;
    Ok(LogicalRequestKey::new(
        ProviderId::Fomo,
        SOCIAL_OPERATION,
        args,
        &context,
    ))
}

/// Bounds a provider snapshot before it is cached or returned.
fn sanitize(mut snapshot: SocialSnapshot) -> SocialSnapshot {
    snapshot.signals.truncate(MAX_SIGNALS);
    for signal in &mut snapshot.signals {
        signal.weight_bps = signal.weight_bps.min(MAX_WEIGHT_BPS);
    }
    snapshot
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
            // Sanitize again as defense-in-depth: every cached value is already
            // bounded at insert, but a fallback must never trust that.
            value: sanitize((*value).clone()),
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
