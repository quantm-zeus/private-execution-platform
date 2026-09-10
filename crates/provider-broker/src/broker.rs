//! Main Provider Intelligence Broker implementation.
//!
//! Enforces:
//! - Request coalescing / singleflight: identical concurrent requests cause at most 1 adapter invocation.
//! - Provider-specific freshness: distinct FOMO/GMGN TTLs, fresh cache hit, stale-while-revalidate (SWR).
//! - Negative caching: opaque failures cached for provider-specific negative TTL.
//! - Weighted budgets: operation cost deduction and deterministic replenishment.
//! - Priority shedding, cooldown, and fail-closed circuit breaker.
//! - Candidate gating: expensive enrichment rejected before adapter call unless candidate criteria met.
//! - Position isolation: position context part of cache key to prevent cross-position leakage.
//! - Safe metadata without endpoints, payloads, credentials, or raw error disclosures.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use mcp_adapters::{
    FomoCapabilitiesResponse, FomoEnvelope, FomoGetTokenRequest, FomoRecentEventsRequest,
    FomoSearchTokensRequest, FomoTrendingTokensRequest, GmgnKlineRequest, GmgnResponse,
    GmgnSearchRequest, GmgnTokenRequest, GmgnTopHoldersRequest, GmgnTrendingRequest,
    McpAdapterError,
};

use crate::budget::ProviderBudget;
use crate::cache::{CacheLookup, LogicalCache};
use crate::circuit::CircuitBreaker;
use crate::clock::Clock;
use crate::error::{BrokerError, OpaqueFailureKind};
use crate::key::{LogicalRequestKey, ProviderId, RequestContext, RequestPriority};
use crate::meta::{
    BrokerResponse, CacheState, DegradedReason, ProviderHealth, ProviderHealthState, ResponseMeta,
};
use crate::policy::{
    BrokerConfig, OperationProfile, OP_FOMO_CAPABILITIES, OP_FOMO_GET_RECENT_EVENTS,
    OP_FOMO_GET_TOKEN, OP_FOMO_GET_TRENDING_TOKENS, OP_FOMO_SEARCH_TOKENS, OP_GMGN_KLINE,
    OP_GMGN_SEARCH, OP_GMGN_TOKEN_INFO, OP_GMGN_TOKEN_SECURITY, OP_GMGN_TOP_HOLDERS,
    OP_GMGN_TRENDING,
};
use crate::provider::IntelligenceProvider;

struct ProviderState {
    budget: ProviderBudget,
    circuit: CircuitBreaker,
}

impl ProviderState {
    fn new(provider: ProviderId, config: &BrokerConfig, start_ms: u64) -> Self {
        let policy = config.policy_for(provider);
        Self {
            budget: ProviderBudget::new(policy.max_budget, policy.budget_refill_per_sec, start_ms),
            circuit: CircuitBreaker::new(
                provider,
                policy.failure_threshold,
                policy.cooldown_duration_ms,
            ),
        }
    }

    fn pre_flight_check(
        &mut self,
        now_ms: u64,
        cost: u32,
        priority: RequestPriority,
    ) -> Result<(), DegradedReason> {
        // 1. Check circuit breaker / cooldown
        self.circuit.check_allowed(now_ms)?;

        // 2. Priority pressure shedding (low priority shed if budget < 25% or health not Healthy)
        if (self.budget.is_under_pressure(now_ms)
            || self.circuit.health_state(now_ms) != ProviderHealthState::Healthy)
            && priority == RequestPriority::Low
        {
            return Err(DegradedReason::LowPriorityShed);
        }

        // 3. Deduct budget
        self.budget.try_consume(now_ms, cost)?;

        Ok(())
    }
}

type InFlightOutcome = Result<Arc<dyn Any + Send + Sync>, BrokerError>;
type InFlightMap = HashMap<LogicalRequestKey, watch::Sender<Option<InFlightOutcome>>>;

/// Provider Intelligence Broker.
pub struct ProviderBroker {
    clock: Arc<dyn Clock>,
    provider: Arc<dyn IntelligenceProvider>,
    config: BrokerConfig,
    cache: Mutex<LogicalCache>,
    fomo_state: Mutex<ProviderState>,
    gmgn_state: Mutex<ProviderState>,
    in_flight: Mutex<InFlightMap>,
    swr_pending: Mutex<HashSet<LogicalRequestKey>>,
    swr_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl ProviderBroker {
    /// Constructs a new `ProviderBroker` with an injected clock, provider, and policy configuration.
    pub fn new(
        clock: Arc<dyn Clock>,
        provider: Arc<dyn IntelligenceProvider>,
        config: BrokerConfig,
    ) -> Arc<Self> {
        let now_ms = clock.now_ms();
        let fomo_state = Mutex::new(ProviderState::new(ProviderId::Fomo, &config, now_ms));
        let gmgn_state = Mutex::new(ProviderState::new(ProviderId::Gmgn, &config, now_ms));

        Arc::new(Self {
            clock,
            provider,
            config,
            cache: Mutex::new(LogicalCache::new()),
            fomo_state,
            gmgn_state,
            in_flight: Mutex::new(HashMap::new()),
            swr_pending: Mutex::new(HashSet::new()),
            swr_handles: Mutex::new(Vec::new()),
        })
    }

    /// Returns a health snapshot for the given provider.
    pub fn health(&self, provider: ProviderId) -> ProviderHealth {
        let now_ms = self.clock.now_ms();
        match provider {
            ProviderId::Fomo => {
                let state = self.fomo_state.lock().unwrap();
                let available = state.budget.available_units(now_ms);
                state.circuit.snapshot(now_ms, available)
            }
            ProviderId::Gmgn => {
                let state = self.gmgn_state.lock().unwrap();
                let available = state.budget.available_units(now_ms);
                state.circuit.snapshot(now_ms, available)
            }
        }
    }

    /// Flushes and awaits all pending asynchronous SWR refresh tasks.
    ///
    /// Enables 100% deterministic test synchronization without wall-clock sleeps.
    pub async fn flush_swr(&self) {
        loop {
            let handles: Vec<_> = {
                let mut guard = self.swr_handles.lock().unwrap();
                std::mem::take(&mut *guard)
            };
            if handles.is_empty() {
                break;
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
    }

    // ------------------------------------------------------------------ //
    // FOMO TYPED OPERATIONS
    // ------------------------------------------------------------------ //

    pub async fn fomo_capabilities(
        self: &Arc<Self>,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<FomoCapabilitiesResponse>, BrokerError> {
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            OP_FOMO_CAPABILITIES.name,
            String::new(),
            ctx,
        );
        let prov = self.provider.clone();
        self.execute_logical_request(
            key,
            &OP_FOMO_CAPABILITIES,
            ProviderId::Fomo,
            ctx,
            move || {
                let p = prov.clone();
                async move { p.fomo_capabilities().await }
            },
        )
        .await
    }

    pub async fn fomo_search_tokens(
        self: &Arc<Self>,
        req: FomoSearchTokensRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<FomoEnvelope>, BrokerError> {
        let query = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Fomo, err))?;
        let canonical_args = format!("query={query}");
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            OP_FOMO_SEARCH_TOKENS.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(
            key,
            &OP_FOMO_SEARCH_TOKENS,
            ProviderId::Fomo,
            ctx,
            move || {
                let p = prov.clone();
                let r = cloned_req.clone();
                async move { p.fomo_search_tokens(r).await }
            },
        )
        .await
    }

    pub async fn fomo_get_token(
        self: &Arc<Self>,
        req: FomoGetTokenRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<FomoEnvelope>, BrokerError> {
        let (nid, addr) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Fomo, err))?;
        let canonical_args = format!("{nid}:{addr}");
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            OP_FOMO_GET_TOKEN.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(key, &OP_FOMO_GET_TOKEN, ProviderId::Fomo, ctx, move || {
            let p = prov.clone();
            let r = cloned_req.clone();
            async move { p.fomo_get_token(r).await }
        })
        .await
    }

    pub async fn fomo_get_trending_tokens(
        self: &Arc<Self>,
        req: FomoTrendingTokensRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<FomoEnvelope>, BrokerError> {
        let list = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Fomo, err))?;
        let canonical_args = format!("list={list}");
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            OP_FOMO_GET_TRENDING_TOKENS.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(
            key,
            &OP_FOMO_GET_TRENDING_TOKENS,
            ProviderId::Fomo,
            ctx,
            move || {
                let p = prov.clone();
                let r = cloned_req.clone();
                async move { p.fomo_get_trending_tokens(r).await }
            },
        )
        .await
    }

    pub async fn fomo_get_recent_events(
        self: &Arc<Self>,
        req: FomoRecentEventsRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<FomoEnvelope>, BrokerError> {
        let validated_args = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Fomo, err))?;
        let canonical_args = serde_json::to_string(&validated_args).unwrap_or_default();
        let key = LogicalRequestKey::new(
            ProviderId::Fomo,
            OP_FOMO_GET_RECENT_EVENTS.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(
            key,
            &OP_FOMO_GET_RECENT_EVENTS,
            ProviderId::Fomo,
            ctx,
            move || {
                let p = prov.clone();
                let r = cloned_req.clone();
                async move { p.fomo_get_recent_events(r).await }
            },
        )
        .await
    }

    // ------------------------------------------------------------------ //
    // GMGN TYPED OPERATIONS
    // ------------------------------------------------------------------ //

    pub async fn gmgn_trending(
        self: &Arc<Self>,
        req: GmgnTrendingRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (chain, interval, limit) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{chain}:{interval}:{limit}");
        let key =
            LogicalRequestKey::new(ProviderId::Gmgn, OP_GMGN_TRENDING.name, canonical_args, ctx);
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(key, &OP_GMGN_TRENDING, ProviderId::Gmgn, ctx, move || {
            let p = prov.clone();
            let r = cloned_req.clone();
            async move { p.gmgn_trending(r).await }
        })
        .await
    }

    pub async fn gmgn_search(
        self: &Arc<Self>,
        req: GmgnSearchRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (query, chain) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{query}:{chain:?}");
        let key =
            LogicalRequestKey::new(ProviderId::Gmgn, OP_GMGN_SEARCH.name, canonical_args, ctx);
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(key, &OP_GMGN_SEARCH, ProviderId::Gmgn, ctx, move || {
            let p = prov.clone();
            let r = cloned_req.clone();
            async move { p.gmgn_search(r).await }
        })
        .await
    }

    pub async fn gmgn_token_info(
        self: &Arc<Self>,
        req: GmgnTokenRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (chain, address) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{chain}:{address}");
        let key = LogicalRequestKey::new(
            ProviderId::Gmgn,
            OP_GMGN_TOKEN_INFO.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(key, &OP_GMGN_TOKEN_INFO, ProviderId::Gmgn, ctx, move || {
            let p = prov.clone();
            let r = cloned_req.clone();
            async move { p.gmgn_token_info(r).await }
        })
        .await
    }

    pub async fn gmgn_token_security(
        self: &Arc<Self>,
        req: GmgnTokenRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (chain, address) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{chain}:{address}");
        let key = LogicalRequestKey::new(
            ProviderId::Gmgn,
            OP_GMGN_TOKEN_SECURITY.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(
            key,
            &OP_GMGN_TOKEN_SECURITY,
            ProviderId::Gmgn,
            ctx,
            move || {
                let p = prov.clone();
                let r = cloned_req.clone();
                async move { p.gmgn_token_security(r).await }
            },
        )
        .await
    }

    pub async fn gmgn_top_holders(
        self: &Arc<Self>,
        req: GmgnTopHoldersRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (chain, address, limit, order_by) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{chain}:{address}:{limit}:{order_by:?}");
        let key = LogicalRequestKey::new(
            ProviderId::Gmgn,
            OP_GMGN_TOP_HOLDERS.name,
            canonical_args,
            ctx,
        );
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(
            key,
            &OP_GMGN_TOP_HOLDERS,
            ProviderId::Gmgn,
            ctx,
            move || {
                let p = prov.clone();
                let r = cloned_req.clone();
                async move { p.gmgn_top_holders(r).await }
            },
        )
        .await
    }

    pub async fn gmgn_kline(
        self: &Arc<Self>,
        req: GmgnKlineRequest,
        ctx: &RequestContext,
    ) -> Result<BrokerResponse<GmgnResponse>, BrokerError> {
        let (chain, address, resolution, from, to) = req
            .validate()
            .map_err(|err| self.build_invalid_arg_err(ProviderId::Gmgn, err))?;
        let canonical_args = format!("{chain}:{address}:{resolution}:{from:?}:{to:?}");
        let key = LogicalRequestKey::new(ProviderId::Gmgn, OP_GMGN_KLINE.name, canonical_args, ctx);
        let prov = self.provider.clone();
        let cloned_req = req.clone();
        self.execute_logical_request(key, &OP_GMGN_KLINE, ProviderId::Gmgn, ctx, move || {
            let p = prov.clone();
            let r = cloned_req.clone();
            async move { p.gmgn_kline(r).await }
        })
        .await
    }

    fn build_invalid_arg_err(&self, provider: ProviderId, err: McpAdapterError) -> BrokerError {
        let meta = self.build_meta(
            provider,
            CacheState::Miss,
            None,
            Some(DegradedReason::CandidateGatingRejected),
            self.clock.now_ms(),
            0,
        );
        BrokerError::Adapter { error: err, meta }
    }

    // ------------------------------------------------------------------ //
    // INTERNAL REQUEST PIPELINE
    // ------------------------------------------------------------------ //

    fn build_meta(
        &self,
        provider: ProviderId,
        cache_state: CacheState,
        freshness_ms: Option<u64>,
        degraded_reason: Option<DegradedReason>,
        now_ms: u64,
        cost: u32,
    ) -> ResponseMeta {
        let (health_state, consecutive_failures) = match provider {
            ProviderId::Fomo => {
                let s = self.fomo_state.lock().unwrap();
                (
                    s.circuit.health_state(now_ms),
                    s.circuit.consecutive_failures(),
                )
            }
            ProviderId::Gmgn => {
                let s = self.gmgn_state.lock().unwrap();
                (
                    s.circuit.health_state(now_ms),
                    s.circuit.consecutive_failures(),
                )
            }
        };

        ResponseMeta {
            provider,
            cache_state,
            freshness_ms,
            degraded_reason,
            health_state,
            consecutive_failures,
            request_cost: cost,
        }
    }

    async fn execute_logical_request<T, F, Fut>(
        self: &Arc<Self>,
        key: LogicalRequestKey,
        op: &OperationProfile,
        provider: ProviderId,
        context: &RequestContext,
        fetch_factory: F,
    ) -> Result<BrokerResponse<T>, BrokerError>
    where
        T: Clone + Send + Sync + 'static,
        F: Fn() -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<T, McpAdapterError>> + Send + 'static,
    {
        let now_ms = self.clock.now_ms();

        // 1. Candidate gating for expensive enrichment
        if op.classification.is_expensive() {
            let is_eligible = context.candidate.as_ref().is_some_and(|c| c.is_eligible());
            if !is_eligible {
                let candidate_id = context
                    .candidate
                    .as_ref()
                    .map(|c| c.candidate_id.clone())
                    .unwrap_or_else(|| "none".to_string());
                let meta = self.build_meta(
                    provider,
                    CacheState::Miss,
                    None,
                    Some(DegradedReason::CandidateGatingRejected),
                    now_ms,
                    0,
                );
                return Err(BrokerError::CandidateNotEligible { candidate_id, meta });
            }
        }

        // 2. Cache inspection
        let policy = self.config.policy_for(provider);
        let lookup = {
            let mut cache = self.cache.lock().unwrap();
            cache.lookup::<T>(&key, now_ms, policy.fresh_ttl_ms, policy.stale_grace_ms)
        };

        match lookup {
            CacheLookup::Fresh { value, age_ms } => {
                let meta = self.build_meta(
                    provider,
                    CacheState::FreshHit,
                    Some(age_ms),
                    None,
                    now_ms,
                    0,
                );
                return Ok(BrokerResponse::new((*value).clone(), meta));
            }
            CacheLookup::Negative(kind) => {
                let meta = self.build_meta(
                    provider,
                    CacheState::NegativeHit,
                    None,
                    Some(DegradedReason::NegativeCached),
                    now_ms,
                    0,
                );
                return Err(BrokerError::NegativeCached {
                    provider,
                    kind,
                    meta,
                });
            }
            CacheLookup::Stale { value, age_ms } => {
                // Stale hit within grace: serve stale immediately and schedule at most one SWR refresh
                let swr_factory = {
                    let f = fetch_factory.clone();
                    move || {
                        let fut = f();
                        Box::pin(async move {
                            fut.await.map(|v| Arc::new(v) as Arc<dyn Any + Send + Sync>)
                        })
                            as Pin<
                                Box<
                                    dyn Future<
                                            Output = Result<
                                                Arc<dyn Any + Send + Sync>,
                                                McpAdapterError,
                                            >,
                                        > + Send,
                                >,
                            >
                    }
                };
                self.maybe_schedule_swr(key.clone(), provider, op.weight, swr_factory);
                let meta = self.build_meta(
                    provider,
                    CacheState::StaleServed,
                    Some(age_ms),
                    None,
                    now_ms,
                    0,
                );
                return Ok(BrokerResponse::new((*value).clone(), meta));
            }
            CacheLookup::Miss | CacheLookup::Expired(_) => {
                // Cache miss or expired: fall through to upstream dispatch
            }
        }

        // 3. Singleflight coalescing for concurrent requests
        let (follower_rx, is_leader) = {
            let mut in_flight = self.in_flight.lock().unwrap();
            if let Some(tx) = in_flight.get(&key) {
                (Some(tx.subscribe()), false)
            } else {
                let (tx, _rx) = watch::channel(None);
                in_flight.insert(key.clone(), tx);
                (None, true)
            }
        };

        if !is_leader {
            let mut rx = follower_rx.unwrap();
            while rx.borrow().is_none() {
                if rx.changed().await.is_err() {
                    let meta = self.build_meta(
                        provider,
                        CacheState::Miss,
                        None,
                        Some(DegradedReason::ProviderUnavailable),
                        self.clock.now_ms(),
                        0,
                    );
                    return Err(BrokerError::Adapter {
                        error: McpAdapterError::TransportFailure { service: provider },
                        meta,
                    });
                }
            }

            let outcome = rx.borrow().as_ref().unwrap().clone();
            return match outcome {
                Ok(any_arc) => {
                    let typed = any_arc
                        .downcast::<T>()
                        .expect("type downcast error in coalesced response");
                    let meta = self.build_meta(
                        provider,
                        CacheState::Miss,
                        Some(0),
                        None,
                        self.clock.now_ms(),
                        0,
                    );
                    Ok(BrokerResponse::new((*typed).clone(), meta))
                }
                Err(err) => Err(err),
            };
        }

        // Leader branch: perform pre-flight check (budget charged exactly once here), invoke adapter, and broadcast outcome
        self.execute_leader_and_broadcast::<T, F, Fut>(
            key,
            provider,
            op.weight,
            context.priority,
            fetch_factory,
        )
        .await
    }

    async fn execute_leader_and_broadcast<T, F, Fut>(
        &self,
        key: LogicalRequestKey,
        provider: ProviderId,
        cost: u32,
        priority: RequestPriority,
        fetch_factory: F,
    ) -> Result<BrokerResponse<T>, BrokerError>
    where
        T: Clone + Send + Sync + 'static,
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, McpAdapterError>> + Send + 'static,
    {
        let now_ms = self.clock.now_ms();

        // 1. Leader pre-flight check (circuit breaker, pressure shedding, and budget deduction)
        let pre_flight_res = match provider {
            ProviderId::Fomo => self
                .fomo_state
                .lock()
                .unwrap()
                .pre_flight_check(now_ms, cost, priority),
            ProviderId::Gmgn => self
                .gmgn_state
                .lock()
                .unwrap()
                .pre_flight_check(now_ms, cost, priority),
        };

        if let Err(degraded_reason) = pre_flight_res {
            // Remove from in_flight map and broadcast failure to any followers that registered
            let maybe_tx = {
                let mut in_flight = self.in_flight.lock().unwrap();
                in_flight.remove(&key)
            };

            // Attempt to serve historical stale fallback if available during degradation
            if let Some(fallback) = self.cache.lock().unwrap().get_stale_fallback::<T>(&key) {
                let meta = self.build_meta(
                    provider,
                    CacheState::StaleServed,
                    None,
                    Some(degraded_reason),
                    now_ms,
                    0,
                );
                if let Some(tx) = maybe_tx {
                    let _ = tx.send(Some(Ok(fallback.clone() as Arc<dyn Any + Send + Sync>)));
                }
                return Ok(BrokerResponse::new((*fallback).clone(), meta));
            }

            let meta = self.build_meta(
                provider,
                CacheState::Miss,
                None,
                Some(degraded_reason),
                now_ms,
                0,
            );
            let broker_err = match degraded_reason {
                DegradedReason::BudgetExhausted => BrokerError::BudgetExhausted { provider, meta },
                DegradedReason::CircuitBreakerOpen => BrokerError::CircuitOpen { provider, meta },
                DegradedReason::CooldownActive => BrokerError::CooldownActive { provider, meta },
                DegradedReason::LowPriorityShed => BrokerError::PriorityShed { provider, meta },
                DegradedReason::CandidateGatingRejected => BrokerError::CandidateNotEligible {
                    candidate_id: "none".into(),
                    meta,
                },
                DegradedReason::ProviderUnavailable => BrokerError::Adapter {
                    error: McpAdapterError::ServiceUnavailable { service: provider },
                    meta,
                },
                DegradedReason::NegativeCached => BrokerError::NegativeCached {
                    provider,
                    kind: OpaqueFailureKind::Other,
                    meta,
                },
            };

            if let Some(tx) = maybe_tx {
                let _ = tx.send(Some(Err(broker_err.clone())));
            }
            return Err(broker_err);
        }

        // 2. Budget is charged exactly once for this leader invocation. Invoke adapter.
        let fut = fetch_factory();
        let adapter_res = fut.await;

        let (final_res, broadcast_outcome) = match adapter_res {
            Ok(value) => {
                let arc_val = Arc::new(value.clone());
                // Record success in circuit breaker
                match provider {
                    ProviderId::Fomo => self.fomo_state.lock().unwrap().circuit.record_success(),
                    ProviderId::Gmgn => self.gmgn_state.lock().unwrap().circuit.record_success(),
                }

                // Insert into cache
                self.cache.lock().unwrap().insert_success(
                    key.clone(),
                    arc_val.clone() as Arc<dyn Any + Send + Sync>,
                    now_ms,
                );

                let meta = self.build_meta(provider, CacheState::Miss, Some(0), None, now_ms, cost);

                (
                    Ok(BrokerResponse::new(value, meta)),
                    Ok(arc_val as Arc<dyn Any + Send + Sync>),
                )
            }
            Err(err) => {
                // Record failure in circuit breaker
                match provider {
                    ProviderId::Fomo => self
                        .fomo_state
                        .lock()
                        .unwrap()
                        .circuit
                        .record_failure(now_ms),
                    ProviderId::Gmgn => self
                        .gmgn_state
                        .lock()
                        .unwrap()
                        .circuit
                        .record_failure(now_ms),
                }

                // Insert into negative cache
                let kind = OpaqueFailureKind::from(&err);
                let policy = self.config.policy_for(provider);
                self.cache.lock().unwrap().insert_negative(
                    key.clone(),
                    kind,
                    now_ms + policy.negative_ttl_ms,
                );

                let meta = self.build_meta(
                    provider,
                    CacheState::Miss,
                    None,
                    Some(DegradedReason::ProviderUnavailable),
                    now_ms,
                    cost,
                );
                let broker_err = BrokerError::Adapter { error: err, meta };

                (Err(broker_err.clone()), Err(broker_err))
            }
        };

        // Remove from in_flight map and broadcast to waiting followers
        let maybe_tx = {
            let mut in_flight = self.in_flight.lock().unwrap();
            in_flight.remove(&key)
        };

        if let Some(tx) = maybe_tx {
            let _ = tx.send(Some(broadcast_outcome));
        }

        final_res
    }

    fn maybe_schedule_swr<F>(
        self: &Arc<Self>,
        key: LogicalRequestKey,
        provider: ProviderId,
        cost: u32,
        fetch_factory: F,
    ) where
        F: Fn() -> Pin<
                Box<
                    dyn Future<Output = Result<Arc<dyn Any + Send + Sync>, McpAdapterError>> + Send,
                >,
            > + Send
            + Sync
            + 'static,
    {
        let is_new = self.swr_pending.lock().unwrap().insert(key.clone());
        if !is_new {
            return; // At most one SWR refresh scheduled
        }

        let this = self.clone();
        let handle = tokio::spawn(async move {
            let now_ms = this.clock.now_ms();

            // Pre-flight check before SWR execution
            let allowed = match provider {
                ProviderId::Fomo => this.fomo_state.lock().unwrap().pre_flight_check(
                    now_ms,
                    cost,
                    RequestPriority::Normal,
                ),
                ProviderId::Gmgn => this.gmgn_state.lock().unwrap().pre_flight_check(
                    now_ms,
                    cost,
                    RequestPriority::Normal,
                ),
            };

            if allowed.is_ok() {
                let fut = fetch_factory();
                match fut.await {
                    Ok(val) => {
                        match provider {
                            ProviderId::Fomo => {
                                this.fomo_state.lock().unwrap().circuit.record_success();
                            }
                            ProviderId::Gmgn => {
                                this.gmgn_state.lock().unwrap().circuit.record_success();
                            }
                        }
                        this.cache
                            .lock()
                            .unwrap()
                            .insert_success(key.clone(), val, now_ms);
                    }
                    Err(err) => {
                        match provider {
                            ProviderId::Fomo => {
                                this.fomo_state
                                    .lock()
                                    .unwrap()
                                    .circuit
                                    .record_failure(now_ms);
                            }
                            ProviderId::Gmgn => {
                                this.gmgn_state
                                    .lock()
                                    .unwrap()
                                    .circuit
                                    .record_failure(now_ms);
                            }
                        }
                        let kind = OpaqueFailureKind::from(&err);
                        let policy = this.config.policy_for(provider);
                        this.cache.lock().unwrap().insert_negative(
                            key.clone(),
                            kind,
                            now_ms + policy.negative_ttl_ms,
                        );
                    }
                }
            }

            this.swr_pending.lock().unwrap().remove(&key);
        });

        self.swr_handles.lock().unwrap().push(handle);
    }
}
