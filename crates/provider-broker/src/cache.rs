//! In-memory logical request cache with provider-specific freshness, SWR, and negative cache.
//!
//! Enforces:
//! - Fresh hit within provider-specific fresh TTL.
//! - Stale-while-revalidate (SWR) within stale grace period.
//! - Negative caching of opaque failures for bounded negative TTL.
//! - Stale fallback access for outage degradation.
//! - Zero leak of raw error strings, credentials, or sensitive request arguments.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::OpaqueFailureKind;
use crate::key::LogicalRequestKey;

struct CacheEntry {
    created_at_ms: u64,
    data: Arc<dyn Any + Send + Sync>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NegativeCacheEntry {
    cached_until_ms: u64,
    kind: OpaqueFailureKind,
}

pub enum CacheLookup<T> {
    /// Completely fresh data; serve immediately.
    Fresh { value: Arc<T>, age_ms: u64 },
    /// Stale data within grace period; serve immediately and schedule SWR.
    Stale { value: Arc<T>, age_ms: u64 },
    /// Active negative cache hit.
    Negative(OpaqueFailureKind),
    /// Expired cached data (can serve as fallback under complete outage).
    Expired(Option<Arc<T>>),
    /// Cache miss.
    Miss,
}

#[derive(Default)]
pub struct LogicalCache {
    entries: HashMap<LogicalRequestKey, CacheEntry>,
    negative_entries: HashMap<LogicalRequestKey, NegativeCacheEntry>,
}

impl LogicalCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates cache state for a request key according to the provider's freshness policy.
    pub fn lookup<T: 'static + Send + Sync>(
        &mut self,
        key: &LogicalRequestKey,
        now_ms: u64,
        fresh_ttl_ms: u64,
        stale_grace_ms: u64,
    ) -> CacheLookup<T> {
        // 1. Check negative cache first
        if let Some(neg) = self.negative_entries.get(key) {
            if now_ms < neg.cached_until_ms {
                return CacheLookup::Negative(neg.kind);
            }
            // Negative cache expired; clean up entry
            self.negative_entries.remove(key);
        }

        // 2. Check data cache
        if let Some(entry) = self.entries.get(key) {
            if let Ok(downcasted) = entry.data.clone().downcast::<T>() {
                let age_ms = now_ms.saturating_sub(entry.created_at_ms);
                if age_ms <= fresh_ttl_ms {
                    return CacheLookup::Fresh {
                        value: downcasted,
                        age_ms,
                    };
                } else if age_ms <= fresh_ttl_ms + stale_grace_ms {
                    return CacheLookup::Stale {
                        value: downcasted,
                        age_ms,
                    };
                } else {
                    return CacheLookup::Expired(Some(downcasted));
                }
            }
        }

        CacheLookup::Miss
    }

    /// Returns a stale fallback value if any historical entry exists, regardless of expiry.
    pub fn get_stale_fallback<T: 'static + Send + Sync>(
        &self,
        key: &LogicalRequestKey,
    ) -> Option<Arc<T>> {
        self.entries
            .get(key)
            .and_then(|entry| entry.data.clone().downcast::<T>().ok())
    }

    /// Inserts a successful result into the cache.
    pub fn insert_success(
        &mut self,
        key: LogicalRequestKey,
        value: Arc<dyn Any + Send + Sync>,
        now_ms: u64,
    ) {
        // Clear any previous negative cache for this key
        self.negative_entries.remove(&key);
        self.entries.insert(
            key,
            CacheEntry {
                created_at_ms: now_ms,
                data: value,
            },
        );
    }

    /// Inserts an opaque failure outcome into the negative cache.
    pub fn insert_negative(
        &mut self,
        key: LogicalRequestKey,
        kind: OpaqueFailureKind,
        cached_until_ms: u64,
    ) {
        self.negative_entries.insert(
            key,
            NegativeCacheEntry {
                cached_until_ms,
                kind,
            },
        );
    }

    /// Clears expired entries.
    pub fn prune_expired(&mut self, now_ms: u64, fresh_ttl_ms: u64, stale_grace_ms: u64) {
        let max_age = fresh_ttl_ms + stale_grace_ms;
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.created_at_ms) <= max_age);
        self.negative_entries
            .retain(|_, neg| now_ms < neg.cached_until_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{ProviderId, RequestContext};

    #[test]
    fn test_cache_fresh_stale_expired_transitions() {
        let mut cache = LogicalCache::new();
        let ctx = RequestContext::default();
        let key = LogicalRequestKey::new(ProviderId::Gmgn, "trending", "sol:1h".into(), &ctx);

        let data = Arc::new("trending_tokens_json".to_string());
        let fresh_ttl = 10_000;
        let stale_grace = 20_000;

        // Insert at t = 1,000
        cache.insert_success(
            key.clone(),
            data.clone() as Arc<dyn Any + Send + Sync>,
            1_000,
        );

        // At t = 5,000 (age 4,000 < fresh_ttl 10,000) -> Fresh
        match cache.lookup::<String>(&key, 5_000, fresh_ttl, stale_grace) {
            CacheLookup::Fresh { value, age_ms } => {
                assert_eq!(*value, "trending_tokens_json");
                assert_eq!(age_ms, 4_000);
            }
            _ => panic!("expected Fresh"),
        }

        // At t = 15,000 (age 14,000 > fresh_ttl, < fresh_ttl + stale_grace 30,000) -> Stale
        match cache.lookup::<String>(&key, 15_000, fresh_ttl, stale_grace) {
            CacheLookup::Stale { value, age_ms } => {
                assert_eq!(*value, "trending_tokens_json");
                assert_eq!(age_ms, 14_000);
            }
            _ => panic!("expected Stale"),
        }

        // At t = 35_000 (age 34,000 > 30,000) -> Expired
        match cache.lookup::<String>(&key, 35_000, fresh_ttl, stale_grace) {
            CacheLookup::Expired(Some(value)) => {
                assert_eq!(*value, "trending_tokens_json");
            }
            _ => panic!("expected Expired"),
        }
    }

    #[test]
    fn test_negative_cache_lifecycle() {
        let mut cache = LogicalCache::new();
        let ctx = RequestContext::default();
        let key = LogicalRequestKey::new(ProviderId::Fomo, "get_token", "8453:0x123".into(), &ctx);

        // Negative cache until t = 5_000
        cache.insert_negative(key.clone(), OpaqueFailureKind::ServiceUnavailable, 5_000);

        // At t = 2_000 -> Negative hit
        match cache.lookup::<String>(&key, 2_000, 10_000, 20_000) {
            CacheLookup::Negative(kind) => {
                assert_eq!(kind, OpaqueFailureKind::ServiceUnavailable);
            }
            _ => panic!("expected Negative"),
        }

        // At t = 6_000 -> Expired negative cache maps to Miss
        match cache.lookup::<String>(&key, 6_000, 10_000, 20_000) {
            CacheLookup::Miss => {}
            _ => panic!("expected Miss after negative TTL"),
        }
    }
}
