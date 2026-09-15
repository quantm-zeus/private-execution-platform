//! One-chain live composition (Base) — a real production path that is
//! fail-closed by default.
//!
//! [`build_live_relay`] assembles the concrete production relay over a durable
//! attempt store, a chain submission adapter, a signed-payload source, and an
//! injected Privy signing transport. It is the code path a deployment uses once
//! credentials and adapters exist; nothing in this module reads credentials or
//! performs I/O, and the default startup never reaches it.
//!
//! The relay still enforces the live policy kill switch, chain health, and the
//! durable exactly-once lifecycle, so building this relay does **not** itself
//! enable trading.

use std::sync::Arc;

use execution_relay::{
    ChainHealthBreaker, ChainSubmissionAdapter, DurableAttemptStore, ExecutionRelay,
    PrivySigningBoundaryAdapter, SignedPayloadSource, UnavailableChainAdapter,
};
use policy::PolicyEngine;
use privy::{PrivyHttpSigningTransport, SigningTransport, UnavailablePrivyHttpClient};

use crate::composition::{UnavailableDurableAttemptStore, UnavailablePayloadSource};

/// The concrete live one-chain relay type.
pub type LiveRelay = ExecutionRelay<
    Arc<dyn DurableAttemptStore>,
    Arc<dyn ChainSubmissionAdapter>,
    Arc<dyn SignedPayloadSource>,
    PrivySigningBoundaryAdapter,
>;

/// Operator-injected dependencies for the live one-chain path.
pub struct LiveDependencies {
    /// The policy engine that owns the live kill switch and limits.
    pub policy: PolicyEngine,
    /// The durable exactly-once attempt store.
    pub store: Arc<dyn DurableAttemptStore>,
    /// The Base chain submission/reconciliation adapter.
    pub chain: Arc<dyn ChainSubmissionAdapter>,
    /// The signed-payload source (transaction builder seam).
    pub payload_source: Arc<dyn SignedPayloadSource>,
    /// The injected Privy signing transport.
    pub privy_transport: Box<dyn SigningTransport>,
    /// Chain health breaker policy.
    pub breaker: ChainHealthBreaker,
}

/// Builds the live one-chain relay from injected dependencies.
///
/// The store is required to be durable, so no live path can be assembled over
/// process-local bookkeeping.
pub fn build_live_relay(dependencies: LiveDependencies) -> LiveRelay {
    let LiveDependencies {
        policy,
        store,
        chain,
        payload_source,
        privy_transport,
        breaker,
    } = dependencies;
    ExecutionRelay::production_with_chain(
        policy,
        store,
        chain,
        payload_source,
        privy_transport,
        breaker,
    )
}

/// Builds a live one-chain relay whose every dependency fails closed: an
/// unavailable durable attempt store, an unavailable chain adapter, an
/// unavailable payload source, and the fail-closed Privy HTTP transport.
///
/// This is the wiring-validation path: it proves the production composition
/// type-checks and assembles end to end while being incapable of signing or
/// broadcasting. A deployment replaces each dependency with the real one under
/// review.
pub fn build_fail_closed_live_relay(policy: PolicyEngine) -> LiveRelay {
    let breaker = ChainHealthBreaker::new(3, 30_000);
    build_live_relay(LiveDependencies {
        policy,
        store: Arc::new(UnavailableDurableAttemptStore),
        chain: Arc::new(UnavailableChainAdapter::new()),
        payload_source: Arc::new(UnavailablePayloadSource),
        privy_transport: Box::new(PrivyHttpSigningTransport::new(UnavailablePrivyHttpClient)),
        breaker,
    })
}

/// Environment variable names a deployment must supply before the live path is
/// considered configured. Values are never read here beyond presence, and the
/// module never logs them.
pub const REQUIRED_LIVE_ENV: &[&str] = &[
    "TRADING_CORE_LIVE",
    "PRIVY_HTTP_ENDPOINT",
    "BASE_RPC_ENDPOINT",
    "EXECUTION_DATABASE_DSN",
];

/// Reports whether the process was explicitly opted into live composition with
/// every required adapter endpoint present.
///
/// The check is presence-only and side-effect free: it never opens a connection
/// and never reads a secret value. A missing variable keeps the startup
/// fail-closed.
pub fn live_env_ready(get: impl Fn(&str) -> Option<String>) -> bool {
    match get("TRADING_CORE_LIVE").as_deref() {
        Some("1") => {}
        _ => return false,
    }
    REQUIRED_LIVE_ENV
        .iter()
        .all(|name| get(name).is_some_and(|value| !value.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn live_env_requires_explicit_opt_in_and_all_endpoints() {
        let complete = env(&[
            ("TRADING_CORE_LIVE", "1"),
            ("PRIVY_HTTP_ENDPOINT", "https://privy.invalid"),
            ("BASE_RPC_ENDPOINT", "https://base.invalid"),
            ("EXECUTION_DATABASE_DSN", "postgres://localhost/db"),
        ]);
        assert!(live_env_ready(|name| complete.get(name).cloned()));

        let no_opt_in = env(&[
            ("TRADING_CORE_LIVE", "0"),
            ("PRIVY_HTTP_ENDPOINT", "https://privy.invalid"),
            ("BASE_RPC_ENDPOINT", "https://base.invalid"),
            ("EXECUTION_DATABASE_DSN", "postgres://localhost/db"),
        ]);
        assert!(!live_env_ready(|name| no_opt_in.get(name).cloned()));

        let missing = env(&[("TRADING_CORE_LIVE", "1")]);
        assert!(!live_env_ready(|name| missing.get(name).cloned()));
        assert!(!live_env_ready(|_| None));
    }
}
