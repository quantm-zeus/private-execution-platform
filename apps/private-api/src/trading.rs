//! Production trading-path composition and typed capability readiness.
//!
//! The private API advertises a capability only when a typed proof says its
//! backing dependency is healthy (remediation F6 / D6). This module is the one
//! place that turns injected trading seams — a durable exactly-once attempt
//! store, a Base chain transport, a Privy signing transport, a market/limit/
//! realtime dependency — into a [`CapabilityReadiness`].
//!
//! # Fail-closed invariants
//!
//! - Every seam defaults to absent and an absent seam proves nothing, so the
//!   default readiness is [`CapabilityReadiness::deny_all`].
//! - `ExecutionCapability` is only ever built from three **healthy** probes plus
//!   the live trading gate; a single unhealthy dependency removes it.
//! - No function here reads, logs, or stores a credential value. The live
//!   wiring decision is presence-only over operator-supplied environment names.
//! - Connecting the durable Postgres store is gated behind the explicit
//!   `TRADING_CORE_LIVE=1` opt-in; the default binary performs no trading I/O.
//!
//! This is deliberately additive: it does not build a live relay itself (that
//! needs a concrete RPC client, transaction builder, and Privy HTTP client the
//! deployment owns) and it cannot make the private API claim execution it
//! cannot prove.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use execution_relay::DurableAttemptStore;
use storage::{ComponentHealth, HealthProbe};
use trading_core::capability::{
    CapabilityReadiness, ExecutionCapability, LimitCapability, MarketCapability, RealtimeCapability,
};

/// Probe component name for the durable execution attempt store.
pub const COMPONENT_DURABLE_STORE: &str = "private-api.execution-store";
/// Probe component name for the Base chain adapter.
pub const COMPONENT_CHAIN: &str = "private-api.base-chain";
/// Probe component name for the Privy signing transport.
pub const COMPONENT_SIGNER: &str = "private-api.privy-signer";
/// Probe component name for authoritative market state.
pub const COMPONENT_MARKET: &str = "private-api.market";
/// Probe component name for the limit-order engine store.
pub const COMPONENT_LIMIT: &str = "private-api.limit-engine";
/// Probe component name for the realtime stream source.
pub const COMPONENT_REALTIME: &str = "private-api.realtime";

/// Environment variable names a deployment supplies to opt into a live path.
pub const LIVE_ENV: &[&str] = &[
    "TRADING_CORE_LIVE",
    "EXECUTION_DATABASE_DSN",
    "BASE_RPC_ENDPOINT",
    "PRIVY_HTTP_ENDPOINT",
];

/// Smallest connection pool the durable store will open.
pub const DURABLE_STORE_POOL_SIZE: usize = 2;

fn wall_clock_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// A healthy probe stamped with the process wall clock.
pub fn healthy(component: &'static str) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Healthy,
        observed_at_ms: wall_clock_ms(),
    }
}

/// An unavailable probe stamped with the process wall clock.
pub fn unavailable(component: &'static str) -> HealthProbe {
    HealthProbe {
        component,
        status: ComponentHealth::Unavailable,
        observed_at_ms: wall_clock_ms(),
    }
}

/// `TRADING_CORE_LIVE` was set to a value that is neither `"0"`, `"1"` nor
/// absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveWiringError;

impl std::fmt::Display for LiveWiringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TRADING_CORE_LIVE must be exactly \"1\" or \"0\"")
    }
}

impl std::error::Error for LiveWiringError {}

/// Strictly parses the explicit live opt-in.
///
/// Absent or `"0"` disables; `"1"` enables; anything else (`"true"`, `"yes"`,
/// `"01"`) is a startup error rather than a silently disabled live path.
pub fn parse_live_opt_in(raw: Option<&str>) -> Result<bool, LiveWiringError> {
    match raw {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(LiveWiringError),
    }
}

/// Presence-only live wiring configuration.
///
/// Values are never read here: only whether the explicit opt-in and each
/// required endpoint were supplied. A partial configuration is a determinate
/// startup misconfiguration rather than a silently disabled live path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveWiring {
    opted_in: bool,
    dsn: bool,
    rpc: bool,
    privy: bool,
}

impl LiveWiring {
    /// Derives the wiring from the parsed opt-in and raw endpoint presence.
    pub fn from_presence(
        opted_in: bool,
        dsn: Option<&str>,
        rpc: Option<&str>,
        privy: Option<&str>,
    ) -> Self {
        let present = |value: Option<&str>| value.is_some_and(|raw| !raw.trim().is_empty());
        Self {
            opted_in,
            dsn: present(dsn),
            rpc: present(rpc),
            privy: present(privy),
        }
    }

    /// Whether the operator explicitly opted into live composition.
    pub fn opted_in(self) -> bool {
        self.opted_in
    }

    /// Whether every required live endpoint was supplied.
    pub fn endpoints_present(self) -> bool {
        self.dsn && self.rpc && self.privy
    }

    /// The explicit opt-in with every required endpoint present.
    pub fn fully_configured(self) -> bool {
        self.opted_in && self.endpoints_present()
    }

    /// An explicit opt-in that is missing at least one required endpoint.
    ///
    /// This is a startup error: a half-configured live path must not run as if
    /// it were complete.
    pub fn partial(self) -> bool {
        self.opted_in && !self.endpoints_present()
    }

    /// Whether the durable store is configured (its endpoint is present).
    pub fn durable_store_configured(self) -> bool {
        self.opted_in && self.dsn
    }
}

/// Injected trading-path seams and their dependency probes.
///
/// Every field defaults to absent; an absent seam proves nothing, so the
/// default readiness denies every trading capability.
#[derive(Default)]
pub struct TradingSeams {
    durable_store: Option<Arc<dyn DurableAttemptStore>>,
    durable_store_probe: Option<HealthProbe>,
    chain_probe: Option<HealthProbe>,
    signer_probe: Option<HealthProbe>,
    market_probe: Option<HealthProbe>,
    limit_probe: Option<HealthProbe>,
    realtime_probe: Option<HealthProbe>,
}

impl TradingSeams {
    /// An empty seam set: every capability is denied.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a durable attempt store and its health observation.
    pub fn with_durable_store(
        mut self,
        store: Arc<dyn DurableAttemptStore>,
        probe: HealthProbe,
    ) -> Self {
        self.durable_store = Some(store);
        self.durable_store_probe = Some(probe);
        self
    }

    /// Records a Base chain health observation.
    pub fn with_chain_probe(mut self, probe: HealthProbe) -> Self {
        self.chain_probe = Some(probe);
        self
    }

    /// Records a Privy signing-transport health observation.
    pub fn with_signer_probe(mut self, probe: HealthProbe) -> Self {
        self.signer_probe = Some(probe);
        self
    }

    /// Records an authoritative market-state health observation.
    pub fn with_market_probe(mut self, probe: HealthProbe) -> Self {
        self.market_probe = Some(probe);
        self
    }

    /// Records a limit-engine health observation.
    pub fn with_limit_probe(mut self, probe: HealthProbe) -> Self {
        self.limit_probe = Some(probe);
        self
    }

    /// Records a realtime stream-source health observation.
    pub fn with_realtime_probe(mut self, probe: HealthProbe) -> Self {
        self.realtime_probe = Some(probe);
        self
    }

    /// The injected durable attempt store, when one was provided.
    pub fn durable_store(&self) -> Option<Arc<dyn DurableAttemptStore>> {
        self.durable_store.clone()
    }

    /// Derives typed capability readiness from the healthy probes.
    ///
    /// Execution additionally requires the live trading gate and all three of
    /// the durable store, chain, and signer probes to be healthy.
    pub fn readiness(&self, trading_enabled: bool) -> CapabilityReadiness {
        let mut readiness = CapabilityReadiness::deny_all();
        if let Some(market) = self.market_probe.as_ref().and_then(MarketCapability::prove) {
            readiness = readiness.with_market(market);
        }
        if let Some(limit) = self.limit_probe.as_ref().and_then(LimitCapability::prove) {
            readiness = readiness.with_limit(limit);
        }
        if let Some(realtime) = self
            .realtime_probe
            .as_ref()
            .and_then(RealtimeCapability::prove)
        {
            readiness = readiness.with_realtime(realtime);
        }
        if let (Some(store), Some(chain), Some(signer)) = (
            self.durable_store_probe.as_ref(),
            self.chain_probe.as_ref(),
            self.signer_probe.as_ref(),
        ) {
            if let Some(execution) =
                ExecutionCapability::prove(trading_enabled, store, chain, signer)
            {
                readiness = readiness.with_execution(execution);
            }
        }
        readiness
    }
}

impl std::fmt::Debug for TradingSeams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TradingSeams")
            .field("durable_store", &self.durable_store.is_some())
            .field("durable_store_probe", &self.durable_store_probe.is_some())
            .field("chain_probe", &self.chain_probe.is_some())
            .field("signer_probe", &self.signer_probe.is_some())
            .field("market_probe", &self.market_probe.is_some())
            .field("limit_probe", &self.limit_probe.is_some())
            .field("realtime_probe", &self.realtime_probe.is_some())
            .finish()
    }
}

/// Opens the durable Postgres attempt store and probes it.
///
/// Fails closed when no connection can be established, so a configured live path
/// either has a durable store or refuses startup; it never falls back to
/// process-local bookkeeping.
pub async fn connect_durable_attempt_store(
    dsn: &str,
) -> Result<(Arc<dyn DurableAttemptStore>, HealthProbe), execution_store::ExecutionStoreError> {
    let store = execution_store::PostgresExecutionAttemptStore::connect_with_system_clock(
        dsn,
        DURABLE_STORE_POOL_SIZE,
    )
    .await?;
    let probe = store.health().await;
    Ok((Arc::new(store), probe))
}

/// Probes a Base chain transport: healthy only when it reports Base's chain id.
///
/// The transport is the operator-injected RPC seam from `chain-adapters`; the
/// probe performs the same read-only `chain_id` check the submission adapter
/// uses for `refresh_health`, and never signs or broadcasts.
pub async fn base_chain_probe(transport: &dyn chain_adapters::BaseChainTransport) -> HealthProbe {
    match transport.chain_id().await {
        Ok(8453) => healthy(COMPONENT_CHAIN),
        _ => unavailable(COMPONENT_CHAIN),
    }
}

/// Wraps an injected Privy HTTP client in the production signing transport and
/// the fail-closed signing boundary.
///
/// The returned boundary still rejects every request until a live client is
/// injected and the surrounding relay policy permits the trade; this helper only
/// replaces the default `UnavailableTransport` with the real HTTP seam.
pub fn privy_signing_boundary<C>(client: C) -> privy::PrivySigningBoundary
where
    C: privy::PrivyHttpClient + 'static,
{
    privy::PrivySigningBoundary::with_signing_transport(Box::new(
        privy::PrivyHttpSigningTransport::new(client),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_wiring_requires_explicit_opt_in_and_every_endpoint() {
        assert_eq!(
            LiveWiring::from_presence(false, None, None, None),
            LiveWiring::default()
        );
        let complete = LiveWiring::from_presence(
            true,
            Some("postgres://localhost/db"),
            Some("https://base.invalid"),
            Some("https://privy.invalid"),
        );
        assert!(complete.fully_configured());
        assert!(!complete.partial());

        // No explicit opt-in: presence of endpoints alone does not configure.
        let no_opt_in = LiveWiring::from_presence(
            false,
            Some("postgres://localhost/db"),
            Some("https://base.invalid"),
            Some("https://privy.invalid"),
        );
        assert!(!no_opt_in.opted_in());
        assert!(!no_opt_in.fully_configured());

        // Opted in but incomplete is a determinate misconfiguration.
        let partial = LiveWiring::from_presence(
            true,
            Some("postgres://localhost/db"),
            Some("https://base.invalid"),
            None,
        );
        assert!(partial.opted_in());
        assert!(!partial.fully_configured());
        assert!(partial.partial());
        // A blank endpoint counts as absent.
        let blank = LiveWiring::from_presence(true, Some("   "), Some("x"), Some("y"));
        assert!(blank.partial());
    }

    #[test]
    fn live_opt_in_is_strict() {
        assert_eq!(parse_live_opt_in(None), Ok(false));
        assert_eq!(parse_live_opt_in(Some("0")), Ok(false));
        assert_eq!(parse_live_opt_in(Some("1")), Ok(true));
        // Anything else refuses startup rather than silently disabling the path.
        for bad in ["true", "yes", "01", "", " 1"] {
            assert_eq!(parse_live_opt_in(Some(bad)), Err(LiveWiringError), "{bad}");
        }
    }

    #[test]
    fn empty_seams_deny_every_capability_even_when_trading_is_enabled() {
        let seams = TradingSeams::default();
        let readiness = seams.readiness(true);
        assert!(!readiness.market());
        assert!(!readiness.execute());
        assert!(!readiness.limits());
        assert!(!readiness.realtime());
        assert_eq!(readiness, CapabilityReadiness::deny_all());
    }

    #[test]
    fn execution_requires_healthy_store_chain_and_signer() {
        let store = healthy(COMPONENT_DURABLE_STORE);
        let chain = healthy(COMPONENT_CHAIN);
        let signer = healthy(COMPONENT_SIGNER);
        let complete = TradingSeams::new()
            .with_durable_store(
                Arc::new(execution_relay::DeterministicDurableStore::new()),
                store,
            )
            .with_chain_probe(chain)
            .with_signer_probe(signer);
        assert!(complete.readiness(true).execute());
        // The gate being off removes execution capability even with healthy deps.
        assert!(!complete.readiness(false).execute());

        // Any single unhealthy dependency removes it.
        let unhealthy = TradingSeams::new()
            .with_durable_store(
                Arc::new(execution_relay::DeterministicDurableStore::new()),
                unavailable(COMPONENT_DURABLE_STORE),
            )
            .with_chain_probe(healthy(COMPONENT_CHAIN))
            .with_signer_probe(healthy(COMPONENT_SIGNER));
        assert!(!unhealthy.readiness(true).execute());

        let unhealthy_chain = TradingSeams::new()
            .with_durable_store(
                Arc::new(execution_relay::DeterministicDurableStore::new()),
                healthy(COMPONENT_DURABLE_STORE),
            )
            .with_chain_probe(unavailable(COMPONENT_CHAIN))
            .with_signer_probe(healthy(COMPONENT_SIGNER));
        assert!(!unhealthy_chain.readiness(true).execute());

        let unhealthy_signer = TradingSeams::new()
            .with_durable_store(
                Arc::new(execution_relay::DeterministicDurableStore::new()),
                healthy(COMPONENT_DURABLE_STORE),
            )
            .with_chain_probe(healthy(COMPONENT_CHAIN))
            .with_signer_probe(unavailable(COMPONENT_SIGNER));
        assert!(!unhealthy_signer.readiness(true).execute());

        let no_signer = TradingSeams::new()
            .with_durable_store(
                Arc::new(execution_relay::DeterministicDurableStore::new()),
                healthy(COMPONENT_DURABLE_STORE),
            )
            .with_chain_probe(healthy(COMPONENT_CHAIN));
        assert!(!no_signer.readiness(true).execute());
    }

    #[test]
    fn market_limit_and_realtime_follow_their_own_probes() {
        let seams = TradingSeams::new()
            .with_market_probe(healthy(COMPONENT_MARKET))
            .with_limit_probe(healthy(COMPONENT_LIMIT))
            .with_realtime_probe(unavailable(COMPONENT_REALTIME));
        let readiness = seams.readiness(false);
        assert!(readiness.market());
        assert!(readiness.limits());
        assert!(!readiness.realtime());
        assert!(!readiness.execute());
    }

    struct FakeChain {
        chain_id: u64,
        fails: bool,
    }

    #[async_trait::async_trait]
    impl chain_adapters::BaseChainTransport for FakeChain {
        async fn chain_id(&self) -> Result<u64, chain_adapters::ChainAdapterError> {
            if self.fails {
                return Err(chain_adapters::ChainAdapterError::TransportUnavailable);
            }
            Ok(self.chain_id)
        }

        async fn block_number(&self) -> Result<u64, chain_adapters::ChainAdapterError> {
            Ok(1)
        }

        async fn call(
            &self,
            _to: &str,
            _data: &[u8],
        ) -> Result<Vec<u8>, chain_adapters::ChainAdapterError> {
            Ok(Vec::new())
        }

        async fn erc20_balance(
            &self,
            _token: &str,
            _owner: &str,
        ) -> Result<u128, chain_adapters::ChainAdapterError> {
            Ok(0)
        }

        async fn erc20_metadata(
            &self,
            _token: &str,
        ) -> Result<chain_adapters::TokenMetadata, chain_adapters::ChainAdapterError> {
            Err(chain_adapters::ChainAdapterError::UnsupportedChain)
        }

        async fn send_raw_transaction(
            &self,
            _raw: &[u8],
        ) -> Result<String, chain_adapters::ChainAdapterError> {
            Err(chain_adapters::ChainAdapterError::UnsupportedChain)
        }

        async fn transaction_receipt(
            &self,
            _reference: &str,
        ) -> Result<Option<chain_adapters::ReceiptObservation>, chain_adapters::ChainAdapterError>
        {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn base_chain_probe_only_accepts_base() {
        let base = base_chain_probe(&FakeChain {
            chain_id: 8453,
            fails: false,
        })
        .await;
        assert!(base.status == ComponentHealth::Healthy);
        // A non-Base chain and a transport failure are both unavailable.
        let wrong_chain = base_chain_probe(&FakeChain {
            chain_id: 1,
            fails: false,
        })
        .await;
        assert!(wrong_chain.status == ComponentHealth::Unavailable);
        let failed = base_chain_probe(&FakeChain {
            chain_id: 8453,
            fails: true,
        })
        .await;
        assert!(failed.status == ComponentHealth::Unavailable);
    }

    #[test]
    fn privy_seam_builds_a_redacted_fail_closed_boundary() {
        let boundary = privy_signing_boundary(privy::UnavailablePrivyHttpClient);
        // The boundary never renders its injected client or endpoint.
        assert_eq!(format!("{boundary:?}"), "PrivySigningBoundary { .. }");
    }
}
