//! P78 composition root for the Trading Core.
//!
//! This module wires the landed pieces — the P76 reconcile seam, the durable
//! limit-order store/read model, the P72 concrete relay-backed market-execution
//! port, and the MCP dispatcher — into one runnable, fail-closed service, plus a
//! bounded, injectable, **read-only** market reconcile loop.
//!
//! # Fail-closed defaults
//! Every operator-owned seam defaults to a local unavailable implementation:
//! [`UnavailableOpaqueStore`], [`UnavailablePayloadSource`],
//! [`UnavailableMarketTrust`], and [`UnavailablePreparedRefSource`]. With no
//! injected [`TradingCoreSeams::market_execution`], [`TradingCore`] installs the
//! concrete relay-backed port via
//! [`build_fail_closed_market_port`] (`UnavailableChainAdapter` +
//! `PrivySigningBoundaryAdapter`), which cannot sign, submit, or move funds.
//!
//! # `TRADING_ENABLED`
//! [`build_policy`] parses `TRADING_ENABLED` strictly (case-exact `"true"` /
//! `"false"`; `None` disables); any other value is a startup error. While
//! disabled, reads and the read-only reconcile pass stay available; every
//! mutation is denied before any port call.
//!
//! # Reconcile is read-only
//! [`MarketReconcileLoop::reconcile_pass`] only calls the typed
//! `MarketExecutionOutcome`-returning reconcile seam and mutates the local
//! [`MarketAttemptRegistry`]. It never calls `execute`, signs, submits, reserves,
//! or advances a reservation, and it is safe to run repeatedly.
//!
//! # Redaction
//! Every payload-bearing type has a hand-written, payload-free [`std::fmt::Debug`]:
//! no amounts, assets, ids, wallets, chains, or policy values are rendered.
//! There is no logging.
//!
//! `#![forbid(unsafe_code)]`; explicit `now_ms` inputs; no
//! `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use agent_backend::{
    AgentReadBackend, DurableOrderReadModel, MarketExecutionError, MarketExecutionOutcome,
    MarketExecutionPort, MarketExecutionRequest, MarketSnapshotSource, OkxQuoteSource,
    OrderReadModel, OrderValuation, PortfolioReadModel, TradingAgentBackend, TradingBackendConfig,
    TrustedClock, UnavailableOrderValuation, UnavailablePortfolioReadModel,
};
use agent_commands::{
    AgentCapabilities, AgentChannel, AgentCommand, AmountSpec, AssetRef, RouterSource, TradeCommand,
};
use async_trait::async_trait;
use chain_types::ChainId;
use domain::{
    IdempotencyKey, IntentId, RiskConstraints, TradeIntent, TradeSide, UserId, WalletRef,
};
use execution_relay::{
    AttemptReservationStore, ChainHealthBreaker, InMemoryReservationStore, RelayError,
    SignedExecutionRef, SignedPayload, SignedPayloadSource,
};
use limit_engine::{
    AttemptExecutor, DurableLimitOrderStore, LimitEngineError, LimitOrderStore, Orchestrator,
    OrderKeyProvider, QuoteProvider, RecoveryReport,
};
use market_execution::{
    MarketExecutionTrust, MarketExecutionTrustSource, PreparedExecutionRefSource,
    RelayMarketExecutionPort,
};
use market_types::AtomicAmount;
use mcp_server::{AgentBackend, BackendOutcome};
use policy::{PolicyEngine, PolicyError, PolicyLimits, TradingGate};
use privy::PreparedExecutionRef;
use routing::GasEstimator;

use crate::benchmark::{
    BenchmarkRequestSource, NoopRouteComparisonRecordSink, ProviderBenchmarkLoop,
    ProviderBenchmarkPort, RouteComparisonRecordSink, MAX_BENCHMARK_REQUESTS_PER_PASS,
};
use storage::{
    ComponentHealth, HealthProbe, OpaqueEventRecord, OpaqueObject, OpaqueSnapshot, OpaqueStore,
    StorageError,
};

/// Hard bound on the number of pending market attempts retained by
/// [`MarketAttemptRegistry`].
pub const MAX_PENDING_MARKET_ATTEMPTS: usize = 256;

/// Chain-health failure threshold used by the default fail-closed port.
const CHAIN_HEALTH_FAILURE_THRESHOLD: u32 = 3;
/// Chain-health cooldown, in milliseconds, used by the default fail-closed port.
const CHAIN_HEALTH_COOLDOWN_MS: i64 = 30_000;

/// The concrete composed agent backend: durable reads, fail-closed portfolio,
/// and the durable limit-order write store.
pub type ComposedBackend<S> = TradingAgentBackend<
    DurableOrderReadModel<S>,
    UnavailablePortfolioReadModel,
    DurableLimitOrderStore<S>,
>;

/// Trusted, owner-scoped composition configuration.
#[derive(Clone)]
pub struct CompositionConfig {
    /// Authenticated owner every order/attempt belongs to.
    pub owner: UserId,
    /// Wallet the orders trade from.
    pub wallet_ref: WalletRef,
    /// Chain every order/attempt must be bound to.
    pub chain: ChainId,
    /// Wallet risk caps forwarded to the backend.
    pub risk: RiskConstraints,
    /// Minimum partial-fill size.
    pub min_fill: AtomicAmount,
    /// Chains the wallet may trade (capability set).
    pub allowed_chains: HashSet<ChainId>,
    /// Maximum notional per trade, in USD micros.
    pub max_trade_usd: u64,
}

impl std::fmt::Debug for CompositionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: owner, wallet, chain, risk, and limits are capability
        // semantics and are never rendered.
        formatter.write_str("CompositionConfig { .. }")
    }
}

/// Strictly parses `TRADING_ENABLED` and builds the policy engine.
///
/// `None` and `"false"` disable trading; `"true"` enables it; every other value
/// (including `"TRUE"`) is [`PolicyError::InvalidTradingEnabled`], which must
/// prevent startup.
pub fn build_policy(
    trading_enabled: Option<&str>,
    limits: PolicyLimits,
) -> Result<PolicyEngine, PolicyError> {
    let gate = TradingGate::from_trusted_startup(trading_enabled)?;
    PolicyEngine::new(gate, limits)
}

/// Builds the trusted capability context for the MCP dispatcher.
pub fn build_capabilities(policy: &PolicyEngine, config: &CompositionConfig) -> AgentCapabilities {
    AgentCapabilities::new(
        policy.is_trading_enabled(),
        config.allowed_chains.clone(),
        config.max_trade_usd,
    )
}

/// Fail-closed [`OpaqueStore`]: every method is unavailable.
///
/// In particular [`OpaqueStore::get_object`] returns `Err(StorageError::Unavailable)`
/// rather than `Ok(None)`, so a missing store can never be mistaken for "no such
/// record".
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableOpaqueStore;

#[async_trait]
impl OpaqueStore for UnavailableOpaqueStore {
    async fn put_object(&self, _object: OpaqueObject) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn get_object(&self, _id: &str) -> Result<Option<OpaqueObject>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn list_objects_by_class(
        &self,
        _class_blind_index: &[u8],
        _limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn list_objects_by_class_page(
        &self,
        _class_blind_index: &[u8],
        _cursor: Option<&storage::ClassListCursor>,
        _limit: usize,
    ) -> Result<Vec<OpaqueObject>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn append_event(&self, _event: OpaqueEventRecord) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn read_events(
        &self,
        _stream_blind_index: &[u8],
        _from_sequence: u64,
        _limit: usize,
    ) -> Result<Vec<OpaqueEventRecord>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn latest_snapshot(
        &self,
        _stream_blind_index: &[u8],
    ) -> Result<Option<OpaqueSnapshot>, StorageError> {
        Err(StorageError::Unavailable)
    }

    async fn health(&self) -> HealthProbe {
        HealthProbe {
            component: "trading-core.unavailable-store",
            status: ComponentHealth::Unavailable,
            observed_at_ms: 0,
        }
    }
}

/// Fail-closed [`SignedPayloadSource`]: no payload can be built or retrieved.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePayloadSource;

#[async_trait]
impl SignedPayloadSource for UnavailablePayloadSource {
    async fn payload_to_sign(
        &self,
        _key: &IdempotencyKey,
        _intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        Err(RelayError::MissingSignedPayload)
    }

    async fn signed_payload(
        &self,
        _signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        Err(RelayError::MissingSignedPayload)
    }
}

/// Fail-closed [`MarketExecutionTrustSource`]: no trusted pre-sign state.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableMarketTrust;

impl MarketExecutionTrustSource for UnavailableMarketTrust {
    fn trust(
        &self,
        _request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionTrust, MarketExecutionError> {
        Err(MarketExecutionError::Unavailable)
    }
}

/// Fail-closed [`PreparedExecutionRefSource`]: no prepared reference exists.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePreparedRefSource;

impl PreparedExecutionRefSource for UnavailablePreparedRefSource {
    fn prepared_ref(
        &self,
        _intent: &TradeIntent,
    ) -> Result<PreparedExecutionRef, MarketExecutionError> {
        Err(MarketExecutionError::Unavailable)
    }
}

/// Builds the concrete relay-backed market port with fail-closed seams.
///
/// This is [`RelayMarketExecutionPort::production`] (`UnavailableChainAdapter` +
/// `PrivySigningBoundaryAdapter`) over the given reservation store and breaker,
/// with [`UnavailablePayloadSource`], [`UnavailableMarketTrust`], and
/// [`UnavailablePreparedRefSource`] installed. Until a real trust/payload/ref
/// source and chain adapter are installed under review, every `execute` fails
/// closed before a reservation is claimed: no sign, submit, or reserve occurs.
///
/// The reservation store is generic so tests can pass a recording store; the
/// canonical call passes an [`InMemoryReservationStore`].
pub fn build_fail_closed_market_port<S>(
    policy: PolicyEngine,
    store: S,
    breaker: ChainHealthBreaker,
) -> Arc<dyn MarketExecutionPort>
where
    S: AttemptReservationStore + 'static,
{
    Arc::new(RelayMarketExecutionPort::production(
        policy,
        store,
        UnavailablePayloadSource,
        breaker,
        UnavailableMarketTrust,
        UnavailablePreparedRefSource,
    ))
}

/// Injected optional seams for [`TradingCore`].
///
/// Every field defaults to `None`; [`TradingCore::new`] then installs the local
/// fail-closed default for that capability.
#[derive(Default)]
pub struct TradingCoreSeams {
    /// Trusted order valuation used by the dispatcher's notional gate.
    pub valuation: Option<Arc<dyn OrderValuation>>,
    /// Trusted exact market state used by previews.
    pub market_snapshot: Option<Arc<dyn MarketSnapshotSource>>,
    /// Deterministic gas model used by preview/execution scoring.
    pub gas: Option<Arc<dyn GasEstimator>>,
    /// Read-only OKX quote source used by the `Okx` route (P84B).
    ///
    /// Defaults to absent; the backend then installs its fail-closed
    /// [`agent_backend::UnavailableOkxQuoteSource`], so an OKX-selected command
    /// fails closed and never silently falls back to Local.
    pub okx_quote_source: Option<Arc<dyn OkxQuoteSource>>,
    /// Concrete market-execution port (defaults to the fail-closed relay port).
    pub market_execution: Option<Arc<dyn MarketExecutionPort>>,
    /// Full limit-orchestrator recovery, operator-injected.
    pub limit_recovery: Option<Arc<dyn LimitRecovery>>,
    /// Observational provider-benchmark evaluator (P93).
    ///
    /// Defaults to absent. A loop is built only when **both** this port and a
    /// [`Self::provider_benchmark_requests`] source are installed; the benchmark
    /// loop is never on the execution path.
    pub provider_benchmark: Option<Arc<dyn ProviderBenchmarkPort>>,
    /// Sink for "our route vs provider route" records (defaults to a no-op).
    pub provider_benchmark_sink: Option<Arc<dyn RouteComparisonRecordSink>>,
    /// Source of the bounded benchmark requests evaluated each pass.
    pub provider_benchmark_requests: Option<Arc<dyn BenchmarkRequestSource>>,
}

impl std::fmt::Debug for TradingCoreSeams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TradingCoreSeams")
            .field("valuation", &self.valuation.is_some())
            .field("market_snapshot", &self.market_snapshot.is_some())
            .field("gas", &self.gas.is_some())
            .field("okx_quote_source", &self.okx_quote_source.is_some())
            .field("market_execution", &self.market_execution.is_some())
            .field("limit_recovery", &self.limit_recovery.is_some())
            .field("provider_benchmark", &self.provider_benchmark.is_some())
            .field(
                "provider_benchmark_sink",
                &self.provider_benchmark_sink.is_some(),
            )
            .field(
                "provider_benchmark_requests",
                &self.provider_benchmark_requests.is_some(),
            )
            .finish()
    }
}

/// One in-flight market attempt recorded by [`RecordingAgentBackend`].
///
/// Carries exactly the command parameters needed to rebuild the P76 preview
/// identity at reconcile time. `Debug` is redacted: no assets, amounts, chains,
/// channels, or caps are rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingMarketAttempt {
    channel: AgentChannel,
    token_in: AssetRef,
    token_out: AssetRef,
    side: TradeSide,
    amount: AmountSpec,
    max_slippage_bps: Option<u16>,
    max_price_impact_bps: Option<u16>,
    router: RouterSource,
}

impl PendingMarketAttempt {
    /// Builds a pending attempt from its exact command parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: AgentChannel,
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        router: RouterSource,
    ) -> Self {
        Self {
            channel,
            token_in,
            token_out,
            side,
            amount,
            max_slippage_bps,
            max_price_impact_bps,
            router,
        }
    }

    /// Builds a pending attempt from an `ExecuteMarketOrder` trade command.
    fn from_execute(channel: AgentChannel, command: &TradeCommand) -> Option<Self> {
        match command {
            TradeCommand::ExecuteMarketOrder {
                token_in,
                token_out,
                side,
                amount,
                max_slippage_bps,
                max_price_impact_bps,
                router,
            } => Some(Self {
                channel,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                side: *side,
                amount: *amount,
                max_slippage_bps: *max_slippage_bps,
                max_price_impact_bps: *max_price_impact_bps,
                router: *router,
            }),
            _ => None,
        }
    }

    /// The channel the attempt was submitted on.
    pub fn channel(&self) -> AgentChannel {
        self.channel
    }

    /// The input asset reference.
    pub fn token_in(&self) -> &AssetRef {
        &self.token_in
    }

    /// The output asset reference.
    pub fn token_out(&self) -> &AssetRef {
        &self.token_out
    }

    /// The trade direction.
    pub fn side(&self) -> TradeSide {
        self.side
    }

    /// The explicit input amount.
    pub fn amount(&self) -> AmountSpec {
        self.amount
    }

    /// The requested slippage cap, if any.
    pub fn max_slippage_bps(&self) -> Option<u16> {
        self.max_slippage_bps
    }

    /// The requested price-impact cap, if any.
    pub fn max_price_impact_bps(&self) -> Option<u16> {
        self.max_price_impact_bps
    }

    /// The selected routing source.
    pub fn router(&self) -> RouterSource {
        self.router
    }
}

impl std::fmt::Debug for PendingMarketAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: asset addresses, amounts, caps, and channel are never
        // rendered.
        formatter.write_str("PendingMarketAttempt { .. }")
    }
}

/// Opaque reservation ticket for one market-attempt reference.
///
/// Carries the registry generation (`epoch`) of the entry it reserved, so a
/// delayed [`MarketAttemptRegistry::release`] after a terminal
/// [`MarketAttemptRegistry::remove`] cannot decrement a *new* entry created for
/// the same attempt identity.
#[derive(Clone, PartialEq, Eq)]
pub struct Reservation {
    attempt: PendingMarketAttempt,
    epoch: u64,
}

impl Reservation {
    /// The attempt this ticket refers to.
    pub fn attempt(&self) -> &PendingMarketAttempt {
        &self.attempt
    }
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Reservation { .. }")
    }
}

/// Result of reserving a slot for one market attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// The attempt was newly stored with a first reference.
    Reserved(Reservation),
    /// An identical attempt was already stored; its reference count grew.
    AlreadyPending(Reservation),
    /// The registry is full of distinct attempts; nothing was stored.
    AtCapacity,
}

/// One stored attempt plus its in-process reservation reference count and
/// generation.
struct PendingEntry {
    attempt: PendingMarketAttempt,
    refs: usize,
    epoch: u64,
}

/// Process-local, bounded, deduplicating registry of pending market attempts.
///
/// Insertion order is preserved. An identical attempt is never stored twice;
/// instead [`Self::reserve`] grows a reference count so concurrent/sibling
/// reservations cannot evict each other's entry. Once
/// [`MAX_PENDING_MARKET_ATTEMPTS`] distinct attempts are retained a new distinct
/// attempt is refused ([`ReserveOutcome::AtCapacity`]) rather than dropped
/// silently, which lets the recorder deny before forwarding an untrackable
/// attempt. Each entry carries a generation so a stale
/// [`Self::release`] ticket cannot affect a later entry for the same identity.
pub struct MarketAttemptRegistry {
    pending: Mutex<Vec<PendingEntry>>,
    next_epoch: AtomicU64,
}

impl Default for MarketAttemptRegistry {
    fn default() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            next_epoch: AtomicU64::new(0),
        }
    }
}

impl MarketAttemptRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves a tracking slot for `attempt`.
    ///
    /// An existing identical attempt increments its reference count
    /// ([`ReserveOutcome::AlreadyPending`]); a new attempt is stored with one
    /// reference ([`ReserveOutcome::Reserved`]); a full registry refuses the
    /// newcomer without storing anything ([`ReserveOutcome::AtCapacity`]).
    pub fn reserve(&self, attempt: PendingMarketAttempt) -> ReserveOutcome {
        let mut pending = lock(&self.pending);
        if let Some(entry) = pending.iter_mut().find(|entry| entry.attempt == attempt) {
            entry.refs = entry.refs.saturating_add(1);
            return ReserveOutcome::AlreadyPending(Reservation {
                attempt: entry.attempt.clone(),
                epoch: entry.epoch,
            });
        }
        if pending.len() >= MAX_PENDING_MARKET_ATTEMPTS {
            return ReserveOutcome::AtCapacity;
        }
        let epoch = self.next_epoch.fetch_add(1, Ordering::SeqCst);
        pending.push(PendingEntry {
            attempt: attempt.clone(),
            refs: 1,
            epoch,
        });
        ReserveOutcome::Reserved(Reservation { attempt, epoch })
    }

    /// Drops the reference held by `reservation`, removing the entry at zero.
    ///
    /// The generation (`epoch`) must match: a ticket from an entry that was
    /// already force-removed is a no-op, so it cannot decrement a freshly
    /// reserved entry with the same attempt identity. Releasing an absent
    /// attempt is likewise a no-op.
    pub fn release(&self, reservation: &Reservation) {
        let mut pending = lock(&self.pending);
        if let Some(index) = pending.iter().position(|entry| {
            entry.epoch == reservation.epoch && entry.attempt == reservation.attempt
        }) {
            if pending[index].refs <= 1 {
                pending.remove(index);
            } else {
                pending[index].refs -= 1;
            }
        }
    }

    /// Force-removes `attempt`, returning `true` when it was present.
    ///
    /// Used for terminal reconcile results, where every outstanding reference is
    /// resolved at once. Outstanding tickets for the removed entry become stale
    /// and their later [`Self::release`] is a no-op.
    pub fn remove(&self, attempt: &PendingMarketAttempt) -> bool {
        let mut pending = lock(&self.pending);
        match pending.iter().position(|entry| &entry.attempt == attempt) {
            Some(index) => {
                pending.remove(index);
                true
            }
            None => false,
        }
    }

    /// Seeds `attempt` as if by [`Self::reserve`], returning `true` only when it
    /// was newly stored.
    ///
    /// A duplicate is a true no-op (the transient reference from
    /// [`Self::reserve`] is released before returning `false`), so a seeder can
    /// never strand a reference. This is the seeding/observational surface for
    /// tests and startup load; the runtime recorder uses [`Self::reserve`]
    /// directly so it can deny at capacity.
    pub fn record(&self, attempt: PendingMarketAttempt) -> bool {
        match self.reserve(attempt) {
            ReserveOutcome::Reserved(_) => true,
            ReserveOutcome::AlreadyPending(reservation) => {
                self.release(&reservation);
                false
            }
            ReserveOutcome::AtCapacity => false,
        }
    }

    /// Snapshots the pending attempts in insertion order.
    pub fn pending(&self) -> Vec<PendingMarketAttempt> {
        lock(&self.pending)
            .iter()
            .map(|entry| entry.attempt.clone())
            .collect()
    }

    /// Number of pending attempts.
    pub fn len(&self) -> usize {
        lock(&self.pending).len()
    }

    /// True when no attempt is pending.
    pub fn is_empty(&self) -> bool {
        lock(&self.pending).is_empty()
    }
}

impl std::fmt::Debug for MarketAttemptRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MarketAttemptRegistry")
            .field("pending", &self.len())
            .finish()
    }
}

/// Records an `ExecuteMarketOrder` into the registry, then forwards to `B`.
///
/// It only observes; the wrapped backend owns the actual work. Trusted
/// valuations are forwarded verbatim, so recording never changes authorization.
pub struct RecordingAgentBackend<B: AgentBackend> {
    inner: Arc<B>,
    registry: Arc<MarketAttemptRegistry>,
}

impl<B: AgentBackend> RecordingAgentBackend<B> {
    /// Wraps `inner`, recording market executions into `registry`.
    pub fn new(inner: Arc<B>, registry: Arc<MarketAttemptRegistry>) -> Self {
        Self { inner, registry }
    }

    /// The shared registry this recorder writes to.
    pub fn registry(&self) -> &Arc<MarketAttemptRegistry> {
        &self.registry
    }
}

impl<B: AgentBackend> std::fmt::Debug for RecordingAgentBackend<B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingAgentBackend")
            .field("pending", &self.registry.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<B: AgentBackend> AgentBackend for RecordingAgentBackend<B> {
    async fn execute(&self, channel: AgentChannel, command: AgentCommand) -> BackendOutcome {
        let observed = match &command {
            AgentCommand::Trade(trade) => PendingMarketAttempt::from_execute(channel, trade),
            AgentCommand::Read(_) => None,
        };
        // Reserve the tracking slot *before* forwarding. A full registry refuses
        // the attempt here, so the inner backend/port never receives a delegated
        // attempt the registry cannot track (losslessness / fail-closed).
        let reserved = match observed {
            None => None,
            Some(attempt) => match self.registry.reserve(attempt) {
                ReserveOutcome::AtCapacity => return BackendOutcome::Denied,
                ReserveOutcome::Reserved(reservation)
                | ReserveOutcome::AlreadyPending(reservation) => Some(reservation),
            },
        };
        let outcome = self.inner.execute(channel, command).await;
        // Every outcome other than `Value` is a definitive non-delegation signal
        // (pre-port denial or a provably pre-submit terminal), so the reservation
        // is released. `Value` means the port may be in flight: keep it pending.
        // The epoch-carrying ticket makes the release race-safe; a cancelled call
        // conservatively leaves the reservation in place.
        if !matches!(outcome, BackendOutcome::Value(_)) {
            if let Some(reservation) = &reserved {
                self.registry.release(reservation);
            }
        }
        outcome
    }

    async fn valuation_usd_micros(&self, command: &AgentCommand) -> Option<u64> {
        self.inner.valuation_usd_micros(command).await
    }
}

/// Bound on one reconcile pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileSchedule {
    /// Maximum attempts examined per pass; `0` means unbounded.
    pub max_per_pass: usize,
    /// Maximum passes run by [`run_reconcile_loop`]; `0` means unbounded.
    pub max_passes: usize,
}

impl Default for ReconcileSchedule {
    fn default() -> Self {
        Self {
            max_per_pass: 32,
            max_passes: 0,
        }
    }
}

/// Counts-only result of one reconcile pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcilePassReport {
    /// Attempts examined this pass.
    pub examined: usize,
    /// Attempts resolved as filled and removed.
    pub filled: usize,
    /// Attempts resolved as failed (or denied) and removed.
    pub failed: usize,
    /// Attempts still in flight and kept.
    pub in_flight: usize,
    /// Attempts whose outcome was unavailable and kept.
    pub unavailable: usize,
}

/// Counts-only result of a [`run_reconcile_loop`] run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileRunReport {
    /// Passes run.
    pub passes: usize,
    /// Attempts examined across every pass.
    pub examined: usize,
    /// Attempts resolved as filled across every pass.
    pub filled: usize,
    /// Attempts resolved as failed (or denied) across every pass.
    pub failed: usize,
    /// Attempts observed in flight across every pass.
    pub in_flight: usize,
    /// Attempts whose outcome was unavailable across every pass.
    pub unavailable: usize,
}

impl ReconcileRunReport {
    fn absorb(&mut self, pass: ReconcilePassReport) {
        self.passes += 1;
        self.examined += pass.examined;
        self.filled += pass.filled;
        self.failed += pass.failed;
        self.in_flight += pass.in_flight;
        self.unavailable += pass.unavailable;
    }
}

/// Read-only reconcile seam over one pending market attempt.
#[async_trait]
pub trait MarketReconcileTarget: Send + Sync {
    /// Reconciles `attempt`, returning the typed observational outcome.
    async fn reconcile(
        &self,
        attempt: &PendingMarketAttempt,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError>;
}

#[async_trait]
impl<O, P, S> MarketReconcileTarget for TradingAgentBackend<O, P, S>
where
    O: OrderReadModel + Send + Sync + 'static,
    P: PortfolioReadModel + Send + Sync + 'static,
    S: LimitOrderStore + Send + Sync + 'static,
{
    async fn reconcile(
        &self,
        attempt: &PendingMarketAttempt,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        self.reconcile_market_order_outcome(
            attempt.channel(),
            attempt.token_in().clone(),
            attempt.token_out().clone(),
            attempt.side(),
            attempt.amount(),
            attempt.max_slippage_bps(),
            attempt.max_price_impact_bps(),
            attempt.router(),
        )
        .await
    }
}

#[async_trait]
impl<T: MarketReconcileTarget + ?Sized> MarketReconcileTarget for Arc<T> {
    async fn reconcile(
        &self,
        attempt: &PendingMarketAttempt,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        (**self).reconcile(attempt).await
    }
}

/// Bounded read-only reconcile driver over a registry and a target.
pub struct MarketReconcileLoop<T> {
    target: T,
    registry: Arc<MarketAttemptRegistry>,
    schedule: ReconcileSchedule,
    /// Rotating start offset (modulo the pending length) so a `max_per_pass`
    /// smaller than the pending set still examines every attempt within
    /// `ceil(n / max_per_pass)` passes.
    cursor: AtomicUsize,
}

impl<T: MarketReconcileTarget> MarketReconcileLoop<T> {
    /// Wires a reconcile loop from its target, registry, and schedule.
    pub fn new(
        target: T,
        registry: Arc<MarketAttemptRegistry>,
        schedule: ReconcileSchedule,
    ) -> Self {
        Self {
            target,
            registry,
            schedule,
            cursor: AtomicUsize::new(0),
        }
    }

    /// The schedule this loop applies.
    pub fn schedule(&self) -> ReconcileSchedule {
        self.schedule
    }

    /// Runs one bounded, read-only pass at `now_ms`.
    ///
    /// `now_ms` is accepted for an explicit-instant public API and to mirror
    /// [`run_reconcile_loop`]'s tick contract; the built-in target
    /// ([`TradingAgentBackend`]) stamps the reconcile with its own injected
    /// [`TrustedClock`], so the instant is not re-derived here.
    ///
    /// The examined set starts at a private rotating cursor and wraps around the
    /// pending snapshot, so with `max_per_pass < n` the same prefix is not
    /// re-examined forever: every pending attempt is examined within
    /// `ceil(n / max_per_pass)` passes. Classification is exact:
    /// `Filled`/`Failed` and a `Denied` error remove the attempt;
    /// `Submitted`/`Unknown` and an `Unavailable` error keep it. Nothing but the
    /// local registry is mutated, and `execute` is never called.
    pub async fn reconcile_pass(&self, _now_ms: i64) -> ReconcilePassReport {
        let snapshot = self.registry.pending();
        let n = snapshot.len();
        let mut report = ReconcilePassReport::default();
        if n == 0 {
            return report;
        }
        let limit = if self.schedule.max_per_pass == 0 {
            n
        } else {
            self.schedule.max_per_pass.min(n)
        };
        let start = self.cursor.load(Ordering::SeqCst) % n;
        let examined: Vec<PendingMarketAttempt> = (0..limit)
            .map(|offset| snapshot[(start + offset) % n].clone())
            .collect();
        self.cursor.store((start + limit) % n, Ordering::SeqCst);
        for attempt in &examined {
            report.examined += 1;
            match self.target.reconcile(attempt).await {
                Ok(MarketExecutionOutcome::Filled { .. }) => {
                    report.filled += 1;
                    self.registry.remove(attempt);
                }
                Ok(MarketExecutionOutcome::Failed) => {
                    report.failed += 1;
                    self.registry.remove(attempt);
                }
                Ok(MarketExecutionOutcome::Submitted) | Ok(MarketExecutionOutcome::Unknown) => {
                    report.in_flight += 1;
                }
                Err(MarketExecutionError::Denied) => {
                    report.failed += 1;
                    self.registry.remove(attempt);
                }
                Err(MarketExecutionError::Unavailable) => {
                    report.unavailable += 1;
                }
            }
        }
        report
    }
}

impl<T> std::fmt::Debug for MarketReconcileLoop<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MarketReconcileLoop")
            .field("schedule", &self.schedule)
            .field("pending", &self.registry.len())
            .finish_non_exhaustive()
    }
}

/// Source of successive reconcile ticks (one reference timestamp each).
#[async_trait]
pub trait ReconcileTick: Send {
    /// Returns the next tick's `now_ms`, or `None` to stop the loop.
    async fn next_tick(&mut self) -> Option<i64>;
}

/// Production tick backed by `tokio::time::sleep` and the system clock.
///
/// This is the only wall-clock read in the composition: the reconcile logic
/// itself takes explicit `now_ms` values. The interval is floored at 1 ms so a
/// zero/absurdly-small interval cannot spin the loop; the default
/// [`ReconcileSchedule`] is unbounded, so a caller wiring this tick must set a
/// non-zero `max_passes` or stop the loop externally.
pub struct TokioTick {
    interval: Duration,
}

/// Minimum wait between passes, preventing a zero-interval hot loop.
///
/// Shared with [`crate::service::ShutdownTick`] so the graceful service tick
/// applies the same floor.
pub(crate) const MIN_TICK_INTERVAL: Duration = Duration::from_millis(1);

impl TokioTick {
    /// Builds a tick that waits `interval` (floored at 1 ms) between passes.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval: interval.max(MIN_TICK_INTERVAL),
        }
    }
}

impl std::fmt::Debug for TokioTick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioTick")
            .field("interval", &self.interval)
            .finish()
    }
}

#[async_trait]
impl ReconcileTick for TokioTick {
    async fn next_tick(&mut self) -> Option<i64> {
        tokio::time::sleep(self.interval).await;
        Some(system_now_ms())
    }
}

/// Runs reconcile passes until the tick is exhausted or `max_passes` is reached.
pub async fn run_reconcile_loop<T, K>(
    reconcile: &MarketReconcileLoop<T>,
    tick: &mut K,
) -> ReconcileRunReport
where
    T: MarketReconcileTarget,
    K: ReconcileTick + ?Sized,
{
    let max_passes = reconcile.schedule().max_passes;
    let mut report = ReconcileRunReport::default();
    while let Some(now_ms) = tick.next_tick().await {
        report.absorb(reconcile.reconcile_pass(now_ms).await);
        if max_passes != 0 && report.passes >= max_passes {
            break;
        }
    }
    report
}

/// Operator-injected restart recovery seam.
#[async_trait]
pub trait LimitRecovery: Send + Sync {
    /// Recovers durable limit-order state at `now_ms`.
    async fn recover(&self, now_ms: i64) -> Result<RecoveryReport, LimitEngineError>;
}

#[async_trait]
impl<S, Q, E> LimitRecovery for Orchestrator<S, Q, E>
where
    S: OpaqueStore + 'static,
    Q: QuoteProvider + 'static,
    E: AttemptExecutor + 'static,
{
    async fn recover(&self, now_ms: i64) -> Result<RecoveryReport, LimitEngineError> {
        Orchestrator::recover(self, now_ms).await
    }
}

/// The runnable composition root.
pub struct TradingCore<S: OpaqueStore> {
    backend: Arc<ComposedBackend<S>>,
    registry: Arc<MarketAttemptRegistry>,
    config: CompositionConfig,
    trading_enabled_at_startup: bool,
    limit_recovery: Option<Arc<dyn LimitRecovery>>,
    provider_benchmark: Option<ProviderBenchmarkLoop>,
}

impl<S: OpaqueStore> TradingCore<S> {
    /// Builds the composition root from its trusted ports and optional seams.
    ///
    /// The durable store, read model, composed backend, registry, and startup
    /// gate snapshot are built here. When no market-execution seam is injected,
    /// the fail-closed relay-backed port is installed, so nothing can sign,
    /// submit, or move funds by default.
    pub fn new(
        config: CompositionConfig,
        policy: PolicyEngine,
        store: Arc<S>,
        keys: Arc<dyn OrderKeyProvider>,
        clock: Arc<dyn TrustedClock>,
        seams: TradingCoreSeams,
    ) -> Self {
        let trading_enabled_at_startup = policy.is_trading_enabled();
        let TradingCoreSeams {
            valuation,
            market_snapshot,
            gas,
            okx_quote_source,
            market_execution,
            limit_recovery,
            provider_benchmark,
            provider_benchmark_sink,
            provider_benchmark_requests,
        } = seams;

        let durable = Arc::new(DurableLimitOrderStore::new(
            store,
            keys,
            config.chain.clone(),
        ));
        let reads = AgentReadBackend::new(
            DurableOrderReadModel::new(durable.clone(), config.owner.clone()),
            UnavailablePortfolioReadModel::new(),
        );
        let backend_config = TradingBackendConfig {
            owner: config.owner.clone(),
            wallet_ref: config.wallet_ref.clone(),
            chain: config.chain.clone(),
            risk: config.risk.clone(),
            min_fill: config.min_fill,
        };
        let valuation = valuation.unwrap_or_else(|| Arc::new(UnavailableOrderValuation));
        let mut backend =
            TradingAgentBackend::new(reads, durable, backend_config, clock, valuation);
        if let Some(snapshot) = market_snapshot {
            backend = backend.with_market_snapshot(snapshot);
        }
        if let Some(gas) = gas {
            backend = backend.with_gas_estimator(gas);
        }
        if let Some(source) = okx_quote_source {
            backend = backend.with_okx_quote_source(source);
        }
        let execution = market_execution.unwrap_or_else(|| {
            build_fail_closed_market_port(
                policy,
                InMemoryReservationStore::new(),
                ChainHealthBreaker::new(CHAIN_HEALTH_FAILURE_THRESHOLD, CHAIN_HEALTH_COOLDOWN_MS),
            )
        });
        let backend = backend.with_market_execution(execution);

        // The observational benchmark loop is built only when both an evaluator
        // and a request source are installed. It is never on the execution path;
        // an absent sink means records are discarded.
        let provider_benchmark = match (provider_benchmark, provider_benchmark_requests) {
            (Some(port), Some(source)) => Some(ProviderBenchmarkLoop::new(
                port,
                provider_benchmark_sink.unwrap_or_else(|| Arc::new(NoopRouteComparisonRecordSink)),
                source,
                MAX_BENCHMARK_REQUESTS_PER_PASS,
            )),
            _ => None,
        };

        Self {
            backend: Arc::new(backend),
            registry: Arc::new(MarketAttemptRegistry::new()),
            config,
            trading_enabled_at_startup,
            limit_recovery,
            provider_benchmark,
        }
    }

    /// The observational provider-benchmark loop, when one is installed.
    ///
    /// `None` means no evaluator and/or request source was injected, so there is
    /// nothing to record. Driving the loop never affects execution.
    pub fn provider_benchmark_loop(&self) -> Option<&ProviderBenchmarkLoop> {
        self.provider_benchmark.as_ref()
    }

    /// The composed agent backend (unrecorded; wrap with
    /// [`RecordingAgentBackend`] to populate the registry).
    pub fn backend(&self) -> Arc<ComposedBackend<S>> {
        self.backend.clone()
    }

    /// The shared pending-market-attempt registry.
    pub fn registry(&self) -> Arc<MarketAttemptRegistry> {
        self.registry.clone()
    }

    /// Trusted capability context for the MCP dispatcher.
    pub fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            self.trading_enabled_at_startup,
            self.config.allowed_chains.clone(),
            self.config.max_trade_usd,
        )
    }

    /// Whether trading was enabled in the startup `TRADING_ENABLED` snapshot.
    pub fn trading_enabled_at_startup(&self) -> bool {
        self.trading_enabled_at_startup
    }

    /// Runs injected restart recovery, or `None` when there is no recovery seam
    /// or trading was disabled at startup.
    ///
    /// Gating on the **startup** gate (not the live one) deliberately avoids the
    /// P52 disabled-path write: a disabled service never calls
    /// `store.recover()` through this method.
    pub async fn startup_recovery(
        &self,
        now_ms: i64,
    ) -> Option<Result<RecoveryReport, LimitEngineError>> {
        if !self.trading_enabled_at_startup {
            return None;
        }
        let recovery = self.limit_recovery.as_ref()?;
        Some(recovery.recover(now_ms).await)
    }
}

impl<S: OpaqueStore> std::fmt::Debug for TradingCore<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TradingCore")
            .field(
                "trading_enabled_at_startup",
                &self.trading_enabled_at_startup,
            )
            .field("pending_market_attempts", &self.registry.len())
            .finish_non_exhaustive()
    }
}

/// Acquires a mutex, recovering from poisoning.
///
/// The guarded value is plain data, so a panicking holder cannot leave torn
/// state. This never panics.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Current wall-clock time in milliseconds, saturating on out-of-range values.
///
/// Shared with [`crate::service::ShutdownTick`]; the reconcile logic itself only
/// takes explicit `now_ms` values.
pub(crate) fn system_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => i64::MIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn asset(address: &str) -> AssetRef {
        AssetRef {
            chain: ChainId::Base,
            address: address.to_string(),
        }
    }

    fn attempt(amount: u128) -> PendingMarketAttempt {
        PendingMarketAttempt::new(
            AgentChannel::Mcp,
            asset("USDC"),
            asset("TOKEN"),
            TradeSide::Buy,
            AmountSpec::TokenAtomic(amount),
            None,
            None,
            RouterSource::Local,
        )
    }

    fn trade(amount: u128) -> AgentCommand {
        AgentCommand::Trade(TradeCommand::ExecuteMarketOrder {
            token_in: asset("USDC"),
            token_out: asset("TOKEN"),
            side: TradeSide::Buy,
            amount: AmountSpec::TokenAtomic(amount),
            max_slippage_bps: None,
            max_price_impact_bps: None,
            router: RouterSource::Local,
        })
    }

    /// Inner backend that counts calls and returns a fixed outcome.
    struct FixedOutcomeBackend {
        calls: AtomicUsize,
        outcome: BackendOutcome,
    }

    impl FixedOutcomeBackend {
        fn new(outcome: BackendOutcome) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                outcome,
            }
        }
    }

    #[async_trait]
    impl AgentBackend for FixedOutcomeBackend {
        async fn execute(&self, _channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    /// Reconcile target that records the examined amounts and keeps them pending.
    struct RecordingTarget {
        seen: Mutex<Vec<u128>>,
    }

    impl RecordingTarget {
        fn new() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl MarketReconcileTarget for RecordingTarget {
        async fn reconcile(
            &self,
            attempt: &PendingMarketAttempt,
        ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
            let value = match attempt.amount() {
                AmountSpec::TokenAtomic(value) => value,
                _ => 0,
            };
            lock(&self.seen).push(value);
            Ok(MarketExecutionOutcome::Unknown)
        }
    }

    #[test]
    fn build_policy_matrix_is_strict() {
        let limits = PolicyLimits {
            max_trade_usd: policy::UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: policy::UsdMicros::new(1_000_000),
            max_daily_turnover_usd: policy::UsdMicros::new(1_000_000),
            max_buy_tax: market_types::Bps::new(100).expect("bps"),
            max_sell_tax: market_types::Bps::new(100).expect("bps"),
            max_price_impact: market_types::Bps::new(100).expect("bps"),
            max_slippage: market_types::Bps::new(100).expect("bps"),
            allowed_chains: HashSet::from([ChainId::Base]),
            allowed_venues: HashSet::new(),
        };
        assert!(!build_policy(None, limits.clone())
            .expect("none")
            .is_trading_enabled());
        assert!(!build_policy(Some("false"), limits.clone())
            .expect("false")
            .is_trading_enabled());
        assert!(build_policy(Some("true"), limits.clone())
            .expect("true")
            .is_trading_enabled());
        assert!(matches!(
            build_policy(Some("TRUE"), limits.clone()),
            Err(PolicyError::InvalidTradingEnabled)
        ));
        assert!(matches!(
            build_policy(Some("1"), limits),
            Err(PolicyError::InvalidTradingEnabled)
        ));
    }

    #[test]
    fn registry_dedups_bounds_and_removes_in_order() {
        let registry = MarketAttemptRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.record(attempt(1)));
        assert!(registry.record(attempt(2)));
        assert!(!registry.record(attempt(1)), "duplicate is a no-op");
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.pending()[0].amount(), AmountSpec::TokenAtomic(1));
        assert_eq!(registry.pending()[1].amount(), AmountSpec::TokenAtomic(2));

        assert!(registry.remove(&attempt(1)));
        assert!(!registry.remove(&attempt(1)));
        assert_eq!(registry.len(), 1);

        for value in 3..=MAX_PENDING_MARKET_ATTEMPTS as u128 {
            assert!(registry.record(attempt(value)), "value {value}");
        }
        // attempt(2) survives the removal above, so the loop leaves 255.
        assert!(registry.record(attempt(MAX_PENDING_MARKET_ATTEMPTS as u128 + 1)));
        assert_eq!(registry.len(), MAX_PENDING_MARKET_ATTEMPTS);
        assert!(
            !registry.record(attempt(MAX_PENDING_MARKET_ATTEMPTS as u128 + 2)),
            "full registry drops the newcomer"
        );
        assert_eq!(registry.len(), MAX_PENDING_MARKET_ATTEMPTS);
    }

    #[test]
    fn reserve_dedups_counts_refs_and_gates_capacity() {
        let registry = MarketAttemptRegistry::new();
        let first = match registry.reserve(attempt(1)) {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected Reserved, got {other:?}"),
        };
        let duplicate = match registry.reserve(attempt(1)) {
            ReserveOutcome::AlreadyPending(reservation) => reservation,
            other => panic!("expected AlreadyPending, got {other:?}"),
        };
        assert_eq!(registry.len(), 1);
        // Two references: one release keeps the entry, the second removes it.
        registry.release(&first);
        assert_eq!(registry.len(), 1);
        registry.release(&duplicate);
        assert!(registry.is_empty());
        // Releasing an absent/stale ticket is a no-op.
        registry.release(&first);
        assert!(registry.is_empty());

        for value in 1..=MAX_PENDING_MARKET_ATTEMPTS as u128 {
            assert!(matches!(
                registry.reserve(attempt(value)),
                ReserveOutcome::Reserved(_)
            ));
        }
        assert_eq!(registry.len(), MAX_PENDING_MARKET_ATTEMPTS);
        assert_eq!(
            registry.reserve(attempt(MAX_PENDING_MARKET_ATTEMPTS as u128 + 1)),
            ReserveOutcome::AtCapacity,
            "a distinct newcomer is refused at capacity"
        );
        assert!(matches!(
            registry.reserve(attempt(1)),
            ReserveOutcome::AlreadyPending(_)
        ));
        assert_eq!(registry.len(), MAX_PENDING_MARKET_ATTEMPTS);
    }

    #[test]
    fn stale_release_cannot_evict_a_re_reserved_attempt() {
        let registry = MarketAttemptRegistry::new();
        let stale = match registry.reserve(attempt(1)) {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected Reserved, got {other:?}"),
        };
        // Reconcile terminalizes the entry while the original reservation is
        // still outstanding.
        assert!(registry.remove(&attempt(1)));
        assert!(registry.is_empty());
        // A concurrent execute re-reserves the same identity (fresh generation).
        let fresh = match registry.reserve(attempt(1)) {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected Reserved, got {other:?}"),
        };
        // The delayed release from the drained generation must not evict it.
        registry.release(&stale);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.pending()[0], attempt(1));
        registry.release(&fresh);
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn recorder_denies_before_forward_at_capacity() {
        let registry = Arc::new(MarketAttemptRegistry::new());
        for value in 1..=MAX_PENDING_MARKET_ATTEMPTS as u128 {
            assert!(matches!(
                registry.reserve(attempt(value)),
                ReserveOutcome::Reserved(_)
            ));
        }
        let inner = Arc::new(FixedOutcomeBackend::new(BackendOutcome::Unavailable));
        let recorder = RecordingAgentBackend::new(inner.clone(), registry.clone());

        let outcome = recorder
            .execute(
                AgentChannel::Mcp,
                trade(MAX_PENDING_MARKET_ATTEMPTS as u128 + 1),
            )
            .await;
        assert_eq!(outcome, BackendOutcome::Denied);
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            0,
            "the capacity gate must not call the inner backend/port"
        );
        assert_eq!(
            registry.len(),
            MAX_PENDING_MARKET_ATTEMPTS,
            "the refused attempt must not be stored"
        );
    }

    #[tokio::test]
    async fn recorder_releases_non_delegation_and_keeps_value() {
        for outcome in [
            BackendOutcome::Denied,
            BackendOutcome::Unavailable,
            BackendOutcome::Failed,
        ] {
            let registry = Arc::new(MarketAttemptRegistry::new());
            let inner = Arc::new(FixedOutcomeBackend::new(outcome.clone()));
            let recorder = RecordingAgentBackend::new(inner.clone(), registry.clone());
            assert_eq!(recorder.execute(AgentChannel::Mcp, trade(1)).await, outcome);
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
            assert!(
                registry.is_empty(),
                "a definitive non-delegation outcome must release the reservation"
            );
        }

        let registry = Arc::new(MarketAttemptRegistry::new());
        let inner = Arc::new(FixedOutcomeBackend::new(BackendOutcome::Value(
            serde_json::Value::Null,
        )));
        let recorder = RecordingAgentBackend::new(inner.clone(), registry.clone());
        assert!(matches!(
            recorder.execute(AgentChannel::Mcp, trade(7)).await,
            BackendOutcome::Value(_)
        ));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            registry.len(),
            1,
            "a delegated Value outcome is kept pending"
        );
        assert_eq!(registry.pending()[0], attempt(7));
        assert!(registry.remove(&attempt(7)));
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn reconcile_pass_rotates_the_prefix() {
        let registry = registry_with(&[1, 2, 3, 4, 5]);
        let target = Arc::new(RecordingTarget::new());
        let schedule = ReconcileSchedule {
            max_per_pass: 2,
            max_passes: 0,
        };
        let loop_ = MarketReconcileLoop::new(target.clone(), registry.clone(), schedule);
        let mut passes = Vec::new();
        for _ in 0..4 {
            lock(&target.seen).clear();
            assert_eq!(loop_.reconcile_pass(1_000).await.examined, 2);
            passes.push(lock(&target.seen).clone());
        }
        assert_eq!(passes[0], vec![1, 2]);
        assert_eq!(passes[1], vec![3, 4]);
        assert_eq!(
            passes[2],
            vec![5, 1],
            "the cursor wraps the pending snapshot"
        );
        assert_eq!(passes[3], vec![2, 3]);

        // Every pending attempt is examined within ceil(5 / 2) == 3 passes.
        let first_three: Vec<u128> = passes[0]
            .iter()
            .chain(&passes[1])
            .chain(&passes[2])
            .copied()
            .collect();
        for value in 1..=5u128 {
            assert!(
                first_three.contains(&value),
                "attempt {value} missed a pass"
            );
        }
        assert_eq!(registry.len(), 5, "Unknown keeps every attempt pending");
    }

    struct ScriptedTarget {
        calls: AtomicUsize,
        script: Mutex<VecDeque<Result<MarketExecutionOutcome, MarketExecutionError>>>,
    }

    impl ScriptedTarget {
        fn new(script: Vec<Result<MarketExecutionOutcome, MarketExecutionError>>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                script: Mutex::new(script.into()),
            }
        }
    }

    #[async_trait]
    impl MarketReconcileTarget for ScriptedTarget {
        async fn reconcile(
            &self,
            _attempt: &PendingMarketAttempt,
        ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.script)
                .pop_front()
                .unwrap_or(Ok(MarketExecutionOutcome::Unknown))
        }
    }

    struct ScriptedTick(VecDeque<i64>);

    #[async_trait]
    impl ReconcileTick for ScriptedTick {
        async fn next_tick(&mut self) -> Option<i64> {
            self.0.pop_front()
        }
    }

    fn registry_with(values: &[u128]) -> Arc<MarketAttemptRegistry> {
        let registry = Arc::new(MarketAttemptRegistry::new());
        for value in values {
            registry.record(attempt(*value));
        }
        registry
    }

    #[tokio::test]
    async fn reconcile_pass_classifies_exactly_and_is_repeatable() {
        let registry = registry_with(&[1, 2, 3, 4, 5]);
        let target = Arc::new(ScriptedTarget::new(vec![
            Ok(MarketExecutionOutcome::Filled {
                net_input: 10,
                net_output: 20,
            }),
            Ok(MarketExecutionOutcome::Failed),
            Ok(MarketExecutionOutcome::Unknown),
            Err(MarketExecutionError::Denied),
            Err(MarketExecutionError::Unavailable),
            // Second pass: only the two retained attempts are re-queried.
            Ok(MarketExecutionOutcome::Unknown),
            Err(MarketExecutionError::Unavailable),
        ]));
        let loop_ = MarketReconcileLoop::new(
            target.clone(),
            registry.clone(),
            ReconcileSchedule::default(),
        );
        let report = loop_.reconcile_pass(1_000).await;
        assert_eq!(
            report,
            ReconcilePassReport {
                examined: 5,
                filled: 1,
                failed: 2,
                in_flight: 1,
                unavailable: 1,
            }
        );
        assert_eq!(target.calls.load(Ordering::SeqCst), 5);
        assert_eq!(registry.len(), 2, "in-flight + unavailable are kept");

        // Second pass: only the retained attempts are examined; the resolved
        // ones are never re-queried.
        let report = loop_.reconcile_pass(2_000).await;
        assert_eq!(
            report,
            ReconcilePassReport {
                examined: 2,
                filled: 0,
                failed: 0,
                in_flight: 1,
                unavailable: 1,
            }
        );
        assert_eq!(target.calls.load(Ordering::SeqCst), 7);
        assert_eq!(registry.len(), 2);
    }

    #[tokio::test]
    async fn filled_attempts_are_removed_and_never_re_examined() {
        let registry = registry_with(&[1, 2]);
        let target = Arc::new(ScriptedTarget::new(vec![
            Ok(MarketExecutionOutcome::Filled {
                net_input: 1,
                net_output: 2,
            }),
            Ok(MarketExecutionOutcome::Filled {
                net_input: 1,
                net_output: 2,
            }),
        ]));
        let loop_ = MarketReconcileLoop::new(
            target.clone(),
            registry.clone(),
            ReconcileSchedule::default(),
        );
        assert_eq!(loop_.reconcile_pass(1).await.filled, 2);
        assert!(registry.is_empty());
        let report = loop_.reconcile_pass(2).await;
        assert_eq!(report, ReconcilePassReport::default());
        assert_eq!(target.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn max_per_pass_truncates_the_examined_set() {
        let registry = registry_with(&[1, 2, 3]);
        let target = Arc::new(ScriptedTarget::new(vec![
            Ok(MarketExecutionOutcome::Submitted),
            Ok(MarketExecutionOutcome::Submitted),
        ]));
        let schedule = ReconcileSchedule {
            max_per_pass: 2,
            max_passes: 0,
        };
        let loop_ = MarketReconcileLoop::new(target.clone(), registry.clone(), schedule);
        let report = loop_.reconcile_pass(1).await;
        assert_eq!(report.examined, 2);
        assert_eq!(report.in_flight, 2);
        assert_eq!(registry.len(), 3, "the untruncated attempt stays pending");
        assert_eq!(target.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn run_reconcile_loop_honours_tick_and_max_passes() {
        let registry = registry_with(&[1]);
        let target = Arc::new(ScriptedTarget::new(vec![Ok(
            MarketExecutionOutcome::Unknown,
        )]));
        let loop_ =
            MarketReconcileLoop::new(target.clone(), registry, ReconcileSchedule::default());
        let mut tick = ScriptedTick(VecDeque::from([10, 20, 30]));
        let report = run_reconcile_loop(&loop_, &mut tick).await;
        assert_eq!(report.passes, 3);
        assert_eq!(report.examined, 3);
        assert_eq!(report.in_flight, 3);
        assert_eq!(target.calls.load(Ordering::SeqCst), 3);

        let registry = registry_with(&[1]);
        let target = Arc::new(ScriptedTarget::new(vec![Ok(
            MarketExecutionOutcome::Unknown,
        )]));
        let bounded = MarketReconcileLoop::new(
            target.clone(),
            registry,
            ReconcileSchedule {
                max_per_pass: 32,
                max_passes: 2,
            },
        );
        let mut tick = ScriptedTick(VecDeque::from([10, 20, 30]));
        let report = run_reconcile_loop(&bounded, &mut tick).await;
        assert_eq!(report.passes, 2);
        assert_eq!(target.calls.load(Ordering::SeqCst), 2);

        let registry = registry_with(&[1]);
        let target = Arc::new(ScriptedTarget::new(Vec::new()));
        let loop_ = MarketReconcileLoop::new(target, registry, ReconcileSchedule::default());
        let mut tick = ScriptedTick(VecDeque::new());
        assert_eq!(
            run_reconcile_loop(&loop_, &mut tick).await,
            ReconcileRunReport::default()
        );
    }

    #[test]
    fn debug_impls_are_redacted_and_counts_only() {
        let config = CompositionConfig {
            owner: UserId::new("owner-secret").expect("owner"),
            wallet_ref: WalletRef::new("wallet-secret").expect("wallet"),
            chain: ChainId::Base,
            risk: RiskConstraints {
                max_buy_tax: market_types::Bps::new(100).expect("bps"),
                max_sell_tax: market_types::Bps::new(100).expect("bps"),
                max_price_impact: market_types::Bps::new(100).expect("bps"),
                max_slippage: market_types::Bps::new(100).expect("bps"),
                max_total_cost: None,
            },
            min_fill: AtomicAmount::new(1),
            allowed_chains: HashSet::from([ChainId::Base]),
            max_trade_usd: 1_000_000,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("owner-secret"));
        assert!(!rendered.contains("wallet-secret"));

        let registry = MarketAttemptRegistry::new();
        registry.record(attempt(1));
        assert_eq!(
            format!("{registry:?}"),
            "MarketAttemptRegistry { pending: 1 }"
        );
        let rendered = format!("{:?}", attempt(1));
        assert_eq!(rendered, "PendingMarketAttempt { .. }");
        assert!(!rendered.contains("USDC"));
        assert!(!rendered.contains("TOKEN"));
    }

    #[test]
    fn tokio_tick_floors_a_zero_interval() {
        let zero = TokioTick::new(Duration::ZERO);
        assert_eq!(format!("{zero:?}"), "TokioTick { interval: 1ms }");
        let tiny = TokioTick::new(Duration::from_nanos(1));
        assert_eq!(format!("{tiny:?}"), "TokioTick { interval: 1ms }");
        let normal = TokioTick::new(Duration::from_millis(250));
        assert_eq!(format!("{normal:?}"), "TokioTick { interval: 250ms }");
    }
}
