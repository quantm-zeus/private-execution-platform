//! Durable limit-order write delegation for the agent channels (Phase 6 S6).
//!
//! This module turns an already-authorized [`TradeCommand`] into a durable
//! [`limit_engine`] order. It is the write half of the agent backend: the read
//! half lives in [`crate::backend`], and both share the same authenticated,
//! owner-scoped composition.
//!
//! ## Boundaries
//! - **Limit orders and cancellation only for writes.** `place_limit_order`
//!   creates a durable `Created` record (no signing, no submission, no funds
//!   movement); `cancel_order` appends a validated `Cancelled` transition.
//!   `preview_market_order` is served read-only through an injected exact
//!   [`MarketSnapshotSource`] (see [`crate::market`]); `execute_market_order` is
//!   delegated to an injected [`MarketExecutionPort`] (fail-closed by default)
//!   that owns the pre-sign revalidation/policy/sign/submit composition.
//! - **Trusted identity and policy.** The owner, wallet, chain, risk caps, and
//!   minimum partial-fill floor come from the injected [`TradingBackendConfig`];
//!   nothing is taken from the command. The command's chain must equal the
//!   configured chain.
//! - **Deterministic idempotency.** The idempotency key (and the internal intent
//!   id) is derived from a domain-separated SHA-256 over the canonical creation
//!   fields, and the order id is derived by the injected store from that key, so
//!   a retried identical placement returns the existing record rather than
//!   creating a second order, and no derived id carries token/amount semantics.
//! - **Fail closed.** Invalid, foreign-owner, terminal, or cross-chain requests
//!   return the redacted [`BackendError::Denied`]; a store or market fault
//!   collapses to [`BackendError::Unavailable`]. No logging, no signing, no
//!   network.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::sync::Arc;

use agent_commands::{
    AgentChannel, AmountSpec, LimitPriceSpec, ReadCommand, RouterSource, TradeCommand,
};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, LimitOrder, LimitPrice, OrderId, OrderStatus, OrderType,
    RiskConstraints, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use limit_engine::{
    apply_transition, is_terminal, AppendOutcome, CreateOutcome, LimitEngineError, LimitOrderStore,
    OrderTransition, StoredLimitOrder, DEFAULT_SCHEMA_VERSION,
};
use market_types::{AssetAmount, AtomicAmount, Bps};
use mcp_server::{AgentBackend, BackendOutcome};
use routing::{quote_provider_route, GasEstimator, PoolRefLabel, ProviderRouteInput, VenueLabel};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::backend::AgentReadBackend;
use crate::error::BackendError;
use crate::execute::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
    UnavailableMarketExecution,
};
use crate::market::{
    plan_market_preview, MarketPreview, MarketPreviewError, MarketSnapshotSource,
    UnavailableMarketSnapshot,
};
use crate::okx::{OkxQuoteError, OkxQuoteSource, UnavailableOkxQuoteSource};
use crate::order::{OrderReadModel, OrderSummary};
use crate::portfolio::PortfolioReadModel;

/// Domain separation for the derived idempotency key.
const IDEMPOTENCY_DOMAIN: &[u8] = b"agent.limit.order.idem.v1";
/// Domain separation for the derived internal intent id.
const INTENT_ID_DOMAIN: &[u8] = b"agent.limit.order.intent.v1";
/// Domain separation for the derived preview-intent idempotency key.
const PREVIEW_IDEMPOTENCY_DOMAIN: &[u8] = b"agent.market.preview.idem.v1";
/// Domain separation for the derived preview-intent id.
const PREVIEW_INTENT_DOMAIN: &[u8] = b"agent.market.preview.intent.v1";

/// Trusted clock used to stamp order deadlines and transition times.
///
/// Injected so tests and callers can be deterministic; a [`SystemClock`] is
/// available for production composition.
pub trait TrustedClock: Send + Sync {
    /// Wall-clock time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// Production clock backed by the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            // Before the epoch cannot be a valid order time; fail closed by
            // returning a value that makes every deadline already expired.
            Err(_) => i64::MIN,
        }
    }
}

/// A clock fixed at one timestamp, for deterministic tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub i64);

impl TrustedClock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

/// Trusted USD-micros valuation port.
///
/// The agent dispatcher never derives value from a request body; it obtains the
/// valuation from this port. Returning `None` fails a mutating command closed.
pub trait OrderValuation: Send + Sync {
    /// Trusted USD-micros value of `amount` atomic units of `asset`, or `None`.
    fn usd_micros(&self, asset: &AssetId, amount: AtomicAmount) -> Option<u64>;
}

/// Fail-closed default valuation: every unknown token cannot be valued.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableOrderValuation;

impl OrderValuation for UnavailableOrderValuation {
    fn usd_micros(&self, _asset: &AssetId, _amount: AtomicAmount) -> Option<u64> {
        None
    }
}

/// Trusted, owner-scoped configuration for the write backend.
#[derive(Clone)]
pub struct TradingBackendConfig {
    /// Authenticated owner every written order belongs to.
    pub owner: UserId,
    /// Wallet the orders trade from.
    pub wallet_ref: WalletRef,
    /// Chain every written order must be bound to.
    pub chain: ChainId,
    /// Wallet risk caps applied to every order.
    ///
    /// `max_total_cost` is always overridden to `None`: the per-trade notional
    /// cap is enforced by the dispatcher's trusted valuation and
    /// [`agent_commands::AgentCapabilities::max_trade_usd`], and an asset-bound
    /// `max_total_cost` would otherwise reject every order whose input asset
    /// differs from the configured asset.
    ///
    /// A **zero** `max_price_impact` (or `max_slippage`) is the router's
    /// "unbounded" sentinel, not a zero-tolerance cap: it is the operator's
    /// configuration and is forwarded as such. Operators who want a real bound
    /// must set a non-zero cap, because a 0 cannot be distinguished from "no
    /// cap" downstream. A command-supplied cap can never loosen this value (see
    /// `effective_cap`).
    pub risk: RiskConstraints,
    /// Minimum partial-fill size; clamped up to 1 and down to the order amount.
    pub min_fill: AtomicAmount,
}

impl std::fmt::Debug for TradingBackendConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: owner/wallet/chain/risk are capability semantics.
        formatter
            .debug_struct("TradingBackendConfig")
            .finish_non_exhaustive()
    }
}

/// Owner-scoped agent backend with a durable limit-order write path.
///
/// Reads are delegated to the same [`AgentReadBackend`] used by the read-only
/// composition, except `get_quote`, which is served here from the exact local
/// router (the read-only composition has no market port); limit-order placement
/// and cancellation are served by the injected durable store;
/// `preview_market_order` is quoted exactly through the injected
/// [`MarketSnapshotSource`] and gas model; `execute_market_order` is delegated to
/// the injected [`MarketExecutionPort`] (fail-closed by default).
pub struct TradingAgentBackend<O: OrderReadModel, P: PortfolioReadModel, S> {
    reads: AgentReadBackend<O, P>,
    store: Arc<S>,
    config: TradingBackendConfig,
    clock: Arc<dyn TrustedClock>,
    valuation: Arc<dyn OrderValuation>,
    market: Arc<dyn MarketSnapshotSource>,
    gas: Option<Arc<dyn GasEstimator>>,
    execution: Arc<dyn MarketExecutionPort>,
    provider: Arc<dyn OkxQuoteSource>,
}

impl<O: OrderReadModel, P: PortfolioReadModel, S> TradingAgentBackend<O, P, S> {
    /// Wires the write backend from its trusted ports.
    ///
    /// The market preview port defaults to fail-closed
    /// ([`UnavailableMarketSnapshot`]), the execution port to fail-closed
    /// ([`UnavailableMarketExecution`]), and the gas model to absent; use
    /// [`Self::with_market_snapshot`], [`Self::with_market_execution`], and
    /// [`Self::with_gas_estimator`] to opt in.
    pub fn new(
        reads: AgentReadBackend<O, P>,
        store: Arc<S>,
        config: TradingBackendConfig,
        clock: Arc<dyn TrustedClock>,
        valuation: Arc<dyn OrderValuation>,
    ) -> Self {
        Self {
            reads,
            store,
            config,
            clock,
            valuation,
            market: Arc::new(UnavailableMarketSnapshot),
            gas: None,
            execution: Arc::new(UnavailableMarketExecution),
            provider: Arc::new(UnavailableOkxQuoteSource),
        }
    }

    /// Installs the trusted market-state source used for exact previews.
    pub fn with_market_snapshot(mut self, source: Arc<dyn MarketSnapshotSource>) -> Self {
        self.market = source;
        self
    }

    /// Installs the deterministic gas model used by preview/execution scoring.
    pub fn with_gas_estimator(mut self, gas: Arc<dyn GasEstimator>) -> Self {
        self.gas = Some(gas);
        self
    }

    /// Installs the market-execution port used by `execute_market_order`.
    pub fn with_market_execution(mut self, execution: Arc<dyn MarketExecutionPort>) -> Self {
        self.execution = execution;
        self
    }

    /// Installs the read-only OKX quote source used by the `Okx` route.
    ///
    /// The default is [`UnavailableOkxQuoteSource`], so an OKX-selected command
    /// fails closed until a source is explicitly installed; it never silently
    /// falls back to the local router.
    pub fn with_okx_quote_source(mut self, source: Arc<dyn OkxQuoteSource>) -> Self {
        self.provider = source;
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn creation_parts<'a>(
        &'a self,
        token_in: &'a agent_commands::AssetRef,
        token_out: &'a agent_commands::AssetRef,
        side: TradeSide,
        amount: &'a AmountSpec,
        limit_price: &'a LimitPriceSpec,
        allow_partial_fill: bool,
        expires_at_ms: i64,
    ) -> Vec<Vec<u8>> {
        let (unit, value) = match amount {
            AmountSpec::TokenAtomic(value) => ("token", *value),
            AmountSpec::StablecoinAtomic(value) => ("stablecoin", *value),
            AmountSpec::UsdMicros(value) => ("usd_micros", *value as u128),
        };
        vec![
            self.config.owner.as_str().as_bytes().to_vec(),
            self.config.wallet_ref.as_str().as_bytes().to_vec(),
            chain_code(&self.config.chain).into_bytes(),
            chain_code(&token_in.chain).into_bytes(),
            token_in.address.as_bytes().to_vec(),
            chain_code(&token_out.chain).into_bytes(),
            token_out.address.as_bytes().to_vec(),
            vec![match side {
                TradeSide::Buy => 1,
                TradeSide::Sell => 2,
            }],
            unit.as_bytes().to_vec(),
            value.to_be_bytes().to_vec(),
            limit_price.numerator_atomic.to_be_bytes().to_vec(),
            limit_price.denominator_atomic.to_be_bytes().to_vec(),
            vec![u8::from(allow_partial_fill)],
            expires_at_ms.to_be_bytes().to_vec(),
            // The trusted config is part of the creation baseline the store
            // compares on an idempotent re-create, so it is part of the
            // identity too.
            self.config.min_fill.get().to_be_bytes().to_vec(),
            self.config.risk.max_buy_tax.get().to_be_bytes().to_vec(),
            self.config.risk.max_sell_tax.get().to_be_bytes().to_vec(),
            self.config
                .risk
                .max_price_impact
                .get()
                .to_be_bytes()
                .to_vec(),
            self.config.risk.max_slippage.get().to_be_bytes().to_vec(),
        ]
    }

    /// Canonical creation identity for one preview request.
    ///
    /// No timestamp is included, so an identical preview request yields an
    /// identical derived intent/idempotency identity. The effective risk caps
    /// are part of the identity because they bound the quoted route, and the
    /// selected `router` source is bound so a Local quote can never be replayed
    /// as an OKX execution (or vice versa).
    #[allow(clippy::too_many_arguments)]
    fn preview_parts(
        &self,
        token_in: &agent_commands::AssetRef,
        token_out: &agent_commands::AssetRef,
        side: TradeSide,
        amount_in: AtomicAmount,
        max_slippage: Bps,
        max_price_impact: Bps,
        router: RouterSource,
    ) -> Vec<Vec<u8>> {
        let mut parts = vec![
            self.config.owner.as_str().as_bytes().to_vec(),
            self.config.wallet_ref.as_str().as_bytes().to_vec(),
            chain_code(&self.config.chain).into_bytes(),
            chain_code(&token_in.chain).into_bytes(),
            token_in.address.as_bytes().to_vec(),
            chain_code(&token_out.chain).into_bytes(),
            token_out.address.as_bytes().to_vec(),
            vec![match side {
                TradeSide::Buy => 1,
                TradeSide::Sell => 2,
            }],
            amount_in.get().to_be_bytes().to_vec(),
            max_slippage.get().to_be_bytes().to_vec(),
            max_price_impact.get().to_be_bytes().to_vec(),
            self.config.risk.max_buy_tax.get().to_be_bytes().to_vec(),
            self.config.risk.max_sell_tax.get().to_be_bytes().to_vec(),
        ];
        // Source-bound identity: OKX appends its discriminant so a Local quote
        // can never be replayed as an OKX execution. Local appends nothing, so a
        // pre-P84B Local intent/idempotency identity is preserved byte-for-byte.
        if router == RouterSource::Okx {
            parts.push(b"okx".to_vec());
        }
        parts
    }

    /// Builds the trusted intent for one market preview.
    ///
    /// Every policy-bearing field comes from [`TradingBackendConfig`]; the
    /// command contributes only the asset pair, side, and explicit input amount.
    /// A requested slippage/impact cap tighter than the wallet's hard cap is
    /// honored; a requested `0` (the router's unbounded-impact sentinel,
    /// ambiguous for slippage) and any request *above* the hard cap both fail
    /// closed with [`BackendError::Denied`].
    #[allow(clippy::too_many_arguments)]
    fn preview_intent(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: &AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        router: RouterSource,
    ) -> Result<(TradeIntent, AtomicAmount), BackendError> {
        // Bind the command to the configured chain before any state is built.
        if token_in.chain != self.config.chain || token_out.chain != self.config.chain {
            return Err(BackendError::Denied);
        }
        let asset_in = token_in.to_asset_id().map_err(|_| BackendError::Denied)?;
        let asset_out = token_out.to_asset_id().map_err(|_| BackendError::Denied)?;
        if asset_in == asset_out {
            return Err(BackendError::Denied);
        }
        // Only explicit atomic input amounts are accepted; a USD amount needs a
        // trusted conversion this layer does not perform, so it fails closed.
        let amount_in = match amount {
            AmountSpec::TokenAtomic(value) | AmountSpec::StablecoinAtomic(value) if *value > 0 => {
                AtomicAmount::new(*value)
            }
            _ => return Err(BackendError::Denied),
        };
        let max_slippage = effective_cap(self.config.risk.max_slippage, max_slippage_bps)?;
        let max_price_impact =
            effective_cap(self.config.risk.max_price_impact, max_price_impact_bps)?;

        let parts = self.preview_parts(
            &token_in,
            &token_out,
            side,
            amount_in,
            max_slippage,
            max_price_impact,
            router,
        );
        let derived = DerivedIdentity::preview(&parts);
        let risk = RiskConstraints {
            max_buy_tax: self.config.risk.max_buy_tax,
            max_sell_tax: self.config.risk.max_sell_tax,
            max_price_impact,
            max_slippage,
            // The trusted per-trade notional cap is enforced by the dispatcher's
            // trusted valuation for mutating commands. A preview moves no funds,
            // and the config cap (when set) is asset-bound to `token_in`, so
            // applying it would false-deny a cross-asset preview; omit it.
            max_total_cost: None,
        };
        let intent = TradeIntent {
            id: IntentId::new(derived.intent_id.as_str()).map_err(|_| BackendError::Denied)?,
            source: channel_source(channel),
            user_id: self.config.owner.clone(),
            wallet_ref: self.config.wallet_ref.clone(),
            chain: self.config.chain.clone(),
            token_in: asset_in,
            token_out: asset_out,
            side,
            amount_type: AmountType::InputAssetAtomic,
            amount: amount_in,
            order_type: OrderType::Market,
            limit_price: None,
            risk,
            allow_partial_fill: false,
            expiry_ms: None,
            nonce: 0,
            idempotency_key: IdempotencyKey::new(derived.idempotency_key.as_str())
                .map_err(|_| BackendError::Denied)?,
        };
        Ok((intent, amount_in))
    }

    /// Quotes an exact market preview, returning the trusted intent and result.
    ///
    /// The intent is returned so `execute_market_order` can hand the exact same
    /// trusted intent (and route) to the execution port that produced the quote.
    /// The caller supplies `now_ms` so one command reads the trusted clock once
    /// and uses the same instant for pricing and execution.
    ///
    /// `router` selects the source. [`RouterSource::Local`] is byte-identical to
    /// the previous local planner path. [`RouterSource::Okx`] fetches the trusted
    /// snapshot for the tax assessment/scoring, computes the provider input, calls
    /// the injected [`OkxQuoteSource`], and composes through the locked provider
    /// bridge. It **never** falls back to Local: a provider outage or rejection
    /// is surfaced as unavailability/denial.
    #[allow(clippy::too_many_arguments)]
    async fn quote_market_preview(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        now_ms: i64,
        router: RouterSource,
    ) -> Result<(TradeIntent, MarketPreview), BackendError> {
        let (intent, amount_in) = self.preview_intent(
            channel,
            token_in,
            token_out,
            side,
            &amount,
            max_slippage_bps,
            max_price_impact_bps,
            router,
        )?;
        match router {
            RouterSource::Local => {
                let preview = plan_market_preview(
                    self.market.as_ref(),
                    self.gas.as_deref(),
                    &intent,
                    amount_in,
                    now_ms,
                )
                .map_err(|error| match error {
                    MarketPreviewError::Unavailable => BackendError::Unavailable,
                    MarketPreviewError::NoViableRoute => BackendError::Denied,
                })?;
                Ok((intent, preview))
            }
            RouterSource::Okx => {
                // The trusted snapshot still supplies the tax assessment, the
                // freshness policy, and the score inputs; the gross output comes
                // from the provider and is validated through the locked bridge.
                let snapshot = self
                    .market
                    .snapshot(&intent, amount_in, now_ms)
                    .map_err(|_| BackendError::Unavailable)?;
                // Sell-side input tax is charged before the swap, so the provider
                // only sees the transferable remainder.
                let provider_amount_in = match intent.side {
                    TradeSide::Buy => amount_in,
                    TradeSide::Sell => {
                        snapshot
                            .assessment
                            .apply_sell_tax_to_input(&AssetAmount {
                                asset: intent.token_in.clone(),
                                amount: amount_in,
                            })
                            .map_err(|_| BackendError::Denied)?
                            .net_transferable_input
                            .amount
                    }
                };
                let normalized = self
                    .provider
                    .fetch_quote(
                        intent.chain.clone(),
                        intent.token_in.clone(),
                        intent.token_out.clone(),
                        provider_amount_in,
                        Some(intent.risk.max_slippage),
                        now_ms,
                    )
                    .await
                    .map_err(|error| match error {
                        OkxQuoteError::Unavailable => BackendError::Unavailable,
                        OkxQuoteError::Rejected => BackendError::Denied,
                    })?;
                let venue = VenueLabel::new("okx").map_err(|_| BackendError::Denied)?;
                let pool_ref = PoolRefLabel::new("okx").map_err(|_| BackendError::Denied)?;
                let input = ProviderRouteInput {
                    intent: &intent,
                    amount_in,
                    provider_gross_output: AtomicAmount::new(normalized.amount_out()),
                    assessment: &snapshot.assessment,
                    freshness_policy: &snapshot.freshness_policy,
                    now_ms,
                    venue: &venue,
                    pool_ref: &pool_ref,
                    scoring: &snapshot.scoring,
                    price_impact_bps: normalized.price_impact_bps(),
                };
                let composed = quote_provider_route(&input).map_err(|_| BackendError::Denied)?;
                Ok((
                    intent,
                    MarketPreview {
                        quote: composed.quote,
                        score: composed.score,
                        truncated: false,
                        router_source: RouterSource::Okx,
                    },
                ))
            }
        }
    }

    /// Executes a market order by delegating the exact quote to the injected port.
    #[allow(clippy::too_many_arguments)]
    async fn execute_market_order(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        router: RouterSource,
    ) -> BackendOutcome {
        // Read the trusted clock once: the quote and the execution request must
        // be stamped with the same instant.
        let now_ms = self.clock.now_ms();
        let (intent, preview) = match self
            .quote_market_preview(
                channel,
                token_in,
                token_out,
                side,
                amount,
                max_slippage_bps,
                max_price_impact_bps,
                now_ms,
                router,
            )
            .await
        {
            Ok(quoted) => quoted,
            Err(BackendError::Denied) => return BackendOutcome::Denied,
            Err(BackendError::Unavailable) => return BackendOutcome::Unavailable,
        };
        let request = MarketExecutionRequest {
            intent,
            quote: preview.quote,
            score: preview.score,
            now_ms,
            router_source: router,
        };
        // BR-10: the stable execution reference is the intent id. Capture it
        // before the port consumes the request so the authenticated result can
        // bind the client to the attempt it submitted.
        let execution_id = request.intent.id.as_str().to_string();
        match self.execution.execute(request).await {
            Ok(outcome) => execution_outcome(outcome, router, Some(&execution_id)),
            Err(MarketExecutionError::Denied) => BackendOutcome::Denied,
            Err(MarketExecutionError::Unavailable) => BackendOutcome::Unavailable,
        }
    }

    /// Reconciles a previously delegated market attempt, returning the typed
    /// [`MarketExecutionOutcome`] instead of a rendered [`BackendOutcome`].
    ///
    /// This is the additive typed seam used by the composition root's read-only
    /// reconcile loop. It rebuilds the deterministic preview identity from the
    /// same parameters [`Self::execute_market_order`] uses (via `preview_intent`),
    /// so the idempotency key handed to the port is byte-identical to the one the
    /// execution used (P76 MR-4 identity parity); a structural denial is returned
    /// without touching the port. No quote is needed to derive the identity, so
    /// no [`MarketSnapshotSource`] is consulted, and the call never signs or
    /// submits.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_market_order_outcome(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        router: RouterSource,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        // Read the trusted clock once, exactly as `execute_market_order` does.
        let now_ms = self.clock.now_ms();
        let (intent, _amount_in) = match self.preview_intent(
            channel,
            token_in,
            token_out,
            side,
            &amount,
            max_slippage_bps,
            max_price_impact_bps,
            router,
        ) {
            Ok(intent) => intent,
            Err(BackendError::Denied) => return Err(MarketExecutionError::Denied),
            Err(BackendError::Unavailable) => return Err(MarketExecutionError::Unavailable),
        };
        let binding = execution_relay::AttemptBinding::from_intent(&intent);
        self.execution.reconcile(&binding, now_ms).await
    }

    /// Reconciles an already-submitted market order identified by the same
    /// command parameters that produced it. Read-only: it never signs or submits.
    ///
    /// Thin rendering wrapper over [`Self::reconcile_market_order_outcome`], so
    /// the typed and backend-shaped surfaces can never drift: it delegates the
    /// identity rebuild and the port call exactly once, then maps the outcome via
    /// `execution_outcome` identically to before.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_market_order(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        router: RouterSource,
    ) -> BackendOutcome {
        match self
            .reconcile_market_order_outcome(
                channel,
                token_in,
                token_out,
                side,
                amount,
                max_slippage_bps,
                max_price_impact_bps,
                router,
            )
            .await
        {
            Ok(outcome) => execution_outcome(outcome, router, None),
            Err(MarketExecutionError::Denied) => BackendOutcome::Denied,
            Err(MarketExecutionError::Unavailable) => BackendOutcome::Unavailable,
        }
    }

    /// Serves the read-only `get_quote` command from the selected router.
    ///
    /// `get_quote` carries no side, so it quotes the exact-input direction:
    /// spending `token_in` to receive `token_out` (a Buy of `token_out`). The
    /// result is the same locked route and full-net-economics preview that
    /// `preview_market_order` returns, so a displayed quote is never mistaken
    /// for an approximate price. `router` selects the same Local/OKX source as
    /// `preview_market_order`; an OKX outage fails closed. No funds move and no
    /// execution port is touched.
    async fn quote_read(
        &self,
        channel: AgentChannel,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        amount: AmountSpec,
        router: RouterSource,
    ) -> BackendOutcome {
        let now_ms = self.clock.now_ms();
        match self
            .quote_market_preview(
                channel,
                token_in,
                token_out,
                TradeSide::Buy,
                amount,
                None,
                None,
                now_ms,
                router,
            )
            .await
        {
            Ok((_intent, preview)) => BackendOutcome::Value(json!({ "quote": preview })),
            Err(BackendError::Denied) => BackendOutcome::Denied,
            Err(BackendError::Unavailable) => BackendOutcome::Unavailable,
        }
    }
}

impl<O: OrderReadModel, P: PortfolioReadModel, S> std::fmt::Debug for TradingAgentBackend<O, P, S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TradingAgentBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<O, P, S> AgentBackend for TradingAgentBackend<O, P, S>
where
    O: OrderReadModel + 'static,
    P: PortfolioReadModel + 'static,
    S: LimitOrderStore + 'static,
{
    async fn execute(
        &self,
        channel: agent_commands::AgentChannel,
        command: agent_commands::AgentCommand,
    ) -> BackendOutcome {
        match command {
            // `get_quote` needs exact local market state, so the trading backend
            // serves it (the read-only composition has no market port and keeps
            // returning Unavailable for it).
            agent_commands::AgentCommand::Read(ReadCommand::GetQuote {
                token_in,
                token_out,
                amount,
                router,
            }) => {
                self.quote_read(channel, token_in, token_out, amount, router)
                    .await
            }
            agent_commands::AgentCommand::Read(read) => {
                self.reads
                    .execute(channel, agent_commands::AgentCommand::Read(read))
                    .await
            }
            agent_commands::AgentCommand::Trade(trade) => self.execute_trade(channel, trade).await,
        }
    }

    async fn valuation_usd_micros(&self, command: &agent_commands::AgentCommand) -> Option<u64> {
        let agent_commands::AgentCommand::Trade(trade) = command else {
            return None;
        };
        match trade {
            TradeCommand::PlaceLimitOrder {
                token_in, amount, ..
            }
            | TradeCommand::ExecuteMarketOrder {
                token_in, amount, ..
            } => match amount {
                // A USD-micros amount is a request-body value, not a trusted
                // valuation, so the port must value it (and today cannot):
                // fail closed rather than echo the body back as "trusted".
                AmountSpec::UsdMicros(_) => None,
                AmountSpec::TokenAtomic(value) | AmountSpec::StablecoinAtomic(value) => {
                    let asset = token_in.to_asset_id().ok()?;
                    self.valuation.usd_micros(&asset, AtomicAmount::new(*value))
                }
            },
            // Cancellation moves no funds; authorize still requires a valuation.
            TradeCommand::CancelOrder { .. } => Some(0),
            // Preview is read-only, so it needs no trusted valuation.
            TradeCommand::PreviewMarketOrder { .. } => None,
        }
    }
}

impl<O, P, S> TradingAgentBackend<O, P, S>
where
    O: OrderReadModel,
    P: PortfolioReadModel,
    S: LimitOrderStore,
{
    async fn execute_trade(&self, channel: AgentChannel, command: TradeCommand) -> BackendOutcome {
        match command {
            TradeCommand::PreviewMarketOrder {
                token_in,
                token_out,
                side,
                amount,
                max_slippage_bps,
                max_price_impact_bps,
                router,
            } => {
                let now_ms = self.clock.now_ms();
                match self
                    .quote_market_preview(
                        channel,
                        token_in,
                        token_out,
                        side,
                        amount,
                        max_slippage_bps,
                        max_price_impact_bps,
                        now_ms,
                        router,
                    )
                    .await
                {
                    Ok((_intent, preview)) => BackendOutcome::Value(json!({ "preview": preview })),
                    Err(BackendError::Denied) => BackendOutcome::Denied,
                    Err(BackendError::Unavailable) => BackendOutcome::Unavailable,
                }
            }
            TradeCommand::ExecuteMarketOrder {
                token_in,
                token_out,
                side,
                amount,
                max_slippage_bps,
                max_price_impact_bps,
                router,
            } => {
                self.execute_market_order(
                    channel,
                    token_in,
                    token_out,
                    side,
                    amount,
                    max_slippage_bps,
                    max_price_impact_bps,
                    router,
                )
                .await
            }
            TradeCommand::PlaceLimitOrder {
                token_in,
                token_out,
                side,
                amount,
                limit_price,
                allow_partial_fill,
                expires_at_ms,
            } => {
                let parts = self.creation_parts(
                    &token_in,
                    &token_out,
                    side,
                    &amount,
                    &limit_price,
                    allow_partial_fill,
                    expires_at_ms,
                );
                let derived = DerivedIdentity::from_parts(&parts);
                let result = self
                    .place_limit_order(
                        token_in,
                        token_out,
                        side,
                        amount,
                        limit_price,
                        allow_partial_fill,
                        expires_at_ms,
                        &derived,
                    )
                    .await;
                outcome_for(result)
            }
            TradeCommand::CancelOrder { order_id } => {
                outcome_for(self.cancel_order(&order_id).await)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn place_limit_order(
        &self,
        token_in: agent_commands::AssetRef,
        token_out: agent_commands::AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        limit_price: LimitPriceSpec,
        allow_partial_fill: bool,
        expires_at_ms: i64,
        derived: &DerivedIdentity,
    ) -> Result<StoredLimitOrder, BackendError> {
        // Bind the command to the configured chain before any state is built.
        if token_in.chain != self.config.chain || token_out.chain != self.config.chain {
            return Err(BackendError::Denied);
        }
        let asset_in = token_in.to_asset_id().map_err(|_| BackendError::Denied)?;
        let asset_out = token_out.to_asset_id().map_err(|_| BackendError::Denied)?;
        if asset_in == asset_out {
            return Err(BackendError::Denied);
        }

        // Only explicit atomic token amounts are accepted; a USD amount needs a
        // conversion this layer does not perform, so it fails closed.
        let max_input = match amount {
            AmountSpec::TokenAtomic(value) | AmountSpec::StablecoinAtomic(value) if value > 0 => {
                AtomicAmount::new(value)
            }
            _ => return Err(BackendError::Denied),
        };

        let now_ms = self.clock.now_ms();
        if expires_at_ms <= now_ms {
            return Err(BackendError::Denied);
        }
        let ratio = limit_price
            .to_price_ratio()
            .map_err(|_| BackendError::Denied)?;
        let (numerator_asset, denominator_asset) = match side {
            TradeSide::Buy => (asset_in.clone(), asset_out.clone()),
            TradeSide::Sell => (asset_out.clone(), asset_in.clone()),
        };
        let min_fill = partial_fill_floor(allow_partial_fill, self.config.min_fill, max_input);

        // The store owns the id derivation: the durable store requires a keyed
        // MAC over the creation key that this layer must not (and cannot)
        // reproduce, so ask the store for the exact id it will accept.
        let idempotency_key = IdempotencyKey::new(derived.idempotency_key.as_str())
            .map_err(|_| BackendError::Denied)?;
        let order_id = self
            .store
            .creation_order_id(&idempotency_key)
            .map_err(|_| BackendError::Unavailable)?;

        let order = LimitOrder {
            id: order_id,
            owner: self.config.owner.clone(),
            wallet_ref: self.config.wallet_ref.clone(),
            chain: self.config.chain.clone(),
            token_in: asset_in.clone(),
            token_out: asset_out.clone(),
            side,
            max_input: AssetAmount {
                asset: asset_in,
                amount: max_input,
            },
            remaining_input: max_input,
            limit_price: LimitPrice {
                numerator_asset,
                denominator_asset,
                ratio,
            },
            risk: RiskConstraints {
                max_total_cost: None,
                ..self.config.risk.clone()
            },
            allow_partial_fill,
            min_fill,
            expires_at_ms,
            status: OrderStatus::Created,
        };
        order.validate(now_ms).map_err(|_| BackendError::Denied)?;

        let stored = StoredLimitOrder {
            schema_version: DEFAULT_SCHEMA_VERSION,
            version: 1,
            order,
            order_intent_id: IntentId::new(derived.intent_id.as_str())
                .map_err(|_| BackendError::Denied)?,
            order_idempotency_key: idempotency_key,
            nonce: 0,
            attempt_seq: 0,
            filled_input: AtomicAmount::ZERO,
            last_transition_seq: 0,
            published_seq: 0,
            next_eligible_at_ms: None,
        };

        match self.store.create(stored).await {
            Ok(CreateOutcome::Created(record)) | Ok(CreateOutcome::Existing(record)) => Ok(record),
            Err(LimitEngineError::IdempotencyConflict) => Err(BackendError::Denied),
            Err(_) => Err(BackendError::Unavailable),
        }
    }

    async fn cancel_order(&self, order_id: &str) -> Result<StoredLimitOrder, BackendError> {
        let id = OrderId::new(order_id).map_err(|_| BackendError::Denied)?;
        let current = match self.store.load(&id).await {
            Ok(Some(record)) => record,
            // Do not reveal whether a foreign or unknown id exists.
            Ok(None) | Err(_) => return Err(BackendError::Denied),
        };
        if current.order.owner != self.config.owner {
            return Err(BackendError::Denied);
        }
        // A repeat cancel is idempotent; any other terminal state is final.
        if current.order.status == OrderStatus::Cancelled {
            return Ok(current);
        }
        if is_terminal(current.order.status) {
            return Err(BackendError::Denied);
        }

        let now_ms = self.clock.now_ms();
        let next = apply_transition(&current, OrderStatus::Cancelled, None, now_ms)
            .map_err(|_| BackendError::Denied)?;
        let transition = OrderTransition {
            order_id: current.order.id.clone(),
            from: current.order.status,
            to: OrderStatus::Cancelled,
            transition_seq: current
                .last_transition_seq
                .checked_add(1)
                .ok_or(BackendError::Denied)?,
            fill: None,
            at_ms: now_ms,
        };
        match self
            .store
            .append_transition(current.version, &transition, &next)
            .await
        {
            // `AlreadyApplied` is only a success when the stored record really is
            // cancelled. The reference in-memory store returns the current head
            // for any already-seen sequence without comparing content, so a
            // racing transition to a different status must not be reported as a
            // successful cancel.
            Ok(AppendOutcome::Applied(record)) | Ok(AppendOutcome::AlreadyApplied(record))
                if record.order.status == OrderStatus::Cancelled =>
            {
                Ok(record)
            }
            // A store fault, a CAS conflict, or an already-applied different
            // transition is a redacted denial: retrying the cancel is safe.
            Ok(_) | Err(_) => Err(BackendError::Denied),
        }
    }
}

/// The domain-separated identities derived from one creation payload.
///
/// The order id is intentionally absent: it is derived by the injected store via
/// `LimitOrderStore::creation_order_id`, because the durable store requires a
/// keyed derivation this layer must not reproduce.
struct DerivedIdentity {
    idempotency_key: String,
    intent_id: String,
}

impl DerivedIdentity {
    fn from_parts(parts: &[Vec<u8>]) -> Self {
        Self::derive(IDEMPOTENCY_DOMAIN, INTENT_ID_DOMAIN, parts)
    }

    /// Preview identity, domain-separated from the durable-order identity so a
    /// preview-derived id can never collide with a placement identity.
    fn preview(parts: &[Vec<u8>]) -> Self {
        Self::derive(PREVIEW_IDEMPOTENCY_DOMAIN, PREVIEW_INTENT_DOMAIN, parts)
    }

    fn derive(idempotency_domain: &[u8], intent_domain: &[u8], parts: &[Vec<u8>]) -> Self {
        Self {
            idempotency_key: prefixed_hex(idempotency_domain, "idem", parts),
            intent_id: prefixed_hex(intent_domain, "intent", parts),
        }
    }
}

/// `prefix-<hex>` of a domain-separated SHA-256 over length-prefixed parts.
fn prefixed_hex(domain: &[u8], prefix: &str, parts: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(prefix.len() + 1 + digest.len() * 2);
    out.push_str(prefix);
    out.push('-');
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Stable, payload-free chain token for the identity hash.
fn chain_code(chain: &ChainId) -> String {
    match chain {
        ChainId::Solana => "solana".to_string(),
        ChainId::Base => "base".to_string(),
        ChainId::BnbChain => "bnb_chain".to_string(),
        ChainId::Ethereum => "ethereum".to_string(),
        ChainId::RobinhoodAssociated => "robinhood_associated".to_string(),
        ChainId::Other(name) => format!("other:{name}"),
    }
}

/// The minimum partial fill: the configured floor clamped to `[1, max_input]`.
///
/// An all-or-nothing order must be fillable only in full, so its floor is the
/// whole amount.
fn partial_fill_floor(
    allow_partial_fill: bool,
    configured: AtomicAmount,
    max_input: AtomicAmount,
) -> AtomicAmount {
    if !allow_partial_fill {
        return max_input;
    }
    if configured.is_zero() || configured.get() > max_input.get() {
        return max_input;
    }
    configured
}

/// Resolves a requested slippage/impact cap against the wallet hard cap.
///
/// A request of `0` fails closed: the router treats `max_price_impact == 0` as
/// "no cap / unbounded", and `0` is ambiguous for slippage, so forwarding it
/// would silently disable the wallet's trusted cap. A request above the hard
/// cap also fails closed with [`BackendError::Denied`]. The trusted cap is used
/// when no request is made; otherwise a tighter request in `1..=trusted` is
/// honored.
fn effective_cap(trusted: Bps, requested: Option<u16>) -> Result<Bps, BackendError> {
    match requested {
        None => Ok(trusted),
        Some(value) if value > 0 && value <= trusted.get() => {
            Bps::new(value).map_err(|_| BackendError::Denied)
        }
        Some(_) => Err(BackendError::Denied),
    }
}

/// Maps an agent channel to the canonical intent source.
fn channel_source(channel: AgentChannel) -> TradeSource {
    match channel {
        AgentChannel::Mcp => TradeSource::Mcp,
        AgentChannel::Telegram => TradeSource::Telegram,
        AgentChannel::Web => TradeSource::Web,
    }
}

fn outcome_for(result: Result<StoredLimitOrder, BackendError>) -> BackendOutcome {
    match result {
        Ok(record) => BackendOutcome::Value(json!({ "order": OrderSummary::from_stored(&record) })),
        Err(BackendError::Unavailable) => BackendOutcome::Unavailable,
        Err(BackendError::Denied) => BackendOutcome::Denied,
    }
}

/// Shapes a port execution outcome into the authenticated backend result.
///
/// The payload is intentionally coarse: the state is explicit and realized
/// amounts are included only when the chain observed them. A definitively
/// failed execution is surfaced as [`BackendOutcome::Failed`] so the MCP layer
/// renders it as an error rather than a successful `"failed"` value.
///
/// BR-10: `router_source` is the routing discriminant the execution was bound
/// to (the same value carried on [`MarketExecutionRequest`]), and
/// `execution_id` is the stable intent reference when known. The private web
/// command surface requires both to attribute a submission honestly; a caller
/// that cannot supply them must not claim a source it cannot substantiate.
fn execution_outcome(
    outcome: MarketExecutionOutcome,
    router_source: RouterSource,
    execution_id: Option<&str>,
) -> BackendOutcome {
    let execution = match outcome {
        MarketExecutionOutcome::Submitted => json!({ "state": "submitted" }),
        MarketExecutionOutcome::Filled {
            net_input,
            net_output,
        } => json!({
            "state": "filled",
            "net_input": net_input,
            "net_output": net_output,
        }),
        MarketExecutionOutcome::Unknown => json!({ "state": "unknown" }),
        MarketExecutionOutcome::Failed => return BackendOutcome::Failed,
    };
    let mut value = json!({ "execution": execution, "router_source": router_source });
    if let Some(execution_id) = execution_id {
        value["execution_id"] = json!(execution_id);
    }
    BackendOutcome::Value(value)
}
