//! Durable limit-order write delegation for the agent channels (Phase 6 S6).
//!
//! This module turns an already-authorized [`TradeCommand`] into a durable
//! [`limit_engine`] order. It is the write half of the agent backend: the read
//! half lives in [`crate::backend`], and both share the same authenticated,
//! owner-scoped composition.
//!
//! ## Boundaries
//! - **Limit orders and cancellation only.** `place_limit_order` creates a
//!   durable `Created` record (no signing, no submission, no funds movement);
//!   `cancel_order` appends a validated `Cancelled` transition. Market-order
//!   preview/execute have no landed market pipeline and fail closed
//!   [`BackendOutcome::Unavailable`].
//! - **Trusted identity and policy.** The owner, wallet, chain, risk caps, and
//!   minimum partial-fill floor come from the injected [`TradingBackendConfig`];
//!   nothing is taken from the command. The command's chain must equal the
//!   configured chain.
//! - **Deterministic idempotency.** The order id and idempotency key are derived
//!   from a domain-separated SHA-256 over the canonical creation fields, so a
//!   retried identical placement returns the existing record rather than
//!   creating a second order, and the derived id never carries token/amount
//!   semantics.
//! - **Fail closed.** Invalid, foreign-owner, terminal, or cross-chain requests
//!   return the redacted [`BackendError::Denied`]; a store fault collapses to
//!   [`BackendError::Unavailable`]. No logging, no signing, no network.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::sync::Arc;

use agent_commands::{AmountSpec, LimitPriceSpec, TradeCommand};
use async_trait::async_trait;
use chain_types::{AssetId, ChainId};
use domain::{
    IdempotencyKey, IntentId, LimitOrder, LimitPrice, OrderId, OrderStatus, RiskConstraints,
    TradeSide, UserId, WalletRef,
};
use limit_engine::{
    apply_transition, is_terminal, AppendOutcome, CreateOutcome, LimitEngineError, LimitOrderStore,
    OrderTransition, StoredLimitOrder, DEFAULT_SCHEMA_VERSION,
};
use market_types::{AssetAmount, AtomicAmount};
use mcp_server::{AgentBackend, BackendOutcome};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::backend::AgentReadBackend;
use crate::error::BackendError;
use crate::order::{OrderReadModel, OrderSummary};
use crate::portfolio::PortfolioReadModel;

/// Domain separation for the derived idempotency key.
const IDEMPOTENCY_DOMAIN: &[u8] = b"agent.limit.order.idem.v1";
/// Domain separation for the derived internal intent id.
const INTENT_ID_DOMAIN: &[u8] = b"agent.limit.order.intent.v1";

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
/// composition; limit-order placement and cancellation are served by the
/// injected durable store. Market-order commands fail closed.
pub struct TradingAgentBackend<O: OrderReadModel, P: PortfolioReadModel, S> {
    reads: AgentReadBackend<O, P>,
    store: Arc<S>,
    config: TradingBackendConfig,
    clock: Arc<dyn TrustedClock>,
    valuation: Arc<dyn OrderValuation>,
}

impl<O: OrderReadModel, P: PortfolioReadModel, S> TradingAgentBackend<O, P, S> {
    /// Wires the write backend from its trusted ports.
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
        }
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
            agent_commands::AgentCommand::Read(read) => {
                self.reads
                    .execute(channel, agent_commands::AgentCommand::Read(read))
                    .await
            }
            agent_commands::AgentCommand::Trade(trade) => self.execute_trade(trade).await,
        }
    }

    async fn valuation_usd_micros(&self, command: &agent_commands::AgentCommand) -> Option<u64> {
        let agent_commands::AgentCommand::Trade(trade) = command else {
            return None;
        };
        match trade {
            TradeCommand::PlaceLimitOrder {
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
            // No market pipeline exists; these are never authorized as mutating.
            TradeCommand::PreviewMarketOrder { .. } | TradeCommand::ExecuteMarketOrder { .. } => {
                None
            }
        }
    }
}

impl<O, P, S> TradingAgentBackend<O, P, S>
where
    O: OrderReadModel,
    P: PortfolioReadModel,
    S: LimitOrderStore,
{
    async fn execute_trade(&self, command: TradeCommand) -> BackendOutcome {
        match command {
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
            // No market pipeline: fail closed rather than guess.
            TradeCommand::PreviewMarketOrder { .. } | TradeCommand::ExecuteMarketOrder { .. } => {
                BackendOutcome::Unavailable
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
        Self {
            idempotency_key: prefixed_hex(IDEMPOTENCY_DOMAIN, "idem", parts),
            intent_id: prefixed_hex(INTENT_ID_DOMAIN, "intent", parts),
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

fn outcome_for(result: Result<StoredLimitOrder, BackendError>) -> BackendOutcome {
    match result {
        Ok(record) => BackendOutcome::Value(json!({ "order": OrderSummary::from_stored(&record) })),
        Err(BackendError::Unavailable) => BackendOutcome::Unavailable,
        Err(BackendError::Denied) => BackendOutcome::Denied,
    }
}
