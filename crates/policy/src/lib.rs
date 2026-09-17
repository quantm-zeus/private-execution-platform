//! Trading policy and one-way kill-switch boundary.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use chain_types::ChainId;
use domain::{AmountType, IdempotencyKey, IntentId, TradeIntent, WalletRef};
use market_types::Bps;
use thiserror::Error;

pub mod wallet;
pub mod withdrawal;

pub use wallet::{
    classify_limits_change, Confirmation, InMemoryWalletPolicyStore, LimitsChange, WalletLimits,
    WalletLimitsChange, WalletPolicyError, WalletPolicyRecord, WalletPolicyStore,
    WebStrongConfirmation, MAX_APPLIED_POLICY_KEYS,
};
pub use withdrawal::{
    authorize_withdrawal, WithdrawalApproval, WithdrawalError, WithdrawalRequest,
    MAX_CONFIRMATION_AGE_MS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsdMicros(u64);
impl UsdMicros {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

#[derive(Debug)]
pub struct TradingGate {
    enabled: AtomicBool,
}
impl Default for TradingGate {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
        }
    }
}
impl TradingGate {
    pub fn from_trusted_startup(value: Option<&str>) -> Result<Self, PolicyError> {
        let enabled = match value {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(PolicyError::InvalidTradingEnabled),
        };
        Ok(Self {
            enabled: AtomicBool::new(enabled),
        })
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug)]
pub struct PolicyLimits {
    pub max_trade_usd: UsdMicros,
    pub max_hourly_turnover_usd: UsdMicros,
    pub max_daily_turnover_usd: UsdMicros,
    pub max_buy_tax: Bps,
    pub max_sell_tax: Bps,
    pub max_price_impact: Bps,
    pub max_slippage: Bps,
    pub allowed_chains: HashSet<ChainId>,
    pub allowed_venues: HashSet<String>,
}
impl PolicyLimits {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.max_trade_usd.get() == 0
            || self.max_hourly_turnover_usd < self.max_trade_usd
            || self.max_daily_turnover_usd < self.max_trade_usd
        {
            return Err(PolicyError::InvalidLimits);
        }
        if self.allowed_chains.is_empty() {
            return Err(PolicyError::InvalidLimits);
        }
        if self.allowed_venues.iter().any(|v| v.trim().is_empty()) {
            return Err(PolicyError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TurnoverSnapshot {
    hourly_used_usd: UsdMicros,
    daily_used_usd: UsdMicros,
}

impl TurnoverSnapshot {
    /// Must be sourced from trusted backend accounting state, never a control-plane request.
    pub fn from_trusted_backend_state(
        hourly_used_usd: UsdMicros,
        daily_used_usd: UsdMicros,
    ) -> Self {
        Self {
            hourly_used_usd,
            daily_used_usd,
        }
    }
    pub fn hourly_used_usd(&self) -> UsdMicros {
        self.hourly_used_usd
    }
    pub fn daily_used_usd(&self) -> UsdMicros {
        self.daily_used_usd
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    now_ms: i64,
    trade_usd: UsdMicros,
    turnover: TurnoverSnapshot,
    venue: Option<String>,
}

impl PolicyContext {
    /// Constructs backend-only policy facts. The valuation and turnover values must come from
    /// authoritative backend state, not Web/MCP/Telegram request payloads.
    pub fn from_trusted_backend_state(
        now_ms: i64,
        trade_usd: UsdMicros,
        turnover: TurnoverSnapshot,
        venue: Option<String>,
    ) -> Result<Self, PolicyError> {
        if trade_usd.get() == 0 {
            return Err(PolicyError::InvalidValuation);
        }
        if matches!(venue.as_deref(), Some(value) if value.trim().is_empty()) {
            return Err(PolicyError::VenueNotAllowed);
        }
        Ok(Self {
            now_ms,
            trade_usd,
            turnover,
            venue,
        })
    }
    pub fn now_ms(&self) -> i64 {
        self.now_ms
    }
    pub fn trade_usd(&self) -> UsdMicros {
        self.trade_usd
    }
    pub fn turnover(&self) -> TurnoverSnapshot {
        self.turnover
    }
    pub fn venue(&self) -> Option<&str> {
        self.venue.as_deref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedExecution {
    intent_id: IntentId,
    wallet_ref: WalletRef,
    chain: ChainId,
    idempotency_key: IdempotencyKey,
    expires_at_ms: Option<i64>,
    approved_trade_usd: UsdMicros,
    approved_at_ms: i64,
}
impl ApprovedExecution {
    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }
    pub fn wallet_ref(&self) -> &WalletRef {
        &self.wallet_ref
    }
    pub fn chain(&self) -> &ChainId {
        &self.chain
    }
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    pub fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at_ms
    }
    pub fn approved_trade_usd(&self) -> UsdMicros {
        self.approved_trade_usd
    }
    pub fn approved_at_ms(&self) -> i64 {
        self.approved_at_ms
    }
}

pub struct PolicyEngine {
    gate: TradingGate,
    limits: PolicyLimits,
}
impl PolicyEngine {
    pub fn new(gate: TradingGate, limits: PolicyLimits) -> Result<Self, PolicyError> {
        limits.validate()?;
        Ok(Self { gate, limits })
    }
    pub fn is_trading_enabled(&self) -> bool {
        self.gate.is_enabled()
    }
    pub fn disable_trading(&self) {
        self.gate.disable();
    }
    pub fn limits(&self) -> &PolicyLimits {
        &self.limits
    }

    pub fn authorize_trade(
        &self,
        intent: &TradeIntent,
        ctx: &PolicyContext,
    ) -> Result<ApprovedExecution, PolicyError> {
        if !self.gate.is_enabled() {
            return Err(PolicyError::TradingDisabled);
        }
        intent
            .validate(ctx.now_ms)
            .map_err(|_| PolicyError::IntentInvalid)?;
        if ctx.trade_usd.get() == 0 {
            return Err(PolicyError::InvalidValuation);
        }
        if intent.amount_type == AmountType::UsdMicros {
            let intent_usd =
                u64::try_from(intent.amount.get()).map_err(|_| PolicyError::ValuationOutOfRange)?;
            if intent_usd != ctx.trade_usd.get() {
                return Err(PolicyError::ValuationMismatch);
            }
        }
        if !self.limits.allowed_chains.contains(&intent.chain) {
            return Err(PolicyError::ChainNotAllowed);
        }
        if ctx.trade_usd > self.limits.max_trade_usd {
            return Err(PolicyError::TradeSizeExceeded);
        }
        let hourly = ctx
            .turnover
            .hourly_used_usd
            .checked_add(ctx.trade_usd)
            .ok_or(PolicyError::TurnoverOverflow)?;
        if hourly > self.limits.max_hourly_turnover_usd {
            return Err(PolicyError::HourlyTurnoverExceeded);
        }
        let daily = ctx
            .turnover
            .daily_used_usd
            .checked_add(ctx.trade_usd)
            .ok_or(PolicyError::TurnoverOverflow)?;
        if daily > self.limits.max_daily_turnover_usd {
            return Err(PolicyError::DailyTurnoverExceeded);
        }
        if intent.risk.max_buy_tax > self.limits.max_buy_tax
            || intent.risk.max_sell_tax > self.limits.max_sell_tax
            || intent.risk.max_price_impact > self.limits.max_price_impact
            || intent.risk.max_slippage > self.limits.max_slippage
        {
            return Err(PolicyError::RiskLimitExceeded);
        }
        if !self.limits.allowed_venues.is_empty() {
            let venue = ctx.venue.as_deref().ok_or(PolicyError::VenueNotAllowed)?;
            if !self.limits.allowed_venues.contains(venue) {
                return Err(PolicyError::VenueNotAllowed);
            }
        }
        Ok(ApprovedExecution {
            intent_id: intent.id.clone(),
            wallet_ref: intent.wallet_ref.clone(),
            chain: intent.chain.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            expires_at_ms: intent.expiry_ms,
            approved_trade_usd: ctx.trade_usd,
            approved_at_ms: ctx.now_ms,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("trading disabled")]
    TradingDisabled,
    #[error("invalid TRADING_ENABLED value")]
    InvalidTradingEnabled,
    #[error("invalid policy limits")]
    InvalidLimits,
    #[error("intent invalid")]
    IntentInvalid,
    #[error("chain not allowed")]
    ChainNotAllowed,
    #[error("trusted valuation must be positive")]
    InvalidValuation,
    #[error("USD intent amount does not match trusted valuation")]
    ValuationMismatch,
    #[error("USD intent amount is outside supported fixed-point range")]
    ValuationOutOfRange,
    #[error("trade size exceeds policy")]
    TradeSizeExceeded,
    #[error("hourly turnover exceeds policy")]
    HourlyTurnoverExceeded,
    #[error("daily turnover exceeds policy")]
    DailyTurnoverExceeded,
    #[error("turnover arithmetic overflow")]
    TurnoverOverflow,
    #[error("risk limits exceed policy")]
    RiskLimitExceeded,
    #[error("venue not allowed")]
    VenueNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::AssetId;
    use domain::{AmountType, OrderType, RiskConstraints, TradeSide, TradeSource, UserId};
    use market_types::AtomicAmount;

    fn limits() -> PolicyLimits {
        PolicyLimits {
            max_trade_usd: UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: UsdMicros::new(5_000_000),
            max_daily_turnover_usd: UsdMicros::new(20_000_000),
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            allowed_chains: [ChainId::Base].into_iter().collect(),
            allowed_venues: ["uniswap".to_string()].into_iter().collect(),
        }
    }
    fn intent(source: TradeSource) -> TradeIntent {
        let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
        let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
        TradeIntent {
            id: IntentId::new("intent-1").unwrap(),
            source,
            user_id: UserId::new("user-1").unwrap(),
            wallet_ref: WalletRef::new("wallet-1").unwrap(),
            chain: ChainId::Base,
            token_in,
            token_out,
            side: TradeSide::Buy,
            amount_type: AmountType::UsdMicros,
            amount: AtomicAmount::new(500_000),
            order_type: OrderType::Market,
            limit_price: None,
            risk: RiskConstraints {
                max_buy_tax: Bps::new(200).unwrap(),
                max_sell_tax: Bps::new(200).unwrap(),
                max_price_impact: Bps::new(100).unwrap(),
                max_slippage: Bps::new(100).unwrap(),
                max_total_cost: None,
            },
            allow_partial_fill: true,
            expiry_ms: Some(10_000),
            nonce: 1,
            idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
        }
    }
    fn ctx() -> PolicyContext {
        PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".into()),
        )
        .unwrap()
    }
    fn enabled_engine() -> PolicyEngine {
        PolicyEngine::new(
            TradingGate::from_trusted_startup(Some("true")).unwrap(),
            limits(),
        )
        .unwrap()
    }

    #[test]
    fn gate_defaults_disabled_and_parser_is_strict() {
        assert!(!TradingGate::default().is_enabled());
        assert!(!TradingGate::from_trusted_startup(None)
            .unwrap()
            .is_enabled());
        assert!(!TradingGate::from_trusted_startup(Some("false"))
            .unwrap()
            .is_enabled());
        assert!(TradingGate::from_trusted_startup(Some("true"))
            .unwrap()
            .is_enabled());
        assert!(matches!(
            TradingGate::from_trusted_startup(Some("TRUE")),
            Err(PolicyError::InvalidTradingEnabled)
        ));
    }

    #[test]
    fn disabled_blocks_all_control_plane_sources() {
        for source in [TradeSource::Web, TradeSource::Mcp, TradeSource::Telegram] {
            let engine = PolicyEngine::new(TradingGate::default(), limits()).unwrap();
            assert_eq!(
                engine.authorize_trade(&intent(source), &ctx()),
                Err(PolicyError::TradingDisabled)
            );
        }
    }

    #[test]
    fn disable_is_one_way_for_runtime_api() {
        let engine = enabled_engine();
        assert!(engine.is_trading_enabled());
        engine.disable_trading();
        assert!(!engine.is_trading_enabled());
        assert_eq!(
            engine.authorize_trade(&intent(TradeSource::Web), &ctx()),
            Err(PolicyError::TradingDisabled)
        );
    }

    #[test]
    fn valid_authorization_binds_identity_and_idempotency() {
        let engine = enabled_engine();
        let i = intent(TradeSource::Web);
        let approved = engine.authorize_trade(&i, &ctx()).unwrap();
        assert_eq!(approved.intent_id(), &i.id);
        assert_eq!(approved.wallet_ref(), &i.wallet_ref);
        assert_eq!(approved.chain(), &i.chain);
        assert_eq!(approved.idempotency_key(), &i.idempotency_key);
        assert_eq!(approved.expires_at_ms(), i.expiry_ms);
    }

    #[test]
    fn trade_turnover_chain_venue_and_risk_limits_fail_closed() {
        let engine = enabled_engine();
        let i = intent(TradeSource::Web);
        let mut oversized = i.clone();
        oversized.amount = AtomicAmount::new(1_000_001);
        let mut c = ctx();
        c.trade_usd = UsdMicros::new(1_000_001);
        assert_eq!(
            engine.authorize_trade(&oversized, &c),
            Err(PolicyError::TradeSizeExceeded)
        );
        let mut c = ctx();
        c.turnover = TurnoverSnapshot::from_trusted_backend_state(
            UsdMicros::new(4_600_000),
            UsdMicros::new(0),
        );
        assert_eq!(
            engine.authorize_trade(&i, &c),
            Err(PolicyError::HourlyTurnoverExceeded)
        );
        let mut c = ctx();
        c.turnover = TurnoverSnapshot::from_trusted_backend_state(
            UsdMicros::new(0),
            UsdMicros::new(19_600_000),
        );
        assert_eq!(
            engine.authorize_trade(&i, &c),
            Err(PolicyError::DailyTurnoverExceeded)
        );
        let mut c = ctx();
        c.venue = Some("unknown".into());
        assert_eq!(
            engine.authorize_trade(&i, &c),
            Err(PolicyError::VenueNotAllowed)
        );
        let mut wrong_chain = i.clone();
        wrong_chain.chain = ChainId::Ethereum;
        wrong_chain.token_in.chain = ChainId::Ethereum;
        wrong_chain.token_out.chain = ChainId::Ethereum;
        assert_eq!(
            engine.authorize_trade(&wrong_chain, &ctx()),
            Err(PolicyError::ChainNotAllowed)
        );
        let mut risky = i;
        risky.risk.max_buy_tax = Bps::new(501).unwrap();
        assert_eq!(
            engine.authorize_trade(&risky, &ctx()),
            Err(PolicyError::RiskLimitExceeded)
        );
    }

    #[test]
    fn usd_intent_must_match_trusted_valuation_exactly() {
        let engine = enabled_engine();
        let i = intent(TradeSource::Web);
        let mut c = ctx();
        c.trade_usd = UsdMicros::new(499_999);
        assert_eq!(
            engine.authorize_trade(&i, &c),
            Err(PolicyError::ValuationMismatch)
        );
    }

    #[test]
    fn zero_and_out_of_range_usd_valuation_fail_closed() {
        assert_eq!(
            PolicyContext::from_trusted_backend_state(
                1,
                UsdMicros::new(0),
                TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
                None,
            ),
            Err(PolicyError::InvalidValuation)
        );
        let engine = enabled_engine();
        let mut i = intent(TradeSource::Web);
        i.amount = AtomicAmount::new(u128::from(u64::MAX) + 1);
        let mut c = ctx();
        c.trade_usd = UsdMicros::new(u64::MAX);
        assert_eq!(
            engine.authorize_trade(&i, &c),
            Err(PolicyError::ValuationOutOfRange)
        );
    }

    #[test]
    fn token_amount_uses_explicit_trusted_backend_valuation() {
        let engine = enabled_engine();
        let mut i = intent(TradeSource::Web);
        i.amount_type = AmountType::InputAssetAtomic;
        i.amount = AtomicAmount::new(123_456_789);
        let approved = engine.authorize_trade(&i, &ctx()).unwrap();
        assert_eq!(approved.approved_trade_usd(), UsdMicros::new(500_000));
    }
}
