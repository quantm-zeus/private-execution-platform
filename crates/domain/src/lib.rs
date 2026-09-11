//! Canonical intent/order/routing domain shared by every control plane.

use chain_types::{AssetId, ChainId};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, PriceRatio, Sequence};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod execution_preview;

pub use execution_preview::{
    cmp_u128_products, mul_u128_wide, validate_execution_preview, ExecutionCostComponents,
    ExecutionPreview, ValidatedExecutionPreview,
};

macro_rules! string_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(DomainError::EmptyIdentifier($kind));
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn validate(&self) -> Result<(), DomainError> {
                if self.0.trim().is_empty() {
                    return Err(DomainError::EmptyIdentifier($kind));
                }
                Ok(())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(<D::Error as serde::de::Error>::custom)
            }
        }
    };
}

string_id!(IntentId, "intent_id");
string_id!(OrderId, "order_id");
string_id!(ExecutionId, "execution_id");
string_id!(IdempotencyKey, "idempotency_key");
string_id!(UserId, "user_id");
string_id!(WalletRef, "wallet_ref");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeSource {
    Web,
    Mcp,
    Telegram,
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeSide {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderType {
    Market,
    Limit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountType {
    InputAssetAtomic,
    OutputAssetAtomic,
    UsdMicros,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitPrice {
    pub numerator_asset: AssetId,
    pub denominator_asset: AssetId,
    pub ratio: PriceRatio,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskConstraints {
    pub max_buy_tax: Bps,
    pub max_sell_tax: Bps,
    pub max_price_impact: Bps,
    pub max_slippage: Bps,
    pub max_total_cost: Option<AssetAmount>,
}

impl RiskConstraints {
    /// Validates that max_total_cost, when present, is non-zero and explicitly
    /// denominated in token_in. Other risk fields are bounded by Bps construction.
    pub fn validate(&self, token_in: &AssetId) -> Result<(), DomainError> {
        if let Some(total) = &self.max_total_cost {
            total
                .validate_nonzero()
                .map_err(|_| DomainError::InvalidMaxTotalCost)?;
            if total.asset != *token_in {
                return Err(DomainError::MaxTotalCostAssetMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeIntent {
    pub id: IntentId,
    pub source: TradeSource,
    pub user_id: UserId,
    pub wallet_ref: WalletRef,
    pub chain: ChainId,
    pub token_in: AssetId,
    pub token_out: AssetId,
    pub side: TradeSide,
    pub amount_type: AmountType,
    pub amount: AtomicAmount,
    pub order_type: OrderType,
    pub limit_price: Option<LimitPrice>,
    pub risk: RiskConstraints,
    pub allow_partial_fill: bool,
    pub expiry_ms: Option<i64>,
    pub nonce: u64,
    pub idempotency_key: IdempotencyKey,
}

impl TradeIntent {
    pub fn validate(&self, now_ms: i64) -> Result<(), DomainError> {
        self.id.validate()?;
        self.user_id.validate()?;
        self.wallet_ref.validate()?;
        self.idempotency_key.validate()?;
        self.chain
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_in
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_out
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        if self.amount.is_zero() {
            return Err(DomainError::ZeroTradeAmount);
        }
        if self.token_in == self.token_out {
            return Err(DomainError::SameAssetPair);
        }
        if self.token_in.chain != self.chain || self.token_out.chain != self.chain {
            return Err(DomainError::ChainMismatch);
        }
        match (self.order_type, &self.limit_price) {
            (OrderType::Market, None) | (OrderType::Limit, Some(_)) => {}
            (OrderType::Market, Some(_)) => return Err(DomainError::UnexpectedLimitPrice),
            (OrderType::Limit, None) => return Err(DomainError::MissingLimitPrice),
        }
        if let Some(price) = &self.limit_price {
            let expected = match self.side {
                TradeSide::Buy => (&self.token_in, &self.token_out),
                TradeSide::Sell => (&self.token_out, &self.token_in),
            };
            if &price.numerator_asset != expected.0 || &price.denominator_asset != expected.1 {
                return Err(DomainError::LimitPriceAssetMismatch);
            }
        }
        if matches!(self.expiry_ms, Some(expiry) if expiry <= now_ms) {
            return Err(DomainError::Expired);
        }
        self.risk.validate(&self.token_in)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Created,
    Active,
    TriggerCandidate,
    Quoting,
    Simulating,
    Executing,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    FailedRetryable,
    FailedFinal,
}

impl OrderStatus {
    pub const fn can_transition_to(self, next: Self) -> bool {
        use OrderStatus::*;
        matches!(
            (self, next),
            (Created, Active)
                | (Created, Cancelled)
                | (Created, Expired)
                | (Active, TriggerCandidate)
                | (Active, Cancelled)
                | (Active, Expired)
                | (TriggerCandidate, Active)
                | (TriggerCandidate, Quoting)
                | (TriggerCandidate, Cancelled)
                | (TriggerCandidate, Expired)
                | (Quoting, Simulating)
                | (Quoting, Active)
                | (Quoting, FailedRetryable)
                | (Quoting, Cancelled)
                | (Quoting, Expired)
                | (Simulating, Executing)
                | (Simulating, Active)
                | (Simulating, FailedRetryable)
                | (Simulating, Cancelled)
                | (Simulating, Expired)
                | (Executing, PartiallyFilled)
                | (Executing, Filled)
                | (Executing, FailedRetryable)
                | (Executing, FailedFinal)
                | (Executing, Expired)
                | (PartiallyFilled, Active)
                | (PartiallyFilled, TriggerCandidate)
                | (PartiallyFilled, Executing)
                | (PartiallyFilled, Filled)
                | (PartiallyFilled, Cancelled)
                | (PartiallyFilled, Expired)
                | (FailedRetryable, Active)
                | (FailedRetryable, TriggerCandidate)
                | (FailedRetryable, FailedFinal)
                | (FailedRetryable, Cancelled)
                | (FailedRetryable, Expired)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitOrder {
    pub id: OrderId,
    pub owner: UserId,
    pub wallet_ref: WalletRef,
    pub chain: ChainId,
    pub token_in: AssetId,
    pub token_out: AssetId,
    pub side: TradeSide,
    pub max_input: AssetAmount,
    pub remaining_input: AtomicAmount,
    pub limit_price: LimitPrice,
    pub risk: RiskConstraints,
    pub allow_partial_fill: bool,
    pub min_fill: AtomicAmount,
    pub expires_at_ms: i64,
    pub status: OrderStatus,
}

impl LimitOrder {
    pub fn validate(&self, now_ms: i64) -> Result<(), DomainError> {
        self.id.validate()?;
        self.owner.validate()?;
        self.wallet_ref.validate()?;
        self.chain
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_in
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_out
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        if self.token_in.chain != self.chain || self.token_out.chain != self.chain {
            return Err(DomainError::ChainMismatch);
        }
        if self.token_in == self.token_out {
            return Err(DomainError::SameAssetPair);
        }
        self.max_input
            .validate_nonzero()
            .map_err(|_| DomainError::ZeroTradeAmount)?;
        if self.max_input.asset != self.token_in {
            return Err(DomainError::InputAssetMismatch);
        }
        // remaining_input must never exceed max_input, in any state.
        if self.remaining_input > self.max_input.amount {
            return Err(DomainError::InvalidRemainingInput);
        }
        // States that can still execute or retry must retain spendable input and a
        // viable min_fill. Historical terminal states (Cancelled, Expired, FailedFinal)
        // are exempt; Filled must have consumed all input.
        let executable = matches!(
            self.status,
            OrderStatus::Created
                | OrderStatus::Active
                | OrderStatus::TriggerCandidate
                | OrderStatus::Quoting
                | OrderStatus::Simulating
                | OrderStatus::Executing
                | OrderStatus::PartiallyFilled
                | OrderStatus::FailedRetryable
        );
        let filled = self.status == OrderStatus::Filled;
        if filled && !self.remaining_input.is_zero() {
            return Err(DomainError::InvalidRemainingInput);
        }
        if executable {
            if self.remaining_input.is_zero() {
                return Err(DomainError::InvalidRemainingInput);
            }
            if self.min_fill.is_zero() || self.min_fill > self.remaining_input {
                return Err(DomainError::InvalidMinFill);
            }
            // An all-or-nothing order must remain fillable only in full. For
            // historical terminal states min_fill records prior configuration,
            // and Filled has no remaining input, so neither needs equality.
            if !self.allow_partial_fill && self.min_fill != self.remaining_input {
                return Err(DomainError::NonPartialFillMismatch);
            }
        }
        // Open states must live within the order window. Executing is an in-flight
        // attempt: it may legitimately remain valid after expires_at_ms crosses once
        // the attempt has been signed/submitted. An Expired status must not validate
        // before its own expiry timestamp.
        let expiry_gated = matches!(
            self.status,
            OrderStatus::Created
                | OrderStatus::Active
                | OrderStatus::TriggerCandidate
                | OrderStatus::Quoting
                | OrderStatus::Simulating
                | OrderStatus::PartiallyFilled
                | OrderStatus::FailedRetryable
        );
        if expiry_gated && self.expires_at_ms <= now_ms {
            return Err(DomainError::Expired);
        }
        if self.status == OrderStatus::Expired && self.expires_at_ms > now_ms {
            return Err(DomainError::ExpiredStatusBeforeWindow);
        }
        let expected = match self.side {
            TradeSide::Buy => (&self.token_in, &self.token_out),
            TradeSide::Sell => (&self.token_out, &self.token_in),
        };
        if &self.limit_price.numerator_asset != expected.0
            || &self.limit_price.denominator_asset != expected.1
        {
            return Err(DomainError::LimitPriceAssetMismatch);
        }
        self.risk.validate(&self.token_in)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteLeg {
    pub venue: String,
    pub pool_ref: String,
    pub token_in: AssetId,
    pub token_out: AssetId,
    pub amount_in: AtomicAmount,
    pub expected_amount_out: AtomicAmount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePlan {
    pub legs: Vec<RouteLeg>,
    pub expected_net_output: AssetAmount,
    pub state: Freshness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteScore {
    pub gross_output: AssetAmount,
    pub simulated_net_output: AssetAmount,
    pub tax_cost: Option<AssetAmount>,
    pub dex_fee: Option<AssetAmount>,
    pub provider_fee: Option<AssetAmount>,
    pub gas_cost: Option<AssetAmount>,
    pub price_impact: Bps,
    pub expected_slippage: Bps,
    pub mev_risk: Bps,
    pub failure_probability: Bps,
    pub state_age_ms: u64,
    pub provider_reliability: Bps,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxObservation {
    pub chain: ChainId,
    pub token: AssetId,
    pub pool_ref: String,
    pub router_ref: String,
    pub wallet_ref: WalletRef,
    pub amount: AtomicAmount,
    pub block_or_slot: u64,
    pub buy_tax: Bps,
    pub sell_tax: Bps,
    pub buy_succeeds: bool,
    pub sell_succeeds: bool,
    pub sellable: bool,
    pub confidence: Bps,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSnapshotMeta {
    pub provider: String,
    pub computed_at_ms: i64,
    pub expires_at_ms: i64,
    pub source_sequence: Option<Sequence>,
}

impl RouteLeg {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.venue.trim().is_empty() || self.pool_ref.trim().is_empty() {
            return Err(DomainError::EmptyRouteRef);
        }
        self.token_in
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        self.token_out
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        if self.token_in == self.token_out {
            return Err(DomainError::SameAssetPair);
        }
        if self.amount_in.is_zero() || self.expected_amount_out.is_zero() {
            return Err(DomainError::ZeroTradeAmount);
        }
        Ok(())
    }
}

impl RoutePlan {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.legs.is_empty() {
            return Err(DomainError::EmptyRoute);
        }
        for leg in &self.legs {
            leg.validate()?;
        }
        // Contiguous token flow: each leg's token_out feeds the next leg's token_in.
        for window in self.legs.windows(2) {
            if window[0].token_out != window[1].token_in {
                return Err(DomainError::RouteTokenMismatch);
            }
        }
        let last = self.legs.last().unwrap();
        if self.expected_net_output.asset != last.token_out {
            return Err(DomainError::RouteOutputAssetMismatch);
        }
        self.expected_net_output
            .validate_nonzero()
            .map_err(|_| DomainError::ZeroTradeAmount)?;
        Ok(())
    }
}

impl TaxObservation {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.token
            .validate()
            .map_err(|_| DomainError::ChainMismatch)?;
        if self.token.chain != self.chain {
            return Err(DomainError::ChainMismatch);
        }
        if self.pool_ref.trim().is_empty() || self.router_ref.trim().is_empty() {
            return Err(DomainError::EmptyRouteRef);
        }
        self.wallet_ref.validate()?;
        if self.amount.is_zero() {
            return Err(DomainError::ZeroTradeAmount);
        }
        if self.observed_at_ms >= self.expires_at_ms {
            return Err(DomainError::InvalidObservationWindow);
        }
        // Sellability and observed success must be coherent.
        if !self.sellable && self.sell_succeeds {
            return Err(DomainError::IncoherentSellability);
        }
        Ok(())
    }
}

impl ProviderSnapshotMeta {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.provider.trim().is_empty() {
            return Err(DomainError::EmptyProvider);
        }
        if self.computed_at_ms >= self.expires_at_ms {
            return Err(DomainError::InvalidObservationWindow);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]

pub enum DomainError {
    #[error("{0} must not be empty")]
    EmptyIdentifier(&'static str),
    #[error("trade amount must be greater than zero")]
    ZeroTradeAmount,
    #[error("token_in and token_out must differ")]
    SameAssetPair,
    #[error("asset chain does not match intent/order chain")]
    ChainMismatch,
    #[error("market order must not carry a limit price")]
    UnexpectedLimitPrice,
    #[error("limit order requires a limit price")]
    MissingLimitPrice,
    #[error("limit price assets do not match side semantics")]
    LimitPriceAssetMismatch,
    #[error("intent/order is expired")]
    Expired,
    #[error("expired status cannot precede its own expiry timestamp")]
    ExpiredStatusBeforeWindow,
    #[error("max total cost must be non-zero when provided")]
    InvalidMaxTotalCost,
    #[error("max input asset must equal token_in")]
    InputAssetMismatch,
    #[error("remaining input must be non-zero and not exceed max input")]
    InvalidRemainingInput,
    #[error("minimum fill must be non-zero and not exceed remaining input")]
    InvalidMinFill,
    #[error("all-or-nothing order requires min_fill to equal remaining input")]
    NonPartialFillMismatch,
    #[error("max total cost asset must equal token_in")]
    MaxTotalCostAssetMismatch,
    #[error("route must contain at least one leg")]
    EmptyRoute,
    #[error("route venue or pool reference must not be empty")]
    EmptyRouteRef,
    #[error("route leg token flow is not contiguous")]
    RouteTokenMismatch,
    #[error("route expected_net_output asset must equal final leg token_out")]
    RouteOutputAssetMismatch,
    #[error("observation time window is invalid")]
    InvalidObservationWindow,
    #[error("non-sellable observation cannot have successful sell")]
    IncoherentSellability,
    #[error("provider identifier must not be empty")]
    EmptyProvider,
    #[error("intent id does not match preview intent id")]
    IntentIdMismatch,
    #[error("output asset does not match expected output asset")]
    OutputAssetMismatch,
    #[error("trade side does not match expected trade side")]
    TradeSideMismatch,
    #[error("simulated net balance delta must be greater than zero")]
    ZeroSimulatedDelta,
    #[error("simulated cost component must be greater than zero")]
    ZeroCostComponent,
    #[error("simulated net economics are internally inconsistent: {0}")]
    InconsistentNetEconomics(&'static str),
    #[error("local market state is stale")]
    StaleMarketState,
    #[error("local market state requires resync")]
    ResyncRequired,
    #[error("simulated net price violates limit price constraint")]
    LimitPriceViolated,
    #[error(
        "route output and side semantics cannot support an executable net price decision: {0}"
    )]
    InvalidNetPriceDecision(&'static str),
    #[error("unsupported amount type")]
    UnsupportedAmountType,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(address: &str) -> AssetId {
        AssetId::new(ChainId::Base, address).unwrap()
    }
    fn risk() -> RiskConstraints {
        RiskConstraints {
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            max_total_cost: None,
        }
    }
    fn price(side: TradeSide, token_in: &AssetId, token_out: &AssetId) -> LimitPrice {
        let (num, den) = match side {
            TradeSide::Buy => (token_in.clone(), token_out.clone()),
            TradeSide::Sell => (token_out.clone(), token_in.clone()),
        };
        LimitPrice {
            numerator_asset: num,
            denominator_asset: den,
            ratio: PriceRatio::new(100, 25).unwrap(),
        }
    }
    fn intent(order_type: OrderType) -> TradeIntent {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        TradeIntent {
            id: IntentId::new("i1").unwrap(),
            source: TradeSource::Web,
            user_id: UserId::new("u1").unwrap(),
            wallet_ref: WalletRef::new("w1").unwrap(),
            chain: ChainId::Base,
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: TradeSide::Buy,
            amount_type: AmountType::InputAssetAtomic,
            amount: AtomicAmount::new(1_000),
            order_type,
            limit_price: if order_type == OrderType::Limit {
                Some(price(TradeSide::Buy, &token_in, &token_out))
            } else {
                None
            },
            risk: risk(),
            allow_partial_fill: true,
            expiry_ms: Some(2_000),
            nonce: 7,
            idempotency_key: IdempotencyKey::new("k1").unwrap(),
        }
    }

    fn limit_order(token_in: &AssetId, token_out: &AssetId) -> LimitOrder {
        LimitOrder {
            id: OrderId::new("o1").unwrap(),
            owner: UserId::new("u1").unwrap(),
            wallet_ref: WalletRef::new("w1").unwrap(),
            chain: ChainId::Base,
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: TradeSide::Buy,
            max_input: AssetAmount {
                asset: token_in.clone(),
                amount: AtomicAmount::new(1_000),
            },
            remaining_input: AtomicAmount::new(1_000),
            limit_price: price(TradeSide::Buy, token_in, token_out),
            risk: risk(),
            allow_partial_fill: true,
            min_fill: AtomicAmount::new(1),
            expires_at_ms: 2_000,
            status: OrderStatus::Active,
        }
    }

    fn route_plan(legs: &[(&AssetId, &AssetId, u128, u128)], output_asset: &AssetId) -> RoutePlan {
        RoutePlan {
            legs: legs
                .iter()
                .map(|(tin, tout, ain, aout)| RouteLeg {
                    venue: "uniswap".to_string(),
                    pool_ref: "pool-1".to_string(),
                    token_in: (*tin).clone(),
                    token_out: (*tout).clone(),
                    amount_in: AtomicAmount::new(*ain),
                    expected_amount_out: AtomicAmount::new(*aout),
                })
                .collect(),
            expected_net_output: AssetAmount {
                asset: output_asset.clone(),
                amount: AtomicAmount::new(250),
            },
            state: Freshness {
                observed_at_ms: 0,
                chain_height: 1,
                sequence: Sequence(1),
            },
        }
    }

    fn tax_observation() -> TaxObservation {
        TaxObservation {
            chain: ChainId::Base,
            token: asset("TOKEN"),
            pool_ref: "pool-1".to_string(),
            router_ref: "router-1".to_string(),
            wallet_ref: WalletRef::new("w1").unwrap(),
            amount: AtomicAmount::new(1_000),
            block_or_slot: 42,
            buy_tax: Bps::new(100).unwrap(),
            sell_tax: Bps::new(100).unwrap(),
            buy_succeeds: true,
            sell_succeeds: true,
            sellable: true,
            confidence: Bps::new(9_000).unwrap(),
            observed_at_ms: 1_000,
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn canonical_intent_round_trips_deterministically() {
        let value = intent(OrderType::Limit);
        value.validate(1_000).unwrap();
        let first = serde_json::to_string(&value).unwrap();
        let decoded: TradeIntent = serde_json::from_str(&first).unwrap();
        let second = serde_json::to_string(&decoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(first, second);
    }

    #[test]
    fn market_and_limit_shape_is_enforced() {
        let mut market = intent(OrderType::Market);
        market.limit_price = Some(price(TradeSide::Buy, &market.token_in, &market.token_out));
        assert_eq!(
            market.validate(1_000),
            Err(DomainError::UnexpectedLimitPrice)
        );
        let mut limit = intent(OrderType::Limit);
        limit.limit_price = None;
        assert_eq!(limit.validate(1_000), Err(DomainError::MissingLimitPrice));
    }

    #[test]
    fn expired_and_zero_intents_are_rejected() {
        let mut value = intent(OrderType::Market);
        value.amount = AtomicAmount::ZERO;
        assert_eq!(value.validate(1_000), Err(DomainError::ZeroTradeAmount));
        let mut value = intent(OrderType::Market);
        value.expiry_ms = Some(1_000);
        assert_eq!(value.validate(1_000), Err(DomainError::Expired));
    }

    #[test]
    fn order_state_machine_rejects_illegal_jumps() {
        assert!(OrderStatus::Created.can_transition_to(OrderStatus::Active));
        assert!(OrderStatus::Executing.can_transition_to(OrderStatus::PartiallyFilled));
        assert!(!OrderStatus::Created.can_transition_to(OrderStatus::Filled));
        assert!(!OrderStatus::Filled.can_transition_to(OrderStatus::Active));
    }

    #[test]
    fn id_types_reject_empty_values() {
        assert_eq!(
            IntentId::new(" "),
            Err(DomainError::EmptyIdentifier("intent_id"))
        );
        assert_eq!(
            IdempotencyKey::new(""),
            Err(DomainError::EmptyIdentifier("idempotency_key"))
        );
    }

    #[test]
    fn serde_rejects_blank_ids() {
        let err = serde_json::from_str::<IntentId>("\"\"").unwrap_err();
        assert_eq!(err.to_string(), "intent_id must not be empty");
        let err = serde_json::from_str::<ExecutionId>("\"  \"").unwrap_err();
        assert_eq!(err.to_string(), "execution_id must not be empty");
        let err = serde_json::from_str::<IdempotencyKey>("\" \\t\\n \"").unwrap_err();
        assert_eq!(err.to_string(), "idempotency_key must not be empty");
        let err = serde_json::from_str::<OrderId>("\"\"").unwrap_err();
        assert_eq!(err.to_string(), "order_id must not be empty");
        let err = serde_json::from_str::<UserId>("\"\"").unwrap_err();
        assert_eq!(err.to_string(), "user_id must not be empty");
        let err = serde_json::from_str::<WalletRef>("\"\"").unwrap_err();
        assert_eq!(err.to_string(), "wallet_ref must not be empty");
    }

    #[test]
    fn id_serde_round_trips() {
        let id = IntentId::new("intent-1").unwrap();
        let encoded = serde_json::to_string(&id).unwrap();
        assert_eq!(encoded, "\"intent-1\"");
        let decoded: IntentId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, id);

        let key = IdempotencyKey::new("key-42").unwrap();
        let encoded = serde_json::to_string(&key).unwrap();
        let decoded: IdempotencyKey = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, key);

        let exec = ExecutionId::new("exec-7").unwrap();
        let decoded: ExecutionId =
            serde_json::from_str(&serde_json::to_string(&exec).unwrap()).unwrap();
        assert_eq!(decoded, exec);
    }
    #[test]
    fn filled_order_must_have_zero_remaining() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut order = limit_order(&token_in, &token_out);
        order.status = OrderStatus::Filled;
        order.remaining_input = AtomicAmount::ZERO;
        assert!(order.validate(1_000).is_ok());

        order.remaining_input = AtomicAmount::new(50);
        assert_eq!(
            order.validate(1_000),
            Err(DomainError::InvalidRemainingInput)
        );
    }

    #[test]
    fn executable_order_must_have_positive_remaining() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut order = limit_order(&token_in, &token_out);
        order.status = OrderStatus::Active;
        order.remaining_input = AtomicAmount::ZERO;
        assert_eq!(
            order.validate(1_000),
            Err(DomainError::InvalidRemainingInput)
        );
        order.remaining_input = AtomicAmount::new(100);
        assert!(order.validate(1_000).is_ok());
    }

    #[test]
    fn min_fill_is_unconstrained_when_fully_filled() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut order = limit_order(&token_in, &token_out);
        order.status = OrderStatus::Filled;
        order.remaining_input = AtomicAmount::ZERO;
        order.min_fill = AtomicAmount::ZERO;
        assert!(order.validate(1_000).is_ok());
    }

    #[test]
    fn all_or_nothing_active_requires_full_remaining_min_fill() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut order = limit_order(&token_in, &token_out);
        order.allow_partial_fill = false;
        order.min_fill = AtomicAmount::new(999);
        assert_eq!(
            order.validate(1_000),
            Err(DomainError::NonPartialFillMismatch)
        );
        order.min_fill = AtomicAmount::new(1_000);
        assert!(order.validate(1_000).is_ok());
    }

    #[test]
    fn all_or_nothing_retry_and_executing_require_full_remaining_min_fill() {
        for status in [OrderStatus::FailedRetryable, OrderStatus::Executing] {
            let mut order = limit_order(&asset("USDC"), &asset("TOKEN"));
            order.status = status;
            order.allow_partial_fill = false;
            order.min_fill = AtomicAmount::new(999);
            assert_eq!(
                order.validate(1_000),
                Err(DomainError::NonPartialFillMismatch),
                "status {status:?}"
            );
            order.min_fill = AtomicAmount::new(1_000);
            assert!(order.validate(1_000).is_ok(), "status {status:?}");
        }
    }

    #[test]
    fn partial_orders_may_have_smaller_min_fill() {
        let mut order = limit_order(&asset("USDC"), &asset("TOKEN"));
        order.allow_partial_fill = true;
        order.min_fill = AtomicAmount::new(1);
        assert!(order.validate(1_000).is_ok());
    }

    #[test]
    fn historical_orders_need_not_match_all_or_nothing_configuration() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        for status in [OrderStatus::Filled, OrderStatus::Cancelled] {
            let mut order = limit_order(&token_in, &token_out);
            order.status = status;
            order.allow_partial_fill = false;
            order.min_fill = AtomicAmount::new(1);
            if status == OrderStatus::Filled {
                order.remaining_input = AtomicAmount::ZERO;
                order.min_fill = AtomicAmount::ZERO;
            }
            assert!(order.validate(1_000).is_ok(), "status {status:?}");
        }
    }

    #[test]
    fn limit_order_serde_round_trips_fill_policy() {
        let mut order = limit_order(&asset("USDC"), &asset("TOKEN"));
        order.allow_partial_fill = false;
        order.min_fill = AtomicAmount::new(1_000);
        order.validate(1_000).unwrap();
        let encoded = serde_json::to_string(&order).unwrap();
        let decoded: LimitOrder = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, order);
        assert!(decoded.validate(1_000).is_ok());
    }

    #[test]
    fn max_total_cost_rejects_zero_and_wrong_asset() {
        let mut value = intent(OrderType::Market);
        value.risk.max_total_cost = Some(AssetAmount {
            asset: value.token_in.clone(),
            amount: AtomicAmount::ZERO,
        });
        assert_eq!(value.validate(1_000), Err(DomainError::InvalidMaxTotalCost));
        value.risk.max_total_cost = Some(AssetAmount {
            asset: value.token_out.clone(),
            amount: AtomicAmount::new(100),
        });
        assert_eq!(
            value.validate(1_000),
            Err(DomainError::MaxTotalCostAssetMismatch)
        );
    }

    #[test]
    fn limit_price_side_orientation_is_enforced() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");

        let mut buy = intent(OrderType::Limit);
        buy.side = TradeSide::Buy;
        buy.limit_price = Some(price(TradeSide::Sell, &token_in, &token_out));
        assert_eq!(
            buy.validate(1_000),
            Err(DomainError::LimitPriceAssetMismatch)
        );

        let mut sell = intent(OrderType::Limit);
        sell.side = TradeSide::Sell;
        sell.limit_price = Some(price(TradeSide::Buy, &token_in, &token_out));
        assert_eq!(
            sell.validate(1_000),
            Err(DomainError::LimitPriceAssetMismatch)
        );

        let mut sell_ok = intent(OrderType::Limit);
        sell_ok.side = TradeSide::Sell;
        sell_ok.limit_price = Some(price(TradeSide::Sell, &token_in, &token_out));
        assert!(sell_ok.validate(1_000).is_ok());
    }

    #[test]
    fn valid_route_plan_passes_validation() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let c = asset("ETH");
        let plan = route_plan(&[(&a, &b, 1_000, 500), (&b, &c, 500, 250)], &c);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn empty_route_plan_is_rejected() {
        let c = asset("ETH");
        let plan = route_plan(&[], &c);
        assert_eq!(plan.validate(), Err(DomainError::EmptyRoute));
    }

    #[test]
    fn route_plan_blank_venue_or_pool_is_rejected() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let mut plan = route_plan(&[(&a, &b, 1_000, 500)], &b);
        plan.legs[0].venue = "  ".to_string();
        assert_eq!(plan.validate(), Err(DomainError::EmptyRouteRef));
        plan.legs[0].venue = "uniswap".to_string();
        plan.legs[0].pool_ref = String::new();
        assert_eq!(plan.validate(), Err(DomainError::EmptyRouteRef));
    }

    #[test]
    fn route_plan_zero_leg_amount_is_rejected() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let mut plan = route_plan(&[(&a, &b, 0, 500)], &b);
        assert_eq!(plan.validate(), Err(DomainError::ZeroTradeAmount));
        plan.legs[0].amount_in = AtomicAmount::new(1_000);
        plan.legs[0].expected_amount_out = AtomicAmount::ZERO;
        assert_eq!(plan.validate(), Err(DomainError::ZeroTradeAmount));
    }

    #[test]
    fn route_plan_non_contiguous_flow_is_rejected() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let c = asset("ETH");
        let d = asset("WBTC");
        let plan = route_plan(&[(&a, &b, 1_000, 500), (&c, &d, 500, 250)], &d);
        assert_eq!(plan.validate(), Err(DomainError::RouteTokenMismatch));
    }

    #[test]
    fn route_plan_output_asset_mismatch_is_rejected() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let c = asset("ETH");
        let plan = route_plan(&[(&a, &b, 1_000, 500), (&b, &c, 500, 250)], &b);
        assert_eq!(plan.validate(), Err(DomainError::RouteOutputAssetMismatch));
    }

    #[test]
    fn route_plan_zero_net_output_is_rejected() {
        let a = asset("USDC");
        let b = asset("TOKEN");
        let mut plan = route_plan(&[(&a, &b, 1_000, 500)], &b);
        plan.expected_net_output.amount = AtomicAmount::ZERO;
        assert_eq!(plan.validate(), Err(DomainError::ZeroTradeAmount));
    }

    #[test]
    fn valid_tax_observation_passes() {
        let obs = tax_observation();
        assert!(obs.validate().is_ok());
    }

    #[test]
    fn tax_observation_chain_mismatch_is_rejected() {
        let mut obs = tax_observation();
        obs.token = AssetId::new(ChainId::Solana, "tok").unwrap();
        assert_eq!(obs.validate(), Err(DomainError::ChainMismatch));
    }

    #[test]
    fn tax_observation_blank_refs_are_rejected() {
        let mut obs = tax_observation();
        obs.pool_ref = String::new();
        assert_eq!(obs.validate(), Err(DomainError::EmptyRouteRef));
        obs.pool_ref = "pool-1".to_string();
        obs.router_ref = " ".to_string();
        assert_eq!(obs.validate(), Err(DomainError::EmptyRouteRef));
    }

    #[test]
    fn tax_observation_invalid_wallet_is_rejected() {
        let mut obs = tax_observation();
        // Tests are a child module, so the private tuple field is visible here.
        // Construct an invalid WalletRef directly to prove validate() rejects it
        // even when encapsulated construction was bypassed.
        obs.wallet_ref = WalletRef(" ".to_string());
        assert_eq!(
            obs.validate(),
            Err(DomainError::EmptyIdentifier("wallet_ref"))
        );
    }

    #[test]
    fn tax_observation_zero_amount_is_rejected() {
        let mut obs = tax_observation();
        obs.amount = AtomicAmount::ZERO;
        assert_eq!(obs.validate(), Err(DomainError::ZeroTradeAmount));
    }

    #[test]
    fn tax_observation_bad_window_is_rejected() {
        let mut obs = tax_observation();
        obs.expires_at_ms = obs.observed_at_ms;
        assert_eq!(obs.validate(), Err(DomainError::InvalidObservationWindow));
    }

    #[test]
    fn tax_observation_sell_coherence_is_enforced() {
        let mut obs = tax_observation();
        obs.sellable = false;
        obs.sell_succeeds = true;
        assert_eq!(obs.validate(), Err(DomainError::IncoherentSellability));
        obs.sell_succeeds = false;
        assert!(obs.validate().is_ok());
    }

    #[test]
    fn provider_snapshot_meta_validates() {
        let meta = ProviderSnapshotMeta {
            provider: "gmgn".to_string(),
            computed_at_ms: 1_000,
            expires_at_ms: 2_000,
            source_sequence: Some(Sequence(7)),
        };
        assert!(meta.validate().is_ok());
        let mut bad = meta.clone();
        bad.provider = " ".to_string();
        assert_eq!(bad.validate(), Err(DomainError::EmptyProvider));
        bad.provider = "gmgn".to_string();
        bad.computed_at_ms = 2_000;
        assert_eq!(bad.validate(), Err(DomainError::InvalidObservationWindow));
    }

    #[test]
    fn terminal_states_are_representable_with_zero_or_small_remaining() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        for status in [
            OrderStatus::Cancelled,
            OrderStatus::Expired,
            OrderStatus::FailedFinal,
        ] {
            let mut order = limit_order(&token_in, &token_out);
            order.status = status;
            order.remaining_input = AtomicAmount::ZERO;
            order.min_fill = AtomicAmount::ZERO;
            if status == OrderStatus::Expired {
                assert_eq!(
                    order.validate(1_000),
                    Err(DomainError::ExpiredStatusBeforeWindow)
                );
            } else {
                assert!(order.validate(1_000).is_ok(), "status {status:?}");
            }
            order.remaining_input = AtomicAmount::new(10);
            order.min_fill = AtomicAmount::new(100);
            if status == OrderStatus::Expired {
                assert_eq!(
                    order.validate(1_000),
                    Err(DomainError::ExpiredStatusBeforeWindow)
                );
            } else {
                assert!(order.validate(1_000).is_ok(), "status {status:?}");
            }
            order.remaining_input = AtomicAmount::new(2_000);
            assert_eq!(
                order.validate(1_000),
                Err(DomainError::InvalidRemainingInput)
            );
        }
    }

    #[test]
    fn executable_states_require_positive_remaining_and_viable_min_fill() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        for status in [
            OrderStatus::Created,
            OrderStatus::Active,
            OrderStatus::TriggerCandidate,
            OrderStatus::Quoting,
            OrderStatus::Simulating,
            OrderStatus::Executing,
            OrderStatus::PartiallyFilled,
            OrderStatus::FailedRetryable,
        ] {
            let mut order = limit_order(&token_in, &token_out);
            order.status = status;
            order.min_fill = AtomicAmount::new(100);
            order.remaining_input = AtomicAmount::ZERO;
            assert_eq!(
                order.validate(1_000),
                Err(DomainError::InvalidRemainingInput),
                "status {status:?}"
            );
            order.remaining_input = AtomicAmount::new(50);
            assert_eq!(
                order.validate(1_000),
                Err(DomainError::InvalidMinFill),
                "status {status:?}"
            );
            order.remaining_input = AtomicAmount::new(100);
            assert!(order.validate(1_000).is_ok(), "status {status:?}");
        }
    }

    #[test]
    fn open_states_must_not_validate_after_expiry() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        for status in [
            OrderStatus::Created,
            OrderStatus::Active,
            OrderStatus::TriggerCandidate,
            OrderStatus::Quoting,
            OrderStatus::Simulating,
            OrderStatus::PartiallyFilled,
            OrderStatus::FailedRetryable,
        ] {
            let mut order = limit_order(&token_in, &token_out);
            order.status = status;
            assert_eq!(order.validate(2_000), Err(DomainError::Expired));
        }
    }

    #[test]
    fn executing_may_validate_after_expiry_but_gated_states_cannot() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut executing = limit_order(&token_in, &token_out);
        executing.status = OrderStatus::Executing;
        assert!(executing.validate(2_000).is_ok());
        assert!(executing.validate(2_500).is_ok());

        for status in [OrderStatus::Active, OrderStatus::FailedRetryable] {
            let mut order = limit_order(&token_in, &token_out);
            order.status = status;
            assert_eq!(order.validate(2_000), Err(DomainError::Expired));
        }
    }

    #[test]
    fn expired_status_must_not_validate_before_expiry() {
        let token_in = asset("USDC");
        let token_out = asset("TOKEN");
        let mut order = limit_order(&token_in, &token_out);
        order.status = OrderStatus::Expired;
        assert_eq!(
            order.validate(999),
            Err(DomainError::ExpiredStatusBeforeWindow)
        );
        assert!(order.validate(2_000).is_ok());
    }

    #[test]
    fn direct_asset_construction_with_invalid_fields_is_rejected() {
        let blank_address = AssetId {
            chain: ChainId::Base,
            address: "  ".to_string(),
        };
        let mut intent = intent(OrderType::Market);
        intent.token_in = blank_address;
        assert_eq!(intent.validate(1_000), Err(DomainError::ChainMismatch));

        let mut order = limit_order(&asset("USDC"), &asset("TOKEN"));
        order.token_out = AssetId {
            chain: ChainId::Other(String::new()),
            address: "tok".to_string(),
        };
        assert_eq!(order.validate(1_000), Err(DomainError::ChainMismatch));

        let a = asset("USDC");
        let b = asset("TOKEN");
        let mut plan = route_plan(&[(&a, &b, 1_000, 500)], &b);
        plan.legs[0].token_out = AssetId {
            chain: ChainId::Base,
            address: String::new(),
        };
        assert_eq!(plan.validate(), Err(DomainError::ChainMismatch));

        let mut obs = tax_observation();
        obs.token = AssetId {
            chain: ChainId::Base,
            address: " ".to_string(),
        };
        assert_eq!(obs.validate(), Err(DomainError::ChainMismatch));
    }
    #[test]
    fn expiry_gated_states_transition_directly_to_expired() {
        for status in [
            OrderStatus::Created,
            OrderStatus::Active,
            OrderStatus::TriggerCandidate,
            OrderStatus::Quoting,
            OrderStatus::Simulating,
            OrderStatus::PartiallyFilled,
            OrderStatus::FailedRetryable,
        ] {
            assert!(
                status.can_transition_to(OrderStatus::Expired),
                "{status:?} must expire directly"
            );
        }
    }

    #[test]
    fn executing_remains_valid_after_expiry_and_may_expire_after_failure() {
        let mut order = limit_order(&asset("USDC"), &asset("TOKEN"));
        order.status = OrderStatus::Executing;
        assert_eq!(order.validate(2_000), Ok(()));
        assert!(order.validate(3_000).is_ok());
        assert!(OrderStatus::Executing.can_transition_to(OrderStatus::Expired));
        assert!(OrderStatus::Executing.can_transition_to(OrderStatus::FailedRetryable));

        order.status = OrderStatus::FailedRetryable;
        assert_eq!(order.validate(3_000), Err(DomainError::Expired));
        assert!(order.status.can_transition_to(OrderStatus::Expired));
        order.status = OrderStatus::Expired;
        assert!(order.validate(3_000).is_ok());
    }

    #[test]
    fn terminal_states_cannot_expire_or_resurrect() {
        for status in [
            OrderStatus::Filled,
            OrderStatus::Cancelled,
            OrderStatus::FailedFinal,
            OrderStatus::Expired,
        ] {
            assert!(!status.can_transition_to(OrderStatus::Expired));
        }
        for next in [
            OrderStatus::Created,
            OrderStatus::Active,
            OrderStatus::TriggerCandidate,
            OrderStatus::Quoting,
            OrderStatus::Simulating,
            OrderStatus::Executing,
            OrderStatus::PartiallyFilled,
            OrderStatus::FailedRetryable,
        ] {
            assert!(!OrderStatus::Expired.can_transition_to(next));
        }
    }
}
