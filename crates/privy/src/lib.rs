//! Narrow Privy signing boundary. No generic signing/transfer/withdraw surface exists.

use async_trait::async_trait;
use domain::{IdempotencyKey, IntentId};
use policy::ApprovedExecution;
use thiserror::Error;

/// Opaque reference to a prepared execution. This is not a signing capability;
/// it only carries the policy intent/idempotency binding for later validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedExecutionRef {
    reference: String,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
}

impl PreparedExecutionRef {
    pub fn new(
        reference: impl Into<String>,
        intent_id: IntentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, PrivyError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(PrivyError::InvalidExecutionReference);
        }
        Ok(Self {
            reference,
            intent_id,
            idempotency_key,
        })
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

/// Read-only reference to an execution submitted by the private signing backend.
/// External crates cannot construct this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedExecutionRef {
    reference: String,
    intent_id: IntentId,
    idempotency_key: IdempotencyKey,
}

impl SubmittedExecutionRef {
    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

#[async_trait]
trait PrivySigningBackend: Send + Sync {
    async fn submit(
        &self,
        approved: &ApprovedExecution,
        prepared: &PreparedExecutionRef,
    ) -> Result<SubmittedExecutionRef, PrivyError>;
}

#[derive(Debug, Default)]
struct UnavailablePrivyBackend;

#[async_trait]
impl PrivySigningBackend for UnavailablePrivyBackend {
    async fn submit(
        &self,
        _approved: &ApprovedExecution,
        _prepared: &PreparedExecutionRef,
    ) -> Result<SubmittedExecutionRef, PrivyError> {
        Err(PrivyError::SigningUnavailable)
    }
}

/// Concrete, non-heritable signing boundary. Production defaults to an
/// unavailable backend and exposes no way for callers to install one.
#[derive(Debug, Default)]
pub struct PrivySigningBoundary {
    backend: UnavailablePrivyBackend,
}

impl PrivySigningBoundary {
    pub fn new() -> Self {
        Self::default()
    }

    fn validate_binding(
        &self,
        approved: &ApprovedExecution,
        prepared: &PreparedExecutionRef,
    ) -> Result<(), PrivyError> {
        if prepared.intent_id != *approved.intent_id()
            || prepared.idempotency_key != *approved.idempotency_key()
        {
            return Err(PrivyError::ApprovalBindingMismatch);
        }
        Ok(())
    }

    pub async fn submit_approved_execution(
        &self,
        approved: &ApprovedExecution,
        prepared: &PreparedExecutionRef,
    ) -> Result<SubmittedExecutionRef, PrivyError> {
        self.validate_binding(approved, prepared)?;
        self.backend.submit(approved, prepared).await
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivyError {
    #[error("Privy signing boundary unavailable")]
    SigningUnavailable,
    #[error("invalid prepared execution reference")]
    InvalidExecutionReference,
    #[error("prepared execution does not match policy approval")]
    ApprovalBindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::{AssetId, ChainId};
    use domain::{
        AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeIntent, TradeSide,
        TradeSource, UserId, WalletRef,
    };
    use market_types::{AtomicAmount, Bps};
    use policy::{
        PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros,
    };
    use std::collections::HashSet;

    fn approved() -> ApprovedExecution {
        let intent = TradeIntent {
            id: IntentId::new("intent").unwrap(),
            source: TradeSource::Web,
            user_id: UserId::new("user").unwrap(),
            wallet_ref: WalletRef::new("wallet").unwrap(),
            chain: ChainId::Base,
            token_in: AssetId::new(ChainId::Base, "USDC").unwrap(),
            token_out: AssetId::new(ChainId::Base, "TOKEN").unwrap(),
            side: TradeSide::Buy,
            amount_type: AmountType::UsdMicros,
            amount: AtomicAmount::new(500_000),
            order_type: OrderType::Market,
            limit_price: None,
            risk: RiskConstraints {
                max_buy_tax: Bps::new(100).unwrap(),
                max_sell_tax: Bps::new(100).unwrap(),
                max_price_impact: Bps::new(100).unwrap(),
                max_slippage: Bps::new(100).unwrap(),
                max_total_cost: None,
            },
            allow_partial_fill: true,
            expiry_ms: Some(10_000),
            nonce: 1,
            idempotency_key: IdempotencyKey::new("idem").unwrap(),
        };
        let limits = PolicyLimits {
            max_trade_usd: UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: UsdMicros::new(10_000_000),
            max_daily_turnover_usd: UsdMicros::new(50_000_000),
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            allowed_chains: HashSet::from([ChainId::Base]),
            allowed_venues: HashSet::from(["uniswap".to_string()]),
        };
        let ctx = PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".to_string()),
        )
        .unwrap();
        PolicyEngine::new(
            TradingGate::from_trusted_startup(Some("true")).unwrap(),
            limits,
        )
        .unwrap()
        .authorize_trade(&intent, &ctx)
        .unwrap()
    }

    #[tokio::test]
    async fn mismatch_is_rejected_before_backend() {
        let boundary = PrivySigningBoundary::default();
        let approved = approved();
        let prepared = PreparedExecutionRef::new(
            "prepared",
            IntentId::new("other").unwrap(),
            approved.idempotency_key().clone(),
        )
        .unwrap();
        assert_eq!(
            boundary
                .submit_approved_execution(&approved, &prepared)
                .await,
            Err(PrivyError::ApprovalBindingMismatch)
        );
    }

    #[tokio::test]
    async fn production_boundary_fails_closed() {
        let boundary = PrivySigningBoundary::default();
        let approved = approved();
        let prepared = PreparedExecutionRef::new(
            "prepared",
            approved.intent_id().clone(),
            approved.idempotency_key().clone(),
        )
        .unwrap();
        assert_eq!(
            boundary
                .submit_approved_execution(&approved, &prepared)
                .await,
            Err(PrivyError::SigningUnavailable)
        );
    }

    #[test]
    fn empty_reference_is_rejected() {
        let approved = approved();
        assert_eq!(
            PreparedExecutionRef::new(
                " ",
                approved.intent_id().clone(),
                approved.idempotency_key().clone(),
            ),
            Err(PrivyError::InvalidExecutionReference)
        );
    }
}
