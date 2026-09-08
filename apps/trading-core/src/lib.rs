//! Phase-0 Trading Core orchestration skeleton. Live execution remains unavailable.

use std::sync::Arc;

use domain::TradeIntent;
use policy::{PolicyContext, PolicyEngine, PolicyError};
use privy::{PreparedExecutionRef, PrivyError, PrivySigningBoundary, SubmittedExecutionRef};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradingCoreStatus {
    pub trading_enabled: bool,
    pub live_execution_wired: bool,
}

pub struct TradingCore {
    policy: PolicyEngine,
    signer: Arc<PrivySigningBoundary>,
}

impl TradingCore {
    pub fn new(policy: PolicyEngine, signer: Arc<PrivySigningBoundary>) -> Self {
        Self { policy, signer }
    }

    pub fn status(&self) -> TradingCoreStatus {
        TradingCoreStatus {
            trading_enabled: self.policy.is_trading_enabled(),
            live_execution_wired: false,
        }
    }

    pub fn disable_trading(&self) {
        self.policy.disable_trading();
    }

    pub async fn request_execution(
        &self,
        intent: &TradeIntent,
        context: &PolicyContext,
        prepared: &PreparedExecutionRef,
    ) -> Result<SubmittedExecutionRef, TradingCoreError> {
        // Policy — including the global kill switch — is always the first execution gate.
        // The Privy boundary validates the prepared execution binding only after approval.
        let approved = self.policy.authorize_trade(intent, context)?;
        let submitted = self
            .signer
            .submit_approved_execution(&approved, prepared)
            .await?;
        Ok(submitted)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TradingCoreError {
    #[error("policy rejected execution")]
    Policy(#[from] PolicyError),
    #[error("signing boundary rejected execution")]
    Privy(#[from] PrivyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::{AssetId, ChainId};
    use domain::{
        AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, TradeSide, TradeSource,
        UserId, WalletRef,
    };
    use market_types::{AtomicAmount, Bps};
    use policy::{PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
    use std::collections::HashSet;

    fn intent() -> TradeIntent {
        TradeIntent {
            id: IntentId::new("intent-1").unwrap(),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").unwrap(),
            wallet_ref: WalletRef::new("wallet-1").unwrap(),
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
            idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
        }
    }

    fn limits() -> PolicyLimits {
        PolicyLimits {
            max_trade_usd: UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: UsdMicros::new(10_000_000),
            max_daily_turnover_usd: UsdMicros::new(50_000_000),
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            allowed_chains: HashSet::from([ChainId::Base]),
            allowed_venues: HashSet::from(["uniswap".to_string()]),
        }
    }

    fn context() -> PolicyContext {
        PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".to_string()),
        )
        .unwrap()
    }

    fn prepared(i: &TradeIntent) -> PreparedExecutionRef {
        PreparedExecutionRef::new("prepared-1", i.id.clone(), i.idempotency_key.clone()).unwrap()
    }

    #[tokio::test]
    async fn default_disabled_blocks_before_privy() {
        let core = TradingCore::new(
            PolicyEngine::new(TradingGate::default(), limits()).unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        let i = intent();
        let result = core.request_execution(&i, &context(), &prepared(&i)).await;
        assert_eq!(
            result,
            Err(TradingCoreError::Policy(PolicyError::TradingDisabled))
        );
        assert!(!core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
    }

    #[tokio::test]
    async fn enabled_valid_request_reaches_unavailable_privy() {
        let core = TradingCore::new(
            PolicyEngine::new(
                TradingGate::from_trusted_startup(Some("true")).unwrap(),
                limits(),
            )
            .unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        let i = intent();
        assert_eq!(
            core.request_execution(&i, &context(), &prepared(&i)).await,
            Err(TradingCoreError::Privy(PrivyError::SigningUnavailable))
        );
    }

    #[tokio::test]
    async fn disabled_gate_wins_over_prepared_binding_mismatch() {
        let core = TradingCore::new(
            PolicyEngine::new(TradingGate::default(), limits()).unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        let i = intent();
        let wrong = PreparedExecutionRef::new(
            "prepared-disabled",
            IntentId::new("other-disabled").unwrap(),
            i.idempotency_key.clone(),
        )
        .unwrap();
        assert_eq!(
            core.request_execution(&i, &context(), &wrong).await,
            Err(TradingCoreError::Policy(PolicyError::TradingDisabled))
        );
    }

    #[tokio::test]
    async fn mismatched_prepared_execution_is_rejected_before_privy() {
        let core = TradingCore::new(
            PolicyEngine::new(
                TradingGate::from_trusted_startup(Some("true")).unwrap(),
                limits(),
            )
            .unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        let i = intent();
        let wrong = PreparedExecutionRef::new(
            "prepared-2",
            IntentId::new("other").unwrap(),
            i.idempotency_key.clone(),
        )
        .unwrap();
        assert_eq!(
            core.request_execution(&i, &context(), &wrong).await,
            Err(TradingCoreError::Privy(PrivyError::ApprovalBindingMismatch))
        );
    }

    #[test]
    fn status_and_one_way_disable_work() {
        let core = TradingCore::new(
            PolicyEngine::new(
                TradingGate::from_trusted_startup(Some("true")).unwrap(),
                limits(),
            )
            .unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        assert!(core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
        core.disable_trading();
        assert!(!core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
    }
}
