//! Phase-0 Trading Core orchestration skeleton. Live execution remains unavailable.

pub mod composition;

use std::sync::Arc;

use domain::{RoutePlan, TradeIntent, ValidatedExecutionPreview};
use policy::{PolicyContext, PolicyEngine, PolicyError};
use privy::{
    PayloadDigest, PreparedExecutionRef, PrivyError, PrivySigningBoundary, SignedExecutionRef,
    SigningRequest,
};
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

    /// Builds a fully bound signing request from the approved execution and the
    /// validated preview, then submits it through the fail-closed Privy
    /// boundary.
    ///
    /// There is no generic signing path: the boundary only accepts a
    /// [`SigningRequest`], and the caller supplies the payload digest that binds
    /// the unsigned transaction. The default boundary returns
    /// [`PrivyError::SigningUnavailable`].
    pub async fn request_execution(
        &self,
        intent: &TradeIntent,
        context: &PolicyContext,
        prepared: &PreparedExecutionRef,
        route: &RoutePlan,
        preview: &ValidatedExecutionPreview,
        payload_digest: PayloadDigest,
    ) -> Result<SignedExecutionRef, TradingCoreError> {
        // Policy — including the global kill switch — is always the first execution gate.
        let approved = self.policy.authorize_trade(intent, context)?;
        let request = SigningRequest::bind(
            &self.policy,
            &approved,
            prepared,
            intent,
            route,
            preview,
            payload_digest,
            context.now_ms(),
        )?;
        let signed = self.signer.submit_signing_request(&request).await?;
        Ok(signed)
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
        AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, OrderType,
        RiskConstraints, RouteLeg, TradeSide, TradeSource, UserId, WalletRef,
    };
    use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, Sequence};
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
            amount_type: AmountType::InputAssetAtomic,
            amount: AtomicAmount::new(1_000),
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

    fn route() -> RoutePlan {
        let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
        let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
        RoutePlan {
            legs: vec![RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "0xpool1".to_string(),
                token_in,
                token_out: token_out.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(250),
            }],
            expected_net_output: AssetAmount {
                asset: token_out,
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: 1_000,
                chain_height: 100,
                sequence: Sequence(1),
            },
        }
    }

    fn preview(i: &TradeIntent, route: &RoutePlan) -> ValidatedExecutionPreview {
        ExecutionPreview {
            intent_id: i.id.clone(),
            chain: i.chain.clone(),
            token_in: i.token_in.clone(),
            token_out: i.token_out.clone(),
            side: i.side,
            simulated_net_input: AssetAmount {
                asset: i.token_in.clone(),
                amount: AtomicAmount::new(1_000),
            },
            simulated_net_output: AssetAmount {
                asset: i.token_out.clone(),
                amount: AtomicAmount::new(240),
            },
            gross_output: AssetAmount {
                asset: i.token_out.clone(),
                amount: AtomicAmount::new(250),
            },
            cost_components: ExecutionCostComponents::default(),
            local_state_freshness: market_types::FreshnessStatus::Fresh,
        }
        .validate(i, route, 1_000)
        .unwrap()
    }

    fn prepared(i: &TradeIntent) -> PreparedExecutionRef {
        PreparedExecutionRef::new("prepared-1", i.id.clone(), i.idempotency_key.clone()).unwrap()
    }

    fn payload() -> PayloadDigest {
        PayloadDigest::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn enabled_core() -> TradingCore {
        TradingCore::new(
            PolicyEngine::new(
                TradingGate::from_trusted_startup(Some("true")).unwrap(),
                limits(),
            )
            .unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        )
    }

    #[tokio::test]
    async fn default_disabled_blocks_before_privy() {
        let core = TradingCore::new(
            PolicyEngine::new(TradingGate::default(), limits()).unwrap(),
            Arc::new(PrivySigningBoundary::default()),
        );
        let i = intent();
        let r = route();
        let p = preview(&i, &r);
        let result = core
            .request_execution(&i, &context(), &prepared(&i), &r, &p, payload())
            .await;
        assert_eq!(
            result,
            Err(TradingCoreError::Policy(PolicyError::TradingDisabled))
        );
        assert!(!core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
    }

    #[tokio::test]
    async fn enabled_valid_request_reaches_unavailable_privy() {
        let core = enabled_core();
        let i = intent();
        let r = route();
        let p = preview(&i, &r);
        assert_eq!(
            core.request_execution(&i, &context(), &prepared(&i), &r, &p, payload())
                .await,
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
        let r = route();
        let p = preview(&i, &r);
        let wrong = PreparedExecutionRef::new(
            "prepared-disabled",
            IntentId::new("other-disabled").unwrap(),
            i.idempotency_key.clone(),
        )
        .unwrap();
        assert_eq!(
            core.request_execution(&i, &context(), &wrong, &r, &p, payload())
                .await,
            Err(TradingCoreError::Policy(PolicyError::TradingDisabled))
        );
    }

    #[tokio::test]
    async fn mismatched_prepared_execution_is_rejected_before_privy() {
        let core = enabled_core();
        let i = intent();
        let r = route();
        let p = preview(&i, &r);
        let wrong = PreparedExecutionRef::new(
            "prepared-2",
            IntentId::new("other").unwrap(),
            i.idempotency_key.clone(),
        )
        .unwrap();
        assert_eq!(
            core.request_execution(&i, &context(), &wrong, &r, &p, payload())
                .await,
            Err(TradingCoreError::Privy(PrivyError::ApprovalBindingMismatch))
        );
    }

    #[test]
    fn status_and_one_way_disable_work() {
        let core = enabled_core();
        assert!(core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
        core.disable_trading();
        assert!(!core.status().trading_enabled);
        assert!(!core.status().live_execution_wired);
    }
}
