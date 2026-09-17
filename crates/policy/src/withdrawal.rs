//! Web-only, strongly-confirmed withdrawal contract.
//!
//! Withdrawal is capital movement, so it is deliberately *not* a generic signing
//! or transfer API. This module defines the control-plane contract only:
//!
//! - a validated [`WithdrawalRequest`];
//! - [`authorize_withdrawal`], which requires the live trading gate, always
//!   requires [`Confirmation::WebStrong`] (the owner's fresh web
//!   re-authentication, bounded in age), binds the request to the wallet the
//!   limits belong to, requires a positive trusted valuation, and enforces the
//!   wallet's allowed chains and per-trade notional cap; and
//! - a data-only [`WithdrawalApproval`] that carries no signing, submission, or
//!   transfer method.
//!
//! The browser can never call a signing/transfer primitive: `agent-commands`
//! exposes no withdrawal or transfer command, and the only path that can produce
//! a [`WithdrawalApproval`] is this trusted, strongly-confirmed web contract. A
//! later, separately reviewed relay adapter owns any actual submission.
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use chain_types::AssetId;
use domain::WalletRef;
use market_types::AtomicAmount;
use thiserror::Error;

use crate::wallet::{Confirmation, WalletLimits};
use crate::UsdMicros;

/// Maximum age of a web strong confirmation at authorization time.
///
/// A stale re-authentication cannot be replayed to authorize a withdrawal later.
pub const MAX_CONFIRMATION_AGE_MS: i64 = 5 * 60 * 1000;

/// A requested withdrawal of one asset to one destination.
#[derive(Clone, PartialEq, Eq)]
pub struct WithdrawalRequest {
    /// Server-generated request id (also the idempotency key).
    pub request_id: String,
    /// Wallet the withdrawal spends from.
    pub wallet_ref: WalletRef,
    /// Asset to withdraw.
    pub asset: AssetId,
    /// Atomic amount to withdraw.
    pub amount: AtomicAmount,
    /// Destination address, exactly as the owner confirmed it.
    pub destination: String,
    /// When the request was raised.
    pub requested_at_ms: i64,
}

impl std::fmt::Debug for WithdrawalRequest {
    /// Redacted: destination, amount, and asset are payload semantics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WithdrawalRequest")
            .finish_non_exhaustive()
    }
}

/// A data-only approval. It exposes no signing or transfer capability.
#[derive(Clone, PartialEq, Eq)]
pub struct WithdrawalApproval {
    request_id: String,
    wallet_ref: WalletRef,
    asset: AssetId,
    amount: AtomicAmount,
    destination: String,
    approved_at_ms: i64,
}

impl std::fmt::Debug for WithdrawalApproval {
    /// Redacted: destination, amount, and asset are payload semantics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WithdrawalApproval")
            .finish_non_exhaustive()
    }
}

impl WithdrawalApproval {
    /// The approved request id.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The wallet the withdrawal spends from.
    pub fn wallet_ref(&self) -> &WalletRef {
        &self.wallet_ref
    }

    /// The approved asset.
    pub fn asset(&self) -> &AssetId {
        &self.asset
    }

    /// The approved atomic amount.
    pub fn amount(&self) -> AtomicAmount {
        self.amount
    }

    /// The approved destination.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// When the approval was granted.
    pub fn approved_at_ms(&self) -> i64 {
        self.approved_at_ms
    }
}

/// Withdrawal failure taxonomy. Redacted: no addresses or amounts are rendered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WithdrawalError {
    /// Trading is disabled, so no withdrawal may be authorized.
    #[error("trading disabled")]
    TradingDisabled,
    /// The request has no id.
    #[error("withdrawal request id is required")]
    MissingRequestId,
    /// The amount is zero.
    #[error("withdrawal amount must be positive")]
    AmountNotPositive,
    /// The destination is empty or blank.
    #[error("withdrawal destination is required")]
    EmptyDestination,
    /// The request's wallet does not match the limits record.
    #[error("withdrawal wallet does not match its limits")]
    WalletMismatch,
    /// The asset's chain is not allowed for this wallet.
    #[error("withdrawal chain is not allowed")]
    ChainNotAllowed,
    /// The trusted valuation is missing or non-positive.
    #[error("withdrawal valuation is unavailable")]
    InvalidValuation,
    /// The notional exceeds the wallet's per-trade cap.
    #[error("withdrawal exceeds the wallet limit")]
    ValueExceedsLimit,
    /// A fresh web re-authentication is required.
    #[error("withdrawal requires web strong confirmation")]
    StrongConfirmationRequired,
    /// The web confirmation is older than [`MAX_CONFIRMATION_AGE_MS`].
    #[error("withdrawal confirmation is stale")]
    StaleConfirmation,
}

/// Authorizes a withdrawal.
///
/// Requires, in order: the live trading gate; a [`Confirmation::WebStrong`]
/// whose `verified_at_ms` is not in the future and is at most
/// [`MAX_CONFIRMATION_AGE_MS`] old at `now_ms`; a non-empty request id, a
/// positive amount, a non-empty destination, a request/limits wallet match, an
/// allowed chain, a positive trusted valuation, and a valuation within the
/// wallet's per-trade cap.
#[allow(clippy::too_many_arguments)]
pub fn authorize_withdrawal(
    request: &WithdrawalRequest,
    limits: &WalletLimits,
    trusted_value_usd: UsdMicros,
    confirmation: Confirmation,
    trading_enabled: bool,
    now_ms: i64,
) -> Result<WithdrawalApproval, WithdrawalError> {
    if !trading_enabled {
        return Err(WithdrawalError::TradingDisabled);
    }
    let Confirmation::WebStrong(confirmation) = confirmation else {
        return Err(WithdrawalError::StrongConfirmationRequired);
    };
    let verified_at_ms = confirmation.verified_at_ms();
    // A negative age is a future confirmation; an age above the bound is stale.
    let age_ms = now_ms
        .checked_sub(verified_at_ms)
        .filter(|age_ms| (0..=MAX_CONFIRMATION_AGE_MS).contains(age_ms));
    if age_ms.is_none() {
        return Err(WithdrawalError::StaleConfirmation);
    }
    if request.request_id.trim().is_empty() {
        return Err(WithdrawalError::MissingRequestId);
    }
    if request.amount.is_zero() {
        return Err(WithdrawalError::AmountNotPositive);
    }
    if request.destination.trim().is_empty() {
        return Err(WithdrawalError::EmptyDestination);
    }
    if request.wallet_ref != limits.wallet_ref {
        return Err(WithdrawalError::WalletMismatch);
    }
    if !limits.allowed_chains.contains(&request.asset.chain) {
        return Err(WithdrawalError::ChainNotAllowed);
    }
    if trusted_value_usd.get() == 0 {
        return Err(WithdrawalError::InvalidValuation);
    }
    if trusted_value_usd > limits.max_trade_usd {
        return Err(WithdrawalError::ValueExceedsLimit);
    }
    Ok(WithdrawalApproval {
        request_id: request.request_id.clone(),
        wallet_ref: request.wallet_ref.clone(),
        asset: request.asset.clone(),
        amount: request.amount,
        destination: request.destination.clone(),
        approved_at_ms: now_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::WebStrongConfirmation;
    use chain_types::ChainId;
    use market_types::Bps;
    use std::collections::HashSet;

    const NOW: i64 = 10_000;

    fn wallet() -> WalletRef {
        WalletRef::new("wallet-1").expect("wallet")
    }

    fn limits() -> WalletLimits {
        WalletLimits {
            wallet_ref: wallet(),
            max_trade_usd: UsdMicros::new(1_000_000),
            max_hourly_turnover_usd: UsdMicros::new(5_000_000),
            max_daily_turnover_usd: UsdMicros::new(20_000_000),
            max_buy_tax: Bps::new(500).expect("bps"),
            max_sell_tax: Bps::new(500).expect("bps"),
            max_price_impact: Bps::new(300).expect("bps"),
            max_slippage: Bps::new(200).expect("bps"),
            allowed_chains: [ChainId::Base].into_iter().collect::<HashSet<_>>(),
            allowed_venues: HashSet::new(),
        }
    }

    fn request(chain: ChainId, amount: u128) -> WithdrawalRequest {
        WithdrawalRequest {
            request_id: "wd-1".to_string(),
            wallet_ref: wallet(),
            asset: AssetId::new(chain, "USDC").expect("asset"),
            amount: AtomicAmount::new(amount),
            destination: "0xabc".to_string(),
            requested_at_ms: NOW - 1,
        }
    }

    fn confirmed_at(verified_at_ms: i64) -> Confirmation {
        Confirmation::WebStrong(WebStrongConfirmation::from_web_reauthentication(
            verified_at_ms,
        ))
    }

    #[test]
    fn withdrawal_always_requires_strong_confirmation_and_the_gate() {
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(10),
                Confirmation::None,
                true,
                NOW,
            ),
            Err(WithdrawalError::StrongConfirmationRequired)
        );
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(10),
                confirmed_at(NOW),
                false,
                NOW,
            ),
            Err(WithdrawalError::TradingDisabled)
        );
        let approval = authorize_withdrawal(
            &request(ChainId::Base, 10),
            &limits(),
            UsdMicros::new(10),
            confirmed_at(NOW),
            true,
            NOW,
        )
        .expect("approved");
        assert_eq!(approval.request_id(), "wd-1");
        assert_eq!(approval.approved_at_ms(), NOW);
        assert_eq!(approval.destination(), "0xabc");
        assert!(!format!("{approval:?}").contains("0xabc"));
        assert!(!format!("{:?}", request(ChainId::Base, 10)).contains("0xabc"));
    }

    #[test]
    fn withdrawal_rejects_a_stale_or_future_confirmation() {
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(10),
                confirmed_at(NOW - MAX_CONFIRMATION_AGE_MS - 1),
                true,
                NOW,
            ),
            Err(WithdrawalError::StaleConfirmation)
        );
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(10),
                confirmed_at(NOW + 1),
                true,
                NOW,
            ),
            Err(WithdrawalError::StaleConfirmation)
        );
    }

    #[test]
    fn withdrawal_enforces_wallet_chain_and_limit() {
        // Wallet mismatch: permissive limits for wallet-2 must not authorize a
        // wallet-1 request.
        let mut other = limits();
        other.wallet_ref = WalletRef::new("wallet-2").expect("wallet");
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &other,
                UsdMicros::new(10),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::WalletMismatch)
        );

        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Ethereum, 10),
                &limits(),
                UsdMicros::new(10),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::ChainNotAllowed)
        );
        // A zero (unavailable) valuation must not bypass the cap.
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(0),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::InvalidValuation)
        );
        assert_eq!(
            authorize_withdrawal(
                &request(ChainId::Base, 10),
                &limits(),
                UsdMicros::new(2_000_000),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::ValueExceedsLimit)
        );
    }

    #[test]
    fn empty_fields_and_zero_amount_are_rejected() {
        let mut zero = request(ChainId::Base, 0);
        assert_eq!(
            authorize_withdrawal(
                &zero,
                &limits(),
                UsdMicros::new(1),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::AmountNotPositive)
        );
        zero.amount = AtomicAmount::new(10);
        zero.request_id = "  ".to_string();
        assert_eq!(
            authorize_withdrawal(
                &zero,
                &limits(),
                UsdMicros::new(1),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::MissingRequestId)
        );
        zero.request_id = "wd-2".to_string();
        zero.destination = String::new();
        assert_eq!(
            authorize_withdrawal(
                &zero,
                &limits(),
                UsdMicros::new(1),
                confirmed_at(NOW),
                true,
                NOW,
            ),
            Err(WithdrawalError::EmptyDestination)
        );
    }
}
