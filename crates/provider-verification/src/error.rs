//! Fail-closed, payload-free verification errors.
//!
//! No variant, `Display`, or `Debug` implementation may disclose an address,
//! amount, calldata byte, digest, router, spender, or provider payload.

use std::fmt;

use thiserror::Error;

/// Redacted provider-proposal verification failure classes.
#[derive(Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderVerificationError {
    /// The proposal is for a different chain than the intent.
    #[error("provider proposal chain mismatch")]
    ChainMismatch,
    /// The proposal's input/output assets do not match the intent.
    #[error("provider proposal token mismatch")]
    TokenMismatch,
    /// The proposal's owner wallet is not the trusted wallet.
    #[error("provider proposal wallet mismatch")]
    WalletMismatch,
    /// The proposal's recipient is not the trusted recipient.
    #[error("provider proposal receiver mismatch")]
    ReceiverMismatch,
    /// The proposal's router is not in the allowlist.
    #[error("provider router is not allowed")]
    RouterNotAllowed,
    /// The proposal's approval spender is not in the allowlist.
    #[error("provider spender is not allowed")]
    SpenderNotAllowed,
    /// The proposal's approval amount exceeds the bound.
    #[error("provider approval exceeds the bound")]
    ApprovalExceeded,
    /// The proposal's input amount does not match the approved route.
    #[error("provider input amount mismatch")]
    AmountInMismatch,
    /// The proposal's output amount does not match the approved route.
    #[error("provider output amount mismatch")]
    AmountOutMismatch,
    /// The proposal carries no minimum receive amount.
    #[error("provider min receive is missing")]
    MinReceiveMissing,
    /// The proposal's minimum receive is below the required floor.
    #[error("provider min receive is below the required floor")]
    MinReceiveTooLow,
    /// The proposal's implied slippage exceeds the hard cap.
    #[error("provider slippage exceeds the hard cap")]
    SlippageExceeded,
    /// The proposal's native value exceeds the spend cap.
    #[error("provider native value exceeds the cap")]
    ValueExceeded,
    /// The proposal carries no calldata.
    #[error("provider calldata is empty")]
    CalldataEmpty,
    /// The proposal calldata exceeds the accepted bound.
    #[error("provider calldata exceeds the bound")]
    CalldataTooLarge,
    /// The proposal's committed calldata digest does not match its calldata.
    #[error("provider calldata digest mismatch")]
    CalldataDigestMismatch,
    /// The proposal is older than the freshness policy allows.
    #[error("provider proposal is stale")]
    ProposalStale,
    /// The proposal is timestamped after the reference time.
    #[error("provider proposal is from the future")]
    ProposalFromFuture,
    /// The approved route has no leg to bind against.
    #[error("approved route is missing a leg")]
    RouteMissing,
    /// The supplied tax assessment is not bound to the intent.
    #[error("tax assessment mismatch")]
    AssessmentMismatch,
}

impl fmt::Debug for ProviderVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Display` is static text only, so this cannot leak a payload.
        write!(formatter, "ProviderVerificationError({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_renders_without_payload() {
        let errors = [
            ProviderVerificationError::ChainMismatch,
            ProviderVerificationError::TokenMismatch,
            ProviderVerificationError::WalletMismatch,
            ProviderVerificationError::ReceiverMismatch,
            ProviderVerificationError::RouterNotAllowed,
            ProviderVerificationError::SpenderNotAllowed,
            ProviderVerificationError::ApprovalExceeded,
            ProviderVerificationError::AmountInMismatch,
            ProviderVerificationError::AmountOutMismatch,
            ProviderVerificationError::MinReceiveMissing,
            ProviderVerificationError::MinReceiveTooLow,
            ProviderVerificationError::SlippageExceeded,
            ProviderVerificationError::ValueExceeded,
            ProviderVerificationError::CalldataEmpty,
            ProviderVerificationError::CalldataTooLarge,
            ProviderVerificationError::CalldataDigestMismatch,
            ProviderVerificationError::ProposalStale,
            ProviderVerificationError::ProposalFromFuture,
            ProviderVerificationError::RouteMissing,
            ProviderVerificationError::AssessmentMismatch,
        ];
        for error in errors {
            let display = format!("{error}");
            let debug = format!("{error:?}");
            assert!(!display.is_empty());
            assert!(debug.starts_with("ProviderVerificationError("));
            assert!(!display.contains("0x"));
            assert!(!debug.contains("0x"));
        }
    }
}
