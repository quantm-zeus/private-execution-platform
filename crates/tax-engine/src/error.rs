//! Safe, bounded, non-secret error definitions for tax and safety evaluation.

use domain::DomainError;
use thiserror::Error;

/// Structured, non-secret errors produced during tax and safety evaluation.
///
/// None of these variants expose endpoints, payloads, credentials, or secrets.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TaxSafetyError {
    /// The trade intent failed validation.
    #[error("trade intent validation failed: {0}")]
    InvalidTradeIntent(DomainError),

    /// The tax observation failed validation.
    #[error("tax observation failed validation: {0}")]
    InvalidTaxObservation(DomainError),

    /// Missing tax observation when one was required.
    #[error("tax observation is missing")]
    MissingObservation,

    /// Observation chain does not match trade intent chain.
    #[error("chain mismatch")]
    ChainMismatch,

    /// Assessed asset does not match expected intent asset (token_out for Buy, token_in for Sell).
    #[error("assessed asset mismatch")]
    AssessedAssetMismatch,

    /// Freshness evaluation parameters were invalid.
    #[error("freshness evaluation failed")]
    FreshnessEvaluationFailed,

    /// Observation is stale according to the freshness policy.
    #[error("tax observation is stale")]
    StaleObservation,

    /// Observation requires resync or excessive future clock skew was detected.
    #[error("tax observation requires resync or clock skew exceeded policy limit")]
    ResyncRequired,

    /// Simulated buy transaction failed in observation.
    #[error("buy simulation failed in tax observation")]
    BuySimulationFailed,

    /// Simulated sell transaction failed in observation.
    #[error("sell simulation failed in tax observation")]
    SellSimulationFailed,

    /// Token is flagged as not sellable (e.g. honeypot/transfer restricted).
    #[error("token is not sellable in tax observation")]
    TokenNotSellable,

    /// Observed buy tax exceeds intent's maximum allowed buy tax cap.
    #[error("buy tax exceeds maximum allowed cap")]
    BuyTaxExceedsCap,

    /// Observed sell tax exceeds intent's maximum allowed sell tax cap.
    #[error("sell tax exceeds maximum allowed cap")]
    SellTaxExceedsCap,

    /// Gross output amount is zero.
    #[error("gross output amount must be greater than zero")]
    ZeroGrossOutput,

    /// Net output amount is zero after deducting tax.
    #[error("net output amount must be greater than zero")]
    ZeroNetOutput,

    /// Gross input amount is zero.
    #[error("gross input amount must be greater than zero")]
    ZeroGrossInput,

    /// Net transferable input amount is zero after deducting tax.
    #[error("net transferable input amount must be greater than zero")]
    ZeroNetInput,
}
