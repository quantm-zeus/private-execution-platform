//! Redacted structural errors for the exact-simulation net-delta bridge.
//!
//! Every variant either carries an already-redacted source error verbatim or a
//! payload-free structural marker. Neither [`Display`](std::fmt::Display) nor
//! [`Debug`](std::fmt::Debug) reveals amounts, assets, prices, reserves, fee
//! parameters, endpoints, or secrets.

use domain::DomainError;
use simulation::{BinSimulationError, ClmmSimulationError, CpmmSimulationErrorClass};
use tax_engine::TaxSafetyError;
use thiserror::Error;

/// Fail-closed bridge error between exact local simulation quotes and the
/// canonical execution-preview contract.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    /// Canonical domain validation failed.
    #[error("domain validation failed: {0}")]
    Domain(#[from] DomainError),

    /// Underlying CPMM simulation failed.
    #[error("cpmm simulation failed: {0}")]
    Cpmm(#[from] CpmmSimulationErrorClass),

    /// Underlying CLMM simulation failed.
    #[error("clmm simulation failed: {0}")]
    Clmm(#[from] ClmmSimulationError),

    /// Underlying Bin/DLMM simulation failed.
    #[error("bin simulation failed: {0}")]
    Bin(#[from] BinSimulationError),

    /// Tax evaluation failed.
    #[error("tax evaluation failed: {0}")]
    Tax(#[from] TaxSafetyError),

    /// The normalized net delta violates exact conservation or denomination rules.
    #[error("net delta is inconsistent: {0}")]
    NetDeltaInconsistent(&'static str),

    /// The quote direction does not match the intent side.
    #[error("trade direction mismatch")]
    DirectionMismatch,

    /// The quote chain does not match the intent chain.
    #[error("chain mismatch")]
    ChainMismatch,

    /// The quote input asset does not match the intent input asset.
    #[error("input asset mismatch")]
    InputAssetMismatch,

    /// The quote output asset does not match the intent output asset.
    #[error("output asset mismatch")]
    OutputAssetMismatch,

    /// The tax assessment is bound to a different asset than the intent assesses.
    #[error("assessed asset mismatch")]
    AssessedAssetMismatch,

    /// The realized delta tax does not equal the tax implied by the assessment.
    #[error("delta tax does not match assessment")]
    AssessmentDeltaMismatch,

    /// The assessed tax exceeds the intent risk cap for the trade side.
    #[error("assessed tax exceeds the intent cap")]
    TaxCapExceeded,

    /// Route state freshness could not be evaluated.
    #[error("market state freshness is unavailable")]
    FreshnessUnavailable,
}
