//! Safe and bounded error definitions for local simulation kernels.

use chain_types::AssetId;
use market_types::MarketTypeError;
use thiserror::Error;

/// Errors produced during deterministic local swap simulation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SimulationError {
    /// The supplied pool state failed its own contract validation.
    #[error("pool state validation failed: {0}")]
    InvalidPoolState(#[from] MarketTypeError),

    /// The swap input amount is zero.
    #[error("swap input amount must be greater than zero")]
    ZeroInputAmount,

    /// One or both pool reserves are zero.
    #[error("pool reserves must be greater than zero")]
    ZeroReserve,

    /// The pool fee basis points is invalid (must be strictly less than 10,000 bps).
    #[error("pool fee {0} bps is invalid (must be strictly less than 10000 bps)")]
    InvalidFeeBps(u16),

    /// The requested input asset does not match either token in the pool.
    #[error("input asset {0:?} not found in pool")]
    AssetNotFoundInPool(AssetId),

    /// The caller-selected output asset does not match the pool direction.
    #[error("output asset mismatch: expected {expected:?}, received {received:?}")]
    OutputAssetMismatch {
        expected: AssetId,
        received: AssetId,
    },

    /// The input asset chain does not match the pool chain.
    #[error("chain mismatch: asset chain does not match pool chain")]
    ChainMismatch,

    /// Effective post-fee input amount was reduced to zero.
    #[error("effective input amount after fee is zero")]
    ZeroEffectiveInput,

    /// Simulated output amount is zero (impossible fill).
    #[error("simulated output amount is zero")]
    ZeroOutputAmount,

    /// Simulated output equals or exceeds available pool reserve.
    #[error("simulated output exceeds or equals pool reserve")]
    ImpossibleOutput,

    /// Checked integer arithmetic overflowed during calculations.
    #[error("arithmetic overflow during simulation calculation")]
    ArithmeticOverflow,

    /// Constant-product invariant k was violated.
    #[error("constant product invariant k violated")]
    InvariantViolated,
}

/// Redacted structural error classes for CPMM simulation failures.
///
/// Contains no value-bearing payloads, amounts, asset identifiers, pool reserves,
/// or fee parameters in either [`Display`](std::fmt::Display) or [`Debug`](std::fmt::Debug).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CpmmSimulationErrorClass {
    /// The supplied pool state failed its own contract validation.
    #[error("pool state validation failed")]
    InvalidPoolState,

    /// The swap input amount is zero.
    #[error("swap input amount must be greater than zero")]
    ZeroInputAmount,

    /// One or both pool reserves are zero.
    #[error("pool reserves must be greater than zero")]
    ZeroReserve,

    /// The pool fee basis points is invalid.
    #[error("pool fee basis points is invalid")]
    InvalidFeeBps,

    /// The requested input asset does not match either token in the pool.
    #[error("input asset not found in pool")]
    AssetNotFoundInPool,

    /// The caller-selected output asset does not match the pool direction.
    #[error("output asset mismatch")]
    OutputAssetMismatch,

    /// The input asset chain does not match the pool chain.
    #[error("chain mismatch: asset chain does not match pool chain")]
    ChainMismatch,

    /// Effective post-fee input amount was reduced to zero.
    #[error("effective input amount after fee is zero")]
    ZeroEffectiveInput,

    /// Simulated output amount is zero.
    #[error("simulated output amount is zero")]
    ZeroOutputAmount,

    /// Simulated output equals or exceeds available pool reserve.
    #[error("simulated output exceeds or equals pool reserve")]
    ImpossibleOutput,

    /// Checked integer arithmetic overflowed during calculations.
    #[error("arithmetic overflow during simulation calculation")]
    ArithmeticOverflow,

    /// Constant-product invariant k was violated.
    #[error("constant product invariant k violated")]
    InvariantViolated,
}

impl From<SimulationError> for CpmmSimulationErrorClass {
    fn from(err: SimulationError) -> Self {
        match err {
            SimulationError::InvalidPoolState(_) => Self::InvalidPoolState,
            SimulationError::ZeroInputAmount => Self::ZeroInputAmount,
            SimulationError::ZeroReserve => Self::ZeroReserve,
            SimulationError::InvalidFeeBps(_) => Self::InvalidFeeBps,
            SimulationError::AssetNotFoundInPool(_) => Self::AssetNotFoundInPool,
            SimulationError::OutputAssetMismatch { .. } => Self::OutputAssetMismatch,
            SimulationError::ChainMismatch => Self::ChainMismatch,
            SimulationError::ZeroEffectiveInput => Self::ZeroEffectiveInput,
            SimulationError::ZeroOutputAmount => Self::ZeroOutputAmount,
            SimulationError::ImpossibleOutput => Self::ImpossibleOutput,
            SimulationError::ArithmeticOverflow => Self::ArithmeticOverflow,
            SimulationError::InvariantViolated => Self::InvariantViolated,
        }
    }
}

/// Redacted error produced during tax-aware CPMM simulation composition.
///
/// Combines underlying CPMM simulation failures (as redacted structural classes)
/// with buy-side tax safety failures (reusing [`TaxSafetyError`]). Neither [`Display`](std::fmt::Display)
/// nor [`Debug`](std::fmt::Debug) reveals amounts, asset identifiers, pool reserves,
/// freshness metadata, endpoints, payloads, credentials, or secrets.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum TaxAwareSimulationError {
    /// Failure during underlying CPMM pool simulation.
    #[error("{0}")]
    Cpmm(#[from] CpmmSimulationErrorClass),

    /// Failure during buy-side tax evaluation.
    #[error("{0}")]
    Tax(#[from] tax_engine::TaxSafetyError),
}

pub type TaxAwareCpmmBuyError = TaxAwareSimulationError;
pub type TaxAwareCpmmError = TaxAwareSimulationError;
pub type CpmmErrorClass = CpmmSimulationErrorClass;

impl From<SimulationError> for TaxAwareSimulationError {
    fn from(err: SimulationError) -> Self {
        Self::Cpmm(CpmmSimulationErrorClass::from(err))
    }
}
