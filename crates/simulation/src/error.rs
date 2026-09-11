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

    /// The pool fee basis points is zero.
    #[error("pool fee must be greater than zero")]
    ZeroFee,

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
