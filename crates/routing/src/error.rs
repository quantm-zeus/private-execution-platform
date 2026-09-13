//! Redacted, payload-free routing errors.
//!
//! Neither [`Display`](std::fmt::Display) nor [`Debug`](std::fmt::Debug) of any
//! [`RoutingError`] variant reveals amounts, asset identifiers, pool references,
//! addresses, endpoints, payloads, or credentials. Inner kernel/tax errors are
//! reused only through their already-redacted structural classes.

use domain::DomainError;
use execution_preview::BridgeError;
use simulation::{BinSimulationError, ClmmSimulationError, CpmmSimulationErrorClass};
use tax_engine::TaxSafetyError;
use thiserror::Error;

use crate::quote::PoolKindClass;

/// Deterministic routing failure taxonomy.
///
/// Every variant is structural and carries no value-bearing payload. `Internal`
/// carries only a fixed `&'static str` reason chosen at compile time, never a
/// runtime-formatted value.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    /// Domain-level contract failure (already payload-free).
    #[error("{0}")]
    Domain(#[from] DomainError),

    /// Redacted CPMM simulation failure class.
    #[error("{0}")]
    Cpmm(CpmmSimulationErrorClass),

    /// Redacted CLMM simulation failure.
    #[error("{0}")]
    Clmm(ClmmSimulationError),

    /// Redacted Bin/DLMM simulation failure.
    #[error("{0}")]
    Bin(BinSimulationError),

    /// Redacted tax/safety failure.
    #[error("{0}")]
    Tax(#[from] TaxSafetyError),

    /// No candidate produced a viable simulated leg.
    #[error("no viable route")]
    NoViableRoute,

    /// The direct-route planner was called without a tax assessment.
    ///
    /// A missing assessment is not evidence of a zero-tax token, so the planner
    /// fails closed rather than overstating net output.
    #[error("tax assessment required")]
    TaxAssessmentRequired,

    /// The candidate's pool state is stale under the supplied freshness policy.
    #[error("pool state is stale")]
    StaleState,

    /// A pool used by a candidate route is stale under the caller or default policy.
    #[error("pool state is stale")]
    StalePoolState,

    /// The candidate's pool state requires resync (gap or excessive future skew).
    #[error("pool state requires resync")]
    ResyncRequired,

    /// The candidate's pool kind is not supported by the direct-route planner.
    #[error("unsupported pool kind")]
    UnsupportedPoolKind,

    /// Tax composition is unsupported for the Bin/DLMM leg configuration.
    #[error("unsupported bin tax composition")]
    UnsupportedBinTaxComposition,

    /// The composed leg violated exact input/output conservation.
    #[error("input conservation violated")]
    InputConservationViolated,

    /// The candidate list exceeds the configured routing budget.
    #[error("candidate budget exceeded")]
    BudgetExceeded,

    /// The intent input and output assets are identical.
    #[error("input and output assets must differ")]
    SameAssetPair,

    /// The requested hop count is outside `1..=MAX_ROUTE_HOPS`.
    #[error("unsupported hop count")]
    UnsupportedHopCount,

    /// The caller supplied no pool descriptors.
    #[error("pool set is empty")]
    EmptyPoolSet,

    /// A pool descriptor's chain does not match the intent chain.
    #[error("pool chain does not match intent chain")]
    PoolChainMismatch,

    /// A pool descriptor's local state failed its structural contract.
    #[error("pool state is invalid")]
    PoolStateInvalid,

    /// The descriptor set exceeds [`crate::MAX_POOLS_SCANNED`].
    #[error("pool set exceeds the scanned-pool bound")]
    PoolSetTooLarge,

    /// A venue label failed its structural contract.
    #[error("invalid venue label")]
    InvalidVenueLabel,

    /// A pool-reference label failed its structural contract.
    #[error("invalid pool reference label")]
    InvalidPoolRef,

    /// The supplied tax assessment is not fresh under the planner reference time.
    #[error("tax assessment is not fresh")]
    TaxAssessmentNotFresh,

    /// The supplied tax assessment is not bound to this intent's chain or asset.
    #[error("tax assessment does not match the route")]
    TaxAssessmentMismatch,

    /// The realized net output after tax is zero.
    #[error("zero net output")]
    ZeroNetOutput,

    /// The gas-asset to output-asset conversion overflowed or was undefined.
    #[error("gas conversion failed")]
    GasConversionFailed,

    /// The gas estimate asset does not belong to the intent chain.
    #[error("gas estimate chain does not match")]
    GasChainMismatch,

    /// A price-impact value is required but unavailable for a hop.
    #[error("price impact unavailable")]
    ImpactUnavailable,

    /// The composed route price impact exceeds the intent cap.
    #[error("price impact exceeds the intent cap")]
    ImpactExceedsCap,

    /// A hop produced zero output (or a zero effective input).
    #[error("hop produced zero output")]
    ZeroHopOutput,

    /// Checked integer arithmetic overflowed on a routing composition path.
    #[error("amount arithmetic overflowed")]
    AmountOverflow,

    /// A hop simulation kernel failed; only the payload-free pool class is carried.
    #[error("hop simulation failed ({0})")]
    HopSimulationFailed(PoolKindClass),

    /// The constructed [`domain::RouteScore`] violated an internal invariant.
    #[error("route score is inconsistent: {0}")]
    ScoreInconsistent(&'static str),

    /// Every viable candidate failed the locked bridge validation.
    #[error("selected route failed bridge validation ({0})")]
    SelectedRejected(BridgeRejectClass),

    /// An internal invariant failed; the reason is a fixed static string.
    #[error("internal routing error: {0}")]
    Internal(&'static str),
}

/// Payload-free classification of a [`BridgeError`] rejection.
///
/// The locked bridge error is never propagated: only this structural class is
/// retained so no asset, amount, pool, or assessment value can leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeRejectClass {
    /// Canonical domain contract rejection.
    Domain,
    /// CPMM kernel rejection.
    Cpmm,
    /// CLMM kernel rejection.
    Clmm,
    /// Bin/DLMM kernel rejection.
    Bin,
    /// Tax evaluation rejection.
    Tax,
    /// Net-delta conservation/denomination rejection.
    NetDeltaInconsistent,
    /// Trade direction mismatch.
    Direction,
    /// Chain mismatch.
    Chain,
    /// Input-asset mismatch.
    InputAsset,
    /// Output-asset mismatch.
    OutputAsset,
    /// Assessed-asset mismatch.
    AssessedAsset,
    /// Realized delta tax disagrees with the assessment.
    AssessmentDelta,
    /// Assessed tax exceeds the intent cap.
    TaxCap,
    /// Route state freshness is unavailable.
    Freshness,
}

impl std::fmt::Display for BridgeRejectClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Domain => "domain",
            Self::Cpmm => "cpmm",
            Self::Clmm => "clmm",
            Self::Bin => "bin",
            Self::Tax => "tax",
            Self::NetDeltaInconsistent => "net_delta_inconsistent",
            Self::Direction => "direction",
            Self::Chain => "chain",
            Self::InputAsset => "input_asset",
            Self::OutputAsset => "output_asset",
            Self::AssessedAsset => "assessed_asset",
            Self::AssessmentDelta => "assessment_delta",
            Self::TaxCap => "tax_cap",
            Self::Freshness => "freshness",
        };
        f.write_str(label)
    }
}

impl BridgeRejectClass {
    /// Maps a locked [`BridgeError`] into a payload-free rejection class.
    pub fn from_bridge_error(error: &BridgeError) -> Self {
        match error {
            BridgeError::Domain(_) => Self::Domain,
            BridgeError::Cpmm(_) => Self::Cpmm,
            BridgeError::Clmm(_) => Self::Clmm,
            BridgeError::Bin(_) => Self::Bin,
            BridgeError::Tax(_) => Self::Tax,
            BridgeError::NetDeltaInconsistent(_) => Self::NetDeltaInconsistent,
            BridgeError::DirectionMismatch => Self::Direction,
            BridgeError::ChainMismatch => Self::Chain,
            BridgeError::InputAssetMismatch => Self::InputAsset,
            BridgeError::OutputAssetMismatch => Self::OutputAsset,
            BridgeError::AssessedAssetMismatch => Self::AssessedAsset,
            BridgeError::AssessmentDeltaMismatch => Self::AssessmentDelta,
            BridgeError::TaxCapExceeded => Self::TaxCap,
            BridgeError::FreshnessUnavailable => Self::Freshness,
        }
    }
}
