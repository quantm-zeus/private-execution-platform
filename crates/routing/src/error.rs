//! Redacted, payload-free routing errors.
//!
//! Neither [`Display`](std::fmt::Display) nor [`Debug`](std::fmt::Debug) of any
//! [`RoutingError`] variant reveals amounts, asset identifiers, pool references,
//! addresses, endpoints, payloads, or credentials. Inner kernel/tax errors are
//! reused only through their already-redacted structural classes.

use domain::DomainError;
use simulation::{BinSimulationError, ClmmSimulationError, CpmmSimulationErrorClass};
use tax_engine::TaxSafetyError;
use thiserror::Error;

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

    /// The candidate's pool state is stale under the supplied freshness policy.
    #[error("pool state is stale")]
    StaleState,

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

    /// An internal invariant failed; the reason is a fixed static string.
    #[error("internal routing error: {0}")]
    Internal(&'static str),
}
