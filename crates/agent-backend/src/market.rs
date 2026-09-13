//! Market-order preview delegation for the agent channels (Phase 6 S7).
//!
//! This module turns an already-authorized `preview_market_order` command into
//! the exact, full-net-economics quote the canonical Trading Core would execute:
//! the same bounded single-path router, exact CPMM/CLMM/Bin kernels, tax
//! composition, and locked net-delta bridge that the market execution path uses.
//! A preview moves no funds and performs no signing, submission, or relay call —
//! it is a pure projection of injected local market state.
//!
//! ## Boundaries
//! - **Injected market state.** All pool descriptors, the tax assessment, the
//!   scoring inputs, the freshness policy, and the gas model are supplied by the
//!   caller through [`MarketSnapshotSource`]. Nothing is fetched here: there is
//!   no RPC, network, wall clock, randomness, or filesystem access.
//! - **Fail closed.** An absent snapshot source, a missing/stale assessment, or
//!   any router failure yields the redacted [`MarketPreviewError`]; the backend
//!   maps it to a redacted denial or unavailability. A preview is never guessed.
//! - **Exact economics only.** The returned [`MarketPreview`] carries the locked
//!   [`routing::RouteQuote`] (route plan + full-wallet-debit net delta), the
//!   gas-aware [`domain::RouteScore`], and the enumeration-truncation flag. No
//!   displayed/raw quote is substituted for the exact simulated net delta.
//! - `#![forbid(unsafe_code)]`; no logging, no secrets, no plaintext `Debug` of
//!   amounts, routes, or assets.

use std::fmt;

use domain::{RouteScore, TradeIntent};
use market_types::{AtomicAmount, FreshnessPolicy};
use routing::{
    plan_single_path, GasConversion, GasEstimator, PoolDescriptor, RouteQuote, RouteRequest,
    RoutingError, ScoringInputs,
};
use serde::Serialize;
use tax_engine::TaxAssessment;

/// Exogenous, trusted market data required to quote one intent exactly.
///
/// The values are owned so the source can build them per request without
/// borrowing caller state across the router call.
pub struct MarketSnapshot {
    /// Caller-supplied pool descriptors; router enumeration is bounded over them.
    pub descriptors: Vec<PoolDescriptor>,
    /// Required, asset-bound, fresh tax assessment for the intent's assessed side.
    pub assessment: TaxAssessment,
    /// Caller-supplied risk/latency/reliability score inputs.
    pub scoring: ScoringInputs,
    /// Caller freshness policy for pool/assessment state.
    pub freshness_policy: FreshnessPolicy,
    /// Requested maximum hop count (`1..=routing::MAX_ROUTE_HOPS`).
    pub max_hops: usize,
    /// Asset-bound gas-asset to output-asset conversion, when a gas view exists.
    pub gas_price_in_output: Option<GasConversion>,
}

impl fmt::Debug for MarketSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: pool refs, assets, tax, and policy values are capability
        // semantics and are never rendered.
        formatter
            .debug_struct("MarketSnapshot")
            .field("descriptors", &self.descriptors.len())
            .field("max_hops", &self.max_hops)
            .field("has_gas_conversion", &self.gas_price_in_output.is_some())
            .finish_non_exhaustive()
    }
}

/// Injected source of the trusted market state for one preview.
///
/// Implementations must be deterministic for identical inputs and must not use
/// wall-clock time, RPC, or randomness: the reference timestamp is supplied by
/// the caller.
pub trait MarketSnapshotSource: Send + Sync {
    /// Builds the exact routing inputs for `intent` at `now_ms`.
    ///
    /// A missing, stale, or unavailable market view must return
    /// [`MarketPreviewError::Unavailable`] or [`MarketPreviewError::NoViableRoute`],
    /// never a fabricated snapshot.
    fn snapshot(
        &self,
        intent: &TradeIntent,
        amount_in: AtomicAmount,
        now_ms: i64,
    ) -> Result<MarketSnapshot, MarketPreviewError>;
}

/// Fail-closed default: no market state is available, so no preview is produced.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableMarketSnapshot;

impl MarketSnapshotSource for UnavailableMarketSnapshot {
    fn snapshot(
        &self,
        _intent: &TradeIntent,
        _amount_in: AtomicAmount,
        _now_ms: i64,
    ) -> Result<MarketSnapshot, MarketPreviewError> {
        Err(MarketPreviewError::Unavailable)
    }
}

/// Redacted preview failure taxonomy.
///
/// Neither `Display` nor `Debug` reveals amounts, assets, pools, routes, or
/// assessment values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MarketPreviewError {
    /// The injected market view could not supply a usable snapshot.
    #[error("market preview is unavailable")]
    Unavailable,
    /// A snapshot existed but no candidate produced an exact viable route.
    #[error("no viable market route")]
    NoViableRoute,
}

/// Fully composed exact market preview.
///
/// `quote` is the locked, contract-validated route and full-wallet-debit net
/// delta; `score` is the gas-aware score of the selected candidate; `truncated`
/// records whether bounded enumeration clipped the candidate set.
#[derive(Clone, Serialize)]
pub struct MarketPreview {
    /// Selected route, per-hop exact economics, and normalized net delta.
    pub quote: RouteQuote,
    /// Gas-aware score used to select `quote`.
    pub score: RouteScore,
    /// `true` when a bridge-asset or route-candidate cap clipped enumeration.
    pub truncated: bool,
}

impl fmt::Debug for MarketPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: amounts, assets, pools, and scores stay hidden.
        formatter
            .debug_struct("MarketPreview")
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// Plans the exact single-path preview for an already-built intent.
///
/// The intent must satisfy the locked [`domain::TradeIntent::validate`] contract;
/// the router revalidates it, so a malformed intent fails closed. A router
/// failure with no viable cause maps to [`MarketPreviewError::NoViableRoute`];
/// every other router failure (configuration, domain, or internal) maps to the
/// redacted [`MarketPreviewError::Unavailable`].
pub fn plan_market_preview(
    source: &dyn MarketSnapshotSource,
    gas: Option<&dyn GasEstimator>,
    intent: &TradeIntent,
    amount_in: AtomicAmount,
    now_ms: i64,
) -> Result<MarketPreview, MarketPreviewError> {
    let snapshot = source.snapshot(intent, amount_in, now_ms)?;
    let request = RouteRequest {
        intent,
        descriptors: &snapshot.descriptors,
        amount_in,
        assessment: &snapshot.assessment,
        max_hops: snapshot.max_hops,
        now_ms,
        freshness_policy: &snapshot.freshness_policy,
        scoring: &snapshot.scoring,
        gas,
        gas_price_in_output: snapshot.gas_price_in_output,
    };
    let decision = plan_single_path(&request).map_err(classify)?;
    let score = decision
        .candidates
        .first()
        .map(|candidate| candidate.score.clone())
        .ok_or(MarketPreviewError::NoViableRoute)?;
    match decision.selected {
        Some(quote) => Ok(MarketPreview {
            quote,
            score,
            truncated: decision.truncated,
        }),
        None => Err(MarketPreviewError::NoViableRoute),
    }
}

/// Collapses the router taxonomy into the two redacted preview classes.
///
/// Every "market said no" class (empty/stale/invalid route state, impact or
/// bridge rejection, zero output) is [`MarketPreviewError::NoViableRoute`]; a
/// configuration/domain/internal failure is [`MarketPreviewError::Unavailable`]
/// so an operator misconfiguration is not reported as a tradeable no-route.
fn classify(error: RoutingError) -> MarketPreviewError {
    use RoutingError::*;
    match error {
        NoViableRoute
        | ImpactExceedsCap
        | ImpactUnavailable
        | HopSimulationFailed(_)
        | SelectedRejected(_)
        | ZeroNetOutput
        | ZeroHopOutput
        | StaleState
        | StalePoolState
        | ResyncRequired
        | EmptyPoolSet
        | UnsupportedPoolKind
        | UnsupportedBinTaxComposition
        | PoolChainMismatch
        | PoolStateInvalid => MarketPreviewError::NoViableRoute,
        _ => MarketPreviewError::Unavailable,
    }
}
