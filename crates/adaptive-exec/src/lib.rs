//! # Adaptive execution (Phase 8)
//!
//! Two pure, deterministic cores for large/uncertain orders:
//!
//! - **[`AdaptiveTwap`]**: instead of a fixed cron schedule, it recalculates each
//!   slice from the plan, the running progress, and a market observation (realized
//!   slippage, liquidity recovery, volatility): it accelerates after observed
//!   recovery, decelerates on deterioration/volatility, and falls back to a fixed
//!   cron interval only when observations are missing or stale.
//! - **[`SolverCompetition`]**: queries injected RFQ solvers, validates and ranks
//!   their quotes, and accepts an external solver only when its net output beats
//!   the local route by the request's required margin.
//!
//! ## Invariants
//! - **The user's hard slippage maximum is absolute.** A realized slippage above
//!   `TwapPlan::max_slippage_bps` halts the plan; the engine never trades through
//!   it.
//! - **Conservation.** Every chunk is `<=` the remaining input and `>= 1`; the
//!   final slice consumes the entire remainder, so a plan always completes
//!   exactly.
//! - **Bounded output.** Every non-final chunk is clamped to
//!   `[min_chunk, max_chunk]`.
//! - **Best execution.** An external RFQ solver is chosen only when it beats the
//!   local baseline by the required bps margin using exact integer arithmetic;
//!   otherwise the caller uses the local route.
//! - **Pure and offline.** No hidden clock, no I/O, no randomness; `now_ms` is
//!   explicit and no arithmetic can panic.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod analytics;
mod engine;
mod plan;
mod rfq;

pub use analytics::{
    analyze, AnalyticsError, Delta, DeltaDirection, ExecutionAnalytics, ExecutionEstimate,
    RealizedExecution,
};
pub use engine::{AdaptiveTwap, ChunkReason, HaltReason, TwapDecision};
pub use plan::{MarketObservation, TwapPlan, TwapPolicy, TwapState};
pub use rfq::{
    CompetitionOutcome, NoWinnerReason, RfqRequest, RfqSide, Solver, SolverCompetition,
    SolverError, SolverQuote, SolverQuoteResult,
};
