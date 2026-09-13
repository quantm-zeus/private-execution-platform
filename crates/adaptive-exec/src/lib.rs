//! # Adaptive TWAP execution (Phase 8)
//!
//! A pure, deterministic chunker for large orders. Instead of a fixed cron
//! schedule, [`AdaptiveTwap`] recalculates each slice from the plan, the running
//! progress, and a market observation (realized slippage, liquidity recovery,
//! volatility): it accelerates after observed recovery, decelerates on
//! deterioration/volatility, and falls back to a fixed cron interval only when
//! observations are missing or stale.
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
//! - **Pure and offline.** No clock, no I/O, no randomness; `now_ms` is explicit
//!   and the engine performs no arithmetic that can panic.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

mod engine;
mod plan;

pub use engine::{AdaptiveTwap, ChunkReason, HaltReason, TwapDecision};
pub use plan::{MarketObservation, TwapPlan, TwapPolicy, TwapState};
