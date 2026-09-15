#![forbid(unsafe_code)]
//! P89 — pure dynamic slippage recommendation core.
//!
//! `docs/PRD.md` requires that a dynamic slippage recommendation may consider
//! volatility, state latency, route uncertainty, and confirmation latency but
//! must **never** exceed the user's hard maximum. This crate implements exactly
//! that recommendation, and nothing else.
//!
//! The core is deliberately minimal and offline:
//!
//! - Pure integer arithmetic: no floating point, no clock, no randomness, no
//!   I/O, and no hidden state. Identical inputs always produce identical
//!   output.
//! - Every risk signal is caller-supplied; the engine invents no data.
//! - The recommendation is clamped to the caller's hard maximum and can never
//!   return a value above it, including a hard maximum of zero.
//! - The output is monotone non-decreasing in every signal and in both policy
//!   values.
//! - [`TRADING_ENABLED`] stays `false`: this crate only *recommends* a bound
//!   and has no order, signing, relay, or network capability.
//!
//! # Scope
//! In scope for P89:
//! - [`SlippageSignals`], [`SlippagePolicy`], [`recommend_slippage`], and the
//!   redacted [`RiskError`].
//!
//! Out of scope: execution wiring, persistence, `max_slippage` enforcement in
//! the order path, and any locked-contract change.

pub mod slippage;

pub use slippage::{recommend_slippage, RiskError, SlippagePolicy, SlippageSignals};

/// Global trading capability gate.
///
/// This crate performs no trading; the flag exists so the pure recommendation
/// core stays consistent with the rest of the fail-closed platform.
pub const TRADING_ENABLED: bool = false;
