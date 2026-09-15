//! P88 — actual-execution analytics mapping for the limit-engine fill path.
//!
//! This module is a pure, deterministic projection: it maps one bound attempt's
//! exact simulated estimate and one realized fill onto the adaptive-exec
//! [`ExecutionAnalytics`] core. It performs no I/O, reads no clock, uses no
//! randomness or floating point, and never panics. It deliberately does not log,
//! render, or persist any amount: the returned record is a derived, redacted
//! comparison, and the caller decides whether to hand it to an injected sink.
//!
//! # Redaction
//! The mapped record is exactly [`adaptive_exec::ExecutionAnalytics`], whose
//! `Debug` renders only derived bps and directions. Neither the returned record
//! nor [`fill_analytics`] itself exposes the assets or amounts it compared.

use adaptive_exec::{analyze, ExecutionAnalytics, ExecutionEstimate, RealizedExecution};

use crate::attempt::{BoundAttempt, RealizedFill};

pub use adaptive_exec::{ExecutionAnalyticsSink, NoopExecutionAnalyticsSink};

/// Maps a bound attempt's exact estimate and a realized fill to the redacted
/// analytics record.
///
/// The estimate is `bound.preview`'s simulated net input/output and the realized
/// side is `fill`'s net input/output; both sides bind to `bound.intent`'s asset
/// pair. Gas and tax baselines are intentionally absent on both sides. Returns
/// `None` when the comparison is undefined (for example a zero expected output)
/// or the assets do not bind; it never panics.
pub fn fill_analytics(bound: &BoundAttempt, fill: &RealizedFill) -> Option<ExecutionAnalytics> {
    let estimate = ExecutionEstimate {
        token_in: bound.intent.token_in.clone(),
        token_out: bound.intent.token_out.clone(),
        amount_in: bound.preview.simulated_net_input.amount.get(),
        expected_amount_out: bound.preview.simulated_net_output.amount.get(),
        expected_gas: None,
        expected_tax: None,
    };
    let realized = RealizedExecution {
        token_in: bound.intent.token_in.clone(),
        token_out: bound.intent.token_out.clone(),
        amount_in: fill.net_input.get(),
        amount_out: fill.net_output.get(),
        gas_paid: None,
        tax_paid: None,
    };
    analyze(&estimate, &realized).ok()
}
