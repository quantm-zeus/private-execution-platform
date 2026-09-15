//! P79 service wiring for the read-only market reconcile loop.
//!
//! This module turns the P78 [`MarketReconcileLoop`] into a runnable service
//! task: a strictly parsed `RECONCILE_INTERVAL_MS`, a graceful shutdown-aware
//! tick, and [`spawn_reconcile_loop`] to drive passes in the background.
//!
//! # Read-only
//! The spawned loop only calls the typed `MarketExecutionOutcome`-returning
//! reconcile seam and mutates the local
//! [`MarketAttemptRegistry`](crate::composition::MarketAttemptRegistry). It never
//! calls `execute`, signs, submits, or reserves.
//!
//! # `RECONCILE_INTERVAL_MS`
//! [`parse_reconcile_interval_ms`] is strict: only non-empty ASCII digits are
//! accepted; `"0"` and an absent value disable the loop; every other spelling
//! (including `"+5"`, `" 5"`, `"1e3"`, `"-1"`, and overflow) is a startup
//! error. A non-Unicode environment value must refuse startup at the call site.
//!
//! # Shutdown
//! [`ShutdownTick`] selects between the interval sleep and a
//! [`tokio::sync::watch`] change, so setting the watch to `true` (or dropping
//! the sender) stops the loop promptly instead of after the next full interval.
//!
//! `#![forbid(unsafe_code)]`; no logging and no payload-bearing `Debug`.

#![forbid(unsafe_code)]

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::composition::{
    run_reconcile_loop, system_now_ms, MarketReconcileLoop, MarketReconcileTarget,
    ReconcileRunReport, ReconcileSchedule, ReconcileTick, MIN_TICK_INTERVAL,
};

/// Production reconcile schedule: at most 32 attempts per pass, unbounded
/// passes (stopped by shutdown).
///
/// Every pending attempt is still examined within
/// `ceil(n / max_per_pass)` passes because the loop rotates its start cursor.
pub const RECONCILE_SCHEDULE: ReconcileSchedule = ReconcileSchedule {
    max_per_pass: 32,
    max_passes: 0,
};

/// Error parsing the reconcile-interval configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileConfigError {
    /// The value was not absent, `"0"`, or a non-empty ASCII-digit integer.
    InvalidInterval,
}

impl std::fmt::Display for ReconcileConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInterval => formatter.write_str("invalid reconcile interval"),
        }
    }
}

impl std::error::Error for ReconcileConfigError {}

/// Largest accepted reconcile interval, so a valid-but-absurd value cannot
/// silently disable the loop.
pub const MAX_RECONCILE_INTERVAL_MS: u64 = 86_400_000;

/// Strictly parses `RECONCILE_INTERVAL_MS`.
///
/// - `None` (absent) -> `Ok(None)` (loop disabled).
/// - `"0"` -> `Ok(None)` (explicitly disabled).
/// - non-empty ASCII digits only, `<= MAX_RECONCILE_INTERVAL_MS` ->
///   `Ok(Some(Duration::from_millis(n)))`.
/// - anything else, including an empty string, a sign, whitespace, scientific
///   notation, an out-of-range value, or `u64` overflow ->
///   `Err(ReconcileConfigError::InvalidInterval)`.
pub fn parse_reconcile_interval_ms(
    value: Option<&str>,
) -> Result<Option<Duration>, ReconcileConfigError> {
    let raw = match value {
        None => return Ok(None),
        Some(raw) => raw,
    };
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ReconcileConfigError::InvalidInterval);
    }
    let millis: u64 = raw
        .parse()
        .map_err(|_| ReconcileConfigError::InvalidInterval)?;
    if millis == 0 {
        return Ok(None);
    }
    if millis > MAX_RECONCILE_INTERVAL_MS {
        return Err(ReconcileConfigError::InvalidInterval);
    }
    Ok(Some(Duration::from_millis(millis)))
}

/// Shutdown-aware reconcile tick.
///
/// Waits `interval` (floored at `MIN_TICK_INTERVAL`) between passes, but returns
/// `None` promptly when the shutdown watch is already set, changes to `true`, or
/// has a dropped sender.
pub struct ShutdownTick {
    interval: Duration,
    shutdown: watch::Receiver<bool>,
}

impl ShutdownTick {
    /// Builds a tick that waits `interval` between passes and stops on shutdown.
    pub fn new(interval: Duration, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            interval: interval.max(MIN_TICK_INTERVAL),
            shutdown,
        }
    }
}

impl std::fmt::Debug for ShutdownTick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShutdownTick")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ReconcileTick for ShutdownTick {
    async fn next_tick(&mut self) -> Option<i64> {
        if *self.shutdown.borrow() {
            return None;
        }
        tokio::select! {
            _ = tokio::time::sleep(self.interval) => Some(system_now_ms()),
            _ = self.shutdown.changed() => None,
        }
    }
}

/// Spawns the read-only reconcile loop until `shutdown` is set.
///
/// The returned handle resolves to the accumulated [`ReconcileRunReport`] once
/// the loop stops; setting the watch to `true` (or dropping the sender) stops it
/// promptly.
pub fn spawn_reconcile_loop<T: MarketReconcileTarget + 'static>(
    reconcile: MarketReconcileLoop<T>,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<ReconcileRunReport> {
    tokio::spawn(async move {
        let mut tick = ShutdownTick::new(interval, shutdown);
        run_reconcile_loop(&reconcile, &mut tick).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reconcile_interval_is_strict() {
        assert_eq!(parse_reconcile_interval_ms(None), Ok(None));
        assert_eq!(parse_reconcile_interval_ms(Some("0")), Ok(None));
        assert_eq!(
            parse_reconcile_interval_ms(Some("250")),
            Ok(Some(Duration::from_millis(250)))
        );
        assert_eq!(
            parse_reconcile_interval_ms(Some("86400000")),
            Ok(Some(Duration::from_millis(MAX_RECONCILE_INTERVAL_MS)))
        );
        for invalid in ["", "+5", " 5", "1e3", "-1", "5 ", "0x10", "1_000"] {
            assert_eq!(
                parse_reconcile_interval_ms(Some(invalid)),
                Err(ReconcileConfigError::InvalidInterval),
                "value {invalid:?} must be rejected"
            );
        }
        // An out-of-range value must not silently disable the loop.
        assert_eq!(
            parse_reconcile_interval_ms(Some("86400001")),
            Err(ReconcileConfigError::InvalidInterval)
        );
        assert_eq!(
            parse_reconcile_interval_ms(Some("18446744073709551615")),
            Err(ReconcileConfigError::InvalidInterval)
        );
        // `u64` overflow is not a valid interval.
        assert_eq!(
            parse_reconcile_interval_ms(Some("18446744073709551616")),
            Err(ReconcileConfigError::InvalidInterval)
        );
        assert_eq!(
            format!("{:?}", ReconcileConfigError::InvalidInterval),
            "InvalidInterval"
        );
    }

    #[tokio::test]
    async fn shutdown_tick_stops_promptly() {
        // Already set: returns `None` without waiting the interval.
        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send shutdown");
        let mut tick = ShutdownTick::new(Duration::from_secs(3_600), rx);
        let stopped = tokio::time::timeout(Duration::from_millis(200), tick.next_tick()).await;
        assert_eq!(stopped.expect("already-shutdown tick is immediate"), None);

        // Set while sleeping: wakes promptly instead of after the full interval.
        let (tx, rx) = watch::channel(false);
        let mut tick = ShutdownTick::new(Duration::from_secs(3_600), rx);
        let handle = tokio::spawn(async move { tick.next_tick().await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send(true).expect("send shutdown");
        let joined = tokio::time::timeout(Duration::from_millis(500), handle).await;
        assert_eq!(
            joined.expect("tick joins").expect("task did not panic"),
            None
        );

        // A dropped sender also stops the loop.
        let (tx, rx) = watch::channel(false);
        let mut tick = ShutdownTick::new(Duration::from_secs(3_600), rx);
        drop(tx);
        let stopped = tokio::time::timeout(Duration::from_millis(200), tick.next_tick()).await;
        assert_eq!(stopped.expect("dropped-sender tick is immediate"), None);
    }

    #[test]
    fn shutdown_tick_debug_is_interval_only() {
        let (_tx, rx) = watch::channel(false);
        let tick = ShutdownTick::new(Duration::from_millis(250), rx);
        assert_eq!(format!("{tick:?}"), "ShutdownTick { interval: 250ms, .. }");
    }
}
