//! Deterministic time abstraction for Provider Intelligence Broker.
//!
//! Enforces:
//! - Complete decoupling from wall-clock sleep in acceptance tests.
//! - Monotonic, overflow-safe millisecond timestamps.
//! - Thread-safe manual time advancement for deterministic test scenarios.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Abstract clock trait returning monotonic timestamps in milliseconds.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time in milliseconds.
    fn now_ms(&self) -> u64;
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

/// System clock backed by the host's actual wall/system time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Deterministic, thread-safe manual clock for acceptance and timing tests.
#[derive(Debug)]
pub struct ManualClock {
    now_ms: AtomicU64,
}

impl ManualClock {
    /// Creates a manual clock initialized to the given millisecond timestamp.
    pub fn new(initial_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(initial_ms),
        }
    }

    /// Sets the manual clock to an exact millisecond timestamp.
    pub fn set_ms(&self, ms: u64) {
        self.now_ms.store(ms, Ordering::Release);
    }

    /// Advances the manual clock forward by `delta_ms` milliseconds.
    pub fn advance_ms(&self, delta_ms: u64) -> u64 {
        self.now_ms.fetch_add(delta_ms, Ordering::AcqRel) + delta_ms
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(1_000)
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_clock_advance() {
        let clock = ManualClock::new(100);
        assert_eq!(clock.now_ms(), 100);

        let new_time = clock.advance_ms(50);
        assert_eq!(new_time, 150);
        assert_eq!(clock.now_ms(), 150);

        clock.set_ms(1_000);
        assert_eq!(clock.now_ms(), 1_000);
    }

    #[test]
    fn test_arc_clock_dispatch() {
        let clock = Arc::new(ManualClock::new(500));
        assert_eq!(clock.now_ms(), 500);
        clock.advance_ms(250);
        assert_eq!(clock.now_ms(), 750);
    }
}
