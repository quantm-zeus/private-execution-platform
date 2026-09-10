//! Deterministic weighted request/cost budget tracker.
//!
//! Enforces:
//! - Deterministic token-bucket replenishment based on injected clock time.
//! - Operation cost weights deduction without floating-point drift.
//! - Structured degradation on budget exhaustion without altering trading execution authority.
//! - Pressure detection for lower-priority request shedding.

use crate::meta::DegradedReason;

const SCALE: u64 = 1_000_000;

#[derive(Clone, Debug)]
pub struct ProviderBudget {
    max_capacity: u32,
    available_scaled: u64,
    refill_per_sec: u32,
    last_replenished_ms: u64,
}

impl ProviderBudget {
    pub fn new(max_capacity: u32, refill_per_sec: u32, start_time_ms: u64) -> Self {
        Self {
            max_capacity,
            available_scaled: (max_capacity as u64) * SCALE,
            refill_per_sec,
            last_replenished_ms: start_time_ms,
        }
    }

    /// Replenishes the budget up to `max_capacity` based on elapsed time.
    pub fn replenish(&mut self, now_ms: u64) {
        if now_ms <= self.last_replenished_ms {
            return;
        }

        let elapsed_ms = now_ms - self.last_replenished_ms;
        let replenish = (elapsed_ms * (self.refill_per_sec as u64) * SCALE) / 1_000;
        let max_scaled = (self.max_capacity as u64) * SCALE;

        self.available_scaled = (self.available_scaled + replenish).min(max_scaled);
        self.last_replenished_ms = now_ms;
    }

    /// Attempts to consume `cost` units from the budget.
    ///
    /// If sufficient budget exists, deducts the cost and returns `Ok(())`.
    /// If exhausted, returns `Err(DegradedReason::BudgetExhausted)`.
    pub fn try_consume(&mut self, now_ms: u64, cost: u32) -> Result<(), DegradedReason> {
        self.replenish(now_ms);

        let cost_scaled = (cost as u64) * SCALE;
        if self.available_scaled >= cost_scaled {
            self.available_scaled -= cost_scaled;
            Ok(())
        } else {
            Err(DegradedReason::BudgetExhausted)
        }
    }

    /// Returns the currently available whole budget units.
    pub fn available_units(&self, now_ms: u64) -> u32 {
        let mut clone = self.clone();
        clone.replenish(now_ms);
        (clone.available_scaled / SCALE) as u32
    }

    /// Checks if the budget is under pressure (remaining capacity < 25%).
    pub fn is_under_pressure(&self, now_ms: u64) -> bool {
        let mut clone = self.clone();
        clone.replenish(now_ms);
        let max_scaled = (self.max_capacity as u64) * SCALE;
        clone.available_scaled < (max_scaled / 4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_consumption_and_replenishment() {
        let mut budget = ProviderBudget::new(10, 2, 1_000);
        assert_eq!(budget.available_units(1_000), 10);

        // Consume 6 units (e.g. expensive query)
        assert!(budget.try_consume(1_000, 6).is_ok());
        assert_eq!(budget.available_units(1_000), 4);

        // Try to consume 5 units (fails, only 4 left)
        assert_eq!(
            budget.try_consume(1_000, 5),
            Err(DegradedReason::BudgetExhausted)
        );
        assert_eq!(budget.available_units(1_000), 4);

        // Advance 1 second (1,000 ms) -> refills 2 units
        budget.replenish(2_000);
        assert_eq!(budget.available_units(2_000), 6);

        // Now consuming 5 units succeeds
        assert!(budget.try_consume(2_000, 5).is_ok());
        assert_eq!(budget.available_units(2_000), 1);
    }

    #[test]
    fn test_budget_pressure_detection() {
        let mut budget = ProviderBudget::new(100, 10, 0);
        assert!(!budget.is_under_pressure(0));

        // Consume 80 units -> remaining 20 units (< 25%)
        assert!(budget.try_consume(0, 80).is_ok());
        assert!(budget.is_under_pressure(0));

        // Advance 1 second -> refills 10 units -> remaining 30 units (>= 25%)
        assert!(!budget.is_under_pressure(1_000));
    }
}
