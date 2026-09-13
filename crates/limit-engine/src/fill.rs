//! Fill-delta ledger arithmetic.
//!
//! The only invariant this module maintains is the conservation of an order's
//! input: `filled_input + order.remaining_input == order.max_input.amount` at
//! all times. Every operation is checked; no operation can panic.

use market_types::AtomicAmount;
use serde::{Deserialize, Serialize};

use crate::error::LimitEngineError;
use crate::order::StoredLimitOrder;

/// One simulated fill for a limit-order attempt.
///
/// `simulated_net_input` is the input actually consumed by the route and
/// `remaining_after` is the order's remaining input once the fill is applied.
/// `simulated_net_output` is informational for the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillDelta {
    /// Net input token amount consumed by the simulated route.
    pub simulated_net_input: AtomicAmount,
    /// Net output token amount produced by the simulated route.
    pub simulated_net_output: AtomicAmount,
    /// Remaining input the order must hold after the fill is applied.
    pub remaining_after: AtomicAmount,
}

/// Applies `fill` to `order`, consuming its input and advancing the filled
/// ledger with checked arithmetic.
///
/// Returns [`LimitEngineError::RemainingUnderflow`] when the fill consumes more
/// than the order has left, [`LimitEngineError::FillMismatch`] when
/// `fill.remaining_after` disagrees with the arithmetic or the conservation
/// invariant breaks, and [`LimitEngineError::ArithmeticOverflow`] on checked
/// overflow. The order's status is left untouched.
pub fn apply_fill(
    order: &StoredLimitOrder,
    fill: &FillDelta,
) -> Result<StoredLimitOrder, LimitEngineError> {
    let remaining = order.order.remaining_input;
    let consumed = fill.simulated_net_input;

    let new_remaining = remaining
        .get()
        .checked_sub(consumed.get())
        .ok_or(LimitEngineError::RemainingUnderflow)?;
    let new_remaining = AtomicAmount::new(new_remaining);
    if fill.remaining_after != new_remaining {
        return Err(LimitEngineError::FillMismatch);
    }

    let new_filled = order
        .filled_input
        .get()
        .checked_add(consumed.get())
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    let new_filled = AtomicAmount::new(new_filled);

    // Conservation: filled + remaining must always equal max_input.
    if new_filled.get().checked_add(new_remaining.get()) != Some(order.order.max_input.amount.get())
    {
        return Err(LimitEngineError::FillMismatch);
    }

    let mut next = order.clone();
    next.filled_input = new_filled;
    next.order.remaining_input = new_remaining;
    Ok(next)
}

/// Reports whether `order` satisfies `filled_input + remaining == max_input`.
pub fn conservation_holds(order: &StoredLimitOrder) -> bool {
    order
        .filled_input
        .get()
        .checked_add(order.order.remaining_input.get())
        == Some(order.order.max_input.amount.get())
}
