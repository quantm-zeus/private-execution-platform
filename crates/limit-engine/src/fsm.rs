//! The limit-order state machine.
//!
//! [`validate_transition`] defers to the authoritative
//! [`domain::OrderStatus::can_transition_to`] table, so the engine can never
//! drift from the domain. [`apply_transition`] layers the fill ledger, the
//! deadline gate, and monotonic versioning on top of that guard.

use domain::OrderStatus;

use crate::error::LimitEngineError;
use crate::fill::{apply_fill, FillDelta};
use crate::order::StoredLimitOrder;

/// Terminal states are absorbing: no transition leaves them.
pub const fn is_terminal(status: OrderStatus) -> bool {
    matches!(
        status,
        OrderStatus::Filled
            | OrderStatus::Cancelled
            | OrderStatus::Expired
            | OrderStatus::FailedFinal
    )
}

/// Accepts exactly the transitions `domain` permits.
///
/// Returns `Ok(())` if and only if `from.can_transition_to(to)` is true, and
/// [`LimitEngineError::InvalidTransition`] otherwise.
pub fn validate_transition(from: OrderStatus, to: OrderStatus) -> Result<(), LimitEngineError> {
    if from.can_transition_to(to) {
        Ok(())
    } else {
        Err(LimitEngineError::InvalidTransition)
    }
}

/// Applies a validated transition to `current`, returning the next record.
///
/// Rules, in order:
/// 1. `current.order.status -> to` must be permitted.
/// 2. `current` must satisfy the conservation invariant.
/// 3. If `to` is non-terminal, `at_ms >= current.order.expires_at_ms` is
///    rejected as [`LimitEngineError::Expired`].
/// 4. Only `Executing -> PartiallyFilled | Filled` may carry a fill, and both
///    require one. Consuming the fill uses checked arithmetic and must agree
///    with `fill.remaining_after`.
/// 5. `Filled` requires the resulting remaining input to be zero.
/// 6. `version` and `last_transition_seq` increment with checked arithmetic.
///
/// The input record is never mutated.
pub fn apply_transition(
    current: &StoredLimitOrder,
    to: OrderStatus,
    fill: Option<&FillDelta>,
    at_ms: i64,
) -> Result<StoredLimitOrder, LimitEngineError> {
    let from = current.order.status;
    validate_transition(from, to)?;

    if !crate::fill::conservation_holds(current) {
        return Err(LimitEngineError::InvalidOrder);
    }

    if !is_terminal(to) && at_ms >= current.order.expires_at_ms {
        return Err(LimitEngineError::Expired);
    }

    let next = match (to, fill) {
        (OrderStatus::PartiallyFilled | OrderStatus::Filled, Some(fill)) => {
            if from != OrderStatus::Executing {
                return Err(LimitEngineError::FillMismatch);
            }
            apply_fill(current, fill)?
        }
        // A fill-required target with no fill is a protocol error, not a
        // no-op: it must never advance the status.
        (OrderStatus::PartiallyFilled | OrderStatus::Filled, None) => {
            return Err(LimitEngineError::FillMismatch);
        }
        (_, None) => current.clone(),
        (_, Some(_)) => return Err(LimitEngineError::FillMismatch),
    };

    if to == OrderStatus::Filled && !next.order.remaining_input.is_zero() {
        return Err(LimitEngineError::FillMismatch);
    }

    let version = current
        .version
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    let last_transition_seq = current
        .last_transition_seq
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;

    let mut result = next;
    result.order.status = to;
    result.version = version;
    result.last_transition_seq = last_transition_seq;
    Ok(result)
}
