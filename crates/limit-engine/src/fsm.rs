//! The limit-order state machine.
//!
//! [`validate_transition`] defers to the authoritative
//! [`domain::OrderStatus::can_transition_to`] table, so the engine can never
//! drift from the domain. [`apply_transition`] layers the fill ledger, the
//! deadline policy, and a full post-state [`domain::LimitOrder::validate`] on
//! top of that guard.

use domain::{DomainError, OrderStatus};

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
/// 1. *Past-expiry partial-fill coercion.* When the caller supplies a
///    [`FillDelta`] for `Executing|PartiallyFilled -> PartiallyFilled` at or
///    after `expires_at_ms`, the post-state is deterministically redirected to
///    `Expired` (the fill is still recorded). `domain::LimitOrder::validate`
///    expiry-gates `PartiallyFilled`, so persisting it past the window would
///    produce a domain-invalid record; the accelerator instead finishes the
///    in-flight fill and closes the order as `Expired` (remainder > 0) or
///    `Filled` (remainder == 0). This coercion is deterministic and replayable.
/// 2. `current.order.status -> to` must be permitted by the domain table
///    (checked against the coerced target).
/// 3. `current` must satisfy the conservation invariant.
/// 4. `-> Expired` requires `at_ms >= expires_at_ms`
///    ([`LimitEngineError::Expired`] otherwise). Every other non-terminal
///    target requires `at_ms < expires_at_ms`. Terminal `Filled`/`Cancelled`/
///    `FailedFinal` may be reached at any time; an `Executing` order is allowed
///    to remain in flight past its deadline.
/// 5. Fills are accepted on `Executing -> PartiallyFilled | Filled | Expired`
///    and `PartiallyFilled -> Filled | Expired`; the first three require a
///    delta and the `Expired` edges accept an optional one (a mid-flight fill
///    reconciled after the deadline). Any other transition carrying a delta is
///    denied.
/// 6. A fill that consumes the last of the input must target `Filled`; a
///    `PartiallyFilled` target with zero remaining is rejected.
/// 7. Partial fills honor the order policy: an all-or-nothing order rejects a
///    partial fill ([`LimitEngineError::PartialFillNotAllowed`]) and a fill
///    that is zero or below `min_fill` is rejected
///    ([`LimitEngineError::AmountBelowMinFill`]).
/// 8. The post-state must satisfy [`domain::LimitOrder::validate`] at `at_ms`;
///    domain failures are mapped to the closest [`LimitEngineError`].
/// 9. `version` and `last_transition_seq` increment with checked arithmetic.
///
/// The input record is never mutated.
pub fn apply_transition(
    current: &StoredLimitOrder,
    to: OrderStatus,
    fill: Option<&FillDelta>,
    at_ms: i64,
) -> Result<StoredLimitOrder, LimitEngineError> {
    let from = current.order.status;
    let requested = to;

    // Rule 1: a confirmed mid-flight partial fill at/after the deadline must
    // not persist a domain-invalid `PartiallyFilled`.
    let mut effective = if requested == OrderStatus::PartiallyFilled
        && fill.is_some()
        && at_ms >= current.order.expires_at_ms
        && matches!(from, OrderStatus::Executing | OrderStatus::PartiallyFilled)
    {
        OrderStatus::Expired
    } else {
        requested
    };

    // Rule 2.
    validate_transition(from, effective)?;

    // Rule 3.
    if !crate::fill::conservation_holds(current) {
        return Err(LimitEngineError::InvalidOrder);
    }

    // Rule 4.
    if effective == OrderStatus::Expired {
        if at_ms < current.order.expires_at_ms {
            return Err(LimitEngineError::Expired);
        }
    } else if !is_terminal(effective) && at_ms >= current.order.expires_at_ms {
        return Err(LimitEngineError::Expired);
    }

    // Rule 5.
    let fill_required = matches!(
        (from, requested),
        (OrderStatus::Executing, OrderStatus::PartiallyFilled)
            | (OrderStatus::Executing, OrderStatus::Filled)
            | (OrderStatus::PartiallyFilled, OrderStatus::Filled)
    );
    let fill_allowed = fill_required
        || matches!(
            (from, requested),
            (
                OrderStatus::Executing | OrderStatus::PartiallyFilled,
                OrderStatus::Expired
            )
        )
        || (matches!(from, OrderStatus::Executing | OrderStatus::PartiallyFilled)
            && requested == OrderStatus::PartiallyFilled);

    let mut next = match fill {
        Some(delta) if fill_allowed => apply_fill(current, delta)?,
        Some(_) => return Err(LimitEngineError::FillMismatch),
        None if fill_required => return Err(LimitEngineError::FillMismatch),
        None => current.clone(),
    };

    // Rule 6.
    if requested == OrderStatus::PartiallyFilled && next.order.remaining_input.is_zero() {
        return Err(LimitEngineError::FillMismatch);
    }
    if requested == OrderStatus::Filled && !next.order.remaining_input.is_zero() {
        return Err(LimitEngineError::FillMismatch);
    }
    // Accelerator line 891: a reconciled fill that completed the order lands in
    // `Filled`, never in `Expired` with zero remaining. Only sources that may
    // legally reach `Filled` participate, so a corrupt zero-remaining record
    // cannot be laundered into a fill-less `Filled`.
    if effective == OrderStatus::Expired
        && fill.is_some()
        && matches!(from, OrderStatus::Executing | OrderStatus::PartiallyFilled)
        && next.order.remaining_input.is_zero()
    {
        effective = OrderStatus::Filled;
    }

    // Rule 7.
    if let Some(delta) = fill {
        if effective == OrderStatus::PartiallyFilled && !current.order.allow_partial_fill {
            return Err(LimitEngineError::PartialFillNotAllowed);
        }
        let consumed = delta.simulated_net_input.get();
        if consumed == 0 || consumed < current.order.min_fill.get() {
            return Err(LimitEngineError::AmountBelowMinFill);
        }
    }

    // Rule 8.
    next.order.status = effective;
    next.order.validate(at_ms).map_err(map_domain_error)?;

    // Rule 9.
    let version = current
        .version
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    let last_transition_seq = current
        .last_transition_seq
        .checked_add(1)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    next.version = version;
    next.last_transition_seq = last_transition_seq;
    Ok(next)
}

/// Maps a post-state [`DomainError`] to the closest engine error.
///
/// The engine error enum is a small, redacted contract; semantically distinct
/// domain failures therefore fold onto an existing variant rather than growing
/// the public surface.
fn map_domain_error(error: DomainError) -> LimitEngineError {
    match error {
        DomainError::InvalidRemainingInput => LimitEngineError::InvalidOrder,
        DomainError::InvalidMinFill => LimitEngineError::AmountBelowMinFill,
        DomainError::NonPartialFillMismatch => LimitEngineError::PartialFillNotAllowed,
        DomainError::Expired | DomainError::ExpiredStatusBeforeWindow => LimitEngineError::Expired,
        _ => LimitEngineError::InvalidOrder,
    }
}
