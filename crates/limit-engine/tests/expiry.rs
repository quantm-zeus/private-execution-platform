//! Deadline gating and terminal absorption.

mod support;

use domain::OrderStatus;
use limit_engine::{apply_transition, conservation_holds, FillDelta, LimitEngineError};
use market_types::AtomicAmount;
use support::{stored, ALL_STATUSES, EXPIRY_MS};

fn delta(input: u128, output: u128, remaining_after: u128) -> FillDelta {
    FillDelta {
        simulated_net_input: AtomicAmount::new(input),
        simulated_net_output: AtomicAmount::new(output),
        remaining_after: AtomicAmount::new(remaining_after),
    }
}

#[test]
fn expiry_rejects_non_terminal_targets() {
    let order = stored("o1", OrderStatus::Active, 1_000, 1_000, 0);
    assert_eq!(
        apply_transition(&order, OrderStatus::TriggerCandidate, None, EXPIRY_MS),
        Err(LimitEngineError::Expired)
    );
    assert!(apply_transition(&order, OrderStatus::TriggerCandidate, None, EXPIRY_MS - 1).is_ok());
}

#[test]
fn expiry_transition_is_allowed_at_and_after_the_deadline() {
    let order = stored("o1", OrderStatus::Active, 1_000, 1_000, 0);
    let expired = apply_transition(&order, OrderStatus::Expired, None, EXPIRY_MS).expect("expire");
    assert_eq!(expired.order.status, OrderStatus::Expired);

    let late =
        apply_transition(&order, OrderStatus::Expired, None, EXPIRY_MS + 500).expect("expire late");
    assert_eq!(late.order.status, OrderStatus::Expired);
    assert!(conservation_holds(&late));
}

#[test]
fn expiry_before_the_window_is_rejected() {
    // M2: `-> Expired` may only be recorded once the deadline has been reached.
    // An early `Expired` would be a domain-invalid `ExpiredStatusBeforeWindow`.
    for from in [
        OrderStatus::Created,
        OrderStatus::Active,
        OrderStatus::Executing,
        OrderStatus::PartiallyFilled,
        OrderStatus::FailedRetryable,
    ] {
        let remaining = 1_000;
        let order = stored("o1", from, 1_000, remaining, 0);
        assert_eq!(
            apply_transition(&order, OrderStatus::Expired, None, EXPIRY_MS - 1),
            Err(LimitEngineError::Expired),
            "{from:?} -> Expired before the deadline must be rejected"
        );
        let at_deadline = apply_transition(&order, OrderStatus::Expired, None, EXPIRY_MS)
            .unwrap_or_else(|err| panic!("{from:?} -> Expired at the deadline: {err:?}"));
        assert_eq!(at_deadline.order.status, OrderStatus::Expired);
        assert!(conservation_holds(&at_deadline));
    }
}

#[test]
fn transitions_out_of_expired_are_rejected() {
    let order = stored("o1", OrderStatus::Expired, 1_000, 1_000, 0);
    for to in ALL_STATUSES {
        assert_eq!(
            apply_transition(&order, to, None, EXPIRY_MS),
            Err(LimitEngineError::InvalidTransition),
            "Expired -> {to:?} must be rejected"
        );
    }
}

#[test]
fn terminal_targets_bypass_the_deadline_gate() {
    // Cancelling an open order at (or past) its deadline is permitted; the
    // state is terminal immediately afterwards.
    let order = stored("o1", OrderStatus::Active, 1_000, 1_000, 0);
    assert!(apply_transition(&order, OrderStatus::Cancelled, None, EXPIRY_MS).is_ok());

    // A non-terminal target stays deadline gated, including the retry edge that
    // would start a new attempt.
    let executing = stored("o2", OrderStatus::Executing, 1_000, 1_000, 0);
    assert_eq!(
        apply_transition(&executing, OrderStatus::FailedRetryable, None, EXPIRY_MS),
        Err(LimitEngineError::Expired)
    );
}

#[test]
fn mid_flight_partial_fill_past_expiry_is_coerced_to_expired() {
    // H1: a confirmed in-flight partial fill at/after the deadline is recorded
    // (the ledger advances) and the order closes as `Expired`; it must never
    // persist a domain-invalid `PartiallyFilled`.
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(400, 95, 600);
    let next = apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), EXPIRY_MS)
        .expect("mid-flight fill past expiry");

    assert_eq!(next.order.status, OrderStatus::Expired);
    assert_eq!(next.filled_input, AtomicAmount::new(400));
    assert_eq!(next.order.remaining_input, AtomicAmount::new(600));
    assert!(conservation_holds(&next));
    assert_eq!(next.version, order.version + 1);
    assert_eq!(next.last_transition_seq, order.last_transition_seq + 1);
    // The post-state is domain-valid: `Expired` is legal once the window closed.
    next.order.validate(EXPIRY_MS).expect("domain-valid");
}

#[test]
fn mid_flight_fill_past_expiry_that_completes_the_order_is_filled() {
    // H1 + line 891: when the reconciled fill consumes the remainder the order
    // is `Filled`, not `Expired` with zero remaining.
    let order = stored("o2", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(1_000, 240, 0);
    let next = apply_transition(&order, OrderStatus::Filled, Some(&fill), EXPIRY_MS + 10)
        .expect("completing fill past expiry");
    assert_eq!(next.order.status, OrderStatus::Filled);
    assert_eq!(next.filled_input, AtomicAmount::new(1_000));
    assert!(next.order.remaining_input.is_zero());
    assert!(conservation_holds(&next));

    // The same fill requested against a coerced `Expired` target also lands in
    // `Filled`.
    let coerced = apply_transition(&order, OrderStatus::Expired, Some(&fill), EXPIRY_MS + 10)
        .expect("coerced completing fill");
    assert_eq!(coerced.order.status, OrderStatus::Filled);
    assert_eq!(coerced.filled_input, AtomicAmount::new(1_000));
}

#[test]
fn partially_filled_order_can_record_a_fill_and_expire() {
    // H1: `PartiallyFilled -> Expired` may carry the final in-flight fill.
    let order = stored("o1", OrderStatus::PartiallyFilled, 1_000, 600, 400);
    let fill = delta(200, 50, 400);
    let next = apply_transition(&order, OrderStatus::Expired, Some(&fill), EXPIRY_MS)
        .expect("partial-fill then expire");
    assert_eq!(next.order.status, OrderStatus::Expired);
    assert_eq!(next.filled_input, AtomicAmount::new(600));
    assert_eq!(next.order.remaining_input, AtomicAmount::new(400));
    assert!(conservation_holds(&next));
}

#[test]
fn corrupt_zero_remaining_open_order_is_not_laundered_into_filled() {
    // A conservation-consistent but domain-invalid open record (remaining == 0)
    // must not be converted into a fill-less `Filled` by the expiry path.
    let order = stored("o1", OrderStatus::Active, 1_000, 0, 1_000);
    let next =
        apply_transition(&order, OrderStatus::Expired, None, EXPIRY_MS).expect("expire corrupt");
    assert_eq!(next.order.status, OrderStatus::Expired);
    assert!(next.order.remaining_input.is_zero());
}

#[test]
fn expired_coercion_is_deterministic_and_replayable() {
    // Identical inputs must coerce identically (no clock, no randomness), so
    // the persisted transition replays to the same record.
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(400, 95, 600);
    let first = apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), EXPIRY_MS)
        .expect("first");
    let second = apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), EXPIRY_MS)
        .expect("second");
    assert_eq!(first, second);
}
