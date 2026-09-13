//! Deadline gating and terminal absorption.

mod support;

use domain::OrderStatus;
use limit_engine::{apply_transition, conservation_holds, LimitEngineError};
use support::{stored, ALL_STATUSES, EXPIRY_MS};

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
    // Interpretation: the deadline gate covers transitions whose target is
    // non-terminal. Cancelling an open order at (or past) its deadline is
    // therefore still permitted; the state is terminal immediately afterwards.
    let order = stored("o1", OrderStatus::Active, 1_000, 1_000, 0);
    assert!(apply_transition(&order, OrderStatus::Cancelled, None, EXPIRY_MS).is_ok());

    // A non-terminal target stays deadline gated.
    let executing = stored("o2", OrderStatus::Executing, 1_000, 1_000, 0);
    assert_eq!(
        apply_transition(&executing, OrderStatus::FailedRetryable, None, EXPIRY_MS),
        Err(LimitEngineError::Expired)
    );
}
