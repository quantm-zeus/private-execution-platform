//! Fill-ledger conservation and checked arithmetic.

mod support;

use domain::OrderStatus;
use limit_engine::{apply_fill, apply_transition, conservation_holds, FillDelta, LimitEngineError};
use market_types::AtomicAmount;
use support::{stored, EXPIRY_MS};

fn delta(input: u128, output: u128, remaining_after: u128) -> FillDelta {
    FillDelta {
        simulated_net_input: AtomicAmount::new(input),
        simulated_net_output: AtomicAmount::new(output),
        remaining_after: AtomicAmount::new(remaining_after),
    }
}

#[test]
fn partial_fill_conserves_input_and_advances_version_and_sequence() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(400, 95, 600);
    let next = apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), 10)
        .expect("partial fill");

    assert_eq!(next.order.status, OrderStatus::PartiallyFilled);
    assert_eq!(next.filled_input, AtomicAmount::new(400));
    assert_eq!(next.order.remaining_input, AtomicAmount::new(600));
    assert!(conservation_holds(&next));
    assert_eq!(next.version, order.version + 1);
    assert_eq!(next.last_transition_seq, order.last_transition_seq + 1);
    assert_eq!(order.filled_input, AtomicAmount::ZERO, "input mutated");
    assert_eq!(order.order.remaining_input, AtomicAmount::new(1_000));
}

#[test]
fn full_fill_requires_zero_remaining_and_conserves() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(1_000, 240, 0);
    let next = apply_transition(&order, OrderStatus::Filled, Some(&fill), 10).expect("full fill");

    assert_eq!(next.order.status, OrderStatus::Filled);
    assert_eq!(next.filled_input, AtomicAmount::new(1_000));
    assert!(next.order.remaining_input.is_zero());
    assert!(conservation_holds(&next));
}

#[test]
fn fill_chain_never_breaks_conservation() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let first = apply_fill(&order, &delta(300, 70, 700)).expect("first fill");
    assert!(conservation_holds(&first));

    let mut second = first.clone();
    second.order.status = OrderStatus::Executing;
    let second = apply_fill(&second, &delta(700, 180, 0)).expect("second fill");
    assert!(conservation_holds(&second));
    assert_eq!(second.filled_input, AtomicAmount::new(1_000));
    assert!(second.order.remaining_input.is_zero());
}

#[test]
fn remaining_after_disagreement_is_fill_mismatch() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(400, 95, 599);
    assert_eq!(
        apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), 10),
        Err(LimitEngineError::FillMismatch)
    );
}

#[test]
fn filled_target_with_nonzero_remaining_is_rejected() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(400, 95, 600);
    assert_eq!(
        apply_transition(&order, OrderStatus::Filled, Some(&fill), 10),
        Err(LimitEngineError::FillMismatch)
    );
}

#[test]
fn fill_beyond_remaining_underflows() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let fill = delta(1_001, 240, 0);
    assert_eq!(
        apply_transition(&order, OrderStatus::PartiallyFilled, Some(&fill), 10),
        Err(LimitEngineError::RemainingUnderflow)
    );
}

#[test]
fn fill_on_a_non_fill_transition_is_rejected() {
    let order = stored("o1", OrderStatus::Active, 1_000, 1_000, 0);
    let fill = delta(100, 25, 900);
    assert_eq!(
        apply_transition(&order, OrderStatus::TriggerCandidate, Some(&fill), 10),
        Err(LimitEngineError::FillMismatch)
    );
}

#[test]
fn fill_required_targets_reject_a_missing_fill() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    for to in [OrderStatus::PartiallyFilled, OrderStatus::Filled] {
        let snapshot = order.clone();
        assert_eq!(
            apply_transition(&order, to, None, 10),
            Err(LimitEngineError::FillMismatch),
            "{to:?} without a fill must be rejected"
        );
        assert_eq!(order, snapshot, "input mutated by {to:?} without a fill");
    }

    // Even a fully consumed order cannot reach Filled without a delta.
    let drained = stored("o1", OrderStatus::Executing, 1_000, 0, 1_000);
    assert_eq!(
        apply_transition(&drained, OrderStatus::Filled, None, 10),
        Err(LimitEngineError::FillMismatch)
    );
}

#[test]
fn partially_filled_to_filled_without_a_fill_cannot_complete() {
    let order = stored("o1", OrderStatus::PartiallyFilled, 1_000, 600, 400);
    assert_eq!(
        apply_transition(&order, OrderStatus::Filled, None, 10),
        Err(LimitEngineError::FillMismatch)
    );
}

#[test]
fn partially_filled_to_filled_with_a_fill_completes() {
    // M1: finishing the remainder is a legal fill edge.
    let order = stored("o1", OrderStatus::PartiallyFilled, 1_000, 600, 400);
    let next = apply_transition(&order, OrderStatus::Filled, Some(&delta(600, 150, 0)), 10)
        .expect("finish remainder");
    assert_eq!(next.order.status, OrderStatus::Filled);
    assert_eq!(next.filled_input, AtomicAmount::new(1_000));
    assert!(next.order.remaining_input.is_zero());
    assert!(conservation_holds(&next));
}

#[test]
fn partially_filled_target_with_zero_remaining_is_rejected() {
    // H2: a fill consuming all remaining must target `Filled`, never
    // `PartiallyFilled` (accelerator line 739).
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let snapshot = order.clone();
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(1_000, 240, 0)),
            10
        ),
        Err(LimitEngineError::FillMismatch)
    );
    assert_eq!(
        order, snapshot,
        "input mutated by a zero-remaining partial fill"
    );

    // The same delta targets `Filled` successfully.
    let filled = apply_transition(&order, OrderStatus::Filled, Some(&delta(1_000, 240, 0)), 10)
        .expect("full fill");
    assert_eq!(filled.order.status, OrderStatus::Filled);
}

#[test]
fn partial_fill_on_all_or_nothing_order_is_rejected() {
    // M3: an all-or-nothing order may only fill in full.
    let mut order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    order.order.allow_partial_fill = false;
    order.order.min_fill = AtomicAmount::new(1_000);
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(400, 95, 600)),
            10
        ),
        Err(LimitEngineError::PartialFillNotAllowed)
    );
    // A full fill is still accepted.
    let filled = apply_transition(&order, OrderStatus::Filled, Some(&delta(1_000, 240, 0)), 10)
        .expect("all-or-nothing full fill");
    assert_eq!(filled.order.status, OrderStatus::Filled);
}

#[test]
fn fill_below_min_fill_is_rejected() {
    let mut order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    order.order.min_fill = AtomicAmount::new(100);
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(50, 10, 950)),
            10
        ),
        Err(LimitEngineError::AmountBelowMinFill)
    );
}

#[test]
fn zero_input_fill_is_rejected() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(0, 0, 1_000)),
            10
        ),
        Err(LimitEngineError::AmountBelowMinFill)
    );
}

#[test]
fn partial_fill_leaving_a_remainder_below_min_fill_is_rejected() {
    // Accelerator line 871: a non-full chunk must leave a fillable remainder.
    let mut order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    order.order.min_fill = AtomicAmount::new(400);
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(700, 160, 300)),
            10
        ),
        Err(LimitEngineError::AmountBelowMinFill)
    );
}

#[test]
fn inconsistent_stored_ledger_is_invalid_order() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 900, 0);
    assert!(!conservation_holds(&order));
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&delta(50, 10, 850)),
            10
        ),
        Err(LimitEngineError::InvalidOrder)
    );
}

#[test]
fn version_overflow_is_checked() {
    let mut order = stored("o1", OrderStatus::Created, 1_000, 1_000, 0);
    order.version = u64::MAX;
    assert_eq!(
        apply_transition(&order, OrderStatus::Active, None, 10),
        Err(LimitEngineError::ArithmeticOverflow)
    );
}

#[test]
fn transition_sequence_overflow_is_checked() {
    let mut order = stored("o1", OrderStatus::Created, 1_000, 1_000, 0);
    order.last_transition_seq = u64::MAX;
    assert_eq!(
        apply_transition(&order, OrderStatus::Active, None, 10),
        Err(LimitEngineError::ArithmeticOverflow)
    );
}

#[test]
fn apply_fill_leaves_status_untouched() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let next = apply_fill(&order, &delta(250, 60, 750)).expect("fill");
    assert_eq!(next.order.status, OrderStatus::Executing);
    assert_eq!(
        next.version, order.version,
        "apply_fill must not bump version"
    );
    assert!(next.order.expires_at_ms <= EXPIRY_MS);
}
