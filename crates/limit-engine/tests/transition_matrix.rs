//! Exhaustive order-status matrix and invalid-transition immutability.

mod support;

use domain::OrderStatus;
use limit_engine::{apply_transition, is_terminal, validate_transition, LimitEngineError};
use support::{stored, ALL_STATUSES, OPEN_STATUSES, TERMINAL_STATUSES};

#[test]
fn transition_table_matches_domain_authority() {
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            assert_eq!(
                validate_transition(from, to).is_ok(),
                from.can_transition_to(to),
                "mismatch for {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn terminal_states_are_absorbing_and_open_states_are_not() {
    for status in ALL_STATUSES {
        assert_eq!(
            is_terminal(status),
            TERMINAL_STATUSES.contains(&status),
            "terminal classification for {status:?}"
        );
    }
    for terminal in TERMINAL_STATUSES {
        for to in ALL_STATUSES {
            assert!(
                validate_transition(terminal, to).is_err(),
                "{terminal:?} -> {to:?} must be rejected"
            );
        }
    }
    for open in OPEN_STATUSES {
        assert!(!is_terminal(open), "{open:?} must not be terminal");
    }
}

#[test]
fn invalid_transitions_are_rejected_with_zero_mutation() {
    // Explicit illegal jumps, including every Expired -> any target.
    let mut cases: Vec<(OrderStatus, OrderStatus)> = vec![
        (OrderStatus::Created, OrderStatus::Filled),
        (OrderStatus::Created, OrderStatus::Executing),
        (OrderStatus::Active, OrderStatus::Filled),
    ];
    for terminal in TERMINAL_STATUSES {
        for to in ALL_STATUSES {
            cases.push((terminal, to));
        }
    }

    for (from, to) in cases {
        let remaining = if from == OrderStatus::Filled {
            0
        } else {
            1_000
        };
        let filled = 1_000 - remaining;
        let order = stored("o1", from, 1_000, remaining, filled);
        let snapshot = order.clone();
        assert_eq!(
            apply_transition(&order, to, None, 0),
            Err(LimitEngineError::InvalidTransition),
            "{from:?} -> {to:?}"
        );
        assert_eq!(order, snapshot, "input mutated by {from:?} -> {to:?}");
    }
}

#[test]
fn every_legal_transition_applies_to_a_fresh_order() {
    // Walk the full 12x12 matrix and confirm applying an accepted transition
    // never panics and always yields a record for which the status agrees.
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            if !from.can_transition_to(to) {
                continue;
            }
            let remaining = if from == OrderStatus::Filled {
                0
            } else {
                1_000
            };
            let filled = 1_000 - remaining;
            let order = stored("o1", from, 1_000, remaining, filled);
            // Fill-carrying transitions (Executing -> PartiallyFilled/Filled)
            // and every zero-remaining Filled target are covered in
            // fill_ledger.rs where a delta can be supplied.
            let needs_fill = to == OrderStatus::Filled
                || (from == OrderStatus::Executing && to == OrderStatus::PartiallyFilled);
            if needs_fill {
                continue;
            }
            let result = apply_transition(&order, to, None, 1);
            assert!(result.is_ok(), "{from:?} -> {to:?} failed: {result:?}");
            assert_eq!(result.expect("applied").order.status, to);
        }
    }
}
