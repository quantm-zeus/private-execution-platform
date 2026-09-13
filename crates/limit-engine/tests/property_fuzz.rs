//! P49 — deterministic property/fuzz sweeps for the order FSM and fill ledger.
//!
//! A seeded splitmix64 generator drives thousands of random (legal and illegal)
//! transition/fill sequences. Every accepted transition must preserve the
//! fill-ledger conservation invariant, advance the version/sequence by exactly
//! one, be a member of an independently hardcoded edge oracle, and leave a
//! domain-valid post-state. Terminal states must be fully absorbing.

mod support;

use domain::OrderStatus;
use limit_engine::{
    apply_transition, conservation_holds, is_terminal, FillDelta, LimitEngineError,
    StoredLimitOrder,
};
use market_types::AtomicAmount;

use support::{stored, ALL_STATUSES, EXPIRY_MS};

/// Deterministic splitmix64 generator (well-mixed output bits).
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: u128, hi: u128) -> u128 {
        if hi <= lo {
            return lo;
        }
        lo + (u128::from(self.next_u64()) % (hi - lo))
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next_u64() as usize) % items.len()]
    }
}

/// Independent hardcoded copy of the authoritative status graph.
///
/// This must never be derived from `OrderStatus::can_transition_to`: comparing
/// the two is what catches an edge being added to, or removed from, the domain
/// table.
const EXPECTED_EDGES: &[(OrderStatus, OrderStatus)] = &[
    (OrderStatus::Created, OrderStatus::Active),
    (OrderStatus::Created, OrderStatus::Cancelled),
    (OrderStatus::Created, OrderStatus::Expired),
    (OrderStatus::Active, OrderStatus::TriggerCandidate),
    (OrderStatus::Active, OrderStatus::Cancelled),
    (OrderStatus::Active, OrderStatus::Expired),
    (OrderStatus::TriggerCandidate, OrderStatus::Active),
    (OrderStatus::TriggerCandidate, OrderStatus::Quoting),
    (OrderStatus::TriggerCandidate, OrderStatus::Cancelled),
    (OrderStatus::TriggerCandidate, OrderStatus::Expired),
    (OrderStatus::Quoting, OrderStatus::Simulating),
    (OrderStatus::Quoting, OrderStatus::Active),
    (OrderStatus::Quoting, OrderStatus::FailedRetryable),
    (OrderStatus::Quoting, OrderStatus::Cancelled),
    (OrderStatus::Quoting, OrderStatus::Expired),
    (OrderStatus::Simulating, OrderStatus::Executing),
    (OrderStatus::Simulating, OrderStatus::Active),
    (OrderStatus::Simulating, OrderStatus::FailedRetryable),
    (OrderStatus::Simulating, OrderStatus::Cancelled),
    (OrderStatus::Simulating, OrderStatus::Expired),
    (OrderStatus::Executing, OrderStatus::PartiallyFilled),
    (OrderStatus::Executing, OrderStatus::Filled),
    (OrderStatus::Executing, OrderStatus::FailedRetryable),
    (OrderStatus::Executing, OrderStatus::FailedFinal),
    (OrderStatus::Executing, OrderStatus::Expired),
    (OrderStatus::PartiallyFilled, OrderStatus::Active),
    (OrderStatus::PartiallyFilled, OrderStatus::TriggerCandidate),
    (OrderStatus::PartiallyFilled, OrderStatus::Executing),
    (OrderStatus::PartiallyFilled, OrderStatus::Filled),
    (OrderStatus::PartiallyFilled, OrderStatus::Cancelled),
    (OrderStatus::PartiallyFilled, OrderStatus::Expired),
    (OrderStatus::FailedRetryable, OrderStatus::Active),
    (OrderStatus::FailedRetryable, OrderStatus::TriggerCandidate),
    (OrderStatus::FailedRetryable, OrderStatus::FailedFinal),
    (OrderStatus::FailedRetryable, OrderStatus::Cancelled),
    (OrderStatus::FailedRetryable, OrderStatus::Expired),
];

fn expected_edge(from: OrderStatus, to: OrderStatus) -> bool {
    EXPECTED_EDGES.contains(&(from, to))
}

#[test]
fn the_independent_edge_oracle_matches_the_domain_table() {
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            assert_eq!(
                from.can_transition_to(to),
                expected_edge(from, to),
                "domain table disagrees with the independent oracle for {from:?} -> {to:?}"
            );
        }
    }
}

fn legal_targets(from: OrderStatus) -> Vec<OrderStatus> {
    ALL_STATUSES
        .iter()
        .copied()
        .filter(|to| from.can_transition_to(*to))
        .collect()
}

/// Builds the exact fill required by a `-> PartiallyFilled | Filled` edge.
fn required_fill(rng: &mut Lcg, order: &StoredLimitOrder, to: OrderStatus) -> Option<FillDelta> {
    let rem = order.order.remaining_input.get();
    let min = order.order.min_fill.get().max(1);
    let net_input = if to == OrderStatus::Filled {
        rem
    } else {
        let max_partial = rem.saturating_sub(min);
        if max_partial < min {
            return None;
        }
        rng.range(min, max_partial + 1)
    };
    let remaining_after = rem.checked_sub(net_input)?;
    Some(FillDelta {
        simulated_net_input: AtomicAmount::new(net_input),
        simulated_net_output: AtomicAmount::new(net_input / 2 + 1),
        remaining_after: AtomicAmount::new(remaining_after),
    })
}

fn fill(net_input: u128, remaining_after: u128) -> FillDelta {
    FillDelta {
        simulated_net_input: AtomicAmount::new(net_input),
        simulated_net_output: AtomicAmount::new(net_input / 2 + 1),
        remaining_after: AtomicAmount::new(remaining_after),
    }
}

#[test]
fn random_transition_sequences_never_violate_the_fsm_or_ledger() {
    let mut rng = Lcg::new(0xF5_0000);
    let mut applied = 0u32;
    let mut partials = 0u32;
    let mut filled = 0u32;
    let mut terminals = 0u32;
    for case in 0..10_000u32 {
        let mut order = stored("fuzz", OrderStatus::Created, 10_000, 10_000, 0);
        for _ in 0..40 {
            if is_terminal(order.order.status) {
                for to in ALL_STATUSES {
                    assert!(
                        apply_transition(&order, to, None, EXPIRY_MS - 1_000).is_err(),
                        "terminal state accepted a transition; case {case}"
                    );
                }
                break;
            }
            let legal = legal_targets(order.order.status);
            // Bias toward forward (non-terminal) progress so the sweep reaches
            // Executing/PartiallyFilled/Filled; still inject an illegal target
            // sometimes and occasionally take a legal terminal edge.
            let forward: Vec<OrderStatus> = legal
                .iter()
                .copied()
                .filter(|to| !is_terminal(*to))
                .collect();
            let to = if rng.range(0, 10) == 0 {
                *rng.pick(&ALL_STATUSES)
            } else if !forward.is_empty() && rng.range(0, 10) != 0 {
                *rng.pick(&forward)
            } else {
                *rng.pick(&legal)
            };
            let at_ms = if rng.range(0, 4) == 0 {
                EXPIRY_MS + 1_000
            } else {
                EXPIRY_MS - 1_000
            };
            let fill_required = matches!(
                (order.order.status, to),
                (OrderStatus::Executing, OrderStatus::PartiallyFilled)
                    | (OrderStatus::Executing, OrderStatus::Filled)
                    | (OrderStatus::PartiallyFilled, OrderStatus::Filled)
            );
            let candidate = if fill_required {
                required_fill(&mut rng, &order, to)
            } else {
                None
            };
            if let Ok(next) = apply_transition(&order, to, candidate.as_ref(), at_ms) {
                applied += 1;
                match next.order.status {
                    OrderStatus::PartiallyFilled => partials += 1,
                    OrderStatus::Filled => filled += 1,
                    OrderStatus::Cancelled | OrderStatus::Expired | OrderStatus::FailedFinal => {
                        terminals += 1
                    }
                    _ => {}
                }
                assert!(conservation_holds(&next), "conservation broke; case {case}");
                assert_eq!(next.version, order.version + 1, "case {case}");
                assert_eq!(
                    next.last_transition_seq,
                    order.last_transition_seq + 1,
                    "case {case}"
                );
                // Independent oracle, not a restatement of `can_transition_to`.
                assert!(
                    expected_edge(order.order.status, next.order.status),
                    "accepted an edge outside the oracle; case {case}"
                );
                assert!(
                    next.order.validate(at_ms).is_ok(),
                    "post-state failed domain validation; case {case}"
                );
                order = next;
            }
        }
    }
    assert!(
        applied > 5_000,
        "sweep applied too few transitions: {applied}"
    );
    // Non-vacuity: the sweep must actually reach the fill and terminal paths.
    assert!(partials > 0, "sweep never exercised a partial fill");
    assert!(filled > 0, "sweep never exercised a fill-to-completion");
    assert!(terminals > 0, "sweep never exercised a terminal transition");
}

#[test]
fn a_partial_fill_never_leaves_an_unfillable_remainder() {
    let mut rng = Lcg::new(0xA11_CE5);
    let mut applied = 0u32;
    for case in 0..20_000u32 {
        let max = rng.range(2, 1_000_000);
        let min = rng.range(1, max / 2 + 1).max(1);
        let mut order = stored("partial", OrderStatus::Executing, max, max, 0);
        order.order.min_fill = AtomicAmount::new(min);
        let rem = order.order.remaining_input.get();
        // `min <= max/2` by construction, so `max_partial >= min` always.
        let max_partial = rem.saturating_sub(min);
        let net = rng.range(min, max_partial + 1);
        let candidate = fill(net, rem - net);
        let next = apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&candidate),
            EXPIRY_MS - 1_000,
        )
        .expect("a remainder-viable partial fill must apply");
        applied += 1;
        assert!(conservation_holds(&next), "case {case}");
        assert!(next.order.remaining_input.get() >= min, "case {case}");
        assert!(next.order.remaining_input.get() < rem, "case {case}");
        assert!(
            next.order.validate(EXPIRY_MS - 1_000).is_ok(),
            "case {case}"
        );
    }
    assert!(
        applied > 0,
        "no remainder-viable partial fill was exercised"
    );
}

#[test]
fn fill_policy_rejects_unsafe_below_minimum_and_inconsistent_fills() {
    let mut order = stored("negative", OrderStatus::Executing, 1_000, 1_000, 0);
    order.order.min_fill = AtomicAmount::new(100);
    let at_ms = EXPIRY_MS - 1_000;

    // A partial fill that leaves less than `min_fill` behind must be rejected.
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&fill(950, 50)),
            at_ms
        ),
        Err(LimitEngineError::AmountBelowMinFill)
    );
    // A zero fill is below the minimum.
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&fill(0, 1_000)),
            at_ms
        ),
        Err(LimitEngineError::AmountBelowMinFill)
    );
    // A fill larger than the remainder underflows the ledger.
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&fill(1_001, 0)),
            at_ms
        ),
        Err(LimitEngineError::RemainingUnderflow)
    );
    // A fill whose declared remainder disagrees with the arithmetic is rejected.
    assert_eq!(
        apply_transition(
            &order,
            OrderStatus::PartiallyFilled,
            Some(&fill(500, 400)),
            at_ms
        ),
        Err(LimitEngineError::FillMismatch)
    );
    // The boundary case (remainder exactly `min_fill`) is accepted.
    assert!(apply_transition(
        &order,
        OrderStatus::PartiallyFilled,
        Some(&fill(900, 100)),
        at_ms
    )
    .is_ok());
    // Completing the order is accepted.
    assert!(apply_transition(&order, OrderStatus::Filled, Some(&fill(1_000, 0)), at_ms).is_ok());
}
