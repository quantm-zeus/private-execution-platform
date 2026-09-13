//! Serde round-trips for the persisted records.

mod support;

use domain::OrderStatus;
use limit_engine::{
    apply_transition, conservation_holds, FillDelta, OrderTransition, StoredLimitOrder,
};
use market_types::AtomicAmount;
use support::stored;

#[test]
fn stored_order_round_trips() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let encoded = serde_json::to_string(&order).expect("encode");
    let decoded: StoredLimitOrder = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, order);
}

#[test]
fn transition_round_trips_and_derives_a_matching_record() {
    let order = stored("o1", OrderStatus::Executing, 1_000, 1_000, 0);
    let delta = FillDelta {
        simulated_net_input: AtomicAmount::new(400),
        simulated_net_output: AtomicAmount::new(95),
        remaining_after: AtomicAmount::new(600),
    };
    let next =
        apply_transition(&order, OrderStatus::PartiallyFilled, Some(&delta), 7).expect("apply");
    let transition = OrderTransition {
        order_id: order.order.id.clone(),
        from: order.order.status,
        to: OrderStatus::PartiallyFilled,
        transition_seq: 1,
        fill: Some(delta),
        at_ms: 7,
    };

    let encoded = serde_json::to_string(&transition).expect("encode");
    let decoded: OrderTransition = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, transition);
    assert_eq!(next.order.status, OrderStatus::PartiallyFilled);
    assert!(conservation_holds(&next));
}
