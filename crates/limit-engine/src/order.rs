//! Persisted limit-order records.
//!
//! These are engine-owned wrappers around `domain::LimitOrder`; the domain type
//! stays the authoritative shape and the wrapper adds the version, idempotency,
//! attempt, and ledger metadata the L1 core needs.

use domain::{IdempotencyKey, IntentId, LimitOrder, OrderId, OrderStatus};
use market_types::AtomicAmount;
use serde::{Deserialize, Serialize};

use crate::fill::FillDelta;

/// Schema version stamped on every newly created record.
pub const DEFAULT_SCHEMA_VERSION: u16 = 1;

/// A durable limit-order record: the domain order plus engine bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredLimitOrder {
    /// Persisted record schema version.
    pub schema_version: u16,
    /// Compare-and-swap version; monotonic, incremented once per transition.
    pub version: u64,
    /// Authoritative domain order (carries status and remaining input).
    pub order: LimitOrder,
    /// Intent that produced the order.
    pub order_intent_id: IntentId,
    /// Idempotency key for order creation.
    pub order_idempotency_key: IdempotencyKey,
    /// Nonce bound to the order.
    pub nonce: u64,
    /// Attempt sequence; owned by later execution slices.
    pub attempt_seq: u64,
    /// Input consumed across all applied fills.
    pub filled_input: AtomicAmount,
    /// Sequence of the last applied transition; `0` before any transition.
    pub last_transition_seq: u64,
    /// Earliest eligible time for the next attempt, when set by later slices.
    pub next_eligible_at_ms: Option<i64>,
}

/// A single validated order-state transition, as appended to a store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderTransition {
    /// Order the transition applies to.
    pub order_id: OrderId,
    /// Status the order held before the transition.
    pub from: OrderStatus,
    /// Status the order holds after the transition.
    pub to: OrderStatus,
    /// Monotonic transition sequence, one greater than the previous one.
    pub transition_seq: u64,
    /// Fill carried by this transition, if any.
    pub fill: Option<FillDelta>,
    /// Explicit caller-supplied time in milliseconds.
    pub at_ms: i64,
}
