//! P54 — Phase 5 P51b: durable order-event outbox publication.
//!
//! The authoritative per-order transition stream already stores sealed
//! [`crate::journal::OrderTransitionEvent`] records as
//! [`storage::OpaqueEventRecord`]s (ciphertext + coarse bucket + sequence). The
//! outbox **re-publishes that already-sealed ciphertext** as an
//! [`storage::InternalEventEnvelope`]; it never re-seals, so there is no nonce
//! reuse and no new plaintext. Only the *subject* is derived from the post-state
//! status, which requires opening the sealed event in-crate; the opened bytes are
//! not published.
//!
//! The outbox is watermark-based and idempotent:
//! [`crate::journal::DurableLimitOrderStore::publish_pending`] publishes every
//! sealed event after `published_seq`, stopping at the first bus error and
//! advancing an object-only watermark only past accepted events. The
//! `event_id` is deterministic, so a republish after a crash (the same
//! `(order, transition_seq)`) carries the same id and consumers dedupe.
//!
//! Nothing in this module signs, reads a clock, or performs I/O; the store
//! method owns the reads and the injected [`storage::EventBus`] owns delivery.

use domain::OrderStatus;
use storage::{EventSubject, InternalEventEnvelope};

use crate::error::LimitEngineError;
use crate::journal::{derive, to_hex, BlindIndexKey};

/// Domain label for the deterministic outbox event id.
pub const ORDER_EVENT_DOMAIN: &[u8] = b"limit.order.event.v1";

/// Maps a post-transition order status to the bus subject.
///
/// The mapping is total and payload-free: it names only the lifecycle phase the
/// event observes, never an order id, token, wallet, or amount.
///
/// - `Created` -> `OrderCreated`
/// - `Active` / `TriggerCandidate` -> `OrderTriggered`
/// - `Quoting` / `Simulating` / `Executing` -> `ExecutionStarted`
/// - `PartiallyFilled` -> `OrderPartiallyFilled`
/// - `Filled` -> `OrderFilled`
/// - `Cancelled` -> `OrderCancelled`
/// - `Expired` -> `OrderExpired`
/// - `FailedRetryable` / `FailedFinal` -> `OrderFailed`
pub fn event_subject(status: OrderStatus) -> EventSubject {
    match status {
        OrderStatus::Created => EventSubject::OrderCreated,
        OrderStatus::Active | OrderStatus::TriggerCandidate => EventSubject::OrderTriggered,
        OrderStatus::Quoting | OrderStatus::Simulating | OrderStatus::Executing => {
            EventSubject::ExecutionStarted
        }
        OrderStatus::PartiallyFilled => EventSubject::OrderPartiallyFilled,
        OrderStatus::Filled => EventSubject::OrderFilled,
        OrderStatus::Cancelled => EventSubject::OrderCancelled,
        OrderStatus::Expired => EventSubject::OrderExpired,
        OrderStatus::FailedRetryable | OrderStatus::FailedFinal => EventSubject::OrderFailed,
    }
}

/// `hex(HMAC(key, "limit.order.event.v1" || stream || u64be(transition_seq)))`.
///
/// The id is deterministic and restart-stable: the same `(order, transition_seq)`
/// always derives the same opaque id, so a republish after a crash is an
/// at-least-once duplicate that consumers can dedupe. It carries no plaintext.
pub fn order_event_id(
    key: &BlindIndexKey,
    stream: &[u8],
    transition_seq: u64,
) -> Result<String, LimitEngineError> {
    let mac = derive(
        key,
        ORDER_EVENT_DOMAIN,
        &[stream, &transition_seq.to_be_bytes()],
    )?;
    Ok(to_hex(&mac))
}

/// A sealed, ready-to-publish envelope plus its transition sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOrderEvent {
    /// Transition sequence this envelope corresponds to; strictly greater than
    /// the watermark that produced it.
    pub transition_seq: u64,
    /// The envelope to hand to the [`storage::EventBus`]. Its `payload` is the
    /// raw sealed [`crate::journal::OrderTransitionEvent`] ciphertext.
    pub envelope: InternalEventEnvelope,
}
