#![forbid(unsafe_code)]
//! P44 — Phase 5 L1: limit-order state machine and fill ledger.
//!
//! This crate is the pure, deterministic L1 core for limit orders. It owns the
//! order-status transition guard, the fill ledger arithmetic, and a persistence
//! *contract* (a trait plus an in-memory fake). There is no clock, no RPC, no
//! network, no encryption, no relay, and no signing anywhere on this path.
//!
//! # Scope
//! In scope for L1:
//! - [`validate_transition`] / [`apply_transition`] / [`apply_fill`] over
//!   [`StoredLimitOrder`], matching the authoritative
//!   [`domain::OrderStatus::can_transition_to`] table exactly.
//! - A [`LimitOrderStore`] trait with idempotent `create` / `append_transition`
//!   semantics and an in-memory implementation.
//! - A redacted, payload-free [`LimitEngineError`].
//!
//! The P45 L2 slice adds the pure trigger and maximum-safe-fill search in
//! [`trigger`]: an injected [`trigger::QuoteProvider`], an explicit `now_ms`,
//! and the exact simulated **net** limit check (never chart/gross price).
//! Bisection is bounded ([`trigger::MAX_SEARCH_STEPS`]) and is followed by a
//! bounded safety-confirmation ladder ([`trigger::MAX_FALLBACK_STEPS`]) so a
//! non-executable chunk is never returned.
//!
//! Explicitly out of scope (later Phase 5 slices): the attempt journal, the
//! execution relay, event publication, and signing. P46 adds the durable
//! encrypted order store and recovery in [`journal`]: an
//! [`journal::OrderKeyProvider`]-keyed, `OpaqueStore`-backed implementation of
//! [`LimitOrderStore`] plus [`journal::recover_open`].
//!
//! # Adaptations forced by the real APIs
//! The P44 spec is a sketch; the landed APIs differ in these ways and the
//! semantics are preserved:
//!
//! 1. `domain::LimitOrder` names the deadline `expires_at_ms`, not `expiry`, so
//!    the expiry gate compares `at_ms >= current.order.expires_at_ms`.
//! 2. `market_types::AtomicAmount` exposes only `new`/`get`/`is_zero`/`ZERO`.
//!    All ledger arithmetic is therefore done on `u128` with explicit
//!    `checked_add`/`checked_sub` and rebuilt through `AtomicAmount::new`,
//!    mapping an underflow to `RemainingUnderflow` and an overflow to
//!    `ArithmeticOverflow`.
//! 3. The spec lists `chain-types` as a dependency but the L1 surface names no
//!    chain type directly; it is kept as a declared workspace dependency.
//! 4. Expiry is a deadline on *starting* work, not on finishing an in-flight
//!    attempt. `-> Expired` requires `at_ms >= expires_at_ms`
//!    (`ExpiredStatusBeforeWindow` in domain terms), while every other
//!    non-terminal target requires the window to still be open. Terminal
//!    `Filled`/`Cancelled`/`FailedFinal` may be reached at any time, and an
//!    `Executing` order may remain in flight past the deadline.
//! 5. A confirmed mid-flight partial fill at/after the deadline cannot persist
//!    a domain-invalid `PartiallyFilled` (domain expiry-gates it), so
//!    [`apply_transition`] deterministically redirects the post-state to
//!    `Expired` (recording the fill) when the remainder is non-zero, and to
//!    `Filled` when the fill completed the order.
//! 6. The store is a normal public `InMemoryLimitOrderStore`, not a
//!    `#[cfg(test)]` item, so the integration tests under `tests/` can exercise
//!    the trait contract directly. It carries no production dependency.
//! 7. `create` rejects a record that violates the fill-ledger conservation
//!    invariant; a repeated key is idempotent only for an identical creation
//!    payload, and a different order id or content under the same key is
//!    [`LimitEngineError::IdempotencyConflict`]. `append_transition` requires a
//!    contiguous `transition_seq == last_transition_seq + 1` in addition to the
//!    version CAS; both are store-integrity checks the spec's trait sketch
//!    implies but does not spell out.
//! 8. A transition that carries a [`fill::FillDelta`] is accepted on
//!    `Executing -> PartiallyFilled | Filled | Expired` and
//!    `PartiallyFilled -> Filled | Expired`; the non-`Expired` edges require a
//!    delta and the `Expired` edges accept an optional one. A `PartiallyFilled`
//!    target with zero remaining, an all-or-nothing partial fill, and a fill
//!    that is zero or below `min_fill` are all rejected fail-closed.

pub mod attempt;
pub mod error;
pub mod fill;
pub mod fsm;
pub mod journal;
pub mod order;
pub mod prepare;
pub mod store;
pub mod trigger;

pub use attempt::{
    attempt_intent_id, attempt_key, attempt_stream_blind_index, ApprovalSnapshot, AttemptPhase,
    BoundAttempt, OrderAttemptEvent, ATTEMPT_SCHEMA_VERSION,
};
pub use error::LimitEngineError;
pub use fill::{apply_fill, conservation_holds, FillDelta};
pub use fsm::{apply_transition, is_terminal, validate_transition};
pub use journal::{
    class_blind_index, object_id, order_id_for_creation, owner_blind_index, recover_in_flight,
    recover_open, stream_blind_index, AttemptAppendOutcome, AttemptRecoveryOutcome, BlindIndexKey,
    DurableLimitOrderStore, DurableOrderRecord, InFlightAttempt, OrderKeyMaterial,
    OrderKeyProvider, OrderTransitionEvent, QuarantinedOrder, RecoveryOutcome,
    UnavailableOrderKeyProvider,
};
pub use order::{OrderTransition, StoredLimitOrder, DEFAULT_SCHEMA_VERSION};
pub use prepare::{
    prepare_attempt, AttemptTrust, PrepareAttemptInput, PreparedAttempt, PreparedAttemptOutcome,
};
pub use store::{AppendOutcome, CreateOutcome, InMemoryLimitOrderStore, LimitOrderStore};
pub use trigger::{
    attempt_is_executable, evaluate_trigger, max_safe_fill, QuoteOutcome, QuoteProvider,
    QuotedAttempt, TriggerDecision, TriggerOutcome, MAX_FALLBACK_STEPS, MAX_SEARCH_STEPS,
};
