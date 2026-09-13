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
//! Explicitly out of scope (later Phase 5 slices L2–L6): the trigger loop, the
//! quote provider, the max-safe-fill search, durable encrypted persistence, the
//! execution relay, and signing.
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
//! 4. "Reject expiry for any non-terminal transition" is interpreted as a
//!    transition whose *target* is non-terminal (the spec's own vocabulary
//!    lists `Filled`/`Cancelled`/`Expired`/`FailedFinal` as the terminal
//!    states). Transitioning an open order to one of those terminal states is
//!    therefore allowed at or after expiry; every transition to a non-terminal
//!    state is rejected with [`LimitEngineError::Expired`].
//! 5. The store is a normal public `InMemoryLimitOrderStore`, not a
//!    `#[cfg(test)]` item, so the integration tests under `tests/` can exercise
//!    the trait contract directly. It carries no production dependency.

pub mod error;
pub mod fill;
pub mod fsm;
pub mod order;
pub mod store;

pub use error::LimitEngineError;
pub use fill::{apply_fill, conservation_holds, FillDelta};
pub use fsm::{apply_transition, is_terminal, validate_transition};
pub use order::{OrderTransition, StoredLimitOrder, DEFAULT_SCHEMA_VERSION};
pub use store::{AppendOutcome, CreateOutcome, InMemoryLimitOrderStore, LimitOrderStore};
