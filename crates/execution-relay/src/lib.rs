//! P41 — transaction relay and chain submission (one chain, end to end).
//!
//! This crate wires the already-landed private execution pipeline (policy
//! approval → execution preview → Privy signing request) to a *single* chain
//! submission attempt with exactly-once semantics. It is pure and
//! deterministic: there is no wall clock, no network, no RPC, and no real
//! transaction broadcast anywhere on this path. Every chain-facing capability
//! is an injected trait (`ChainSubmissionAdapter`, `SignedPayloadSource`,
//! `SigningBoundary`), and the production defaults fail closed.
//!
//! # Exactly-once / no blind retry (INVARIANTS #9)
//! `ExecutionRelay::execute` claims an attempt in the [`AttemptReservationStore`]
//! *before* it asks the signing boundary for a signature, then calls
//! `ChainSubmissionAdapter::submit` at most once per
//! `(idempotency_key, request_digest)` pair. A duplicate or conflicting attempt
//! never reaches the signer or the adapter, and `reconcile` never submits.
//!
//! # Adaptations forced by the real P40 APIs
//! The P41 spec sketches the relay against `privy::SignedExecutionRef` and a
//! `PrivySigningBoundary` held directly. Two facts about the landed P40 code
//! make the literal sketch untestable and one ordering impossible:
//!
//! 1. `privy::SignedExecutionRef` has a crate-private constructor, so no other
//!    crate (including this one's integration tests) can build one. P41
//!    therefore defines its own shape-equivalent [`plan::SignedExecutionRef`]
//!    and a [`adapter::SigningBoundary`] seam. The production
//!    [`adapter::PrivySigningBoundaryAdapter`] wraps the real
//!    `PrivySigningBoundary` and converts its output faithfully.
//! 2. `PrivySigningBoundary` is a concrete, non-heritable type whose only public
//!    constructor installs an always-unavailable transport, so a working signer
//!    cannot be injected without a P41-owned trait.
//! 3. `SigningRequest::bind` needs the payload digest *before* signing, while
//!    the spec's `SignedPayloadSource::signed_payload` needs a signed reference.
//!    [`plan::SignedPayloadSource`] therefore also exposes
//!    `payload_to_sign`, and the relay claims the reservation *before* signing
//!    (the spec's sign-then-reserve order would double-sign or dead-end on the
//!    real, exactly-once Privy boundary).
//!
//! Every check and error path is fail-closed and payload-free. See
//! `crates/execution-relay/tests/` for the executable specification.

use std::sync::{Mutex, MutexGuard};

pub mod adapter;
pub mod error;
pub mod health;
pub mod plan;
pub mod relay;
pub mod reservation;
pub mod state;

pub use adapter::{
    ChainObservation, ChainSubmissionAdapter, PrivySigningBoundaryAdapter, SigningBoundary,
    SubmissionReceipt, UnavailableChainAdapter,
};
pub use error::RelayError;
pub use health::{ChainHealth, ChainHealthBreaker, ProbeGuard};
pub use plan::{
    SignedExecutionRef, SignedPayload, SignedPayloadSource, SubmitRequest, MAX_SIGNED_PAYLOAD_BYTES,
};
pub use relay::{ExecutionRelay, RelayExecutionInput};
pub use reservation::InMemoryReservationStore;
pub use state::{
    AttemptReservationStore, ObservedFill, RelayOutcome, Reservation, SubmissionState,
};

/// Acquires a mutex, recovering from poisoning.
///
/// The guarded values in this crate are plain maps/records, so a panicking
/// holder cannot leave a torn state: at worst a key is inserted or not. This
/// never panics and is used only for the relay's in-memory bookkeeping.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
