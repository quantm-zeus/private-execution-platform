//! Deterministic in-memory reservation store.
//!
//! This is a normal, publicly constructible implementation intended for tests,
//! local composition, and as a reference for a durable store. It is not a
//! persistence layer: state is process-local and lost on restart.

use std::collections::HashMap;
use std::sync::Mutex;

use domain::IdempotencyKey;
use privy::RequestDigest;

use crate::error::RelayError;
use crate::state::{AttemptReservationStore, RelayOutcome, Reservation};

#[derive(Clone)]
struct StoreEntry {
    digest: [u8; 32],
    outcome: Option<RelayOutcome>,
}

/// Process-local reservation store keyed by idempotency key.
#[derive(Default)]
pub struct InMemoryReservationStore {
    entries: Mutex<HashMap<IdempotencyKey, StoreEntry>>,
}

impl InMemoryReservationStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl AttemptReservationStore for InMemoryReservationStore {
    fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let digest = *digest.as_bytes();
        let mut entries = crate::lock(&self.entries);
        match entries.get(key) {
            Some(entry) if entry.digest == digest => Ok(Reservation::AlreadyReserved(
                entry.outcome.clone().unwrap_or(RelayOutcome::Reserved),
            )),
            Some(_) => Ok(Reservation::Conflict),
            None => {
                entries.insert(
                    key.clone(),
                    StoreEntry {
                        digest,
                        outcome: None,
                    },
                );
                Ok(Reservation::Reserved)
            }
        }
    }

    fn record_signed(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        let digest = *digest.as_bytes();
        let mut entries = crate::lock(&self.entries);
        match entries.get_mut(key) {
            Some(entry) if entry.digest == digest => {
                if entry.outcome.is_none() {
                    entry.outcome = Some(RelayOutcome::Signed);
                }
                Ok(())
            }
            _ => Err(RelayError::ReservationUnavailable),
        }
    }

    fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        let digest = *digest.as_bytes();
        let mut entries = crate::lock(&self.entries);
        match entries.get_mut(key) {
            Some(entry) if entry.digest == digest => {
                entry.outcome = Some(outcome);
                Ok(())
            }
            _ => Err(RelayError::ReservationUnavailable),
        }
    }
}
