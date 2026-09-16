//! Reservation stores.
//!
//! [`InMemoryReservationStore`] is the minimal process-local store used by unit
//! tests. [`DeterministicDurableStore`] implements the full durable lifecycle and
//! the [`DurableAttemptStore`] marker: it is a deterministic reference adapter
//! for integration tests, local composition, and as the behavioral spec a
//! concrete Postgres adapter must match. Neither is a production database
//! adapter; a durable production adapter lives outside this crate.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use domain::{IdempotencyKey, UserId, WalletRef};
use privy::{ProviderIdempotencyId, RequestDigest};

use crate::error::RelayError;
use crate::plan::SubmitRequest;
use crate::state::{
    AttemptBinding, AttemptReservationStore, AttemptStatus, DurableAttemptStore, DurableSubmission,
    RelayOutcome, Reservation,
};

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

#[async_trait]
impl AttemptReservationStore for InMemoryReservationStore {
    async fn reserve(
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

    async fn record_signed(
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

    async fn record_outcome(
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

/// Owner/workspace used by the legacy [`AttemptReservationStore::reserve`]
/// entry point, which carries no owning identity.
const LEGACY_OWNER: &str = "attempt-store-legacy-owner";
const LEGACY_WORKSPACE: &str = "attempt-store-legacy-workspace";

#[derive(Clone, PartialEq, Eq, Hash)]
struct DurableKey {
    owner: String,
    workspace: String,
    idempotency_key: IdempotencyKey,
}

impl DurableKey {
    fn from_binding(binding: &AttemptBinding) -> Self {
        Self {
            owner: binding.owner().as_str().to_string(),
            workspace: binding.workspace().as_str().to_string(),
            idempotency_key: binding.idempotency_key().clone(),
        }
    }
}

#[derive(Clone)]
struct DurableEntry {
    digest: [u8; 32],
    status: AttemptStatus,
    provider_idempotency: Option<String>,
    signed_reference: Option<String>,
    submission: Option<DurableSubmission>,
    outcome: Option<RelayOutcome>,
}

/// Deterministic durable attempt store for tests and local composition.
///
/// It enforces the same unique identity `(owner, workspace, idempotency_key)`
/// plus request digest as a database adapter, persists every lifecycle
/// transition, and keeps the bound submission so a **new relay over the same
/// store** can reconcile after a simulated restart. State is still in-process,
/// so this is a reference adapter, not a production persistence layer.
#[derive(Default)]
pub struct DeterministicDurableStore {
    attempts: Mutex<HashMap<DurableKey, DurableEntry>>,
}

impl DeterministicDurableStore {
    /// Creates an empty durable reference store.
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    fn legacy_binding(key: &IdempotencyKey) -> Result<AttemptBinding, RelayError> {
        let owner = UserId::new(LEGACY_OWNER).map_err(|_| RelayError::StoreUnavailable)?;
        let workspace =
            WalletRef::new(LEGACY_WORKSPACE).map_err(|_| RelayError::StoreUnavailable)?;
        let intent_id =
            domain::IntentId::new(LEGACY_OWNER).map_err(|_| RelayError::StoreUnavailable)?;
        Ok(AttemptBinding::new(
            owner,
            workspace,
            key.clone(),
            intent_id,
            chain_types::ChainId::Base,
        ))
    }

    /// Returns the persisted status for `binding`, when the attempt exists.
    pub fn status(&self, binding: &AttemptBinding) -> Option<AttemptStatus> {
        let key = DurableKey::from_binding(binding);
        crate::lock(&self.attempts)
            .get(&key)
            .map(|entry| entry.status)
    }

    /// Returns the persisted provider idempotency identifier, when present.
    pub fn provider_idempotency(&self, binding: &AttemptBinding) -> Option<String> {
        let key = DurableKey::from_binding(binding);
        crate::lock(&self.attempts)
            .get(&key)
            .and_then(|entry| entry.provider_idempotency.clone())
    }

    /// Number of distinct attempts retained (the primary key cardinality).
    pub fn len(&self) -> usize {
        crate::lock(&self.attempts).len()
    }

    /// True when no attempt is retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies `mutate` to the unique entry matching `key` + `digest`.
    ///
    /// Returns [`RelayError::ReservationUnavailable`] when no entry matches and
    /// [`RelayError::StoreUnavailable`] when the match is ambiguous, so a
    /// transition never lands on the wrong attempt.
    fn with_entry<F>(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        mutate: F,
    ) -> Result<(), RelayError>
    where
        F: FnOnce(&mut DurableEntry),
    {
        let digest = *digest.as_bytes();
        let mut attempts = crate::lock(&self.attempts);
        let mut matched: Option<&mut DurableEntry> = None;
        for (stored_key, entry) in attempts.iter_mut() {
            if stored_key.idempotency_key == *key && entry.digest == digest {
                if matched.is_some() {
                    return Err(RelayError::StoreUnavailable);
                }
                matched = Some(entry);
            }
        }
        match matched {
            Some(entry) => {
                mutate(entry);
                Ok(())
            }
            None => Err(RelayError::ReservationUnavailable),
        }
    }

    /// Finds the unique entry for `key` regardless of owner/workspace.
    fn unique_by_key(&self, key: &IdempotencyKey) -> Result<Option<DurableEntry>, RelayError> {
        let attempts = crate::lock(&self.attempts);
        let mut matched: Option<&DurableEntry> = None;
        let mut count = 0usize;
        for (stored_key, entry) in attempts.iter() {
            if stored_key.idempotency_key == *key {
                count += 1;
                matched = Some(entry);
            }
        }
        if count > 1 {
            // Ambiguous across owners/workspaces: fail closed rather than
            // reconcile the wrong attempt.
            return Err(RelayError::StoreUnavailable);
        }
        Ok(matched.cloned())
    }
}

#[async_trait]
impl AttemptReservationStore for DeterministicDurableStore {
    async fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let binding = Self::legacy_binding(key)?;
        self.reserve_bound(&binding, digest).await
    }

    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let digest = *digest.as_bytes();
        let key = DurableKey::from_binding(binding);
        let mut attempts = crate::lock(&self.attempts);
        match attempts.get(&key) {
            Some(entry) if entry.digest == digest => Ok(Reservation::AlreadyReserved(
                entry.outcome.clone().unwrap_or(RelayOutcome::Reserved),
            )),
            Some(_) => Ok(Reservation::Conflict),
            None => {
                attempts.insert(
                    key,
                    DurableEntry {
                        digest,
                        status: AttemptStatus::Reserved,
                        provider_idempotency: None,
                        signed_reference: None,
                        submission: None,
                        outcome: None,
                    },
                );
                Ok(Reservation::Reserved)
            }
        }
    }

    async fn record_sign_requested(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        let value = provider_idempotency.as_str().to_string();
        self.with_entry(key, digest, |entry| {
            entry.status = AttemptStatus::SignRequested;
            entry.provider_idempotency = Some(value);
        })
    }

    async fn record_signed(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        self.with_entry(key, digest, |entry| {
            entry.status = AttemptStatus::Signed;
            if entry.outcome.is_none() {
                entry.outcome = Some(RelayOutcome::Signed);
            }
        })
    }

    async fn record_signed_reference(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        let value = signed_reference.to_string();
        self.with_entry(key, digest, |entry| {
            entry.status = AttemptStatus::Signed;
            entry.signed_reference = Some(value);
            if entry.outcome.is_none() {
                entry.outcome = Some(RelayOutcome::Signed);
            }
        })
    }

    async fn record_submission(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        request: &SubmitRequest,
    ) -> Result<(), RelayError> {
        let submission = DurableSubmission::from_request(request)?;
        self.with_entry(key, digest, |entry| {
            entry.submission = Some(submission);
            entry.status = AttemptStatus::SubmissionUnknown;
            // A duplicate execute after this boundary must observe an ambiguous
            // in-flight state, never a fresh attempt.
            entry.outcome = Some(RelayOutcome::Unknown);
        })
    }

    async fn load_submission(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        Ok(self.unique_by_key(key)?.and_then(|entry| entry.submission))
    }

    async fn load_outcome(&self, key: &IdempotencyKey) -> Result<Option<RelayOutcome>, RelayError> {
        Ok(self.unique_by_key(key)?.and_then(|entry| entry.outcome))
    }

    async fn record_outcome(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        self.with_entry(key, digest, |entry| {
            // A terminal outcome is never downgraded by a later observation.
            if entry.status.is_terminal() {
                return;
            }
            if let Some(reference) = outcome_reference(&outcome) {
                if let Some(submission) = entry.submission.as_mut() {
                    submission.set_chain_reference(reference);
                }
            }
            entry.status = outcome.attempt_status();
            entry.outcome = Some(outcome);
        })
    }
}

impl DurableAttemptStore for DeterministicDurableStore {}

/// The chain acknowledgement reference carried by an outcome, if any.
fn outcome_reference(outcome: &RelayOutcome) -> Option<&str> {
    match outcome {
        RelayOutcome::Submitted { reference, .. } | RelayOutcome::Confirmed { reference, .. } => {
            Some(reference.as_str())
        }
        _ => None,
    }
}
