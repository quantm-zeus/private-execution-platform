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

/// Process-local reservation store keyed by the full attempt identity.
///
/// It is the minimal store used by unit tests, but it still scopes entries to
/// `(owner, workspace, idempotency_key)` so a cross-owner key reuse cannot be
/// mistaken for a duplicate of the same attempt.
#[derive(Default)]
pub struct InMemoryReservationStore {
    entries: Mutex<HashMap<DurableKey, StoreEntry>>,
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
        let binding = legacy_binding(key)?;
        self.reserve_bound(&binding, digest).await
    }

    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let digest = *digest.as_bytes();
        let key = DurableKey::from_binding(binding);
        let mut entries = crate::lock(&self.entries);
        match entries.get(&key) {
            Some(entry) if entry.digest == digest => Ok(Reservation::AlreadyReserved(
                entry.outcome.clone().unwrap_or(RelayOutcome::Reserved),
            )),
            Some(_) => Ok(Reservation::Conflict),
            None => {
                entries.insert(
                    key,
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
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        let digest = *digest.as_bytes();
        let key = DurableKey::from_binding(binding);
        let mut entries = crate::lock(&self.entries);
        match entries.get_mut(&key) {
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
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        let digest = *digest.as_bytes();
        let key = DurableKey::from_binding(binding);
        let mut entries = crate::lock(&self.entries);
        match entries.get_mut(&key) {
            Some(entry) if entry.digest == digest => {
                // A terminal outcome is never overwritten, matching the durable
                // reference store and the Postgres monotonic guard.
                if entry
                    .outcome
                    .as_ref()
                    .is_some_and(|existing| existing.attempt_status().is_terminal())
                {
                    return Ok(());
                }
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

/// Synthetic binding for the legacy key-only entry point.
///
/// Durable production stores reject the bare-key path outright; this exists so
/// the process-local test seam keeps working with an explicit, fixed identity.
fn legacy_binding(key: &IdempotencyKey) -> Result<AttemptBinding, RelayError> {
    let owner = UserId::new(LEGACY_OWNER).map_err(|_| RelayError::StoreUnavailable)?;
    let workspace = WalletRef::new(LEGACY_WORKSPACE).map_err(|_| RelayError::StoreUnavailable)?;
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
        legacy_binding(key)
    }

    /// Returns the persisted status for `binding`, when the attempt exists.
    pub fn status(&self, binding: &AttemptBinding) -> Option<AttemptStatus> {
        self.entry_for(binding).map(|entry| entry.status)
    }

    /// Returns the persisted provider idempotency identifier, when present.
    pub fn provider_idempotency(&self, binding: &AttemptBinding) -> Option<String> {
        self.entry_for(binding)
            .and_then(|entry| entry.provider_idempotency)
    }

    /// Number of distinct attempts retained (the primary key cardinality).
    pub fn len(&self) -> usize {
        crate::lock(&self.attempts).len()
    }

    /// True when no attempt is retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies `mutate` to the unique entry matching `binding` + `digest`.
    ///
    /// The lookup is exact on the `(owner, workspace, idempotency_key)` primary
    /// key, so a transition can never land on a different tenant's attempt.
    /// Returns [`RelayError::ReservationUnavailable`] when no entry matches.
    fn with_entry<F>(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        mutate: F,
    ) -> Result<(), RelayError>
    where
        F: FnOnce(&mut DurableEntry),
    {
        let digest = *digest.as_bytes();
        let key = DurableKey::from_binding(binding);
        let mut attempts = crate::lock(&self.attempts);
        match attempts.get_mut(&key) {
            Some(entry) if entry.digest == digest => {
                mutate(entry);
                Ok(())
            }
            _ => Err(RelayError::ReservationUnavailable),
        }
    }

    /// Finds the entry named by the full attempt binding.
    fn entry_for(&self, binding: &AttemptBinding) -> Option<DurableEntry> {
        let key = DurableKey::from_binding(binding);
        crate::lock(&self.attempts).get(&key).cloned()
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
        binding: &AttemptBinding,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        let value = provider_idempotency.as_str().to_string();
        self.with_entry(binding, digest, |entry| {
            // A terminal attempt is immutable, matching the Postgres
            // `status IN (...)` transition predicates.
            if entry.status.is_terminal() {
                return;
            }
            entry.status = AttemptStatus::SignRequested;
            entry.provider_idempotency = Some(value);
        })
    }

    async fn record_signed(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        self.with_entry(binding, digest, |entry| {
            if entry.status.is_terminal() {
                return;
            }
            entry.status = AttemptStatus::Signed;
            if entry.outcome.is_none() {
                entry.outcome = Some(RelayOutcome::Signed);
            }
        })
    }

    async fn record_signed_reference(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        let value = signed_reference.to_string();
        self.with_entry(binding, digest, |entry| {
            if entry.status.is_terminal() {
                return;
            }
            entry.status = AttemptStatus::Signed;
            entry.signed_reference = Some(value);
            if entry.outcome.is_none() {
                entry.outcome = Some(RelayOutcome::Signed);
            }
        })
    }

    async fn record_submission(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        request: &SubmitRequest,
    ) -> Result<(), RelayError> {
        let submission = DurableSubmission::from_request(request)?;
        self.with_entry(binding, digest, |entry| {
            if entry.status.is_terminal() {
                return;
            }
            entry.submission = Some(submission);
            entry.status = AttemptStatus::SubmissionUnknown;
            // A duplicate execute after this boundary must observe an ambiguous
            // in-flight state, never a fresh attempt.
            entry.outcome = Some(RelayOutcome::Unknown);
        })
    }

    async fn load_submission(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        Ok(self.entry_for(binding).and_then(|entry| entry.submission))
    }

    async fn load_outcome(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<RelayOutcome>, RelayError> {
        Ok(self.entry_for(binding).and_then(|entry| entry.outcome))
    }

    async fn record_outcome(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        self.with_entry(binding, digest, |entry| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::ChainId;
    use domain::IntentId;

    fn binding(owner: &str, workspace: &str, key: &str) -> AttemptBinding {
        AttemptBinding::new(
            UserId::new(owner).expect("owner"),
            WalletRef::new(workspace).expect("workspace"),
            IdempotencyKey::new(key).expect("key"),
            IntentId::new(format!("intent-{key}")).expect("intent"),
            ChainId::Base,
        )
    }

    fn digest(byte: u8) -> RequestDigest {
        RequestDigest::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn cross_owner_same_key_is_distinct_and_never_crosses() {
        let store = DeterministicDurableStore::new();
        let alice = binding("owner-a", "wallet-a", "shared-key");
        let bob = binding("owner-b", "wallet-b", "shared-key");
        let digest = digest(7);

        // The same idempotency key under two owners is two distinct attempts.
        assert_eq!(
            store.reserve_bound(&alice, &digest).await,
            Ok(Reservation::Reserved)
        );
        assert_eq!(
            store.reserve_bound(&bob, &digest).await,
            Ok(Reservation::Reserved)
        );
        assert_eq!(store.len(), 2);

        store
            .record_signed_reference(&alice, &digest, "alice-signed")
            .await
            .expect("alice signed");
        assert_eq!(store.status(&alice), Some(AttemptStatus::Signed));
        assert_eq!(store.status(&bob), Some(AttemptStatus::Reserved));

        // A transition on one owner never lands on the other, and a read for
        // another owner never observes a foreign row.
        store
            .record_outcome(&alice, &digest, RelayOutcome::Unknown)
            .await
            .expect("alice outcome");
        assert_eq!(store.status(&alice), Some(AttemptStatus::SubmissionUnknown));
        assert_eq!(store.status(&bob), Some(AttemptStatus::Reserved));
        assert_eq!(store.load_outcome(&bob).await, Ok(None));

        // A third owner sharing the key has no row at all and reads `None`
        // rather than the first matching attempt.
        let carol = binding("owner-c", "wallet-c", "shared-key");
        assert_eq!(store.load_submission(&carol).await, Ok(None));
        assert_eq!(store.load_outcome(&carol).await, Ok(None));
    }

    #[tokio::test]
    async fn failed_before_submit_is_terminal_in_the_durable_store() {
        let store = DeterministicDurableStore::new();
        let binding = binding("owner", "wallet", "terminal-key");
        let digest = digest(9);
        store
            .reserve_bound(&binding, &digest)
            .await
            .expect("reserve");
        store
            .record_outcome(&binding, &digest, RelayOutcome::FailedBeforeSubmit)
            .await
            .expect("failed before submit");

        // A later ambiguous observation must never overwrite the terminal state.
        store
            .record_outcome(&binding, &digest, RelayOutcome::Unknown)
            .await
            .expect("late unknown");
        store
            .record_outcome(
                &binding,
                &digest,
                RelayOutcome::Confirmed {
                    reference: "late".to_string(),
                    fill: None,
                },
            )
            .await
            .expect("late confirmation");
        assert_eq!(
            store.status(&binding),
            Some(AttemptStatus::FailedBeforeSubmit)
        );
        assert_eq!(
            store.load_outcome(&binding).await,
            Ok(Some(RelayOutcome::FailedBeforeSubmit))
        );

        // A late signing/submission transition must not resurrect the attempt by
        // flipping its status back to a non-terminal state, which would reopen
        // the outcome guard and let a later ambiguous write downgrade it.
        store
            .record_sign_requested(
                &binding,
                &digest,
                &ProviderIdempotencyId::from_string("late-idem"),
            )
            .await
            .expect("late sign requested");
        store
            .record_signed_reference(&binding, &digest, "late-signed")
            .await
            .expect("late signed reference");
        assert_eq!(
            store.status(&binding),
            Some(AttemptStatus::FailedBeforeSubmit)
        );
        store
            .record_outcome(&binding, &digest, RelayOutcome::Unknown)
            .await
            .expect("late unknown after transitions");
        assert_eq!(
            store.load_outcome(&binding).await,
            Ok(Some(RelayOutcome::FailedBeforeSubmit))
        );
    }

    #[tokio::test]
    async fn legacy_key_only_reserve_uses_a_distinct_synthetic_identity() {
        // The legacy key-only path uses a fixed synthetic identity; a real owner
        // reusing the same key must remain a distinct attempt, never a replay.
        let store = DeterministicDurableStore::new();
        let key = IdempotencyKey::new("legacy-shared").expect("key");
        let digest = digest(3);
        assert_eq!(
            store.reserve(&key, &digest).await,
            Ok(Reservation::Reserved)
        );
        let real = binding("real-owner", "real-wallet", "legacy-shared");
        assert_eq!(
            store.reserve_bound(&real, &digest).await,
            Ok(Reservation::Reserved)
        );
        assert_eq!(store.len(), 2);
    }
}
