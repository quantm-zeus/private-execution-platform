//! Postgres attempt-store integration test (feature-gated).
//!
//! Runs only with `--features postgres-integration` and a reachable DSN in
//! `PEP_EXECUTION_TEST_DSN` (or `DATABASE_URL`). It never runs in the default CI
//! gate and never requires credentials in the repository. When the DSN is absent
//! the test skips (returns) rather than failing, so a developer without a local
//! database is not blocked.
//!
//! Apply `infra/postgres/migrations/0001`..`0003` before running.

#![cfg(feature = "postgres-integration")]

use std::sync::Arc;

use chain_types::ChainId;
use domain::{IdempotencyKey, IntentId, UserId, WalletRef};
use execution_relay::{AttemptBinding, AttemptReservationStore, DurableAttemptStore, Reservation};
use execution_store::{AttemptClock, PostgresExecutionAttemptStore};

/// Fixed clock so bucket values are deterministic.
#[derive(Clone, Copy)]
struct FixedClock(i64);

impl AttemptClock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

fn dsn() -> Option<String> {
    std::env::var("PEP_EXECUTION_TEST_DSN")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn binding(suffix: &str) -> AttemptBinding {
    AttemptBinding::new(
        UserId::new("integration-owner").expect("owner"),
        WalletRef::new("integration-workspace").expect("workspace"),
        IdempotencyKey::new(format!("integration-key-{suffix}")).expect("key"),
        IntentId::new(format!("integration-intent-{suffix}")).expect("intent"),
        ChainId::Base,
    )
}

async fn connect(dsn: &str) -> PostgresExecutionAttemptStore {
    PostgresExecutionAttemptStore::connect(dsn, 1, Arc::new(FixedClock(86_400_000)), 86_400_000)
        .await
        .expect("connect")
}

#[tokio::test]
async fn postgres_store_persists_reserve_replay_and_conflict() {
    let Some(dsn) = dsn() else {
        return;
    };
    let store = connect(&dsn).await;
    assert_eq!(
        store.health().await.status,
        storage::ComponentHealth::Healthy
    );
    // The concrete adapter satisfies the production marker.
    let _: &dyn DurableAttemptStore = &store;

    // A unique-enough suffix keeps repeated local runs from colliding.
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis())
            .unwrap_or_default()
    );
    let binding = binding(&suffix);
    let digest = privy::RequestDigest::from_bytes([7u8; 32]);
    assert_eq!(
        store.reserve_bound(&binding, &digest).await,
        Ok(Reservation::Reserved)
    );

    // Replay with the same digest returns the stored outcome, never a fresh claim.
    assert!(matches!(
        store.reserve_bound(&binding, &digest).await,
        Ok(Reservation::AlreadyReserved(_))
    ));

    // A conflicting digest fails closed.
    let conflict = privy::RequestDigest::from_bytes([9u8; 32]);
    assert_eq!(
        store.reserve_bound(&binding, &conflict).await,
        Ok(Reservation::Conflict)
    );

    // Lifecycle: SIGN_REQUESTED -> SIGNED persists and is visible to a fresh
    // store handle over the same database (restart recovery).
    store
        .record_sign_requested(
            binding.idempotency_key(),
            &digest,
            &privy::ProviderIdempotencyId::from_string("integration-idem"),
        )
        .await
        .expect("sign requested");
    store
        .record_signed_reference(binding.idempotency_key(), &digest, "integration-signed-ref")
        .await
        .expect("signed");

    let second = connect(&dsn).await;
    // No submission payload is stored, so load returns `None` (not an error).
    assert_eq!(
        second.load_submission(binding.idempotency_key()).await,
        Ok(None)
    );
}
