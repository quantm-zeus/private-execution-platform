//! Postgres/Timescale implementation of the durable attempt ledger.
//!
//! The schema lives in `infra/postgres/migrations/0003_execution_attempts.sql`.
//! Every transition is a single guarded SQL statement so a concurrent writer can
//! never interleave a check-then-act:
//!
//! - `reserve_bound` inserts `RESERVED` with `ON CONFLICT DO NOTHING`, then
//!   reads the existing row: same digest yields the stored outcome, a different
//!   digest yields [`execution_relay::Reservation::Conflict`];
//! - each transition `UPDATE ... WHERE request_digest = $n AND status IN (...)` so
//!   a stale or conflicting writer affects zero rows and fails closed;
//! - `record_outcome` updates only when the full
//!   `(owner_id, workspace_ref, idempotency_key, request_digest)` primary key
//!   names exactly one non-terminal row, so neither an ambiguous key across
//!   owners nor a terminal outcome can be overwritten.
//!
//! No logging, no plaintext, no DSN in errors.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use domain::{IdempotencyKey, IntentId};
use execution_relay::{
    AttemptBinding, AttemptReservationStore, AttemptStatus, DurableAttemptStore, DurableSubmission,
    ObservedFill, RelayError, RelayOutcome, Reservation, SubmissionState,
};
use privy::{
    canonical_chain_tag, chain_from_canonical_tag, PayloadDigest, ProviderIdempotencyId,
    RequestDigest,
};
use tokio_postgres::error::SqlState;
use tokio_postgres::NoTls;

use crate::{
    bucket_for, healthy_probe, unavailable_probe, AttemptClock, ExecutionStoreError, SystemClock,
    DEFAULT_BUCKET_MS,
};

/// Postgres-backed durable execution attempt ledger.
///
/// The pool is deliberately small and dependency-free, mirroring
/// `storage::PostgresStore`: a fixed set of established connections acquired
/// round-robin. The store fails closed if any connection cannot be established
/// and never degrades to a partial pool.
pub struct PostgresExecutionAttemptStore {
    connections: Vec<tokio_postgres::Client>,
    next: AtomicUsize,
    clock: Arc<dyn AttemptClock>,
    bucket_ms: i64,
}

impl std::fmt::Debug for PostgresExecutionAttemptStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresExecutionAttemptStore")
            .field("connections", &self.connections.len())
            .finish_non_exhaustive()
    }
}

fn map_error(error: tokio_postgres::Error) -> RelayError {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        RelayError::IdempotencyConflict
    } else {
        RelayError::StoreUnavailable
    }
}

/// i64 -> u8 chain tag, rejecting out-of-range persisted values.
fn decode_chain_tag(raw: i16) -> Result<chain_types::ChainId, RelayError> {
    let tag = u8::try_from(raw).map_err(|_| RelayError::StoreUnavailable)?;
    chain_from_canonical_tag(tag).ok_or(RelayError::StoreUnavailable)
}

/// Decodes the persisted outcome for a `reserve_bound` replay.
fn decode_existing_outcome(row: &tokio_postgres::Row) -> Result<RelayOutcome, RelayError> {
    let status: String = row
        .try_get("status")
        .map_err(|_| RelayError::StoreUnavailable)?;
    let status = AttemptStatus::parse(&status).ok_or(RelayError::StoreUnavailable)?;
    let signed_reference: Option<String> = row
        .try_get("signed_reference")
        .map_err(|_| RelayError::StoreUnavailable)?;
    let submission_reference: Option<String> = row
        .try_get("submission_reference")
        .map_err(|_| RelayError::StoreUnavailable)?;
    let final_reason: Option<String> = row
        .try_get("final_reason")
        .map_err(|_| RelayError::StoreUnavailable)?;
    let net_input: Option<String> = row
        .try_get("net_input")
        .map_err(|_| RelayError::StoreUnavailable)?;
    let net_output: Option<String> = row
        .try_get("net_output")
        .map_err(|_| RelayError::StoreUnavailable)?;
    match status {
        AttemptStatus::Reserved | AttemptStatus::SignRequested => Ok(RelayOutcome::Reserved),
        AttemptStatus::Signed => Ok(RelayOutcome::Signed),
        AttemptStatus::Submitted => match submission_reference {
            Some(reference) if !reference.trim().is_empty() => Ok(RelayOutcome::Submitted {
                reference,
                state: SubmissionState::Unknown,
            }),
            // An acknowledgement without a reference carries no information.
            _ => Ok(RelayOutcome::Unknown),
        },
        AttemptStatus::SubmissionUnknown => Ok(RelayOutcome::Unknown),
        AttemptStatus::Confirmed => {
            let reference = submission_reference
                .or(signed_reference)
                .filter(|value| !value.trim().is_empty())
                .ok_or(RelayError::StoreUnavailable)?;
            let fill = match (net_input, net_output) {
                (Some(input), Some(output)) => Some(ObservedFill {
                    net_input: input.parse().map_err(|_| RelayError::StoreUnavailable)?,
                    net_output: output.parse().map_err(|_| RelayError::StoreUnavailable)?,
                }),
                // A confirmation without both amounts is real but unresolved;
                // the consumer must reconcile rather than infer a fill.
                _ => None,
            };
            Ok(RelayOutcome::Confirmed { reference, fill })
        }
        AttemptStatus::Rejected => Ok(RelayOutcome::Rejected {
            final_reason: final_reason.unwrap_or_default(),
        }),
        AttemptStatus::FailedBeforeSubmit => Ok(RelayOutcome::FailedBeforeSubmit),
    }
}

impl PostgresExecutionAttemptStore {
    /// Opens `pool_size` connections to `dsn` with the given clock and bucket.
    ///
    /// Fails closed on a zero pool, a non-positive bucket width, or any
    /// connection failure. The DSN is consumed here and never stored.
    pub async fn connect(
        dsn: &str,
        pool_size: usize,
        clock: Arc<dyn AttemptClock>,
        bucket_ms: i64,
    ) -> Result<Self, ExecutionStoreError> {
        if pool_size == 0 || bucket_ms <= 0 {
            return Err(ExecutionStoreError::InvalidConfig);
        }
        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let (client, connection) = tokio_postgres::connect(dsn, NoTls)
                .await
                .map_err(|_| ExecutionStoreError::Unavailable)?;
            tokio::spawn(async move {
                // Failure surfaces through later queries; never logged here.
                let _ = connection.await;
            });
            connections.push(client);
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
            clock,
            bucket_ms,
        })
    }

    /// Opens connections with the system clock and default bucket width.
    pub async fn connect_with_system_clock(
        dsn: &str,
        pool_size: usize,
    ) -> Result<Self, ExecutionStoreError> {
        Self::connect(dsn, pool_size, Arc::new(SystemClock), DEFAULT_BUCKET_MS).await
    }

    fn next_client(&self) -> &tokio_postgres::Client {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        &self.connections[index]
    }

    fn bucket(&self) -> i64 {
        bucket_for(self.clock.now_ms(), self.bucket_ms)
    }

    /// Readiness probe over one pooled connection.
    ///
    /// Reads the `execution_attempts` table (bounded to one row) rather than a
    /// bare `SELECT 1`: a reachable database that has not had migration `0003`
    /// applied is not a usable durable store and must probe unavailable, so the
    /// caller cannot prove execution capability from a store that cannot
    /// reserve.
    pub async fn health(&self) -> storage::HealthProbe {
        let now = self.clock.now_ms();
        match self
            .next_client()
            .simple_query("SELECT 1 FROM execution_attempts LIMIT 1")
            .await
        {
            Ok(_) => healthy_probe("execution-store.postgres", now),
            Err(_) => unavailable_probe("execution-store.postgres", now),
        }
    }
}

#[async_trait]
impl AttemptReservationStore for PostgresExecutionAttemptStore {
    async fn reserve(
        &self,
        key: &IdempotencyKey,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        // The legacy entry point has no owning identity. Reject it rather than
        // invent one: production composition always uses `reserve_bound`.
        let _ = (key, digest);
        Err(RelayError::ReservationUnavailable)
    }

    async fn reserve_bound(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<Reservation, RelayError> {
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let intent = binding.intent_id().as_str();
        let chain_tag = i16::from(
            canonical_chain_tag(binding.chain()).map_err(|_| RelayError::StoreUnavailable)?,
        );
        let digest_bytes: &[u8] = digest.as_bytes();
        let bucket = self.bucket();
        let inserted = self
            .next_client()
            .execute(
                "INSERT INTO execution_attempts
                     (owner_id, workspace_ref, idempotency_key, request_digest, intent_id,
                      chain_tag, status, created_bucket, updated_bucket)
                 VALUES ($1, $2, $3, $4, $5, $6, 'RESERVED', $7, $7)
                 ON CONFLICT (owner_id, workspace_ref, idempotency_key) DO NOTHING",
                &[
                    &owner,
                    &workspace,
                    &key,
                    &digest_bytes,
                    &intent,
                    &chain_tag,
                    &bucket,
                ],
            )
            .await
            .map_err(map_error)?;
        if inserted == 1 {
            return Ok(Reservation::Reserved);
        }
        // The identity already exists: replay only when the digest matches.
        let row = self
            .next_client()
            .query_opt(
                "SELECT request_digest, status, signed_reference, submission_reference,
                        final_reason, CAST(net_input AS TEXT) AS net_input,
                        CAST(net_output AS TEXT) AS net_output
                 FROM execution_attempts
                 WHERE owner_id = $1 AND workspace_ref = $2 AND idempotency_key = $3",
                &[&owner, &workspace, &key],
            )
            .await
            .map_err(map_error)?;
        let Some(row) = row else {
            return Err(RelayError::StoreUnavailable);
        };
        let stored: Vec<u8> = row
            .try_get("request_digest")
            .map_err(|_| RelayError::StoreUnavailable)?;
        if stored.as_slice() != digest.as_bytes() {
            return Ok(Reservation::Conflict);
        }
        Ok(Reservation::AlreadyReserved(decode_existing_outcome(&row)?))
    }

    async fn record_sign_requested(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        provider_idempotency: &ProviderIdempotencyId,
    ) -> Result<(), RelayError> {
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let digest_bytes: &[u8] = digest.as_bytes();
        let bucket = self.bucket();
        let updated = self
            .next_client()
            .execute(
                "UPDATE execution_attempts
                 SET status = 'SIGN_REQUESTED',
                     provider_idempotency_id = $5,
                     attempt_version = attempt_version + 1,
                     updated_bucket = $6
                 WHERE owner_id = $1
                   AND workspace_ref = $2
                   AND idempotency_key = $3
                   AND request_digest = $4
                   AND status IN ('RESERVED', 'SIGN_REQUESTED')",
                &[
                    &owner,
                    &workspace,
                    &key,
                    &digest_bytes,
                    &provider_idempotency.as_str(),
                    &bucket,
                ],
            )
            .await
            .map_err(map_error)?;
        if updated == 0 {
            return Err(RelayError::StoreUnavailable);
        }
        Ok(())
    }

    async fn record_signed(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
    ) -> Result<(), RelayError> {
        // `record_signed` carries no reference; production always uses
        // `record_signed_reference`. Persist the status without a reference.
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let digest_bytes: &[u8] = digest.as_bytes();
        let bucket = self.bucket();
        let updated = self
            .next_client()
            .execute(
                "UPDATE execution_attempts
                 SET status = 'SIGNED',
                     attempt_version = attempt_version + 1,
                     updated_bucket = $5
                 WHERE owner_id = $1
                   AND workspace_ref = $2
                   AND idempotency_key = $3
                   AND request_digest = $4
                   AND status IN ('SIGN_REQUESTED', 'SIGNED')",
                &[&owner, &workspace, &key, &digest_bytes, &bucket],
            )
            .await
            .map_err(map_error)?;
        if updated == 0 {
            return Err(RelayError::StoreUnavailable);
        }
        Ok(())
    }

    async fn record_signed_reference(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        signed_reference: &str,
    ) -> Result<(), RelayError> {
        if signed_reference.trim().is_empty() {
            return Err(RelayError::SigningFailed);
        }
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let digest_bytes: &[u8] = digest.as_bytes();
        let bucket = self.bucket();
        let updated = self
            .next_client()
            .execute(
                "UPDATE execution_attempts
                 SET status = 'SIGNED',
                     signed_reference = $5,
                     attempt_version = attempt_version + 1,
                     updated_bucket = $6
                 WHERE owner_id = $1
                   AND workspace_ref = $2
                   AND idempotency_key = $3
                   AND request_digest = $4
                   AND status IN ('SIGN_REQUESTED', 'SIGNED')",
                &[
                    &owner,
                    &workspace,
                    &key,
                    &digest_bytes,
                    &signed_reference,
                    &bucket,
                ],
            )
            .await
            .map_err(map_error)?;
        if updated == 0 {
            return Err(RelayError::StoreUnavailable);
        }
        Ok(())
    }

    async fn record_submission(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        request: &execution_relay::SubmitRequest,
    ) -> Result<(), RelayError> {
        // Reuse the canonical validation (payload non-empty, bounded, digest
        // consistent) before any database contact.
        let submission = DurableSubmission::from_request(request)?;
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let digest_bytes: &[u8] = digest.as_bytes();
        let payload_digest: &[u8] = submission.payload_digest().as_bytes();
        let payload: &[u8] = submission.payload();
        let bucket = self.bucket();
        let updated = self
            .next_client()
            .execute(
                "UPDATE execution_attempts
                 SET status = 'SUBMISSION_UNKNOWN',
                     payload_digest = $5,
                     payload = $6,
                     attempt_version = attempt_version + 1,
                     updated_bucket = $7
                 WHERE owner_id = $1
                   AND workspace_ref = $2
                   AND idempotency_key = $3
                   AND request_digest = $4
                   AND status IN ('SIGNED', 'SUBMISSION_UNKNOWN', 'SUBMITTED')",
                &[
                    &owner,
                    &workspace,
                    &key,
                    &digest_bytes,
                    &payload_digest,
                    &payload,
                    &bucket,
                ],
            )
            .await
            .map_err(map_error)?;
        if updated == 0 {
            return Err(RelayError::StoreUnavailable);
        }
        Ok(())
    }

    async fn load_submission(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<DurableSubmission>, RelayError> {
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let row = self
            .next_client()
            .query_opt(
                "SELECT intent_id, chain_tag, request_digest, payload_digest,
                        signed_reference, submission_reference, payload
                 FROM execution_attempts
                 WHERE owner_id = $1 AND workspace_ref = $2 AND idempotency_key = $3",
                &[&owner, &workspace, &key],
            )
            .await
            .map_err(map_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let payload: Option<Vec<u8>> = row
            .try_get("payload")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let payload_digest: Option<Vec<u8>> = row
            .try_get("payload_digest")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let signed_reference: Option<String> = row
            .try_get("signed_reference")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let chain_reference: Option<String> = row
            .try_get("submission_reference")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let (Some(payload), Some(payload_digest), Some(signed_reference)) =
            (payload, payload_digest, signed_reference)
        else {
            return Ok(None);
        };
        let intent_id: String = row
            .try_get("intent_id")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let intent_id = IntentId::new(intent_id).map_err(|_| RelayError::StoreUnavailable)?;
        let chain_tag: i16 = row
            .try_get("chain_tag")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let chain = decode_chain_tag(chain_tag)?;
        let request_digest: Vec<u8> = row
            .try_get("request_digest")
            .map_err(|_| RelayError::StoreUnavailable)?;
        let request_digest: [u8; 32] = request_digest
            .try_into()
            .map_err(|_| RelayError::StoreUnavailable)?;
        let payload_digest: [u8; 32] = payload_digest
            .try_into()
            .map_err(|_| RelayError::StoreUnavailable)?;
        let submission = DurableSubmission::new(
            intent_id,
            binding.idempotency_key().clone(),
            chain,
            RequestDigest::from_bytes(request_digest),
            PayloadDigest::from_bytes(payload_digest),
            signed_reference,
            chain_reference,
            payload,
        )?;
        Ok(Some(submission))
    }

    async fn load_outcome(
        &self,
        binding: &AttemptBinding,
    ) -> Result<Option<RelayOutcome>, RelayError> {
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let row = self
            .next_client()
            .query_opt(
                "SELECT status, signed_reference, submission_reference, final_reason,
                        CAST(net_input AS TEXT) AS net_input,
                        CAST(net_output AS TEXT) AS net_output
                 FROM execution_attempts
                 WHERE owner_id = $1 AND workspace_ref = $2 AND idempotency_key = $3",
                &[&owner, &workspace, &key],
            )
            .await
            .map_err(map_error)?;
        match row {
            Some(row) => Ok(Some(decode_existing_outcome(&row)?)),
            None => Ok(None),
        }
    }

    async fn record_outcome(
        &self,
        binding: &AttemptBinding,
        digest: &RequestDigest,
        outcome: RelayOutcome,
    ) -> Result<(), RelayError> {
        let status = outcome.attempt_status();
        let (submission_reference, final_reason, net_input, net_output) = match &outcome {
            RelayOutcome::Submitted { reference, .. } => {
                (Some(reference.clone()), None, None, None)
            }
            RelayOutcome::Confirmed { reference, fill } => {
                let (input, output) = match fill {
                    Some(fill) => (
                        Some(fill.net_input.to_string()),
                        Some(fill.net_output.to_string()),
                    ),
                    None => (None, None),
                };
                (Some(reference.clone()), None, input, output)
            }
            RelayOutcome::Rejected { final_reason } => {
                (None, Some(final_reason.clone()), None, None)
            }
            RelayOutcome::Prepared
            | RelayOutcome::Reserved
            | RelayOutcome::Signed
            | RelayOutcome::Unknown
            | RelayOutcome::FailedBeforeSubmit => (None, None, None, None),
        };
        let owner = binding.owner().as_str();
        let workspace = binding.workspace().as_str();
        let key = binding.idempotency_key().as_str();
        let digest_bytes: &[u8] = digest.as_bytes();
        let bucket = self.bucket();
        // `FAILED_BEFORE_SUBMIT` is terminal in the Rust state machine; the SQL
        // monotonic guard must therefore exclude it too, so a later ambiguous
        // observation can never overwrite a definitively pre-send failure.
        let updated = self
            .next_client()
            .execute(
                "UPDATE execution_attempts
                 SET status = $5,
                     submission_reference = COALESCE($6, submission_reference),
                     final_reason = $7,
                     net_input = CAST($8 AS NUMERIC),
                     net_output = CAST($9 AS NUMERIC),
                     attempt_version = attempt_version + 1,
                     updated_bucket = $10
                 WHERE owner_id = $1
                   AND workspace_ref = $2
                   AND idempotency_key = $3
                   AND request_digest = $4
                   AND status NOT IN ('CONFIRMED', 'REJECTED', 'FAILED_BEFORE_SUBMIT')",
                &[
                    &owner,
                    &workspace,
                    &key,
                    &digest_bytes,
                    &status.as_str(),
                    &submission_reference,
                    &final_reason,
                    &net_input,
                    &net_output,
                    &bucket,
                ],
            )
            .await
            .map_err(map_error)?;
        if updated == 0 {
            // A terminal row is never downgraded; treat that as a no-op.
            let terminal = self
                .next_client()
                .query_opt(
                    "SELECT 1 FROM execution_attempts
                     WHERE owner_id = $1 AND workspace_ref = $2 AND idempotency_key = $3
                       AND request_digest = $4
                       AND status IN ('CONFIRMED', 'REJECTED', 'FAILED_BEFORE_SUBMIT')",
                    &[&owner, &workspace, &key, &digest_bytes],
                )
                .await
                .map_err(map_error)?;
            if terminal.is_some() {
                return Ok(());
            }
            return Err(RelayError::StoreUnavailable);
        }
        Ok(())
    }
}

impl DurableAttemptStore for PostgresExecutionAttemptStore {}
