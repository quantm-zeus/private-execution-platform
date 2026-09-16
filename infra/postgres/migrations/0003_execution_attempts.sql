-- D5: durable exactly-once execution attempts.
--
-- Additive only. This table is the durable reserve-before-sign ledger for the
-- execution relay. It binds the attempt identity (owner + workspace +
-- idempotency key) to the canonical request digest and persists every
-- consequential lifecycle transition before it happens:
--
--   RESERVED -> SIGN_REQUESTED -> SIGNED
--            -> SUBMISSION_UNKNOWN / SUBMITTED -> CONFIRMED / REJECTED
--
-- The primary key makes (owner, workspace, idempotency_key) unique, so a
-- duplicate attempt can never become a second reservation. The request digest
-- is stored on the row; a replay of the same key with a different digest is
-- detected in SQL and fails closed (no second sign, no second submit).
--
-- This table intentionally stores only stable execution reference data: the
-- signed provider reference, the bound payload digest, and the signed payload
-- bytes needed for post-restart reconciliation. It never stores private signing
-- key material.
--
-- Buckets are caller-supplied coarse time buckets (matching 0001_opaque_storage
-- conventions); the store never derives them from the database clock.

BEGIN;

CREATE TABLE IF NOT EXISTS execution_attempts (
    owner_id                TEXT NOT NULL,
    workspace_ref           TEXT NOT NULL,
    idempotency_key         TEXT NOT NULL,
    request_digest          BYTEA NOT NULL,
    intent_id               TEXT NOT NULL,
    chain_tag               SMALLINT NOT NULL,
    status                  TEXT NOT NULL,
    attempt_version         BIGINT NOT NULL DEFAULT 1,
    provider_idempotency_id TEXT,
    signed_reference        TEXT,
    submission_reference    TEXT,
    payload_digest          BYTEA,
    payload                 BYTEA,
    final_reason            TEXT,
    net_input               NUMERIC(40, 0),
    net_output              NUMERIC(40, 0),
    created_bucket          BIGINT NOT NULL,
    updated_bucket          BIGINT NOT NULL,
    PRIMARY KEY (owner_id, workspace_ref, idempotency_key),
    CHECK (length(btrim(owner_id)) > 0),
    CHECK (length(btrim(workspace_ref)) > 0),
    CHECK (length(btrim(idempotency_key)) > 0),
    CHECK (length(btrim(intent_id)) > 0),
    CHECK (octet_length(request_digest) = 32),
    CHECK (attempt_version > 0),
    CHECK (status IN (
        'RESERVED',
        'SIGN_REQUESTED',
        'SIGNED',
        'SUBMISSION_UNKNOWN',
        'SUBMITTED',
        'CONFIRMED',
        'REJECTED',
        'FAILED_BEFORE_SUBMIT'
    )),
    CHECK (payload IS NULL OR octet_length(payload) > 0),
    CHECK (payload_digest IS NULL OR octet_length(payload_digest) = 32),
    -- Payload bytes and their digest are written together or not at all.
    CHECK ((payload IS NULL) = (payload_digest IS NULL)),
    -- Realized amounts are both-or-neither.
    CHECK ((net_input IS NULL) = (net_output IS NULL)),
    CHECK (created_bucket >= 0),
    CHECK (updated_bucket >= 0)
);

-- Reconciliation scans non-terminal attempts; this index serves that scan and
-- keeps it bounded without a full table scan.
CREATE INDEX IF NOT EXISTS idx_execution_attempts_reconcile
    ON execution_attempts (status, updated_bucket);

-- Every lifecycle transition filters on (idempotency_key, request_digest), so
-- index that pair directly instead of scanning the table per transition.
CREATE INDEX IF NOT EXISTS idx_execution_attempts_key_digest
    ON execution_attempts (idempotency_key, request_digest);

COMMIT;
