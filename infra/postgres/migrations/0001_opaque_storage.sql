BEGIN;

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS streams (
    stream_blind_index BYTEA PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    head_sequence BIGINT NOT NULL DEFAULT 0 CHECK (head_sequence >= 0),
    ciphertext BYTEA,
    created_bucket BIGINT NOT NULL CHECK (created_bucket >= 0),
    updated_bucket BIGINT NOT NULL CHECK (updated_bucket >= 0),
    CHECK (octet_length(stream_blind_index) > 0),
    CHECK (ciphertext IS NULL OR octet_length(ciphertext) > 0)
);

CREATE TABLE IF NOT EXISTS objects (
    id TEXT NOT NULL,
    owner_blind_index BYTEA NOT NULL,
    class_blind_index BYTEA NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    ciphertext BYTEA NOT NULL,
    created_bucket BIGINT NOT NULL CHECK (created_bucket >= 0),
    PRIMARY KEY (id, version),
    CHECK (length(btrim(id)) > 0),
    CHECK (octet_length(owner_blind_index) > 0),
    CHECK (octet_length(class_blind_index) > 0),
    CHECK (octet_length(ciphertext) > 0)
);

CREATE INDEX IF NOT EXISTS idx_objects_owner_class
    ON objects (owner_blind_index, class_blind_index, created_bucket DESC);

CREATE TABLE IF NOT EXISTS events (
    stream_blind_index BYTEA NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    schema_version SMALLINT NOT NULL CHECK (schema_version > 0),
    ciphertext BYTEA NOT NULL,
    created_bucket BIGINT NOT NULL CHECK (created_bucket >= 0),
    PRIMARY KEY (stream_blind_index, sequence),
    CHECK (octet_length(stream_blind_index) > 0),
    CHECK (octet_length(ciphertext) > 0)
);

CREATE INDEX IF NOT EXISTS idx_events_created_bucket ON events (created_bucket DESC);

CREATE TABLE IF NOT EXISTS snapshots (
    stream_blind_index BYTEA NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    version BIGINT NOT NULL CHECK (version > 0),
    ciphertext BYTEA NOT NULL,
    created_bucket BIGINT NOT NULL CHECK (created_bucket >= 0),
    PRIMARY KEY (stream_blind_index, sequence, version),
    CHECK (octet_length(stream_blind_index) > 0),
    CHECK (octet_length(ciphertext) > 0)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_latest
    ON snapshots (stream_blind_index, sequence DESC, version DESC);

COMMIT;
