-- P46: class-scoped object listing for durable limit-order recovery.
--
-- Additive only: no data change. The existing index is
-- (owner_blind_index, class_blind_index, created_bucket DESC), which cannot
-- serve a class-only scan. Recovery enumerates order-class objects without an
-- active-owner registry, so it needs a class-leading index.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_objects_class
    ON objects (class_blind_index, created_bucket DESC);

COMMIT;
