# Local infrastructure

This stack is for local development only. It binds PostgreSQL and NATS to loopback and contains no production credentials. Copy `.env.example` to an untracked `.env`, replace the placeholder password, then run `docker compose --env-file .env up -d`.

`postgres/migrations/0001_opaque_storage.sql` creates only generic physical persistence (`objects`, `events`, `snapshots`, `streams`). Plaintext trading semantics do not belong in this layer. The migration enables the TimescaleDB extension for later time-series use without weakening durable sequence constraints by converting the event journal into a hypertable prematurely.

NATS starts with JetStream enabled and file-backed storage. Production credentials, mTLS/service identities, retention policies, stream definitions, backup policy, and KMS/KEK integration are deployment concerns and must not be committed here.

Readiness is provided by container health checks. Application services should additionally expose their own dependency readiness using the storage/event-bus health interfaces.
