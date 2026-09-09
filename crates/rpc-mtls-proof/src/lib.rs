//! In-process gRPC over mTLS runtime wiring proof (P0-5, audit item F).
//!
//! Proves with REAL TLS handshakes (tokio + tonic 0.14.5, rustls/ring):
//!   1. Happy path: a tonic server configured from `service-identity`'s
//!      `load_server_tls_config` and a client endpoint configured via
//!      `configure_client_endpoint` (generated test CA + server + client
//!      identities, all written to temp PEM files, never committed) complete
//!      a unary `RelayService` call through the opaque relay contract.
//!   2. Fail closed on: client identity issued by a DIFFERENT CA; no client
//!      certificate at all; client identity with the WRONG EKU (no clientAuth);
//!      client pinned to the wrong server DNS name (server-name mismatch).
//!
//! No application semantics: the relay contract carries ciphertext-only
//! payloads. This is a wiring proof, not a production service.
//!
//! Everything in this crate is test-harness material; it ships no runtime
//! code and exists to exercise `service-identity` + `rpc-contracts` under a
//! real TLS stack. The lib target is intentionally empty outside tests.

#[cfg(test)]
mod proof;
