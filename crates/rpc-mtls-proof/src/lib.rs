//! In-process gRPC over mTLS runtime wiring proof (P0-5, audit item F).
//!
//! Proves with REAL TLS handshakes (tokio + tonic 0.14.5, rustls/ring):
//!   1. Happy path: a tonic server configured from `service-identity`'s
//!      `load_server_tls_config` and a client endpoint configured via
//!      `configure_client_endpoint` (generated test CA + server + client
//!      identities, all written to temp PEM files, never committed) complete
//!      a unary `RelayService` call through the opaque relay contract.
//!   2. Fail closed (asserted rejections): client identity issued by a
//!      DIFFERENT CA; anonymous client (no client certificate at all);
//!      client with a WRONG EKU (serverAuth-only leaf, rejected with a fatal
//!      TLS alert by the pinned stack); client pinned to the wrong server
//!      DNS name (server-name mismatch).
//!
//! ### What this proof demonstrates — exactly
//!
//! - The server REQUIRES a client certificate (mTLS, not server-only TLS)
//!   and validates it against the trusted client CA.
//! - The pinned tonic/rustls stack rejects a client certificate with a WRONG
//!   EKU (`serverAuth`-only) for client authentication.
//! - The client validates the server certificate against the trusted CA AND
//!   the configured expected peer DNS name (server-name pinning).
//!
//! ### What this proof does NOT claim
//!
//! - Per-client authorization beyond the above. A client leaf with NO EKU
//!   extension is unrestricted per RFC 5280 and is accepted by the pinned
//!   stack; that is standard PKI semantics for absent EKU and is characterized
//!   by `proof::client_without_eku_extension_is_accepted_as_unrestricted`.
//!   No client SAN allowlist exists. Anything finer would be a new locked-
//!   boundary requirement and is out of scope here.
//!
//! No application semantics: the relay contract carries ciphertext-only
//! payloads. This is a wiring proof, not a production service.
//!
//! Everything in this crate is test-harness material; it ships no runtime
//! code and exists to exercise `service-identity` + `rpc-contracts` under a
//! real TLS stack. The lib target is intentionally empty outside tests.

#[cfg(test)]
mod proof;
