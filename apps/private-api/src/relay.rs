//! Opaque relay gRPC server for the internal mTLS boundary.
//!
//! Phase 0 contract: pure ciphertext passthrough. The handler validates the
//! request against the opaque relay contract (route present, bounded payload)
//! and reflects the ciphertext back. No application semantics, no plaintext,
//! no payload detail in gRPC statuses — every failure is a bare
//! `Status::unavailable` or the contract's own opaque validation errors.

use rpc_contracts::relay_service::{RelayService, RelayServiceServer};
use rpc_contracts::{validate_relay_request, RelayRequest, RelayResponse, RelayResponseResult};
use tonic::{Request, Response};

/// Pure opaque passthrough relay service.
#[derive(Debug, Default)]
pub struct OpaquePassthroughRelay;

#[tonic::async_trait]
impl RelayService for OpaquePassthroughRelay {
    async fn relay(&self, request: Request<RelayRequest>) -> RelayResponseResult {
        let inner = request.into_inner();
        // Contract-level validation maps to opaque invalid_argument /
        // out_of_range statuses that carry no payload content.
        validate_relay_request(&inner)?;
        Ok(Response::new(RelayResponse {
            ciphertext: inner.ciphertext,
        }))
    }
}

/// Builds the mTLS server TLS config from operator-supplied identity files.
///
/// Public so the binary wiring stays in one place; identity errors are
/// opaque to callers and never include file contents.
pub fn server_tls_config(
    config: &service_identity::ServiceIdentityConfig,
) -> Result<tonic::transport::ServerTlsConfig, service_identity::ServiceIdentityError> {
    service_identity::load_server_tls_config(config)
}

/// Convenience constructor returning the TLS-ready server. The TLS config
/// MUST be applied (mTLS is mandatory on this boundary); callers then serve
/// with their own incoming/shutdown wiring.
pub fn relay_tls_router(
    tls: tonic::transport::ServerTlsConfig,
) -> Result<tonic::transport::server::Router, tonic::transport::Error> {
    tonic::transport::Server::builder()
        .tls_config(tls)
        .map(|mut server| server.add_service(RelayServiceServer::new(OpaquePassthroughRelay)))
}
