//! Production opaque relay client: edge -> private-api over internal mTLS.
//!
//! The [`PrivateRelay`] type implements the edge's [`OpaqueRelay`] surface by
//! forwarding bounded ciphertext payloads to the private-api `RelayService`
//! over the pinned internal mTLS boundary (service-identity client config).
//! Only opaque bytes cross this boundary: no application semantics, no
//! plaintext, no route/payload logging.
//!
//! Construction is strictly opt-in. The operator supplies identity file
//! paths plus the pinned private-api DNS name (see [`PrivateRelayConfig`]);
//! until then the edge keeps its `UnavailableRelay` fail-closed default.
//! All transport and gRPC failures collapse to
//! [`EdgeError::BackendUnavailable`] — tonic Status text can embed peer
//! addresses and is never forwarded.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use rpc_contracts::relay_service_client::RelayServiceClient;
use rpc_contracts::{RelayRequest, Route};
use service_identity::ServiceIdentityConfig;
use tokio::sync::RwLock;

use crate::{EdgeError, OpaqueRelay, OpaqueRoute};

/// Operator-supplied identity wiring for the private-api relay backend.
///
/// Mirrors [`ServiceIdentityConfig`] exactly; `expected_peer_dns` is the
/// pinned DNS name of the private-api service certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateRelayConfig {
    pub identity: ServiceIdentityConfig,
    /// `https://` origin of the private-api relay endpoint, e.g.
    /// `https://private-api.internal`. The host must equal
    /// `identity.expected_peer_dns` (validated on connect) so the URI and
    /// the TLS-validated name can never diverge.
    pub endpoint_origin: String,
}

impl std::fmt::Debug for PrivateRelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateRelayConfig")
            .field("identity", &self.identity)
            .field("endpoint_origin", &self.endpoint_origin)
            .finish()
    }
}

/// Lazily-dialed mTLS channel to the private-api relay service.
///
/// The channel is established on first use (or after a connection loss) so
/// a temporarily-down backend does not prevent edge startup. Access is
/// serialized by [`RwLock`]: holders of the read guard share one channel,
/// a lost channel is replaced under the write guard.
pub struct PrivateRelay {
    config: PrivateRelayConfig,
    channel: RwLock<Option<tonic::transport::Channel>>,
}

impl std::fmt::Debug for PrivateRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateRelay").finish_non_exhaustive()
    }
}

impl PrivateRelay {
    /// Validates the operator config. Fails closed without dialing; the
    /// edge stays `UnavailableRelay` until a validated relay replaces it.
    pub fn new(config: PrivateRelayConfig) -> Result<Arc<Self>, EdgeError> {
        let origin_host = endpoint_host(&config.endpoint_origin)?;
        if origin_host != config.identity.expected_peer_dns {
            return Err(EdgeError::InvalidConfiguration);
        }
        config
            .identity
            .validate()
            .map_err(|_| EdgeError::InvalidConfiguration)?;
        Ok(Arc::new(Self {
            config,
            channel: RwLock::new(None),
        }))
    }

    async fn client(&self) -> Result<RelayServiceClient<tonic::transport::Channel>, EdgeError> {
        {
            let guard = self.channel.read().await;
            if let Some(channel) = guard.as_ref() {
                return Ok(RelayServiceClient::new(channel.clone()));
            }
        }
        let mut guard = self.channel.write().await;
        if let Some(channel) = guard.as_ref() {
            return Ok(RelayServiceClient::new(channel.clone()));
        }
        let endpoint = service_identity::configure_client_endpoint(
            tonic::transport::Endpoint::from_shared(self.config.endpoint_origin.clone())
                .map_err(|_| EdgeError::InvalidConfiguration)?,
            &self.config.identity,
        )
        .map_err(|_| EdgeError::InvalidConfiguration)?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|_| EdgeError::BackendUnavailable)?;
        *guard = Some(channel.clone());
        Ok(RelayServiceClient::new(channel))
    }
}

fn endpoint_host(origin: &str) -> Result<&str, EdgeError> {
    let rest = origin
        .strip_prefix("https://")
        .ok_or(EdgeError::InvalidConfiguration)?;
    let host = rest
        .split(['/', ':', '?', '#'])
        .next()
        .filter(|host| !host.is_empty())
        .ok_or(EdgeError::InvalidConfiguration)?;
    Ok(host)
}

fn proto_route(route: OpaqueRoute) -> i32 {
    match route {
        OpaqueRoute::Bootstrap => Route::Bootstrap as i32,
        OpaqueRoute::Sync => Route::Sync as i32,
        OpaqueRoute::Blob => Route::Blob as i32,
        OpaqueRoute::Command => Route::Command as i32,
    }
}

#[async_trait]
impl OpaqueRelay for PrivateRelay {
    async fn relay(&self, route: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError> {
        // Client-side size gate mirrors the edge HTTP body limit before any
        // network contact; the backend re-validates with the same bound.
        if payload.is_empty() || payload.len() > crate::DEFAULT_MAX_OPAQUE_BODY_BYTES {
            return Err(EdgeError::PayloadTooLarge);
        }
        let mut client = self.client().await?;
        let request = RelayRequest {
            route: proto_route(route),
            ciphertext: payload.to_vec(),
        };
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.relay(tonic::Request::new(request)),
        )
        .await
        .map_err(|_| {
            // A timed-out channel is poisoned for ordering guarantees;
            // drop it so the next call re-dials.
            if let Ok(mut guard) = self.channel.try_write() {
                *guard = None;
            }
            EdgeError::BackendUnavailable
        })?
        .map_err(|_| EdgeError::BackendUnavailable)?;
        let ciphertext = response.into_inner().ciphertext;
        if ciphertext.is_empty() {
            return Err(EdgeError::BackendUnavailable);
        }
        Ok(Bytes::from(ciphertext))
    }
}
