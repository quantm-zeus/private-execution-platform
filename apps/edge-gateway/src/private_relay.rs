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
use rpc_contracts::relay_stream_service_client::RelayStreamServiceClient;
use rpc_contracts::{RelayRequest, Route, StreamFrame as WireStreamFrame};
use service_identity::ServiceIdentityConfig;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;

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
    /// Serializes dials. Held across the network wait *instead of* the channel
    /// write lock, so a black-holed backend cannot block readers that only need
    /// the cached channel.
    dial: tokio::sync::Mutex<()>,
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
            dial: tokio::sync::Mutex::new(()),
        }))
    }

    /// Shared lazily-dialed mTLS channel to the private-api relay endpoint.
    ///
    /// The unary relay and the realtime bidi stream share one channel so a
    /// reconnect never leaves two divergent TLS sessions to the same peer.
    pub(crate) async fn channel(&self) -> Result<tonic::transport::Channel, EdgeError> {
        // Fast path: a cached channel, under a read guard released immediately.
        let cached = { self.channel.read().await.clone() };
        if let Some(channel) = cached {
            return Ok(channel);
        }
        // Serialize dials without holding the channel lock across the network
        // wait, so a black-holed backend cannot block every reader behind one
        // in-flight dial.
        let _dial = self.dial.lock().await;
        let cached = { self.channel.read().await.clone() };
        if let Some(channel) = cached {
            return Ok(channel);
        }
        let endpoint = service_identity::configure_client_endpoint(
            tonic::transport::Endpoint::from_shared(self.config.endpoint_origin.clone())
                .map_err(|_| EdgeError::InvalidConfiguration)?,
            &self.config.identity,
        )
        .map_err(|_| EdgeError::InvalidConfiguration)?;
        // A bounded connect timeout keeps one unreachable backend from wedging
        // the relay indefinitely.
        let channel = endpoint
            .connect_timeout(std::time::Duration::from_secs(10))
            .connect()
            .await
            .map_err(|_| EdgeError::BackendUnavailable)?;
        *self.channel.write().await = Some(channel.clone());
        Ok(channel)
    }

    async fn client(&self) -> Result<RelayServiceClient<tonic::transport::Channel>, EdgeError> {
        Ok(RelayServiceClient::new(self.channel().await?))
    }

    /// Drop the cached channel so the next call re-dials. Used when a stream
    /// handshake fails and the channel may be poisoned.
    async fn reset_channel(&self) {
        let mut guard = self.channel.write().await;
        *guard = None;
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

/// Bounded queues between the browser WebSocket and the gRPC bidi stream.
const STREAM_QUEUE: usize = 64;
/// Bound the bidi handshake so a hung backend cannot stall the WS upgrade.
const STREAM_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Production opaque realtime relay: edge `/v1/stream` <-> private-api
/// `RelayStreamService` over the same pinned mTLS channel as the unary relay.
///
/// Only ciphertext frames cross either hop. Both directions are size-bounded and
/// every transport/gRPC failure collapses to [`EdgeError::BackendUnavailable`];
/// the edge never inspects the envelope, the `kid` or any frame content.
pub struct PrivateStreamRelay {
    relay: Arc<PrivateRelay>,
}

impl std::fmt::Debug for PrivateStreamRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateStreamRelay").finish_non_exhaustive()
    }
}

impl PrivateStreamRelay {
    /// Share the unary relay's validated config and mTLS channel.
    pub fn new(relay: Arc<PrivateRelay>) -> Arc<Self> {
        Arc::new(Self { relay })
    }
}

#[async_trait]
impl crate::OpaqueStreamRelay for PrivateStreamRelay {
    async fn open(&self) -> Result<crate::OpaqueStreamBridge, EdgeError> {
        let mut client = RelayStreamServiceClient::new(self.relay.channel().await?);
        let (to_backend_tx, mut to_backend_rx) = mpsc::channel::<Bytes>(STREAM_QUEUE);
        let (grpc_tx, grpc_rx) = mpsc::channel::<WireStreamFrame>(STREAM_QUEUE);
        let response = match tokio::time::timeout(
            STREAM_OPEN_TIMEOUT,
            client.stream(tonic::Request::new(ReceiverStream::new(grpc_rx))),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                // A timed-out/failed handshake may leave a poisoned channel; drop
                // it so the next upgrade re-dials instead of re-waiting the full
                // timeout.
                self.relay.reset_channel().await;
                return Err(EdgeError::BackendUnavailable);
            }
        };
        let mut inbound = response.into_inner();
        let (from_backend_tx, from_backend_rx) = mpsc::channel::<Bytes>(STREAM_QUEUE);
        // Browser -> backend: never buffer a cleared channel indefinitely.
        tokio::spawn(async move {
            while let Some(bytes) = to_backend_rx.recv().await {
                if grpc_tx
                    .send(WireStreamFrame {
                        ciphertext: bytes.to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        // Backend -> browser: enforce the same size bound the unary path uses.
        tokio::spawn(async move {
            while let Ok(Some(frame)) = inbound.message().await {
                if frame.ciphertext.is_empty()
                    || frame.ciphertext.len() > crate::DEFAULT_MAX_OPAQUE_BODY_BYTES
                {
                    break;
                }
                if from_backend_tx
                    .send(Bytes::from(frame.ciphertext))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(crate::OpaqueStreamBridge::new(
            to_backend_tx,
            from_backend_rx,
        ))
    }
}
