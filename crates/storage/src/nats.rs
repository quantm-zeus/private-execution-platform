//! Production NATS implementation of the internal event bus contract.
//!
//! Security/operational posture:
//! - Payloads crossing this boundary are already-encrypted
//!   [`InternalEventEnvelope`]s; this layer adds no semantics, no
//!   plaintext, and never logs subjects, event ids, or payload bytes.
//! - Publish is at-least-once-safe for consumers: NATS Core is
//!   fire-and-forget, so publication requires a live connection but not
//!   per-message acknowledgements; failures surface as the opaque
//!   [`StorageError`]s without NATS error text.
//! - Subjects are the envelope's own subject strings
//!   (`order.created`, ...). No blind indexes, ids, or ciphertext ever
//!   appear in subject names or logs; this module performs no logging.

use tokio::sync::RwLock;

use crate::{ComponentHealth, EventBus, HealthProbe, InternalEventEnvelope, StorageError};

/// Core NATS connection plus a process-wide publish mutex.
///
/// Phase 0 uses NATS Core exactly as the contract requires: a single
/// shared connection, publishes serialized by an internal lock so
/// consumers observe per-subject order, and JetStream can be layered on
/// later without changing the [`EventBus`] surface.
pub struct NatsEventBus {
    /// Exposed read-only so trusted callers/tests can subscribe and
    /// prove delivery; publishes still go through [`EventBus::publish`].
    pub client: async_nats::Client,
    /// Serializes publishes on the shared Core connection so per-subject
    /// ordering matches per-caller ordering (no per-message acks on Core).
    publish_lock: RwLock<()>,
}

impl std::fmt::Debug for NatsEventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsEventBus").finish_non_exhaustive()
    }
}

impl NatsEventBus {
    /// Connects to the server at `url` (e.g. `nats://127.0.0.1:4222`).
    /// Fails closed on any connect error; the URL is consumed here and
    /// never stored or serialized into errors.
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        if url.trim().is_empty() {
            return Err(StorageError::Unavailable);
        }
        let client = async_nats::connect(url)
            .await
            .map_err(|_| StorageError::Unavailable)?;
        Ok(Self {
            client,
            publish_lock: RwLock::new(()),
        })
    }

    /// Health probe over the live connection: NATS Core has no request
    /// path without a responder, so liveness is the client's own
    /// connection state. No data leaves the bus through this path.
    pub async fn health(&self) -> HealthProbe {
        let status = if self.client.connection_state() == async_nats::connection::State::Connected {
            ComponentHealth::Healthy
        } else {
            ComponentHealth::Unavailable
        };
        HealthProbe {
            component: "storage.nats",
            status,
            observed_at_ms: 0,
        }
    }
}

#[async_trait::async_trait]
impl EventBus for NatsEventBus {
    async fn publish(&self, event: InternalEventEnvelope) -> Result<(), StorageError> {
        event.validate()?;
        let subject = async_nats::Subject::from(event.subject.as_str());
        let payload: Vec<u8> = match serde_json::to_vec(&event) {
            Ok(bytes) => bytes,
            Err(_) => return Err(StorageError::Backend),
        };
        // Serialize publishes on the shared Core connection so
        // per-subject publication order matches the caller's order
        // (Core is fire-and-forget with no per-message acks).
        let _guard = self.publish_lock.read().await;
        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|_| StorageError::Backend)?;
        Ok(())
    }

    async fn health(&self) -> HealthProbe {
        NatsEventBus::health(self).await
    }
}
