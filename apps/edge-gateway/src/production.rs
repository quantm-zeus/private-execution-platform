//! Production edge composition (BR-7): wire the real opaque relay instead of
//! the fail-closed `Unavailable*` defaults.
//!
//! This module is the single place that turns operator-supplied environment
//! configuration into a live [`EdgeState`]. It is strictly opt-in and
//! fail-closed:
//!
//! * With no relay identity configured, the edge keeps `EdgeState::unavailable()`
//!   and every `/v1/*` request is a `503` — never a silent cleartext fallback.
//! * With an identity, the edge forwards ciphertext only, over the pinned
//!   internal mTLS boundary. It never parses the envelope, the `kid` or any
//!   trading semantic (PRD line 71 / INVARIANTS #8).
//!
//! Authorization is a separate operator-owned seam. The platform perimeter is
//! an external access layer (Cloudflare Access + passkey); the edge cannot
//! validate the private-API session cookie (that store lives in the private
//! origin), so the operator supplies an assertion header that the perimeter
//! injects and strips. [`HeaderAssertionAuthorization`] requires that header to
//! be present and non-empty; it never trusts a browser-supplied header on its
//! own, and it fails closed when unconfigured.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{header::HeaderName, HeaderMap};

use crate::private_relay::{PrivateRelay, PrivateRelayConfig, PrivateStreamRelay};
use crate::{AuthorizationBackend, EdgeError, EdgeState, DEFAULT_MAX_OPAQUE_BODY_BYTES};

/// Environment variable naming the operator's access-assertion header.
pub const ACCESS_ASSERTION_HEADER_ENV: &str = "EDGE_ACCESS_ASSERTION_HEADER";

/// Authorization backend that requires the configured access-assertion header.
///
/// The perimeter (Cloudflare Access or an equivalent reverse proxy) is
/// responsible for authenticating the browser and adding this header, and for
/// stripping any client-supplied copy. The edge additionally *requires* the
/// header name to be explicitly configured: an unconfigured edge never
/// authorizes anything.
pub struct HeaderAssertionAuthorization {
    header: HeaderName,
}

impl std::fmt::Debug for HeaderAssertionAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderAssertionAuthorization")
            .field("header", &self.header.as_str())
            .finish()
    }
}

impl HeaderAssertionAuthorization {
    /// Build from an explicit header name. An empty/invalid name is a
    /// configuration error so the edge never silently authorizes everything.
    pub fn new(header_name: &str) -> Result<Self, EdgeError> {
        let trimmed = header_name.trim();
        if trimmed.is_empty() {
            return Err(EdgeError::InvalidConfiguration);
        }
        let header = HeaderName::from_bytes(trimmed.as_bytes())
            .map_err(|_| EdgeError::InvalidConfiguration)?;
        Ok(Self { header })
    }
}

#[async_trait]
impl AuthorizationBackend for HeaderAssertionAuthorization {
    async fn authorize(&self, headers: &HeaderMap) -> Result<(), EdgeError> {
        // Presence of a non-empty assertion is required. The edge does not
        // interpret the value (cryptographic verification of the perimeter JWT
        // is the perimeter's job and belongs to the platform's ingress policy);
        // it must never accept a request the perimeter did not stamp.
        match headers.get(&self.header) {
            Some(value) if !value.is_empty() => Ok(()),
            _ => Err(EdgeError::Unauthorized),
        }
    }
}

/// The fully-resolved production edge wiring, or `None` when the operator has
/// not supplied a relay identity (the caller then keeps the fail-closed
/// default).
#[derive(Clone)]
pub struct EdgeProductionConfig {
    pub relay: PrivateRelayConfig,
    /// Explicit access-assertion header name. Required: without it the edge
    /// cannot distinguish a perimeter-authenticated request from an anonymous
    /// one, so composition fails rather than authorizing everything.
    pub access_assertion_header: String,
}

impl std::fmt::Debug for EdgeProductionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeProductionConfig")
            .field("relay", &self.relay)
            .field("access_assertion_header", &self.access_assertion_header)
            .finish()
    }
}

/// Read the production config from the environment, if fully supplied.
///
/// Returns `Ok(None)` when the relay identity is absent (the intended
/// fail-closed default). Returns `Err` when a *partial* identity is supplied, so
/// a typo in one of the four required variables cannot silently downgrade a
/// deployment to the unavailable edge.
pub fn config_from_env() -> Result<Option<EdgeProductionConfig>, EdgeError> {
    let identity = identity_from_env();
    let endpoint_origin = std::env::var("EDGE_PRIVATE_API_ORIGIN").ok();
    let access_assertion_header = std::env::var(ACCESS_ASSERTION_HEADER_ENV).ok();

    match (identity, endpoint_origin, access_assertion_header) {
        (None, None, None) => Ok(None),
        (Some(identity), Some(endpoint_origin), Some(header)) => Ok(Some(EdgeProductionConfig {
            relay: PrivateRelayConfig {
                identity,
                endpoint_origin,
            },
            access_assertion_header: header,
        })),
        // A partial configuration is an operator error, not a fail-closed
        // default: refuse to start rather than silently serving 503s.
        _ => Err(EdgeError::InvalidConfiguration),
    }
}

/// Read the four mTLS identity variables, requiring all-or-none.
///
/// All four present => `Some`; none present => `None`; a partial set returns
/// `None` here and is caught by [`config_from_env`] as a configuration error.
fn identity_from_env() -> Option<service_identity::ServiceIdentityConfig> {
    let cert_chain_path = std::env::var("EDGE_TLS_CERT").ok()?;
    let private_key_path = std::env::var("EDGE_TLS_KEY").ok()?;
    let ca_path = std::env::var("EDGE_TLS_CA").ok()?;
    let expected_peer_dns = std::env::var("EDGE_PRIVATE_API_DNS").ok()?;
    if cert_chain_path.is_empty()
        || private_key_path.is_empty()
        || ca_path.is_empty()
        || expected_peer_dns.is_empty()
    {
        return None;
    }
    Some(service_identity::ServiceIdentityConfig {
        cert_chain_path: cert_chain_path.into(),
        private_key_path: private_key_path.into(),
        ca_path: ca_path.into(),
        expected_peer_dns,
    })
}

/// Build the live edge state from a validated production config.
pub fn edge_state(config: &EdgeProductionConfig) -> Result<EdgeState, EdgeError> {
    let authorization = Arc::new(HeaderAssertionAuthorization::new(
        &config.access_assertion_header,
    )?);
    let relay = PrivateRelay::new(config.relay.clone())?;
    let stream_relay = PrivateStreamRelay::new(relay.clone());
    // The relay and the stream share one validated config and one mTLS channel.
    EdgeState::with_stream_relay(
        authorization,
        relay,
        stream_relay,
        DEFAULT_MAX_OPAQUE_BODY_BYTES,
    )
}

/// Resolve the production router, failing closed to the unavailable edge when no
/// identity is configured.
pub fn router_from_env() -> Result<axum::Router, EdgeError> {
    match config_from_env()? {
        Some(config) => Ok(crate::router(edge_state(&config)?)),
        None => Ok(crate::default_router()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn authorization_requires_the_configured_header() {
        let backend = HeaderAssertionAuthorization::new("cf-access-jwt-assertion").expect("config");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let empty = HeaderMap::new();
        assert!(runtime.block_on(backend.authorize(&empty)).is_err());

        let mut present = HeaderMap::new();
        present.insert(
            HeaderName::from_static("cf-access-jwt-assertion"),
            "opaque-assertion".parse().expect("header value"),
        );
        assert!(runtime.block_on(backend.authorize(&present)).is_ok());

        // An empty value never authorizes.
        let mut blank = HeaderMap::new();
        blank.insert(
            HeaderName::from_static("cf-access-jwt-assertion"),
            "".parse().expect("empty header value"),
        );
        assert!(runtime.block_on(backend.authorize(&blank)).is_err());
    }

    #[test]
    fn an_empty_or_invalid_header_name_is_a_configuration_error() {
        assert!(HeaderAssertionAuthorization::new("").is_err());
        assert!(HeaderAssertionAuthorization::new("   ").is_err());
        assert!(HeaderAssertionAuthorization::new("bad header name").is_err());
    }

    #[tokio::test]
    async fn an_unconfigured_edge_stays_fail_closed() {
        // No identity => the unavailable default: /v1/* returns 503 and never a
        // cleartext or partially-wired path.
        let app = router(crate::EdgeState::unavailable());
        for path in ["/v1/bootstrap", "/v1/sync", "/v1/command", "/v1/blob"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/octet-stream")
                        .body(Body::from(vec![0u8; 4]))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{path} must fail closed without a relay identity"
            );
        }
    }
}
