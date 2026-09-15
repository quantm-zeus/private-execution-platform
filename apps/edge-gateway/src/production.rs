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

/// Custom-header prefixes the perimeter access assertion must use.
///
/// The assertion proves the request crossed the operator's perimeter, which adds
/// and strips it. Browsers and generic proxies always set standard headers
/// (`accept`, `authorization`, `cookie`, `content-type`, `origin`, `user-agent`,
/// `sec-fetch-*`, …), so allowing one as the assertion would authorize ordinary
/// requests — the exact opposite of the gate. Requiring a custom-header prefix
/// (`cf-`/`x-`) makes that misconfiguration a startup error while still
/// accepting the real perimeter seams (`cf-access-jwt-assertion`,
/// `x-auth-request-*`, `x-forwarded-access-*`, …).
pub const ACCESS_ASSERTION_PREFIXES: [&str; 2] = ["x-", "cf-"];

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
        // Only a custom (`x-`/`cf-`) header can be the perimeter assertion; a
        // standard header would be present on ordinary requests.
        if !ACCESS_ASSERTION_PREFIXES
            .iter()
            .any(|prefix| header.as_str().starts_with(prefix))
        {
            return Err(EdgeError::InvalidConfiguration);
        }
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
#[derive(Clone, PartialEq, Eq)]
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
    resolve_config(
        read_env("EDGE_TLS_CERT")?,
        read_env("EDGE_TLS_KEY")?,
        read_env("EDGE_TLS_CA")?,
        read_env("EDGE_PRIVATE_API_DNS")?,
        read_env("EDGE_PRIVATE_API_ORIGIN")?,
        read_env(ACCESS_ASSERTION_HEADER_ENV)?,
    )
}

/// Read one composition variable, treating a present-but-non-Unicode value as a
/// configuration error rather than as absent (an operator who set it has
/// attempted to configure the edge).
fn read_env(name: &str) -> Result<Option<String>, EdgeError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(EdgeError::InvalidConfiguration),
    }
}

/// Pure resolver for the six composition inputs, so the all-or-none rule is
/// testable without mutating the process environment.
///
/// * No input present at all => `Ok(None)` (the intended fail-closed default).
/// * Every input present and non-empty => `Ok(Some(..))`.
/// * *Any* input present but the set incomplete or blank => `Err`. An operator
///   who sets even one of the six has attempted to configure the edge; silently
///   ignoring a partial/blank set would downgrade the deployment to 503s when a
///   typo made the identity incomplete, so it refuses to start instead.
pub fn resolve_config(
    cert: Option<String>,
    key: Option<String>,
    ca: Option<String>,
    dns: Option<String>,
    origin: Option<String>,
    header: Option<String>,
) -> Result<Option<EdgeProductionConfig>, EdgeError> {
    let any_present = cert.is_some()
        || key.is_some()
        || ca.is_some()
        || dns.is_some()
        || origin.is_some()
        || header.is_some();
    if !any_present {
        return Ok(None);
    }

    let identity = match (cert, key, ca, dns) {
        (Some(cert), Some(key), Some(ca), Some(dns))
            if !cert.is_empty() && !key.is_empty() && !ca.is_empty() && !dns.is_empty() =>
        {
            Some(service_identity::ServiceIdentityConfig {
                cert_chain_path: cert.into(),
                private_key_path: key.into(),
                ca_path: ca.into(),
                expected_peer_dns: dns,
            })
        }
        _ => None,
    };

    match (identity, origin, header) {
        (Some(identity), Some(origin), Some(header))
            if !origin.is_empty() && !header.is_empty() =>
        {
            Ok(Some(EdgeProductionConfig {
                relay: PrivateRelayConfig {
                    identity,
                    endpoint_origin: origin,
                },
                access_assertion_header: header,
            }))
        }
        // Any present-but-incomplete set is an operator error: refuse startup
        // rather than silently serving 503s.
        _ => Err(EdgeError::InvalidConfiguration),
    }
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

    #[test]
    fn a_browser_controlled_header_can_never_be_the_assertion() {
        // A standard header a browser or proxy sets itself would authorize
        // ordinary requests, so it is a configuration error rather than a silent
        // authorize-everything gate.
        for name in [
            "cookie",
            "Cookie",
            "authorization",
            "Proxy-Authorization",
            "content-type",
            "origin",
            "referer",
            "user-agent",
            "host",
            "content-length",
            "accept",
            "accept-language",
            "sec-fetch-site",
            "priority",
        ] {
            assert!(
                HeaderAssertionAuthorization::new(name).is_err(),
                "{name} must not be configurable as the access assertion"
            );
        }
        // The real perimeter seams (custom `cf-`/`x-` headers) are accepted.
        for name in [
            "cf-access-jwt-assertion",
            "x-auth-request-email",
            "x-forwarded-access",
        ] {
            assert!(
                HeaderAssertionAuthorization::new(name).is_ok(),
                "{name} is a valid perimeter assertion header"
            );
        }
    }

    fn s(value: &str) -> Option<String> {
        Some(value.to_string())
    }

    #[test]
    fn a_fully_unset_composition_is_the_fail_closed_default() {
        assert_eq!(resolve_config(None, None, None, None, None, None), Ok(None));
    }

    #[test]
    fn a_complete_composition_resolves() {
        let resolved = resolve_config(
            s("cert.pem"),
            s("key.pem"),
            s("ca.pem"),
            s("private-api.internal"),
            s("https://private.internal:8443"),
            s("cf-access-jwt-assertion"),
        )
        .expect("complete config");
        let config = resolved.expect("some config");
        assert_eq!(
            config.relay.endpoint_origin,
            "https://private.internal:8443"
        );
        assert_eq!(config.access_assertion_header, "cf-access-jwt-assertion");
    }

    #[test]
    fn a_partial_or_blank_composition_refuses_startup() {
        // A single identity variable is an attempted configuration, not the
        // fail-closed default: it must be refused rather than silently ignored.
        assert_eq!(
            resolve_config(s("cert.pem"), None, None, None, None, None),
            Err(EdgeError::InvalidConfiguration)
        );
        // Identity present but no origin/header.
        assert_eq!(
            resolve_config(
                s("cert.pem"),
                s("key.pem"),
                s("ca.pem"),
                s("dns"),
                None,
                None
            ),
            Err(EdgeError::InvalidConfiguration)
        );
        // Origin/header present but no identity.
        assert_eq!(
            resolve_config(
                None,
                None,
                None,
                None,
                s("https://private.internal"),
                s("cf-access-jwt-assertion")
            ),
            Err(EdgeError::InvalidConfiguration)
        );
        // A present-but-empty value is invalid, not "absent".
        assert_eq!(
            resolve_config(
                s(""),
                s("key.pem"),
                s("ca.pem"),
                s("dns"),
                s("https://private.internal"),
                s("cf-access-jwt-assertion")
            ),
            Err(EdgeError::InvalidConfiguration)
        );
        assert_eq!(
            resolve_config(
                s("cert.pem"),
                s("key.pem"),
                s("ca.pem"),
                s("dns"),
                s(""),
                s("cf-access-jwt-assertion")
            ),
            Err(EdgeError::InvalidConfiguration)
        );
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
