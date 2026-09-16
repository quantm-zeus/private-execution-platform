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
/// `x-auth-request-*`, …).
pub const ACCESS_ASSERTION_PREFIXES: [&str; 2] = ["x-", "cf-"];

/// Exact forwarding/topology header names that are client-controllable and must
/// never be accepted as the perimeter access assertion.
///
/// These carry request routing/topology data that a browser or generic proxy can
/// set, so a deployment that named one as its assertion would authorize ordinary
/// requests. The dedicated `cf-access-jwt-assertion`, the oauth2-proxy
/// `x-auth-request-*` family, and the oauth2-proxy identity seam
/// (`x-forwarded-access-token`/`-user`/`-email`/`-groups`) are intentionally not
/// listed and stay accepted.
pub const FORBIDDEN_ASSERTION_HEADERS: [&str; 16] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-forwarded-prefix",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "cf-connecting-ip",
    "cf-pseudo-ipv4",
    "true-client-ip",
    "forwarded",
];

/// Prefix families for topology headers that have multiple variants
/// (`cf-connecting-ipv6`, `cf-ipcountry`, `cf-ipcity`, …). Deliberately narrow:
/// it must not match the accepted oauth2-proxy `x-forwarded-access-token` family.
pub const FORBIDDEN_ASSERTION_PREFIXES: [&str; 2] = ["cf-connecting-ip", "cf-ip"];

/// The only `cf-` header that may be the perimeter access assertion.
///
/// Cloudflare stamps many `cf-*` headers on every proxied request (`cf-ray`,
/// `cf-worker`, `cf-cache-status`, `cf-request-id`, …), so accepting any `cf-`
/// header as the assertion would authorize ordinary traffic that merely reached
/// Cloudflare. The Access JWT assertion is the one header Cloudflare Access adds
/// for an authenticated identity and strips from client input, so it is the only
/// accepted `cf-` seam.
pub const ALLOWED_CF_ASSERTION_HEADERS: [&str; 1] = ["cf-access-jwt-assertion"];

/// Whether `name` (already lowercased by [`HeaderName`]) may be the perimeter
/// assertion. `x-` headers keep the denylist (so the oauth2-proxy
/// `x-auth-request-*` and identity seams stay accepted), while `cf-` headers are
/// restricted to the single Access assertion name.
fn is_forbidden_assertion_header(name: &str) -> bool {
    if name.starts_with("cf-") {
        return !ALLOWED_CF_ASSERTION_HEADERS.contains(&name);
    }
    FORBIDDEN_ASSERTION_HEADERS.contains(&name)
        || FORBIDDEN_ASSERTION_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

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
        // Forwarding/proxy metadata headers are also client-controllable, so an
        // `x-`/`cf-` prefix alone is not enough: reject the known forwarding
        // families before accepting the header as the perimeter assertion.
        if is_forbidden_assertion_header(header.as_str()) {
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
        (Some(cert), Some(key), Some(ca), Some(dns)) => {
            // Whitespace-only values are not configuration: trim before the
            // presence check so a blank path cannot start a permanently-503 edge.
            let (cert, key, ca, dns) = (cert.trim(), key.trim(), ca.trim(), dns.trim());
            if !cert.is_empty() && !key.is_empty() && !ca.is_empty() && !dns.is_empty() {
                Some(service_identity::ServiceIdentityConfig {
                    cert_chain_path: cert.into(),
                    private_key_path: key.into(),
                    ca_path: ca.into(),
                    expected_peer_dns: dns.to_string(),
                })
            } else {
                None
            }
        }
        _ => None,
    };

    match (identity, origin, header) {
        (Some(identity), Some(origin), Some(header)) => {
            let (origin, header) = (origin.trim(), header.trim());
            if !origin.is_empty() && !header.is_empty() {
                Ok(Some(EdgeProductionConfig {
                    relay: PrivateRelayConfig {
                        identity,
                        endpoint_origin: origin.to_string(),
                    },
                    access_assertion_header: header.to_string(),
                }))
            } else {
                Err(EdgeError::InvalidConfiguration)
            }
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
    // Readiness requires both a real authorization backend and the loaded
    // relay identity, then a bounded private-api probe over that identity.
    EdgeState::with_stream_relay(
        authorization,
        relay.clone(),
        stream_relay,
        DEFAULT_MAX_OPAQUE_BODY_BYTES,
    )
    .map(|state| state.with_readiness(true, true, relay))
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
    use axum::body::{Body, Bytes};
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
            "x-auth-request-groups",
        ] {
            assert!(
                HeaderAssertionAuthorization::new(name).is_ok(),
                "{name} is a valid perimeter assertion header"
            );
        }
    }

    #[test]
    fn forwarding_headers_can_never_be_the_assertion() {
        // `x-`/`cf-` alone is not sufficient: these genuine routing/topology
        // headers are client-controllable, so configuring one as the assertion
        // must be a startup error rather than an authorize-everything gate.
        for name in [
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-forwarded-prefix",
            "x-real-ip",
            "x-client-ip",
            "x-cluster-client-ip",
            "x-originating-ip",
            "x-remote-ip",
            "x-remote-addr",
            "cf-connecting-ip",
            "cf-connecting-ipv6",
            "cf-pseudo-ipv4",
            "cf-ipcountry",
            "cf-ipcity",
            "true-client-ip",
        ] {
            assert!(
                HeaderAssertionAuthorization::new(name).is_err(),
                "{name} must not be configurable as the access assertion"
            );
            assert!(is_forbidden_assertion_header(name), "{name}");
        }
        // The dedicated perimeter assertion and the oauth2-proxy identity seam
        // are explicitly not forbidden, so they stay usable.
        for name in [
            "cf-access-jwt-assertion",
            "x-auth-request-email",
            "x-forwarded-access-token",
            "x-forwarded-user",
            "x-forwarded-email",
            "x-forwarded-groups",
        ] {
            assert!(
                !is_forbidden_assertion_header(name),
                "{name} must stay accepted"
            );
            assert!(
                HeaderAssertionAuthorization::new(name).is_ok(),
                "{name} is a valid perimeter assertion header"
            );
        }
    }

    #[test]
    fn always_present_cf_headers_can_never_be_the_assertion() {
        // Cloudflare stamps these on ordinary proxied requests, so naming one as
        // the assertion would authorize every request that merely reached
        // Cloudflare with no Access authentication.
        for name in [
            "cf-ray",
            "cf-worker",
            "cf-cache-status",
            "cf-request-id",
            "cf-access-client-id",
            "cf-access-client-secret",
            "cf-visitor",
            "cf-ew-via",
        ] {
            assert!(
                HeaderAssertionAuthorization::new(name).is_err(),
                "{name} must not be configurable as the access assertion"
            );
            assert!(is_forbidden_assertion_header(name), "{name}");
        }
        // The single Access identity assertion is the only accepted `cf-` seam.
        assert!(HeaderAssertionAuthorization::new("cf-access-jwt-assertion").is_ok());
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
        // A whitespace-only value is not configuration either.
        assert_eq!(
            resolve_config(
                s("   "),
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
                s("https://private.internal"),
                s("\t")
            ),
            Err(EdgeError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn a_forged_or_absent_perimeter_assertion_is_gated_at_the_router() {
        let authorization =
            Arc::new(HeaderAssertionAuthorization::new("cf-access-jwt-assertion").expect("config"));
        let state = crate::EdgeState::new(
            authorization,
            Arc::new(crate::UnavailableRelay),
            DEFAULT_MAX_OPAQUE_BODY_BYTES,
        )
        .expect("state");
        let app = crate::router(state);

        let call = |headers: HeaderMap| {
            let app = app.clone();
            async move {
                let mut builder = Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap")
                    .header("content-type", "application/octet-stream");
                for (name, value) in headers.iter() {
                    builder = builder.header(name.clone(), value.clone());
                }
                app.oneshot(builder.body(Body::from(vec![1u8, 2, 3])).expect("request"))
                    .await
                    .expect("response")
            }
        };

        // No perimeter assertion: refused before any backend contact.
        assert_eq!(
            call(HeaderMap::new()).await.status(),
            StatusCode::UNAUTHORIZED
        );

        // Forwarding headers a client or generic proxy can set never satisfy the
        // configured perimeter assertion.
        for name in [
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
            "cf-connecting-ip",
        ] {
            let mut wrong = HeaderMap::new();
            wrong.insert(
                HeaderName::from_static(name),
                "203.0.113.7".parse().expect("value"),
            );
            assert_eq!(
                call(wrong).await.status(),
                StatusCode::UNAUTHORIZED,
                "{name} must not authorize"
            );
        }

        // The configured assertion alone authorizes; with no relay wired the
        // backend stays unavailable. This is exactly why a non-loopback bind is
        // refused until a cryptographic Access-JWT check exists: a direct-origin
        // caller who can reach the listener could otherwise forge the header.
        let mut forged = HeaderMap::new();
        forged.insert(
            HeaderName::from_static("cf-access-jwt-assertion"),
            "forged-by-a-direct-origin-caller".parse().expect("value"),
        );
        assert_eq!(call(forged).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// TRUST BOUNDARY, pinned explicitly: the edge verifies only that the
    /// perimeter-injected assertion header is *present*, not that its value is a
    /// valid Cloudflare Access JWT. With a live backend, a forged value is
    /// accepted by design. The compensating control is the non-loopback
    /// `EDGE_BIND_ADDR` refusal in `main.rs` (a direct-origin caller cannot reach
    /// the listener) plus the private-api session/HPKE relay. This test documents
    /// the assumption so a future change cannot mistake it for cryptographic
    /// forgery rejection; if Access-JWT validation is implemented, this test must
    /// be updated to expect 401.
    #[tokio::test]
    async fn a_forged_assertion_value_is_accepted_by_design_with_a_live_backend() {
        struct EchoRelay;
        #[async_trait]
        impl crate::OpaqueRelay for EchoRelay {
            async fn relay(
                &self,
                _route: crate::OpaqueRoute,
                payload: Bytes,
            ) -> Result<Bytes, EdgeError> {
                Ok(payload)
            }
        }

        let authorization =
            Arc::new(HeaderAssertionAuthorization::new("cf-access-jwt-assertion").expect("config"));
        let state = EdgeState::new(
            authorization,
            Arc::new(EchoRelay),
            DEFAULT_MAX_OPAQUE_BODY_BYTES,
        )
        .expect("state");
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bootstrap")
                    .header("content-type", "application/octet-stream")
                    .header(
                        "cf-access-jwt-assertion",
                        "forged-by-a-direct-origin-caller",
                    )
                    .body(Body::from(vec![1u8, 2, 3]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_intended_assertion_header_still_authorizes_at_the_router() {
        let authorization =
            Arc::new(HeaderAssertionAuthorization::new("x-auth-request-email").expect("config"));
        let state = crate::EdgeState::new(
            authorization,
            Arc::new(crate::UnavailableRelay),
            DEFAULT_MAX_OPAQUE_BODY_BYTES,
        )
        .expect("state");
        let app = crate::router(state);

        let request = |name: &'static str, value: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/v1/bootstrap")
                .header("content-type", "application/octet-stream")
                .header(name, value)
                .body(Body::from(vec![1u8, 2, 3]))
                .expect("request")
        };

        // A forwarding header does not satisfy the configured assertion.
        assert_eq!(
            app.clone()
                .oneshot(request("x-forwarded-for", "203.0.113.7"))
                .await
                .expect("response")
                .status(),
            StatusCode::UNAUTHORIZED
        );
        // The configured (intended) assertion header does; with no relay wired
        // the backend is unavailable (503), proving authorization passed.
        assert_eq!(
            app.oneshot(request("x-auth-request-email", "op@example.test"))
                .await
                .expect("response")
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
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
