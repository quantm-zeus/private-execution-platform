//! Internal private authentication service. Not a browser-facing public API.

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auth::{AuthError, AuthState, ChallengeId, PasskeyVerifier, SessionId, UnavailableVerifier};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{header, uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use zeroize::{Zeroize, Zeroizing};

pub const CHALLENGE_COOKIE_NAME: &str = "__Host-evergreen_challenge";
pub const SESSION_COOKIE_NAME: &str = "__Host-evergreen_session";
pub const MAX_ASSERTION_BYTES: usize = 64 * 1024;
const CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Debug)]
pub struct PrivateApiConfig {
    pub rp_id: String,
    pub origin: String,
    pub challenge_ttl_ms: i64,
    pub session_ttl_ms: i64,
    pub artifact_grant_ttl_ms: i64,
}
impl PrivateApiConfig {
    pub fn validate(&self) -> Result<(), PrivateApiError> {
        let invalid = || PrivateApiError::InvalidConfiguration;
        if self.rp_id.is_empty()
            || self.rp_id.trim() != self.rp_id
            || self.rp_id.chars().any(char::is_whitespace)
            || self.rp_id.contains(['/', ':', '?', '#', '@'])
        {
            return Err(invalid());
        }
        let rp_authority: Authority = self.rp_id.parse().map_err(|_| invalid())?;
        if rp_authority.port().is_some() || !valid_hostname(rp_authority.host()) {
            return Err(invalid());
        }

        let origin: Uri = self.origin.parse().map_err(|_| invalid())?;
        if origin.scheme_str() != Some("https") {
            return Err(invalid());
        }
        let origin_authority = origin.authority().ok_or_else(invalid)?;
        if origin_authority.as_str().contains('@') {
            return Err(invalid());
        }
        if let Some(path_and_query) = origin.path_and_query() {
            if path_and_query.query().is_some() || !matches!(path_and_query.path(), "" | "/") {
                return Err(invalid());
            }
        }
        let rp = rp_authority.host().to_ascii_lowercase();
        let host = origin_authority.host().to_ascii_lowercase();
        let bound = host == rp
            || host
                .strip_suffix(&rp)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
        if !bound {
            return Err(invalid());
        }
        if self.challenge_ttl_ms <= 0 || self.session_ttl_ms <= 0 || self.artifact_grant_ttl_ms <= 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<i64, PrivateApiError>;
}

#[derive(Debug)]
struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> Result<i64, PrivateApiError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PrivateApiError::ClockUnavailable)?;
        i64::try_from(duration.as_millis()).map_err(|_| PrivateApiError::ClockUnavailable)
    }
}

#[derive(PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct TransportToken(String);

impl TransportToken {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for TransportToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TransportToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportToken([REDACTED])")
    }
}

#[derive(Default)]
struct TransportState {
    challenges: HashMap<TransportToken, (ChallengeId, i64)>,
    sessions: HashMap<TransportToken, (SessionId, i64)>,
}
impl TransportState {
    fn prune(&mut self, now_ms: i64) {
        self.challenges.retain(|_, (_, expires)| *expires > now_ms);
        self.sessions.retain(|_, (_, expires)| *expires > now_ms);
    }
}

#[derive(Clone)]
pub struct PrivateApiState {
    config: PrivateApiConfig,
    auth: Arc<Mutex<AuthState>>,
    transport: Arc<Mutex<TransportState>>,
    verifier: Arc<dyn PasskeyVerifier>,
    clock: Arc<dyn Clock>,
    auth_enabled: bool,
}

impl PrivateApiState {
    pub fn production(config: PrivateApiConfig) -> Result<Self, PrivateApiError> {
        config.validate()?;
        let auth = AuthState::new(
            config.challenge_ttl_ms,
            config.session_ttl_ms,
            config.artifact_grant_ttl_ms,
        )?;
        Ok(Self {
            config,
            auth: Arc::new(Mutex::new(auth)),
            transport: Arc::new(Mutex::new(TransportState::default())),
            verifier: Arc::new(UnavailableVerifier),
            clock: Arc::new(SystemClock),
            auth_enabled: false,
        })
    }

    #[cfg(test)]
    fn with_test_dependencies(
        config: PrivateApiConfig,
        verifier: Arc<dyn PasskeyVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PrivateApiError> {
        config.validate()?;
        let auth = AuthState::new(
            config.challenge_ttl_ms,
            config.session_ttl_ms,
            config.artifact_grant_ttl_ms,
        )?;
        Ok(Self {
            config,
            auth: Arc::new(Mutex::new(auth)),
            transport: Arc::new(Mutex::new(TransportState::default())),
            verifier,
            clock,
            auth_enabled: true,
        })
    }
}

pub fn router(state: PrivateApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/internal/auth/challenge", post(issue_challenge))
        .route("/internal/auth/verify", post(verify_challenge))
        .route("/internal/auth/session", get(validate_session))
        .layer(DefaultBodyLimit::max(MAX_ASSERTION_BYTES))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn issue_challenge(State(state): State<PrivateApiState>) -> Response {
    if !state.auth_enabled {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let challenge = {
        let mut auth = match state.auth.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        match auth.issue_challenge(&state.config.rp_id, &state.config.origin, now) {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        }
    };
    let token = match random_transport_token() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let cookie = challenge_cookie(token.as_str(), state.config.challenge_ttl_ms);
    {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        transport
            .challenges
            .insert(token, (challenge.id().clone(), challenge.expires_at_ms()));
    }
    let mut response = no_store(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, CONTENT_TYPE)],
            Bytes::copy_from_slice(challenge.challenge_bytes()),
        )
            .into_response(),
    );
    if set_cookie(&mut response, cookie).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    response
}

async fn verify_challenge(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !state.auth_enabled {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    if content_type(&headers) != Some(CONTENT_TYPE) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let challenge_token = match cookie_value(&headers, CHALLENGE_COOKIE_NAME) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return generic_error(StatusCode::UNAUTHORIZED),
    };
    let assertion = match to_bytes(body, MAX_ASSERTION_BYTES).await {
        Ok(v) => Zeroizing::new(v.to_vec()),
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    if assertion.is_empty() {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let challenge_id = {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        match transport.challenges.remove(challenge_token) {
            Some((id, _)) => id,
            None => return clear_challenge(generic_error(StatusCode::UNAUTHORIZED)),
        }
    };
    let mut auth = match state.auth.lock() {
        Ok(v) => v,
        Err(_) => return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let session_result = auth.verify_challenge(
        &challenge_id,
        &state.config.rp_id,
        &state.config.origin,
        &assertion,
        now,
        state.verifier.as_ref(),
    );
    drop(auth);
    let session = match session_result {
        Ok(v) => v,
        Err(AuthError::VerifierUnavailable | AuthError::EntropyUnavailable) => {
            return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(_) => return clear_challenge(generic_error(StatusCode::UNAUTHORIZED)),
    };
    let session_token = match random_transport_token() {
        Ok(v) => v,
        Err(_) => return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let session_cookie = session_cookie(session_token.as_str(), state.config.session_ttl_ms);
    {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
        };
        transport.prune(now);
        transport.sessions.insert(
            session_token,
            (session.id().clone(), session.expires_at_ms()),
        );
    }
    let mut response = no_store(StatusCode::NO_CONTENT.into_response());
    if set_cookie(&mut response, session_cookie).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    if append_cookie(&mut response, expired_cookie(CHALLENGE_COOKIE_NAME)).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    response
}

async fn validate_session(State(state): State<PrivateApiState>, headers: HeaderMap) -> Response {
    if !state.auth_enabled {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let token = match cookie_value(&headers, SESSION_COOKIE_NAME) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return generic_error(StatusCode::UNAUTHORIZED),
    };
    let session_id = {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        match transport.sessions.get(token) {
            Some((id, _)) => id.clone(),
            None => return clear_session(generic_error(StatusCode::UNAUTHORIZED)),
        }
    };
    let valid = match state.auth.lock() {
        Ok(auth) => auth.validate_session(&session_id, now).is_ok(),
        Err(_) => false,
    };
    if valid {
        no_store(StatusCode::NO_CONTENT.into_response())
    } else {
        clear_session(generic_error(StatusCode::UNAUTHORIZED))
    }
}

fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
}

fn cookie_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, PrivateApiError> {
    let mut cookie_headers = headers.get_all(header::COOKIE).iter();
    let Some(header_value) = cookie_headers.next() else {
        return Ok(None);
    };
    if cookie_headers.next().is_some() {
        return Err(PrivateApiError::InvalidCookie);
    }
    let cookie = header_value
        .to_str()
        .map_err(|_| PrivateApiError::InvalidCookie)?;
    let mut found = None;
    for part in cookie.split(';').map(str::trim) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key == name {
            if value.is_empty() || found.is_some() {
                return Err(PrivateApiError::InvalidCookie);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn random_transport_token() -> Result<TransportToken, PrivateApiError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 32];
    if getrandom::getrandom(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(PrivateApiError::EntropyUnavailable);
    }
    let mut token = String::with_capacity(64);
    for &byte in &bytes {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    bytes.zeroize();
    Ok(TransportToken(token))
}

fn max_age_seconds(ttl_ms: i64) -> i64 {
    ((ttl_ms + 999) / 1000).max(1)
}
fn challenge_cookie(token: &str, ttl_ms: i64) -> String {
    secure_cookie(CHALLENGE_COOKIE_NAME, token, max_age_seconds(ttl_ms))
}
fn session_cookie(token: &str, ttl_ms: i64) -> String {
    secure_cookie(SESSION_COOKIE_NAME, token, max_age_seconds(ttl_ms))
}
fn secure_cookie(name: &str, token: &str, max_age: i64) -> String {
    format!("{name}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}")
}
fn expired_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

fn set_cookie(response: &mut Response, mut value: String) -> Result<(), PrivateApiError> {
    let result = HeaderValue::from_str(&value)
        .map(|parsed| {
            response.headers_mut().insert(header::SET_COOKIE, parsed);
        })
        .map_err(|_| PrivateApiError::InvalidCookie);
    value.zeroize();
    result
}
fn append_cookie(response: &mut Response, mut value: String) -> Result<(), PrivateApiError> {
    let result = HeaderValue::from_str(&value)
        .map(|parsed| {
            response.headers_mut().append(header::SET_COOKIE, parsed);
        })
        .map_err(|_| PrivateApiError::InvalidCookie);
    value.zeroize();
    result
}
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
fn clear_challenge(mut response: Response) -> Response {
    let _ = append_cookie(&mut response, expired_cookie(CHALLENGE_COOKIE_NAME));
    no_store(response)
}
fn clear_session(mut response: Response) -> Response {
    let _ = append_cookie(&mut response, expired_cookie(SESSION_COOKIE_NAME));
    no_store(response)
}
fn generic_error(status: StatusCode) -> Response {
    no_store((status, "request unavailable").into_response())
}

#[derive(Debug)]
pub enum PrivateApiError {
    InvalidConfiguration,
    ClockUnavailable,
    EntropyUnavailable,
    InvalidCookie,
    Auth(AuthError),
}
impl From<AuthError> for PrivateApiError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tower::ServiceExt;

    struct AcceptVerifier;
    impl PasskeyVerifier for AcceptVerifier {
        fn verify(
            &self,
            _: &[u8; 32],
            assertion: &[u8],
            _: &str,
            _: &str,
        ) -> Result<(), AuthError> {
            if assertion == b"valid-assertion" {
                Ok(())
            } else {
                Err(AuthError::VerificationFailed)
            }
        }
    }
    struct FixedClock(AtomicI64);
    impl Clock for FixedClock {
        fn now_ms(&self) -> Result<i64, PrivateApiError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    fn config() -> PrivateApiConfig {
        PrivateApiConfig {
            rp_id: "example.com".into(),
            origin: "https://example.com".into(),
            challenge_ttl_ms: 60_000,
            session_ttl_ms: 120_000,
            artifact_grant_ttl_ms: 30_000,
        }
    }

    fn config_with(rp_id: &str, origin: &str) -> PrivateApiConfig {
        PrivateApiConfig {
            rp_id: rp_id.into(),
            origin: origin.into(),
            ..config()
        }
    }

    #[test]
    fn private_api_config_accepts_exact_and_subdomain_https_origins() {
        for origin in ["https://example.com", "https://login.example.com:8443"] {
            assert!(
                config_with("example.com", origin).validate().is_ok(),
                "expected {origin} to be accepted"
            );
        }
    }

    #[test]
    fn private_api_config_rejects_invalid_rp_id_or_origin() {
        let invalid = [
            config_with("example.com", "http://example.com"),
            config_with("example.com", "https://example.com/login?next=/"),
            config_with("example.com", "https://example.com/login#fragment"),
            config_with("https://example.com", "https://example.com"),
            config_with("example.com:8443", "https://example.com:8443"),
            config_with(" example.com", "https://example.com"),
            config_with("example.com ", "https://example.com"),
            config_with("example.com", "https://not-example.com"),
            config_with("example.com", "https://unrelated.com"),
            config_with("example.com", "https://notexample.com"),
        ];
        for config in invalid {
            assert!(
                config.validate().is_err(),
                "expected {config:?} to be rejected"
            );
        }
    }
    fn test_state(clock: Arc<FixedClock>) -> PrivateApiState {
        PrivateApiState::with_test_dependencies(config(), Arc::new(AcceptVerifier), clock).unwrap()
    }
    async fn begin(app: Router) -> (String, Bytes) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (cookie, body)
    }

    #[tokio::test]
    async fn production_default_is_unavailable() {
        let state = PrivateApiState::production(config()).unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn challenge_is_binary_and_cookie_is_secure() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (cookie, body) = begin(router(test_state(clock))).await;
        assert_eq!(body.len(), 32);
        assert!(cookie.starts_with(CHALLENGE_COOKIE_NAME));
        let full = secure_cookie(CHALLENGE_COOKIE_NAME, "x", 10);
        for required in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(full.contains(required));
        }
    }

    #[tokio::test]
    async fn successful_verify_mints_http_only_session_and_session_validates() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from("valid-assertion"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(SESSION_COOKIE_NAME)
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap();
        let session = router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/auth/session")
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn failed_assertion_consumes_transport_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let make = || {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from("bad"))
                .unwrap()
        };
        assert_eq!(
            router(state.clone())
                .oneshot(make())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            router(state).oneshot(make()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn expired_session_cookie_is_rejected() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock.clone());
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from("valid-assertion"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(SESSION_COOKIE_NAME)
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap();
        clock.0.store(121_001, Ordering::SeqCst);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/auth/session")
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ambiguous_challenge_cookies_fail_closed_without_consuming_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let (challenge_cookie, _) = begin(router(state.clone())).await;

        let duplicate_value =
            format!("{challenge_cookie}; {CHALLENGE_COOKIE_NAME}=different-token");
        let duplicate = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header(header::COOKIE, duplicate_value)
            .body(Body::from("valid-assertion"))
            .unwrap();
        assert_eq!(
            router(state.clone())
                .oneshot(duplicate)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let multiple_headers = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie.clone())
            .header(header::COOKIE, "other_cookie=value")
            .body(Body::from("valid-assertion"))
            .unwrap();
        assert_eq!(
            multiple_headers
                .headers()
                .get_all(header::COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(
            router(state.clone())
                .oneshot(multiple_headers)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let valid = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie)
            .body(Body::from("valid-assertion"))
            .unwrap();
        assert_eq!(
            router(state).oneshot(valid).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
    }

    #[test]
    fn transport_token_debug_is_redacted() {
        let token = random_transport_token().unwrap();
        let debug = format!("{token:?}");
        assert_eq!(debug, "TransportToken([REDACTED])");
        assert!(!debug.contains(token.as_str()));
    }

    #[tokio::test]
    async fn auth_responses_are_no_store_and_stale_cookies_are_cleared() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let challenge = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            challenge.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let stale_challenge = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, CONTENT_TYPE)
                    .header(header::COOKIE, format!("{CHALLENGE_COOKIE_NAME}=deadbeef"))
                    .body(Body::from("valid-assertion"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_challenge.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            stale_challenge
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert!(stale_challenge
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                let s = v.to_str().unwrap();
                s.starts_with(CHALLENGE_COOKIE_NAME) && s.contains("Max-Age=0")
            }));

        let stale_session = router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/auth/session")
                    .header(header::COOKIE, format!("{SESSION_COOKIE_NAME}=deadbeef"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_session.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            stale_session.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(stale_session
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                let s = v.to_str().unwrap();
                s.starts_with(SESSION_COOKIE_NAME) && s.contains("Max-Age=0")
            }));
    }

    #[tokio::test]
    async fn malformed_verify_does_not_consume_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let make = |body: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from(body))
                .unwrap()
        };
        assert_eq!(
            router(state.clone())
                .oneshot(make(""))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let response = router(state)
            .oneshot(make("valid-assertion"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn same_challenge_cookie_single_use_across_verify_attempts() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state = test_state(clock);
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let make = || {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from("valid-assertion"))
                .unwrap()
        };
        assert_eq!(
            router(state.clone())
                .oneshot(make())
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            router(state).oneshot(make()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn verifier_failure_consumes_challenge() {
        struct RejectVerifier;
        impl PasskeyVerifier for RejectVerifier {
            fn verify(&self, _: &[u8; 32], _: &[u8], _: &str, _: &str) -> Result<(), AuthError> {
                Err(AuthError::VerificationFailed)
            }
        }
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let state =
            PrivateApiState::with_test_dependencies(config(), Arc::new(RejectVerifier), clock)
                .unwrap();
        let (challenge_cookie, _) = begin(router(state.clone())).await;
        let make = || {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from("valid-assertion"))
                .unwrap()
        };
        assert_eq!(
            router(state.clone())
                .oneshot(make())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            router(state).oneshot(make()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
