//! Internal private authentication service. Not a browser-facing public API.

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auth::passkey::PasskeyCredentialStore;
use auth::passkey::{AuthenticationAttempt, WebAuthnPasskeyAuthenticator};
use auth::{
    ArtifactGrantId, AuthError, AuthState, AuthenticationResult, Passkey, PublicKeyCredential,
    SessionId,
};
use axum::{
    body::{to_bytes, Body},
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
pub const JSON_CONTENT_TYPE: &str = "application/json";
const CONTENT_TYPE: &str = JSON_CONTENT_TYPE;

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

#[derive(Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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

struct PendingAuthentication {
    attempt: AuthenticationAttempt,
    expires_at_ms: i64,
}

#[derive(Default)]
struct TransportState {
    pending: HashMap<TransportToken, PendingAuthentication>,
    sessions: HashMap<TransportToken, (SessionId, i64)>,
    grants: HashMap<TransportToken, PendingArtifactGrant>,
}
impl TransportState {
    fn prune(&mut self, now_ms: i64) {
        self.pending
            .retain(|_, pending| pending.expires_at_ms > now_ms);
        self.sessions.retain(|_, (_, expires)| *expires > now_ms);
        self.grants.retain(|_, grant| grant.expires_at_ms > now_ms);
    }
}

type ArtifactLoader = Arc<dyn Fn() -> Result<Vec<u8>, StatusCode> + Send + Sync>;

#[derive(Clone)]
pub struct PrivateApiState {
    config: PrivateApiConfig,
    auth: Arc<Mutex<AuthState>>,
    transport: Arc<Mutex<TransportState>>,
    authenticator: Option<Arc<WebAuthnPasskeyAuthenticator>>,
    clock: Arc<dyn Clock>,
    artifact_loader: ArtifactLoader,
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
            authenticator: None,
            clock: Arc::new(SystemClock),
            artifact_loader: Arc::new(load_workspace_artifact),
        })
    }

    pub fn with_webauthn(config: PrivateApiConfig) -> Result<Self, PrivateApiError> {
        let authenticator = build_authenticator(&config)?;
        let mut state = Self::production(config)?;
        state.authenticator = Some(Arc::new(authenticator));
        Ok(state)
    }

    #[cfg(test)]
    fn with_test_dependencies(
        config: PrivateApiConfig,
        authenticator: Option<Arc<WebAuthnPasskeyAuthenticator>>,
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
            authenticator,
            clock,
            artifact_loader: Arc::new(load_workspace_artifact),
        })
    }

    #[cfg(test)]
    fn with_artifact_loader(mut self, loader: ArtifactLoader) -> Self {
        self.artifact_loader = loader;
        self
    }
}

struct ProductionPasskeyCredentialStore;

impl PasskeyCredentialStore for ProductionPasskeyCredentialStore {
    fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
        Err(AuthError::VerifierUnavailable)
    }

    fn apply_authentication_result(&self, _: &AuthenticationResult) -> Result<(), AuthError> {
        Err(AuthError::VerifierUnavailable)
    }
}

fn build_authenticator(
    config: &PrivateApiConfig,
) -> Result<WebAuthnPasskeyAuthenticator, PrivateApiError> {
    config.validate()?;
    WebAuthnPasskeyAuthenticator::new(
        &config.rp_id,
        &config.origin,
        Arc::new(ProductionPasskeyCredentialStore),
    )
    .map_err(PrivateApiError::Auth)
}

pub fn router(state: PrivateApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/internal/auth/challenge", post(issue_challenge))
        .route("/internal/auth/verify", post(verify_challenge))
        .route("/internal/auth/session", get(validate_session))
        .route("/internal/artifact/grant", post(issue_artifact_grant))
        .route("/internal/artifact", post(deliver_artifact))
        .layer(DefaultBodyLimit::max(
            MAX_ASSERTION_BYTES.max(MAX_OFFER_BYTES),
        ))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn issue_challenge(State(state): State<PrivateApiState>) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let authenticator = match state.authenticator.as_ref() {
        Some(v) => v.clone(),
        None => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let (options, attempt) = match authenticator.start_authentication() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
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
        transport.pending.insert(
            token,
            PendingAuthentication {
                attempt,
                expires_at_ms: now.saturating_add(state.config.challenge_ttl_ms),
            },
        );
    }
    let body = match serde_json::to_vec(&options) {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut response =
        no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response());
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
    if state.authenticator.is_none() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    if content_type(&headers) != Some(CONTENT_TYPE) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let challenge_token = match cookie_value(&headers, CHALLENGE_COOKIE_NAME) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return generic_error(StatusCode::UNAUTHORIZED),
    };
    let body_bytes = match to_bytes(body, MAX_ASSERTION_BYTES).await {
        Ok(v) => Zeroizing::new(v.to_vec()),
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let credential: PublicKeyCredential = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    // Re-read the clock after the body is fully consumed: a slow-rolled request must
    // not extend the effective validity of the pending attempt beyond its TTL.
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let pending = {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        transport.pending.remove(challenge_token)
    };
    let Some(pending) = pending else {
        return clear_challenge(generic_error(StatusCode::UNAUTHORIZED));
    };
    if pending.expires_at_ms <= now {
        return clear_challenge(generic_error(StatusCode::UNAUTHORIZED));
    }
    let verified = match state
        .authenticator
        .as_ref()
        .expect("checked above")
        .finish_authentication(pending.attempt, &credential)
    {
        Ok(v) => v,
        Err(_) => return clear_challenge(generic_error(StatusCode::UNAUTHORIZED)),
    };
    let mut auth = match state.auth.lock() {
        Ok(v) => v,
        Err(_) => return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let session_result = auth.create_session_from_verified(verified, now);
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
    if append_challenge_clear(&mut response).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    response
}

fn append_challenge_clear(response: &mut Response) -> Result<(), PrivateApiError> {
    append_cookie(response, expired_cookie(CHALLENGE_COOKIE_NAME))
}

fn clear_grant(mut response: Response) -> Response {
    let _ = append_cookie(&mut response, expired_cookie(ARTIFACT_GRANT_COOKIE_NAME));
    response
}

async fn validate_session(State(state): State<PrivateApiState>, headers: HeaderMap) -> Response {
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

const ARTIFACT_GRANT_COOKIE_NAME: &str = "__Host-evergreen_grant";
const MAX_OFFER_BYTES: usize = 4096;
/// Envelope overhead for a delivered artifact: kid (16) + nonce (12) + sequence (8).
const ENVELOPE_OVERHEAD_BYTES: usize = 36;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
pub const ARTIFACT_DELIVERY_CONTENT_TYPE: &str = "application/octet-stream";

/// Request body for `/internal/artifact`: the client's HPKE handshake answer,
/// all fields base64 (standard alphabet, padded).
#[derive(serde::Deserialize)]
struct ArtifactDeliveryRequest {
    grant_id: String,
    kid: String,
    encapsulated_key: String,
}

/// Public wire half of the server's per-grant ephemeral HPKE offer. The private
/// keypair stays in RAM inside the pending grant and is dropped at first use.
#[derive(serde::Serialize)]
struct ArtifactGrantResponse {
    grant_id: String,
    kid: String,
    recipient_public_key: String,
    expires_in_ms: i64,
}

/// A pending artifact grant plus its server-generated ephemeral responder
/// keypair. The keypair exists only between grant issuance and single-use
/// delivery; it is never serialized or logged.
struct PendingArtifactGrant {
    grant_id: ArtifactGrantId,
    session_id: SessionId,
    expires_at_ms: i64,
    offer: crypto_envelope::hpke::HpkeHandshakeOffer,
    keypair: crypto_envelope::hpke::HpkeRecipientKeyPair,
}

async fn issue_artifact_grant(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    if content_type(&headers) != Some(CONTENT_TYPE) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let expires_at_ms = now.saturating_add(state.config.artifact_grant_ttl_ms);
    let grant = {
        let mut auth = match state.auth.lock() {
            Ok(auth) => auth,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        match auth.issue_artifact_grant(&session_id, now) {
            Ok(grant) => grant,
            Err(AuthError::VerifierUnavailable | AuthError::EntropyUnavailable) => {
                return generic_error(StatusCode::SERVICE_UNAVAILABLE)
            }
            Err(_) => return generic_error(StatusCode::UNAUTHORIZED),
        }
    };
    let token = match random_transport_token() {
        Ok(token) => token,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    // Per-grant ephemeral responder keypair. The offer half is published to the
    // authenticated client in this response (ADR 0001: the offer must ride the
    // authenticated session channel); the private half never leaves RAM.
    let kid = match random_kid() {
        Ok(kid) => kid,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let (offer, keypair) = match crypto_envelope::hpke::HpkeHandshakeOffer::generate(kid) {
        Ok(result) => result,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    {
        let mut transport = match state.transport.lock() {
            Ok(transport) => transport,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        transport.grants.insert(
            token.clone(),
            PendingArtifactGrant {
                grant_id: grant.id().clone(),
                session_id,
                expires_at_ms,
                offer: offer.clone(),
                keypair,
            },
        );
    }
    let body = match serde_json::to_vec(&ArtifactGrantResponse {
        grant_id: hex_encode(grant.id().as_bytes()),
        kid: base64_encode(&offer.kid),
        recipient_public_key: base64_encode(&offer.recipient_public_key.0),
        expires_in_ms: state.config.artifact_grant_ttl_ms,
    }) {
        Ok(body) => body,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let cookie = secure_cookie(
        ARTIFACT_GRANT_COOKIE_NAME,
        token.as_str(),
        max_age_seconds(state.config.artifact_grant_ttl_ms),
    );
    let mut response =
        no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response());
    if set_cookie(&mut response, cookie).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    response
}

/// Loads the sealed workspace artifact, if configured and readable. Absence is a
/// fail-closed 503 at delivery time, never an error surfaced to logs with content.
fn load_workspace_artifact() -> Result<Vec<u8>, StatusCode> {
    let Ok(path) = std::env::var("WORKSPACE_ARTIFACT_PATH") else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if path.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    std::fs::read(&path).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn deliver_artifact(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    if content_type(&headers) != Some(CONTENT_TYPE) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let grant_token = match cookie_value(&headers, ARTIFACT_GRANT_COOKIE_NAME) {
        Ok(Some(value)) => TransportToken(value.to_string()),
        Ok(None) | Err(_) => return generic_error(StatusCode::UNAUTHORIZED),
    };
    let session_token = match cookie_value(&headers, SESSION_COOKIE_NAME) {
        Ok(Some(value)) => TransportToken(value.to_string()),
        Ok(None) | Err(_) => return clear_session(generic_error(StatusCode::UNAUTHORIZED)),
    };
    let body_bytes = match to_bytes(body, MAX_OFFER_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: ArtifactDeliveryRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    // Grant and session cookies must both be present and unambiguous; the grant
    // is consumed on first successful validation regardless of crypto outcome
    // beyond this point (matching challenge consumption semantics).
    let pending_grant = {
        let mut transport = match state.transport.lock() {
            Ok(transport) => transport,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        let Some(grant) = transport.grants.remove(&grant_token) else {
            return clear_grant(generic_error(StatusCode::UNAUTHORIZED));
        };
        if grant.expires_at_ms <= now {
            return clear_grant(generic_error(StatusCode::UNAUTHORIZED));
        }
        match transport.sessions.get(&session_token) {
            Some((bound_session, session_expires))
                if *bound_session == grant.session_id && *session_expires > now => {}
            _ => return clear_grant(clear_session(generic_error(StatusCode::UNAUTHORIZED))),
        }
        grant
    };
    if hex_encode(pending_grant.grant_id.as_bytes()) != request.grant_id {
        return clear_grant(clear_session(generic_error(StatusCode::UNAUTHORIZED)));
    }
    let artifact = match (state.artifact_loader)() {
        Ok(artifact) => artifact,
        Err(status) => return clear_grant(generic_error(status)),
    };
    if artifact.len() > MAX_ARTIFACT_BYTES.saturating_sub(ENVELOPE_OVERHEAD_BYTES) {
        return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE));
    }
    let encapsulated = match decode_encapsulated_key(&request) {
        Ok(encapsulated) => encapsulated,
        Err(_) => return clear_grant(generic_error(StatusCode::BAD_REQUEST)),
    };
    // Establish against the offer published at grant time; the request must
    // echo the same kid. Server private key material lives only in this grant
    // and is dropped after this single use.
    if base64_encode(&pending_grant.offer.kid) != request.kid {
        return clear_grant(generic_error(StatusCode::UNAUTHORIZED));
    }
    let mut session = match crypto_envelope::hpke::responder_establish(
        &pending_grant.offer,
        &pending_grant.keypair,
        &encapsulated,
    ) {
        Ok(session) => session,
        Err(_) => return clear_grant(generic_error(StatusCode::UNAUTHORIZED)),
    };
    let envelope = match session.seal(1, &artifact) {
        Ok(envelope) => envelope,
        Err(_) => return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let response_body = encode_envelope(&envelope);
    let mut response = no_store(
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(ARTIFACT_DELIVERY_CONTENT_TYPE),
            )],
            response_body,
        )
            .into_response(),
    );
    // Defense in depth: opaque artifact bytes must never be sniffed into a
    // renderable type by any intermediary or browser.
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    clear_grant(response)
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

fn random_kid() -> Result<[u8; 16], PrivateApiError> {
    let mut kid = [0u8; 16];
    if getrandom::getrandom(&mut kid).is_err() {
        kid.zeroize();
        return Err(PrivateApiError::EntropyUnavailable);
    }
    Ok(kid)
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

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn base64_decode_lenient(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(expected_len);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' || byte == b'\n' || byte == b'\r' {
            continue;
        }
        let v = value(byte)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if out.len() != expected_len {
        return None;
    }
    Some(out)
}

/// Resolves the transport-token cookie to a live SessionId. Returns None on any
/// ambiguity; the caller decides whether to also clear cookies.
fn session_id_from_headers(
    state: &PrivateApiState,
    headers: &HeaderMap,
    now: i64,
) -> Option<SessionId> {
    let token = cookie_value(headers, SESSION_COOKIE_NAME).ok()??;
    let mut transport = state.transport.lock().ok()?;
    transport.prune(now);
    let (session_id, expires_at_ms) = transport.sessions.get(token)?.clone();
    if expires_at_ms <= now {
        return None;
    }
    Some(session_id)
}

fn decode_encapsulated_key(
    request: &ArtifactDeliveryRequest,
) -> Result<crypto_envelope::hpke::HpkeEncapsulatedKey, ()> {
    let encapsulated_raw = base64_decode_lenient(&request.encapsulated_key, 32).ok_or(())?;
    // All-zero X25519 points are rejected during HPKE setup; still, refuse the
    // degenerate value here to fail closed before touching key material.
    if encapsulated_raw.iter().all(|&b| b == 0) {
        return Err(());
    }
    Ok(crypto_envelope::hpke::HpkeEncapsulatedKey(
        encapsulated_raw.try_into().map_err(|_| ())?,
    ))
}

fn encode_envelope(envelope: &crypto_envelope::Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 12 + 8 + envelope.ciphertext.len());
    out.extend_from_slice(&envelope.kid);
    out.extend_from_slice(&envelope.nonce);
    out.extend_from_slice(&envelope.sequence.to_be_bytes());
    out.extend_from_slice(&envelope.ciphertext);
    out
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

pub mod relay;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tower::ServiceExt;

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

    struct LegacyAcceptStore {
        passkey: Mutex<Passkey>,
    }

    impl PasskeyCredentialStore for LegacyAcceptStore {
        fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
            Ok(vec![self.passkey.lock().unwrap().clone()])
        }

        fn apply_authentication_result(
            &self,
            result: &AuthenticationResult,
        ) -> Result<(), AuthError> {
            self.passkey
                .lock()
                .unwrap()
                .update_credential(result)
                .ok_or(AuthError::VerificationFailed)?;
            Ok(())
        }
    }

    fn test_state(clock: Arc<FixedClock>) -> (PrivateApiState, TestRegistrationClient) {
        let (authenticator, client) = legacy_authenticator();
        let state =
            PrivateApiState::with_test_dependencies(config(), Some(authenticator), clock).unwrap();
        (state, client)
    }

    /// The client whose SoftPasskey token store matches the passkey registered in the
    /// test store. Authentication challenges must be answered by this client.
    type TestRegistrationClient = std::sync::Mutex<auth::passkey::__private_test_client_type>;

    fn legacy_authenticator() -> (Arc<WebAuthnPasskeyAuthenticator>, TestRegistrationClient) {
        let origin = auth::passkey::__private_test_origin();
        let server = auth::passkey::__private_test_server(&origin);
        let (creation, reg_state) = server
            .start_passkey_registration(
                auth::passkey::__private_test_uuid(),
                "owner",
                "Owner",
                None,
            )
            .unwrap();
        // The registration client is retained so its SoftPasskey token store holds the
        // registered credential; a fresh client would have no matching token for the
        // challenge allow-list and fail the ceremony with Internal.
        let registration_client = std::sync::Mutex::new(auth::passkey::__private_test_client(true));
        let registration = registration_client
            .lock()
            .unwrap()
            .do_registration(origin.clone(), creation)
            .unwrap();
        let passkey = server
            .finish_passkey_registration(&registration, &reg_state)
            .unwrap();
        let store: Arc<dyn PasskeyCredentialStore> = Arc::new(LegacyAcceptStore {
            passkey: Mutex::new(passkey),
        });
        let authenticator = Arc::new(
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap(),
        );
        (authenticator, registration_client)
    }

    async fn begin(app: Router) -> (String, auth::RequestChallengeResponse) {
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
        let options: auth::RequestChallengeResponse = serde_json::from_slice(&body).unwrap();
        (cookie, options)
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
    async fn production_verify_is_unavailable() {
        let state = PrivateApiState::production(config()).unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{CHALLENGE_COOKIE_NAME}=x"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn challenge_is_json_and_cookie_is_secure() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        let (cookie, body) = begin(router(state)).await;
        let _options = body;
        assert!(cookie.starts_with(CHALLENGE_COOKIE_NAME));
        let full = secure_cookie(CHALLENGE_COOKIE_NAME, "x", 10);
        for required in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(full.contains(required));
        }
    }

    #[tokio::test]
    async fn successful_verify_mints_http_only_session_and_session_validates() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let body = serde_json::to_vec(&credential).unwrap();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from(body))
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
        let (state, client) = test_state(clock);
        let (challenge_cookie, _options) = begin(router(state.clone())).await;
        // Sign a DIFFERENT server challenge; submitting it here must fail crypto
        // and consume the pending attempt for this cookie.
        let (_, other_options) = begin(router(state.clone())).await;
        let wrong_credential = {
            let mut client = client.lock().unwrap();
            client.do_authentication(auth::passkey::__private_test_origin_url(), other_options)
        }
        .unwrap();
        let body = serde_json::to_vec(&wrong_credential).unwrap();
        let make = || {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from(body.clone()))
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
        let (state, client) = test_state(clock.clone());
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let body = serde_json::to_vec(&credential).unwrap();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from(body))
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
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let body = serde_json::to_vec(&credential).unwrap();

        let duplicate_value =
            format!("{challenge_cookie}; {CHALLENGE_COOKIE_NAME}=different-token");
        let duplicate = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, duplicate_value)
            .body(Body::from(body.clone()))
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
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie.clone())
            .header(header::COOKIE, "other_cookie=value")
            .body(Body::from(body.clone()))
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
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie)
            .body(Body::from(body.clone()))
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
        let (state, _client) = test_state(clock);
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
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{CHALLENGE_COOKIE_NAME}=deadbeef"))
                    .body(Body::from(
                        r#"{"id":"x","rawId":"eA","type":"public-key","response":{"authenticatorData":"eA","clientDataJSON":"eA","signature":"eA"}}"#
                    ))
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
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let body = serde_json::to_vec(&credential).unwrap();
        let malformed = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie.clone())
            .body(Body::from(r#"{"id":not-json}"#))
            .unwrap();
        assert_eq!(
            router(state.clone())
                .oneshot(malformed)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        // The malformed attempt must not have consumed the pending challenge.
        let valid = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie.clone())
            .body(Body::from(body))
            .unwrap();
        let response = router(state).oneshot(valid).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn same_challenge_cookie_single_use_across_verify_attempts() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let body = serde_json::to_vec(&credential).unwrap();
        let make = || {
            Request::builder()
                .method("POST")
                .uri("/internal/auth/verify")
                .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(header::COOKIE, challenge_cookie.clone())
                .body(Body::from(body.clone()))
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
    async fn expired_pending_challenge_is_rejected_without_creating_session() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock.clone());
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        // Advance the clock past challenge_ttl_ms (60_000): the pending attempt is
        // now expired, and prune must drop it before any verification happens.
        clock.0.store(1_000 + 60_000, Ordering::SeqCst);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from(serde_json::to_vec(&credential).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let minted_session = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(SESSION_COOKIE_NAME).then_some(())
            })
            .is_some();
        assert!(!minted_session);
    }

    // ---- P0-4 artifact delivery tests ----

    /// Full ceremony helper: verify -> session cookie -> grant cookie + grant id.
    /// Builds the client-side initiator half against the server's published
    /// per-grant offer (base64 kid + recipient public key).
    fn establish_initiator(
        server_kid: &str,
        server_pk: &str,
    ) -> (
        crypto_envelope::hpke::HpkeEncapsulatedKey,
        crypto_envelope::hpke::HpkeInitiatorSession,
    ) {
        let kid_raw = base64::decode::<16>(server_kid);
        let pk_raw = base64::decode::<32>(server_pk);
        let offer = crypto_envelope::hpke::HpkeHandshakeOffer {
            version: crypto_envelope::hpke::HPKE_VERSION,
            suite_id: crypto_envelope::hpke::HPKE_SUITE_ID,
            kid: kid_raw,
            recipient_public_key: crypto_envelope::hpke::HpkePublicKey(pk_raw),
        };
        crypto_envelope::hpke::initiator_establish(&offer).unwrap()
    }

    mod base64 {
        pub(super) fn decode<const N: usize>(input: &str) -> [u8; N] {
            fn value(byte: u8) -> u32 {
                match byte {
                    b'A'..=b'Z' => (byte - b'A') as u32,
                    b'a'..=b'z' => (byte - b'a' + 26) as u32,
                    b'0'..=b'9' => (byte - b'0' + 52) as u32,
                    b'+' => 62,
                    b'/' => 63,
                    _ => unreachable!(),
                }
            }
            let mut out = [0u8; N];
            let mut acc: u32 = 0;
            let mut bits = 0u32;
            let mut idx = 0;
            for byte in input.bytes() {
                if byte == b'=' {
                    continue;
                }
                acc = (acc << 6) | value(byte);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out[idx] = ((acc >> bits) & 0xff) as u8;
                    idx += 1;
                }
            }
            assert_eq!(idx, N);
            out
        }
    }

    async fn establish_session_and_grant(
        state: &PrivateApiState,
        client: &TestRegistrationClient,
    ) -> (String, String, String, (String, String)) {
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/verify")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, challenge_cookie)
                    .body(Body::from(serde_json::to_vec(&credential).unwrap()))
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
        let grant_response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact/grant")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant_response.status(), StatusCode::OK);
        let grant_cookie = grant_response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(ARTIFACT_GRANT_COOKIE_NAME)
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap();
        let body = grant_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let grant_id = parsed["grant_id"].as_str().unwrap().to_string();
        let kid = parsed["kid"].as_str().unwrap().to_string();
        let recipient_public_key = parsed["recipient_public_key"].as_str().unwrap().to_string();
        (
            session_cookie,
            grant_cookie,
            grant_id,
            (kid, recipient_public_key),
        )
    }

    fn base64(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
            out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(triple >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[triple as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[tokio::test]
    async fn artifact_delivery_fails_closed_without_artifact_file() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let state = state.with_artifact_loader(Arc::new(|| Err(StatusCode::SERVICE_UNAVAILABLE)));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        // Artifact source unavailable: delivery must fail closed (503) and
        // consume the grant cookie.
        let (encapsulated, _initiator) = establish_initiator(&server_kid, &server_pk);
        let body = serde_json::json!({
            "grant_id": grant_id,
            "kid": server_kid,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{session_cookie}; {grant_cookie}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn artifact_delivery_end_to_end_roundtrip_and_single_use() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        let artifact_bytes = vec![0xABu8; 4096];
        let artifact_copy = artifact_bytes.clone();
        let state = state.with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())));

        let (encapsulated, mut initiator) = establish_initiator(&server_kid, &server_pk);
        let body = serde_json::json!({
            "grant_id": grant_id,
            "kid": server_kid,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{session_cookie}; {grant_cookie}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        // Grant cookie must be cleared on success (single-use delivery).
        let cleared_grant = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.starts_with(ARTIFACT_GRANT_COOKIE_NAME) && s.contains("Max-Age=0"))
                    .unwrap_or(false)
            });
        assert!(cleared_grant, "grant cookie must be cleared after delivery");

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.len() > 16 + 12 + 8);
        let (kid_bytes, nonce_bytes, seq_bytes, ciphertext) =
            { (&body[..16], &body[16..28], &body[28..36], &body[36..]) };
        let _ = (kid_bytes, nonce_bytes);
        let mut sequence = [0u8; 8];
        sequence.copy_from_slice(seq_bytes);
        assert_eq!(u64::from_be_bytes(sequence), 1);
        let kid_bytes: [u8; 16] = kid_bytes.try_into().unwrap();
        let envelope = crypto_envelope::Envelope {
            kid: kid_bytes,
            nonce: nonce_bytes.try_into().unwrap(),
            sequence: u64::from_be_bytes(sequence),
            ciphertext: ciphertext.to_vec(),
        };
        let plaintext = initiator.receive(&envelope).unwrap();
        assert_eq!(plaintext, artifact_bytes);
    }

    #[tokio::test]
    async fn artifact_grant_is_single_use_and_session_bound() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let state = state.with_artifact_loader(Arc::new(|| Ok(b"opaque-ciphertext".to_vec())));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;

        let (encapsulated, _initiator) = establish_initiator(&server_kid, &server_pk);
        let body = serde_json::json!({
            "grant_id": grant_id,
            "kid": server_kid,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let make = |cookie: String| {
            Request::builder()
                .method("POST")
                .uri("/internal/artifact")
                .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&body).unwrap().clone()))
                .unwrap()
        };
        let first = router(state.clone())
            .oneshot(make(format!("{session_cookie}; {grant_cookie}")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        // Replay with the same grant cookie: consumed -> unauthorized.
        let replay = router(state.clone())
            .oneshot(make(format!("{session_cookie}; {grant_cookie}")))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        // A grant minted under a different session must not validate against
        // this session's cookies: mint a fresh grant, then verify with only the
        // session cookie missing -> unauthorized.
        let (_s2, grant_cookie2, _grant2, _offer2) =
            establish_session_and_grant(&state, &client).await;
        let no_session = router(state.clone())
            .oneshot(make(grant_cookie2))
            .await
            .unwrap();
        assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn artifact_grant_rejects_cross_session_cookie_pairing() {
        // Session A + grant B (minted under session B): binding must fail even
        // though both cookies are individually live.
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let state = state.with_artifact_loader(Arc::new(|| Ok(b"opaque-ciphertext".to_vec())));
        let (session_a, _grant_a, _id_a, _offer_a) =
            establish_session_and_grant(&state, &client).await;
        let (_session_b, grant_b, id_b, (kid_b, pk_b)) =
            establish_session_and_grant(&state, &client).await;
        let (encapsulated, _initiator) = establish_initiator(&kid_b, &pk_b);
        let body = serde_json::json!({
            "grant_id": id_b,
            "kid": kid_b,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{session_a}; {grant_b}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_artifact_grant_is_rejected_and_cookie_cleared() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock.clone());
        let state = state.with_artifact_loader(Arc::new(|| Ok(b"opaque-ciphertext".to_vec())));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        // Advance the clock past artifact_grant_ttl_ms (30_000): prune drops the
        // pending grant before any crypto runs; response must be 401 with the
        // grant cookie cleared.
        clock.0.store(1_000 + 30_000, Ordering::SeqCst);
        let (encapsulated, _initiator) = establish_initiator(&server_kid, &server_pk);
        let body = serde_json::json!({
            "grant_id": grant_id,
            "kid": server_kid,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{session_cookie}; {grant_cookie}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let cleared = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.starts_with(ARTIFACT_GRANT_COOKIE_NAME) && s.contains("Max-Age=0"))
                    .unwrap_or(false)
            });
        assert!(cleared, "expired grant cookie must be cleared");
    }
}
