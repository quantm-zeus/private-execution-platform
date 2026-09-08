//! Semantically opaque, fail-closed edge relay.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Bytes},
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use thiserror::Error;

pub const DEFAULT_MAX_OPAQUE_BODY_BYTES: usize = 1024 * 1024;
const OPAQUE_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueRoute {
    Bootstrap,
    Sync,
    Blob,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EdgeError {
    #[error("authorization denied")]
    Unauthorized,
    #[error("backend unavailable")]
    BackendUnavailable,
    #[error("invalid opaque content type")]
    InvalidContentType,
    #[error("opaque payload too large")]
    PayloadTooLarge,
    #[error("invalid edge configuration")]
    InvalidConfiguration,
}

#[async_trait]
pub trait AuthorizationBackend: Send + Sync {
    async fn authorize(&self, credential: Option<&str>) -> Result<(), EdgeError>;
}

#[async_trait]
pub trait OpaqueRelay: Send + Sync {
    async fn relay(&self, route: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError>;
}

#[derive(Debug, Default)]
pub struct UnavailableAuthorization;

#[async_trait]
impl AuthorizationBackend for UnavailableAuthorization {
    async fn authorize(&self, _: Option<&str>) -> Result<(), EdgeError> {
        Err(EdgeError::BackendUnavailable)
    }
}

#[derive(Debug, Default)]
pub struct UnavailableRelay;

#[async_trait]
impl OpaqueRelay for UnavailableRelay {
    async fn relay(&self, _: OpaqueRoute, _: Bytes) -> Result<Bytes, EdgeError> {
        Err(EdgeError::BackendUnavailable)
    }
}

#[derive(Clone)]
pub struct EdgeState {
    authorization: Arc<dyn AuthorizationBackend>,
    relay: Arc<dyn OpaqueRelay>,
    max_body_bytes: usize,
}

impl EdgeState {
    pub fn new(
        authorization: Arc<dyn AuthorizationBackend>,
        relay: Arc<dyn OpaqueRelay>,
        max_body_bytes: usize,
    ) -> Result<Self, EdgeError> {
        if max_body_bytes == 0 {
            return Err(EdgeError::InvalidConfiguration);
        }
        Ok(Self {
            authorization,
            relay,
            max_body_bytes,
        })
    }

    pub fn unavailable() -> Self {
        Self {
            authorization: Arc::new(UnavailableAuthorization),
            relay: Arc::new(UnavailableRelay),
            max_body_bytes: DEFAULT_MAX_OPAQUE_BODY_BYTES,
        }
    }
}

pub fn router(state: EdgeState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/sync", post(sync))
        .route("/v1/blob", post(blob))
        .with_state(state)
}

pub fn default_router() -> Router {
    router(EdgeState::unavailable())
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn bootstrap(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    protected(state, OpaqueRoute::Bootstrap, headers, request).await
}

async fn sync(State(state): State<EdgeState>, headers: HeaderMap, request: Request) -> Response {
    protected(state, OpaqueRoute::Sync, headers, request).await
}

async fn blob(State(state): State<EdgeState>, headers: HeaderMap, request: Request) -> Response {
    protected(state, OpaqueRoute::Blob, headers, request).await
}

async fn protected(
    state: EdgeState,
    route: OpaqueRoute,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if let Err(error) = state.authorization.authorize(credential).await {
        return edge_response(error);
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some(OPAQUE_CONTENT_TYPE) {
        return edge_response(EdgeError::InvalidContentType);
    }

    let body = match to_bytes(request.into_body(), state.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => return edge_response(EdgeError::PayloadTooLarge),
    };

    match state.relay.relay(route, body).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, OPAQUE_CONTENT_TYPE)],
            bytes,
        )
            .into_response(),
        Err(error) => edge_response(error),
    }
}

fn edge_response(error: EdgeError) -> Response {
    let status = match error {
        EdgeError::Unauthorized => StatusCode::UNAUTHORIZED,
        EdgeError::BackendUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        EdgeError::InvalidContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        EdgeError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        EdgeError::InvalidConfiguration => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, "request unavailable").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct TestAuthorization {
        allow: bool,
    }
    #[async_trait]
    impl AuthorizationBackend for TestAuthorization {
        async fn authorize(&self, credential: Option<&str>) -> Result<(), EdgeError> {
            if self.allow && credential == Some("Bearer test") {
                Ok(())
            } else {
                Err(EdgeError::Unauthorized)
            }
        }
    }

    struct EchoRelay {
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl OpaqueRelay for EchoRelay {
        async fn relay(&self, _: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(payload)
        }
    }

    fn request(path: &str, body: &'static [u8], authorized: bool) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, OPAQUE_CONTENT_TYPE);
        if authorized {
            builder = builder.header(header::AUTHORIZATION, "Bearer test");
        }
        builder.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn health_is_available_with_unavailable_backends() {
        let response = default_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn production_default_fails_closed() {
        let response = default_router()
            .oneshot(request("/v1/bootstrap", b"ciphertext", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn authorized_roundtrip_preserves_exact_bytes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization { allow: true }),
            Arc::new(EchoRelay {
                calls: calls.clone(),
            }),
            1024,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/sync", b"\x00\x01opaque\xff", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"\x00\x01opaque\xff");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unauthorized_request_never_reaches_relay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization { allow: false }),
            Arc::new(EchoRelay {
                calls: calls.clone(),
            }),
            1024,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/blob", b"opaque", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn zero_max_body_is_invalid_configuration() {
        let state = EdgeState::new(
            Arc::new(TestAuthorization { allow: true }),
            Arc::new(EchoRelay {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            0,
        );
        assert!(matches!(state, Err(EdgeError::InvalidConfiguration)));
    }

    #[tokio::test]
    async fn authorization_precedes_body_read_and_size_validation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization { allow: false }),
            Arc::new(EchoRelay {
                calls: calls.clone(),
            }),
            4,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/blob", b"12345", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oversize_payload_is_rejected() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization { allow: true }),
            Arc::new(EchoRelay {
                calls: calls.clone(),
            }),
            4,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/blob", b"12345", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn semantic_routes_do_not_exist() {
        for path in ["/swap", "/wallet", "/order", "/route", "/tax"] {
            let response = default_router()
                .oneshot(request(path, b"x", true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
