//! Semantically opaque, fail-closed edge relay.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Bytes},
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use thiserror::Error;
use tokio::sync::mpsc;

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
    async fn authorize(&self, headers: &HeaderMap) -> Result<(), EdgeError>;
}

#[async_trait]
pub trait OpaqueRelay: Send + Sync {
    async fn relay(&self, route: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError>;
}

/// Bidirectional opaque stream bridge. Both channels carry ciphertext bytes only.
pub struct OpaqueStreamBridge {
    to_backend: mpsc::Sender<Bytes>,
    from_backend: mpsc::Receiver<Bytes>,
}

impl OpaqueStreamBridge {
    pub fn new(to_backend: mpsc::Sender<Bytes>, from_backend: mpsc::Receiver<Bytes>) -> Self {
        Self {
            to_backend,
            from_backend,
        }
    }
}

#[async_trait]
pub trait OpaqueStreamRelay: Send + Sync {
    async fn open(&self) -> Result<OpaqueStreamBridge, EdgeError>;
}

#[derive(Debug, Default)]
pub struct UnavailableAuthorization;

#[async_trait]
impl AuthorizationBackend for UnavailableAuthorization {
    async fn authorize(&self, _: &HeaderMap) -> Result<(), EdgeError> {
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

#[derive(Debug, Default)]
pub struct UnavailableStreamRelay;

#[async_trait]
impl OpaqueStreamRelay for UnavailableStreamRelay {
    async fn open(&self) -> Result<OpaqueStreamBridge, EdgeError> {
        Err(EdgeError::BackendUnavailable)
    }
}

#[derive(Clone)]
pub struct EdgeState {
    authorization: Arc<dyn AuthorizationBackend>,
    relay: Arc<dyn OpaqueRelay>,
    stream_relay: Arc<dyn OpaqueStreamRelay>,
    max_body_bytes: usize,
}

impl EdgeState {
    pub fn new(
        authorization: Arc<dyn AuthorizationBackend>,
        relay: Arc<dyn OpaqueRelay>,
        max_body_bytes: usize,
    ) -> Result<Self, EdgeError> {
        Self::with_stream_relay(
            authorization,
            relay,
            Arc::new(UnavailableStreamRelay),
            max_body_bytes,
        )
    }

    pub fn with_stream_relay(
        authorization: Arc<dyn AuthorizationBackend>,
        relay: Arc<dyn OpaqueRelay>,
        stream_relay: Arc<dyn OpaqueStreamRelay>,
        max_body_bytes: usize,
    ) -> Result<Self, EdgeError> {
        if max_body_bytes == 0 {
            return Err(EdgeError::InvalidConfiguration);
        }
        Ok(Self {
            authorization,
            relay,
            stream_relay,
            max_body_bytes,
        })
    }

    pub fn unavailable() -> Self {
        Self {
            authorization: Arc::new(UnavailableAuthorization),
            relay: Arc::new(UnavailableRelay),
            stream_relay: Arc::new(UnavailableStreamRelay),
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
        .route("/v1/stream", get(stream))
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

async fn stream(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(error) = state.authorization.authorize(&headers).await {
        return edge_response(error);
    }
    let bridge = match state.stream_relay.open().await {
        Ok(bridge) => bridge,
        Err(error) => return edge_response(error),
    };
    let max_frame_bytes = state.max_body_bytes;
    ws.max_message_size(max_frame_bytes)
        .max_frame_size(max_frame_bytes)
        .on_upgrade(move |socket| drive_stream(socket, bridge, max_frame_bytes))
        .into_response()
}

async fn drive_stream(
    mut socket: WebSocket,
    mut bridge: OpaqueStreamBridge,
    max_frame_bytes: usize,
) {
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) if bytes.len() <= max_frame_bytes => {
                        if bridge.to_backend.try_send(bytes).is_err() {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Text(_))) => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
            outbound = bridge.from_backend.recv() => {
                match outbound {
                    Some(bytes) if bytes.len() <= max_frame_bytes => {
                        if socket.send(Message::Binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Some(_) | None => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }
    }
}

async fn protected(
    state: EdgeState,
    route: OpaqueRoute,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if let Err(error) = state.authorization.authorize(&headers).await {
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
        Ok(bytes) if bytes.len() <= state.max_body_bytes => {
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, OPAQUE_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
            apply_opaque_response_headers(&mut response);
            response
        }
        Ok(_) => edge_response(EdgeError::PayloadTooLarge),
        Err(error) => edge_response(error),
    }
}

/// Hardening headers for opaque payloads. The edge cannot know payload semantics,
/// so it refuses to let any renderer interpret them: no caching, no rendering in
/// any embedding context, no content-type sniffing, no referrer leakage.
fn apply_opaque_response_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
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
    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        net::TcpListener,
        task::JoinHandle,
        time::{timeout, Duration},
    };
    use tokio_tungstenite::{
        tungstenite::{client::IntoClientRequest, Message as WsMessage},
        MaybeTlsStream, WebSocketStream,
    };
    use tower::ServiceExt;

    #[derive(Clone, Copy)]
    enum TestAuthMode {
        Bearer,
        Cookie,
        Deny,
    }

    struct TestAuthorization {
        mode: TestAuthMode,
    }
    #[async_trait]
    impl AuthorizationBackend for TestAuthorization {
        async fn authorize(&self, headers: &HeaderMap) -> Result<(), EdgeError> {
            let authorized = match self.mode {
                TestAuthMode::Bearer => {
                    headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer test")
                }
                TestAuthMode::Cookie => headers
                    .get(header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|cookie| {
                        cookie
                            .split(';')
                            .any(|part| part.trim() == "__Host-evergreen_session=test-session")
                    }),
                TestAuthMode::Deny => false,
            };
            if authorized {
                Ok(())
            } else {
                Err(EdgeError::Unauthorized)
            }
        }
    }

    struct OversizeRelay {
        limit: usize,
    }
    #[async_trait]
    impl OpaqueRelay for OversizeRelay {
        async fn relay(&self, _: OpaqueRoute, _: Bytes) -> Result<Bytes, EdgeError> {
            Ok(Bytes::from(vec![0_u8; self.limit + 1]))
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

    const TEST_TIMEOUT: Duration = Duration::from_secs(3);

    async fn spawn_router(router: Router) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("ws://{addr}/v1/stream"), task)
    }

    async fn connect(
        url: &str,
        headers: &[(&str, &str)],
    ) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
        let mut request = url.into_client_request().unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        let (stream, response) = timeout(TEST_TIMEOUT, tokio_tungstenite::connect_async(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SWITCHING_PROTOCOLS
        );
        stream
    }

    async fn handshake_fails(
        url: &str,
        headers: &[(&str, &str)],
        expected: axum::http::StatusCode,
    ) {
        let mut request = url.into_client_request().unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        let error = timeout(TEST_TIMEOUT, tokio_tungstenite::connect_async(request))
            .await
            .unwrap()
            .unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), expected)
            }
            other => panic!("expected HTTP {expected}, got {other}"),
        }
    }

    async fn expect_close(stream: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>) {
        loop {
            let message = timeout(TEST_TIMEOUT, stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match message {
                WsMessage::Close(_) => return,
                WsMessage::Ping(_) | WsMessage::Pong(_) => {}
                other => panic!("expected close, got {other:?}"),
            }
        }
    }
    struct CountingStreamRelay {
        opens: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OpaqueStreamRelay for CountingStreamRelay {
        async fn open(&self) -> Result<OpaqueStreamBridge, EdgeError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let (to_backend, _from_browser) = mpsc::channel(1);
            let (_to_browser, from_backend) = mpsc::channel(1);
            Ok(OpaqueStreamBridge::new(to_backend, from_backend))
        }
    }

    struct EchoStreamRelay {
        opens: Arc<AtomicUsize>,
        forwarded: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OpaqueStreamRelay for EchoStreamRelay {
        async fn open(&self) -> Result<OpaqueStreamBridge, EdgeError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let (to_backend, mut from_browser) = mpsc::channel(8);
            let (to_browser, from_backend) = mpsc::channel(8);
            let forwarded = self.forwarded.clone();
            tokio::spawn(async move {
                if to_browser
                    .send(Bytes::from_static(b"server-push"))
                    .await
                    .is_err()
                {
                    return;
                }
                while let Some(bytes) = from_browser.recv().await {
                    forwarded.fetch_add(1, Ordering::SeqCst);
                    if to_browser.send(bytes).await.is_err() {
                        break;
                    }
                }
            });
            Ok(OpaqueStreamBridge::new(to_backend, from_backend))
        }
    }

    fn request(path: &str, body: &'static [u8], authorized: bool) -> Request<Body> {
        request_with_auth(path, body, authorized.then_some(TestAuthMode::Bearer))
    }

    fn request_with_auth(
        path: &str,
        body: &'static [u8],
        mode: Option<TestAuthMode>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, OPAQUE_CONTENT_TYPE);
        match mode {
            Some(TestAuthMode::Bearer) => {
                builder = builder.header(header::AUTHORIZATION, "Bearer test");
            }
            Some(TestAuthMode::Cookie) => {
                builder = builder.header(header::COOKIE, "__Host-evergreen_session=test-session");
            }
            Some(TestAuthMode::Deny) | None => {}
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
    async fn authorized_stream_with_unavailable_backend_fails_before_upgrade() {
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
            Arc::new(EchoRelay {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            1024,
        )
        .unwrap();
        let (url, server) = spawn_router(router(state)).await;
        handshake_fails(
            &url,
            &[("authorization", "Bearer test")],
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    async fn unauthorized_stream_never_opens_backend() {
        let opens = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::with_stream_relay(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Deny,
            }),
            Arc::new(EchoRelay {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(CountingStreamRelay {
                opens: opens.clone(),
            }),
            1024,
        )
        .unwrap();
        let (url, server) = spawn_router(router(state)).await;
        handshake_fails(
            &url,
            &[("authorization", "Bearer test")],
            StatusCode::UNAUTHORIZED,
        )
        .await;
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn cookie_stream_is_binary_bidirectional_and_text_fails_closed() {
        let opens = Arc::new(AtomicUsize::new(0));
        let forwarded = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::with_stream_relay(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Cookie,
            }),
            Arc::new(EchoRelay {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(EchoStreamRelay {
                opens: opens.clone(),
                forwarded: forwarded.clone(),
            }),
            1024,
        )
        .unwrap();
        let (url, server) = spawn_router(router(state)).await;
        let mut stream =
            connect(&url, &[("cookie", "__Host-evergreen_session=test-session")]).await;

        let pushed = timeout(TEST_TIMEOUT, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            pushed,
            WsMessage::Binary(Bytes::from_static(b"server-push"))
        );

        let payload = Bytes::from_static(b"opaque-client-frame");
        stream
            .send(WsMessage::Binary(payload.clone()))
            .await
            .unwrap();
        let echoed = timeout(TEST_TIMEOUT, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(echoed, WsMessage::Binary(payload));
        assert_eq!(forwarded.load(Ordering::SeqCst), 1);

        stream
            .send(WsMessage::Text("not-binary".into()))
            .await
            .unwrap();
        expect_close(&mut stream).await;
        assert_eq!(forwarded.load(Ordering::SeqCst), 1);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn authorized_roundtrip_preserves_exact_bytes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
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
    async fn cookie_authorized_sync_roundtrip_preserves_exact_bytes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Cookie,
            }),
            Arc::new(EchoRelay {
                calls: calls.clone(),
            }),
            1024,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request_with_auth(
                "/v1/sync",
                b"\x00\x02opaque\xff",
                Some(TestAuthMode::Cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"\x00\x02opaque\xff");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unauthorized_request_never_reaches_relay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Deny,
            }),
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
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
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
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Deny,
            }),
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
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
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
    async fn oversize_relay_response_is_rejected_without_returning_bytes() {
        let max_body_bytes = 8;
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
            Arc::new(OversizeRelay {
                limit: max_body_bytes,
            }),
            max_body_bytes,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/sync", b"opaque", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"request unavailable");
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

    #[tokio::test]
    async fn opaque_relay_response_carries_hardening_headers() {
        let state = EdgeState::new(
            Arc::new(TestAuthorization {
                mode: TestAuthMode::Bearer,
            }),
            Arc::new(EchoRelay {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            1024,
        )
        .unwrap();
        let response = router(state)
            .oneshot(request("/v1/blob", b"ciphertext", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "opaque artifacts must never be cached"
        );
        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "opaque payload must not be renderable or embeddable"
        );
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            OPAQUE_CONTENT_TYPE
        );
    }
}
