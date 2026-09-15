//! In-process end-to-end integration: a browser-shaped opaque envelope travels
//! through the edge `/v1/command` (and `/v1/bootstrap`) route into the
//! private-api encrypted session service and reaches the fail-closed command
//! dispatcher seam.
//!
//! This is the transport contract the real browser speaks (BR-7): the edge
//! relays ciphertext only, the private API owns the sole plaintext, and every
//! response is AEAD-sealed at the request sequence with the request `request_id`
//! echoed inside the ciphertext (BR-3). No trading backend is installed, so
//! every mutation must fail closed with an authenticated typed denial — never a
//! false success.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Request, StatusCode};
use edge_gateway::{AuthorizationBackend, EdgeError, EdgeState, OpaqueRelay, OpaqueRoute};
use http_body_util::BodyExt;
use private_api::opaque::{
    BootstrapDocument, BootstrapProvider, FailClosedBootstrap, FailClosedDispatcher, OpaqueClock,
    OpaqueRoute as PrivateRoute, OpaqueServiceState, StaticBootstrap,
};
use private_api::{
    AgentCapabilities, CommandDispatcher, FailClosedWebContract, WebContractDispatcher,
};
use session_transport::{
    parse_wire_envelope, ClientSession, CommandDenial, CommandRequest, ServerSession,
    SessionRegistry, WireEnvelope,
};
use tower::ServiceExt;

const KID: [u8; 16] = [0xAB; 16];
const OCTET_STREAM: &str = "application/octet-stream";

struct AllowAllAuthorization;

#[async_trait]
impl AuthorizationBackend for AllowAllAuthorization {
    async fn authorize(&self, _headers: &HeaderMap) -> Result<(), EdgeError> {
        Ok(())
    }
}

/// Forwards the edge's opaque payload directly to the private-api session
/// service (the in-process equivalent of the mTLS gRPC relay).
#[derive(Clone)]
struct ForwardingRelay {
    state: OpaqueServiceState,
}

#[async_trait]
impl OpaqueRelay for ForwardingRelay {
    async fn relay(&self, route: OpaqueRoute, payload: Bytes) -> Result<Bytes, EdgeError> {
        let route = match route {
            OpaqueRoute::Bootstrap => PrivateRoute::Bootstrap,
            OpaqueRoute::Sync => PrivateRoute::Sync,
            OpaqueRoute::Command => PrivateRoute::Command,
            OpaqueRoute::Blob => PrivateRoute::Blob,
        };
        self.state
            .relay_envelope(route, &payload)
            .await
            .map(Bytes::from)
            .map_err(|_| EdgeError::BackendUnavailable)
    }
}

struct FixedClock(i64);

impl OpaqueClock for FixedClock {
    fn now_ms(&self) -> Option<i64> {
        Some(self.0)
    }
}

struct Harness {
    state: EdgeState,
    client: ClientSession,
}

fn harness(now_ms: i64) -> Harness {
    harness_full(
        Arc::new(FailClosedDispatcher),
        Arc::new(FailClosedBootstrap),
        now_ms,
    )
}

/// A bootstrap document that permits writes, used to exercise the dispatcher and
/// response-normalization seams (the advertised kill switch is authoritative for
/// mutating commands, so a fail-closed document would short-circuit them).
fn permissive_bootstrap() -> Arc<dyn BootstrapProvider> {
    let mut document = BootstrapDocument::fail_closed();
    document.trading_enabled = true;
    document.kill_switch_enabled = false;
    document.kill_switch_reason = None;
    Arc::new(StaticBootstrap::new(document))
}

/// A web contract over a scripted canonical dispatcher with trading enabled.
fn trading_web_contract(canonical: Arc<dyn CommandDispatcher>) -> Arc<dyn CommandDispatcher> {
    Arc::new(WebContractDispatcher::with_capabilities(
        canonical,
        Arc::new(FailClosedWebContract),
        AgentCapabilities::new(true, std::collections::HashSet::new(), u64::MAX),
    ))
}

fn harness_full(
    dispatcher: Arc<dyn CommandDispatcher>,
    bootstrap: Arc<dyn BootstrapProvider>,
    now_ms: i64,
) -> Harness {
    let keys = crypto_envelope::hpke::AppDirectionKeys::from_bytes([0x11u8; 32], [0x22u8; 32]);
    let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
    sessions
        .lock()
        .expect("registry lock")
        .insert(ServerSession::new(KID, &keys, i64::MAX).expect("session"))
        .expect("insert session");
    let opaque = OpaqueServiceState::new(
        sessions,
        dispatcher,
        bootstrap,
        Arc::new(FixedClock(now_ms)),
        60_000,
    )
    .expect("opaque state");
    let state = EdgeState::new(
        Arc::new(AllowAllAuthorization),
        Arc::new(ForwardingRelay { state: opaque }),
        1024 * 1024,
    )
    .expect("edge state");
    let client = ClientSession::new(KID, &keys).expect("client");
    Harness { state, client }
}

/// Scripted canonical dispatcher (stands in for the Trading Core port).
struct ScriptedDispatcher {
    value: serde_json::Value,
}

#[async_trait]
impl CommandDispatcher for ScriptedDispatcher {
    async fn dispatch(
        &self,
        _request: &CommandRequest,
    ) -> Result<serde_json::Value, CommandDenial> {
        Ok(self.value.clone())
    }
}

fn post(path: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, OCTET_STREAM)
        .body(Body::from(body))
        .expect("request")
}

async fn roundtrip(
    harness: &mut Harness,
    path: &str,
    plaintext: &[u8],
) -> (StatusCode, Option<String>, WireEnvelope, Vec<u8>) {
    let envelope = harness
        .client
        .seal_next(plaintext)
        .expect("seal request envelope");
    let response = edge_gateway::router(harness.state.clone())
        .oneshot(post(path, envelope.to_wire_bytes()))
        .await
        .expect("edge response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let sealed = parse_wire_envelope(&body).expect("sealed envelope");
    assert_eq!(
        sealed.sequence, envelope.sequence,
        "response must bind the request sequence"
    );
    let plaintext = harness.client.open(&sealed).expect("open response");
    (status, content_type, sealed, plaintext)
}

#[tokio::test]
async fn opaque_command_traverses_edge_to_private_api_and_fails_closed() {
    let mut harness = harness(1_000);
    let (status, content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/command",
        br#"{"op":"get_quote","payload":{},"request_id":"edge-e2e","idempotency_key":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(OCTET_STREAM));
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["request_id"], "edge-e2e");
    assert_eq!(value["error"]["code"], "capability_missing");
    assert!(value.get("result").is_none(), "no false success");
}

#[tokio::test]
async fn opaque_command_replay_through_the_edge_is_refused() {
    let harness = harness(1_000);
    let plaintext = br#"{"op":"get_quote","payload":{},"request_id":"replay"}"#;
    let envelope = harness.client.seal_at(0, plaintext).expect("seal");
    let body = envelope.to_wire_bytes();

    let first = edge_gateway::router(harness.state.clone())
        .oneshot(post("/v1/command", body.clone()))
        .await
        .expect("first");
    assert_eq!(first.status(), StatusCode::OK);

    // The identical authenticated envelope is a replay: the private API refuses
    // it before dispatch and the edge surfaces the opaque backend failure (no
    // ciphertext, generic body), never a success.
    let second = edge_gateway::router(harness.state.clone())
        .oneshot(post("/v1/command", body))
        .await
        .expect("second");
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    let second_body = second.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(&second_body[..], b"request unavailable");
}

#[tokio::test]
async fn opaque_bootstrap_through_the_edge_is_fail_closed_and_session_bound() {
    let mut harness = harness(4_242);
    let (status, content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/bootstrap",
        br#"{"op":"bootstrap","protocol_version":1,"request_id":"boot"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(OCTET_STREAM));
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["protocol_version"], 1);
    assert_eq!(value["trading_enabled"], false);
    assert_eq!(value["kill_switch"]["enabled"], true);
    assert_eq!(value["capabilities"]["execute"], false);
    assert_eq!(value["request_id"], "boot");
    assert_eq!(value["server_time_ms"], 4_242);
    assert_eq!(
        value["session"]["key_id"],
        session_transport::wire_kid(&KID)
    );
}

#[tokio::test]
async fn json_body_on_the_edge_command_route_is_refused_before_the_relay() {
    let harness = harness(1_000);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/command")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .expect("request");
    let response = edge_gateway::router(harness.state.clone())
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // The client session is untouched: no sequence was consumed.
    assert_eq!(harness.client.next_sequence(), 0);
}

/// BR-10 end-to-end: a Trading Core seam that reports `submitted` without the
/// `execution_id`/`router_source` echo must NOT become a success at the browser.
#[tokio::test]
async fn execute_without_a_backend_identity_echo_is_indeterminate_through_the_edge() {
    let canonical = Arc::new(ScriptedDispatcher {
        value: serde_json::json!({ "execution": { "state": "submitted" } }),
    });
    let mut harness = harness_full(
        trading_web_contract(canonical),
        permissive_bootstrap(),
        1_000,
    );
    let (status, _content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/command",
        br#"{"op":"execute_market_order","payload":{"quote_id":"q1","router_preference":"okx"},"request_id":"exec-e2e","idempotency_key":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["request_id"], "exec-e2e");
    assert_eq!(value["error"]["code"], "unknown");
    assert_eq!(value["error"]["retryable"], true);
    assert!(value.get("result").is_none(), "no false success");
}

/// BR-12 end-to-end: a 2xx limit-order result without an `order_id` is
/// indeterminate, so the UI keeps its UNKNOWN guard and idempotency key.
#[tokio::test]
async fn place_limit_without_an_order_id_is_indeterminate_through_the_edge() {
    let canonical = Arc::new(ScriptedDispatcher {
        value: serde_json::json!({ "order": { "status": "ACTIVE" } }),
    });
    let mut harness = harness_full(
        trading_web_contract(canonical),
        permissive_bootstrap(),
        1_000,
    );
    let (status, _content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/command",
        br#"{"op":"place_limit_order","payload":{"chain":"base"},"request_id":"limit-e2e","idempotency_key":"k2"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["error"]["code"], "unknown");
    assert!(value.get("result").is_none(), "no false success");
}

/// A fully attributed execute result (backend-echoed source + execution id)
/// passes the web contract unchanged.
#[tokio::test]
async fn attributable_execute_succeeds_through_the_edge() {
    let canonical = Arc::new(ScriptedDispatcher {
        value: serde_json::json!({
            "execution": { "state": "submitted" },
            "execution_id": "intent-42",
            "router_source": "okx",
        }),
    });
    let mut harness = harness_full(
        trading_web_contract(canonical),
        permissive_bootstrap(),
        1_000,
    );
    let (_status, _content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/command",
        br#"{"op":"execute_market_order","payload":{"quote_id":"q1","router_preference":"okx"},"request_id":"exec-ok","idempotency_key":"k3"}"#,
    )
    .await;
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["result"]["execution_id"], "intent-42");
    assert_eq!(value["result"]["router_source"], "okx");
}

/// BR-1/F4: the advertised bootstrap kill switch is authoritative for writes. A
/// mutating command is denied even when the composed canonical dispatcher would
/// accept it, so a mis-composition cannot execute while the browser is told
/// trading is halted. Reads remain available (verified by the bootstrap test).
#[tokio::test]
async fn mutating_command_is_denied_while_the_advertised_kill_switch_is_engaged() {
    let canonical = Arc::new(ScriptedDispatcher {
        value: serde_json::json!({
            "execution": { "state": "submitted" },
            "execution_id": "intent-42",
            "router_source": "okx",
        }),
    });
    // Trading-enabled web contract over the scripted canonical, but a fail-closed
    // bootstrap document: the service-level gate must still deny the write.
    let mut harness = harness_full(
        trading_web_contract(canonical),
        Arc::new(FailClosedBootstrap),
        1_000,
    );
    let (status, _content_type, _sealed, plaintext) = roundtrip(
        &mut harness,
        "/v1/command",
        br#"{"op":"execute_market_order","payload":{"quote_id":"q1","router_preference":"okx"},"request_id":"exec-kill","idempotency_key":"k9"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    assert_eq!(value["request_id"], "exec-kill");
    assert_eq!(value["error"]["code"], "capability_missing");
    assert!(value.get("result").is_none(), "no false success");
}

/// BR-3/F5: bootstrap and sync require the authenticated `request_id` challenge;
/// a missing one is a protocol refusal, never a replayable success.
#[tokio::test]
async fn bootstrap_without_a_request_id_is_refused() {
    let mut harness = harness(1_000);
    let envelope = harness
        .client
        .seal_next(br#"{"op":"bootstrap","protocol_version":1}"#)
        .expect("seal");
    let response = edge_gateway::router(harness.state.clone())
        .oneshot(post("/v1/bootstrap", envelope.to_wire_bytes()))
        .await
        .expect("edge response");
    // The private API refuses the malformed request; the edge surfaces the opaque
    // backend failure rather than sealing a challenge-less success.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
