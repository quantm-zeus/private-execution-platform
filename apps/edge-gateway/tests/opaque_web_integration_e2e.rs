//! True end-to-end: browser-shaped opaque envelope -> edge `/v1/command` ->
//! private-api encrypted session -> BR-11 intent translation -> canonical
//! `agent-commands` authorization -> injected Trading Core backend seam.
//!
//! These tests exercise the *real* composition (`web_command_dispatcher`) rather
//! than a scripted dispatcher, so they prove the browser's human-shaped payload
//! is translated into the exact canonical `AssetRef`/`AmountSpec`/`RouterSource`
//! the Trading Core receives, and that no mutation becomes a success while
//! `TRADING_ENABLED=false`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Request, StatusCode};
use chain_types::ChainId;
use edge_gateway::{AuthorizationBackend, EdgeError, EdgeState, OpaqueRelay, OpaqueRoute};
use http_body_util::BodyExt;
use private_api::opaque::{
    BootstrapDocument, BootstrapProvider, OpaqueClock, OpaqueRoute as PrivateRoute,
    OpaqueServiceState, StaticBootstrap,
};
use private_api::{
    web_command_dispatcher, AgentBackend, AgentCapabilities, AgentChannel, AgentCommand,
    AmountSpec, BackendOutcome, FailClosedWebContract, RouterSource, StaticInstrumentRegistry,
    TradeCommand,
};
use serde_json::json;
use session_transport::{ClientSession, ServerSession, SessionRegistry, WireEnvelope};
use tower::ServiceExt;

const KID: [u8; 16] = [0xCD; 16];
const OCTET_STREAM: &str = "application/octet-stream";

struct AllowAllAuthorization;

#[async_trait]
impl AuthorizationBackend for AllowAllAuthorization {
    async fn authorize(&self, _headers: &HeaderMap) -> Result<(), EdgeError> {
        Ok(())
    }
}

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

/// Injected Trading Core seam. Records every command it is asked to run.
struct FakeTradingCore {
    commands: Mutex<Vec<AgentCommand>>,
    preview: serde_json::Value,
    execute: BackendOutcome,
}

impl FakeTradingCore {
    fn new(preview: serde_json::Value, execute: BackendOutcome) -> Arc<Self> {
        Arc::new(Self {
            commands: Mutex::new(Vec::new()),
            preview,
            execute,
        })
    }

    fn commands(&self) -> Vec<AgentCommand> {
        self.commands.lock().expect("lock").clone()
    }
}

#[async_trait]
impl AgentBackend for FakeTradingCore {
    async fn execute(&self, _channel: AgentChannel, command: AgentCommand) -> BackendOutcome {
        let is_preview = matches!(
            command,
            AgentCommand::Trade(TradeCommand::PreviewMarketOrder { .. })
        );
        self.commands.lock().expect("lock").push(command);
        if is_preview {
            BackendOutcome::Value(self.preview.clone())
        } else {
            self.execute.clone()
        }
    }

    async fn valuation_usd_micros(&self, _command: &AgentCommand) -> Option<u64> {
        Some(0)
    }
}

fn preview_document() -> serde_json::Value {
    json!({
        "preview": {
            "quote": {
                "net_delta": {
                    "gross_output": { "asset": { "chain": { "kind": "base" }, "address": "TOKEN" }, "amount": 2_000_000_000_000_000_000u64 },
                    "net_output": { "asset": { "chain": { "kind": "base" }, "address": "TOKEN" }, "amount": 1_900_000_000_000_000_000u64 },
                    "dex_fee": { "asset": { "chain": { "kind": "base" }, "address": "USDC" }, "amount": 7_500u64 },
                    "tax_cost": null
                },
                "hop_quotes": [{
                    "venue": "uniswap",
                    "token_in": { "chain": { "kind": "base" }, "address": "USDC" },
                    "token_out": { "chain": { "kind": "base" }, "address": "TOKEN" },
                    "kind": "cpmm"
                }]
            },
            "score": {
                "price_impact": 30,
                "expected_slippage": 50,
                "mev_risk": 10,
                "failure_probability": 100,
                "state_age_ms": 120
            },
            "truncated": false,
            "router_source": "okx"
        }
    })
}

fn registry(include_token: bool) -> Arc<StaticInstrumentRegistry> {
    let mut entries = vec![("base".to_string(), "USDC".to_string(), ChainId::Base, 6)];
    if include_token {
        entries.push(("base".to_string(), "TOKEN".to_string(), ChainId::Base, 18));
    }
    Arc::new(StaticInstrumentRegistry::from_slug_entries(entries).expect("registry"))
}

struct Harness {
    state: EdgeState,
    client: ClientSession,
}

fn harness(
    backend: Arc<FakeTradingCore>,
    trading_enabled: bool,
    include_token: bool,
    now_ms: i64,
) -> (Harness, Arc<FakeTradingCore>) {
    let capabilities =
        AgentCapabilities::new(trading_enabled, HashSet::from([ChainId::Base]), u64::MAX);
    let dispatcher = web_command_dispatcher(
        backend.clone(),
        capabilities,
        Arc::new(FailClosedWebContract),
        registry(include_token),
        Arc::new(FixedClock(now_ms)),
    );

    let keys = crypto_envelope::hpke::AppDirectionKeys::from_bytes([0x33u8; 32], [0x44u8; 32]);
    let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
    sessions
        .lock()
        .expect("registry lock")
        .insert(ServerSession::new(KID, &keys, i64::MAX).expect("session"))
        .expect("insert session");
    // The advertised bootstrap document is authoritative for mutating commands,
    // so a trading-enabled composition must advertise a disengaged kill switch.
    let bootstrap: Arc<dyn BootstrapProvider> = if trading_enabled {
        let mut document = BootstrapDocument::fail_closed();
        document.trading_enabled = true;
        document.kill_switch_enabled = false;
        document.kill_switch_reason = None;
        // BR-1/F2: the advertised capability set is enforced server-side, so a
        // trading-enabled composition must advertise each capability it expects
        // to serve rather than relying on `trading_enabled` alone.
        document.capabilities.execute = true;
        document.capabilities.limits = true;
        document.capabilities.preview = true;
        document.capabilities.quotes = true;
        document.capabilities.portfolio = true;
        document.capabilities.wallet_limits = true;
        Arc::new(StaticBootstrap::new(document))
    } else {
        // Trading is disabled: mutations stay denied, but the PRD requires
        // read-only data to remain available, so the read capabilities the
        // preview path needs are still advertised (BR-1/F2 enforces them
        // server-side, so they must be truthful).
        let mut document = BootstrapDocument::fail_closed();
        document.capabilities.preview = true;
        document.capabilities.quotes = true;
        document.capabilities.portfolio = true;
        // Deliberately NOT advertising `execute`/`limits`.
        Arc::new(StaticBootstrap::new(document))
    };
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
    (Harness { state, client }, backend)
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
) -> (StatusCode, WireEnvelope, serde_json::Value) {
    let envelope = harness
        .client
        .seal_next(plaintext)
        .expect("seal request envelope");
    let response = edge_gateway::router(harness.state.clone())
        .oneshot(post(path, envelope.to_wire_bytes()))
        .await
        .expect("edge response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let sealed = session_transport::parse_wire_envelope(&body).expect("sealed envelope");
    assert_eq!(sealed.sequence, envelope.sequence);
    let plaintext = harness.client.open(&sealed).expect("open response");
    let value: serde_json::Value = serde_json::from_slice(&plaintext).expect("json");
    (status, sealed, value)
}

fn preview_payload() -> Vec<u8> {
    br#"{"op":"preview_market_order","payload":{"intent":{"chain":"base","token_in":"USDC","token_out":"TOKEN","side":"buy","amount_type":"stablecoin","amount":"25","max_slippage_bps":100,"max_price_impact_bps":150,"max_total_cost_usd":null},"router_preference":"okx"},"request_id":"e2e-preview","idempotency_key":null}"#.to_vec()
}

fn execute_payload(quote_id: &str) -> Vec<u8> {
    format!(
        r#"{{"op":"execute_market_order","payload":{{"quote_id":"{quote_id}","router_preference":"okx"}},"request_id":"e2e-exec","idempotency_key":"key-exec"}}"#
    )
    .into_bytes()
}

#[tokio::test]
async fn browser_preview_is_translated_into_the_canonical_trading_core_command() {
    let backend = FakeTradingCore::new(preview_document(), BackendOutcome::Unavailable);
    let (mut harness, backend) = harness(backend, true, true, 1_000);

    let (status, _sealed, value) = roundtrip(&mut harness, "/v1/command", &preview_payload()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["request_id"], "e2e-preview");
    let quote_id = value["result"]["quoteId"]
        .as_str()
        .expect("projected quote id");
    assert_eq!(value["result"]["intent"]["chain"], "base");
    assert_eq!(value["result"]["intent"]["tokenIn"], "USDC");
    assert_eq!(value["result"]["routerSource"], "okx");

    let commands = backend.commands();
    assert_eq!(commands.len(), 1);
    match &commands[0] {
        AgentCommand::Trade(TradeCommand::PreviewMarketOrder {
            token_in,
            token_out,
            amount,
            router,
            ..
        }) => {
            assert_eq!(token_in.address, "USDC");
            assert_eq!(token_in.chain, ChainId::Base);
            assert_eq!(token_out.address, "TOKEN");
            assert_eq!(*amount, AmountSpec::StablecoinAtomic(25_000_000));
            assert_eq!(*router, RouterSource::Okx);
        }
        other => panic!("unexpected command: {other:?}"),
    }
    assert!(!quote_id.is_empty());
}

#[tokio::test]
async fn execute_is_denied_while_trading_is_disabled_but_preview_stays_available() {
    let backend = FakeTradingCore::new(
        preview_document(),
        BackendOutcome::Value(json!({
            "execution": { "state": "submitted" },
            "execution_id": "intent-1",
            "router_source": "okx"
        })),
    );
    let (mut harness, _backend) = harness(backend, false, true, 1_000);

    let (_status, _sealed, preview) =
        roundtrip(&mut harness, "/v1/command", &preview_payload()).await;
    let quote_id = preview["result"]["quoteId"]
        .as_str()
        .expect("quote id")
        .to_string();

    let (status, _sealed, value) =
        roundtrip(&mut harness, "/v1/command", &execute_payload(&quote_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["request_id"], "e2e-exec");
    assert_eq!(value["error"]["code"], "capability_missing");
    assert_eq!(value["error"]["retryable"], false);
    assert!(value.get("result").is_none(), "no false success");
}

#[tokio::test]
async fn execute_succeeds_only_with_an_attributable_backend_identity() {
    let backend = FakeTradingCore::new(
        preview_document(),
        BackendOutcome::Value(json!({
            "execution": { "state": "submitted" },
            "execution_id": "intent-1",
            "router_source": "okx"
        })),
    );
    let (mut harness, backend) = harness(backend, true, true, 1_000);

    let (_status, _sealed, preview) =
        roundtrip(&mut harness, "/v1/command", &preview_payload()).await;
    let quote_id = preview["result"]["quoteId"]
        .as_str()
        .expect("quote id")
        .to_string();

    let (_status, _sealed, value) =
        roundtrip(&mut harness, "/v1/command", &execute_payload(&quote_id)).await;
    assert_eq!(value["result"]["execution_id"], "intent-1");
    assert_eq!(value["result"]["router_source"], "okx");

    // The executed command is the exact reviewed intent, not the quote id.
    let commands = backend.commands();
    match &commands[1] {
        AgentCommand::Trade(TradeCommand::ExecuteMarketOrder {
            token_in, amount, ..
        }) => {
            assert_eq!(token_in.address, "USDC");
            assert_eq!(*amount, AmountSpec::StablecoinAtomic(25_000_000));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_instrument_fails_closed_without_reaching_the_backend() {
    let backend = FakeTradingCore::new(preview_document(), BackendOutcome::Unavailable);
    let (mut harness, backend) = harness(backend, true, false, 1_000);

    let (_status, _sealed, value) =
        roundtrip(&mut harness, "/v1/command", &preview_payload()).await;
    assert_eq!(value["error"]["code"], "capability_missing");
    assert!(value.get("result").is_none());
    assert!(
        backend.commands().is_empty(),
        "no command reached the backend"
    );
}

#[tokio::test]
async fn an_unverifiable_execute_is_indeterminate_not_a_success() {
    let backend = FakeTradingCore::new(
        preview_document(),
        // A write that reports no execution identity can never be a success.
        BackendOutcome::Value(json!({ "execution": { "state": "unknown" } })),
    );
    let (mut harness, _backend) = harness(backend, true, true, 1_000);

    let (_status, _sealed, preview) =
        roundtrip(&mut harness, "/v1/command", &preview_payload()).await;
    let quote_id = preview["result"]["quoteId"]
        .as_str()
        .expect("quote id")
        .to_string();

    let (_status, _sealed, value) =
        roundtrip(&mut harness, "/v1/command", &execute_payload(&quote_id)).await;
    assert_eq!(value["error"]["code"], "unknown");
    assert_eq!(value["error"]["retryable"], true);
    assert!(value.get("result").is_none());
}
