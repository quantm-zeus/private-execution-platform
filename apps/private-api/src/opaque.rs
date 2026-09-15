//! Opaque encrypted session service for the neutral `/v1/*` routes.
//!
//! The edge relays `application/octet-stream` ciphertext (BR-7); this module
//! owns the only place the private plaintext exists: it opens the browser's
//! AES-256-GCM session envelope, dispatches the encrypted operation, and seals
//! the response back under the same `kid` and request sequence.
//!
//! Security properties:
//! - The operation type and all trading semantics stay inside the AEAD.
//! - Every response echoes the request `request_id` inside the AEAD (BR-3).
//! - Writes are bound to an `idempotency_key`; backends that cannot commit
//!   produce an indeterminate (retryable) denial so the client keeps its key.
//! - Responses are sealed at the exact request sequence, binding them to the
//!   request envelope.
//! - No secret is logged, and every failure is value-free.

use std::sync::{Arc, Mutex};

use agent_commands::{
    authorize, AgentCapabilities, AgentChannel, AgentCommand, AgentCommandError, AuthorizedCommand,
    DenyReason,
};
use async_trait::async_trait;
use mcp_server::{AgentBackend, BackendOutcome};
use rpc_contracts::relay_service::{RelayService, RelayServiceServer};
use rpc_contracts::{
    validate_relay_request, RelayRequest, RelayResponse, RelayResponseResult, Route,
};
use serde::Serialize;
use serde_json::{json, Value};
use session_transport::{
    parse_wire_envelope, CommandDenial, CommandRequest, CommandResponse, DenialCode, Purpose,
    SessionError, SessionRegistry, WireEnvelope,
};
use tonic::{Request, Response, Status};

/// Closed capability set exposed to the browser. Authoritative and
/// fail-closed: every field defaults to `false`.
#[derive(Clone, Debug, Serialize)]
pub struct CapabilitySet {
    pub market: bool,
    pub realtime: bool,
    pub quotes: bool,
    pub preview: bool,
    pub execute: bool,
    pub limits: bool,
    pub portfolio: bool,
    pub intelligence: bool,
    pub twitter: bool,
    pub gmgn: bool,
    pub okx: bool,
    pub twap: bool,
    pub rfq: bool,
    pub withdraw: bool,
    pub wallet_limits: bool,
}

impl CapabilitySet {
    /// No capability is available; mutations fail closed.
    pub fn none() -> Self {
        Self {
            market: false,
            realtime: false,
            quotes: false,
            preview: false,
            execute: false,
            limits: false,
            portfolio: false,
            intelligence: false,
            twitter: false,
            gmgn: false,
            okx: false,
            twap: false,
            rfq: false,
            withdraw: false,
            wallet_limits: false,
        }
    }
}

/// Chain advertised in the bootstrap document (BR-11 native token is optional
/// and `null` when the backend cannot resolve it).
#[derive(Clone, Debug, Serialize)]
pub struct ChainEntry {
    pub id: String,
    pub display: String,
    pub enabled: bool,
    pub native_token: Option<String>,
}

/// Authoritative bootstrap document (BR-1).
#[derive(Clone, Debug)]
pub struct BootstrapDocument {
    pub capabilities: CapabilitySet,
    pub trading_enabled: bool,
    pub kill_switch_enabled: bool,
    pub kill_switch_reason: Option<String>,
    pub chains: Vec<ChainEntry>,
}

impl BootstrapDocument {
    /// The production fail-closed default: nothing is available and the kill
    /// switch is engaged.
    pub fn fail_closed() -> Self {
        Self {
            capabilities: CapabilitySet::none(),
            trading_enabled: false,
            kill_switch_enabled: true,
            kill_switch_reason: Some("Private API capabilities are not configured.".to_string()),
            chains: Vec::new(),
        }
    }

    /// Serialize the flat wire document the web `parseWorkspaceSession` reads.
    pub fn to_wire(
        &self,
        kid: &str,
        expires_at_ms: i64,
        server_time_ms: i64,
        request_id: Option<&str>,
    ) -> Value {
        let mut document = json!({
            "protocol_version": 1,
            "capabilities": self.capabilities,
            "trading_enabled": self.trading_enabled,
            "kill_switch": {
                "enabled": self.kill_switch_enabled,
                "reason": self.kill_switch_reason,
            },
            "chains": self.chains,
            "session": {
                "key_id": kid,
                "expires_at_ms": expires_at_ms,
            },
            "server_time_ms": server_time_ms,
        });
        if let Some(id) = request_id {
            document["request_id"] = json!(id);
        }
        document
    }
}

/// Authoritative capability/kill-switch source.
pub trait BootstrapProvider: Send + Sync {
    fn document(&self) -> BootstrapDocument;
}

/// Fail-closed default provider.
#[derive(Debug, Default)]
pub struct FailClosedBootstrap;

impl BootstrapProvider for FailClosedBootstrap {
    fn document(&self) -> BootstrapDocument {
        BootstrapDocument::fail_closed()
    }
}

/// Static provider used by tests and the binary once the operator config is
/// resolved.
#[derive(Debug, Clone)]
pub struct StaticBootstrap {
    document: BootstrapDocument,
}

impl StaticBootstrap {
    pub fn new(document: BootstrapDocument) -> Self {
        Self { document }
    }
}

impl BootstrapProvider for StaticBootstrap {
    fn document(&self) -> BootstrapDocument {
        self.document.clone()
    }
}

/// Executes an authenticated, decrypted command operation.
#[async_trait]
pub trait CommandDispatcher: Send + Sync {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial>;
}

/// Fail-closed dispatcher: every command is a determinate capability denial
/// (nothing can have committed because no backend is installed).
#[derive(Debug, Default)]
pub struct FailClosedDispatcher;

#[async_trait]
impl CommandDispatcher for FailClosedDispatcher {
    async fn dispatch(&self, _request: &CommandRequest) -> Result<Value, CommandDenial> {
        Err(CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Command backend is not configured.",
        ))
    }
}

/// Adapter over the canonical `agent-commands` / `mcp-server` command core.
///
/// The channel grants no privilege: `authorize` runs the identical rule set for
/// every channel. `Web` is used only so source attribution stays honest.
pub struct AgentCommandDispatcher {
    backend: Arc<dyn AgentBackend>,
    capabilities: Arc<AgentCapabilities>,
    channel: AgentChannel,
}

impl AgentCommandDispatcher {
    pub fn new(
        backend: Arc<dyn AgentBackend>,
        capabilities: AgentCapabilities,
        channel: AgentChannel,
    ) -> Self {
        Self {
            backend,
            capabilities: Arc::new(capabilities),
            channel,
        }
    }

    /// Convenience constructor for the private web channel.
    pub fn for_web(backend: Arc<dyn AgentBackend>, capabilities: AgentCapabilities) -> Self {
        Self::new(backend, capabilities, AgentChannel::Web)
    }
}

#[async_trait]
impl CommandDispatcher for AgentCommandDispatcher {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        let wire = command_wire_json(&request.op, &request.payload)?;
        let command = AgentCommand::parse(&wire).map_err(map_parse_error)?;
        let mutating = command.is_mutating();

        // BR-3: every write carries an idempotency key so a retry cannot create
        // a duplicate trade. A missing key is a determinate protocol rejection
        // (nothing was executed).
        if mutating && request.idempotency_key.as_deref().is_none_or(str::is_empty) {
            return Err(CommandDenial::determinate(
                DenialCode::Protocol,
                "idempotency_key is required for write commands.",
            ));
        }

        let valuation = self.backend.valuation_usd_micros(&command).await;
        match authorize(self.channel, command.clone(), &self.capabilities, valuation) {
            AuthorizedCommand::Denied(reason) => Err(map_deny_reason(reason)),
            AuthorizedCommand::Read(_) | AuthorizedCommand::Trade(_) => {
                match self.backend.execute(self.channel, command).await {
                    BackendOutcome::Value(value) => Ok(value),
                    BackendOutcome::Unavailable => Err(CommandDenial::indeterminate(
                        DenialCode::CapabilityMissing,
                        "Command backend is unavailable.",
                    )),
                    BackendOutcome::Denied => Err(CommandDenial::determinate(
                        DenialCode::CapabilityMissing,
                        "Command was denied.",
                    )),
                    // A write that "definitively failed" may still have reached
                    // the chain before failing, so it stays indeterminate and
                    // the client keeps its idempotency key.
                    BackendOutcome::Failed => Err(if mutating {
                        CommandDenial::indeterminate(DenialCode::Server, "Command failed.")
                    } else {
                        CommandDenial::determinate(DenialCode::Server, "Command failed.")
                    }),
                }
            }
        }
    }
}

/// Build the canonical command JSON (`{"tool": op, ...payload}`), refusing a
/// payload that tries to set `tool` itself.
fn command_wire_json(op: &str, payload: &Value) -> Result<String, CommandDenial> {
    let mut map = match payload {
        Value::Null => serde_json::Map::new(),
        Value::Object(map) => map.clone(),
        _ => {
            return Err(CommandDenial::determinate(
                DenialCode::Protocol,
                "Command payload must be a JSON object.",
            ))
        }
    };
    if map.contains_key("tool") {
        return Err(CommandDenial::determinate(
            DenialCode::Protocol,
            "Command payload must not set the tool name.",
        ));
    }
    map.insert("tool".to_string(), Value::String(op.to_string()));
    serde_json::to_string(&Value::Object(map)).map_err(|_| {
        CommandDenial::determinate(
            DenialCode::Protocol,
            "Command payload could not be encoded.",
        )
    })
}

fn map_parse_error(error: AgentCommandError) -> CommandDenial {
    match error {
        // Forbidden/unknown operations can never have committed.
        AgentCommandError::ForbiddenOperation | AgentCommandError::UnknownTool => {
            CommandDenial::determinate(
                DenialCode::CapabilityMissing,
                "Operation is not available on this channel.",
            )
        }
        _ => CommandDenial::determinate(DenialCode::Protocol, "Command was malformed."),
    }
}

fn map_deny_reason(reason: DenyReason) -> CommandDenial {
    match reason {
        DenyReason::TradingDisabled => CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Trading is disabled by the global kill switch.",
        ),
        DenyReason::ForbiddenOperation => CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Operation is not available on this channel.",
        ),
        DenyReason::ChainNotAllowed => CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Chain is not allowed for this wallet.",
        ),
        DenyReason::NotionalExceedsLimit => CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Trade exceeds the configured wallet limit.",
        ),
    }
}

/// Clock seam so tests can control expiry/anchor time.
pub trait OpaqueClock: Send + Sync {
    fn now_ms(&self) -> Option<i64>;
}

/// Process wall clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl OpaqueClock for SystemClock {
    fn now_ms(&self) -> Option<i64> {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        i64::try_from(duration.as_millis()).ok()
    }
}

/// Opaque routes this service understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueRoute {
    Bootstrap,
    Sync,
    Command,
    Blob,
}

impl OpaqueRoute {
    fn purpose(self) -> Option<Purpose> {
        match self {
            OpaqueRoute::Bootstrap => Some(Purpose::Bootstrap),
            OpaqueRoute::Sync => Some(Purpose::Sync),
            OpaqueRoute::Command => Some(Purpose::Command),
            // Blob remains available only through the artifact/enrollment
            // boundary; there is no encrypted app operation for it yet.
            OpaqueRoute::Blob => None,
        }
    }
}

fn route_from_proto(route: i32) -> Option<OpaqueRoute> {
    match Route::try_from(route) {
        Ok(Route::Bootstrap) => Some(OpaqueRoute::Bootstrap),
        Ok(Route::Sync) => Some(OpaqueRoute::Sync),
        Ok(Route::Command) => Some(OpaqueRoute::Command),
        Ok(Route::Blob) => Some(OpaqueRoute::Blob),
        Ok(Route::Unspecified) | Err(_) => None,
    }
}

/// Value-free relay failure, mapped to an opaque gRPC status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFailure {
    Unavailable,
    Malformed,
    TooLarge,
    UnknownSession,
    Protocol,
}

impl RelayFailure {
    pub fn to_status(self) -> Status {
        match self {
            RelayFailure::Unavailable => Status::unavailable("relay unavailable"),
            RelayFailure::Malformed => Status::invalid_argument("malformed relay envelope"),
            RelayFailure::TooLarge => Status::out_of_range("relay envelope too large"),
            RelayFailure::UnknownSession => Status::unauthenticated("session unavailable"),
            RelayFailure::Protocol => Status::failed_precondition("relay protocol error"),
        }
    }
}

/// Shared opaque session service state.
#[derive(Clone)]
pub struct OpaqueServiceState {
    sessions: Arc<Mutex<SessionRegistry>>,
    dispatcher: Arc<dyn CommandDispatcher>,
    bootstrap: Arc<dyn BootstrapProvider>,
    clock: Arc<dyn OpaqueClock>,
    session_ttl_ms: i64,
}

impl OpaqueServiceState {
    pub fn new(
        sessions: Arc<Mutex<SessionRegistry>>,
        dispatcher: Arc<dyn CommandDispatcher>,
        bootstrap: Arc<dyn BootstrapProvider>,
        clock: Arc<dyn OpaqueClock>,
        session_ttl_ms: i64,
    ) -> Result<Self, &'static str> {
        if session_ttl_ms <= 0 {
            return Err("session ttl must be positive");
        }
        Ok(Self {
            sessions,
            dispatcher,
            bootstrap,
            clock,
            session_ttl_ms,
        })
    }

    /// Fail-closed state with no sessions, no backend and no capabilities.
    pub fn fail_closed(
        sessions: Arc<Mutex<SessionRegistry>>,
        clock: Arc<dyn OpaqueClock>,
        session_ttl_ms: i64,
    ) -> Result<Self, &'static str> {
        Self::new(
            sessions,
            Arc::new(FailClosedDispatcher),
            Arc::new(FailClosedBootstrap),
            clock,
            session_ttl_ms,
        )
    }

    pub fn sessions(&self) -> Arc<Mutex<SessionRegistry>> {
        self.sessions.clone()
    }

    /// Handle one opaque envelope end-to-end (no gRPC), returning the sealed
    /// response envelope bytes.
    pub async fn relay_envelope(
        &self,
        route: OpaqueRoute,
        body: &[u8],
    ) -> Result<Vec<u8>, RelayFailure> {
        let now = self.clock.now_ms().ok_or(RelayFailure::Unavailable)?;
        let envelope = parse_wire_envelope(body).map_err(|error| match error {
            SessionError::TooLarge => RelayFailure::TooLarge,
            _ => RelayFailure::Malformed,
        })?;
        let kid = envelope.decode_kid().map_err(|_| RelayFailure::Malformed)?;
        let purpose = route.purpose().ok_or(RelayFailure::Unavailable)?;
        let sequence = envelope.sequence;

        // Open the envelope under the registry lock; the lock is released
        // before any await so a slow backend cannot block other sessions.
        let plaintext = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| RelayFailure::Unavailable)?;
            sessions.prune(now);
            let session = sessions.get_mut(&kid).ok_or(RelayFailure::UnknownSession)?;
            session
                .open(&envelope, now, purpose)
                .map_err(|error| match error {
                    SessionError::Expired => RelayFailure::UnknownSession,
                    SessionError::ReplayDetected | SessionError::StaleSequence => {
                        RelayFailure::Protocol
                    }
                    _ => RelayFailure::Protocol,
                })?
        };

        verify_route_op(route, &plaintext)?;
        let response_bytes = self
            .build_response(route, &envelope, &plaintext, now)
            .await?;

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| RelayFailure::Unavailable)?;
        let session = sessions.get_mut(&kid).ok_or(RelayFailure::UnknownSession)?;
        let sealed = session
            .seal(sequence, &response_bytes)
            .map_err(|_| RelayFailure::Unavailable)?;
        Ok(sealed.to_wire_bytes())
    }

    async fn build_response(
        &self,
        route: OpaqueRoute,
        envelope: &WireEnvelope,
        plaintext: &[u8],
        now: i64,
    ) -> Result<Vec<u8>, RelayFailure> {
        match route {
            OpaqueRoute::Bootstrap => {
                let request_id = extract_request_id(plaintext);
                let document = self.bootstrap.document();
                let body = document.to_wire(
                    &envelope.kid,
                    now.saturating_add(self.session_ttl_ms),
                    now,
                    request_id.as_deref(),
                );
                serde_json::to_vec(&body).map_err(|_| RelayFailure::Unavailable)
            }
            OpaqueRoute::Sync => {
                let request_id = extract_request_id(plaintext);
                let from_seq = extract_from_seq(plaintext);
                let body = json!({
                    "request_id": request_id,
                    "result": { "accepted": true, "from_seq": from_seq },
                });
                serde_json::to_vec(&body).map_err(|_| RelayFailure::Unavailable)
            }
            OpaqueRoute::Command => {
                let request =
                    CommandRequest::parse(plaintext).map_err(|_| RelayFailure::Protocol)?;
                let response = match self.dispatcher.dispatch(&request).await {
                    Ok(result) => CommandResponse::success(&request.request_id, result),
                    Err(denial) => CommandResponse::denial(&request.request_id, denial),
                };
                Ok(response.to_bytes())
            }
            OpaqueRoute::Blob => Err(RelayFailure::Unavailable),
        }
    }
}

impl std::fmt::Debug for OpaqueServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueServiceState")
            .field("session_ttl_ms", &self.session_ttl_ms)
            .finish_non_exhaustive()
    }
}

/// Reject cross-route envelope substitution: a bootstrap/sync plaintext
/// replayed on `/v1/command` (or a command plaintext on a control route) must
/// not be interpreted as the other route.
fn verify_route_op(route: OpaqueRoute, plaintext: &[u8]) -> Result<(), RelayFailure> {
    let value: Value = serde_json::from_slice(plaintext).map_err(|_| RelayFailure::Protocol)?;
    let op = value.get("op").and_then(Value::as_str);
    match route {
        OpaqueRoute::Bootstrap => match op {
            Some("bootstrap") | None => Ok(()),
            Some(_) => Err(RelayFailure::Protocol),
        },
        OpaqueRoute::Sync => match op {
            Some("sync") | None => Ok(()),
            Some(_) => Err(RelayFailure::Protocol),
        },
        OpaqueRoute::Command => match op {
            // Route-control operations never travel on the command channel.
            Some("bootstrap") | Some("sync") => Err(RelayFailure::Protocol),
            Some(_) => Ok(()),
            None => Err(RelayFailure::Protocol),
        },
        OpaqueRoute::Blob => Ok(()),
    }
}

fn extract_request_id(plaintext: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(plaintext).ok()?;
    value
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= session_transport::MAX_REQUEST_ID_LEN)
        .map(str::to_string)
}

fn extract_from_seq(plaintext: &[u8]) -> Value {
    serde_json::from_slice::<Value>(plaintext)
        .ok()
        .and_then(|value| value.get("from_seq").cloned())
        .unwrap_or(Value::Null)
}

/// gRPC relay service that owns the encrypted session service.
pub struct EncryptedRelayService {
    state: OpaqueServiceState,
}

impl EncryptedRelayService {
    pub fn new(state: OpaqueServiceState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl RelayService for EncryptedRelayService {
    async fn relay(&self, request: Request<RelayRequest>) -> RelayResponseResult {
        let inner = request.into_inner();
        validate_relay_request(&inner)?;
        let route = route_from_proto(inner.route)
            .ok_or_else(|| Status::invalid_argument("invalid relay route"))?;
        let ciphertext = self
            .state
            .relay_envelope(route, &inner.ciphertext)
            .await
            .map_err(RelayFailure::to_status)?;
        Ok(Response::new(RelayResponse { ciphertext }))
    }
}

/// Build the TLS-ready gRPC server with the encrypted relay service.
pub fn relay_tls_router_with(
    state: OpaqueServiceState,
    tls: tonic::transport::ServerTlsConfig,
) -> Result<tonic::transport::server::Router, tonic::transport::Error> {
    tonic::transport::Server::builder()
        .tls_config(tls)
        .map(|mut server| {
            server.add_service(RelayServiceServer::new(EncryptedRelayService::new(state)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crypto_envelope::hpke::AppDirectionKeys;
    use session_transport::{ClientSession, ServerSession};

    const KID: [u8; 16] = [0x5Au8; 16];

    struct FixedClock(i64);
    impl OpaqueClock for FixedClock {
        fn now_ms(&self) -> Option<i64> {
            Some(self.0)
        }
    }

    fn test_keys() -> AppDirectionKeys {
        AppDirectionKeys::from_bytes([0x01u8; 32], [0x02u8; 32])
    }

    fn state(now: i64) -> (OpaqueServiceState, ClientSession) {
        state_with(
            now,
            Arc::new(FailClosedDispatcher),
            Arc::new(FailClosedBootstrap),
        )
    }

    fn state_with(
        now: i64,
        dispatcher: Arc<dyn CommandDispatcher>,
        bootstrap: Arc<dyn BootstrapProvider>,
    ) -> (OpaqueServiceState, ClientSession) {
        let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
        sessions
            .lock()
            .unwrap()
            .insert(ServerSession::new(KID, &test_keys(), now + 60_000).unwrap())
            .unwrap();
        let state = OpaqueServiceState::new(
            sessions,
            dispatcher,
            bootstrap,
            Arc::new(FixedClock(now)),
            60_000,
        )
        .unwrap();
        (state, ClientSession::new(KID, &test_keys()).unwrap())
    }

    async fn roundtrip(
        state: &OpaqueServiceState,
        client: &mut ClientSession,
        route: OpaqueRoute,
        plaintext: &[u8],
    ) -> Result<Value, RelayFailure> {
        let envelope = client.seal_at(client.next_sequence(), plaintext).unwrap();
        let response_bytes = state
            .relay_envelope(route, &envelope.to_wire_bytes())
            .await?;
        let response = parse_wire_envelope(&response_bytes).unwrap();
        assert_eq!(response.sequence, envelope.sequence);
        let opened = client.open(&response).unwrap();
        Ok(serde_json::from_slice(&opened).unwrap())
    }

    #[tokio::test]
    async fn bootstrap_is_fail_closed_and_carries_session_identity() {
        let now = 1_700_000_000_000i64;
        let (state, mut client) = state(now);
        let response = roundtrip(
            &state,
            &mut client,
            OpaqueRoute::Bootstrap,
            br#"{"op":"bootstrap","protocol_version":1,"request_id":"r1"}"#,
        )
        .await
        .expect("bootstrap");
        assert_eq!(response["protocol_version"], 1);
        assert_eq!(response["trading_enabled"], false);
        assert_eq!(response["kill_switch"]["enabled"], true);
        assert_eq!(response["capabilities"]["execute"], false);
        assert_eq!(response["request_id"], "r1");
        assert_eq!(response["server_time_ms"], now);
        assert_eq!(response["session"]["expires_at_ms"], now + 60_000);
        assert_eq!(
            response["session"]["key_id"],
            session_transport::wire_kid(&KID)
        );
    }

    #[tokio::test]
    async fn command_denials_are_authenticated_and_echo_request_id() {
        let now = 1_000i64;
        let (state, mut client) = state(now);
        let response = roundtrip(
            &state,
            &mut client,
            OpaqueRoute::Command,
            br#"{"op":"get_quote","payload":{},"request_id":"cmd-1","idempotency_key":null}"#,
        )
        .await
        .expect("command response");
        assert_eq!(response["request_id"], "cmd-1");
        assert_eq!(response["error"]["code"], "capability_missing");
        assert_eq!(response["error"]["retryable"], false);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn replaying_a_command_envelope_is_rejected() {
        let now = 1_000i64;
        let (state, client) = state(now);
        let envelope = client
            .seal_at(0, br#"{"op":"get_quote","payload":{},"request_id":"a"}"#)
            .unwrap();
        assert!(state
            .relay_envelope(OpaqueRoute::Command, &envelope.to_wire_bytes())
            .await
            .is_ok());
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Command, &envelope.to_wire_bytes())
                .await,
            Err(RelayFailure::Protocol)
        );
    }

    #[tokio::test]
    async fn unknown_or_expired_session_fails_closed() {
        let now = 1_000i64;
        // A different kid is unknown.
        let (state, _client) = state(now);
        let mut other = ClientSession::new([0x99u8; 16], &test_keys()).unwrap();
        let envelope = other.seal_next(b"{}").unwrap();
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Bootstrap, &envelope.to_wire_bytes())
                .await,
            Err(RelayFailure::UnknownSession)
        );

        // Expiry: the session's deadline equals the current clock.
        let sessions = Arc::new(Mutex::new(SessionRegistry::new()));
        sessions
            .lock()
            .unwrap()
            .insert(ServerSession::new(KID, &test_keys(), now + 1).unwrap())
            .unwrap();
        let expired = OpaqueServiceState::new(
            sessions,
            Arc::new(FailClosedDispatcher),
            Arc::new(FailClosedBootstrap),
            Arc::new(FixedClock(now + 1)),
            60_000,
        )
        .unwrap();
        let mut expired_client = ClientSession::new(KID, &test_keys()).unwrap();
        let envelope = expired_client.seal_next(b"{}").unwrap();
        assert_eq!(
            expired
                .relay_envelope(OpaqueRoute::Bootstrap, &envelope.to_wire_bytes())
                .await,
            Err(RelayFailure::UnknownSession)
        );
    }

    #[tokio::test]
    async fn cross_route_substitution_is_rejected() {
        let now = 1_000i64;
        let (state, mut client) = state(now);
        // A bootstrap plaintext posted to /v1/command must not be interpreted
        // as a command.
        let envelope = client
            .seal_next(br#"{"op":"bootstrap","request_id":"x"}"#)
            .unwrap();
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Command, &envelope.to_wire_bytes())
                .await,
            Err(RelayFailure::Protocol)
        );
    }

    struct CountingDispatcher {
        calls: Arc<AtomicUsize>,
        result: Value,
    }

    #[async_trait]
    impl CommandDispatcher for CountingDispatcher {
        async fn dispatch(&self, _request: &CommandRequest) -> Result<Value, CommandDenial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result.clone())
        }
    }

    #[tokio::test]
    async fn configured_dispatcher_result_is_sealed_with_request_echo() {
        let now = 2_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        let (state, mut client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            Arc::new(FailClosedBootstrap),
        );
        let response = roundtrip(
            &state,
            &mut client,
            OpaqueRoute::Command,
            br#"{"op":"get_quote","payload":{},"request_id":"r9"}"#,
        )
        .await
        .expect("command");
        assert_eq!(response["request_id"], "r9");
        assert_eq!(response["result"]["status"], "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn grpc_relay_service_round_trips_an_opaque_command() {
        let now = 3_000i64;
        let (state, mut client) = state(now);
        let service = EncryptedRelayService::new(state);
        let envelope = client
            .seal_next(br#"{"op":"get_quote","payload":{},"request_id":"grpc-1"}"#)
            .unwrap();
        let request = RelayRequest {
            route: Route::Command as i32,
            ciphertext: envelope.to_wire_bytes(),
        };
        let response = service
            .relay(Request::new(request))
            .await
            .expect("relay ok")
            .into_inner();
        let sealed = parse_wire_envelope(&response.ciphertext).unwrap();
        assert_eq!(sealed.sequence, envelope.sequence);
        let plaintext = client.open(&sealed).unwrap();
        let body: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(body["request_id"], "grpc-1");
        assert_eq!(body["error"]["code"], "capability_missing");
    }

    #[tokio::test]
    async fn grpc_relay_service_fails_closed_on_bad_route_and_unknown_session() {
        let now = 3_000i64;
        let (state, _client) = state(now);
        let service = EncryptedRelayService::new(state);

        let bad_route = RelayRequest {
            route: 0,
            ciphertext: vec![1, 2, 3],
        };
        assert_eq!(
            service
                .relay(Request::new(bad_route))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );

        let mut stranger = ClientSession::new([0x77u8; 16], &test_keys()).unwrap();
        let envelope = stranger.seal_next(b"{}").unwrap();
        let unknown = RelayRequest {
            route: Route::Bootstrap as i32,
            ciphertext: envelope.to_wire_bytes(),
        };
        assert_eq!(
            service
                .relay(Request::new(unknown))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    struct FakeBackend {
        outcome: BackendOutcome,
        valuation: Option<u64>,
    }

    #[async_trait]
    impl AgentBackend for FakeBackend {
        async fn execute(&self, _channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
            self.outcome.clone()
        }

        async fn valuation_usd_micros(&self, _command: &AgentCommand) -> Option<u64> {
            self.valuation
        }
    }

    fn web_capabilities(trading_enabled: bool) -> AgentCapabilities {
        AgentCapabilities::new(trading_enabled, std::collections::HashSet::new(), u64::MAX)
    }

    async fn dispatch(
        outcome: BackendOutcome,
        valuation: Option<u64>,
        trading_enabled: bool,
        json: &[u8],
    ) -> Result<Value, CommandDenial> {
        let dispatcher = AgentCommandDispatcher::for_web(
            Arc::new(FakeBackend { outcome, valuation }),
            web_capabilities(trading_enabled),
        );
        let request = CommandRequest::parse(json).expect("request parses");
        dispatcher.dispatch(&request).await
    }

    #[tokio::test]
    async fn read_command_forwards_the_backend_value() {
        let result = dispatch(
            BackendOutcome::Value(json!({"portfolio": {"balances": []}})),
            None,
            false,
            br#"{"op":"get_portfolio","payload":{},"request_id":"r","idempotency_key":null}"#,
        )
        .await
        .expect("read allowed");
        assert_eq!(result["portfolio"]["balances"], json!([]));
    }

    #[tokio::test]
    async fn mutating_command_is_denied_while_trading_is_disabled() {
        let denial = dispatch(
            BackendOutcome::Value(json!({})),
            Some(0),
            false,
            br#"{"op":"cancel_order","payload":{"order_id":"o1"},"request_id":"r","idempotency_key":"k1"}"#,
        )
        .await
        .expect_err("trading disabled");
        assert_eq!(denial.code, "capability_missing");
        assert!(!denial.retryable);
    }

    #[tokio::test]
    async fn mutating_command_without_valuation_is_denied() {
        let denial = dispatch(
            BackendOutcome::Value(json!({})),
            None,
            true,
            br#"{"op":"cancel_order","payload":{"order_id":"o1"},"request_id":"r","idempotency_key":"k1"}"#,
        )
        .await
        .expect_err("no valuation");
        assert_eq!(denial.code, "capability_missing");
    }

    #[tokio::test]
    async fn write_without_idempotency_key_is_a_protocol_denial() {
        let denial = dispatch(
            BackendOutcome::Value(json!({})),
            Some(0),
            true,
            br#"{"op":"cancel_order","payload":{"order_id":"o1"},"request_id":"r"}"#,
        )
        .await
        .expect_err("missing key");
        assert_eq!(denial.code, "protocol");
    }

    #[tokio::test]
    async fn unavailable_backend_is_indeterminate() {
        let denial = dispatch(
            BackendOutcome::Unavailable,
            None,
            true,
            br#"{"op":"get_portfolio","payload":{},"request_id":"r"}"#,
        )
        .await
        .expect_err("unavailable");
        assert_eq!(denial.code, "capability_missing");
        assert!(denial.retryable);
    }

    #[tokio::test]
    async fn forbidden_operation_is_rejected_before_the_backend() {
        let denial = dispatch(
            BackendOutcome::Value(json!({})),
            None,
            true,
            br#"{"op":"request_withdrawal","payload":{},"request_id":"r","idempotency_key":"k"}"#,
        )
        .await
        .expect_err("forbidden");
        assert_eq!(denial.code, "capability_missing");
        assert!(!denial.retryable);
    }

    #[test]
    fn system_clock_is_sane() {
        let now = SystemClock.now_ms().expect("clock");
        let expected = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!((now - expected).abs() < 5_000);
    }
}
