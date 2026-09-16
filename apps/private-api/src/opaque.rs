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
use rpc_contracts::relay_stream_service::RelayStreamServiceServer;
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

use crate::stream::{
    EncryptedStreamService, FailClosedStreamSource, StreamDriver, StreamHub, StreamSource,
};

/// Closed capability set exposed to the browser. Authoritative and
/// fail-closed: every field defaults to `false`.
#[derive(Clone, Debug, Serialize)]
pub struct CapabilitySet {
    pub market: bool,
    /// Read-only chart history (`get_chart`). Separate from `market` so a
    /// deployment that only wires the FOMO chart does not advertise token
    /// search/detail, which it does not serve.
    pub chart: bool,
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
            chart: false,
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

    /// The capability flag that gates a browser operation.
    ///
    /// BR-1 calls the advertised capabilities authoritative, so a `false` flag
    /// must refuse the operation server-side, not merely hide the button. Every
    /// operation whose surface is advertised as a capability is listed here; an
    /// operation outside this map is denied unless it is one of the explicitly
    /// ungated reconciliation reads ([`Self::is_ungated_read`]), so a new op
    /// cannot accidentally escape the gate.
    pub fn for_op(op: &str) -> Option<&'static str> {
        let capabilities = match op {
            "execute_market_order" => "execute",
            "place_limit_order" | "cancel_order" | "get_orders" | "get_order" => "limits",
            "preview_market_order" => "preview",
            "get_quote" => "quotes",
            "get_portfolio" | "get_balances" | "get_history" => "portfolio",
            "start_twap" => "twap",
            "submit_rfq" => "rfq",
            "request_withdrawal" => "withdraw",
            "get_wallet_limits" | "set_wallet_limits" => "wallet_limits",
            "get_intelligence" | "get_provider_health" | "get_alerts" => "intelligence",
            "search_token" | "get_token" => "market",
            "get_chart" => "chart",
            _ => return None,
        };
        Some(capabilities)
    }

    /// Reconciliation reads that stay available regardless of the advertised
    /// capability so an UNKNOWN mutation can always be resolved by an
    /// authoritative read (BR-9). They carry no trading semantics and only read
    /// state the authenticated session already owns.
    pub fn is_ungated_read(op: &str) -> bool {
        matches!(
            op,
            "get_order_by_client_id" | "get_withdrawal_by_request_id" | "get_execution_progress"
        )
    }

    /// The boolean value for a capability name produced by [`Self::for_op`].
    fn flag(&self, capability: &str) -> bool {
        match capability {
            "market" => self.market,
            "chart" => self.chart,
            "realtime" => self.realtime,
            "quotes" => self.quotes,
            "preview" => self.preview,
            "execute" => self.execute,
            "limits" => self.limits,
            "portfolio" => self.portfolio,
            "intelligence" => self.intelligence,
            "twitter" => self.twitter,
            "gmgn" => self.gmgn,
            "okx" => self.okx,
            "twap" => self.twap,
            "rfq" => self.rfq,
            "withdraw" => self.withdraw,
            "wallet_limits" => self.wallet_limits,
            // An unknown capability name resolves to unavailable.
            _ => false,
        }
    }

    /// Whether the advertised set permits `op`.
    pub fn permits(&self, op: &str) -> bool {
        match Self::for_op(op) {
            Some(capability) => self.flag(capability),
            None => Self::is_ungated_read(op),
        }
    }

    /// Whether the advertised set permits the request's router preference.
    ///
    /// BR-10: an explicit `okx` preference needs the authoritative `okx`
    /// capability, so a deployment that only wires the Local router cannot have
    /// its `preview`/`execute` capability endorse an OKX-routed command. A
    /// missing/`local` preference is unaffected.
    pub fn permits_router_preference(&self, payload: &Value) -> bool {
        match payload.get("router_preference").and_then(Value::as_str) {
            Some("okx") => self.okx,
            _ => true,
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

    /// Session-scoped dispatch. The default ignores the session identity; the
    /// web integration layer uses it to bind preview quotes to the
    /// authenticated `kid` so one session cannot execute another's quote.
    async fn dispatch_for_session(
        &self,
        _kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        self.dispatch(request).await
    }
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
    stream_hub: Arc<StreamHub>,
    stream_source: Arc<dyn StreamSource>,
}

impl OpaqueServiceState {
    pub fn new(
        sessions: Arc<Mutex<SessionRegistry>>,
        dispatcher: Arc<dyn CommandDispatcher>,
        bootstrap: Arc<dyn BootstrapProvider>,
        clock: Arc<dyn OpaqueClock>,
        session_ttl_ms: i64,
    ) -> Result<Self, &'static str> {
        Self::with_stream(
            sessions,
            dispatcher,
            bootstrap,
            clock,
            session_ttl_ms,
            Arc::new(FailClosedStreamSource),
        )
    }

    /// Full constructor with an injected realtime source (BR-2).
    pub fn with_stream(
        sessions: Arc<Mutex<SessionRegistry>>,
        dispatcher: Arc<dyn CommandDispatcher>,
        bootstrap: Arc<dyn BootstrapProvider>,
        clock: Arc<dyn OpaqueClock>,
        session_ttl_ms: i64,
        stream_source: Arc<dyn StreamSource>,
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
            stream_hub: Arc::new(StreamHub::new()),
            stream_source,
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

    pub fn clock(&self) -> Arc<dyn OpaqueClock> {
        self.clock.clone()
    }

    pub fn stream_hub(&self) -> Arc<StreamHub> {
        self.stream_hub.clone()
    }

    pub fn stream_source(&self) -> Arc<dyn StreamSource> {
        self.stream_source.clone()
    }

    /// The authoritative bootstrap provider (BR-1). Exposed for composition
    /// tests and the production wiring that derives the advertised document.
    pub fn bootstrap(&self) -> Arc<dyn BootstrapProvider> {
        self.bootstrap.clone()
    }

    /// Build a stream driver bound to this service's session registry, clock and
    /// injected realtime source.
    pub fn stream_driver(&self) -> StreamDriver {
        StreamDriver::new(
            self.sessions.clone(),
            self.stream_hub.clone(),
            self.clock.clone(),
            self.stream_source.clone(),
        )
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

        // Authenticate and validate under the registry lock; the lock is released
        // before any await so a slow backend cannot block other sessions.
        let (plaintext, session_expires_at_ms) = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| RelayFailure::Unavailable)?;
            sessions.prune(now);
            let session = sessions.get_mut(&kid).ok_or(RelayFailure::UnknownSession)?;
            // Decrypt WITHOUT consuming a sequence slot, validate the route
            // binding, and only then advance the replay window. A captured
            // envelope replayed on another route therefore cannot burn the slot
            // the honest client is about to use (fail-closed DoS hardening).
            let plaintext =
                session
                    .open_unverified(&envelope, now)
                    .map_err(|error| match error {
                        SessionError::Expired => RelayFailure::UnknownSession,
                        _ => RelayFailure::Protocol,
                    })?;
            verify_route_op(route, &plaintext)?;
            session
                .accept_sequence(sequence, purpose)
                .map_err(|error| match error {
                    SessionError::ReplayDetected | SessionError::StaleSequence => {
                        RelayFailure::Protocol
                    }
                    _ => RelayFailure::Protocol,
                })?;
            // BR-1/F5: the advertised session deadline must be the session's real
            // deadline, not a fresh `now + ttl`. The client derives its mutation
            // deadline from the advertised duration, so recomputing it on a
            // re-bootstrap would let the client keep writing past the server's
            // actual expiry (and get indeterminate 503s for every write).
            (plaintext, session.expires_at_ms())
        };
        // BR-2: an authenticated `/v1/sync` asks the active stream connection for
        // a fresh snapshot at/after the client's high-water mark. The snapshot is
        // delivered on the stream (never in this HTTP body), matching the web
        // worker's contract.
        if route == OpaqueRoute::Sync {
            self.stream_hub
                .request_resync(kid, extract_from_seq_u64(&plaintext));
        }
        let response_bytes = self
            .build_response(route, &envelope, &plaintext, now, session_expires_at_ms)
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
        session_expires_at_ms: i64,
    ) -> Result<Vec<u8>, RelayFailure> {
        match route {
            OpaqueRoute::Bootstrap => {
                // BR-3/F5: the request challenge is required on every route. The
                // browser rejects a response that does not echo it, so a server
                // that omitted it would emit an unusable (and replayable) success.
                let request_id = extract_request_id(plaintext).ok_or(RelayFailure::Protocol)?;
                let document = self.bootstrap.document();
                let body =
                    document.to_wire(&envelope.kid, session_expires_at_ms, now, Some(&request_id));
                serde_json::to_vec(&body).map_err(|_| RelayFailure::Unavailable)
            }
            OpaqueRoute::Sync => {
                let request_id = extract_request_id(plaintext).ok_or(RelayFailure::Protocol)?;
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
                let kid = envelope.decode_kid().map_err(|_| RelayFailure::Malformed)?;
                // BR-1/F4: the bootstrap document is the authoritative trading and
                // kill-switch surface the browser renders. A mutating command must
                // honour that same gate, so a composition whose advertised kill
                // switch is engaged cannot execute a write through an injected
                // dispatcher that would otherwise allow it. Reads and previews stay
                // available.
                let response =
                    if session_transport::is_mutating_op(&request.op) && !self.writes_allowed() {
                        CommandResponse::denial(
                            &request.request_id,
                            CommandDenial::determinate(
                                DenialCode::CapabilityMissing,
                                "Trading is disabled by the global kill switch.",
                            ),
                        )
                    } else if !self.capabilities().permits(&request.op)
                        || !self
                            .capabilities()
                            .permits_router_preference(&request.payload)
                    {
                        // BR-1/F2 and BR-10: the advertised capability set is
                        // authoritative, so a `false` flag (including `okx` for an
                        // explicit OKX router preference) must refuse the operation
                        // server-side. Otherwise a crafted client could use any op
                        // the injected dispatcher allows while the UI renders that
                        // capability as unavailable, or force an OKX route the
                        // deployment never advertised. Deny before the dispatcher.
                        CommandResponse::denial(
                            &request.request_id,
                            CommandDenial::determinate(
                                DenialCode::CapabilityMissing,
                                "The requested capability is not available.",
                            ),
                        )
                    } else {
                        match self.dispatcher.dispatch_for_session(&kid, &request).await {
                            Ok(result) => CommandResponse::success(&request.request_id, result),
                            Err(denial) => CommandResponse::denial(&request.request_id, denial),
                        }
                    };
                Ok(response.to_bytes())
            }
            OpaqueRoute::Blob => Err(RelayFailure::Unavailable),
        }
    }

    /// Whether the advertised bootstrap document currently permits writes.
    ///
    /// `trading_enabled` and the kill switch must agree for writes to be allowed:
    /// an engaged kill switch or a disabled trading gate denies mutations even if
    /// an injected dispatcher would accept them.
    fn writes_allowed(&self) -> bool {
        let document = self.bootstrap.document();
        document.trading_enabled && !document.kill_switch_enabled
    }

    /// The advertised capability set that gates command dispatch (BR-1/F2).
    fn capabilities(&self) -> CapabilitySet {
        self.bootstrap.document().capabilities
    }
}

impl std::fmt::Debug for OpaqueServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueServiceState")
            .field("session_ttl_ms", &self.session_ttl_ms)
            .finish_non_exhaustive()
    }
}

/// Reject cross-route envelope substitution: a bootstrap/sync/stream-subscribe
/// plaintext replayed on `/v1/command` (or a command plaintext on a control
/// route) must not be interpreted as the other route.
///
/// This runs *before* the replay window advances, so a route-control plaintext
/// replayed on the command route must be refused here — never dispatched and
/// never allowed to burn a `Purpose::Command` sequence the honest client is
/// about to use. The check refuses the closed `session_transport` route-control
/// set (`bootstrap`/`sync`/`subscribe`); the dispatcher and the capability gate
/// backstop every other op, so a non-control op that is not a real command is
/// still rejected before it can produce a result.
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
            // Route-control operations (`bootstrap`, `sync`, `subscribe`) never
            // travel on the command channel. Refusing them here — before
            // `accept_sequence` — closes the cross-purpose replay DoS where a
            // captured stream `subscribe` envelope consumed a command sequence
            // and the dispatcher's later `ForbiddenOperation` rejection could
            // not undo it.
            Some("bootstrap") | Some("sync") | Some("subscribe") => Err(RelayFailure::Protocol),
            Some(op) => {
                if session_transport::is_route_control_op(op) {
                    Err(RelayFailure::Protocol)
                } else {
                    Ok(())
                }
            }
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

fn extract_from_seq_u64(plaintext: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(plaintext)
        .ok()
        .and_then(|value| value.get("from_seq").and_then(Value::as_u64))
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

/// Build the TLS-ready gRPC server with the encrypted relay + realtime stream
/// services.
pub fn relay_tls_router_with(
    state: OpaqueServiceState,
    tls: tonic::transport::ServerTlsConfig,
) -> Result<tonic::transport::server::Router, tonic::transport::Error> {
    let stream_service = EncryptedStreamService::new(state.clone());
    tonic::transport::Server::builder()
        .tls_config(tls)
        .map(|mut server| {
            server
                .add_service(RelayServiceServer::new(EncryptedRelayService::new(state)))
                .add_service(RelayStreamServiceServer::new(stream_service))
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

    /// A bootstrap that advertises the read capabilities the dispatcher tests
    /// exercise, with trading disabled and the kill switch engaged. BR-1/F2
    /// enforces the advertised set, so a test that expects dispatch to run must
    /// advertise the matching capability.
    fn read_only_bootstrap() -> Arc<dyn BootstrapProvider> {
        let mut document = BootstrapDocument::fail_closed();
        document.capabilities.quotes = true;
        document.capabilities.preview = true;
        document.capabilities.market = true;
        document.capabilities.portfolio = true;
        Arc::new(StaticBootstrap::new(document))
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
            read_only_bootstrap(),
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
    async fn cross_route_replay_does_not_consume_the_target_sequence() {
        let now = 1_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        let (state, mut client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            read_only_bootstrap(),
        );
        // A captured bootstrap envelope at sequence 0 posted to /v1/command is a
        // route mismatch...
        let captured = client
            .seal_at(0, br#"{"op":"bootstrap","request_id":"x"}"#)
            .unwrap();
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Command, &captured.to_wire_bytes())
                .await,
            Err(RelayFailure::Protocol)
        );
        // ...and the honest command at the same sequence is still accepted: the
        // replay window must not advance before route validation.
        let honest = client
            .seal_at(0, br#"{"op":"get_quote","payload":{},"request_id":"ok"}"#)
            .unwrap();
        let opened = state
            .relay_envelope(OpaqueRoute::Command, &honest.to_wire_bytes())
            .await
            .expect("honest command must not be wedged");
        let response = parse_wire_envelope(&opened).unwrap();
        assert_eq!(response.sequence, 0, "response binds the request sequence");
        let plaintext = client.open(&response).unwrap();
        let value: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(value["result"]["status"], "ok", "response: {value}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stream_subscribe_replayed_on_command_does_not_consume_the_sequence() {
        // F4 regression: a captured `/v1/stream` subscribe envelope replayed on
        // `/v1/command` must be refused *before* the replay window advances.
        // Otherwise `accept_sequence(Purpose::Command)` burns the slot and the
        // dispatcher's later ForbiddenOperation rejection cannot undo it, so an
        // observer could pre-burn a run of the honest client's command sequences
        // (one subscribe per reconnect) and wedge every write with a 503.
        let now = 1_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        let (state, mut client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            read_only_bootstrap(),
        );
        let captured = client
            .seal_at(0, br#"{"op":"subscribe","from_seq":0,"request_id":"x"}"#)
            .unwrap();
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Command, &captured.to_wire_bytes())
                .await,
            Err(RelayFailure::Protocol),
            "a stream subscribe is a route-control op, not a command"
        );
        // The honest command at the same sequence is still accepted.
        let honest = client
            .seal_at(0, br#"{"op":"get_quote","payload":{},"request_id":"ok"}"#)
            .unwrap();
        let opened = state
            .relay_envelope(OpaqueRoute::Command, &honest.to_wire_bytes())
            .await
            .expect("honest command must not be wedged");
        let response = parse_wire_envelope(&opened).unwrap();
        let plaintext = client.open(&response).unwrap();
        let value: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(value["result"]["status"], "ok", "response: {value}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the replayed subscribe never reached the dispatcher"
        );
    }

    #[tokio::test]
    async fn bootstrap_without_a_request_challenge_is_refused() {
        let now = 1_000i64;
        let (state, mut client) = state(now);
        let envelope = client
            .seal_next(br#"{"op":"bootstrap","protocol_version":1}"#)
            .unwrap();
        assert_eq!(
            state
                .relay_envelope(OpaqueRoute::Bootstrap, &envelope.to_wire_bytes())
                .await,
            Err(RelayFailure::Protocol)
        );
    }

    #[tokio::test]
    async fn mutating_command_is_denied_by_the_advertised_kill_switch() {
        let now = 1_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        // A dispatcher that would accept the write, under a fail-closed bootstrap
        // document: the advertised kill switch must win.
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
            br#"{"op":"execute_market_order","payload":{},"request_id":"kill","idempotency_key":"k"}"#,
        )
        .await
        .expect("sealed denial");
        assert_eq!(response["error"]["code"], "capability_missing");
        assert!(response.get("result").is_none(), "no false success");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "dispatcher never reached");
    }

    #[tokio::test]
    async fn an_operation_is_denied_when_its_advertised_capability_is_false() {
        // BR-1/F2: the advertised capability set is authoritative. A document
        // that enables trading but advertises `execute=false` must refuse the
        // operation server-side, otherwise a crafted client executes a trade the
        // UI renders as unavailable.
        let now = 1_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut document = BootstrapDocument::fail_closed();
        document.trading_enabled = true;
        document.kill_switch_enabled = false;
        document.kill_switch_reason = None;
        // Deliberately leave `execute` false while advertising `preview`.
        document.capabilities.preview = true;
        let (state, mut client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            Arc::new(StaticBootstrap::new(document)),
        );
        let response = roundtrip(
            &state,
            &mut client,
            OpaqueRoute::Command,
            br#"{"op":"execute_market_order","payload":{},"request_id":"cap","idempotency_key":"k"}"#,
        )
        .await
        .expect("sealed denial");
        assert_eq!(response["request_id"], "cap");
        assert_eq!(response["error"]["code"], "capability_missing");
        assert!(response.get("result").is_none(), "no false success");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unavailable capability never reaches the dispatcher"
        );
        // A capability that *is* advertised still works (at the next sequence).
        let envelope = client
            .seal_at(
                1,
                br#"{"op":"preview_market_order","payload":{},"request_id":"ok"}"#,
            )
            .unwrap();
        let opened = state
            .relay_envelope(OpaqueRoute::Command, &envelope.to_wire_bytes())
            .await
            .expect("advertised capability is served");
        let sealed = parse_wire_envelope(&opened).unwrap();
        let plaintext = client.open(&sealed).unwrap();
        let allowed: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(allowed["result"]["status"], "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unlisted_operation_is_denied_but_reconcile_reads_stay_available() {
        // The capability map is authoritative in both directions: an op that is
        // neither capability-gated nor an explicit reconciliation read must be
        // denied (a new op cannot accidentally escape the gate), while the BR-9
        // reconciliation reads stay available so an UNKNOWN write can always be
        // resolved by an authoritative read.
        let now = 1_000i64;
        let calls = Arc::new(AtomicUsize::new(0));
        let (state, mut client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            read_only_bootstrap(),
        );

        let reconcile = roundtrip(
            &state,
            &mut client,
            OpaqueRoute::Command,
            br#"{"op":"get_order_by_client_id","payload":{"client_order_id":"c1"},"request_id":"recon"}"#,
        )
        .await
        .expect("reconcile read is served");
        assert_eq!(reconcile["result"]["status"], "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // The map is default-deny: an op that is neither capability-gated nor an
        // explicit reconciliation read is refused, so a future op cannot escape
        // the gate; the reconcile reads are deliberately ungated.
        let none = CapabilitySet::none();
        assert!(!none.permits("definitely_not_a_command"));
        assert!(!none.permits("get_quote"));
        assert!(none.permits("get_order_by_client_id"));
        assert!(none.permits("get_withdrawal_by_request_id"));
        assert!(none.permits("get_execution_progress"));
        assert_eq!(CapabilitySet::for_op("definitely_not_a_command"), None);
        assert!(!CapabilitySet::is_ungated_read("definitely_not_a_command"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the reconcile read reached the dispatcher"
        );
    }

    #[tokio::test]
    async fn an_okx_router_preference_requires_the_okx_capability() {
        // BR-10: a deployment that only wires the Local router must not let its
        // advertised `preview` capability endorse an explicit OKX-routed command.
        let now = 1_000i64;

        // `preview` advertised but `okx` false: the OKX-routed preview is denied
        // before the dispatcher.
        let calls = Arc::new(AtomicUsize::new(0));
        let mut denied_doc = BootstrapDocument::fail_closed();
        denied_doc.trading_enabled = true;
        denied_doc.kill_switch_enabled = false;
        denied_doc.kill_switch_reason = None;
        denied_doc.capabilities.preview = true;
        let (denied_state, mut denied_client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            Arc::new(StaticBootstrap::new(denied_doc)),
        );
        let denied = roundtrip(
            &denied_state,
            &mut denied_client,
            OpaqueRoute::Command,
            br#"{"op":"preview_market_order","payload":{"router_preference":"okx"},"request_id":"okx"}"#,
        )
        .await
        .expect("sealed denial");
        assert_eq!(denied["error"]["code"], "capability_missing");
        assert!(denied.get("result").is_none(), "no false success");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unadvertised OKX route never reaches the dispatcher"
        );

        // With `okx` advertised the same request is served.
        let calls = Arc::new(AtomicUsize::new(0));
        let mut allowed_doc = BootstrapDocument::fail_closed();
        allowed_doc.trading_enabled = true;
        allowed_doc.kill_switch_enabled = false;
        allowed_doc.kill_switch_reason = None;
        allowed_doc.capabilities.preview = true;
        allowed_doc.capabilities.okx = true;
        let (allowed_state, mut allowed_client) = state_with(
            now,
            Arc::new(CountingDispatcher {
                calls: calls.clone(),
                result: json!({"status": "ok"}),
            }),
            Arc::new(StaticBootstrap::new(allowed_doc)),
        );
        let allowed = roundtrip(
            &allowed_state,
            &mut allowed_client,
            OpaqueRoute::Command,
            br#"{"op":"preview_market_order","payload":{"router_preference":"okx"},"request_id":"okx"}"#,
        )
        .await
        .expect("advertised OKX route is served");
        assert_eq!(allowed["result"]["status"], "ok");
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
