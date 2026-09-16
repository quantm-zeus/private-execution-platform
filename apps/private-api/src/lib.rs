//! Internal private authentication service. Not a browser-facing public API.

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use auth::passkey::PasskeyCredentialStore;
use auth::passkey::{
    AuthenticationAttempt, PasskeyRegistrationAttempt, WebAuthnPasskeyAuthenticator,
};
use auth::{
    ArtifactGrantId, AuthError, AuthState, PublicKeyCredential, RegisterPublicKeyCredential,
    SessionId, Uuid,
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

use subtle::ConstantTimeEq;

pub mod fomo_market;
mod hardened_file;
pub mod live;
pub mod opaque;
pub mod passkey_store;
pub mod production;
pub mod recovery;
pub mod release;
pub mod stream;
pub mod trading;
pub mod web_contract;
pub mod web_integration;

pub use passkey_store::FilePasskeyCredentialStore;
pub use recovery::{FileRecoveryWrapperStore, RecoveryWrapperStore};
pub use release::{
    ArtifactDescriptor, DescriptorError, EnrollmentSnapshot, ReleaseManifest, UnlockCompatibility,
    RELEASE_MANIFEST_ENV, WORKSPACE_PROTOCOL_VERSION,
};

pub use fomo_market::{
    build_wiring as build_fomo_market_wiring,
    build_wiring_with_health as build_fomo_market_wiring_with_health,
    build_wiring_with_health_flags as build_fomo_market_wiring_with_health_flags, probe_history,
    probe_realtime, Bar, BarsProvider, FomoBarsClient, FomoChartDispatcher, FomoMarketConfig,
    FomoMarketError, FomoMarketWiring, FomoOhlcvStreamSource,
};
pub use opaque::{
    AgentCommandDispatcher, BootstrapDocument, BootstrapProvider, CapabilitySet, ChainEntry,
    CommandDispatcher, FailClosedBootstrap, FailClosedDispatcher, OpaqueClock, OpaqueRoute,
    OpaqueServiceState, StaticBootstrap, SystemClock as OpaqueSystemClock,
};
pub use stream::{
    EncryptedStreamService, FailClosedStreamSource, FrameSink, SourceFrame, StreamDriver,
    StreamHub, StreamSource,
};
pub use web_contract::{FailClosedWebContract, WebContractBackend, WebContractDispatcher};
pub use web_integration::{
    FailClosedInstrumentRegistry, Instrument, InstrumentRegistry, QuoteStore,
    StaticInstrumentRegistry, WebIntegrationDispatcher, DEFAULT_QUOTE_TTL_MS,
};

// Re-exported so an embedding application can compose the private command
// surface without taking a direct dependency on the canonical vocabularies.
pub use agent_commands::{
    AgentCapabilities, AgentChannel, AgentCommand, AmountSpec, AssetRef, RouterSource, TradeCommand,
};
pub use chain_types::ChainId;
pub use mcp_server::{AgentBackend, BackendOutcome};

/// Read a small operator secret file through the hardened (non-symlink,
/// owner-only `0600`, not group/world writable) path and return its trimmed
/// contents in a zeroizing buffer.
///
/// Used for the local `fomo-mcp` bridge bearer key. The value is never logged,
/// the intermediate buffers are zeroized, and the returned buffer zeroizes on
/// drop.
pub fn read_operator_secret_file(path: &std::path::Path) -> std::io::Result<Zeroizing<String>> {
    use std::io::Read;

    let opened = hardened_file::open_hardened_secret(path)?
        .ok_or_else(|| std::io::Error::other("secret file is missing"))?;
    let mut raw = Vec::new();
    // Read at most one byte past the limit so an over-long file is rejected
    // rather than silently truncated.
    opened.file.take(4097).read_to_end(&mut raw)?;
    if raw.len() > 4096 {
        raw.zeroize();
        return Err(std::io::Error::other("secret file is too large"));
    }
    let mut text = match String::from_utf8(raw) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(std::io::Error::other("secret file must be valid UTF-8"));
        }
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        text.zeroize();
        return Err(std::io::Error::other("secret file is empty"));
    }
    let value = Zeroizing::new(trimmed.to_string());
    text.zeroize();
    Ok(value)
}

/// Compose the full private web command surface for an injected Trading Core.
///
/// The canonical `agent-commands` core is wrapped by the web response contract
/// (BR-9/BR-10/BR-12/BR-14) and then by the web intent translation + preview
/// projection + quote binding (BR-10/BR-11). The caller injects the
/// authoritative [`InstrumentRegistry`], the [`WebContractBackend`] (wallet
/// limits and reconciliation) and the [`OpaqueClock`].
///
/// This derives no capability: `capabilities` and the backend are supplied by
/// the caller, and `TRADING_ENABLED=false` still denies every mutation through
/// the shared `agent-commands` authorization core.
pub fn web_command_dispatcher(
    backend: std::sync::Arc<dyn mcp_server::AgentBackend>,
    capabilities: agent_commands::AgentCapabilities,
    web: std::sync::Arc<dyn WebContractBackend>,
    registry: std::sync::Arc<dyn InstrumentRegistry>,
    clock: std::sync::Arc<dyn OpaqueClock>,
) -> std::sync::Arc<dyn CommandDispatcher> {
    let gate = capabilities.clone();
    let canonical = std::sync::Arc::new(AgentCommandDispatcher::for_web(backend, capabilities));
    let contract = std::sync::Arc::new(WebContractDispatcher::with_capabilities(
        canonical, web, gate,
    ));
    std::sync::Arc::new(WebIntegrationDispatcher::new(contract, registry, clock))
}

pub const CHALLENGE_COOKIE_NAME: &str = "__Host-evergreen_challenge";
pub const SESSION_COOKIE_NAME: &str = "__Host-evergreen_session";
/// Single-use cookie binding an operator passkey-enrollment ceremony.
pub const REGISTRATION_COOKIE_NAME: &str = "__Host-evergreen_register";
/// Operator bootstrap header for passkey enrollment. The value is compared
/// against `PRIVATE_PASSKEY_ENROLL_SECRET` in constant time.
pub const ENROLLMENT_SECRET_HEADER: &str = "x-evergreen-enroll-secret";
/// Minimum length of the operator enrollment secret. A weak bootstrap secret is
/// a direct path to minting an attacker credential, so a short one refuses
/// startup instead of being accepted.
pub const MIN_ENROLLMENT_SECRET_LEN: usize = 32;
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

/// A pending operator passkey-enrollment ceremony. Holds only the single-use
/// WebAuthn registration challenge; never serialized, persisted or logged.
struct PendingRegistration {
    attempt: PasskeyRegistrationAttempt,
    expires_at_ms: i64,
}

/// Bounded pending-challenge budget for the whole process (P0-7).
///
/// The budget is deliberately GLOBAL, not per-request-header: private-api
/// has no trusted peer-identity seam in Phase 0. It is loopback-only and
/// reachable through the opaque edge, and the edge neither injects nor
/// attests any client identity on this path — so any header-derived
/// bucket key would be client-controlled and trivially rotated to bypass
/// a per-peer cap. A global bound closes the unbounded-pending-growth /
/// resource-exhaustion hole without inventing a new trust boundary.
/// Per-peer attribution can be layered on when a trusted identity seam
/// exists (e.g. edge-attested identity over the mTLS internal boundary).
/// Challenges are TTL-pruned on every issuance/consumption path; at this
/// many simultaneously pending challenges the endpoint answers with a
/// deterministic 429 instead of growing server memory.
const MAX_PENDING_CHALLENGES: usize = 32;

#[derive(Default)]
struct TransportState {
    pending: HashMap<TransportToken, PendingAuthentication>,
    registrations: HashMap<TransportToken, PendingRegistration>,
    sessions: HashMap<TransportToken, (SessionId, i64)>,
    grants: HashMap<TransportToken, PendingArtifactGrant>,
}
impl TransportState {
    fn prune(&mut self, now_ms: i64) {
        self.pending
            .retain(|_, pending| pending.expires_at_ms > now_ms);
        self.registrations
            .retain(|_, pending| pending.expires_at_ms > now_ms);
        self.sessions.retain(|_, (_, expires)| *expires > now_ms);
        self.grants.retain(|_, grant| grant.expires_at_ms > now_ms);
    }
}

type ArtifactLoader = Arc<dyn Fn() -> Result<Vec<u8>, StatusCode> + Send + Sync>;

/// Fully validated immutable artifact metadata, computed once at startup.
///
/// `/ready` consumes this verified state instead of a header/size-only probe:
/// the full ciphertext is read and (when a release manifest is configured) its
/// SHA-256 must equal the manifest digest, so a same-size corruption is not
/// reported ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub version: u8,
    pub kid: [u8; auth::WORKSPACE_KID_BYTES],
    pub size: u64,
    pub sha256_hex: String,
}

/// Process-wide, first-computation-wins cache of [`VerifiedArtifact`].
///
/// Clones of [`PrivateApiState`] share the cell (via `Arc`); the loader-mutating
/// test seams reset it so a later loader can never observe a stale verdict.
type VerifiedArtifactCache = Arc<tokio::sync::Mutex<Option<Result<VerifiedArtifact, StatusCode>>>>;

/// Injectable release-manifest loader. Production reads the operator-configured
/// path; tests inject a hermetic manifest instead of mutating process env.
type ManifestLoader =
    Arc<dyn Fn() -> Result<Option<ReleaseManifest>, DescriptorError> + Send + Sync>;

#[derive(Clone)]
pub struct PrivateApiState {
    config: PrivateApiConfig,
    auth: Arc<Mutex<AuthState>>,
    transport: Arc<Mutex<TransportState>>,
    authenticator: Option<Arc<WebAuthnPasskeyAuthenticator>>,
    clock: Arc<dyn Clock>,
    artifact_loader: ArtifactLoader,
    /// First-computation-wins cache of the fully verified immutable artifact.
    verified_artifact: VerifiedArtifactCache,
    /// Release-manifest loader (production reads the operator path).
    manifest_loader: ManifestLoader,
    /// Optional durable passkey-bound recovery wrapper store. `None` keeps the
    /// recovery surface closed (all recovery routes answer 503).
    recovery_store: Option<Arc<dyn RecoveryWrapperStore>>,
    /// Bounded, in-memory proof-of-possession challenges for wrapper mutation.
    recovery_challenges: Arc<Mutex<recovery::RecoveryChallengeState>>,
    /// Established browser transport sessions (BR-5 key epoch). Shared with the
    /// opaque command/bootstrap/sync service.
    sessions: Arc<Mutex<session_transport::SessionRegistry>>,
    /// Operator bootstrap secret for passkey enrollment. `None` disables the
    /// enrollment surface entirely (fail closed); the value is held only in a
    /// self-zeroizing buffer.
    enrollment_secret: Option<Arc<Zeroizing<String>>>,
    /// Whether additional credentials may be enrolled once the store is no
    /// longer empty. Defaults to `false`, so the operator secret is a one-time
    /// bootstrap capability rather than a standing credential-mint.
    allow_additional_credentials: bool,
    /// Serializes the finish half of an enrollment ceremony with the
    /// "is another credential allowed?" decision, so the one-time bootstrap
    /// policy cannot be defeated by concurrent verifies.
    enrollment_lock: Arc<Mutex<()>>,
    /// Whether the opaque relay is a required dependency of this process, and
    /// the live ready flag set once its listener is bound. Kept separate from
    /// liveness so a process with a dead relay is not reported healthy.
    relay_required: bool,
    relay_ready: Arc<AtomicBool>,
    /// Whether the opaque command dispatcher surface is available. The
    /// production binary always injects a fail-closed dispatcher before serving
    /// (a build without one refuses startup), so this defaults to ready; a
    /// composition that can lose its dispatcher clears it to fail `/ready`.
    dispatcher_ready: Arc<AtomicBool>,
    /// Whether the realtime stream source is a required dependency and whether
    /// its listener/source is currently usable. Without a composed source it is
    /// not required, so the fail-closed default does not fail readiness.
    stream_required: bool,
    stream_ready: Arc<AtomicBool>,
    /// Whether a configured FOMO market source is a required dependency and
    /// whether its chart-history proof is currently healthy. A configured
    /// source fails `/ready` until the bounded authenticated `/market/bars`
    /// probe observes it healthy, so an expired bridge session is reported
    /// truthfully rather than masked by a live process.
    fomo_required: bool,
    fomo_ready: Arc<AtomicBool>,
    /// Whether a live execution path was configured (`TRADING_CORE_LIVE=1`) and
    /// whether every concrete dependency (durable store, Base RPC, Privy HTTP
    /// signer, payload builder) was proven healthy at composition time. A
    /// configured-but-unproven live path fails `/ready` instead of reporting a
    /// half-wired dependency (for example a missing credential) as healthy.
    live_required: bool,
    live_ready: bool,
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
            verified_artifact: Arc::new(tokio::sync::Mutex::new(None)),
            manifest_loader: Arc::new(release::load_release_manifest_from_env),
            recovery_store: None,
            recovery_challenges: Arc::new(Mutex::new(recovery::RecoveryChallengeState::default())),
            sessions: Arc::new(Mutex::new(session_transport::SessionRegistry::new())),
            enrollment_secret: None,
            allow_additional_credentials: false,
            enrollment_lock: Arc::new(Mutex::new(())),
            relay_required: false,
            relay_ready: Arc::new(AtomicBool::new(false)),
            dispatcher_ready: Arc::new(AtomicBool::new(true)),
            stream_required: false,
            stream_ready: Arc::new(AtomicBool::new(true)),
            fomo_required: false,
            fomo_ready: Arc::new(AtomicBool::new(true)),
            live_required: false,
            live_ready: false,
        })
    }

    /// Production composition with a real, durable passkey credential store.
    ///
    /// This is the constructor the production binary uses when the operator has
    /// configured a credential store. `authenticator` is built from the
    /// configured RP id/origin and the injected store; `/internal/auth/challenge`
    /// becomes available as soon as the store holds at least one credential, and
    /// stays `503` while it is empty (fail closed). The enrollment surface is
    /// only reachable when `enrollment_secret` is supplied.
    pub fn production_with_passkeys(
        config: PrivateApiConfig,
        store: Arc<dyn PasskeyCredentialStore>,
        enrollment_secret: Option<Zeroizing<String>>,
        allow_additional_credentials: bool,
    ) -> Result<Self, PrivateApiError> {
        config.validate()?;
        let enrollment_secret = match enrollment_secret {
            Some(secret) if secret.is_empty() => None,
            Some(secret) if secret.len() < MIN_ENROLLMENT_SECRET_LEN => {
                return Err(PrivateApiError::InvalidConfiguration)
            }
            other => other.map(Arc::new),
        };
        let authenticator = WebAuthnPasskeyAuthenticator::new(&config.rp_id, &config.origin, store)
            .map_err(PrivateApiError::Auth)?;
        let mut state = Self::production(config)?;
        state.authenticator = Some(Arc::new(authenticator));
        state.enrollment_secret = enrollment_secret;
        state.allow_additional_credentials = allow_additional_credentials;
        Ok(state)
    }

    /// Shared encrypted-session registry (BR-5 key epoch) for the opaque relay.
    pub fn sessions(&self) -> Arc<Mutex<session_transport::SessionRegistry>> {
        self.sessions.clone()
    }

    /// Whether the operator bootstrap enrollment surface is actually open.
    ///
    /// True only when a bootstrap secret is configured *and* either additional
    /// credentials are explicitly allowed or the durable store is still empty.
    /// A store error is a fail-closed `false`, so the shell never renders
    /// bootstrap controls against a store it cannot read.
    pub fn enrollment_open(&self) -> bool {
        if self.enrollment_secret.is_none() {
            return false;
        }
        if self.allow_additional_credentials {
            return true;
        }
        match self.authenticator.as_ref() {
            Some(authenticator) => matches!(authenticator.has_credentials(), Ok(false)),
            None => false,
        }
    }

    /// Attach the opaque relay's readiness contract. `required` records that the
    /// process was configured to serve the relay; `ready` is set once the
    /// listener is actually bound, so `/ready` can fail while `/health` stays
    /// live rather than reporting a degraded process as healthy.
    pub fn with_relay_readiness(mut self, required: bool, ready: Arc<AtomicBool>) -> Self {
        self.relay_required = required;
        self.relay_ready = ready;
        self
    }

    /// Attach the opaque command dispatcher's readiness contract. The process
    /// refuses to start without a dispatcher, so the default is ready; a future
    /// composition that can lose its dispatcher clears this to fail `/ready`.
    pub fn with_dispatcher_readiness(mut self, ready: Arc<AtomicBool>) -> Self {
        self.dispatcher_ready = ready;
        self
    }

    /// Attach the realtime stream source's readiness contract. `required`
    /// records that the composition advertises `realtime` and therefore depends
    /// on a live stream; without a composed source the dependency is absent and
    /// readiness is unaffected. A composition whose stream dies clears `ready`
    /// to fail `/ready` while `/health` stays live.
    pub fn with_stream_readiness(mut self, required: bool, ready: Arc<AtomicBool>) -> Self {
        self.stream_required = required;
        self.stream_ready = ready;
        self
    }

    /// Attach the FOMO market source's readiness contract. `required` records
    /// that a FOMO source was configured (so it is a deployment dependency);
    /// `ready` is set true only after a bounded authenticated `/market/bars`
    /// history proof succeeds. A configured-but-auth-rejected source therefore
    /// fails `/ready` even while the process stays live on `/health`.
    pub fn with_fomo_readiness(mut self, required: bool, ready: Arc<AtomicBool>) -> Self {
        self.fomo_required = required;
        self.fomo_ready = ready;
        self
    }

    /// Attach the live execution path's readiness contract. `required` records
    /// that the operator explicitly opted into live composition
    /// (`TRADING_CORE_LIVE=1`); `ready` is true only when the durable store and
    /// all concrete transports (Base RPC, Privy HTTP signer, payload builder)
    /// were proven healthy. A configured-but-unproven live path therefore fails
    /// `/ready` — a missing credential is a determinate readiness denial, never a
    /// healthy process with a half-wired execution dependency.
    pub fn with_live_readiness(mut self, required: bool, ready: bool) -> Self {
        self.live_required = required;
        self.live_ready = ready;
        self
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
            verified_artifact: Arc::new(tokio::sync::Mutex::new(None)),
            manifest_loader: Arc::new(release::load_release_manifest_from_env),
            recovery_store: None,
            recovery_challenges: Arc::new(Mutex::new(recovery::RecoveryChallengeState::default())),
            sessions: Arc::new(Mutex::new(session_transport::SessionRegistry::new())),
            enrollment_secret: None,
            allow_additional_credentials: false,
            enrollment_lock: Arc::new(Mutex::new(())),
            relay_required: false,
            relay_ready: Arc::new(AtomicBool::new(false)),
            dispatcher_ready: Arc::new(AtomicBool::new(true)),
            stream_required: false,
            stream_ready: Arc::new(AtomicBool::new(true)),
            fomo_required: false,
            fomo_ready: Arc::new(AtomicBool::new(true)),
            live_required: false,
            live_ready: false,
        })
    }

    /// Load the configured workspace artifact off the async runtime.
    ///
    /// The loader performs synchronous file I/O and the artifact can be large,
    /// so it runs on the blocking pool. A join failure (for example a panicking
    /// loader) is a fail-closed `503`, never an unwrapped panic on the worker.
    async fn load_artifact(&self) -> Result<Vec<u8>, StatusCode> {
        let loader = self.artifact_loader.clone();
        tokio::task::spawn_blocking(move || loader())
            .await
            .unwrap_or(Err(StatusCode::SERVICE_UNAVAILABLE))
    }

    /// Load the optional release manifest off the async runtime.
    async fn load_manifest(&self) -> Result<Option<ReleaseManifest>, DescriptorError> {
        let loader = self.manifest_loader.clone();
        tokio::task::spawn_blocking(move || loader())
            .await
            .unwrap_or(Err(DescriptorError::ManifestInvalid))
    }

    /// Return the fully verified immutable artifact, computing it once.
    ///
    /// The first caller reads the whole bounded ciphertext, validates it against
    /// the configured release manifest (including the full SHA-256 digest), and
    /// caches the verdict for the process. `/ready` therefore consumes verified
    /// state, so a same-size corruption that keeps the header and length intact
    /// is not reported ready.
    async fn verified_artifact(&self) -> Result<VerifiedArtifact, StatusCode> {
        let mut guard = self.verified_artifact.lock().await;
        if let Some(cached) = guard.as_ref() {
            return cached.clone();
        }
        let verdict = self.compute_verified_artifact().await;
        *guard = Some(verdict.clone());
        verdict
    }

    /// Reads, validates, and digests the immutable artifact exactly once.
    async fn compute_verified_artifact(&self) -> Result<VerifiedArtifact, StatusCode> {
        let manifest = self
            .load_manifest()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let artifact = self.load_artifact().await?;
        let header = release::parse_artifact_header(&artifact)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Some(manifest) = manifest.as_ref() {
            // Full byte-level validation: version, KID, exact size, and the
            // SHA-256 digest. A same-size corruption therefore fails here.
            manifest
                .validate_against(&artifact)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        Ok(VerifiedArtifact {
            version: header.version,
            kid: header.kid,
            size: artifact.len() as u64,
            sha256_hex: release::sha256_hex(&artifact),
        })
    }

    /// Eagerly validate and cache the immutable artifact during startup.
    ///
    /// Best-effort: a failure is cached and surfaced by `/ready` (never a
    /// startup abort), so an operator can see the precise readiness verdict.
    pub async fn warm_artifact_readiness(&self) {
        let _ = self.verified_artifact().await;
    }

    /// Attach an optional durable recovery wrapper store. Additive: without it
    /// the recovery surface stays closed and the offline recovery code is the
    /// only credential.
    pub fn with_recovery_store(mut self, store: Arc<dyn RecoveryWrapperStore>) -> Self {
        self.recovery_store = Some(store);
        self
    }

    /// Whether passkey recovery enrollment/management is configured.
    pub fn recovery_enabled(&self) -> bool {
        self.recovery_store.is_some()
    }

    #[cfg(test)]
    fn with_artifact_loader(mut self, loader: ArtifactLoader) -> Self {
        self.artifact_loader = loader;
        // A new loader invalidates any verdict computed from the previous one.
        self.verified_artifact = Arc::new(tokio::sync::Mutex::new(None));
        self
    }

    #[cfg(test)]
    fn with_manifest_loader(mut self, loader: ManifestLoader) -> Self {
        self.manifest_loader = loader;
        self.verified_artifact = Arc::new(tokio::sync::Mutex::new(None));
        self
    }
}

pub fn router(state: PrivateApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/internal/auth/challenge", post(issue_challenge))
        .route("/internal/auth/enrollment-status", get(enrollment_status))
        .route("/internal/auth/verify", post(verify_challenge))
        .route("/internal/auth/session", get(validate_session))
        .route(
            "/internal/auth/register/challenge",
            post(issue_registration_challenge),
        )
        .route("/internal/auth/register/verify", post(verify_registration))
        .route(
            "/internal/auth/enroll",
            post(enroll_workspace_key).get(get_workspace_enrollment_handler),
        )
        .route(
            "/internal/workspace/enroll",
            post(enroll_workspace_key).get(get_workspace_enrollment_handler),
        )
        .route(
            "/internal/workspace/descriptor",
            get(get_workspace_descriptor_handler),
        )
        .route(
            "/internal/workspace/recovery",
            get(list_recovery_wrappers).post(add_recovery_wrapper),
        )
        .route(
            "/internal/workspace/recovery/challenge",
            post(issue_recovery_challenge),
        )
        .route(
            "/internal/workspace/recovery/revoke",
            post(revoke_recovery_wrapper),
        )
        .route(
            "/internal/workspace/recovery/touch",
            post(touch_recovery_wrapper),
        )
        .route(
            "/internal/workspace/identity",
            get(get_workspace_identity).post(bootstrap_workspace_identity),
        )
        .route("/internal/artifact/grant", post(issue_artifact_grant))
        .route("/internal/artifact", post(deliver_artifact))
        .layer(DefaultBodyLimit::max(
            MAX_ASSERTION_BYTES
                .max(MAX_OFFER_BYTES)
                .max(MAX_ENROLLMENT_BYTES)
                .max(MAX_WORKSPACE_BOOTSTRAP_BYTES),
        ))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

/// Dependency readiness, distinct from liveness. A process that is running but
/// whose required opaque relay never bound, whose artifact/release manifest is
/// unreadable or incompatible, or whose passkey store cannot be read is NOT
/// ready. Reports a generic per-dependency boolean map and nothing else.
async fn readiness(State(state): State<PrivateApiState>) -> Response {
    let relay_ok = if state.relay_required {
        state.relay_ready.load(Ordering::SeqCst)
    } else {
        true
    };
    // Consume the fully verified immutable artifact computed once at startup:
    // the whole ciphertext was read and, when a release manifest is configured,
    // its SHA-256 digest was validated. The unauthenticated probe therefore
    // cannot report ready for a same-size-corrupted artifact that keeps the
    // header and length intact.
    //
    // `manifest_configured` is reported separately: without an immutable release
    // manifest the preflight enforces only version/KID and cannot compare the
    // recipient fingerprint, so operators can see that weaker (still
    // fail-closed) mode from the readiness response.
    let manifest_result = state.load_manifest().await;
    let manifest_configured = !matches!(&manifest_result, Ok(None));
    let (artifact_ok, manifest_ok) = match state.verified_artifact().await {
        Ok(_) => (true, true),
        // A verified-artifact failure means the artifact/immutable binding is
        // unusable; the manifest check is only healthy in the explicit
        // no-manifest mode.
        Err(_) => (false, matches!(manifest_result, Ok(None))),
    };
    // A configured passkey store that cannot be read is not ready; an absent
    // authenticator in production means every auth route is 503, so it is also
    // not ready rather than a false-positive healthy dependency.
    let passkey_store_ok = match state.authenticator.as_ref() {
        Some(authenticator) => authenticator.has_credentials().is_ok(),
        None => false,
    };
    // Recovery wrappers are optional: when the store is configured it must be
    // readable, otherwise it is not a dependency.
    let recovery_ok = match state.recovery_store.as_ref() {
        Some(store) => store.list().is_ok(),
        None => true,
    };
    // The opaque command dispatcher is a required dependency. The binary always
    // wires one before serving (startup refuses otherwise); a composition that
    // clears this flag must not be reported ready.
    let dispatcher_ok = state.dispatcher_ready.load(Ordering::SeqCst);
    // The realtime stream is a dependency only when the composition advertises
    // `realtime`; an unadvertised, absent source does not fail readiness.
    let stream_ok = if state.stream_required {
        state.stream_ready.load(Ordering::SeqCst)
    } else {
        true
    };
    // A configured FOMO market source is a dependency even when its startup
    // probe failed (for example an expired bridge session): readiness is only
    // true once the bounded authenticated history proof observed it healthy.
    let fomo_ok = if state.fomo_required {
        state.fomo_ready.load(Ordering::SeqCst)
    } else {
        true
    };
    // A configured live execution path is a dependency even when a concrete
    // transport or credential could not be proven: `/ready` fails rather than
    // reporting a half-wired execution dependency as healthy. Without the
    // explicit live opt-in the dependency is absent and readiness is unaffected.
    let live_ok = if state.live_required {
        state.live_ready
    } else {
        true
    };
    let ready = relay_ok
        && artifact_ok
        && manifest_ok
        && dispatcher_ok
        && stream_ok
        && fomo_ok
        && live_ok
        && passkey_store_ok
        && recovery_ok;
    let body = serde_json::json!({
        "ready": ready,
        "manifest_configured": manifest_configured,
        "checks": {
            "relay": relay_ok,
            "artifact": artifact_ok,
            "release_manifest": manifest_ok,
            "dispatcher": dispatcher_ok,
            "stream": stream_ok,
            "fomo_market": fomo_ok,
            "live_execution": live_ok,
            "passkey_store": passkey_store_ok,
            "recovery_store": recovery_ok,
        }
    })
    .to_string();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    no_store((status, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
}

/// Unauthenticated, non-secret bootstrap probe: tells the clear shell whether
/// first-run passkey enrollment is actually open, so it can hide bootstrap
/// controls instead of inviting a dead ceremony. It exposes a single boolean
/// and nothing about the credential store's contents.
async fn enrollment_status(State(state): State<PrivateApiState>) -> Response {
    let body = serde_json::json!({ "enrollment_open": state.enrollment_open() }).to_string();
    no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
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
        // Global pending budget: deterministic 429 once the process holds
        // MAX_PENDING_CHALLENGES live challenges. The budget key is never
        // derived from request data (no client-controllable header can
        // select or rotate a bucket). The challenge generated above is
        // discarded; the refused request consumed no budget.
        if transport.pending.len() >= MAX_PENDING_CHALLENGES {
            return too_many_requests();
        }
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
        // Consumption removes the pending record immediately, whether the
        // attempt then verifies or not, freeing its budget slot.
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
        // Taxonomy (P0-8): credential-store unavailability AFTER successful
        // WebAuthn crypto is a backend condition (503), while crypto/verify
        // failure is an ordinary auth failure (401). Both clear the
        // consumed challenge: the pending attempt was already removed from
        // the transport map above, so the challenge is single-use either way.
        Err(AuthError::VerifierUnavailable) => {
            return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(_) => return clear_challenge(generic_error(StatusCode::UNAUTHORIZED)),
    };
    // Step-up verification: the caller already holds a live authenticated
    // session, so this ceremony confirms one more passkey rather than logging
    // in. Minting a new session here would silently replace the caller's
    // session — and with it the workspace enrollment bound to it — so a
    // subsequent recovery/artifact call would fail `enrollment_required`
    // against a session the browser never had a chance to enroll. Keep the
    // existing session and return its expiry; `PEP`'s single-owner model means
    // the credential has still been verified by this ceremony.
    if let Ok(Some(value)) = cookie_value(&headers, SESSION_COOKIE_NAME) {
        let token = TransportToken(value.to_string());
        let live = {
            let mut transport = match state.transport.lock() {
                Ok(v) => v,
                Err(_) => return clear_challenge(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
            };
            transport.prune(now);
            match transport.sessions.get(&token) {
                Some((_, expires_at_ms)) if *expires_at_ms > now => Some(*expires_at_ms),
                _ => None,
            }
        };
        if live.is_some() {
            let mut response = no_store(StatusCode::NO_CONTENT.into_response());
            if append_challenge_clear(&mut response).is_err() {
                // A response that cannot clear the consumed challenge could let
                // it be replayed against the pending attempt, so fail closed.
                return generic_error(StatusCode::SERVICE_UNAVAILABLE);
            }
            return response;
        }
    }
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

/// Bounded pending enrollment-ceremony budget. Enrollment is operator-gated, so
/// this only bounds resource use if the bootstrap secret leaks; it is small and
/// pruned by the challenge TTL.
const MAX_PENDING_REGISTRATIONS: usize = 8;

/// Resolve whether the request carries the configured operator enrollment
/// secret. Returns `None` when enrollment is disabled (no secret configured),
/// `Some(true)`/`Some(false)` otherwise. The comparison is constant time so a
/// timing side channel cannot recover the secret byte by byte.
fn enrollment_secret_matches(state: &PrivateApiState, headers: &HeaderMap) -> Option<bool> {
    let secret = state.enrollment_secret.as_ref()?;
    let presented = headers
        .get(ENROLLMENT_SECRET_HEADER)
        .and_then(|value| value.to_str().ok());
    match presented {
        Some(presented) => Some(presented.as_bytes().ct_eq(secret.as_bytes()).into()),
        None => Some(false),
    }
}

/// Whether the enrollment surface may currently mint another credential.
///
/// A store failure is a backend condition (`Err`), not a policy conflict, so
/// callers can answer `503` rather than `409`.
fn enrollment_open(
    state: &PrivateApiState,
    authenticator: &WebAuthnPasskeyAuthenticator,
) -> Result<bool, AuthError> {
    match authenticator.has_credentials()? {
        false => Ok(true),
        true => Ok(state.allow_additional_credentials),
    }
}

fn registration_cookie(token: &str, ttl_ms: i64) -> String {
    secure_cookie(REGISTRATION_COOKIE_NAME, token, max_age_seconds(ttl_ms))
}

fn clear_registration(mut response: Response) -> Response {
    let _ = append_cookie(&mut response, expired_cookie(REGISTRATION_COOKIE_NAME));
    no_store(response)
}

/// Begin an operator passkey-enrollment ceremony (bootstrap path).
///
/// This endpoint is the *only* way a production credential store becomes
/// non-empty. It is disabled unless `PRIVATE_PASSKEY_ENROLL_SECRET` is
/// configured, requires the matching header, and — unless the operator opted in
/// with `PRIVATE_PASSKEY_ALLOW_ADDITIONAL=true` — refuses once a credential
/// exists, so the secret is a one-time bootstrap capability.
async fn issue_registration_challenge(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let Some(matches) = enrollment_secret_matches(&state, &headers) else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !matches {
        return generic_error(StatusCode::UNAUTHORIZED);
    }
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let authenticator = match state.authenticator.as_ref() {
        Some(v) => v.clone(),
        None => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    match enrollment_open(&state, &authenticator) {
        Ok(true) => {}
        Ok(false) => return generic_error(StatusCode::CONFLICT),
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    }
    let (options, attempt) =
        match authenticator.start_registration(Uuid::new_v4(), "owner", "Owner") {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
    let token = match random_transport_token() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let cookie = registration_cookie(token.as_str(), state.config.challenge_ttl_ms);
    {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        if transport.registrations.len() >= MAX_PENDING_REGISTRATIONS {
            return too_many_requests();
        }
        transport.registrations.insert(
            token,
            PendingRegistration {
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

/// Finish an operator passkey-enrollment ceremony and durably register the
/// credential. The stored record is public WebAuthn material only; the response
/// deliberately returns no credential id.
async fn verify_registration(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(matches) = enrollment_secret_matches(&state, &headers) else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !matches {
        return generic_error(StatusCode::UNAUTHORIZED);
    }
    if content_type(&headers) != Some(CONTENT_TYPE) {
        return generic_error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let authenticator = match state.authenticator.as_ref() {
        Some(v) => v.clone(),
        None => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let challenge_token = match cookie_value(&headers, REGISTRATION_COOKIE_NAME) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return clear_registration(generic_error(StatusCode::UNAUTHORIZED)),
    };
    let body_bytes = match to_bytes(body, MAX_ASSERTION_BYTES).await {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let credential: RegisterPublicKeyCredential = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return clear_registration(generic_error(StatusCode::BAD_REQUEST)),
    };
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    // Hold the enrollment lock across the policy re-check and the durable
    // registration (no `.await` inside) so N concurrent verifies of challenges
    // minted while the store was empty cannot all pass the emptiness check and
    // enroll N credentials under a one-time bootstrap policy.
    let _enrollment_guard = match state.enrollment_lock.lock() {
        Ok(guard) => guard,
        Err(_) => return clear_registration(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    match enrollment_open(&state, &authenticator) {
        Ok(true) => {}
        Ok(false) => return clear_registration(generic_error(StatusCode::CONFLICT)),
        Err(_) => return clear_registration(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    }
    let pending = {
        let mut transport = match state.transport.lock() {
            Ok(v) => v,
            Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        transport.prune(now);
        transport.registrations.remove(challenge_token)
    };
    let Some(pending) = pending else {
        return clear_registration(generic_error(StatusCode::UNAUTHORIZED));
    };
    if pending.expires_at_ms <= now {
        return clear_registration(generic_error(StatusCode::UNAUTHORIZED));
    }
    match authenticator.finish_registration(pending.attempt, &credential) {
        Ok(_) => {
            let mut response = no_store(StatusCode::NO_CONTENT.into_response());
            if append_cookie(&mut response, expired_cookie(REGISTRATION_COOKIE_NAME)).is_err() {
                return generic_error(StatusCode::SERVICE_UNAVAILABLE);
            }
            response
        }
        Err(AuthError::CredentialConflict) => {
            clear_registration(generic_error(StatusCode::CONFLICT))
        }
        Err(AuthError::VerifierUnavailable | AuthError::EntropyUnavailable) => {
            clear_registration(generic_error(StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(_) => clear_registration(generic_error(StatusCode::UNAUTHORIZED)),
    }
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

const MAX_ENROLLMENT_BYTES: usize = 4096;

#[derive(serde::Deserialize)]
struct WorkspaceEnrollmentRequest {
    version: u8,
    kid: String,
    #[serde(alias = "workspace_public_key")]
    public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WorkspaceEnrollmentResponse {
    enrolled: bool,
    version: u8,
    kid: String,
    public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WorkspaceEnrollmentDetailsResponse {
    version: u8,
    kid: String,
    public_key: String,
    enrolled_at_ms: i64,
}

async fn enroll_workspace_key(
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
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let body_bytes = match to_bytes(body, MAX_ENROLLMENT_BYTES).await {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: WorkspaceEnrollmentRequest = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    if request.version != auth::ARTIFACT_VERSION {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let kid_bytes = match base64_decode_canonical(&request.kid, auth::WORKSPACE_KID_BYTES) {
        Some(v) => v,
        None => return generic_error(StatusCode::BAD_REQUEST),
    };
    if kid_bytes.iter().all(|&b| b == 0) {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let pk_bytes =
        match base64_decode_canonical(&request.public_key, auth::WORKSPACE_PUBLIC_KEY_BYTES) {
            Some(v) => v,
            None => return generic_error(StatusCode::BAD_REQUEST),
        };
    if pk_bytes.iter().all(|&b| b == 0) {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let mut kid_arr = [0u8; auth::WORKSPACE_KID_BYTES];
    kid_arr.copy_from_slice(&kid_bytes);
    let mut pk_arr = [0u8; auth::WORKSPACE_PUBLIC_KEY_BYTES];
    pk_arr.copy_from_slice(&pk_bytes);

    let mut auth = match state.auth.lock() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    match auth.enroll_workspace_public_key(&session_id, request.version, kid_arr, pk_arr, now) {
        Ok(metadata) => {
            let response = WorkspaceEnrollmentResponse {
                enrolled: true,
                version: metadata.version(),
                kid: base64_encode(metadata.kid()),
                public_key: base64_encode(metadata.public_key()),
            };
            let body = match serde_json::to_vec(&response) {
                Ok(v) => v,
                Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
            };
            no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
        }
        Err(AuthError::EnrollmentConflict) => generic_error(StatusCode::CONFLICT),
        Err(AuthError::SessionNotFound | AuthError::SessionExpired) => {
            clear_session(generic_error(StatusCode::UNAUTHORIZED))
        }
        Err(AuthError::UnsupportedVersion | AuthError::InvalidInput) => {
            generic_error(StatusCode::BAD_REQUEST)
        }
        Err(AuthError::VerifierUnavailable | AuthError::EntropyUnavailable) => {
            generic_error(StatusCode::SERVICE_UNAVAILABLE)
        }
        Err(_) => generic_error(StatusCode::UNAUTHORIZED),
    }
}

async fn get_workspace_enrollment_handler(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let auth = match state.auth.lock() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    match auth.get_workspace_enrollment(&session_id, now) {
        Ok(metadata) => {
            let response = WorkspaceEnrollmentDetailsResponse {
                version: metadata.version(),
                kid: base64_encode(metadata.kid()),
                public_key: base64_encode(metadata.public_key()),
                enrolled_at_ms: metadata.enrolled_at_ms(),
            };
            let body = match serde_json::to_vec(&response) {
                Ok(v) => v,
                Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
            };
            no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
        }
        Err(AuthError::EnrollmentNotFound) => generic_error(StatusCode::NOT_FOUND),
        Err(AuthError::SessionNotFound | AuthError::SessionExpired) => {
            clear_session(generic_error(StatusCode::UNAUTHORIZED))
        }
        Err(_) => generic_error(StatusCode::UNAUTHORIZED),
    }
}

/// Result of looking up the session's workspace enrollment. Kept distinct from
/// "not enrolled" so an internal/auth failure is never reported as a policy
/// state the client could retry by re-entering a code.
enum EnrollmentLookup {
    Enrolled(EnrollmentSnapshot),
    NotEnrolled,
    Unavailable,
}

/// Owned snapshot of the session's workspace enrollment. The auth lock is
/// released before the caller does any artifact I/O.
fn enrollment_snapshot(
    state: &PrivateApiState,
    session_id: &SessionId,
    now: i64,
) -> EnrollmentLookup {
    let Ok(auth) = state.auth.lock() else {
        return EnrollmentLookup::Unavailable;
    };
    match auth.get_workspace_enrollment(session_id, now) {
        Ok(metadata) => EnrollmentLookup::Enrolled(EnrollmentSnapshot {
            version: metadata.version(),
            kid: *metadata.kid(),
            public_key: *metadata.public_key(),
        }),
        Err(AuthError::EnrollmentNotFound) => EnrollmentLookup::NotEnrolled,
        Err(_) => EnrollmentLookup::Unavailable,
    }
}

/// Privacy-safe typed error: a generic machine code the shell can map to a
/// recovery stage, with no exception text, path, key, ciphertext, or secret.
fn typed_error(status: StatusCode, code: &'static str) -> Response {
    no_store(
        (
            status,
            [(header::CONTENT_TYPE, CONTENT_TYPE)],
            serde_json::json!({ "code": code }).to_string(),
        )
            .into_response(),
    )
}

/// Authenticated artifact/release descriptor. Exposes only public metadata:
/// artifact version, KID, release id, digests, expected recipient public-key
/// fingerprint, and protocol compatibility. The shell uses the KID to derive
/// the workspace key automatically, so a normal user never types a KID.
async fn get_workspace_descriptor_handler(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let artifact = match state.load_artifact().await {
        Ok(artifact) => artifact,
        Err(status) => return generic_error(status),
    };
    let manifest = match state.load_manifest().await {
        Ok(manifest) => manifest,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let descriptor = match release::describe(&artifact, manifest.as_ref()) {
        Ok(descriptor) => descriptor,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let enrollment = match enrollment_snapshot(&state, &session_id, now) {
        EnrollmentLookup::Enrolled(snapshot) => Some(snapshot),
        EnrollmentLookup::NotEnrolled => None,
        EnrollmentLookup::Unavailable => {
            return clear_session(generic_error(StatusCode::UNAUTHORIZED));
        }
    };
    let descriptor = descriptor.with_enrollment(enrollment.as_ref());
    let body = match serde_json::to_vec(&descriptor) {
        Ok(body) => body,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
}

const RECOVERY_WRAPPER_REQUEST_BYTES: usize = 8192;
/// Upper bound on a workspace identity bootstrap: a public key plus up to
/// `MAX_RECOVERY_WRAPPERS` opaque wrappers.
const MAX_WORKSPACE_BOOTSTRAP_BYTES: usize = 128 * 1024;

#[derive(serde::Serialize)]
struct RecoveryChallengeResponse {
    challenge_id: String,
    sealed_challenge_b64: String,
    expires_in_ms: i64,
}

#[derive(serde::Deserialize)]
struct RecoveryWrapperUpsertRequest {
    challenge_id: String,
    proof_b64: String,
    wrapper: recovery::RecoveryWrapperInput,
}

#[derive(serde::Deserialize)]
struct RecoveryRevokeRequest {
    challenge_id: String,
    proof_b64: String,
    credential_id_b64: String,
}

#[derive(serde::Deserialize)]
struct RecoveryTouchRequest {
    challenge_id: String,
    proof_b64: String,
    credential_id_b64: String,
}

#[derive(serde::Serialize)]
struct RecoveryWrapperListResponse {
    wrappers: Vec<recovery::RecoveryWrapperRecord>,
}

/// Public workspace identity. Contains no secret material: only the stable
/// public key and its fingerprint (server-computed).
#[derive(serde::Serialize)]
struct WorkspaceIdentityResponse {
    configured: bool,
    version: Option<u8>,
    public_key_b64: Option<String>,
    fingerprint_b64: Option<String>,
}

impl WorkspaceIdentityResponse {
    fn unconfigured() -> Self {
        Self {
            configured: false,
            version: None,
            public_key_b64: None,
            fingerprint_b64: None,
        }
    }

    fn configured(identity: &recovery::WorkspaceIdentityRecord) -> Self {
        Self {
            configured: true,
            version: Some(identity.version),
            public_key_b64: Some(identity.public_key_b64.clone()),
            fingerprint_b64: Some(identity.fingerprint_b64.clone()),
        }
    }
}

/// One-time initial workspace setup. The browser generates the Workspace Root
/// Secret locally, derives the stable public key, wraps the root under a
/// passkey-PRF wrapper and an offline-recovery wrapper, and uploads only the
/// public key plus the opaque wrappers here. No secret field exists, and
/// `deny_unknown_fields` rejects a client that tries to add one.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceBootstrapRequest {
    version: u8,
    public_key: String,
    wrappers: Vec<recovery::RecoveryWrapperInput>,
}

/// Consume a single-use proof-of-possession challenge and compare the returned
/// nonce in constant time. Always consumes the challenge, success or failure.
fn consume_recovery_proof(
    state: &PrivateApiState,
    now_ms: i64,
    session_id: &SessionId,
    challenge_id: &str,
    proof_b64: &str,
) -> bool {
    let expected = match state.recovery_challenges.lock() {
        Ok(mut challenges) => challenges.consume(now_ms, challenge_id, session_id),
        Err(_) => return false,
    };
    let Some(expected) = expected else {
        return false;
    };
    let Some(proof) = release::decode_canonical_b64(proof_b64, recovery::RECOVERY_CHALLENGE_BYTES)
    else {
        return false;
    };
    recovery::proof_matches(&proof, &expected)
}

/// Validate a client-supplied credential id (canonical base64, bounded).
fn decode_recovery_credential_id(input: &str) -> Option<String> {
    let bytes = release::decode_canonical_b64_variable(input)?;
    if bytes.is_empty() || bytes.len() > recovery::MAX_CREDENTIAL_ID_BYTES {
        return None;
    }
    Some(base64_encode(&bytes))
}

/// Prove possession of the workspace key, then return a single-use challenge
/// sealed to the enrolled workspace public key.
///
/// This is the authorization gate for adding or revoking a recovery wrapper: a
/// caller must already hold an existing trusted recovery factor (the workspace
/// key derivable from the offline recovery code or a previously wrapped
/// passkey). A bare authenticated session is not sufficient. The server learns
/// nothing about the secret and never validates a guess at it.
async fn issue_recovery_challenge(
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
    if state.recovery_store.is_none() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    // The durable public workspace identity is the trust anchor for recovery
    // mutation. It is created exactly once at bootstrap and never changes, so a
    // caller can only self-approve a wrapper when they already hold the
    // workspace root (and therefore the private key the server seals to here).
    // This is deliberately independent of any release id/KID.
    let identity = match store.identity() {
        Ok(Some(identity)) => identity,
        Ok(None) => return typed_error(StatusCode::CONFLICT, "workspace_identity_required"),
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(public_key) = identity.public_key_bytes() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut nonce = [0u8; recovery::RECOVERY_CHALLENGE_BYTES];
    if getrandom::getrandom(&mut nonce).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let sealed = match crypto_envelope::seal_artifact(
        &crypto_envelope::hpke::HpkePublicKey(public_key),
        crypto_envelope::ARTIFACT_VERSION,
        &recovery::WORKSPACE_ROOT_CONTEXT_KID,
        &nonce,
    ) {
        Ok(sealed) => sealed,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut challenge_id_bytes = [0u8; recovery::RECOVERY_CHALLENGE_ID_BYTES];
    if getrandom::getrandom(&mut challenge_id_bytes).is_err() {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    }
    let challenge_id = hex_encode(&challenge_id_bytes);
    let issued = match state.recovery_challenges.lock() {
        Ok(mut challenges) => {
            challenges.issue(now, session_id, challenge_id.clone(), nonce.to_vec())
        }
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    if issued.is_err() {
        return generic_error(StatusCode::TOO_MANY_REQUESTS);
    }
    let body = match serde_json::to_vec(&RecoveryChallengeResponse {
        challenge_id,
        sealed_challenge_b64: base64_encode(&sealed),
        expires_in_ms: recovery::RECOVERY_CHALLENGE_TTL_MS,
    }) {
        Ok(body) => body,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
}

/// List the stored recovery wrappers (public metadata plus opaque ciphertext).
/// Read-only and non-destructive, so it only requires an authenticated session.
async fn list_recovery_wrappers(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(_session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let wrappers = match store.list() {
        Ok(wrappers) => wrappers,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let body = match serde_json::to_vec(&RecoveryWrapperListResponse { wrappers }) {
        Ok(body) => body,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
}

/// Add or replace a recovery wrapper. Requires a valid proof-of-possession
/// challenge (an existing trusted recovery factor).
async fn add_recovery_wrapper(
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
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let body_bytes = match to_bytes(body, RECOVERY_WRAPPER_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: RecoveryWrapperUpsertRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    let record = match request.wrapper.into_record(now) {
        Ok(record) => record,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    if !consume_recovery_proof(
        &state,
        now,
        &session_id,
        &request.challenge_id,
        &request.proof_b64,
    ) {
        return generic_error(StatusCode::UNAUTHORIZED);
    }
    match store.upsert(record) {
        Ok(()) => no_store(StatusCode::NO_CONTENT.into_response()),
        Err(AuthError::CredentialConflict) => generic_error(StatusCode::CONFLICT),
        Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Soft-revoke a recovery wrapper. Requires the same proof-of-possession as
/// adding one, so a bare session cannot destroy a trusted credential.
async fn revoke_recovery_wrapper(
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
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let body_bytes = match to_bytes(body, RECOVERY_WRAPPER_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: RecoveryRevokeRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    let Some(credential_id) = decode_recovery_credential_id(&request.credential_id_b64) else {
        return generic_error(StatusCode::BAD_REQUEST);
    };
    if !consume_recovery_proof(
        &state,
        now,
        &session_id,
        &request.challenge_id,
        &request.proof_b64,
    ) {
        return generic_error(StatusCode::UNAUTHORIZED);
    }
    match store.revoke(&credential_id, now) {
        Ok(true) => no_store(StatusCode::NO_CONTENT.into_response()),
        Ok(false) => generic_error(StatusCode::NOT_FOUND),
        Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Record a coarse last-used timestamp for a wrapper that was just used to
/// unwrap. Like add/revoke this requires proof of possession: an unproven
/// caller must not be able to forge the device audit signal or force a
/// persisted store write on demand.
async fn touch_recovery_wrapper(
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
    let Some(session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let body_bytes = match to_bytes(body, RECOVERY_WRAPPER_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: RecoveryTouchRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    let Some(credential_id) = decode_recovery_credential_id(&request.credential_id_b64) else {
        return generic_error(StatusCode::BAD_REQUEST);
    };
    if !consume_recovery_proof(
        &state,
        now,
        &session_id,
        &request.challenge_id,
        &request.proof_b64,
    ) {
        return generic_error(StatusCode::UNAUTHORIZED);
    }
    match store.touch(&credential_id, now) {
        Ok(()) => no_store(StatusCode::NO_CONTENT.into_response()),
        Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Return the durable public workspace identity, if configured. Public metadata
/// only. Any authenticated session may read it so a new device can validate the
/// root it just unwrapped before trusting it.
async fn get_workspace_identity(
    State(state): State<PrivateApiState>,
    headers: HeaderMap,
) -> Response {
    let now = match state.clock.now_ms() {
        Ok(v) => v,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(_session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let identity = match store.identity() {
        Ok(identity) => identity,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    let response = match &identity {
        Some(identity) => WorkspaceIdentityResponse::configured(identity),
        None => WorkspaceIdentityResponse::unconfigured(),
    };
    let body = match serde_json::to_vec(&response) {
        Ok(body) => body,
        Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
    };
    no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
}

/// One-time initial workspace setup. The browser generates the Workspace Root
/// Secret locally and uploads only the derived public key plus the opaque
/// passkey-PRF and offline-recovery wrappers. Create-once: a second bootstrap is
/// refused, so the workspace identity can never be replaced or rotated here.
async fn bootstrap_workspace_identity(
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
    let Some(_session_id) = session_id_from_headers(&state, &headers, now) else {
        return clear_session(generic_error(StatusCode::UNAUTHORIZED));
    };
    let Some(store) = state.recovery_store.as_ref() else {
        return generic_error(StatusCode::SERVICE_UNAVAILABLE);
    };
    let body_bytes = match to_bytes(body, MAX_WORKSPACE_BOOTSTRAP_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return generic_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request: WorkspaceBootstrapRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => return generic_error(StatusCode::BAD_REQUEST),
    };
    if request.version != recovery::WORKSPACE_IDENTITY_VERSION {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let identity =
        match recovery::WorkspaceIdentityRecord::from_public_key(&request.public_key, now) {
            Ok(identity) => identity,
            Err(_) => return generic_error(StatusCode::BAD_REQUEST),
        };
    if request.wrappers.is_empty() || request.wrappers.len() > recovery::MAX_RECOVERY_WRAPPERS {
        return generic_error(StatusCode::BAD_REQUEST);
    }
    let mut wrappers = Vec::with_capacity(request.wrappers.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for input in request.wrappers {
        let record = match input.into_record(now) {
            Ok(record) => record,
            Err(_) => return generic_error(StatusCode::BAD_REQUEST),
        };
        // Bootstrap creates the stable identity; every initial wrapper must be
        // the stable `workspace_root_v2` source. Legacy wrappers are bounded
        // migration records, never part of a new workspace root.
        if record.key_source != recovery::RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2
            || !seen.insert(record.credential_id_b64.clone())
        {
            return generic_error(StatusCode::BAD_REQUEST);
        }
        wrappers.push(record);
    }
    match store.bootstrap_identity(identity.clone(), wrappers) {
        Ok(()) => {
            let response = WorkspaceIdentityResponse::configured(&identity);
            let body = match serde_json::to_vec(&response) {
                Ok(body) => body,
                Err(_) => return generic_error(StatusCode::SERVICE_UNAVAILABLE),
            };
            no_store((StatusCode::OK, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response())
        }
        Err(AuthError::CredentialConflict) => {
            typed_error(StatusCode::CONFLICT, "workspace_identity_configured")
        }
        Err(_) => generic_error(StatusCode::SERVICE_UNAVAILABLE),
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

/// Read at most `max + 1` bytes from `reader`.
///
/// The extra sentinel byte lets the caller distinguish "at the bound" from "over
/// the bound" without ever reading an unbounded amount, so a file that grows
/// between its metadata check and its read cannot force an over-limit
/// allocation. Mirrors the bounded read in `release::load_release_manifest_from`.
fn read_bounded_bytes(reader: impl std::io::Read, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut bytes = Vec::new();
    reader.take(max as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Loads the sealed workspace artifact, if configured and readable. Absence is a
/// fail-closed 503 at delivery time, never an error surfaced to logs with content.
///
/// The size is bounded from metadata *before* the read, and the read itself is
/// capped at `MAX_ARTIFACT_BYTES + 1`, so a misconfigured path (or a hostile
/// local writer, or a file that grows after the metadata call) cannot force an
/// over-limit allocation. The read itself runs on the blocking pool via
/// `PrivateApiState::load_artifact`.
fn load_workspace_artifact() -> Result<Vec<u8>, StatusCode> {
    let Ok(path) = std::env::var("WORKSPACE_ARTIFACT_PATH") else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if path.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    // Hardened open: reject a symlink, a non-regular file, a path swapped
    // between stat and open, a file owned by another user, and a
    // group/world-writable file or world-writable parent. Without this a local
    // writer could replace the artifact the browser is told to decrypt.
    let opened = crate::hardened_file::open_hardened(std::path::Path::new(&path))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    // A file too short to hold a header plus the AEAD tag can never be
    // delivered; a file over the bound cannot be read. Both are refused before
    // the read, and the read is capped again below.
    if !artifact_length_is_deliverable(opened.metadata.len()) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let bytes = read_bounded_bytes(opened.file, MAX_ARTIFACT_BYTES)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !artifact_length_is_deliverable(bytes.len() as u64) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(bytes)
}

/// A workspace artifact file is deliverable only when it is long enough to hold
/// the header plus the AEAD tag and no larger than the hard bound. Kept as a
/// named predicate so the exact boundary is unit-tested independently of the
/// readiness probe.
fn artifact_length_is_deliverable(len: u64) -> bool {
    (crypto_envelope::MIN_ARTIFACT_LEN as u64..=MAX_ARTIFACT_BYTES as u64).contains(&len)
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
    let artifact = match state.load_artifact().await {
        Ok(artifact) => artifact,
        Err(status) => return clear_grant(generic_error(status)),
    };
    if artifact.len() > MAX_ARTIFACT_BYTES.saturating_sub(ENVELOPE_OVERHEAD_BYTES) {
        return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE));
    }
    // Compatibility preflight (F1/F7/F10): reject an artifact that does not
    // match the version/KID bound to this session, and (when a release manifest
    // is configured) an artifact whose bytes or recipient fingerprint the
    // manifest does not describe. This rejects the production KID/stale-artifact
    // class of failure before any transport crypto runs. Without a manifest the
    // server cannot verify the recipient key, so a wrong key falls through to
    // the browser's fail-closed `decrypt_artifact`. It compares only public
    // metadata, so it is not a secret-validation oracle.
    let manifest = match state.load_manifest().await {
        Ok(manifest) => manifest,
        Err(_) => return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let enrollment = match enrollment_snapshot(&state, &pending_grant.session_id, now) {
        EnrollmentLookup::Enrolled(snapshot) => Some(snapshot),
        EnrollmentLookup::NotEnrolled => None,
        EnrollmentLookup::Unavailable => {
            return clear_grant(clear_session(generic_error(StatusCode::UNAUTHORIZED)));
        }
    };
    match release::preflight(&artifact, enrollment.as_ref(), manifest.as_ref()) {
        release::UnlockCompatibility::Ok => {}
        release::UnlockCompatibility::EnrollmentRequired => {
            return clear_grant(typed_error(StatusCode::CONFLICT, "enrollment_required"));
        }
        release::UnlockCompatibility::ArtifactIncompatible => {
            return clear_grant(typed_error(StatusCode::CONFLICT, "artifact_incompatible"));
        }
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
    // BR-5: the authenticated HPKE exchange that delivers the artifact also
    // yields the browser transport session. Register the responder's
    // directional app keys under the grant kid so the payload can immediately
    // start encrypted bootstrap/command/sync once the shell hands the mirrored
    // initiator keys over. Nothing is persisted; expiry is bounded here.
    let session_expires_at_ms = now.saturating_add(state.config.session_ttl_ms);
    let owner = *pending_grant.session_id.as_bytes();
    // Seal the artifact *before* touching the key-epoch registry. A seal failure
    // must not retire the previous epoch or register a half-established session:
    // the caller gets a fail-closed 503 and the prior authenticated session keeps
    // working until it is legitimately replaced.
    let envelope = match session.seal(1, &artifact) {
        Ok(envelope) => envelope,
        Err(_) => return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    let server_session = match session_transport::ServerSession::new_owned(
        session.kid(),
        session.app_keys(),
        session_expires_at_ms,
        owner,
    ) {
        Ok(server_session) => server_session,
        Err(_) => return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
    };
    {
        let mut sessions = match state.sessions.lock() {
            Ok(sessions) => sessions,
            Err(_) => return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE)),
        };
        sessions.prune(now);
        // BR-5 authenticated key epoch: a fresh handoff retires every previous
        // epoch for this authenticated workspace session. Otherwise a `kid`
        // issued before a lock (or an earlier unlock) would keep an
        // authenticated command/stream channel until its TTL, so rotating to a
        // new `kid` would not actually terminate the old epoch.
        sessions.retire_owner(&owner);
        // Kids are fresh random values per grant, so a collision can only mean
        // an internal fault; never replace a live session.
        if sessions.insert(server_session).is_err() {
            return clear_grant(generic_error(StatusCode::SERVICE_UNAVAILABLE));
        }
    }
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

/// Deterministic budget response (P0-7): peer exhausted its bounded
/// pending-challenge allowance. Carries Retry-After so well-behaved
/// clients back off until challenges can expire, and nothing about the
/// peer or its pending count is disclosed.
fn too_many_requests() -> Response {
    no_store(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "request unavailable",
        )
            .into_response(),
    )
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
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

fn base64_decode_canonical(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    let decoded = base64_decode_lenient(input, expected_len)?;
    if base64_encode(&decoded) != input {
        return None;
    }
    Some(decoded)
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
    use auth::{AuthenticationResult, Passkey};
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tower::ServiceExt;

    /// Serializes tests that mutate the process-global `WORKSPACE_ARTIFACT_PATH`.
    static WORKSPACE_ARTIFACT_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct FixedClock(AtomicI64);
    impl Clock for FixedClock {
        fn now_ms(&self) -> Result<i64, PrivateApiError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    /// Opaque-service clock sharing the `FixedClock` value so session expiry is
    /// deterministic in tests.
    struct TestOpaqueClock(i64);
    impl OpaqueClock for TestOpaqueClock {
        fn now_ms(&self) -> Option<i64> {
            Some(self.0)
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

    /// Store whose crypto accepts but whose persistence layer is DOWN.
    /// Used to prove the P0-8 taxonomy: successful WebAuthn crypto followed
    /// by store unavailability must surface as 503 (backend condition),
    /// never 401 (auth failure).
    struct UnavailableApplyStore {
        passkey: Mutex<Passkey>,
    }

    impl PasskeyCredentialStore for UnavailableApplyStore {
        fn list_passkeys(&self) -> Result<Vec<Passkey>, AuthError> {
            Ok(vec![self.passkey.lock().unwrap().clone()])
        }

        fn apply_authentication_result(&self, _: &AuthenticationResult) -> Result<(), AuthError> {
            Err(AuthError::VerifierUnavailable)
        }
    }

    /// Restores a process environment variable on drop, so a panicking test
    /// cannot leak mutated global env into other tests.
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let previous = std::env::var(key).ok();
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            EnvGuard { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn test_state(clock: Arc<FixedClock>) -> (PrivateApiState, TestRegistrationClient) {
        let (authenticator, client) = legacy_authenticator();
        let state =
            PrivateApiState::with_test_dependencies(config(), Some(authenticator), clock).unwrap();
        (state, client)
    }

    /// Same ceremony wiring as [`test_state`] but backed by
    /// [`UnavailableApplyStore`]: crypto succeeds, persistence is down.
    fn test_state_store_unavailable(
        clock: Arc<FixedClock>,
    ) -> (PrivateApiState, TestRegistrationClient) {
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
        let registration_client = std::sync::Mutex::new(auth::passkey::__private_test_client(true));
        let registration = registration_client
            .lock()
            .unwrap()
            .do_registration(origin.clone(), creation)
            .unwrap();
        let passkey = server
            .finish_passkey_registration(&registration, &reg_state)
            .unwrap();
        let store: Arc<dyn PasskeyCredentialStore> = Arc::new(UnavailableApplyStore {
            passkey: Mutex::new(passkey),
        });
        let authenticator = Arc::new(
            WebAuthnPasskeyAuthenticator::new("example.com", "https://example.com", store).unwrap(),
        );
        let state =
            PrivateApiState::with_test_dependencies(config(), Some(authenticator), clock).unwrap();
        (state, registration_client)
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

    const ENROLL_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn production_state_with_store(
        path: &std::path::Path,
        secret: Option<&str>,
        allow_additional: bool,
    ) -> PrivateApiState {
        let store = Arc::new(FilePasskeyCredentialStore::open(path).unwrap());
        PrivateApiState::production_with_passkeys(
            config(),
            store,
            secret.map(|value| Zeroizing::new(value.to_string())),
            allow_additional,
        )
        .unwrap()
    }

    /// Drive a real operator enrollment ceremony through the HTTP surface:
    /// begin (operator secret) -> `navigator.credentials.create` equivalent ->
    /// finish. Returns the terminal status.
    async fn register_passkey_over_http(
        app: &Router,
        secret: &str,
        client: &TestRegistrationClient,
    ) -> StatusCode {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/register/challenge")
                    .header(ENROLLMENT_SECRET_HEADER, secret)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        if status != StatusCode::OK {
            return status;
        }
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
        assert!(cookie.starts_with(REGISTRATION_COOKIE_NAME));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let options: auth::CreationChallengeResponse = serde_json::from_slice(&body).unwrap();
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_registration(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let verify = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/register/verify")
                    .header(ENROLLMENT_SECRET_HEADER, secret)
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, cookie)
                    .body(Body::from(serde_json::to_vec(&credential).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        verify.status()
    }

    async fn authenticate_session_cookie(app: &Router, client: &TestRegistrationClient) -> String {
        let (challenge_cookie, options) = begin(app.clone()).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let verify = app
            .clone()
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
        assert_eq!(verify.status(), StatusCode::NO_CONTENT);
        verify
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let cookie = value.to_str().ok()?;
                cookie
                    .starts_with(&format!("{SESSION_COOKIE_NAME}="))
                    .then(|| cookie.split(';').next().unwrap().to_string())
            })
            .unwrap()
    }

    #[tokio::test]
    async fn production_passkey_enrollment_unlocks_authenticated_internal_routes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkeys.json");
        let state = production_state_with_store(&path, Some(ENROLL_SECRET), false);
        let app = router(state);
        let client = std::sync::Mutex::new(auth::passkey::__private_test_client(true));

        // Empty store: authentication is unavailable (fail closed) even though
        // the authenticator is wired.
        let response = app
            .clone()
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

        // Enrollment requires the exact operator secret.
        assert_eq!(
            register_passkey_over_http(&app, "wrong-secret-wrong-secret-wrong!!", &client).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            register_passkey_over_http(&app, ENROLL_SECRET, &client).await,
            StatusCode::NO_CONTENT
        );
        assert!(path.exists());

        // The enrolled credential now authenticates through the real HTTP path.
        let session_cookie = authenticate_session_cookie(&app, &client).await;
        let session = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/auth/session")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::NO_CONTENT);

        // The authenticated session can reach the workspace enrollment and
        // artifact grant routes the clear shell needs after unlock prerequisites.
        let enroll = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(
                        serde_json::json!({
                            "version": 1,
                            "kid": base64_encode(&[7u8; auth::WORKSPACE_KID_BYTES]),
                            "public_key": base64_encode(&[9u8; auth::WORKSPACE_PUBLIC_KEY_BYTES]),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enroll.status(), StatusCode::OK);
        let grant = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact/grant")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant.status(), StatusCode::OK);

        // One-time bootstrap: the secret no longer mints a second credential.
        assert_eq!(
            register_passkey_over_http(&app, ENROLL_SECRET, &client).await,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn production_passkey_enrollment_disabled_without_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkeys.json");
        let state = production_state_with_store(&path, None, false);
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/register/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn production_passkey_rejects_short_enrollment_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkeys.json");
        let store = Arc::new(FilePasskeyCredentialStore::open(&path).unwrap());
        assert!(PrivateApiState::production_with_passkeys(
            config(),
            store,
            Some(Zeroizing::new("too-short".to_string())),
            false,
        )
        .is_err());
    }

    #[tokio::test]
    async fn production_passkey_store_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkeys.json");
        let client = std::sync::Mutex::new(auth::passkey::__private_test_client(true));
        {
            let state = production_state_with_store(&path, Some(ENROLL_SECRET), false);
            let app = router(state);
            assert_eq!(
                register_passkey_over_http(&app, ENROLL_SECRET, &client).await,
                StatusCode::NO_CONTENT
            );
            let _ = authenticate_session_cookie(&app, &client).await;
        }
        // A fresh process (new state + store loaded from disk) still accepts the
        // same credential, so enrollment is genuinely durable.
        let state = production_state_with_store(&path, Some(ENROLL_SECRET), false);
        let app = router(state);
        let _ = authenticate_session_cookie(&app, &client).await;
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

    /// P0-9 INFO follow-up: assert the security flags on the ACTUAL
    /// Set-Cookie headers the endpoints emit, not only on the builder
    /// helper's output. Every cookie this service mints (challenge,
    /// session, artifact grant) must carry the full fail-closed flag set.
    async fn assert_set_cookie_flags(response: &axum::response::Response, cookie_name: &str) {
        let cookie_prefix = format!("{cookie_name}=");
        let raw = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(&cookie_prefix).then(|| s.to_string())
            })
            .unwrap_or_else(|| panic!("no Set-Cookie for {cookie_name}"));
        assert!(
            raw.contains("Path=/"),
            "missing Path=/ on Set-Cookie for {cookie_name}"
        );
        assert!(
            raw.contains("Secure"),
            "missing Secure on Set-Cookie for {cookie_name}"
        );
        assert!(
            raw.contains("HttpOnly"),
            "missing HttpOnly on Set-Cookie for {cookie_name}"
        );
        assert!(
            raw.contains("SameSite=Strict"),
            "missing SameSite=Strict on Set-Cookie for {cookie_name}"
        );
        assert!(
            raw.contains("Max-Age="),
            "missing Max-Age (no session cookies) on Set-Cookie for {cookie_name}"
        );
    }

    #[tokio::test]
    async fn challenge_set_cookie_header_carries_all_security_flags() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
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
        assert_eq!(response.status(), StatusCode::OK);
        assert_set_cookie_flags(&response, CHALLENGE_COOKIE_NAME).await;
    }

    #[tokio::test]
    async fn session_set_cookie_header_carries_all_security_flags() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
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
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_set_cookie_flags(&response, SESSION_COOKIE_NAME).await;
    }

    #[tokio::test]
    async fn artifact_grant_set_cookie_header_carries_all_security_flags() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (challenge_cookie, options) = begin(router(state.clone())).await;
        let credential = {
            let mut client = client.lock().unwrap();
            client
                .do_authentication(auth::passkey::__private_test_origin_url(), options)
                .unwrap()
        };
        let verify_response = router(state.clone())
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
        assert_eq!(verify_response.status(), StatusCode::NO_CONTENT);
        let session_cookie = verify_response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(&format!("{SESSION_COOKIE_NAME}="))
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap();
        let grant_response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact/grant")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant_response.status(), StatusCode::OK);
        assert_set_cookie_flags(&grant_response, ARTIFACT_GRANT_COOKIE_NAME).await;
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

    // ---- P0-8 store-error taxonomy tests ----

    #[tokio::test]
    async fn successful_crypto_with_unavailable_store_returns_503_and_consumes_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state_store_unavailable(clock);
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
        // WebAuthn crypto SUCCEEDS, then the credential store is down:
        // the documented taxonomy says backend condition => 503, and the
        // challenge is consumed exactly as on any other post-crypto path.
        let response = router(state.clone()).oneshot(make()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(is_challenge_cleared(&response));
        // No session may exist on a 503 path.
        assert!(response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|v| {
                v.to_str()
                    .map(|s| !s.starts_with(SESSION_COOKIE_NAME))
                    .unwrap_or(true)
            }));
        // Replay of the same challenge is rejected: single-use held.
        assert_eq!(
            router(state).oneshot(make()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bad_crypto_still_returns_401_and_consumes_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (challenge_cookie, _options) = begin(router(state.clone())).await;
        // Sign a DIFFERENT server challenge: crypto fails => 401, and the
        // pending attempt is consumed (existing documented policy).
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
    async fn malformed_body_still_401s_without_consuming_challenge() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state_store_unavailable(clock.clone());
        // Sign a REAL assertion for this ceremony first, then submit it
        // malformed: the malformed try must not consume the challenge.
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
        // The same challenge is still live: the well-formed retry now
        // reaches the (unavailable) store and must 503, proving the
        // taxonomy and the non-consumption policy compose.
        let valid = Request::builder()
            .method("POST")
            .uri("/internal/auth/verify")
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(header::COOKIE, challenge_cookie)
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            router(state).oneshot(valid).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Whether the response clears the challenge cookie (Max-Age=0 form).
    fn is_challenge_cleared(response: &axum::response::Response) -> bool {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.starts_with(CHALLENGE_COOKIE_NAME) && s.contains("Max-Age=0"))
                    .unwrap_or(false)
            })
    }

    // ---- P0-7 challenge-issuance budget tests ----

    /// Issues one challenge and returns the response status.
    async fn challenge_for(app: Router) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/auth/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    /// Issues one challenge carrying a request-controlled peer header and
    /// returns the response status. The budget must be indifferent to
    /// these headers: they cannot select or rotate a bucket.
    async fn challenge_with_peer_header(app: Router, peer: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/auth/challenge")
                .header("X-Evergreen-Peer", peer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn global_exhaustion_returns_deterministic_429() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        for _ in 0..MAX_PENDING_CHALLENGES {
            assert_eq!(challenge_for(router(state.clone())).await, StatusCode::OK);
        }
        // The (MAX+1)th challenge is refused deterministically and carries
        // Retry-After; nothing about internal state is disclosed.
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        // Further requests keep failing closed at the cap (no drift).
        assert_eq!(
            challenge_for(router(state)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn header_rotation_cannot_bypass_the_bound() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        // Fill the global budget, rotating a client-controlled identity
        // header on every request the way an attacker would.
        for index in 0..MAX_PENDING_CHALLENGES {
            let peer = format!("rotating-peer-{index}.attacker.internal");
            assert_eq!(
                challenge_with_peer_header(router(state.clone()), &peer).await,
                StatusCode::OK
            );
        }
        // Every further rotation lands in the SAME exhausted budget: the
        // header cannot mint a fresh bucket. This is the regression guard
        // against per-header budget keys.
        for index in 0..16 {
            let peer = format!("bypass-{index}.attacker.internal");
            assert_eq!(
                challenge_with_peer_header(router(state.clone()), &peer).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        // Omitting the header entirely is equally capped.
        assert_eq!(
            challenge_for(router(state)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn budget_recovers_after_challenge_is_consumed() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        // Mint one challenge BEFORE saturating so we hold a completable
        // ceremony.
        let (challenge_cookie, options) = {
            let response = router(state.clone())
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
        };
        // Saturate the remaining budget.
        for _ in 0..(MAX_PENDING_CHALLENGES - 1) {
            assert_eq!(challenge_for(router(state.clone())).await, StatusCode::OK);
        }
        assert_eq!(
            challenge_for(router(state.clone())).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Complete the ceremony: consumption frees the slot even though
        // nothing expired.
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
        // The consumed challenge's slot is free again.
        assert_eq!(challenge_for(router(state)).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn budget_recovers_after_ttl_expiry() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock.clone());
        for _ in 0..MAX_PENDING_CHALLENGES {
            assert_eq!(challenge_for(router(state.clone())).await, StatusCode::OK);
        }
        assert_eq!(
            challenge_for(router(state.clone())).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Advance past challenge_ttl_ms: prune drops every expired pending
        // challenge and the full budget recovers.
        clock.0.store(1_000 + 60_000, Ordering::SeqCst);
        for _ in 0..MAX_PENDING_CHALLENGES {
            assert_eq!(challenge_for(router(state.clone())).await, StatusCode::OK);
        }
        // The refreshed budget is bounded exactly as before.
        assert_eq!(
            challenge_for(router(state)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn concurrent_challenges_at_the_cap_allow_exactly_the_budget() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        // Fire 3x the budget concurrently; exactly MAX_PENDING_CHALLENGES
        // may succeed under the mutex, with attacker-style header rotation
        // in flight proving the cap is rotation-proof even under races.
        let total = MAX_PENDING_CHALLENGES * 3;
        let mut handles = Vec::with_capacity(total);
        for index in 0..total {
            let state = state.clone();
            let peer = format!("race-peer-{index}.attacker.internal");
            handles.push(tokio::spawn(async move {
                challenge_with_peer_header(router(state), &peer).await
            }));
        }
        let mut ok = 0usize;
        let mut too_many = 0usize;
        for handle in handles {
            match handle.await.unwrap() {
                StatusCode::OK => ok += 1,
                StatusCode::TOO_MANY_REQUESTS => too_many += 1,
                other => panic!("unexpected status at the cap: {other}"),
            }
        }
        assert_eq!(ok, MAX_PENDING_CHALLENGES);
        assert_eq!(too_many, total - MAX_PENDING_CHALLENGES);
    }

    // ---- P0-4 artifact delivery tests ----

    /// Derive a deterministic workspace keypair for artifact tests.
    fn test_keypair(secret_byte: u8, kid_byte: u8) -> crypto_envelope::WorkspaceUnlockKeyPair {
        let secret = [secret_byte; crypto_envelope::UNLOCK_SECRET_LEN];
        let kid = [kid_byte; auth::WORKSPACE_KID_BYTES];
        crypto_envelope::derive_workspace_keypair(&secret, auth::ARTIFACT_VERSION, &kid).unwrap()
    }

    /// Pack files in the exact custom package format the shell unpacks
    /// (`u32 count || {u16 pathLen, u32 dataLen, path, data}*`). This is the
    /// production package layout, so a test that seals this is exercising the
    /// same stage-6 bytes the browser will receive.
    fn pack_test_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(files.len() as u32).to_be_bytes());
        for (path, data) in files {
            out.extend_from_slice(&(path.len() as u16).to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    /// Mirror of the browser package unpack so a test can prove stage 6
    /// (`unpackPackageFromMemory`) succeeds on the delivered bytes.
    fn unpack_test_package(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        assert!(bytes.len() >= 4);
        let count = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut offset = 4usize;
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            let path_len =
                u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            let data_len =
                u32::from_be_bytes(bytes[offset + 2..offset + 6].try_into().unwrap()) as usize;
            offset += 6;
            let path =
                String::from_utf8(bytes[offset..offset + path_len].to_vec()).expect("utf8 path");
            offset += path_len;
            let data = bytes[offset..offset + data_len].to_vec();
            offset += data_len;
            files.push((path, data));
        }
        assert_eq!(offset, bytes.len(), "package must be exactly consumed");
        files
    }

    /// Authenticated workspace enrollment for a test session.
    async fn enroll_test_workspace(
        state: &PrivateApiState,
        session_cookie: &str,
        keypair: &crypto_envelope::WorkspaceUnlockKeyPair,
    ) {
        let body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": base64_encode(&keypair.kid()),
            "public_key": base64_encode(&keypair.public_key_bytes()),
        });
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/workspace/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.to_string())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

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
        // Production-shaped artifact: a custom package sealed to the workspace
        // public key the session enrolls, so the compatibility preflight passes
        // and stage-6 unpack can be asserted on the delivered bytes.
        let keypair = test_keypair(0x5a, 0x6b);
        let package = pack_test_files(&[
            ("index.html", b"<main>workspace</main>"),
            ("assets/app.js", b"console.log(1)"),
        ]);
        let artifact_bytes = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        enroll_test_workspace(&state, &session_cookie, &keypair).await;
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
        let decrypted = crypto_envelope::decrypt_artifact(&keypair, &plaintext).unwrap();
        let files = unpack_test_package(&decrypted);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "index.html");
        assert_eq!(files[0].1, b"<main>workspace</main>");
        assert_eq!(files[1].0, "assets/app.js");
    }

    #[tokio::test]
    async fn artifact_grant_is_single_use_and_session_bound() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let keypair = test_keypair(0x11, 0x22);
        let package = pack_test_files(&[("index.html", b"workspace")]);
        let artifact = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        let artifact_copy = artifact.clone();
        let state = state.with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        enroll_test_workspace(&state, &session_cookie, &keypair).await;

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

    async fn establish_authenticated_session(
        state: &PrivateApiState,
        client: &TestRegistrationClient,
    ) -> String {
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
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(SESSION_COOKIE_NAME)
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap()
    }

    #[tokio::test]
    async fn workspace_enrollment_succeeds_for_authenticated_session_and_is_queryable() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let session_cookie = establish_authenticated_session(&state, &client).await;

        let kid = [0x11u8; auth::WORKSPACE_KID_BYTES];
        let pk = [0x22u8; auth::WORKSPACE_PUBLIC_KEY_BYTES];
        let kid_b64 = base64_encode(&kid);
        let pk_b64 = base64_encode(&pk);

        let enroll_body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": kid_b64,
            "public_key": pk_b64,
        });

        // Enroll on /internal/auth/enroll
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "no-store"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enroll_resp: WorkspaceEnrollmentResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(enroll_resp.enrolled);
        assert_eq!(enroll_resp.version, auth::ARTIFACT_VERSION);
        assert_eq!(enroll_resp.kid, kid_b64);
        assert_eq!(enroll_resp.public_key, pk_b64);

        // Query via GET /internal/auth/enroll
        let get_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/auth/enroll")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        assert_eq!(
            get_resp
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "no-store"
        );
        let get_bytes = get_resp.into_body().collect().await.unwrap().to_bytes();
        let details: WorkspaceEnrollmentDetailsResponse =
            serde_json::from_slice(&get_bytes).unwrap();
        assert_eq!(details.version, auth::ARTIFACT_VERSION);
        assert_eq!(details.kid, kid_b64);
        assert_eq!(details.public_key, pk_b64);
        assert_eq!(details.enrolled_at_ms, 1_000);

        // Also query via GET /internal/workspace/enroll
        let get_ws_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/enroll")
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_ws_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn workspace_enrollment_rejects_unauthenticated_and_expired_session() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock.clone());

        let kid_b64 = base64_encode(&[1u8; auth::WORKSPACE_KID_BYTES]);
        let pk_b64 = base64_encode(&[2u8; auth::WORKSPACE_PUBLIC_KEY_BYTES]);
        let enroll_body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": kid_b64,
            "public_key": pk_b64,
        });

        // 1. Unauthenticated (no session cookie)
        let unauth_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

        // 2. Expired session
        let session_cookie = establish_authenticated_session(&state, &client).await;
        // Advance clock past session TTL (120_000 ms)
        clock.0.store(1_000 + 120_001, Ordering::SeqCst);

        let expired_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_resp.status(), StatusCode::UNAUTHORIZED);
        let cleared = expired_resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.starts_with(SESSION_COOKIE_NAME) && s.contains("Max-Age=0"))
                    .unwrap_or(false)
            });
        assert!(cleared, "expired session cookie must be cleared");

        // 3. GET on unenrolled session returns 404
        clock.0.store(200_000, Ordering::SeqCst);
        let fresh_cookie = establish_authenticated_session(&state, &client).await;
        let not_found_resp = router(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/auth/enroll")
                    .header(header::COOKIE, fresh_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_found_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn workspace_enrollment_rejects_duplicate_and_conflict() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let session_cookie = establish_authenticated_session(&state, &client).await;

        let kid = [0x33u8; auth::WORKSPACE_KID_BYTES];
        let pk = [0x44u8; auth::WORKSPACE_PUBLIC_KEY_BYTES];
        let enroll_body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": base64_encode(&kid),
            "public_key": base64_encode(&pk),
        });

        // First enrollment succeeds
        let resp1 = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Re-enrolling the identical binding is idempotent (page reload or a
        // lock/unlock cycle in the same session), so a second unlock is not
        // rejected with 409.
        let resp2 = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let resp2_body = resp2.into_body().collect().await.unwrap().to_bytes();
        let parsed: WorkspaceEnrollmentResponse = serde_json::from_slice(&resp2_body).unwrap();
        assert!(parsed.enrolled);
        assert_eq!(parsed.kid, base64_encode(&kid));
        assert_eq!(parsed.public_key, base64_encode(&pk));

        // Conflicting enrollment (different public key) on same session also rejected with 409 Conflict
        let conflict_body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": base64_encode(&kid),
            "public_key": base64_encode(&[0x99u8; auth::WORKSPACE_PUBLIC_KEY_BYTES]),
        });
        let resp3 = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/workspace/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::from(serde_json::to_vec(&conflict_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp3.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn workspace_enrollment_rejects_malformed_inputs() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let session_cookie = establish_authenticated_session(&state, &client).await;

        let valid_kid = base64_encode(&[1u8; auth::WORKSPACE_KID_BYTES]);
        let valid_pk = base64_encode(&[2u8; auth::WORKSPACE_PUBLIC_KEY_BYTES]);

        let test_cases = vec![
            // Unsupported version
            serde_json::json!({ "version": 2, "kid": valid_kid, "public_key": valid_pk }),
            // All-zero kid
            serde_json::json!({ "version": 1, "kid": base64_encode(&[0u8; 16]), "public_key": valid_pk }),
            // All-zero pk
            serde_json::json!({ "version": 1, "kid": valid_kid, "public_key": base64_encode(&[0u8; 32]) }),
            // Truncated kid (15 bytes)
            serde_json::json!({ "version": 1, "kid": base64_encode(&[1u8; 15]), "public_key": valid_pk }),
            // Truncated pk (31 bytes)
            serde_json::json!({ "version": 1, "kid": valid_kid, "public_key": base64_encode(&[2u8; 31]) }),
            // Non-canonical base64 kid
            serde_json::json!({ "version": 1, "kid": "not-valid-base64!", "public_key": valid_pk }),
            // Non-canonical base64 pk
            serde_json::json!({ "version": 1, "kid": valid_kid, "public_key": "not-valid-base64!" }),
        ];

        for body in test_cases {
            let resp = router(state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/internal/auth/enroll")
                        .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                        .header(header::COOKIE, session_cookie.clone())
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for {body:?}"
            );
        }

        // Wrong Content-Type returns 415
        let wrong_ct = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_ct.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Malformed JSON returns 400
        let bad_json = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::from("{malformed}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_json.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn workspace_enrollment_retains_only_public_metadata_proof() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let session_cookie = establish_authenticated_session(&state, &client).await;

        let kid = [0x77u8; auth::WORKSPACE_KID_BYTES];
        let pk = [0x88u8; auth::WORKSPACE_PUBLIC_KEY_BYTES];

        let body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": base64_encode(&kid),
            "public_key": base64_encode(&pk),
        });

        let resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Inspect internal state: AuthState holds only public metadata
        let auth = state.auth.lock().unwrap();
        let (session_id, _) = state
            .transport
            .lock()
            .unwrap()
            .sessions
            .values()
            .next()
            .unwrap()
            .clone();
        let meta = auth.get_workspace_enrollment(&session_id, 1_000).unwrap();
        assert_eq!(meta.version(), auth::ARTIFACT_VERSION);
        assert_eq!(meta.kid(), &kid);
        assert_eq!(meta.public_key(), &pk);
        // Debug representation proves no private or secret key fields exist
        let dbg = format!("{meta:?}");
        assert!(!dbg.contains("secret"));
        assert!(!dbg.contains("private"));
        assert!(dbg.contains("WorkspacePublicKeyMetadata"));
    }

    #[tokio::test]
    async fn end_to_end_enrollment_and_workspace_artifact_unlock() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);

        // 1. Ephemeral client unlock secret + kid
        let unlock_secret = [0x5au8; crypto_envelope::UNLOCK_SECRET_LEN];
        let kid = [0x6bu8; auth::WORKSPACE_KID_BYTES];

        // 2. Client derives keypair in memory and computes public key
        let keypair =
            crypto_envelope::derive_workspace_keypair(&unlock_secret, auth::ARTIFACT_VERSION, &kid)
                .unwrap();
        let ws_pk = keypair.public_key();

        // 3. Build pipeline seals payload to this public key
        let original_payload = b"<!doctype html><html><body>Private Workspace Active</body></html>";
        let sealed_artifact =
            crypto_envelope::seal_artifact(&ws_pk, auth::ARTIFACT_VERSION, &kid, original_payload)
                .unwrap();

        let state = state.with_artifact_loader(Arc::new({
            let artifact = sealed_artifact.clone();
            move || Ok(artifact.clone())
        }));

        // 4. Authenticate WebAuthn session
        let session_cookie = establish_authenticated_session(&state, &client).await;

        // 5. Authenticated enrollment of workspace public key
        let enroll_body = serde_json::json!({
            "version": auth::ARTIFACT_VERSION,
            "kid": base64_encode(&kid),
            "public_key": base64_encode(&ws_pk.0),
        });
        let enroll_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/auth/enroll")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&enroll_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enroll_resp.status(), StatusCode::OK);

        // 6. Request artifact grant (HPKE offer)
        let grant_resp = router(state.clone())
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
        assert_eq!(grant_resp.status(), StatusCode::OK);

        let grant_cookie = grant_resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                s.starts_with(ARTIFACT_GRANT_COOKIE_NAME)
                    .then(|| s.split(';').next().unwrap().to_string())
            })
            .unwrap();
        let grant_bytes = grant_resp.into_body().collect().await.unwrap().to_bytes();
        let grant_data: serde_json::Value = serde_json::from_slice(&grant_bytes).unwrap();
        let grant_id = grant_data["grant_id"].as_str().unwrap().to_string();
        let server_kid = grant_data["kid"].as_str().unwrap();
        let server_pk = grant_data["recipient_public_key"].as_str().unwrap();

        // 7. Client HPKE handshake
        let (encapsulated, mut initiator) = establish_initiator(server_kid, server_pk);

        // 8. Deliver artifact over HPKE session
        let deliver_body = serde_json::json!({
            "grant_id": grant_id,
            "kid": server_kid,
            "encapsulated_key": base64(&encapsulated.0),
        });
        let deliver_resp = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/artifact")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, format!("{session_cookie}; {grant_cookie}"))
                    .body(Body::from(serde_json::to_vec(&deliver_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deliver_resp.status(), StatusCode::OK);

        let deliver_bytes = deliver_resp.into_body().collect().await.unwrap().to_bytes();

        // 9. Client decrypts session envelope in memory
        let envelope = crypto_envelope::Envelope {
            kid: deliver_bytes[..16].try_into().unwrap(),
            nonce: deliver_bytes[16..28].try_into().unwrap(),
            sequence: u64::from_be_bytes(deliver_bytes[28..36].try_into().unwrap()),
            ciphertext: deliver_bytes[36..].to_vec(),
        };
        let delivered_artifact = initiator.receive(&envelope).unwrap();
        assert_eq!(delivered_artifact, sealed_artifact);

        // 9b. BR-5/BR-7/BR-1/BR-3: the same authenticated HPKE exchange
        //     registered the browser transport session. Drive the real opaque
        //     bootstrap + command surface with the initiator's directional app
        //     keys, exactly as the payload would after the shell handoff.
        let mut session_client =
            session_transport::ClientSession::new(initiator.kid(), initiator.app_keys()).unwrap();
        let opaque = OpaqueServiceState::new(
            state.sessions(),
            Arc::new(FailClosedDispatcher),
            Arc::new(FailClosedBootstrap),
            Arc::new(TestOpaqueClock(1_000)),
            state.config.session_ttl_ms,
        )
        .unwrap();

        let bootstrap_request = session_client
            .seal_next(br#"{"op":"bootstrap","protocol_version":1,"request_id":"e2e-bootstrap"}"#)
            .unwrap();
        let bootstrap_bytes = opaque
            .relay_envelope(OpaqueRoute::Bootstrap, &bootstrap_request.to_wire_bytes())
            .await
            .unwrap();
        let bootstrap_response = session_transport::parse_wire_envelope(&bootstrap_bytes).unwrap();
        assert_eq!(bootstrap_response.sequence, bootstrap_request.sequence);
        let bootstrap_plaintext = session_client.open(&bootstrap_response).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bootstrap_plaintext).unwrap();
        assert_eq!(document["request_id"], "e2e-bootstrap");
        assert_eq!(document["protocol_version"], 1);
        assert_eq!(document["trading_enabled"], false);
        assert_eq!(document["kill_switch"]["enabled"], true);
        assert_eq!(document["capabilities"]["execute"], false);

        // A command with no configured backend is an AEAD-authenticated typed
        // denial that still echoes the request challenge (never a false
        // success).
        let command_request = session_client
            .seal_next(
                br#"{"op":"get_quote","payload":{},"request_id":"e2e-command","idempotency_key":null}"#,
            )
            .unwrap();
        let command_bytes = opaque
            .relay_envelope(OpaqueRoute::Command, &command_request.to_wire_bytes())
            .await
            .unwrap();
        let command_response = session_transport::parse_wire_envelope(&command_bytes).unwrap();
        assert_eq!(command_response.sequence, command_request.sequence);
        let command_plaintext = session_client.open(&command_response).unwrap();
        let command_body: serde_json::Value = serde_json::from_slice(&command_plaintext).unwrap();
        assert_eq!(command_body["request_id"], "e2e-command");
        assert_eq!(command_body["error"]["code"], "capability_missing");
        assert!(command_body.get("result").is_none());

        // 10. Client decrypts inner workspace artifact in memory
        let decrypted_payload =
            crypto_envelope::decrypt_artifact(&keypair, &delivered_artifact).unwrap();
        assert_eq!(decrypted_payload, original_payload);

        // 11. Wrong secret fails closed
        let mut wrong_secret = unlock_secret;
        wrong_secret[31] ^= 0x01;
        let wrong_keypair =
            crypto_envelope::derive_workspace_keypair(&wrong_secret, auth::ARTIFACT_VERSION, &kid)
                .unwrap();
        assert!(crypto_envelope::decrypt_artifact(&wrong_keypair, &delivered_artifact).is_err());

        // 12. Wrong kid fails closed
        let mut wrong_kid = kid;
        wrong_kid[0] ^= 0x01;
        let wrong_kid_keypair = crypto_envelope::derive_workspace_keypair(
            &unlock_secret,
            auth::ARTIFACT_VERSION,
            &wrong_kid,
        )
        .unwrap();
        assert!(
            crypto_envelope::decrypt_artifact(&wrong_kid_keypair, &delivered_artifact).is_err()
        );

        // 13. Tampered ciphertext fails closed
        let mut tampered_artifact = delivered_artifact.clone();
        let last_byte = tampered_artifact.len() - 1;
        tampered_artifact[last_byte] ^= 0x01;
        assert!(crypto_envelope::decrypt_artifact(&keypair, &tampered_artifact).is_err());
    }

    // ---- F1/F7/F10 compatibility preflight + descriptor tests ----

    async fn deliver_artifact_request(
        state: &PrivateApiState,
        session_cookie: &str,
        grant_cookie: &str,
        grant_id: &str,
        server_kid: &str,
        server_pk: &str,
    ) -> (StatusCode, axum::body::Bytes) {
        let (encapsulated, _initiator) = establish_initiator(server_kid, server_pk);
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
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, bytes)
    }

    #[tokio::test]
    async fn artifact_delivery_rejects_kid_mismatch_before_transport() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        // Enrollment uses kid A; the artifact on disk was sealed under kid B.
        // This is the production class of failure: delivery must be rejected
        // with a typed code before any outer HPKE wrapping happens.
        let enrolled = test_keypair(0x5a, 0x01);
        let sealed_under = test_keypair(0x5a, 0x02);
        let package = pack_test_files(&[("index.html", b"workspace")]);
        let artifact = crypto_envelope::seal_artifact(
            &sealed_under.public_key(),
            auth::ARTIFACT_VERSION,
            &sealed_under.kid(),
            &package,
        )
        .unwrap();
        let artifact_copy = artifact.clone();
        let state = state.with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        enroll_test_workspace(&state, &session_cookie, &enrolled).await;

        let (status, body) = deliver_artifact_request(
            &state,
            &session_cookie,
            &grant_cookie,
            &grant_id,
            &server_kid,
            &server_pk,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["code"], "artifact_incompatible");
        assert!(body.len() < 4096, "error body must be bounded");
    }

    #[tokio::test]
    async fn artifact_delivery_requires_an_enrollment() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let keypair = test_keypair(0x5a, 0x03);
        let package = pack_test_files(&[("index.html", b"workspace")]);
        let artifact = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        let artifact_copy = artifact.clone();
        let state = state.with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        // Deliberately skip enrollment.
        let (status, body) = deliver_artifact_request(
            &state,
            &session_cookie,
            &grant_cookie,
            &grant_id,
            &server_kid,
            &server_pk,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["code"], "enrollment_required");
    }

    #[tokio::test]
    async fn workspace_descriptor_exposes_only_public_release_metadata() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let keypair = test_keypair(0x5a, 0x04);
        let package = pack_test_files(&[("index.html", b"workspace")]);
        let artifact = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        let artifact_copy = artifact.clone();
        let state = state.with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())));
        let session_cookie = establish_authenticated_session(&state, &client).await;
        enroll_test_workspace(&state, &session_cookie, &keypair).await;

        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/descriptor")
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(descriptor["protocol_version"], 1);
        assert_eq!(descriptor["artifact_version"], auth::ARTIFACT_VERSION);
        assert_eq!(
            descriptor["artifact_kid_b64"],
            base64_encode(&keypair.kid())
        );
        assert_eq!(descriptor["package_format_version"], 1);
        assert_eq!(descriptor["enrolled"], true);
        // The descriptor must never carry ciphertext, paths or secrets.
        assert!(descriptor.get("artifact_bytes").is_none());
        assert!(descriptor.get("path").is_none());
    }

    #[tokio::test]
    async fn workspace_descriptor_requires_authentication() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/descriptor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Production-faithful loader test: the artifact is read from
    /// `WORKSPACE_ARTIFACT_PATH` by the real `load_workspace_artifact`, wrapped
    /// in the real transport HPKE envelope over the real routes, then decrypted
    /// and unpacked with the production package layout.
    #[tokio::test]
    async fn production_artifact_loader_delivers_and_unpacks_a_real_package() {
        let _guard = WORKSPACE_ARTIFACT_ENV_LOCK.lock().await;

        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        // No loader override: `test_state` keeps the real `load_workspace_artifact`.
        let (state, client) = test_state(clock);
        let keypair = test_keypair(0x77, 0x88);
        let package = pack_test_files(&[
            (
                "index.html",
                b"<!doctype html><html><body>boot</body></html>",
            ),
            ("assets/index-abc.js", b"export const boot = true;"),
        ]);
        let artifact = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let artifact_path = dir.path().join("workspace.artifact");
        std::fs::write(&artifact_path, &artifact).unwrap();
        // The real loader requires an owner/world-non-writable trust file; make
        // the fixture match the production artifact mode (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        let previous = std::env::var("WORKSPACE_ARTIFACT_PATH").ok();
        std::env::set_var("WORKSPACE_ARTIFACT_PATH", &artifact_path);

        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        enroll_test_workspace(&state, &session_cookie, &keypair).await;

        // Re-run the client HPKE establishment so the response can be opened.
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
        let status = response.status();
        let delivered = response.into_body().collect().await.unwrap().to_bytes();

        // Restore the environment before asserting so a failure cannot leak the
        // test path into sibling tests.
        match previous {
            Some(value) => std::env::set_var("WORKSPACE_ARTIFACT_PATH", value),
            None => std::env::remove_var("WORKSPACE_ARTIFACT_PATH"),
        }

        assert_eq!(status, StatusCode::OK);
        let envelope = crypto_envelope::Envelope {
            kid: delivered[..16].try_into().unwrap(),
            nonce: delivered[16..28].try_into().unwrap(),
            sequence: u64::from_be_bytes(delivered[28..36].try_into().unwrap()),
            ciphertext: delivered[36..].to_vec(),
        };
        let delivered_artifact = initiator.receive(&envelope).unwrap();
        assert_eq!(delivered_artifact, artifact);
        let decrypted = crypto_envelope::decrypt_artifact(&keypair, &delivered_artifact).unwrap();
        assert_eq!(decrypted, package);
        let files = unpack_test_package(&decrypted);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "index.html");
        assert!(files[0].1.starts_with(b"<!doctype html>"));
        assert_eq!(files[1].0, "assets/index-abc.js");
    }

    /// The loader bounds the artifact size from metadata before reading, so an
    /// oversized or non-file path cannot force an unbounded allocation even on
    /// the unauthenticated `/ready` probe.
    #[tokio::test]
    async fn artifact_loader_bounds_size_before_reading() {
        let _guard = WORKSPACE_ARTIFACT_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.artifact");
        let file = std::fs::File::create(&path).unwrap();
        // Sparse file: metadata reports the size without committing bytes.
        file.set_len(MAX_ARTIFACT_BYTES as u64 + 1).unwrap();
        drop(file);

        let previous = std::env::var("WORKSPACE_ARTIFACT_PATH").ok();
        std::env::set_var("WORKSPACE_ARTIFACT_PATH", &path);
        let oversized = load_workspace_artifact();
        // A directory at the configured path is refused, not read.
        std::env::set_var("WORKSPACE_ARTIFACT_PATH", dir.path());
        let directory = load_workspace_artifact();
        match previous {
            Some(value) => std::env::set_var("WORKSPACE_ARTIFACT_PATH", value),
            None => std::env::remove_var("WORKSPACE_ARTIFACT_PATH"),
        }

        assert_eq!(oversized, Err(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(directory, Err(StatusCode::SERVICE_UNAVAILABLE));
    }

    /// The real loader refuses a symlinked or group-writable artifact. The
    /// manifest binds the recipient fingerprint the browser trusts, so a local
    /// writer must not be able to redirect or replace the artifact bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn artifact_loader_refuses_symlinked_and_group_writable_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let _guard = WORKSPACE_ARTIFACT_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.artifact");
        std::fs::write(&real, vec![0x11u8; crypto_envelope::MIN_ARTIFACT_LEN]).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.artifact");
        symlink(&real, &link).unwrap();

        let previous = std::env::var("WORKSPACE_ARTIFACT_PATH").ok();
        std::env::set_var("WORKSPACE_ARTIFACT_PATH", &link);
        let symlinked = load_workspace_artifact();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o660)).unwrap();
        std::env::set_var("WORKSPACE_ARTIFACT_PATH", &real);
        let group_writable = load_workspace_artifact();
        match previous {
            Some(value) => std::env::set_var("WORKSPACE_ARTIFACT_PATH", value),
            None => std::env::remove_var("WORKSPACE_ARTIFACT_PATH"),
        }

        assert_eq!(symlinked, Err(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(group_writable, Err(StatusCode::SERVICE_UNAVAILABLE));
    }

    /// The bounded read is capped at `max + 1` bytes even when the underlying
    /// reader yields more. This is the seam that closes the
    /// grow-between-metadata-and-read allocation hazard: the extra sentinel byte
    /// makes an over-limit file detectable without an unbounded read.
    #[test]
    fn bounded_artifact_read_is_capped_at_the_limit() {
        let over = read_bounded_bytes(std::io::Cursor::new(vec![0xabu8; 64]), 16).unwrap();
        assert_eq!(over.len(), 17, "reads exactly one past the bound");
        let at = read_bounded_bytes(std::io::Cursor::new(vec![0xabu8; 16]), 16).unwrap();
        assert_eq!(at.len(), 16);
        let under = read_bounded_bytes(std::io::Cursor::new(vec![0xabu8; 3]), 16).unwrap();
        assert_eq!(under.len(), 3);
        let empty = read_bounded_bytes(std::io::Cursor::new(Vec::<u8>::new()), 16).unwrap();
        assert!(empty.is_empty());
    }

    /// P0-C production-faithful test: the artifact bytes are produced by the
    /// real production build script (`scripts/build-workspace-encrypted.mjs`),
    /// read by the real `load_workspace_artifact` (no loader override), wrapped
    /// by the real per-grant HPKE transport over the real routes, then decrypted
    /// with the matching production-derived workspace key and unpacked with the
    /// production package layout. When the fixture also carries a release
    /// manifest, the real manifest-vs-artifact byte validation and recipient
    /// fingerprint are exercised on the matching path; the *rejection* path is
    /// proven by `recovery_challenge_refuses_a_self_enrolled_foreign_key` and the
    /// `release.rs` unit tests.
    ///
    /// Ignored by default because it needs a fixture produced by the Node build
    /// script; `scripts/verify-web-boundary.mjs` builds that fixture and runs
    /// this test with `--ignored`.
    #[tokio::test]
    #[ignore = "run by verify:web-boundary with WORKSPACE_BUILD_SCRIPT_FIXTURE set"]
    async fn production_build_script_artifact_loads_delivers_and_unpacks() {
        let _guard = WORKSPACE_ARTIFACT_ENV_LOCK.lock().await;
        let fixture_path = std::env::var("WORKSPACE_BUILD_SCRIPT_FIXTURE")
            .expect("WORKSPACE_BUILD_SCRIPT_FIXTURE must name the build-script fixture");
        let fixture_bytes = std::fs::read(&fixture_path).expect("fixture readable");
        let fixture: serde_json::Value =
            serde_json::from_slice(&fixture_bytes).expect("fixture json");
        let artifact_path = fixture["artifactPath"]
            .as_str()
            .expect("artifactPath")
            .to_string();
        // Optional: when verify:web-boundary also writes a release manifest the
        // test exercises the real manifest-vs-artifact/fingerprint preflight, not
        // just version/KID compatibility.
        let manifest_path = fixture["manifestPath"].as_str().map(str::to_string);
        let secret_bytes = release::decode_canonical_b64(
            fixture["secretB64"].as_str().expect("secretB64"),
            crypto_envelope::UNLOCK_SECRET_LEN,
        )
        .expect("fixture secret");
        let kid_bytes = release::decode_canonical_b64(
            fixture["kidB64"].as_str().expect("kidB64"),
            auth::WORKSPACE_KID_BYTES,
        )
        .expect("fixture kid");
        let secret: [u8; crypto_envelope::UNLOCK_SECRET_LEN] =
            secret_bytes.try_into().expect("secret length");
        let kid: [u8; auth::WORKSPACE_KID_BYTES] = kid_bytes.try_into().expect("kid length");
        let keypair =
            crypto_envelope::derive_workspace_keypair(&secret, auth::ARTIFACT_VERSION, &kid)
                .expect("derive workspace keypair");
        let expected_artifact = std::fs::read(&artifact_path).expect("artifact readable");

        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        // Guards restore the process env on drop, so a panic cannot leak global
        // state into other tests.
        let _manifest_guard = manifest_path
            .as_deref()
            .map(|path| EnvGuard::set("WORKSPACE_RELEASE_MANIFEST", Some(path)));
        let (state, client) = test_state(clock);
        if manifest_path.is_some() {
            assert!(
                state
                    .load_manifest()
                    .await
                    .expect("manifest loader")
                    .is_some(),
                "the production fixture must exercise the manifest preflight"
            );
        }

        let _artifact_guard =
            EnvGuard::set("WORKSPACE_ARTIFACT_PATH", Some(artifact_path.as_str()));
        let (session_cookie, grant_cookie, grant_id, (server_kid, server_pk)) =
            establish_session_and_grant(&state, &client).await;
        enroll_test_workspace(&state, &session_cookie, &keypair).await;
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
        let status = response.status();
        let delivered = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(status, StatusCode::OK, "real loader delivery must succeed");
        let envelope = crypto_envelope::Envelope {
            kid: delivered[..16].try_into().unwrap(),
            nonce: delivered[16..28].try_into().unwrap(),
            sequence: u64::from_be_bytes(delivered[28..36].try_into().unwrap()),
            ciphertext: delivered[36..].to_vec(),
        };
        let delivered_artifact = initiator.receive(&envelope).unwrap();
        assert_eq!(
            delivered_artifact, expected_artifact,
            "delivered bytes must equal the production build-script artifact"
        );
        let package = crypto_envelope::decrypt_artifact(&keypair, &delivered_artifact)
            .expect("inner artifact decrypt");
        let files = unpack_test_package(&package);
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            names.contains(&"index.html"),
            "production payload must contain index.html, got {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("assets/") && name.ends_with(".js")),
            "production payload must contain a hashed JS asset, got {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("assets/") && name.ends_with(".css")),
            "production payload must contain a hashed CSS asset, got {names:?}"
        );
        let index = files
            .iter()
            .find(|(name, _)| name == "index.html")
            .expect("index.html");
        assert!(!index.1.is_empty(), "index.html must not be empty");
    }

    // ---- F5 relay readiness tests ----

    #[tokio::test]
    async fn readiness_separates_liveness_from_dependency_health() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, _client) = test_state(clock);
        let keypair = test_keypair(0x91, 0x92);
        let package = pack_test_files(&[("index.html", b"ok")]);
        let artifact = crypto_envelope::seal_artifact(
            &keypair.public_key(),
            auth::ARTIFACT_VERSION,
            &keypair.kid(),
            &package,
        )
        .unwrap();
        let artifact_copy = artifact.clone();
        // Pin the manifest loader so `manifest_configured` is not racy against
        // other tests that mutate `WORKSPACE_RELEASE_MANIFEST`.
        let state = state
            .with_artifact_loader(Arc::new(move || Ok(artifact_copy.clone())))
            .with_manifest_loader(Arc::new(|| Ok(None)));

        let get = |app: Router, path: &'static str| async move {
            app.oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        // Liveness is unconditional; readiness reflects dependencies.
        assert_eq!(
            get(router(state.clone()), "/health").await.status(),
            StatusCode::OK
        );
        let ready = get(router(state.clone()), "/ready").await;
        assert_eq!(ready.status(), StatusCode::OK);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], true);
        assert_eq!(parsed["checks"]["relay"], true);
        // No immutable release manifest is configured, so the response says so
        // explicitly: the preflight is in the weaker version/KID-only mode.
        assert_eq!(parsed["manifest_configured"], false);

        // A configured manifest that matches the artifact header flips the flag
        // and keeps readiness healthy.
        let manifest = test_manifest(&artifact, &keypair);
        let configured = state
            .clone()
            .with_manifest_loader(Arc::new(move || Ok(Some(manifest.clone()))));
        let ready = get(router(configured), "/ready").await;
        assert_eq!(ready.status(), StatusCode::OK);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["manifest_configured"], true);
        assert_eq!(parsed["checks"]["release_manifest"], true);

        // Relay required but not yet bound: not ready, while liveness stays 200.
        let relay_flag = Arc::new(AtomicBool::new(false));
        let degraded = state.clone().with_relay_readiness(true, relay_flag.clone());
        assert_eq!(
            get(router(degraded), "/health").await.status(),
            StatusCode::OK
        );
        let ready = get(
            router(state.clone().with_relay_readiness(true, relay_flag)),
            "/ready",
        )
        .await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Artifact unavailable: not ready.
        let broken = state
            .clone()
            .with_artifact_loader(Arc::new(|| Err(StatusCode::SERVICE_UNAVAILABLE)));
        assert_eq!(
            get(router(broken), "/ready").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // Malformed artifact with no manifest configured: the header parse fails,
        // so readiness stays false rather than trusting an unparseable file.
        let malformed = state
            .clone()
            .with_artifact_loader(Arc::new(|| Ok(b"not-an-artifact".to_vec())));
        let ready = get(router(malformed), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(parsed["checks"]["artifact"], false);

        // Same-size corruption: a flipped ciphertext byte that keeps the header
        // and length intact must fail the full manifest SHA-256 validation, so
        // `/ready` cannot report the corrupted artifact as ready.
        let corrupted = {
            let mut bytes = artifact.clone();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            bytes
        };
        let manifest_for_original = test_manifest(&artifact, &keypair);
        let tampered = state
            .clone()
            .with_artifact_loader(Arc::new({
                let corrupted = corrupted.clone();
                move || Ok(corrupted.clone())
            }))
            .with_manifest_loader(Arc::new(move || Ok(Some(manifest_for_original.clone()))));
        let ready = get(router(tampered), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(
            parsed["checks"]["artifact"], false,
            "a same-size corrupted artifact must not be reported ready"
        );
        assert_eq!(parsed["manifest_configured"], true);

        // A header-length file whose public header is undeliverable (wrong
        // version / all-zero KID / all-zero encapsulated key) must not be
        // reported as a healthy artifact. The file is padded to
        // `MIN_ARTIFACT_LEN` so it passes the length predicate and actually
        // reaches `parse_artifact_header`; a 49-byte input would be rejected for
        // its length alone and never exercise the parser.
        for bad_header in [
            {
                let mut header = vec![0x11u8; crypto_envelope::MIN_ARTIFACT_LEN];
                header[0] = auth::ARTIFACT_VERSION + 1;
                header
            },
            {
                let mut header = vec![0x11u8; crypto_envelope::MIN_ARTIFACT_LEN];
                header[0] = auth::ARTIFACT_VERSION;
                header[1..1 + auth::WORKSPACE_KID_BYTES].fill(0);
                header
            },
            {
                let mut header = vec![0x11u8; crypto_envelope::MIN_ARTIFACT_LEN];
                header[0] = auth::ARTIFACT_VERSION;
                header[1 + auth::WORKSPACE_KID_BYTES..].fill(0);
                header
            },
        ] {
            let bad = state
                .clone()
                .with_artifact_loader(Arc::new(move || Ok(bad_header.clone())));
            let ready = get(router(bad), "/ready").await;
            assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = ready.into_body().collect().await.unwrap().to_bytes();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["ready"], false);
            assert_eq!(parsed["checks"]["artifact"], false);
        }

        // Dispatcher unavailable: the required command surface is not ready.
        let no_dispatcher = state
            .clone()
            .with_dispatcher_readiness(Arc::new(AtomicBool::new(false)));
        let ready = get(router(no_dispatcher), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(parsed["checks"]["dispatcher"], false);

        // A realtime source is not required by default, so an absent stream does
        // not fail readiness.
        let ready = get(router(state.clone()), "/ready").await;
        assert_eq!(ready.status(), StatusCode::OK);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["checks"]["stream"], true);

        // An unconfigured FOMO source is not a dependency.
        assert_eq!(parsed["checks"]["fomo_market"], true);

        // When the composition advertises realtime, a dead stream fails `/ready`
        // while `/health` stays live (liveness is not readiness).
        let dead_stream = state
            .clone()
            .with_stream_readiness(true, Arc::new(AtomicBool::new(false)));
        assert_eq!(
            get(router(dead_stream.clone()), "/health").await.status(),
            StatusCode::OK
        );
        let ready = get(router(dead_stream), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(parsed["checks"]["stream"], false);

        // A configured FOMO market source is a dependency even when its startup
        // auth/probe failed: `/health` stays live but `/ready` fails until the
        // bounded `/market/bars` history proof succeeds.
        let dead_fomo = state
            .clone()
            .with_fomo_readiness(true, Arc::new(AtomicBool::new(false)));
        assert_eq!(
            get(router(dead_fomo.clone()), "/health").await.status(),
            StatusCode::OK
        );
        let ready = get(router(dead_fomo), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(parsed["checks"]["fomo_market"], false);

        // A configured live execution path is a required dependency: an
        // unproven live path (for example a missing credential or unreachable
        // transport) fails `/ready` while `/health` stays live, and a proven one
        // passes. Without the explicit opt-in the dependency is absent.
        let unproven_live = state.clone().with_live_readiness(true, false);
        assert_eq!(
            get(router(unproven_live.clone()), "/health").await.status(),
            StatusCode::OK
        );
        let ready = get(router(unproven_live), "/ready").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], false);
        assert_eq!(parsed["checks"]["live_execution"], false);

        let proven_live = state.clone().with_live_readiness(true, true);
        let ready = get(router(proven_live), "/ready").await;
        assert_eq!(ready.status(), StatusCode::OK);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["ready"], true);
        assert_eq!(parsed["checks"]["live_execution"], true);

        // Not opted in: the live dependency is absent and does not gate readiness.
        let not_required = state.clone().with_live_readiness(false, false);
        let ready = get(router(not_required), "/ready").await;
        assert_eq!(ready.status(), StatusCode::OK);
        let body = ready.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["checks"]["live_execution"], true);
    }

    #[test]
    fn artifact_length_bound_is_exact() {
        // The readiness probe's test seam truncates to the header, so the real
        // minimum-length boundary is pinned here.
        assert!(artifact_length_is_deliverable(
            crypto_envelope::MIN_ARTIFACT_LEN as u64
        ));
        assert!(!artifact_length_is_deliverable(
            crypto_envelope::MIN_ARTIFACT_LEN as u64 - 1
        ));
        assert!(!artifact_length_is_deliverable(
            crypto_envelope::ARTIFACT_HEADER_LEN as u64
        ));
        assert!(artifact_length_is_deliverable(MAX_ARTIFACT_BYTES as u64));
        assert!(!artifact_length_is_deliverable(
            MAX_ARTIFACT_BYTES as u64 + 1
        ));
    }

    // ---- Passkey-bound recovery wrapper tests ----

    fn recovery_state(
        clock: Arc<FixedClock>,
    ) -> (PrivateApiState, TestRegistrationClient, tempfile::TempDir) {
        let (state, client) = test_state(clock);
        let directory = tempfile::tempdir().unwrap();
        // `tempfile` honours `$TMPDIR`, which may be group/world-writable; the
        // store refuses such a parent, so create an explicitly private one.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let store = FileRecoveryWrapperStore::open(directory.path().join("recovery.json")).unwrap();
        (
            state.with_recovery_store(Arc::new(store)),
            client,
            directory,
        )
    }

    fn test_manifest(
        artifact: &[u8],
        keypair: &crypto_envelope::WorkspaceUnlockKeyPair,
    ) -> release::ReleaseManifest {
        release::ReleaseManifest {
            manifest_version: release::MANIFEST_VERSION,
            release_id: "release-recovery-test".into(),
            source_sha: "9a5a712".into(),
            artifact: release::ManifestArtifact {
                version: auth::ARTIFACT_VERSION,
                kid_b64: base64_encode(&keypair.kid()),
                sha256_hex: release::sha256_hex(artifact),
                size: artifact.len() as u64,
                package_format_version: release::PACKAGE_FORMAT_VERSION,
            },
            recipient: release::ManifestRecipient {
                public_key_fingerprint_b64: release::public_key_fingerprint_b64(
                    &keypair.public_key_bytes(),
                ),
            },
            workspace_protocol: release::ManifestProtocol {
                min: release::WORKSPACE_PROTOCOL_VERSION,
                max: release::WORKSPACE_PROTOCOL_VERSION,
            },
            shell: None,
        }
    }

    async fn issue_recovery(state: &PrivateApiState, session_cookie: &str) -> (String, Vec<u8>) {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/workspace/recovery/challenge")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "recovery challenge body: {}",
            String::from_utf8_lossy(&body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (
            parsed["challenge_id"].as_str().unwrap().to_string(),
            base64::decode::<97>(parsed["sealed_challenge_b64"].as_str().unwrap()).to_vec(),
        )
    }

    /// Stable workspace root keypair for a test root secret under the fixed
    /// protocol context. It never depends on a release KID, so the identity is
    /// identical across releases.
    fn test_root_keypair(secret_byte: u8) -> crypto_envelope::WorkspaceUnlockKeyPair {
        crypto_envelope::derive_workspace_keypair(
            &[secret_byte; crypto_envelope::UNLOCK_SECRET_LEN],
            auth::ARTIFACT_VERSION,
            &recovery::WORKSPACE_ROOT_CONTEXT_KID,
        )
        .unwrap()
    }

    fn v2_wrapper_json(credential_byte: u8) -> serde_json::Value {
        serde_json::json!({
            "credential_id_b64": base64_encode(&[credential_byte; 32]),
            "label": "Test device",
            "version": recovery::RECOVERY_WRAPPER_VERSION,
            "algorithm": recovery::RECOVERY_ALGORITHM,
            "key_source": recovery::RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2,
            "salt_b64": base64_encode(&[0x22; recovery::RECOVERY_SALT_BYTES]),
            "iv_b64": base64_encode(&[0x33; recovery::RECOVERY_IV_BYTES]),
            "wrapped_root_key_b64": base64_encode(&[0x44; recovery::WRAPPED_ROOT_KEY_BYTES]),
        })
    }

    /// One-time initial setup: upload only the public identity + opaque wrappers.
    async fn bootstrap_identity(
        state: &PrivateApiState,
        session_cookie: &str,
        keypair: &crypto_envelope::WorkspaceUnlockKeyPair,
    ) -> Response {
        let body = serde_json::json!({
            "version": recovery::WORKSPACE_IDENTITY_VERSION,
            "public_key": base64_encode(&keypair.public_key_bytes()),
            "wrappers": [v2_wrapper_json(0x10)],
        });
        post_json(state, session_cookie, "/internal/workspace/identity", body).await
    }

    async fn get_identity(
        state: &PrivateApiState,
        session_cookie: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/identity")
                    .header(header::COOKIE, session_cookie.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn wrapper_body(challenge_id: &str, proof_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "challenge_id": challenge_id,
            "proof_b64": proof_b64,
            "wrapper": v2_wrapper_json(0x11),
        })
    }

    async fn post_json(
        state: &PrivateApiState,
        session_cookie: &str,
        uri: &'static str,
        body: serde_json::Value,
    ) -> Response {
        router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.to_string())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn recovery_wrapper_lifecycle_requires_proof_of_possession() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client, _directory) = recovery_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;
        let keypair = test_root_keypair(0x91);
        assert_eq!(
            bootstrap_identity(&state, &session_cookie, &keypair)
                .await
                .status(),
            StatusCode::OK
        );

        // Add a wrapper using a valid proof of possession. The challenge is
        // sealed to the durable workspace identity, so only the holder of the
        // stable root can open it.
        let (challenge_id, sealed) = issue_recovery(&state, &session_cookie).await;
        let nonce = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        let proof = base64_encode(&nonce);
        let response = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery",
            wrapper_body(&challenge_id, &proof),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The wrapper is listed (public metadata + opaque ciphertext only).
        let listed = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/recovery")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let body = listed.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["wrappers"].as_array().unwrap().len(), 2);
        assert!(parsed["wrappers"].as_array().unwrap().iter().all(
            |wrapper| wrapper["key_source"] == recovery::RECOVERY_KEY_SOURCE_WORKSPACE_ROOT_V2
        ));
        assert!(parsed["wrappers"][0]["wrapped_root_key_b64"].is_string());

        // A wrong proof is rejected and consumes the challenge.
        let (wrong_challenge_id, wrong_sealed) = issue_recovery(&state, &session_cookie).await;
        let correct_nonce = crypto_envelope::decrypt_artifact(&keypair, &wrong_sealed).unwrap();
        let wrong = base64_encode(&[0u8; recovery::RECOVERY_CHALLENGE_BYTES]);
        let response = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery",
            wrapper_body(&wrong_challenge_id, &wrong),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // The consumed challenge cannot be replayed even with the correct nonce.
        let replay = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery",
            wrapper_body(&wrong_challenge_id, &base64_encode(&correct_nonce)),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        // Revoke needs a fresh proof.
        let (challenge_id, sealed) = issue_recovery(&state, &session_cookie).await;
        let nonce = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        let revoke = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery/revoke",
            serde_json::json!({
                "challenge_id": challenge_id,
                "proof_b64": base64_encode(&nonce),
                "credential_id_b64": base64_encode(&[0x11; 32]),
            }),
        )
        .await;
        assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn recovery_challenge_requires_a_durable_workspace_identity() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client, _directory) = recovery_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;

        // No identity yet: recovery mutation is closed, not silently allowed.
        let missing = post_raw(
            &state,
            &session_cookie,
            "/internal/workspace/recovery/challenge",
        )
        .await;
        assert_eq!(missing.status(), StatusCode::CONFLICT);
        let body = missing.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["code"], "workspace_identity_required");

        // Unauthenticated callers are rejected before any check.
        let anonymous = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/workspace/recovery/challenge")
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        // After bootstrap the challenge is a full-size sealed nonce that only the
        // stable root can open.
        let keypair = test_root_keypair(0x93);
        assert_eq!(
            bootstrap_identity(&state, &session_cookie, &keypair)
                .await
                .status(),
            StatusCode::OK
        );
        let (challenge_id, sealed) = issue_recovery(&state, &session_cookie).await;
        assert_eq!(
            challenge_id.len(),
            recovery::RECOVERY_CHALLENGE_ID_BYTES * 2
        );
        assert_eq!(sealed.len(), 97);
        let nonce = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        assert_eq!(nonce.len(), recovery::RECOVERY_CHALLENGE_BYTES);
    }

    async fn post_raw(
        state: &PrivateApiState,
        session_cookie: &str,
        uri: &'static str,
    ) -> Response {
        router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                    .header(header::COOKIE, session_cookie.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Create-once is the self-approval defence: a caller that controls a
    /// different workspace key cannot replace the durable identity (and so
    /// cannot make the server seal recovery challenges to a key they hold),
    /// because bootstrap refuses once an identity exists.
    #[tokio::test]
    async fn workspace_identity_bootstrap_is_create_once_and_public_only() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client, _directory) = recovery_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;
        let released = test_root_keypair(0x95);

        // Before bootstrap the identity is explicitly unconfigured.
        let (status, body) = get_identity(&state, &session_cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configured"], false);
        assert!(body["public_key_b64"].is_null());

        assert_eq!(
            bootstrap_identity(&state, &session_cookie, &released)
                .await
                .status(),
            StatusCode::OK
        );

        let (status, body) = get_identity(&state, &session_cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configured"], true);
        assert_eq!(
            body["fingerprint_b64"],
            release::public_key_fingerprint_b64(&released.public_key_bytes())
        );
        // Public metadata only: no secret-shaped field is ever returned.
        for forbidden in [
            "root_secret",
            "recovery_code",
            "prf_output",
            "unwrap_key",
            "private_key",
        ] {
            assert!(
                body.get(forbidden).is_none(),
                "identity response must not expose {forbidden}"
            );
        }

        // A second bootstrap with a different key cannot replace the identity.
        let attacker = test_root_keypair(0xA1);
        let replace = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/identity",
            serde_json::json!({
                "version": recovery::WORKSPACE_IDENTITY_VERSION,
                "public_key": base64_encode(&attacker.public_key_bytes()),
                "wrappers": [v2_wrapper_json(0x12)],
            }),
        )
        .await;
        assert_eq!(replace.status(), StatusCode::CONFLICT);
        let (_, body) = get_identity(&state, &session_cookie).await;
        assert_eq!(
            body["fingerprint_b64"],
            release::public_key_fingerprint_b64(&released.public_key_bytes())
        );

        // A challenge still opens only with the original stable root.
        let (_, sealed) = issue_recovery(&state, &session_cookie).await;
        assert!(crypto_envelope::decrypt_artifact(&released, &sealed).is_ok());
        assert!(crypto_envelope::decrypt_artifact(&attacker, &sealed).is_err());
    }

    /// The bootstrap API must reject any attempt to smuggle plaintext secret
    /// material, and must only accept stable `workspace_root_v2` wrappers.
    #[tokio::test]
    async fn workspace_identity_bootstrap_rejects_secret_fields_and_legacy_wrappers() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client, _directory) = recovery_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;
        let keypair = test_root_keypair(0x92);
        let public_key = base64_encode(&keypair.public_key_bytes());

        // A secret field a client might try to send is refused outright by
        // `deny_unknown_fields`, so the server never even reads it.
        for (field, value) in [
            ("root_secret", serde_json::json!(base64_encode(&[0x77; 32]))),
            (
                "recovery_code",
                serde_json::json!(base64_encode(&[0x77; 32])),
            ),
            ("prf_output", serde_json::json!(base64_encode(&[0x77; 32]))),
            ("unwrap_key", serde_json::json!(base64_encode(&[0x77; 32]))),
        ] {
            let mut body = serde_json::json!({
                "version": recovery::WORKSPACE_IDENTITY_VERSION,
                "public_key": public_key.clone(),
                "wrappers": [v2_wrapper_json(0x11)],
            });
            body[field] = value;
            let response = post_json(
                &state,
                &session_cookie,
                "/internal/workspace/identity",
                body,
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{field} must be refused"
            );
        }

        // A legacy `unlock_secret_v1` wrapper is never part of a new workspace root.
        let mut legacy = v2_wrapper_json(0x11);
        legacy["key_source"] = serde_json::json!(recovery::RECOVERY_KEY_SOURCE_UNLOCK_SECRET_V1);
        let response = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/identity",
            serde_json::json!({
                "version": recovery::WORKSPACE_IDENTITY_VERSION,
                "public_key": public_key.clone(),
                "wrappers": [legacy],
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // An all-zero public key is refused.
        let response = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/identity",
            serde_json::json!({
                "version": recovery::WORKSPACE_IDENTITY_VERSION,
                "public_key": base64_encode(&[0u8; recovery::WORKSPACE_PUBLIC_KEY_BYTES]),
                "wrappers": [v2_wrapper_json(0x11)],
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn recovery_touch_requires_proof_of_possession() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client, _directory) = recovery_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;
        let keypair = test_root_keypair(0x97);
        assert_eq!(
            bootstrap_identity(&state, &session_cookie, &keypair)
                .await
                .status(),
            StatusCode::OK
        );

        // Add a wrapper so there is something to touch.
        let (challenge_id, sealed) = issue_recovery(&state, &session_cookie).await;
        let nonce = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        let response = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery",
            wrapper_body(&challenge_id, &base64_encode(&nonce)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // A bare session cannot forge the last-used signal.
        let unproven = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery/touch",
            serde_json::json!({
                "challenge_id": "00",
                "proof_b64": base64_encode(&[0u8; recovery::RECOVERY_CHALLENGE_BYTES]),
                "credential_id_b64": base64_encode(&[0x11; 32]),
            }),
        )
        .await;
        assert_eq!(unproven.status(), StatusCode::UNAUTHORIZED);

        // With a real proof it succeeds.
        let (challenge_id, sealed) = issue_recovery(&state, &session_cookie).await;
        let nonce = crypto_envelope::decrypt_artifact(&keypair, &sealed).unwrap();
        let proven = post_json(
            &state,
            &session_cookie,
            "/internal/workspace/recovery/touch",
            serde_json::json!({
                "challenge_id": challenge_id,
                "proof_b64": base64_encode(&nonce),
                "credential_id_b64": base64_encode(&[0x11; 32]),
            }),
        )
        .await;
        assert_eq!(proven.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn recovery_surface_is_closed_without_a_store() {
        let clock = Arc::new(FixedClock(AtomicI64::new(1_000)));
        let (state, client) = test_state(clock);
        let (session_cookie, _grant_cookie, _grant_id, _offer) =
            establish_session_and_grant(&state, &client).await;
        assert!(!state.recovery_enabled());
        let response = post_raw(
            &state,
            &session_cookie,
            "/internal/workspace/recovery/challenge",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let listed = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/workspace/recovery")
                    .header(header::COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod operator_secret_file_tests {
    use super::*;
    use std::io::Write;

    #[cfg(unix)]
    fn write_secret(dir: &std::path::Path, name: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"  secret-value\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn reads_and_trims_an_owner_only_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret(dir.path(), "key", 0o600);
        let value = read_operator_secret_file(&path).unwrap();
        assert_eq!(value.as_str(), "secret-value");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_group_or_world_readable_secret() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o644] {
            let path = write_secret(dir.path(), &format!("key-{mode:o}"), mode);
            assert!(
                read_operator_secret_file(&path).is_err(),
                "mode {mode:o} must be refused"
            );
        }
    }

    #[test]
    fn refuses_a_missing_empty_or_oversized_secret() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_operator_secret_file(&dir.path().join("absent")).is_err());
        for (name, bytes) in [("empty", vec![b' '; 4]), ("big", vec![b'a'; 5000])] {
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(read_operator_secret_file(&path).is_err(), "{name}");
        }
    }
}
