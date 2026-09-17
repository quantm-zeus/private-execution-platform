//! Concrete production transports for the one-chain live execution path.
//!
//! This module supplies the real, compiled adapters the typed capability gates
//! were previously missing: a retry-free Base JSON-RPC transport, a Privy HTTP
//! signing client, an HTTP signed-payload (transaction builder) source, and the
//! composition that assembles them into the production relay.
//!
//! # Safety posture
//!
//! * Every adapter is constructed and probed only behind the existing
//!   `TRADING_CORE_LIVE` composition gate, and `TRADING_ENABLED` remains the
//!   authoritative policy kill switch. Nothing here enables trading, signs, or
//!   broadcasts: a healthy probe merely lets the typed readiness surface prove
//!   the dependency.
//! * A missing or unreadable credential is never defaulted: the caller omits the
//!   transport, so the corresponding dependency stays unproven and the
//!   capability is denied.
//! * Endpoints are validated. Only a loopback `http://` endpoint is accepted
//!   (the repository's "every PEP listener on loopback" posture); a remote
//!   provider must be fronted by the operator's local authenticating gateway so
//!   a bearer credential is never sent in cleartext off-host.
//! * Errors are redacted: no endpoint, credential, payload, or upstream body is
//!   ever rendered.
//! * No retries anywhere: each call performs exactly one request.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chain_adapters::{
    BaseChainSubmissionAdapter, BaseChainTransport, ChainAdapterError, ReceiptObservation,
    ReceiptStatus, TokenMetadata,
};
use chain_types::ChainId;
use domain::{IdempotencyKey, IntentId};
use execution_relay::{
    ChainHealthBreaker, DurableAttemptStore, RelayError, SignedExecutionRef, SignedPayload,
    SignedPayloadSource,
};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use market_types::Bps;
use policy::{PolicyEngine, PolicyLimits, UsdMicros};
use privy::{PrivyCredentials, PrivyError, PrivyHttpClient, ProviderIdempotencyId, SigningRequest};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::Zeroizing;

/// Upper bound on any live transport response body (2 MiB).
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// The canonical Base chain id the submission adapter must report healthy.
const BASE_CHAIN_ID: u64 = 8453;

/// Fail-closed transport configuration error. Redacted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum LiveTransportError {
    /// The endpoint or credential configuration is invalid.
    #[error("live transport configuration invalid")]
    InvalidConfiguration,
}

/// Redacted transport-level failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportError {
    /// The endpoint could not be reached.
    Unavailable,
    /// The endpoint did not answer within the bounded timeout.
    Timeout,
    /// The peer answered with a definitive 4xx rejection.
    Rejected,
    /// The answer could not be decoded.
    InvalidResponse,
    /// The endpoint configuration is invalid.
    InvalidConfiguration,
}

/// Validates an operator-supplied endpoint.
///
/// Only a loopback `http://` endpoint is accepted. The repository's deployment
/// posture keeps every PEP listener on loopback and terminates remote transport
/// security in an operator-controlled local gateway; accepting a remote
/// cleartext endpoint would send a bearer credential off-host in the clear, and
/// a direct TLS client stack is deliberately not linked here. Userinfo, query
/// and fragment are always refused.
fn validated_endpoint(value: &str) -> Result<String, TransportError> {
    let base = value.trim().trim_end_matches('/').to_string();
    if base.is_empty() || base.len() > 512 {
        return Err(TransportError::InvalidConfiguration);
    }
    let rest = base
        .strip_prefix("http://")
        .ok_or(TransportError::InvalidConfiguration)?;
    if rest.is_empty() || rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err(TransportError::InvalidConfiguration);
    }
    let authority = rest.split('/').next().unwrap_or("");
    let host = host_of(authority)?;
    if !is_loopback_host(host) {
        return Err(TransportError::InvalidConfiguration);
    }
    Ok(base)
}

/// Extracts the host from an authority (`host`, `host:port`, `[v6]:port`).
fn host_of(authority: &str) -> Result<&str, TransportError> {
    if authority.is_empty() {
        return Err(TransportError::InvalidConfiguration);
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or(TransportError::InvalidConfiguration)?;
        return Ok(&authority[..=end + 1]);
    }
    let host = authority.split(':').next().unwrap_or("");
    if host.is_empty() {
        return Err(TransportError::InvalidConfiguration);
    }
    Ok(host)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host,
        "127.0.0.1" | "localhost" | "[::1]" | "[0:0:0:0:0:0:0:1]"
    )
}

/// Bounded, retry-free JSON-over-HTTP transport.
///
/// `Debug` is redacted: it never renders the endpoint or the bearer credential.
struct JsonHttpTransport {
    client: HyperClient<HttpConnector, Full<Bytes>>,
    base_url: String,
    bearer: Option<Zeroizing<String>>,
    timeout: Duration,
}

impl std::fmt::Debug for JsonHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JsonHttpTransport")
            .field("bearer", &self.bearer.is_some())
            .finish_non_exhaustive()
    }
}

impl JsonHttpTransport {
    fn new(
        base_url: &str,
        bearer: Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::InvalidConfiguration);
        }
        let base_url = validated_endpoint(base_url)?;
        let mut http = HttpConnector::new();
        http.enforce_http(true);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(timeout));
        let client = HyperClient::builder(TokioExecutor::new()).build(http);
        Ok(Self {
            client,
            base_url,
            bearer,
            timeout,
        })
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, TransportError> {
        let uri = format!("{}{}", self.base_url, path);
        let mut builder = Request::builder()
            .method(method)
            .uri(&uri)
            .header("accept", "application/json");
        if let Some(token) = self.bearer.as_ref() {
            builder = builder.header("authorization", format!("Bearer {}", token.as_str()));
        }
        let request = match body {
            Some(value) => {
                let bytes =
                    serde_json::to_vec(value).map_err(|_| TransportError::InvalidResponse)?;
                builder
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(bytes)))
            }
            None => builder.body(Full::new(Bytes::new())),
        }
        .map_err(|_| TransportError::InvalidConfiguration)?;

        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Unavailable)?;
        let status = response.status();
        let body = tokio::time::timeout(self.timeout, async {
            let mut collected = Vec::new();
            let mut stream = response.into_body();
            while let Some(frame) = stream.frame().await {
                let frame = frame.map_err(|_| TransportError::Unavailable)?;
                if let Some(chunk) = frame.data_ref() {
                    if collected.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                        return Err(TransportError::InvalidResponse);
                    }
                    collected.extend_from_slice(chunk);
                }
            }
            Ok::<Vec<u8>, TransportError>(collected)
        })
        .await
        .map_err(|_| TransportError::Timeout)??;

        if !status.is_success() {
            return Err(if status.is_client_error() {
                TransportError::Rejected
            } else {
                TransportError::Unavailable
            });
        }
        serde_json::from_slice(&body).map_err(|_| TransportError::InvalidResponse)
    }

    async fn get_json(&self, path: &str) -> Result<Value, TransportError> {
        self.request("GET", path, None).await
    }

    async fn post_json(&self, path: &str, value: &Value) -> Result<Value, TransportError> {
        self.request("POST", path, Some(value)).await
    }
}

// ---------------------------------------------------------------------------
// Shared EVM JSON-RPC transport (Base, Ethereum, BNB Chain)
// ---------------------------------------------------------------------------

/// Concrete, retry-free EVM JSON-RPC transport.
///
/// It implements the shared `EvmChainTransport` seam over a single JSON-RPC
/// endpoint and is chain-agnostic: the same type serves Base, Ethereum and BNB
/// Chain, and the [`BaseChainSubmissionAdapter`] (or
/// `chain_adapters::EvmChainSubmissionAdapter::for_chain`) binds and verifies
/// the expected `eth_chainId`. It never retries: every method performs exactly
/// one HTTP request.
///
/// `BaseRpcChainTransport` remains as a compatibility alias.
pub struct EvmRpcChainTransport {
    rpc: JsonHttpTransport,
}

/// Compatibility alias for the original Base-only transport name.
pub type BaseRpcChainTransport = EvmRpcChainTransport;

impl std::fmt::Debug for EvmRpcChainTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EvmRpcChainTransport { .. }")
    }
}

impl EvmRpcChainTransport {
    /// Wires the transport to an operator endpoint and optional bearer token.
    pub fn new(
        endpoint: &str,
        bearer: Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Self, ChainAdapterError> {
        let rpc = JsonHttpTransport::new(endpoint, bearer, timeout)
            .map_err(|_| ChainAdapterError::TransportUnavailable)?;
        Ok(Self { rpc })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, ChainAdapterError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response = self
            .rpc
            .post_json("/", &body)
            .await
            .map_err(|error| match error {
                TransportError::Rejected => ChainAdapterError::Rejected,
                TransportError::Timeout => ChainAdapterError::Timeout,
                TransportError::InvalidResponse => ChainAdapterError::InvalidResponse,
                _ => ChainAdapterError::TransportUnavailable,
            })?;
        if response.get("error").is_some_and(|error| !error.is_null()) {
            return Err(ChainAdapterError::Rejected);
        }
        response
            .get("result")
            .cloned()
            .ok_or(ChainAdapterError::InvalidResponse)
    }
}

#[async_trait]
impl BaseChainTransport for EvmRpcChainTransport {
    async fn chain_id(&self) -> Result<u64, ChainAdapterError> {
        let result = self.rpc("eth_chainId", json!([])).await?;
        parse_u64_hex(&result)
    }

    async fn block_number(&self) -> Result<u64, ChainAdapterError> {
        let result = self.rpc("eth_blockNumber", json!([])).await?;
        parse_u64_hex(&result)
    }

    async fn call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, ChainAdapterError> {
        let params = json!([{ "to": to, "data": hex_encode(data) }, "latest"]);
        let result = self.rpc("eth_call", params).await?;
        let encoded = result.as_str().ok_or(ChainAdapterError::InvalidResponse)?;
        hex_decode(encoded).ok_or(ChainAdapterError::InvalidResponse)
    }

    async fn erc20_balance(&self, token: &str, owner: &str) -> Result<u128, ChainAdapterError> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&hex_decode(ERC20_BALANCE_OF).expect("constant selector"));
        data.extend_from_slice(&address_word(owner)?);
        let returned = self.call(token, &data).await?;
        parse_word_u128(&returned)
    }

    async fn erc20_metadata(&self, token: &str) -> Result<TokenMetadata, ChainAdapterError> {
        let symbol_bytes = self
            .call(token, &hex_decode(ERC20_SYMBOL).expect("constant selector"))
            .await?;
        let symbol = decode_abi_string(&symbol_bytes).ok_or(ChainAdapterError::InvalidResponse)?;
        let decimals_bytes = self
            .call(
                token,
                &hex_decode(ERC20_DECIMALS).expect("constant selector"),
            )
            .await?;
        let decimals = parse_word_u128(&decimals_bytes)?;
        let decimals = u8::try_from(decimals).map_err(|_| ChainAdapterError::InvalidResponse)?;
        Ok(TokenMetadata { symbol, decimals })
    }

    async fn send_raw_transaction(&self, raw: &[u8]) -> Result<String, ChainAdapterError> {
        let result = self
            .rpc("eth_sendRawTransaction", json!([hex_encode(raw)]))
            .await?;
        result
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or(ChainAdapterError::InvalidResponse)
    }

    async fn transaction_receipt(
        &self,
        reference: &str,
    ) -> Result<Option<ReceiptObservation>, ChainAdapterError> {
        let result = self
            .rpc("eth_getTransactionReceipt", json!([reference]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let status = match result.get("status").and_then(Value::as_str) {
            Some("0x1") => ReceiptStatus::Success,
            _ => ReceiptStatus::Reverted,
        };
        // A receipt carries no exact realized amounts for the bound intent; the
        // relay records a confirmation with `fill: None` and the consumer
        // reconciles for evidence instead of fabricating a fill.
        Ok(Some(ReceiptObservation {
            status,
            net_input: None,
            net_output: None,
        }))
    }
}

const ERC20_BALANCE_OF: &str = "0x70a08231";
const ERC20_SYMBOL: &str = "0x95d89b41";
const ERC20_DECIMALS: &str = "0x313ce567";

fn address_word(address: &str) -> Result<[u8; 32], ChainAdapterError> {
    let bytes = hex_decode(address).ok_or(ChainAdapterError::InvalidResponse)?;
    if bytes.len() != 20 {
        return Err(ChainAdapterError::InvalidResponse);
    }
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&bytes);
    Ok(word)
}

fn parse_u64_hex(value: &Value) -> Result<u64, ChainAdapterError> {
    let encoded = value.as_str().ok_or(ChainAdapterError::InvalidResponse)?;
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    u64::from_str_radix(encoded, 16).map_err(|_| ChainAdapterError::InvalidResponse)
}

fn parse_word_u128(bytes: &[u8]) -> Result<u128, ChainAdapterError> {
    if bytes.len() < 16 {
        return Err(ChainAdapterError::InvalidResponse);
    }
    let mut word = [0u8; 16];
    word.copy_from_slice(&bytes[bytes.len() - 16..]);
    // Any non-zero byte above the low 128 bits is an out-of-range value.
    if bytes[..bytes.len() - 16].iter().any(|byte| *byte != 0) {
        return Err(ChainAdapterError::InvalidResponse);
    }
    Ok(u128::from_be_bytes(word))
}

/// Decodes a standard ABI `string` return, also tolerating a right-padded
/// `bytes32` symbol.
fn decode_abi_string(data: &[u8]) -> Option<String> {
    if data.len() < 64 {
        let trimmed: Vec<u8> = data.iter().copied().take_while(|byte| *byte != 0).collect();
        return String::from_utf8(trimmed).ok();
    }
    let offset = word_to_usize(data.get(0..32)?)?;
    let length = word_to_usize(data.get(offset..offset.checked_add(32)?)?)?;
    let start = offset.checked_add(32)?;
    let end = start.checked_add(length)?;
    // `get` keeps a hostile ABI offset/length from panicking the process.
    let encoded = data.get(start..end)?;
    String::from_utf8(encoded.to_vec()).ok()
}

fn word_to_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&word[24..]);
    usize::try_from(u64::from_be_bytes(value)).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 || !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Privy HTTP signing client
// ---------------------------------------------------------------------------

/// Concrete [`PrivyHttpClient`] over a bounded HTTPS/loopback-HTTP transport.
///
/// The credential is held only inside the redacted transport; it is sent as a
/// bearer token and never rendered.
pub struct HttpPrivyClient {
    rpc: JsonHttpTransport,
}

impl std::fmt::Debug for HttpPrivyClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HttpPrivyClient { .. }")
    }
}

impl HttpPrivyClient {
    /// Wires the client from an endpoint and operator credentials.
    pub fn new(
        endpoint: &str,
        credentials: PrivyCredentials,
        timeout: Duration,
    ) -> Result<Self, PrivyError> {
        let bearer = Zeroizing::new(credentials.expose().to_string());
        let rpc = JsonHttpTransport::new(endpoint, Some(bearer), timeout)
            .map_err(|_| PrivyError::SigningUnavailable)?;
        Ok(Self { rpc })
    }

    /// Bounded connectivity/credential presence probe (`GET /health`).
    pub async fn health(&self) -> bool {
        self.rpc.get_json("/health").await.is_ok()
    }
}

/// Builds the provider-facing signing-request body.
///
/// Pure and credential-free, so the bound field contract is unit-testable
/// without a network or a signer.
fn signing_request_body(
    request: &SigningRequest,
    idempotency: &ProviderIdempotencyId,
) -> Result<Value, PrivyError> {
    let chain_tag =
        privy::canonical_chain_tag(request.chain()).map_err(|_| PrivyError::UnsupportedChain)?;
    Ok(json!({
        "intent_id": request.intent_id().as_str(),
        "idempotency_key": request.idempotency_key().as_str(),
        "wallet_ref": request.wallet_ref().as_str(),
        "request_digest": hex_encode(request.request_digest().as_bytes()),
        "payload_digest": hex_encode(request.payload_digest().as_bytes()),
        "chain_tag": chain_tag,
        "provider_idempotency_id": idempotency.as_str(),
    }))
}

#[async_trait]
impl PrivyHttpClient for HttpPrivyClient {
    async fn submit_signing_request(
        &self,
        request: &SigningRequest,
        idempotency: &ProviderIdempotencyId,
    ) -> Result<String, PrivyError> {
        let body = signing_request_body(request, idempotency)?;
        let response = self
            .rpc
            .post_json("/v1/signing-requests", &body)
            .await
            .map_err(|error| match error {
                TransportError::Rejected => PrivyError::SignerRejected,
                _ => PrivyError::SigningUnavailable,
            })?;
        response
            .get("reference")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or(PrivyError::SigningUnavailable)
    }
}

// ---------------------------------------------------------------------------
// HTTP signed-payload source
// ---------------------------------------------------------------------------

/// Concrete [`SignedPayloadSource`] over an operator transaction-builder
/// endpoint.
///
/// The builder service returns `{ "payload_hex": "0x..." }` for the bound
/// `(idempotency_key, intent_id)` (pre-sign) or signed reference (post-sign).
/// The returned bytes are re-validated by [`SignedPayload::new`].
pub struct HttpSignedPayloadSource {
    rpc: JsonHttpTransport,
}

impl std::fmt::Debug for HttpSignedPayloadSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HttpSignedPayloadSource { .. }")
    }
}

impl HttpSignedPayloadSource {
    /// Wires the source from an endpoint and optional bearer token.
    pub fn new(
        endpoint: &str,
        bearer: Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Self, RelayError> {
        let rpc = JsonHttpTransport::new(endpoint, bearer, timeout)
            .map_err(|_| RelayError::MissingSignedPayload)?;
        Ok(Self { rpc })
    }

    /// Bounded connectivity probe (`GET /health`).
    pub async fn health(&self) -> bool {
        self.rpc.get_json("/health").await.is_ok()
    }

    async fn fetch(&self, path: &str) -> Result<SignedPayload, RelayError> {
        let value = self
            .rpc
            .get_json(path)
            .await
            .map_err(|_| RelayError::MissingSignedPayload)?;
        let encoded = value
            .get("payload_hex")
            .and_then(Value::as_str)
            .ok_or(RelayError::MissingSignedPayload)?;
        let bytes = hex_decode(encoded).ok_or(RelayError::MissingSignedPayload)?;
        SignedPayload::new(bytes)
    }
}

#[async_trait]
impl SignedPayloadSource for HttpSignedPayloadSource {
    async fn payload_to_sign(
        &self,
        key: &IdempotencyKey,
        intent_id: &IntentId,
    ) -> Result<SignedPayload, RelayError> {
        self.fetch(&format!(
            "/v1/payload-to-sign?idempotency_key={}&intent_id={}",
            percent_encode(key.as_str()),
            percent_encode(intent_id.as_str())
        ))
        .await
    }

    async fn signed_payload(
        &self,
        signed: &SignedExecutionRef,
    ) -> Result<SignedPayload, RelayError> {
        self.fetch(&format!(
            "/v1/signed-payload?reference={}",
            percent_encode(signed.reference())
        ))
        .await
    }
}

/// Percent-encodes a query value, leaving only RFC 3986 unreserved bytes.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Composition and probes
// ---------------------------------------------------------------------------

/// Resolved operator configuration for the concrete live transports.
pub struct LiveTransportConfig {
    pub base_rpc_endpoint: String,
    pub base_rpc_bearer: Option<Zeroizing<String>>,
    pub privy_endpoint: String,
    pub privy_credentials: PrivyCredentials,
    pub payload_endpoint: String,
    pub payload_bearer: Option<Zeroizing<String>>,
    pub request_timeout: Duration,
}

/// The concrete live transports plus the composed chain submission adapter.
pub struct LiveTransports {
    /// The shared EVM JSON-RPC transport used by the probes. It is deliberately
    /// chain-agnostic; `chain_submission` binds and verifies the Base chain id.
    pub chain: Arc<EvmRpcChainTransport>,
    /// The relay-facing chain submission adapter (wraps `chain`).
    pub chain_submission: Arc<dyn execution_relay::ChainSubmissionAdapter>,
    /// The Privy signing client.
    pub privy: Arc<HttpPrivyClient>,
    /// The signed-payload source.
    pub payload: Arc<HttpSignedPayloadSource>,
}

impl std::fmt::Debug for LiveTransports {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LiveTransports { .. }")
    }
}

/// Builds the concrete transports. Any invalid endpoint is a determinate
/// configuration error, never a partially-wired live path.
pub async fn build_live_transports(
    config: LiveTransportConfig,
) -> Result<LiveTransports, LiveTransportError> {
    let chain = Arc::new(
        EvmRpcChainTransport::new(
            &config.base_rpc_endpoint,
            config.base_rpc_bearer,
            config.request_timeout,
        )
        .map_err(|_| LiveTransportError::InvalidConfiguration)?,
    );
    // `BaseChainSubmissionAdapter` owns its transport; an `Arc` transport keeps
    // the same underlying RPC connection for the probe and the adapter.
    let submission = BaseChainSubmissionAdapter::new(chain.clone());
    // Refresh the cached health synchronously at composition time; the probe is
    // read-only (`eth_chainId`) and never signs or broadcasts.
    submission.refresh_health().await;
    let privy = Arc::new(
        HttpPrivyClient::new(
            &config.privy_endpoint,
            config.privy_credentials,
            config.request_timeout,
        )
        .map_err(|_| LiveTransportError::InvalidConfiguration)?,
    );
    let payload = Arc::new(
        HttpSignedPayloadSource::new(
            &config.payload_endpoint,
            config.payload_bearer,
            config.request_timeout,
        )
        .map_err(|_| LiveTransportError::InvalidConfiguration)?,
    );
    Ok(LiveTransports {
        chain,
        chain_submission: Arc::new(submission),
        privy,
        payload,
    })
}

/// Per-dependency probe results for the concrete live transports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveTransportProbes {
    pub chain: bool,
    pub signer: bool,
    pub payload: bool,
}

/// Probes every concrete transport with bounded, read-only requests.
pub async fn probe_live_transports(transports: &LiveTransports) -> LiveTransportProbes {
    let chain = matches!(transports.chain.chain_id().await, Ok(BASE_CHAIN_ID));
    let signer = transports.privy.health().await;
    let payload = transports.payload.health().await;
    LiveTransportProbes {
        chain,
        signer,
        payload,
    }
}

/// The assembled production execution path: the concrete transports and the
/// relay built over them.
pub struct LiveExecution {
    pub transports: LiveTransports,
    /// The production relay. It is assembled and held for the process lifetime;
    /// `TRADING_ENABLED` still gates every execution, so it cannot sign or
    /// submit while disabled.
    pub relay: trading_core::live::LiveRelay,
}

impl std::fmt::Debug for LiveExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LiveExecution { .. }")
    }
}

/// Assembles the production relay over the durable store and concrete
/// transports.
pub fn build_live_execution(
    store: Arc<dyn DurableAttemptStore>,
    transports: LiveTransports,
    policy: PolicyEngine,
) -> LiveExecution {
    let breaker = ChainHealthBreaker::new(3, 30_000);
    let privy_transport = Box::new(privy::PrivyHttpSigningTransport::new(
        transports.privy.clone(),
    ));
    let relay = trading_core::live::build_live_relay(trading_core::live::LiveDependencies {
        policy,
        store,
        chain: transports.chain_submission.clone(),
        payload_source: transports.payload.clone(),
        privy_transport,
        breaker,
    });
    LiveExecution { transports, relay }
}

/// Builds the policy engine for the composed relay from the raw
/// `TRADING_ENABLED` value and a fixed, conservative Base/uniswap limit set.
pub fn build_live_policy(
    trading_enabled: Option<&str>,
) -> Result<PolicyEngine, LiveTransportError> {
    trading_core::composition::build_policy(trading_enabled, live_policy_limits())
        .map_err(|_| LiveTransportError::InvalidConfiguration)
}

fn live_policy_limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).expect("constant policy limit"),
        max_sell_tax: Bps::new(500).expect("constant policy limit"),
        max_price_impact: Bps::new(300).expect("constant policy limit"),
        max_slippage: Bps::new(200).expect("constant policy limit"),
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::from(["uniswap".to_string()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A minimal loopback HTTP/1.1 mock server.
    ///
    /// `handler` receives `(path, body)` and returns `(status, response_body)`.
    /// It performs no external I/O and binds an ephemeral loopback port.
    async fn spawn_mock<F>(handler: F) -> String
    where
        F: Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let request = read_request(&mut socket).await;
                    let mut lines = request.lines();
                    let request_line = lines.next().unwrap_or("");
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let body = request
                        .split_once("\r\n\r\n")
                        .map(|(_, body)| body.to_string())
                        .unwrap_or_default();
                    let (status, response_body) = handler(&path, &body);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                        response_body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{address}")
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(read) = socket.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&buffer).to_string();
            if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if body.len() >= content_length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buffer).to_string()
    }

    fn rpc_result(result: Value) -> (u16, String) {
        (
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string(),
        )
    }

    #[tokio::test]
    async fn base_rpc_decodes_chain_id_block_and_rejects_wrong_chain() {
        let base = spawn_mock(|_path, body| {
            let method = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|value| {
                    value
                        .get("method")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default();
            match method.as_str() {
                "eth_chainId" => rpc_result(json!("0x2105")),
                "eth_blockNumber" => rpc_result(json!("0x10")),
                _ => (200, "{\"result\":null}".to_string()),
            }
        })
        .await;
        let transport =
            BaseRpcChainTransport::new(&base, None, Duration::from_secs(2)).expect("transport");
        assert_eq!(transport.chain_id().await, Ok(BASE_CHAIN_ID));
        assert_eq!(transport.block_number().await, Ok(16));

        let wrong = spawn_mock(|_path, _body| rpc_result(json!("0x1"))).await;
        let transport =
            BaseRpcChainTransport::new(&wrong, None, Duration::from_secs(2)).expect("transport");
        assert_eq!(transport.chain_id().await, Ok(1));
    }

    #[tokio::test]
    async fn evm_rpc_timeout_maps_to_a_typed_timeout() {
        // A listener that accepts and never answers forces the bounded read to
        // time out; the transport reports the typed timeout rather than a
        // generic outage.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        });
        let transport = EvmRpcChainTransport::new(
            &format!("http://{address}"),
            None,
            Duration::from_millis(100),
        )
        .expect("transport");
        assert_eq!(transport.chain_id().await, Err(ChainAdapterError::Timeout));
    }

    #[tokio::test]
    async fn evm_rpc_malformed_body_is_rejected() {
        // A 200 with a non-JSON body must fail closed, not be treated as a
        // chain answer.
        let base = spawn_mock(|_path, _body| (200, "not-json".to_string())).await;
        let transport =
            EvmRpcChainTransport::new(&base, None, Duration::from_secs(2)).expect("transport");
        assert_eq!(
            transport.chain_id().await,
            Err(ChainAdapterError::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn base_rpc_call_balance_and_metadata_round_trip() {
        let base = spawn_mock(|_path, body| {
            let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let data = value
                .get("params")
                .and_then(|params| params.get(0))
                .and_then(|call| call.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if data.starts_with(ERC20_BALANCE_OF) {
                // 42 as a 32-byte word.
                let mut word = vec![0u8; 32];
                word[31] = 42;
                rpc_result(json!(hex_encode(&word)))
            } else if data.starts_with(ERC20_SYMBOL) {
                // ABI-encoded "USDC".
                let mut returned = Vec::new();
                returned.extend_from_slice(&[0u8; 31]);
                returned.push(32);
                returned.extend_from_slice(&[0u8; 31]);
                returned.push(4);
                returned.extend_from_slice(b"USDC");
                returned.extend_from_slice(&[0u8; 28]);
                rpc_result(json!(hex_encode(&returned)))
            } else if data.starts_with(ERC20_DECIMALS) {
                let mut word = vec![0u8; 32];
                word[31] = 6;
                rpc_result(json!(hex_encode(&word)))
            } else {
                rpc_result(json!("0x"))
            }
        })
        .await;
        let transport =
            BaseRpcChainTransport::new(&base, None, Duration::from_secs(2)).expect("transport");
        assert_eq!(
            transport.call("0xpool", &[0x01, 0x02]).await,
            Ok(Vec::new())
        );
        assert_eq!(
            transport
                .erc20_balance("0xusdc", "0x0000000000000000000000000000000000000001")
                .await,
            Ok(42)
        );
        let metadata = transport.erc20_metadata("0xusdc").await.expect("metadata");
        assert_eq!(metadata.symbol, "USDC");
        assert_eq!(metadata.decimals, 6);
    }

    #[tokio::test]
    async fn base_rpc_receipt_reports_confirmed_without_fabricated_amounts() {
        let base = spawn_mock(|_path, _body| {
            rpc_result(json!({ "status": "0x1", "transactionHash": "0xabc" }))
        })
        .await;
        let transport =
            BaseRpcChainTransport::new(&base, None, Duration::from_secs(2)).expect("transport");
        let receipt = transport
            .transaction_receipt("0xabc")
            .await
            .expect("receipt")
            .expect("some receipt");
        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(receipt.net_input, None);
        assert_eq!(receipt.net_output, None);
    }

    #[tokio::test]
    async fn privy_client_sends_the_bound_idempotency_and_parses_the_reference() {
        let seen = Arc::new(StdMutex::new(String::new()));
        let captured = seen.clone();
        let base = spawn_mock(move |path, body| {
            if path == "/health" {
                return (200, "{}".to_string());
            }
            *captured.lock().expect("lock") = body.to_string();
            (200, json!({ "reference": "privy-ref-1" }).to_string())
        })
        .await;
        let client = HttpPrivyClient::new(
            &base,
            PrivyCredentials::new("test-token"),
            Duration::from_secs(2),
        )
        .expect("client");
        assert!(client.health().await);

        let (request, idempotency) = signing_fixture();
        let reference = client
            .submit_signing_request(&request, &idempotency)
            .await
            .expect("reference");
        assert_eq!(reference, "privy-ref-1");
        let body: Value = serde_json::from_str(&seen.lock().expect("lock")).expect("json");
        assert_eq!(body["provider_idempotency_id"], idempotency.as_str());
        assert_eq!(body["intent_id"], request.intent_id().as_str());
        assert_eq!(body["idempotency_key"], request.idempotency_key().as_str());
        assert_eq!(body["chain_tag"], 1);
    }

    #[tokio::test]
    async fn payload_source_fetches_and_decodes_bounded_bytes() {
        let base = spawn_mock(|path, _body| {
            if path == "/health" {
                return (200, "{}".to_string());
            }
            (200, json!({ "payload_hex": "0x010203" }).to_string())
        })
        .await;
        let source =
            HttpSignedPayloadSource::new(&base, None, Duration::from_secs(2)).expect("source");
        assert!(source.health().await);
        let key = IdempotencyKey::new("idem-1").expect("key");
        let intent = IntentId::new("intent-1").expect("intent");
        let payload = source
            .payload_to_sign(&key, &intent)
            .await
            .expect("payload");
        assert_eq!(payload.bytes(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn payload_source_fails_closed_on_a_malformed_response() {
        let base = spawn_mock(|_path, _body| (200, "{\"payload_hex\":\"zz\"}".to_string())).await;
        let source =
            HttpSignedPayloadSource::new(&base, None, Duration::from_secs(2)).expect("source");
        let key = IdempotencyKey::new("idem-1").expect("key");
        let intent = IntentId::new("intent-1").expect("intent");
        assert_eq!(
            source.payload_to_sign(&key, &intent).await,
            Err(RelayError::MissingSignedPayload)
        );
    }

    #[test]
    fn endpoint_validation_refuses_off_host_and_non_loopback_forms() {
        assert!(validated_endpoint("http://127.0.0.1:8545").is_ok());
        assert!(validated_endpoint("http://localhost:8545").is_ok());
        assert!(validated_endpoint("http://[::1]:8545").is_ok());
        // A remote or TLS endpoint must be fronted by the operator's local
        // gateway; a cleartext off-host endpoint would leak the bearer
        // credential.
        assert_eq!(
            validated_endpoint("http://base.example"),
            Err(TransportError::InvalidConfiguration)
        );
        assert_eq!(
            validated_endpoint("https://base.example/rpc"),
            Err(TransportError::InvalidConfiguration)
        );
        assert_eq!(
            validated_endpoint("ftp://base.example"),
            Err(TransportError::InvalidConfiguration)
        );
        assert_eq!(
            validated_endpoint("http://user:pass@127.0.0.1:8545"),
            Err(TransportError::InvalidConfiguration)
        );
        assert_eq!(
            validated_endpoint("http://127.0.0.1:8545?query=1"),
            Err(TransportError::InvalidConfiguration)
        );
    }

    #[tokio::test]
    async fn probes_deny_an_unhealthy_dependency() {
        // 503 on /health makes the signer probe unavailable; unreachable
        // endpoints make the chain and payload probes unavailable.
        let dead = spawn_mock(|_path, _body| (503, "{}".to_string())).await;
        let chain = Arc::new(
            BaseRpcChainTransport::new(&dead, None, Duration::from_secs(1)).expect("chain"),
        );
        let privy = Arc::new(
            HttpPrivyClient::new(
                &dead,
                PrivyCredentials::new("token"),
                Duration::from_secs(1),
            )
            .expect("privy"),
        );
        let payload = Arc::new(
            HttpSignedPayloadSource::new(&dead, None, Duration::from_secs(1)).expect("payload"),
        );
        let transports = LiveTransports {
            chain,
            chain_submission: Arc::new(BaseChainSubmissionAdapter::new(
                BaseRpcChainTransport::new(&dead, None, Duration::from_secs(1)).expect("chain"),
            )),
            privy,
            payload,
        };
        let probes = probe_live_transports(&transports).await;
        assert!(!probes.chain);
        assert!(!probes.signer);
        assert!(!probes.payload);
    }

    #[test]
    fn live_policy_is_disabled_by_default() {
        let policy = build_live_policy(None).expect("policy");
        assert!(!policy.is_trading_enabled());
        let enabled = build_live_policy(Some("true")).expect("policy");
        assert!(enabled.is_trading_enabled());
    }

    #[test]
    fn decode_abi_string_rejects_hostile_bounds_without_panicking() {
        // An offset word far beyond the buffer must fail closed, not panic.
        let mut data = vec![0u8; 64];
        data[31] = 0xff;
        assert_eq!(decode_abi_string(&data), None);

        // An in-range offset with an over-long declared length is rejected too.
        let mut data = vec![0u8; 96];
        data[31] = 32;
        data[63] = 0xff;
        assert_eq!(decode_abi_string(&data), None);

        // A short right-padded `bytes32` symbol still decodes.
        assert_eq!(decode_abi_string(&[0u8; 10]), Some(String::new()));
    }

    // ---- SigningRequest fixture (mirrors the locked execution fixtures) ----

    fn signing_fixture() -> (SigningRequest, ProviderIdempotencyId) {
        use domain::{
            AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId,
            OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource,
            UserId, WalletRef,
        };
        use market_types::{AssetAmount, AtomicAmount, Freshness, Sequence};

        use chain_types::AssetId;
        use policy::{
            PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros,
        };
        use privy::{PayloadDigest, PreparedExecutionRef};

        let mut chains = HashSet::new();
        chains.insert(ChainId::Base);
        let engine = PolicyEngine::new(
            TradingGate::from_trusted_startup(Some("true")).expect("gate"),
            PolicyLimits {
                max_trade_usd: UsdMicros::new(1_000_000),
                max_hourly_turnover_usd: UsdMicros::new(10_000_000),
                max_daily_turnover_usd: UsdMicros::new(50_000_000),
                max_buy_tax: Bps::new(500).expect("bps"),
                max_sell_tax: Bps::new(500).expect("bps"),
                max_price_impact: Bps::new(300).expect("bps"),
                max_slippage: Bps::new(200).expect("bps"),
                allowed_chains: chains,
                allowed_venues: HashSet::from(["uniswap".to_string()]),
            },
        )
        .expect("policy");

        let token_in = AssetId::new(ChainId::Base, "USDC").expect("asset");
        let token_out = AssetId::new(ChainId::Base, "TOKEN").expect("asset");
        let intent = TradeIntent {
            id: IntentId::new("intent-1").expect("intent"),
            source: TradeSource::Web,
            user_id: UserId::new("user-1").expect("user"),
            wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
            chain: ChainId::Base,
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: TradeSide::Buy,
            amount_type: AmountType::InputAssetAtomic,
            amount: AtomicAmount::new(1_000),
            order_type: OrderType::Market,
            limit_price: None,
            risk: RiskConstraints {
                max_buy_tax: Bps::new(100).expect("bps"),
                max_sell_tax: Bps::new(100).expect("bps"),
                max_price_impact: Bps::new(100).expect("bps"),
                max_slippage: Bps::new(100).expect("bps"),
                max_total_cost: None,
            },
            allow_partial_fill: true,
            expiry_ms: Some(10_000),
            nonce: 7,
            idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
        };
        let route = RoutePlan {
            legs: vec![RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "0xpool1".to_string(),
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(250),
            }],
            expected_net_output: AssetAmount {
                asset: token_out.clone(),
                amount: AtomicAmount::new(240),
            },
            state: Freshness {
                observed_at_ms: 1_000,
                chain_height: 100,
                sequence: Sequence(1),
            },
        };
        let preview = ExecutionPreview {
            intent_id: intent.id.clone(),
            chain: ChainId::Base,
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            side: intent.side,
            simulated_net_input: AssetAmount {
                asset: token_in,
                amount: AtomicAmount::new(1_000),
            },
            simulated_net_output: AssetAmount {
                asset: token_out,
                amount: AtomicAmount::new(240),
            },
            gross_output: AssetAmount {
                asset: intent.token_out.clone(),
                amount: AtomicAmount::new(250),
            },
            cost_components: ExecutionCostComponents::default(),
            local_state_freshness: market_types::FreshnessStatus::Fresh,
        }
        .validate(&intent, &route, 1_000)
        .expect("preview");
        let prepared = PreparedExecutionRef::new(
            "prepared-1",
            intent.id.clone(),
            intent.idempotency_key.clone(),
        )
        .expect("prepared");
        let context = PolicyContext::from_trusted_backend_state(
            1_000,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap".to_string()),
        )
        .expect("context");
        let approved = engine.authorize_trade(&intent, &context).expect("approved");
        let request = SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent,
            &route,
            &preview,
            PayloadDigest::from_bytes([3u8; 32]),
            1_000,
        )
        .expect("signing request");
        let idempotency = request.provider_idempotency_id();
        (request, idempotency)
    }
}
