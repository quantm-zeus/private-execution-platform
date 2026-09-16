//! Read-only FOMO market-data adapter for the private web chart.
//!
//! This is the PEP-side consumer of the local, read-only `fomo-mcp`
//! market bridge. It deliberately never talks to FOMO directly and never holds
//! FOMO auth material: `fomo-mcp` owns the FOMO REST/WS session, and PEP only
//! calls the loopback bridge with the bridge's own bearer key.
//!
//! ## Contract consumed
//!
//! ```text
//! GET {base}/market/bars?...    (fresh upstream fetch)
//! GET {base}/market/latest?...  (bounded-cadence polling)
//! ```
//!
//! with query `symbol=<address>:<networkId>`, `resolution=<1|5|15|60|240|1D>`,
//! optional `countBack`, `from`, `to`, and an `Authorization: Bearer <key>`
//! header. The bridge response is a strict JSON document whose `bars` are
//! normalized ascending, unique-millisecond OHLCV and whose
//! `source.provenance` is `"polling"` (`wsPromoted=false`). PEP re-validates
//! every bar and refuses a payload that is not explicitly labelled polling, so
//! a future WebSocket-promoted source can never be silently treated as this
//! polling contract.
//!
//! ## Fail-closed guarantees
//!
//! * An unconfigured, unreachable, non-2xx, oversized or malformed source
//!   yields no candles and a typed denial/error — never a fabricated bar.
//! * Upstream error bodies, the bearer key and provider identifiers never
//!   appear in a denial, log line or `Debug` output.
//! * The realtime source only ever forwards a bar the provider just returned;
//!   a gap is never interpolated and a provider outage emits nothing.
//!
//! ## Non-authoritative
//!
//! Chart data is visual only. Limits and trades continue to depend on exact
//! route simulation / net executable economics, never on a chart crossing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use session_transport::{CommandDenial, CommandRequest, DenialCode};

use crate::opaque::CommandDispatcher;
use crate::stream::{SourceFrame, StreamSource};

/// Upper bound on the number of candles a single history page may return.
pub const FOMO_MAX_COUNT_BACK: u32 = 1_500;
/// Default candle count when a caller does not ask for one.
pub const FOMO_DEFAULT_COUNT_BACK: u32 = 300;
/// Hard cap on a bridge response body; the bridge bounds itself to 1 500 bars.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum accepted token address length (the bridge enforces the same bound).
const MAX_ADDRESS_LEN: usize = 128;
/// Requests are bounded so a hung loopback bridge cannot stall the stream.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds for the realtime poll cadence.
pub const MIN_STREAM_POLL: Duration = Duration::from_secs(1);
pub const MAX_STREAM_POLL: Duration = Duration::from_secs(60);
/// Consecutive provider failures before a polled stream ends (so the driver can
/// release its hub slot and the client can reconnect with a fresh snapshot).
const MAX_STREAM_FAILURES: u32 = 6;
/// Sanity ceiling for a millisecond timestamp (year 2100).
const MAX_TIMESTAMP_MS: i64 = 4_102_444_800_000;

/// Current wall clock in milliseconds (0 when the system clock is before epoch).
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Age of the newest bar in milliseconds, for the frame's freshness stamp. A
/// future-dated bar clamps to 0 rather than reporting a negative age.
fn data_age_ms(bar_time_ms: i64) -> u64 {
    now_ms().saturating_sub(bar_time_ms).max(0) as u64
}

/// A redacted market-source failure. No upstream text is ever carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FomoMarketError {
    /// No market source is configured for this process.
    #[error("fomo market source is not configured")]
    NotConfigured,
    /// The request itself is invalid (unknown chain/window, bad address).
    #[error("fomo market request is invalid")]
    InvalidRequest,
    /// The bridge could not be reached or answered with a failure status.
    #[error("fomo market source is unavailable")]
    Unavailable,
    /// The bridge answered with a payload that violates the contract.
    #[error("fomo market source returned an invalid response")]
    InvalidResponse,
}

impl FomoMarketError {
    /// Map to a fixed, privacy-safe command denial. Messages are constants so
    /// no upstream value can leak through the authenticated error channel.
    pub fn denial(self) -> CommandDenial {
        match self {
            Self::NotConfigured => CommandDenial::determinate(
                DenialCode::CapabilityMissing,
                "Chart data source is not configured.",
            ),
            Self::InvalidRequest => {
                CommandDenial::determinate(DenialCode::Protocol, "Chart request is invalid.")
            }
            Self::Unavailable | Self::InvalidResponse => CommandDenial::indeterminate(
                DenialCode::Server,
                "Chart data is temporarily unavailable.",
            ),
        }
    }
}

/// One normalized OHLCV candle with a millisecond timestamp.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Bar {
    pub time_ms: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
}

fn is_finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

/// A bar is valid only when its timestamp is sane and its prices satisfy the
/// OHLC envelope. A hostile or broken source cannot inject a nonsensical row.
pub fn is_valid_bar(bar: &Bar) -> bool {
    bar.time_ms >= 1
        && bar.time_ms <= MAX_TIMESTAMP_MS
        && is_finite_positive(bar.open)
        && is_finite_positive(bar.high)
        && is_finite_positive(bar.low)
        && is_finite_positive(bar.close)
        && bar.volume.is_finite()
        && bar.volume >= 0.0
        && bar.high >= bar.low
        && bar.high >= bar.open
        && bar.high >= bar.close
        && bar.low <= bar.open
        && bar.low <= bar.close
}

/// Sort ascending, drop malformed rows, dedupe last-wins, and cap the result.
/// The returned series is always ascending with unique millisecond timestamps.
pub fn normalize_bars<I: IntoIterator<Item = Bar>>(raw: I) -> Vec<Bar> {
    let mut bars: Vec<Bar> = raw.into_iter().filter(is_valid_bar).collect();
    // `sort_by_key` is stable, so for equal timestamps the later input wins the
    // dedupe below (a delta that corrects an in-progress candle).
    bars.sort_by_key(|bar| bar.time_ms);
    let mut out: Vec<Bar> = Vec::with_capacity(bars.len());
    for bar in bars {
        match out.last_mut() {
            Some(last) if last.time_ms == bar.time_ms => *last = bar,
            _ => out.push(bar),
        }
    }
    if out.len() > FOMO_MAX_COUNT_BACK as usize {
        let drop = out.len() - FOMO_MAX_COUNT_BACK as usize;
        out.drain(0..drop);
    }
    out
}

/// Map a chart window to the FOMO resolution token.
///
/// Accepts both the canonical `get_chart` window values the browser sends
/// (`m5`/`m15`/`h1`/`h4`/`d1`) and the frontend timeframe ids used by the
/// operator stream target (`5m`/`1h`/…). Unknown ids fail closed.
pub fn fomo_resolution(timeframe_id: &str) -> Option<&'static str> {
    match timeframe_id {
        "1m" | "m1" => Some("1"),
        "5m" | "m5" => Some("5"),
        "15m" | "m15" => Some("15"),
        "1h" | "h1" => Some("60"),
        "4h" | "h4" => Some("240"),
        "1d" | "d1" => Some("1D"),
        _ => None,
    }
}

/// Map a PEP chain slug to the FOMO network id. Only chains whose FOMO network
/// id is verified are mapped; anything else refuses rather than guessing. The
/// lookup is case-insensitive so a mixed-case producer cannot silently fall back
/// to the local buffer.
pub fn fomo_network_id(chain_slug: &str) -> Option<i64> {
    match chain_slug.trim().to_ascii_lowercase().as_str() {
        "solana" => Some(1_399_811_149),
        "base" => Some(8_453),
        "ethereum" => Some(1),
        "bnb_chain" | "bsc" | "bnb" => Some(56),
        _ => None,
    }
}

/// A token address must be a short alphanumeric string (EVM hex, Solana
/// base58). Anything else is refused before it can reach the bridge query.
pub fn valid_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_ADDRESS_LEN
        && address.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Build the FOMO token id `address:networkId`, or `None` for an unknown chain
/// or malformed address.
pub fn fomo_symbol(chain_slug: &str, address: &str) -> Option<String> {
    let network_id = fomo_network_id(chain_slug)?;
    if !valid_address(address) {
        return None;
    }
    Some(format!("{address}:{network_id}"))
}

/// An injected read-only OHLCV source. The HTTP client and test fakes both
/// implement this, so the dispatcher/stream logic is testable without network.
/// One request is grouped so the seam stays a single argument.
pub struct BarsQuery<'a> {
    pub chain_slug: &'a str,
    pub address: &'a str,
    pub resolution: &'a str,
    pub count_back: u32,
    pub from_s: Option<i64>,
    pub to_s: Option<i64>,
    /// Use the bridge's bounded-cadence `/market/latest` read.
    pub latest: bool,
}

#[async_trait]
pub trait BarsProvider: Send + Sync {
    /// Fetch normalized candles. Implementations MUST fail closed and MUST NOT
    /// synthesize a bar for a gap.
    async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError>;
}

/// Operator configuration for the FOMO market bridge.
#[derive(Clone, Debug)]
pub struct FomoMarketConfig {
    pub base_url: String,
    pub api_key_file: PathBuf,
    pub request_timeout: Duration,
    /// Optional single realtime target `(chain_slug, address, timeframe_id)`.
    pub stream_target: Option<(String, String, String)>,
    pub stream_poll: Duration,
    pub stream_count_back: u32,
}

impl FomoMarketConfig {
    /// Validate an operator-supplied base URL.
    ///
    /// The `fomo-mcp` bridge is a loopback plaintext read-only service, so the
    /// base must be an absolute `http://` URL whose host is `127.0.0.1`,
    /// `[::1]` or `localhost` (an optional port is allowed), with no userinfo,
    /// path, query or fragment. A remote or TLS base is refused rather than
    /// transmitting the bridge bearer key in cleartext to another host.
    pub fn validated_base_url(base_url: &str) -> Result<String, FomoMarketError> {
        let base = base_url.trim().trim_end_matches('/').to_string();
        let rest = base
            .strip_prefix("http://")
            .ok_or(FomoMarketError::InvalidRequest)?;
        if rest.is_empty() || base.len() > 512 {
            return Err(FomoMarketError::InvalidRequest);
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') || rest.len() != authority.len() {
            return Err(FomoMarketError::InvalidRequest);
        }
        let host = if let Some(stripped) = authority.strip_prefix('[') {
            // Bracketed IPv6 literal, optionally followed by `:port`.
            let end = stripped.find(']').ok_or(FomoMarketError::InvalidRequest)?;
            &authority[..=end + 1]
        } else {
            authority.split(':').next().unwrap_or("")
        };
        match host {
            "127.0.0.1" | "localhost" | "[::1]" | "[0:0:0:0:0:0:0:1]" => Ok(base),
            _ => Err(FomoMarketError::InvalidRequest),
        }
    }

    /// Clamp an operator poll interval into the supported bounded range.
    pub fn clamp_poll(interval: Duration) -> Duration {
        interval.clamp(MIN_STREAM_POLL, MAX_STREAM_POLL)
    }

    pub fn clamp_count_back(count: u32) -> u32 {
        count.clamp(1, FOMO_MAX_COUNT_BACK)
    }
}

/// HTTP client for the loopback `fomo-mcp` market bridge.
///
/// `Debug` is redacted: the bearer key must never appear in a log or panic.
pub struct FomoBarsClient {
    http: HyperClient<HttpConnector, Empty<Bytes>>,
    base_url: String,
    api_key: Zeroizing<String>,
    timeout: Duration,
}

impl std::fmt::Debug for FomoBarsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoBarsClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

/// Wire shape of one bridge bar. `time` is the normalized millisecond field;
/// `time_ms` is accepted as a compatibility alias.
#[derive(Debug, Deserialize)]
struct BarWire {
    #[serde(default)]
    time: Option<i64>,
    #[serde(default)]
    time_ms: Option<i64>,
    open: f64,
    high: f64,
    low: f64,
    close: f64,
    #[serde(default)]
    volume: f64,
}

impl BarWire {
    fn into_bar(self) -> Option<Bar> {
        let time_ms = self.time.or(self.time_ms)?;
        Some(Bar {
            time_ms,
            open: self.open,
            high: self.high,
            low: self.low,
            close: self.close,
            volume: self.volume,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SourceWire {
    #[serde(default)]
    provenance: Option<String>,
    #[serde(default, rename = "wsPromoted")]
    ws_promoted: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BarsWire {
    #[serde(default)]
    bars: Vec<BarWire>,
    #[serde(default)]
    latest: Option<BarWire>,
    #[serde(default)]
    source: Option<SourceWire>,
}

impl FomoBarsClient {
    /// Build a client. The base URL is validated (absolute `http://`, no
    /// userinfo) and only connects to the configured loopback bridge.
    pub fn new(
        base_url: &str,
        api_key: Zeroizing<String>,
        request_timeout: Duration,
    ) -> Result<Self, FomoMarketError> {
        let base_url = FomoMarketConfig::validated_base_url(base_url)?;
        if api_key.trim().is_empty() {
            return Err(FomoMarketError::InvalidRequest);
        }
        if request_timeout.is_zero() {
            return Err(FomoMarketError::InvalidRequest);
        }
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(request_timeout));
        let http = HyperClient::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            http,
            base_url,
            api_key,
            timeout: request_timeout,
        })
    }

    async fn fetch(
        &self,
        path: &str,
        symbol: &str,
        resolution: &str,
        count_back: u32,
        from_s: Option<i64>,
        to_s: Option<i64>,
    ) -> Result<Vec<Bar>, FomoMarketError> {
        // Every interpolated value is validated alphanumeric/numeric (symbol
        // address, resolution, counts), so no query-escapable input can reach
        // the URI. `:` inside `address:networkId` is a legal query character.
        let mut uri = format!(
            "{}{}?symbol={}&resolution={}&countBack={}",
            self.base_url, path, symbol, resolution, count_back
        );
        if let Some(from) = from_s {
            uri.push_str(&format!("&from={from}"));
        }
        if let Some(to) = to_s {
            uri.push_str(&format!("&to={to}"));
        }
        // The bearer header is built in a zeroizing buffer; the underlying
        // `HeaderValue` copy is owned by hyper and cannot be zeroized.
        let authorization = Zeroizing::new(format!("Bearer {}", self.api_key.as_str()));
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", authorization.as_str())
            .header("accept", "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FomoMarketError::InvalidResponse)?;
        let response = tokio::time::timeout(self.timeout, self.http.request(request))
            .await
            .map_err(|_| FomoMarketError::Unavailable)?
            .map_err(|_| FomoMarketError::Unavailable)?;
        if !response.status().is_success() {
            return Err(FomoMarketError::Unavailable);
        }
        // Bound the body explicitly *and* on a deadline: a compromised loopback
        // listener must not be able to stall the read (or make PEP buffer an
        // unbounded amount).
        let mut stream = response.into_body();
        let body = tokio::time::timeout(self.timeout, async {
            let mut body = Vec::new();
            while let Some(frame) = stream.frame().await {
                let frame = frame.map_err(|_| FomoMarketError::Unavailable)?;
                if let Some(chunk) = frame.data_ref() {
                    if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                        return Err(FomoMarketError::InvalidResponse);
                    }
                    body.extend_from_slice(chunk);
                }
            }
            Ok::<Vec<u8>, FomoMarketError>(body)
        })
        .await
        .map_err(|_| FomoMarketError::Unavailable)??;
        let wire: BarsWire =
            serde_json::from_slice(&body).map_err(|_| FomoMarketError::InvalidResponse)?;
        // Provenance is a hard contract: only an explicit REST-polling payload
        // is accepted. A WebSocket-promoted or unlabelled payload fails closed.
        let provenance_ok = wire
            .source
            .as_ref()
            .and_then(|source| source.provenance.as_deref())
            == Some("polling");
        if !provenance_ok
            || wire
                .source
                .as_ref()
                .is_some_and(|s| s.ws_promoted == Some(true))
        {
            return Err(FomoMarketError::InvalidResponse);
        }
        let mut bars: Vec<Bar> = wire
            .bars
            .into_iter()
            .filter_map(BarWire::into_bar)
            .collect();
        if let Some(latest) = wire.latest.and_then(BarWire::into_bar) {
            bars.push(latest);
        }
        Ok(normalize_bars(bars))
    }
}

#[async_trait]
impl BarsProvider for FomoBarsClient {
    async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError> {
        let symbol =
            fomo_symbol(query.chain_slug, query.address).ok_or(FomoMarketError::InvalidRequest)?;
        if query.from_s.is_some_and(|value| value < 0) || query.to_s.is_some_and(|value| value < 0)
        {
            return Err(FomoMarketError::InvalidRequest);
        }
        if let (Some(from), Some(to)) = (query.from_s, query.to_s) {
            if from > to {
                return Err(FomoMarketError::InvalidRequest);
            }
        }
        // History always requests a fresh read; the realtime poller uses the
        // bridge's bounded-cadence read so concurrent sessions collapse into one
        // upstream fetch.
        let path = if query.latest {
            "/market/latest"
        } else {
            "/market/bars"
        };
        self.fetch(
            path,
            &symbol,
            query.resolution,
            FomoMarketConfig::clamp_count_back(query.count_back),
            query.from_s,
            query.to_s,
        )
        .await
    }
}

fn bar_json(bar: &Bar) -> Value {
    json!({
        "time_ms": bar.time_ms,
        "open": bar.open,
        "high": bar.high,
        "low": bar.low,
        "close": bar.close,
        "volume": bar.volume,
    })
}

fn required_string(payload: &Value, key: &str) -> Result<String, CommandDenial> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            CommandDenial::determinate(DenialCode::Protocol, "Chart request is invalid.")
        })
}

fn optional_i64(payload: &Value, key: &str) -> Result<Option<i64>, CommandDenial> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            CommandDenial::determinate(DenialCode::Protocol, "Chart request is invalid.")
        }),
    }
}

fn optional_u32(payload: &Value, key: &str) -> Result<Option<u32>, CommandDenial> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => u32::try_from(value.as_u64().ok_or_else(|| {
            CommandDenial::determinate(DenialCode::Protocol, "Chart request is invalid.")
        })?)
        .map(Some)
        .map_err(|_| CommandDenial::determinate(DenialCode::Protocol, "Chart request is invalid.")),
    }
}

/// Serves the browser `get_chart` read from the FOMO bridge and delegates every
/// other operation to the wrapped dispatcher unchanged.
///
/// This sits outermost so it receives the browser-shaped payload
/// `{chain, address, window, from?, to?, countBack?}`; the server-side
/// capability gate still enforces the advertised `market` capability before
/// dispatch.
pub struct FomoChartDispatcher {
    inner: Arc<dyn CommandDispatcher>,
    provider: Arc<dyn BarsProvider>,
}

impl std::fmt::Debug for FomoChartDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoChartDispatcher")
            .finish_non_exhaustive()
    }
}

impl FomoChartDispatcher {
    pub fn new(inner: Arc<dyn CommandDispatcher>, provider: Arc<dyn BarsProvider>) -> Self {
        Self { inner, provider }
    }

    async fn get_chart(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        let chain = required_string(&request.payload, "chain")?;
        let address = required_string(&request.payload, "address")?;
        let window = required_string(&request.payload, "window")?;
        if fomo_symbol(&chain, &address).is_none() {
            return Err(FomoMarketError::InvalidRequest.denial());
        }
        let resolution =
            fomo_resolution(&window).ok_or_else(|| FomoMarketError::InvalidRequest.denial())?;
        let count_back = optional_u32(&request.payload, "countBack")?
            .map(FomoMarketConfig::clamp_count_back)
            .unwrap_or(FOMO_DEFAULT_COUNT_BACK);
        let from = optional_i64(&request.payload, "from")?;
        let to = optional_i64(&request.payload, "to")?;
        if let (Some(from), Some(to)) = (from, to) {
            if from > to {
                return Err(FomoMarketError::InvalidRequest.denial());
            }
        }
        let bars = self
            .provider
            .bars(BarsQuery {
                chain_slug: &chain,
                address: &address,
                resolution,
                count_back,
                from_s: from,
                to_s: to,
                latest: false,
            })
            .await
            .map_err(FomoMarketError::denial)?;
        // Normalize regardless of provider: an injected implementation must not
        // be able to return an unordered or duplicate series to a renderer.
        let bars = normalize_bars(bars);
        Ok(json!({
            "window": window,
            "chain": chain,
            "address": address,
            "source": "fomo-polling",
            "candles": bars.iter().map(bar_json).collect::<Vec<_>>(),
        }))
    }
}

#[async_trait]
impl CommandDispatcher for FomoChartDispatcher {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        if request.op == "get_chart" {
            return self.get_chart(request).await;
        }
        self.inner.dispatch(request).await
    }

    async fn dispatch_for_session(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        if request.op == "get_chart" {
            return self.get_chart(request).await;
        }
        self.inner.dispatch_for_session(kid, request).await
    }
}

/// Bounded-polling realtime OHLCV source.
///
/// The PEP encrypted stream has no client-supplied subscription target, so this
/// first implementation is configured by the operator with a single instrument
/// target. It polls the bridge's bounded-cadence read at a bounded interval and
/// emits only authoritative frames:
///
/// * `snapshot` — the full normalized series at connect/resync,
/// * `delta` — the provider's current latest bar (the browser replaces the last
///   bar in place or appends a new one).
///
/// The source is stateless: it never suppresses a bar because another session
/// already saw it, so concurrent sessions each receive every authoritative bar.
/// A provider outage emits **nothing** (no heartbeat with fabricated data) and a
/// gap is never interpolated; after a bounded number of consecutive failures the
/// stream ends so the driver can release the connection slot.
pub struct FomoOhlcvStreamSource {
    provider: Arc<dyn BarsProvider>,
    chain: String,
    address: String,
    timeframe: String,
    resolution: &'static str,
    entity_key: String,
    count_back: u32,
    interval: Duration,
}

impl std::fmt::Debug for FomoOhlcvStreamSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoOhlcvStreamSource")
            .field("timeframe", &self.timeframe)
            .field("entity_key", &self.entity_key)
            .finish_non_exhaustive()
    }
}

impl FomoOhlcvStreamSource {
    /// Build a source for one `(chain, address, timeframe)` target. An unknown
    /// chain/window, a malformed address or an out-of-range cadence fails.
    pub fn new(
        provider: Arc<dyn BarsProvider>,
        chain: String,
        address: String,
        timeframe: String,
        count_back: u32,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        if fomo_symbol(&chain, &address).is_none() {
            return Err(FomoMarketError::InvalidRequest);
        }
        let resolution = fomo_resolution(&timeframe).ok_or(FomoMarketError::InvalidRequest)?;
        if !(MIN_STREAM_POLL..=MAX_STREAM_POLL).contains(&interval) {
            return Err(FomoMarketError::InvalidRequest);
        }
        let entity_key = format!("ohlcv:{chain}:{address}");
        Ok(Self {
            provider,
            chain,
            address,
            timeframe,
            resolution,
            entity_key,
            count_back: FomoMarketConfig::clamp_count_back(count_back),
            interval,
        })
    }

    /// Test-only constructor that bypasses the production poll-cadence floor so
    /// tests exercise snapshot/delta/outage behavior without sleeping seconds.
    #[cfg(test)]
    fn new_for_test(
        provider: Arc<dyn BarsProvider>,
        chain: String,
        address: String,
        timeframe: String,
        count_back: u32,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        let mut source = Self::new(
            provider,
            chain,
            address,
            timeframe,
            count_back,
            MIN_STREAM_POLL,
        )?;
        source.interval = interval;
        Ok(source)
    }

    async fn fetch(&self) -> Result<Vec<Bar>, FomoMarketError> {
        Ok(normalize_bars(
            self.provider
                .bars(BarsQuery {
                    chain_slug: &self.chain,
                    address: &self.address,
                    resolution: self.resolution,
                    count_back: self.count_back,
                    from_s: None,
                    to_s: None,
                    latest: true,
                })
                .await?,
        ))
    }
}

#[async_trait]
impl StreamSource for FomoOhlcvStreamSource {
    async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
        let bars = self.fetch().await.ok()?;
        let latest = bars.last()?;
        Some(
            SourceFrame::snapshot(
                "ohlcv",
                json!({
                    "timeframe": self.timeframe,
                    "candles": bars.iter().map(bar_json).collect::<Vec<_>>(),
                }),
                None,
            )
            .with_entity_key(self.entity_key.clone())
            .with_priority(1)
            .with_source_age_ms(data_age_ms(latest.time_ms)),
        )
    }

    async fn next_delta(&self) -> Option<SourceFrame> {
        let mut failures = 0u32;
        loop {
            tokio::time::sleep(self.interval).await;
            let bars = match self.fetch().await {
                Ok(bars) => {
                    // A reachable-but-empty response is still a success.
                    failures = 0;
                    bars
                }
                // Provider outage: stay silent rather than fabricate. After a
                // bounded number of consecutive failures, end the stream so the
                // driver returns and releases the hub slot and task; the client
                // reconnects and gets a fresh snapshot/error.
                Err(_) => {
                    failures = failures.saturating_add(1);
                    if failures >= MAX_STREAM_FAILURES {
                        return None;
                    }
                    continue;
                }
            };
            let Some(latest) = bars.last() else {
                continue;
            };
            return Some(
                SourceFrame::delta(
                    "ohlcv",
                    self.entity_key.clone(),
                    json!({ "timeframe": self.timeframe, "candle": bar_json(latest) }),
                    None,
                )
                .with_priority(1)
                .with_source_age_ms(data_age_ms(latest.time_ms)),
            );
        }
    }

    async fn unavailable(&self) -> Vec<SourceFrame> {
        vec![SourceFrame::error(
            "ohlcv",
            "Market data source is temporarily unavailable.",
        )]
    }
}

/// A configured FOMO market wiring: the history dispatcher and an optional
/// realtime source.
pub struct FomoMarketWiring {
    pub dispatcher: Arc<dyn CommandDispatcher>,
    pub stream_source: Option<Arc<dyn StreamSource>>,
}

/// Build the FOMO market wiring from a resolved config and API key.
///
/// `provider` is injected so tests can supply a fake; production callers pass
/// [`FomoBarsClient::new`].
pub fn build_wiring(
    config: &FomoMarketConfig,
    provider: Arc<dyn BarsProvider>,
    inner: Arc<dyn CommandDispatcher>,
) -> Result<FomoMarketWiring, FomoMarketError> {
    let dispatcher: Arc<dyn CommandDispatcher> =
        Arc::new(FomoChartDispatcher::new(inner, provider.clone()));
    let stream_source: Option<Arc<dyn StreamSource>> = match &config.stream_target {
        None => None,
        Some((chain, address, timeframe)) => Some(Arc::new(FomoOhlcvStreamSource::new(
            provider,
            chain.clone(),
            address.clone(),
            timeframe.clone(),
            config.stream_count_back,
            config.stream_poll,
        )?)),
    };
    Ok(FomoMarketWiring {
        dispatcher,
        stream_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::sync::Mutex as StdMutex;

    fn bar(time_ms: i64, close: f64) -> Bar {
        Bar {
            time_ms,
            open: close - 0.5,
            high: close + 0.5,
            low: close - 1.0,
            close,
            volume: 1.0,
        }
    }

    /// Scripted provider: each call pops the next queued result; once exhausted
    /// it repeats the last one (or Unavailable when empty).
    #[derive(Default)]
    struct FakeProvider {
        results: StdMutex<Vec<Result<Vec<Bar>, FomoMarketError>>>,
        calls: StdMutex<usize>,
    }

    impl FakeProvider {
        fn new(results: Vec<Result<Vec<Bar>, FomoMarketError>>) -> Self {
            Self {
                results: StdMutex::new(results),
                calls: StdMutex::new(0),
            }
        }
    }

    #[async_trait]
    impl BarsProvider for FakeProvider {
        async fn bars(&self, _query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError> {
            *self.calls.lock().unwrap() += 1;
            let mut results = self.results.lock().unwrap();
            if results.is_empty() {
                return Err(FomoMarketError::Unavailable);
            }
            if results.len() == 1 {
                return results[0].clone();
            }
            results.remove(0)
        }
    }

    /// Convenience query builder for the client tests.
    fn bars_query<'a>(
        chain: &'a str,
        address: &'a str,
        resolution: &'a str,
        count_back: u32,
        latest: bool,
    ) -> BarsQuery<'a> {
        BarsQuery {
            chain_slug: chain,
            address,
            resolution,
            count_back,
            from_s: None,
            to_s: None,
            latest,
        }
    }

    fn fake(value: Vec<Bar>) -> Arc<FakeProvider> {
        Arc::new(FakeProvider::new(vec![Ok(value)]))
    }

    #[test]
    fn normalization_sorts_dedupes_and_drops_malformed() {
        let normalized = normalize_bars(vec![
            bar(3_000, 30.0),
            bar(1_000, 10.0),
            Bar {
                time_ms: 2_000,
                open: 1.0,
                high: 0.5,
                low: 2.0,
                close: 1.0,
                volume: 1.0,
            },
            bar(2_000, 20.0),
            bar(2_000, 25.0),
            Bar {
                time_ms: 4_000,
                open: 1.0,
                high: 2.0,
                low: 0.5,
                close: 1.0,
                volume: -1.0,
            },
            Bar {
                time_ms: 0,
                open: 1.0,
                high: 2.0,
                low: 0.5,
                close: 1.0,
                volume: 1.0,
            },
        ]);
        assert_eq!(
            normalized.iter().map(|b| b.time_ms).collect::<Vec<_>>(),
            vec![1_000, 2_000, 3_000]
        );
        assert_eq!(normalized[1].close, 25.0);
    }

    #[test]
    fn normalization_caps_at_the_maximum_and_keeps_the_newest() {
        let raw = (1..=FOMO_MAX_COUNT_BACK as i64 + 50)
            .map(|i| bar(i, 10.0))
            .collect::<Vec<_>>();
        let normalized = normalize_bars(raw);
        assert_eq!(normalized.len(), FOMO_MAX_COUNT_BACK as usize);
        assert_eq!(normalized.first().unwrap().time_ms, 51);
    }

    #[test]
    fn resolution_and_network_maps_are_closed() {
        assert_eq!(fomo_resolution("1h"), Some("60"));
        assert_eq!(fomo_resolution("h1"), Some("60"));
        assert_eq!(fomo_resolution("m5"), Some("5"));
        assert_eq!(fomo_resolution("1d"), Some("1D"));
        assert_eq!(fomo_resolution("d1"), Some("1D"));
        assert_eq!(fomo_resolution("1s"), None);
        assert_eq!(fomo_network_id("solana"), Some(1_399_811_149));
        assert_eq!(fomo_network_id("base"), Some(8_453));
        assert_eq!(fomo_network_id("unknown"), None);
        assert_eq!(fomo_symbol("base", "0xabc").as_deref(), Some("0xabc:8453"));
        assert!(fomo_symbol("base", "has space").is_none());
        assert!(fomo_symbol("base", "").is_none());
    }

    #[test]
    fn base_url_validation_requires_a_loopback_origin() {
        assert_eq!(
            FomoMarketConfig::validated_base_url("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert!(FomoMarketConfig::validated_base_url("http://localhost:8787").is_ok());
        assert!(FomoMarketConfig::validated_base_url("http://[::1]:8787").is_ok());
        // The loopback bridge is plaintext-only; https is refused, not attempted.
        assert!(FomoMarketConfig::validated_base_url("https://fomo.internal/").is_err());
        assert!(FomoMarketConfig::validated_base_url("ftp://x").is_err());
        assert!(FomoMarketConfig::validated_base_url("http://user:pass@127.0.0.1").is_err());
        assert!(FomoMarketConfig::validated_base_url("http://").is_err());
        // A remote host must never receive the bridge bearer key in cleartext.
        assert!(FomoMarketConfig::validated_base_url("http://10.0.0.5:8787").is_err());
        assert!(FomoMarketConfig::validated_base_url("http://fomo-mcp:8787").is_err());
        // No path/query/fragment: the bridge path is fixed.
        assert!(FomoMarketConfig::validated_base_url("http://127.0.0.1:8787/extra").is_err());
        assert!(FomoMarketConfig::validated_base_url("http://127.0.0.1:8787?x=1").is_err());
    }

    #[tokio::test]
    async fn dispatcher_records_the_clamped_count_back() {
        // A recording provider captures the countBack the dispatcher forwarded.
        struct Recording {
            seen: StdMutex<Vec<(u32, bool)>>,
        }
        #[async_trait]
        impl BarsProvider for Recording {
            async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError> {
                self.seen
                    .lock()
                    .unwrap()
                    .push((query.count_back, query.latest));
                Ok(vec![bar(1_000, 10.0)])
            }
        }
        let provider = Arc::new(Recording {
            seen: StdMutex::new(Vec::new()),
        });
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        );
        dispatcher
            .dispatch(&request(json!({
                "chain": "base",
                "address": "0xabc",
                "window": "m5",
                "countBack": 10_000_000,
            })))
            .await
            .unwrap();
        assert_eq!(
            provider.seen.lock().unwrap().as_slice(),
            &[(FOMO_MAX_COUNT_BACK, false)]
        );
    }

    #[tokio::test]
    async fn stream_emits_to_every_session_without_suppression() {
        let provider = Arc::new(FakeProvider::new(vec![
            Ok(vec![bar(1_000, 10.0)]),
            Ok(vec![bar(1_000, 10.0), bar(2_000, 11.0)]),
        ]));
        let source = FomoOhlcvStreamSource::new_for_test(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        let _ = source.snapshot(None).await.expect("snapshot");
        // Two independent driver calls (two sessions) both receive the newer bar.
        let first = source.next_delta().await.expect("first session delta");
        let second = source.next_delta().await.expect("second session delta");
        assert_eq!(first.payload.as_ref().unwrap()["candle"]["time_ms"], 2_000);
        assert_eq!(second.payload.as_ref().unwrap()["candle"]["time_ms"], 2_000);
    }

    #[tokio::test]
    async fn stream_ends_after_bounded_consecutive_failures() {
        // Every fetch fails: after MAX_STREAM_FAILURES the stream returns None so
        // the driver can release its slot instead of polling forever.
        let provider = Arc::new(FakeProvider::new(vec![Err(FomoMarketError::Unavailable)]));
        let source = FomoOhlcvStreamSource::new_for_test(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        let delta = tokio::time::timeout(Duration::from_secs(5), source.next_delta())
            .await
            .expect("bounded");
        assert!(delta.is_none());
    }

    fn request(payload: Value) -> CommandRequest {
        CommandRequest {
            op: "get_chart".to_string(),
            payload,
            request_id: "req".to_string(),
            idempotency_key: None,
        }
    }

    #[tokio::test]
    async fn chart_dispatcher_serves_normalized_candles() {
        let provider = fake(vec![bar(2_000, 20.0), bar(1_000, 10.0), bar(1_000, 11.0)]);
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&request(json!({
                "chain": "base",
                "address": "0xabc",
                "window": "m5",
                "countBack": 10,
            })))
            .await
            .unwrap();
        assert_eq!(result["source"], "fomo-polling");
        let candles = result["candles"].as_array().unwrap();
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0]["time_ms"], 1_000);
        assert_eq!(candles[0]["close"], 11.0);
        assert_eq!(candles[1]["time_ms"], 2_000);
    }

    #[tokio::test]
    async fn chart_dispatcher_fails_closed_on_unknown_chain_window_and_bad_range() {
        let provider = fake(vec![bar(1_000, 10.0)]);
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let err = dispatcher
            .dispatch(&request(
                json!({"chain": "unknown", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, "protocol");
        let err = dispatcher
            .dispatch(&request(
                json!({"chain": "base", "address": "0xabc", "window": "1s"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, "protocol");
        let err = dispatcher
            .dispatch(&request(json!({
                "chain": "base", "address": "0xabc", "window": "m5", "from": 20, "to": 10
            })))
            .await
            .unwrap_err();
        assert_eq!(err.code, "protocol");
    }

    #[tokio::test]
    async fn chart_dispatcher_is_indeterminate_when_the_provider_is_down() {
        let provider = Arc::new(FakeProvider::new(vec![Err(FomoMarketError::Unavailable)]));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let err = dispatcher
            .dispatch(&request(
                json!({"chain": "base", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code, "server");
        assert!(err.retryable);
    }

    #[tokio::test]
    async fn chart_dispatcher_delegates_other_ops_unchanged() {
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), fake(vec![]));
        let err = dispatcher
            .dispatch(&CommandRequest {
                op: "get_token".to_string(),
                payload: json!({}),
                request_id: "req".to_string(),
                idempotency_key: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, "capability_missing");
    }

    #[tokio::test]
    async fn stream_snapshot_then_replaces_last_bar_and_appends() {
        let provider = Arc::new(FakeProvider::new(vec![
            Ok(vec![bar(1_000, 10.0), bar(2_000, 11.0)]),
            Ok(vec![bar(1_000, 10.0), bar(2_000, 12.0)]),
            Ok(vec![bar(1_000, 10.0), bar(2_000, 12.0), bar(3_000, 13.0)]),
        ]));
        let source = FomoOhlcvStreamSource::new_for_test(
            provider.clone(),
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap();

        let snapshot = source.snapshot(None).await.expect("snapshot");
        assert_eq!(snapshot.op, session_transport::StreamOp::Snapshot);
        assert_eq!(snapshot.channel, "ohlcv");
        assert_eq!(snapshot.entity_key.as_deref(), Some("ohlcv:base:0xabc"));
        assert_eq!(snapshot.payload.as_ref().unwrap()["timeframe"], "1m");
        assert_eq!(
            snapshot.payload.as_ref().unwrap()["candles"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // Same timestamp, changed close -> replace.
        let replace = source.next_delta().await.expect("replace");
        assert_eq!(replace.op, session_transport::StreamOp::Delta);
        assert_eq!(replace.payload.as_ref().unwrap()["candle"]["close"], 12.0);
        // New timestamp -> append.
        let append = source.next_delta().await.expect("append");
        assert_eq!(append.payload.as_ref().unwrap()["candle"]["time_ms"], 3_000);
    }

    #[tokio::test]
    async fn stream_emits_nothing_while_the_provider_is_down() {
        let provider = Arc::new(FakeProvider::new(vec![
            Ok(vec![bar(1_000, 10.0)]),
            Err(FomoMarketError::Unavailable),
            Ok(vec![bar(1_000, 10.0), bar(2_000, 11.0)]),
        ]));
        let source = FomoOhlcvStreamSource::new_for_test(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        let _ = source.snapshot(None).await.expect("snapshot");
        // The outage call returns nothing; the recovery call yields the new bar.
        let delta = tokio::time::timeout(Duration::from_secs(2), source.next_delta())
            .await
            .expect("no hang")
            .expect("delta");
        assert_eq!(delta.payload.as_ref().unwrap()["candle"]["time_ms"], 2_000);
    }

    #[tokio::test]
    async fn stream_snapshot_is_none_when_the_provider_is_empty() {
        let provider = Arc::new(FakeProvider::new(vec![Ok(vec![])]));
        let source = FomoOhlcvStreamSource::new_for_test(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(source.snapshot(None).await.is_none());
    }

    #[test]
    fn stream_constructor_rejects_unknown_target_and_cadence() {
        let provider = fake(vec![]);
        assert!(FomoOhlcvStreamSource::new(
            provider.clone(),
            "unknown".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_secs(5),
        )
        .is_err());
        assert!(FomoOhlcvStreamSource::new(
            provider.clone(),
            "base".into(),
            "0xabc".into(),
            "1s".into(),
            10,
            Duration::from_secs(5),
        )
        .is_err());
        assert!(FomoOhlcvStreamSource::new(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .is_err());
    }

    // ---- HTTP client (real loopback bridge, in-process axum server) ----

    #[derive(Clone)]
    struct BridgeState {
        status: axum::http::StatusCode,
        body: String,
    }

    async fn bridge_handler(
        axum::extract::State(state): axum::extract::State<BridgeState>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer test-key")
        {
            return (axum::http::StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
        (
            state.status,
            [("content-type", "application/json")],
            state.body,
        )
            .into_response()
    }

    async fn spawn_bridge(state: BridgeState) -> String {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/market/bars", get(bridge_handler))
            .route("/market/latest", get(bridge_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{address}")
    }

    fn test_client(base: &str) -> FomoBarsClient {
        FomoBarsClient::new(
            base,
            Zeroizing::new("test-key".to_string()),
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn polling_body() -> String {
        json!({
            "bars": [
                {"time": 2_000, "open": 1.0, "high": 2.0, "low": 0.5, "close": 1.5, "volume": 1.0},
                {"time": 1_000, "open": 1.0, "high": 2.0, "low": 0.5, "close": 1.5, "volume": 1.0},
            ],
            "latest": {"time": 3_000, "open": 1.0, "high": 2.0, "low": 0.5, "close": 1.5, "volume": 1.0},
            "source": {"provenance": "polling", "wsPromoted": false},
        })
        .to_string()
    }

    #[tokio::test]
    async fn client_parses_a_polling_payload_and_requires_the_bearer_key() {
        let base = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::OK,
            body: polling_body(),
        })
        .await;
        let bars = test_client(&base)
            .bars(bars_query("base", "0xabc", "5", 10, false))
            .await
            .unwrap();
        assert_eq!(
            bars.iter().map(|bar| bar.time_ms).collect::<Vec<_>>(),
            vec![1_000, 2_000, 3_000]
        );
        // A client with the wrong key gets the same redacted Unavailable error.
        let wrong = FomoBarsClient::new(
            &base,
            Zeroizing::new("wrong".to_string()),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            wrong
                .bars(bars_query("base", "0xabc", "5", 10, false))
                .await,
            Err(FomoMarketError::Unavailable)
        );
    }

    #[tokio::test]
    async fn client_rejects_non_polling_provenance_and_promoted_ws() {
        for body in [
            json!({"bars": [], "source": {"provenance": "websocket", "wsPromoted": false}})
                .to_string(),
            json!({"bars": [], "source": {"provenance": "polling", "wsPromoted": true}})
                .to_string(),
            json!({"bars": []}).to_string(),
        ] {
            let base = spawn_bridge(BridgeState {
                status: axum::http::StatusCode::OK,
                body,
            })
            .await;
            assert_eq!(
                test_client(&base)
                    .bars(bars_query("base", "0xabc", "5", 10, false))
                    .await,
                Err(FomoMarketError::InvalidResponse)
            );
        }
    }

    #[tokio::test]
    async fn client_fails_closed_on_error_malformed_and_oversized_responses() {
        let error = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::BAD_GATEWAY,
            body: json!({"error": "upstream"}).to_string(),
        })
        .await;
        assert_eq!(
            test_client(&error)
                .bars(bars_query("base", "0xabc", "5", 10, false))
                .await,
            Err(FomoMarketError::Unavailable)
        );

        let malformed = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::OK,
            body: "not json".to_string(),
        })
        .await;
        assert_eq!(
            test_client(&malformed)
                .bars(bars_query("base", "0xabc", "5", 10, false))
                .await,
            Err(FomoMarketError::InvalidResponse)
        );

        let oversized = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::OK,
            body: "a".repeat(MAX_RESPONSE_BYTES + 1),
        })
        .await;
        assert_eq!(
            test_client(&oversized)
                .bars(bars_query("base", "0xabc", "5", 10, false))
                .await,
            Err(FomoMarketError::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn client_accepts_a_latest_only_payload_and_drops_malformed_bars() {
        let latest_only = json!({
            "bars": [],
            "latest": {"time": 1_000, "open": 1.0, "high": 2.0, "low": 0.5, "close": 1.5, "volume": 1.0},
            "source": {"provenance": "polling", "wsPromoted": false},
        })
        .to_string();
        let base = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::OK,
            body: latest_only,
        })
        .await;
        let bars = test_client(&base)
            .bars(bars_query("base", "0xabc", "5", 10, true))
            .await
            .unwrap();
        assert_eq!(bars.len(), 1);
        assert_eq!(bars[0].time_ms, 1_000);

        // One inverted bar is dropped; the valid one survives.
        let mixed = json!({
            "bars": [
                {"time": 1_000, "open": 1.0, "high": 0.5, "low": 2.0, "close": 1.0, "volume": 1.0},
                {"time": 2_000, "open": 1.0, "high": 2.0, "low": 0.5, "close": 1.5, "volume": 1.0},
            ],
            "source": {"provenance": "polling", "wsPromoted": false},
        })
        .to_string();
        let base = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::OK,
            body: mixed,
        })
        .await;
        let bars = test_client(&base)
            .bars(bars_query("base", "0xabc", "5", 10, false))
            .await
            .unwrap();
        assert_eq!(
            bars.iter().map(|bar| bar.time_ms).collect::<Vec<_>>(),
            vec![2_000]
        );
    }

    #[tokio::test]
    async fn client_rejects_a_negative_range_before_connecting() {
        // No server is spawned: a negative bound must fail before any request.
        let client = test_client("http://127.0.0.1:1");
        assert_eq!(
            client
                .bars(BarsQuery {
                    chain_slug: "base",
                    address: "0xabc",
                    resolution: "5",
                    count_back: 10,
                    from_s: Some(-5),
                    to_s: None,
                    latest: false,
                })
                .await,
            Err(FomoMarketError::InvalidRequest)
        );
    }
}
