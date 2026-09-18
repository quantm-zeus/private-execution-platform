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

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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
use tokio::sync::watch;
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
///
/// The floor is 1s: a 1s/2s poll is allowed in code (the production default is
/// 2s) and a misconfigured faster interval is clamped up, never honoured. The
/// floor only bounds the *polling fallback*; the WS-first lane is bounded by its
/// own interval.
pub const MIN_STREAM_POLL: Duration = Duration::from_secs(1);
pub const MAX_STREAM_POLL: Duration = Duration::from_secs(60);
/// Consecutive provider failures before a polled stream ends (so the driver can
/// release its hub slot and the client can reconnect with a fresh snapshot).
const MAX_STREAM_FAILURES: u32 = 6;
/// Sanity ceiling for a millisecond timestamp (year 2100).
const MAX_TIMESTAMP_MS: i64 = 4_102_444_800_000;

/// Bounded-cadence interval for the WS-first lane's `/market/realtime` poll.
pub const DEFAULT_LANE_INTERVAL: Duration = Duration::from_secs(1);
/// A live lane with no event for this long is marked stale (provenance falls
/// back to polling). The hub task also uses it to bound an idle `next_event`.
pub const DEFAULT_LANE_FRESHNESS_TTL: Duration = Duration::from_secs(15);
/// Backoff after a lane `next_event` returns `None` (endpoint missing/unreachable
/// /invalid provenance).
pub const DEFAULT_LANE_BACKOFF: Duration = Duration::from_secs(2);
/// Upper bound on distinct `(network, address)` price events retained by a hub.
pub const DEFAULT_LANE_MAX_PRICES: usize = 4096;
/// Upper bound on tokens retained from one trending lane event.
pub const DEFAULT_LANE_MAX_TOKENS: usize = 200;

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

    /// The token/market-read variant of [`Self::denial`]. Same redaction rules;
    /// only the constant message differs so a search/detail/trending failure is
    /// not mislabelled as a chart failure.
    pub fn market_denial(self) -> CommandDenial {
        match self {
            Self::NotConfigured => CommandDenial::determinate(
                DenialCode::CapabilityMissing,
                "Market data source is not configured.",
            ),
            Self::InvalidRequest => {
                CommandDenial::determinate(DenialCode::Protocol, "Market request is invalid.")
            }
            Self::Unavailable | Self::InvalidResponse => CommandDenial::indeterminate(
                DenialCode::Server,
                "Market data is temporarily unavailable.",
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
///
/// Verified set: Solana (`1_399_811_149`), Base (`8_453`), Ethereum (`1`),
/// BNB Chain (`56`) and the Robinhood-associated network (`4_663`). Robinhood
/// is a read-path identity only: its execution transport/provider semantics are
/// deliberately NOT asserted here.
pub fn fomo_network_id(chain_slug: &str) -> Option<i64> {
    match chain_slug.trim().to_ascii_lowercase().as_str() {
        "solana" => Some(1_399_811_149),
        "base" => Some(8_453),
        "ethereum" => Some(1),
        "bnb_chain" | "bsc" | "bnb" => Some(56),
        "robinhood" | "robinhood_chain" => Some(4_663),
        _ => None,
    }
}

/// The canonical PEP chain slug for a verified FOMO network id.
///
/// Unknown ids return `None`, so a read result on a network PEP cannot verify is
/// dropped rather than mislabelled to another chain.
pub fn fomo_chain_slug(network_id: i64) -> Option<&'static str> {
    match network_id {
        1_399_811_149 => Some("solana"),
        8_453 => Some("base"),
        1 => Some("ethereum"),
        56 => Some("bnb_chain"),
        4_663 => Some("robinhood"),
        _ => None,
    }
}

/// The read-path chain registry advertised in the authoritative bootstrap
/// document.
///
/// Every entry is a chain whose FOMO network id is verified above. `enabled`
/// is consumed by the terminal's mutation surfaces as execution readiness, so
/// a read-path registry must NEVER set it merely because an adapter type exists.
/// Production execution readiness belongs to the live composition after a
/// concrete transport is configured and probed; this read-only FOMO registry
/// therefore advertises every identity with `enabled=false`, including chains
/// that have verified adapter implementations. The native quote asset is
/// intentionally `None`: PEP has no authoritative native-asset address for
/// these read identities and must not guess one.
pub fn read_path_chains() -> Vec<crate::opaque::ChainEntry> {
    [
        ("solana", "Solana", false),
        ("base", "Base", false),
        ("ethereum", "Ethereum", false),
        ("bnb_chain", "BNB Chain", false),
        ("robinhood", "Robinhood", false),
    ]
    .into_iter()
    .map(|(id, display, enabled)| crate::opaque::ChainEntry {
        id: id.to_string(),
        display: display.to_string(),
        enabled,
        native_token: None,
    })
    .collect()
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

/// Whether a chain's token identity is verified EVM-address-shaped and may
/// therefore be compared ASCII-case-insensitively.
///
/// Only Base/Ethereum/BNB Chain are verified EVM chains. Solana base58 is
/// case-sensitive, and the Robinhood-associated network is not verified as EVM,
/// so both must compare byte-for-byte rather than guess.
fn identity_is_case_insensitive(chain_slug: &str) -> bool {
    matches!(
        chain_slug.trim().to_ascii_lowercase().as_str(),
        "base" | "ethereum" | "bnb_chain" | "bsc" | "bnb"
    )
}

/// Compare a bridge token row's identity against the exact identity PEP
/// requested, using the chain-specific case rule. Used both for the detail
/// envelope and for the exact-address enrichment row.
fn row_identity_matches(
    chain_slug: &str,
    expected_network: i64,
    expected_address: &str,
    row: &BridgeToken,
) -> bool {
    row.network_id == expected_network
        && if identity_is_case_insensitive(chain_slug) {
            row.address.eq_ignore_ascii_case(expected_address)
        } else {
            row.address == expected_address
        }
}

/// Compare the bridge-echoed token identity against the exact identity PEP
/// requested, using the chain-specific case rule.
///
/// A response that fails this rule is an invalid provider response: it must
/// never be rendered under the requested identity. EVM chains accept a
/// checksum/case variant; Solana and the unverified Robinhood-associated
/// network require byte-for-byte equality.
fn returned_identity_matches(
    chain_slug: &str,
    expected_network: i64,
    expected_address: &str,
    detail: &BridgeTokenDetail,
) -> bool {
    detail.network_id == expected_network
        && if identity_is_case_insensitive(chain_slug) {
            detail.address.eq_ignore_ascii_case(expected_address)
        } else {
            detail.address == expected_address
        }
}

/// A per-session realtime chart target.
///
/// The target is only ever set through the authenticated encrypted command
/// channel and is stored against the session's `kid`. It never appears in a URL,
/// a clear relay frame, a log line or the outbound stream metadata (the stream
/// frames are sealed under the session key, so `entity_key`/`channel` stay
/// confidential).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeTarget {
    pub chain: String,
    pub address: String,
    pub timeframe: String,
}

impl RealtimeTarget {
    /// Validate against the closed chain/timeframe maps. Unknown chains and
    /// windows are refused rather than coerced to a default.
    pub fn validated(chain: &str, address: &str, timeframe: &str) -> Option<Self> {
        if fomo_symbol(chain, address).is_none() || fomo_resolution(timeframe).is_none() {
            return None;
        }
        Some(Self {
            chain: chain.to_string(),
            address: address.to_string(),
            timeframe: timeframe.to_string(),
        })
    }

    /// The sealed stream entity key, derived from the validated target.
    pub fn entity_key(&self) -> String {
        format!("ohlcv:{}:{}", self.chain, self.address)
    }
}

/// Session-scoped realtime target bindings (`kid` -> target).
///
/// Bounded and RAM-only: one entry per live session, evicted arbitrarily once
/// the cap is reached so a flood of authenticated enrollments cannot grow the
/// process without limit. A missing binding is a fail-closed state, not a
/// default target.
pub struct RealtimeTargetRegistry {
    inner: Mutex<HashMap<Vec<u8>, RealtimeTarget>>,
    max_entries: usize,
}

impl std::fmt::Debug for RealtimeTargetRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.inner.lock().map(|map| map.len()).unwrap_or(0);
        f.debug_struct("RealtimeTargetRegistry")
            .field("sessions", &len)
            .finish()
    }
}

impl Default for RealtimeTargetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeTargetRegistry {
    /// Upper bound on distinct session bindings held in memory.
    pub const MAX_ENTRIES: usize = 4096;

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries: Self::MAX_ENTRIES,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, RealtimeTarget>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Bind (or replace) the target for a session. The target is re-validated
    /// here so a caller that bypassed the dispatcher's own check still cannot
    /// store an unknown chain/window.
    pub fn set(&self, kid: &[u8], target: RealtimeTarget) -> Result<(), FomoMarketError> {
        if kid.is_empty()
            || RealtimeTarget::validated(&target.chain, &target.address, &target.timeframe)
                .is_none()
        {
            return Err(FomoMarketError::InvalidRequest);
        }
        let mut map = self.lock();
        if map.len() >= self.max_entries && !map.contains_key(kid) {
            if let Some(evict) = map.keys().next().cloned() {
                map.remove(&evict);
            }
        }
        map.insert(kid.to_vec(), target);
        Ok(())
    }

    /// The session's current target, or `None` when it has not selected one.
    pub fn get(&self, kid: &[u8]) -> Option<RealtimeTarget> {
        self.lock().get(kid).cloned()
    }

    /// Forget a session binding (called when a session ends).
    pub fn clear(&self, kid: &[u8]) {
        self.lock().remove(kid);
    }

    /// Diagnostic count of live bindings.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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

/// One bounded token row from the FOMO bridge read contract.
///
/// Every financial field is optional: `None` means the provider did not return
/// a usable value, never a fabricated zero.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeToken {
    pub address: String,
    pub network_id: i64,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub price_usd: Option<f64>,
    #[serde(default)]
    pub market_cap_usd: Option<f64>,
    #[serde(default)]
    pub liquidity_usd: Option<f64>,
    #[serde(default)]
    pub volume24h_usd: Option<f64>,
    #[serde(default)]
    pub change24h: Option<f64>,
    #[serde(default)]
    pub holders: Option<f64>,
    #[serde(default)]
    pub rank: Option<i64>,
}

/// Bounded search response from `GET /market/search`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSearch {
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub results: Vec<BridgeToken>,
}

/// Token-detail metrics from `GET /market/token`.
#[derive(Clone, Debug, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeDetailMetrics {
    #[serde(default)]
    pub price: Option<f64>,
    #[serde(default)]
    pub market_cap: Option<f64>,
    #[serde(default)]
    pub fdv: Option<f64>,
    #[serde(default)]
    pub liquidity: Option<f64>,
    #[serde(default)]
    pub volume24: Option<f64>,
    #[serde(default)]
    pub change24: Option<f64>,
    #[serde(default)]
    pub holders: Option<f64>,
    #[serde(default)]
    pub top10_holders_percent: Option<f64>,
}

/// Risk/warning state from `GET /market/token`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeRisk {
    #[serde(default)]
    pub disable_buying: Option<bool>,
    #[serde(default)]
    pub disable_selling: Option<bool>,
    /// `clear` or `hard_risk`; absent/unknown is treated as unknown, never safe.
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Bounded token-detail response from `GET /market/token`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeTokenDetail {
    pub address: String,
    pub network_id: i64,
    #[serde(default)]
    pub chain: Option<String>,
    pub token: BridgeToken,
    #[serde(default)]
    pub detail: Option<BridgeDetailMetrics>,
    #[serde(default)]
    pub risk: Option<BridgeRisk>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Bounded token-list response from `GET /market/trending`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeTrending {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tokens: Vec<BridgeToken>,
}

/// An injected read-only OHLCV + market-read source. The HTTP client and test
/// fakes both implement this, so the dispatcher/stream logic is testable without
/// network. One request is grouped so the seam stays a single argument.
#[async_trait]
pub trait BarsProvider: Send + Sync {
    /// Fetch normalized candles. Implementations MUST fail closed and MUST NOT
    /// synthesize a bar for a gap.
    async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError>;

    /// Bounded token search by symbol/name/address. The default fails closed so
    /// an injected provider that does not serve reads cannot fabricate results.
    async fn search(&self, _query: &str) -> Result<BridgeSearch, FomoMarketError> {
        Err(FomoMarketError::NotConfigured)
    }

    /// Bounded token detail for a verified chain/address pair.
    async fn token(
        &self,
        _chain_slug: &str,
        _address: &str,
    ) -> Result<BridgeTokenDetail, FomoMarketError> {
        Err(FomoMarketError::NotConfigured)
    }

    /// Bounded verified token list.
    async fn trending(
        &self,
        _category: &str,
        _limit: u32,
    ) -> Result<BridgeTrending, FomoMarketError> {
        Err(FomoMarketError::NotConfigured)
    }
}

/// Operator configuration for the FOMO market bridge.
#[derive(Clone, Debug)]
pub struct FomoMarketConfig {
    pub base_url: String,
    pub api_key_file: PathBuf,
    pub request_timeout: Duration,
    /// Optional single realtime target `(chain_slug, address, timeframe_id)`.
    pub stream_target: Option<(String, String, String)>,
    /// Optional `(chain_slug, address)` used only by the chart-history health
    /// proof. When absent the proof falls back to the realtime target's
    /// chain/address; when both are absent the configured source cannot prove
    /// chart history and `chart` is not advertised.
    pub history_target: Option<(String, String)>,
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

    /// The `(chain_slug, address)` the bounded history health proof targets.
    ///
    /// Prefers the dedicated history target; otherwise reuses the realtime
    /// target. `None` means the source has no provable history target and must
    /// not advertise `chart`.
    pub fn history_probe_pair(&self) -> Option<(&str, &str)> {
        if let Some((chain, address)) = self.history_target.as_ref() {
            return Some((chain.as_str(), address.as_str()));
        }
        self.stream_target
            .as_ref()
            .map(|(chain, address, _)| (chain.as_str(), address.as_str()))
    }
}

/// One authenticated loopback GET returning the bounded body. Shared by the
/// bars/read client and the WS-first realtime lane client so the bearer-header
/// and body-bound rules cannot drift.
///
/// The bearer header is built in a zeroizing buffer; the underlying
/// `HeaderValue` copy is owned by hyper and cannot be zeroized.
async fn bridge_get_bytes(
    http: &HyperClient<HttpConnector, Empty<Bytes>>,
    api_key: &str,
    timeout: Duration,
    uri: String,
) -> Result<Vec<u8>, FomoMarketError> {
    let authorization = Zeroizing::new(format!("Bearer {api_key}"));
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", authorization.as_str())
        .header("accept", "application/json")
        .body(Empty::<Bytes>::new())
        .map_err(|_| FomoMarketError::InvalidResponse)?;
    let response = tokio::time::timeout(timeout, http.request(request))
        .await
        .map_err(|_| FomoMarketError::Unavailable)?
        .map_err(|_| FomoMarketError::Unavailable)?;
    if !response.status().is_success() {
        // A determinate per-request 4xx rejection (for example an unknown
        // token) must not let any authenticated caller flip the shared
        // `/ready` dependency. Auth/permission failures (401/403) and
        // provider throttling/cool-off statuses (408/425/429) are access or
        // availability problems, and 5xx/transport failures are real
        // outages, so those stay `Unavailable`.
        let code = response.status().as_u16();
        if (400..500).contains(&code) && !matches!(code, 401 | 403 | 408 | 425 | 429) {
            return Err(FomoMarketError::InvalidRequest);
        }
        return Err(FomoMarketError::Unavailable);
    }
    // Bound the body explicitly *and* on a deadline: a compromised loopback
    // listener must not be able to stall the read (or make PEP buffer an
    // unbounded amount).
    let mut stream = response.into_body();
    tokio::time::timeout(timeout, async {
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
    .map_err(|_| FomoMarketError::Unavailable)?
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

    /// Perform one authenticated loopback GET and return the bounded body.
    ///
    /// The bearer header is built in a zeroizing buffer; the underlying
    /// `HeaderValue` copy is owned by hyper and cannot be zeroized.
    async fn get_bytes(&self, uri: String) -> Result<Vec<u8>, FomoMarketError> {
        bridge_get_bytes(&self.http, self.api_key.as_str(), self.timeout, uri).await
    }

    /// One authenticated read parsed as JSON.
    async fn get_json(&self, uri: String) -> Result<Value, FomoMarketError> {
        let body = self.get_bytes(uri).await?;
        serde_json::from_slice(&body).map_err(|_| FomoMarketError::InvalidResponse)
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
        let body = self.get_bytes(uri).await?;
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

    /// Bound a symbol/name/address search to the `fomo-mcp` read route. The
    /// query is percent-encoded so a phrase with spaces/symbols cannot alter the
    /// request line.
    async fn search(&self, query: &str) -> Result<BridgeSearch, FomoMarketError> {
        let query = query.trim();
        if query.is_empty() || query.len() > 128 {
            return Err(FomoMarketError::InvalidRequest);
        }
        let uri = format!(
            "{}/market/search?query={}",
            self.base_url,
            encode_query_component(query)
        );
        let value = self.get_json(uri).await?;
        serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)
    }

    /// Bounded token detail. The chain slug/address are validated by
    /// [`fomo_symbol`] before any request, so an unknown chain never reaches the
    /// bridge.
    async fn token(
        &self,
        chain_slug: &str,
        address: &str,
    ) -> Result<BridgeTokenDetail, FomoMarketError> {
        let symbol = fomo_symbol(chain_slug, address).ok_or(FomoMarketError::InvalidRequest)?;
        let uri = format!("{}/market/token?symbol={symbol}", self.base_url);
        let value = self.get_json(uri).await?;
        serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)
    }

    /// Bounded verified token list. The category is closed to the verified set
    /// so an arbitrary path cannot be probed through the bridge.
    async fn trending(
        &self,
        category: &str,
        limit: u32,
    ) -> Result<BridgeTrending, FomoMarketError> {
        let category = category.trim();
        if !matches!(
            category,
            "trending" | "most-held" | "graduated" | "crypto-tokens" | "verified"
        ) {
            return Err(FomoMarketError::InvalidRequest);
        }
        let limit = limit.clamp(1, 100);
        let uri = format!(
            "{}/market/trending?category={category}&limit={limit}",
            self.base_url
        );
        let value = self.get_json(uri).await?;
        serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)
    }
}

// ---- WS-first realtime lane ------------------------------------------- //

/// One event pushed by a [`RealtimeLane`]. The lane is the bridge's
/// WebSocket-promoted realtime feed; PEP only consumes it when the strict
/// provenance gate below passes.
#[derive(Clone, Debug, PartialEq)]
pub struct LaneEvent {
    pub kind: LaneEventKind,
    pub observed_at_ms: i64,
}

/// The bounded kinds of lane event PEP consumes.
#[derive(Clone, Debug, PartialEq)]
pub enum LaneEventKind {
    Trending {
        category: String,
        tokens: Vec<BridgeToken>,
    },
    Price {
        network_id: i64,
        address: String,
        price_usd: f64,
        change24h: Option<f64>,
        market_cap_usd: Option<f64>,
        liquidity_usd: Option<f64>,
        volume24h_usd: Option<f64>,
    },
}

/// An injected realtime lane.
///
/// Implementations MUST fail closed: a lane that cannot prove WS provenance
/// returns `None` from `next_event` and reports `is_live() == false`.
#[async_trait]
pub trait RealtimeLane: Send + Sync {
    /// The next pushed event, or `None` when the lane is not live.
    async fn next_event(&self) -> Option<LaneEvent>;
    /// Whether the lane is currently WS-verified.
    fn is_live(&self) -> bool;
}

/// The latest trending frame pushed by a lane.
#[derive(Clone, Debug, PartialEq)]
pub struct TrendingLaneEvent {
    pub category: String,
    pub tokens: Vec<BridgeToken>,
    pub observed_at_ms: i64,
    /// The lane generation that produced this event, so a consumer can emit it
    /// exactly once instead of re-sending it on every unrelated price tick.
    pub generation: u64,
}

/// The latest price frame pushed by a lane for one exact entity.
#[derive(Clone, Debug, PartialEq)]
pub struct PriceLaneEvent {
    pub network_id: i64,
    pub address: String,
    pub price_usd: f64,
    pub change24h: Option<f64>,
    pub market_cap_usd: Option<f64>,
    pub liquidity_usd: Option<f64>,
    pub volume24h_usd: Option<f64>,
    pub observed_at_ms: i64,
    /// The lane generation that produced this event.
    pub generation: u64,
}

/// The shared, bounded lane state a stream source subscribes to.
#[derive(Clone, Debug, Default)]
pub struct LaneState {
    pub generation: u64,
    pub live: bool,
    pub trending: Option<TrendingLaneEvent>,
    pub prices: HashMap<(i64, String), PriceLaneEvent>,
}

/// Fan-out hub for one [`RealtimeLane`].
///
/// `publish` updates the watch state; `spawn` drives a lane, marking the state
/// live on every event and stale after a freshness TTL or on `None`, with a
/// bounded backoff. The price map is capped (oldest evicted) and a trending
/// token list is truncated, so a hostile/broken lane cannot grow memory.
pub struct LaneHub {
    sender: watch::Sender<LaneState>,
    freshness_ttl: Duration,
    backoff: Duration,
    max_prices: usize,
    max_tokens: usize,
}

impl std::fmt::Debug for LaneHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneHub")
            .field("freshness_ttl", &self.freshness_ttl)
            .field("backoff", &self.backoff)
            .field("max_prices", &self.max_prices)
            .field("max_tokens", &self.max_tokens)
            .finish_non_exhaustive()
    }
}

impl Default for LaneHub {
    fn default() -> Self {
        Self::new()
    }
}

impl LaneHub {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_LANE_FRESHNESS_TTL,
            DEFAULT_LANE_BACKOFF,
            DEFAULT_LANE_MAX_PRICES,
            DEFAULT_LANE_MAX_TOKENS,
        )
    }

    /// Constructor with explicit freshness/backoff bounds and map caps. The caps
    /// are floored at 1 so a zero can never make the hub drop every value.
    pub fn with_limits(
        freshness_ttl: Duration,
        backoff: Duration,
        max_prices: usize,
        max_tokens: usize,
    ) -> Self {
        let (sender, _receiver) = watch::channel(LaneState::default());
        Self {
            sender,
            freshness_ttl,
            backoff,
            max_prices: max_prices.max(1),
            max_tokens: max_tokens.max(1),
        }
    }

    /// A receiver positioned at the current state.
    pub fn subscribe(&self) -> watch::Receiver<LaneState> {
        self.sender.subscribe()
    }

    /// The current state (a cheap clone; the maps are bounded).
    pub fn current(&self) -> LaneState {
        self.sender.borrow().clone()
    }

    /// Publish one event, marking the lane live.
    pub fn publish(&self, event: LaneEvent) {
        self.sender.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            let generation = state.generation;
            state.live = true;
            match event.kind {
                LaneEventKind::Trending { category, tokens } => {
                    let mut tokens = tokens;
                    if tokens.len() > self.max_tokens {
                        tokens.truncate(self.max_tokens);
                    }
                    state.trending = Some(TrendingLaneEvent {
                        category,
                        tokens,
                        observed_at_ms: event.observed_at_ms,
                        generation,
                    });
                }
                LaneEventKind::Price {
                    network_id,
                    address,
                    price_usd,
                    change24h,
                    market_cap_usd,
                    liquidity_usd,
                    volume24h_usd,
                } => {
                    let key = (network_id, address.clone());
                    if !state.prices.contains_key(&key) && state.prices.len() >= self.max_prices {
                        if let Some(oldest) = state
                            .prices
                            .iter()
                            .min_by_key(|(_, value)| value.observed_at_ms)
                            .map(|(key, _)| key.clone())
                        {
                            state.prices.remove(&oldest);
                        }
                    }
                    state.prices.insert(
                        key,
                        PriceLaneEvent {
                            network_id,
                            address,
                            price_usd,
                            change24h,
                            market_cap_usd,
                            liquidity_usd,
                            volume24h_usd,
                            observed_at_ms: event.observed_at_ms,
                            generation,
                        },
                    );
                }
            }
        });
    }

    /// Mark the lane not live. The last data is retained for a later
    /// reconciliation but is never labelled live.
    pub fn mark_stale(&self) {
        self.sender.send_modify(|state| {
            state.live = false;
            state.generation = state.generation.wrapping_add(1);
        });
    }

    /// Drive `lane`, publishing every event and marking live/stale with the
    /// freshness TTL. Backs off when the lane reports `None`.
    pub fn spawn(self: &Arc<Self>, lane: Arc<dyn RealtimeLane>) {
        let hub = self.clone();
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(hub.freshness_ttl, lane.next_event()).await {
                    Ok(Some(event)) => hub.publish(event),
                    Ok(None) => {
                        hub.mark_stale();
                        tokio::time::sleep(hub.backoff).await;
                    }
                    // No event within the TTL: the lane is live-but-idle or
                    // wedged, so provenance falls back to polling until the next
                    // event.
                    Err(_) => hub.mark_stale(),
                }
            }
        });
    }
}

/// Wire shape of one `/market/realtime` event. The `type` tag discriminates the
/// two bounded kinds.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum RealtimeEventWire {
    #[serde(rename_all = "camelCase")]
    Trending {
        #[serde(default)]
        category: String,
        #[serde(default)]
        tokens: Vec<BridgeToken>,
        #[serde(default)]
        observed_at_ms: i64,
    },
    #[serde(rename_all = "camelCase")]
    Price {
        network_id: i64,
        address: String,
        price_usd: f64,
        #[serde(default)]
        change24h: Option<f64>,
        #[serde(default)]
        market_cap_usd: Option<f64>,
        #[serde(default)]
        liquidity_usd: Option<f64>,
        #[serde(default)]
        volume24h_usd: Option<f64>,
        #[serde(default)]
        observed_at_ms: i64,
    },
}

impl RealtimeEventWire {
    fn into_lane_event(self) -> Option<LaneEvent> {
        match self {
            Self::Trending {
                category,
                tokens,
                observed_at_ms,
            } => Some(LaneEvent {
                kind: LaneEventKind::Trending { category, tokens },
                observed_at_ms,
            }),
            Self::Price {
                network_id,
                address,
                price_usd,
                change24h,
                market_cap_usd,
                liquidity_usd,
                volume24h_usd,
                observed_at_ms,
            } => {
                // A malformed price event is dropped, never repaired. The lane
                // source additionally filters by exact target identity.
                if !valid_address(&address) || !price_usd.is_finite() {
                    return None;
                }
                Some(LaneEvent {
                    kind: LaneEventKind::Price {
                        network_id,
                        address,
                        price_usd,
                        change24h,
                        market_cap_usd,
                        liquidity_usd,
                        volume24h_usd,
                    },
                    observed_at_ms,
                })
            }
        }
    }
}

/// Bounded `/market/realtime` batch.
#[derive(Debug, Deserialize)]
struct RealtimeBatchWire {
    #[serde(default)]
    events: Vec<RealtimeEventWire>,
    #[serde(default)]
    cursor: i64,
    #[serde(default)]
    source: Option<SourceWire>,
}

/// The strict WS provenance gate: a batch is WS-verified only when the bridge
/// explicitly labels it `websocket` AND `wsPromoted == true`. Anything else
/// (polling, unlabelled, promoted=false) is not live and must never be labelled
/// `fomo-ws`.
fn ws_provenance_verified(source: Option<&SourceWire>) -> bool {
    source.is_some_and(|source| {
        source.provenance.as_deref() == Some("websocket") && source.ws_promoted == Some(true)
    })
}

/// WS-first realtime lane client.
///
/// Performs a bounded-cadence authenticated `GET /market/realtime?since=<cursor>`
/// over the same loopback bridge/bearer pattern as [`FomoBarsClient`]. A batch
/// that fails the provenance gate (or an unreachable/missing endpoint) yields
/// `None` and leaves `is_live()` false. `Debug` is redacted.
pub struct FomoRealtimeLaneClient {
    http: HyperClient<HttpConnector, Empty<Bytes>>,
    base_url: String,
    api_key: Zeroizing<String>,
    timeout: Duration,
    interval: Duration,
    cursor: Mutex<i64>,
    buffer: Mutex<VecDeque<LaneEvent>>,
    live: AtomicBool,
}

impl std::fmt::Debug for FomoRealtimeLaneClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoRealtimeLaneClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl FomoRealtimeLaneClient {
    /// Build a lane client. The base URL is validated exactly like the bars
    /// client (absolute plaintext loopback, no userinfo/path/query).
    pub fn new(
        base_url: &str,
        api_key: Zeroizing<String>,
        request_timeout: Duration,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        let base_url = FomoMarketConfig::validated_base_url(base_url)?;
        if api_key.trim().is_empty() || request_timeout.is_zero() || interval.is_zero() {
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
            interval,
            cursor: Mutex::new(0),
            buffer: Mutex::new(VecDeque::new()),
            live: AtomicBool::new(false),
        })
    }

    /// Test-only constructor with a short bounded interval.
    #[cfg(test)]
    fn new_for_test(
        base_url: &str,
        api_key: Zeroizing<String>,
        request_timeout: Duration,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        Self::new(base_url, api_key, request_timeout, interval)
    }

    /// Fetch one batch, validate provenance, advance the cursor and buffer the
    /// parsed events. An invalid gate is an `InvalidResponse` (never a silent
    /// downgrade to polling).
    async fn fetch_batch(&self) -> Result<(), FomoMarketError> {
        let since = *self
            .cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let uri = format!("{}/market/realtime?since={since}", self.base_url);
        let body = bridge_get_bytes(&self.http, self.api_key.as_str(), self.timeout, uri).await?;
        let wire: RealtimeBatchWire =
            serde_json::from_slice(&body).map_err(|_| FomoMarketError::InvalidResponse)?;
        if !ws_provenance_verified(wire.source.as_ref()) {
            return Err(FomoMarketError::InvalidResponse);
        }
        let events: Vec<LaneEvent> = wire
            .events
            .into_iter()
            .filter_map(RealtimeEventWire::into_lane_event)
            .collect();
        {
            let mut cursor = self
                .cursor
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if wire.cursor > *cursor {
                *cursor = wire.cursor;
            }
        }
        let mut buffer = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buffer.extend(events);
        Ok(())
    }
}

#[async_trait]
impl RealtimeLane for FomoRealtimeLaneClient {
    async fn next_event(&self) -> Option<LaneEvent> {
        loop {
            if let Some(event) = self
                .buffer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
            {
                return Some(event);
            }
            tokio::time::sleep(self.interval).await;
            match self.fetch_batch().await {
                Ok(()) => self.live.store(true, Ordering::SeqCst),
                Err(_) => {
                    self.live.store(false, Ordering::SeqCst);
                    return None;
                }
            }
        }
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }
}

/// Percent-encode a query component (RFC 3986 unreserved set preserved).
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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

/// Build a web `TokenRef` from a bridge row.
///
/// Returns `None` when the row's network id is not in the verified read-path
/// registry, so an unknown-network result is dropped rather than mislabelled.
/// `decimals` is deliberately omitted: FOMO does not authoritatively provide
/// token decimals here and PEP must never guess them.
fn token_ref_json(row: &BridgeToken) -> Option<Value> {
    let chain = fomo_chain_slug(row.network_id)?;
    let mut map = serde_json::Map::new();
    map.insert("chain".to_string(), json!(chain));
    map.insert("address".to_string(), json!(row.address));
    if let Some(symbol) = row.symbol.as_ref() {
        map.insert("symbol".to_string(), json!(symbol));
    }
    if let Some(name) = row.name.as_ref() {
        map.insert("name".to_string(), json!(name));
    }
    Some(Value::Object(map))
}

/// A market-list row: a `TokenRef` plus the bounded financial fields the
/// provider actually returned (absent fields are omitted, never zero-filled).
/// This is the shared projection for `search_token` and `get_trending` (and the
/// realtime trending lane frame), so every list surface carries the same
/// truthful fields.
fn trending_row_json(row: &BridgeToken) -> Option<Value> {
    let mut value = token_ref_json(row)?;
    let map = value.as_object_mut()?;
    if let Some(price) = row.price_usd {
        map.insert("priceUsd".to_string(), json!(price));
    }
    if let Some(change) = row.change24h {
        map.insert("priceChange24h".to_string(), json!(change));
    }
    if let Some(cap) = row.market_cap_usd {
        map.insert("marketCapUsd".to_string(), json!(cap));
    }
    if let Some(liquidity) = row.liquidity_usd {
        map.insert("liquidityUsd".to_string(), json!(liquidity));
    }
    if let Some(volume) = row.volume24h_usd {
        map.insert("volume24hUsd".to_string(), json!(volume));
    }
    if let Some(rank) = row.rank {
        map.insert("rank".to_string(), json!(rank));
    }
    Some(value)
}

/// Project FOMO's own risk booleans and warning strings into the web risk
/// contract. No score is invented (`score` stays `null`); factors carry only
/// the provider's own statements.
fn risk_json(risk: &BridgeRisk) -> Value {
    let hard = risk.level.as_deref() == Some("hard_risk");
    let mut factors: Vec<Value> = Vec::new();
    if risk.disable_buying == Some(true) {
        factors.push(json!({
            "id": "fomo_disable_buying",
            "label": "Buying disabled",
            "severity": "critical",
            "detail": "FOMO reports buying is disabled for this token.",
        }));
    }
    if risk.disable_selling == Some(true) {
        factors.push(json!({
            "id": "fomo_disable_selling",
            "label": "Selling disabled",
            "severity": "critical",
            "detail": "FOMO reports selling is disabled for this token.",
        }));
    }
    for (index, warning) in risk.warnings.iter().enumerate() {
        factors.push(json!({
            "id": format!("fomo_warning_{index}"),
            "label": "Provider warning",
            "severity": if hard { "high" } else { "info" },
            "detail": warning,
        }));
    }
    json!({
        "score": Value::Null,
        "factors": factors,
        "buyTaxBps": Value::Null,
        "sellTaxBps": Value::Null,
        "transferFeeBps": Value::Null,
        // FOMO's `disableSelling` is about its own trading surface, not an
        // on-chain sell restriction, so it is reported as a factor and never
        // mapped onto `sellRestricted` (which stays unknown).
        "sellRestricted": Value::Null,
        "simulated": false,
        "level": risk.level,
    })
}

/// Merge one projected stat: prefer the detail metrics value when the bridge
/// supplied it, else the exact matched enrichment row value, else `null`. A
/// value is never synthesized.
fn merge_stat(
    metrics: Option<&BridgeDetailMetrics>,
    enrichment: Option<&BridgeToken>,
    from_metrics: impl Fn(&BridgeDetailMetrics) -> Option<f64>,
    from_row: impl Fn(&BridgeToken) -> Option<f64>,
) -> Value {
    metrics
        .and_then(&from_metrics)
        .or_else(|| enrichment.and_then(&from_row))
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

/// Whether the detail metrics carry every financial field the web `TokenStats`
/// exposes. When any is absent PEP makes one bounded exact-identity enrichment
/// lookup rather than rendering a partial stats object.
fn detail_stats_complete(metrics: Option<&BridgeDetailMetrics>) -> bool {
    let Some(metrics) = metrics else {
        return false;
    };
    metrics.price.is_some()
        && metrics.change24.is_some()
        && metrics.market_cap.is_some()
        && metrics.liquidity.is_some()
        && metrics.volume24.is_some()
}

/// Project a bridge token detail into the web `TokenDetail` shape. Every absent
/// value stays explicit (`null`) so the renderer never shows a confident zero.
///
/// `enrichment` is an exact network+address matched provider row (never a fuzzy
/// symbol/name match); it only fills fields the detail metrics left absent.
fn token_detail_json(
    chain: &str,
    address: &str,
    detail: &BridgeTokenDetail,
    enrichment: Option<&BridgeToken>,
) -> Value {
    let mut token = serde_json::Map::new();
    token.insert("chain".to_string(), json!(chain));
    token.insert("address".to_string(), json!(address));
    if let Some(symbol) = detail.token.symbol.as_ref() {
        token.insert("symbol".to_string(), json!(symbol));
    }
    if let Some(name) = detail.token.name.as_ref() {
        token.insert("name".to_string(), json!(name));
    }
    let metrics = detail.detail.as_ref();
    let stats = json!({
        "priceUsd": merge_stat(metrics, enrichment, |m| m.price, |r| r.price_usd),
        "priceChange24h": merge_stat(metrics, enrichment, |m| m.change24, |r| r.change24h),
        "marketCapUsd": merge_stat(metrics, enrichment, |m| m.market_cap, |r| r.market_cap_usd),
        "liquidityUsd": merge_stat(metrics, enrichment, |m| m.liquidity, |r| r.liquidity_usd),
        "volume24hUsd": merge_stat(metrics, enrichment, |m| m.volume24, |r| r.volume24h_usd),
        "holders": merge_stat(metrics, enrichment, |m| m.holders, |r| r.holders),
    });
    let risk = detail.risk.as_ref().map(risk_json);
    json!({
        "token": Value::Object(token),
        "stats": stats,
        "risk": risk,
        "evidence": Value::Array(Vec::new()),
        "slot": Value::Null,
        "sourceAgeMs": 0,
        "source": "fomo-rest",
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

/// The market-read variant of [`required_string`]: identical validation with a
/// market-specific constant denial message.
fn market_string(payload: &Value, key: &str) -> Result<String, CommandDenial> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            CommandDenial::determinate(DenialCode::Protocol, "Market request is invalid.")
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

fn optional_string(payload: &Value, key: &str) -> Result<Option<String>, CommandDenial> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| {
                CommandDenial::determinate(DenialCode::Protocol, "Market request is invalid.")
            }),
    }
}

/// Serves the browser market reads from the FOMO bridge and delegates every
/// other operation to the wrapped dispatcher unchanged.
///
/// This sits outermost so it receives the browser-shaped payloads
/// (`get_chart` `{chain, address, window, ...}`, `search_token` `{query}`,
/// `get_token` `{chain, address}`, `get_trending` `{category?, limit?}` and the
/// session-scoped `set_realtime_target` `{chain, address, timeframe}`). The
/// server-side capability gate still enforces the advertised `chart`/`market`/
/// `realtime` capability before dispatch.
pub struct FomoChartDispatcher {
    inner: Arc<dyn CommandDispatcher>,
    provider: Arc<dyn BarsProvider>,
    /// Optional observational history-health flag.
    ///
    /// Set `true` on every successful `/market/bars` chart read and `false` when
    /// the bridge refuses one. The composition shares it with `/ready`, so a
    /// bridge session that expires *after* the startup history proof still flips
    /// the FOMO readiness dependency to unhealthy rather than leaving a stale
    /// `chart` capability advertised.
    health: Option<Arc<AtomicBool>>,
    /// Optional observational market-read health flag (search/detail/trending).
    ///
    /// Set `true` on every successful read and `false` on a provider outage, so
    /// `/ready` degrades when the token read path becomes unavailable even if
    /// the chart route still works. A determinate client-side rejection never
    /// demotes it.
    market_health: Option<Arc<AtomicBool>>,
    /// Session-scoped realtime target bindings shared with the stream source.
    targets: Arc<RealtimeTargetRegistry>,
}

impl std::fmt::Debug for FomoChartDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoChartDispatcher")
            .finish_non_exhaustive()
    }
}

impl FomoChartDispatcher {
    pub fn new(inner: Arc<dyn CommandDispatcher>, provider: Arc<dyn BarsProvider>) -> Self {
        Self {
            inner,
            provider,
            health: None,
            market_health: None,
            targets: Arc::new(RealtimeTargetRegistry::new()),
        }
    }

    /// Attaches the shared history-health flag updated on every chart read.
    pub fn with_health_flag(mut self, health: Option<Arc<AtomicBool>>) -> Self {
        self.health = health;
        self
    }

    /// Attaches the shared market-read health flag updated on every token read.
    pub fn with_market_health_flag(mut self, health: Option<Arc<AtomicBool>>) -> Self {
        self.market_health = health;
        self
    }

    /// Shares the session target registry with the realtime stream source, so a
    /// target bound through `set_realtime_target` reaches the stream.
    pub fn with_targets(mut self, targets: Arc<RealtimeTargetRegistry>) -> Self {
        self.targets = targets;
        self
    }

    fn mark_health(&self, healthy: bool) {
        if let Some(flag) = self.health.as_ref() {
            flag.store(healthy, Ordering::SeqCst);
        }
    }

    fn mark_market_health(&self, healthy: bool) {
        if let Some(flag) = self.market_health.as_ref() {
            flag.store(healthy, Ordering::SeqCst);
        }
    }

    /// Map a provider result, updating the market-read health flag only for a
    /// real outage (a determinate client rejection is never an outage).
    fn market_result<T>(&self, result: Result<T, FomoMarketError>) -> Result<T, CommandDenial> {
        match result {
            Ok(value) => {
                self.mark_market_health(true);
                Ok(value)
            }
            Err(error) => {
                if !matches!(error, FomoMarketError::InvalidRequest) {
                    self.mark_market_health(false);
                }
                Err(error.market_denial())
            }
        }
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
        // Mirror the provider's own validation so a determinate client error is
        // refused here and can never reach the provider or demote readiness.
        if from.is_some_and(|value| value < 0) || to.is_some_and(|value| value < 0) {
            return Err(FomoMarketError::InvalidRequest.denial());
        }
        if let (Some(from), Some(to)) = (from, to) {
            if from > to {
                return Err(FomoMarketError::InvalidRequest.denial());
            }
        }
        let bars = match self
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
        {
            Ok(bars) => {
                self.mark_health(true);
                bars
            }
            // Only a real provider outage is the observable history failure the
            // readiness dependency must report. A determinate client-side
            // rejection (a bad address the provider refuses) must not let an
            // authenticated caller force `/ready` false.
            Err(error) => {
                if !matches!(error, FomoMarketError::InvalidRequest) {
                    self.mark_health(false);
                }
                return Err(error.denial());
            }
        };
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

    /// `search_token` -> web `{results: MarketListRow[]}`. Unverified networks
    /// are dropped by [`trending_row_json`]; no `decimals` is ever synthesized.
    /// Search rows carry the same truthful Price/24h/MCap/Liquidity/Volume
    /// projection as trending when the provider supplied them.
    async fn search_token(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        let query = market_string(&request.payload, "query")?;
        if query.chars().count() > 128 {
            return Err(FomoMarketError::InvalidRequest.market_denial());
        }
        let result = self.market_result(self.provider.search(&query).await)?;
        let results: Vec<Value> = result
            .results
            .iter()
            .filter_map(trending_row_json)
            .collect();
        Ok(json!({
            "results": results,
            "count": results.len(),
            "source": "fomo-rest",
            "sourceAgeMs": 0,
        }))
    }

    /// `get_token` -> web `TokenDetail`. The bridge must echo the exact identity
    /// PEP asked for; a mismatched row is refused rather than rendered.
    async fn get_token(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        let chain = market_string(&request.payload, "chain")?;
        let address = market_string(&request.payload, "address")?;
        let Some(expected_network) = fomo_network_id(&chain) else {
            return Err(FomoMarketError::InvalidRequest.market_denial());
        };
        if fomo_symbol(&chain, &address).is_none() {
            return Err(FomoMarketError::InvalidRequest.market_denial());
        }
        let detail = self.market_result(self.provider.token(&chain, &address).await)?;
        // The bridge must echo the exact identity PEP asked for under the
        // chain-specific case rule. A mismatch (including a same-network Solana
        // base58 case variant) is an invalid provider response: route it through
        // `market_result` so the shared market-read health flag is demoted before
        // the fail-closed denial, and `/ready` can never stay green on it.
        if !returned_identity_matches(&chain, expected_network, &address, &detail) {
            return self.market_result(Err(FomoMarketError::InvalidResponse));
        }
        // Truthful stats: if the detail metrics are incomplete, make at most one
        // bounded exact-identity lookup. The embedded token is preferred only
        // when it matches the exact requested network+address; otherwise a
        // single address search. A fuzzy symbol/name match is never used, and a
        // failed enrichment lookup neither fails the detail read nor demotes the
        // shared market-read health flag (the primary read succeeded).
        let enrichment = if detail_stats_complete(detail.detail.as_ref()) {
            None
        } else if row_identity_matches(&chain, expected_network, &address, &detail.token) {
            Some(detail.token.clone())
        } else {
            self.exact_search_row(&chain, expected_network, &address)
                .await
        };
        Ok(token_detail_json(
            &chain,
            &address,
            &detail,
            enrichment.as_ref(),
        ))
    }

    /// One bounded address search that selects only a result whose identity
    /// matches the exact expected network+address under the chain case rule.
    /// Any provider error or absent exact match yields `None`.
    async fn exact_search_row(
        &self,
        chain: &str,
        expected_network: i64,
        address: &str,
    ) -> Option<BridgeToken> {
        match self.provider.search(address).await {
            Ok(result) => result
                .results
                .into_iter()
                .find(|row| row_identity_matches(chain, expected_network, address, row)),
            Err(_) => None,
        }
    }

    /// `get_trending` -> bounded `{category, count, tokens[]}`.
    async fn get_trending(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        let category = optional_string(&request.payload, "category")?
            .unwrap_or_else(|| "trending".to_string());
        if !matches!(
            category.as_str(),
            "trending" | "most-held" | "graduated" | "crypto-tokens" | "verified"
        ) {
            return Err(FomoMarketError::InvalidRequest.market_denial());
        }
        let limit = optional_u32(&request.payload, "limit")?
            .unwrap_or(50)
            .clamp(1, 100);
        let result = self.market_result(self.provider.trending(&category, limit).await)?;
        let tokens: Vec<Value> = result.tokens.iter().filter_map(trending_row_json).collect();
        Ok(json!({
            "category": category,
            "count": tokens.len(),
            "tokens": tokens,
            "source": "fomo-rest",
            "sourceAgeMs": 0,
        }))
    }

    /// `set_realtime_target` -> bind the session's encrypted realtime target.
    ///
    /// The target is stored against the authenticated `kid`; it never travels
    /// in a URL, clear relay metadata or log line.
    async fn set_realtime_target(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        if kid.is_empty() {
            return Err(CommandDenial::determinate(
                DenialCode::Protocol,
                "A session is required to select a realtime target.",
            ));
        }
        let chain = market_string(&request.payload, "chain")?;
        let address = market_string(&request.payload, "address")?;
        let timeframe = market_string(&request.payload, "timeframe")?;
        let target = RealtimeTarget::validated(&chain, &address, &timeframe)
            .ok_or_else(|| FomoMarketError::InvalidRequest.denial())?;
        self.targets
            .set(kid, target.clone())
            .map_err(|_| FomoMarketError::InvalidRequest.denial())?;
        Ok(json!({
            "accepted": true,
            "chain": target.chain,
            "address": target.address,
            "timeframe": target.timeframe,
        }))
    }
}

#[async_trait]
impl CommandDispatcher for FomoChartDispatcher {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        match request.op.as_str() {
            "get_chart" => self.get_chart(request).await,
            "search_token" => self.search_token(request).await,
            "get_token" => self.get_token(request).await,
            "get_trending" => self.get_trending(request).await,
            // A target binding is session-scoped; the session-less dispatch path
            // cannot bind one.
            "set_realtime_target" => Err(CommandDenial::determinate(
                DenialCode::Protocol,
                "A session is required to select a realtime target.",
            )),
            _ => self.inner.dispatch(request).await,
        }
    }

    async fn dispatch_for_session(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        match request.op.as_str() {
            "get_chart" => self.get_chart(request).await,
            "search_token" => self.search_token(request).await,
            "get_token" => self.get_token(request).await,
            "get_trending" => self.get_trending(request).await,
            "set_realtime_target" => self.set_realtime_target(kid, request).await,
            _ => self.inner.dispatch_for_session(kid, request).await,
        }
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
    /// Optional observational health flag.
    ///
    /// When present it is set `true` on every successful bridge read and
    /// `false` when a snapshot read fails or the bounded consecutive-failure
    /// budget is exhausted (the point at which the source ends the stream). The
    /// readiness probe reads it, so `/ready` reflects an observed provider
    /// outage rather than a configuration claim.
    health: Option<Arc<AtomicBool>>,
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
            health: None,
        })
    }

    /// Attaches an observational health flag updated on every bridge read.
    ///
    /// The composition shares this flag with `/ready`; it is never a
    /// configuration assertion (the initial value is chosen by the caller).
    pub fn with_health_flag(mut self, health: Arc<AtomicBool>) -> Self {
        self.health = Some(health);
        self
    }

    fn mark_health(&self, healthy: bool) {
        if let Some(flag) = self.health.as_ref() {
            flag.store(healthy, Ordering::SeqCst);
        }
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
        let bars = match self.fetch().await {
            Ok(bars) => {
                self.mark_health(true);
                bars
            }
            Err(_) => {
                self.mark_health(false);
                return None;
            }
        };
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
                    self.mark_health(true);
                    bars
                }
                // Provider outage: stay silent rather than fabricate. After a
                // bounded number of consecutive failures, end the stream so the
                // driver returns and releases the hub slot and task; the client
                // reconnects and gets a fresh snapshot/error.
                Err(_) => {
                    failures = failures.saturating_add(1);
                    if failures >= MAX_STREAM_FAILURES {
                        self.mark_health(false);
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

/// The provenance a `market:status` frame reports. `Ws` is only ever used when
/// the strict lane gate passed; polling is never mislabelled as `fomo-ws`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaneProvenance {
    Ws,
    Polling,
    Unavailable,
}

impl LaneProvenance {
    fn label(self) -> &'static str {
        match self {
            Self::Ws => "fomo-ws",
            Self::Polling => "fomo-polling",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Per-session lane bookkeeping: the last generation/provenance already emitted
/// and any lane frames queued for the next `next_delta_for` call.
#[derive(Clone, Debug, Default)]
struct LaneSession {
    provenance: Option<LaneProvenance>,
    /// Last lane generation whose trending event was emitted for this session.
    trending_generation: Option<u64>,
    /// Last lane generation whose selected-target price was emitted.
    price_generation: Option<u64>,
    pending: VecDeque<SourceFrame>,
}

/// A `market:status` frame carrying the honest realtime provenance.
fn market_status_frame(provenance: LaneProvenance, reason: Option<&str>) -> SourceFrame {
    let mut payload = json!({
        "kind": "status",
        "realtimeSource": provenance.label(),
    });
    if let Some(reason) = reason {
        payload["reason"] = json!(reason);
    }
    SourceFrame::delta("market", "market:status", payload, None)
}

/// A broadcast `market:trending` frame with the enriched row projection.
fn market_trending_frame(event: &TrendingLaneEvent) -> SourceFrame {
    let tokens: Vec<Value> = event.tokens.iter().filter_map(trending_row_json).collect();
    SourceFrame::delta(
        "market",
        "market:trending",
        json!({
            "kind": "trending",
            "category": event.category,
            "tokens": tokens,
            "source": "fomo-ws",
            "observedAtMs": event.observed_at_ms,
        }),
        None,
    )
}

/// Exact-identity match between a session target and a lane price event under
/// the chain-specific case rule (EVM case-insensitive; Solana/Robinhood strict).
fn lane_price_matches(target: &RealtimeTarget, event: &PriceLaneEvent) -> bool {
    let Some(expected_network) = fomo_network_id(&target.chain) else {
        return false;
    };
    event.network_id == expected_network
        && if identity_is_case_insensitive(&target.chain) {
            event.address.eq_ignore_ascii_case(&target.address)
        } else {
            event.address == target.address
        }
}

/// A per-session `market:price` frame for the kid's exact bound target. The
/// payload chain/address exactly equal the entity key's chain/address; the chain
/// is the canonical [`fomo_chain_slug`] so a `bsc` target and a `bnb_chain`
/// target never produce divergent keys.
fn market_price_frame(target: &RealtimeTarget, event: &PriceLaneEvent) -> Option<SourceFrame> {
    if !lane_price_matches(target, event) {
        return None;
    }
    let chain = fomo_chain_slug(event.network_id)?;
    let entity_key = format!("market:price:{chain}:{}", target.address);
    let mut payload = json!({
        "kind": "price",
        "chain": chain,
        "address": target.address,
        "priceUsd": event.price_usd,
        "source": "fomo-ws",
        "observedAtMs": event.observed_at_ms,
    });
    if let Some(value) = event.change24h {
        payload["priceChange24h"] = json!(value);
    }
    if let Some(value) = event.market_cap_usd {
        payload["marketCapUsd"] = json!(value);
    }
    if let Some(value) = event.liquidity_usd {
        payload["liquidityUsd"] = json!(value);
    }
    if let Some(value) = event.volume24h_usd {
        payload["volume24hUsd"] = json!(value);
    }
    Some(SourceFrame::delta("market", entity_key, payload, None))
}

/// Select the lane price event matching the kid's exact target, if any.
fn lane_price_event_for<'a>(
    target: &RealtimeTarget,
    state: &'a LaneState,
) -> Option<&'a PriceLaneEvent> {
    state
        .prices
        .values()
        .find(|event| lane_price_matches(target, event))
}

/// Session-aware bounded-polling realtime OHLCV source.
///
/// The target is resolved per authenticated session from the encrypted
/// [`RealtimeTargetRegistry`]. When a session binds a new target, the source
/// emits a **fresh snapshot** for the new token instead of a delta, so token B
/// can never silently retain token A's series. The target and entity key travel
/// only inside the sealed stream frame; no token semantics appear in a URL or
/// clear relay metadata.
///
/// With an attached [`LaneHub`] the source is WS-first: `next_delta_for`
/// prefers pushed lane `market` frames and falls back to the bounded
/// `/market/latest` polling (emitting the existing `ohlcv` frames) when the lane
/// is not live or has no new state. With no lane the behavior is exactly the
/// polling source above.
pub struct FomoSessionStreamSource {
    provider: Arc<dyn BarsProvider>,
    targets: Arc<RealtimeTargetRegistry>,
    /// Operator seed used only before a session binds its own target.
    default_target: Option<RealtimeTarget>,
    count_back: u32,
    interval: Duration,
    /// Optional observational health flag updated on every bridge read.
    health: Option<Arc<AtomicBool>>,
    /// Last target emitted per session, used to detect a switch.
    sessions: Mutex<HashMap<Vec<u8>, RealtimeTarget>>,
    /// Optional WS-first lane hub. Absent means exactly today's polling source.
    lane: Option<Arc<LaneHub>>,
    /// Per-session lane generation/provenance/pending-frame bookkeeping.
    lane_sessions: Mutex<HashMap<Vec<u8>, LaneSession>>,
}

impl std::fmt::Debug for FomoSessionStreamSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FomoSessionStreamSource")
            .field("has_default", &self.default_target.is_some())
            .field("has_lane", &self.lane.is_some())
            .finish_non_exhaustive()
    }
}

impl FomoSessionStreamSource {
    /// Build a session-aware source. An out-of-range cadence or a malformed
    /// default target fails closed.
    pub fn new(
        provider: Arc<dyn BarsProvider>,
        targets: Arc<RealtimeTargetRegistry>,
        default_target: Option<RealtimeTarget>,
        count_back: u32,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        if !(MIN_STREAM_POLL..=MAX_STREAM_POLL).contains(&interval) {
            return Err(FomoMarketError::InvalidRequest);
        }
        if let Some(target) = &default_target {
            if RealtimeTarget::validated(&target.chain, &target.address, &target.timeframe)
                .is_none()
            {
                return Err(FomoMarketError::InvalidRequest);
            }
        }
        Ok(Self {
            provider,
            targets,
            default_target,
            count_back: FomoMarketConfig::clamp_count_back(count_back),
            interval,
            health: None,
            sessions: Mutex::new(HashMap::new()),
            lane: None,
            lane_sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Attaches an observational health flag updated on every bridge read.
    pub fn with_health_flag(mut self, health: Arc<AtomicBool>) -> Self {
        self.health = Some(health);
        self
    }

    /// Attach a WS-first lane hub. The source then prefers pushed lane `market`
    /// frames and keeps the bounded poll as an explicit reconciliation fallback.
    pub fn with_lane(mut self, lane: Arc<LaneHub>) -> Self {
        self.lane = Some(lane);
        self
    }

    /// Test-only constructor that bypasses the production poll-cadence floor.
    #[cfg(test)]
    fn new_for_test(
        provider: Arc<dyn BarsProvider>,
        targets: Arc<RealtimeTargetRegistry>,
        default_target: Option<RealtimeTarget>,
        count_back: u32,
        interval: Duration,
    ) -> Result<Self, FomoMarketError> {
        let mut source = Self::new(
            provider,
            targets,
            default_target,
            count_back,
            MIN_STREAM_POLL,
        )?;
        source.interval = interval;
        Ok(source)
    }

    fn lane_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, LaneSession>> {
        self.lane_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `f` with this session's lane bookkeeping, creating it (and evicting an
    /// arbitrary entry when the cap is reached) if needed.
    fn with_lane_session<R>(&self, kid: &[u8], f: impl FnOnce(&mut LaneSession) -> R) -> R {
        let mut sessions = self.lane_sessions();
        if sessions.len() >= RealtimeTargetRegistry::MAX_ENTRIES && !sessions.contains_key(kid) {
            if let Some(evict) = sessions.keys().next().cloned() {
                sessions.remove(&evict);
            }
        }
        f(sessions.entry(kid.to_vec()).or_default())
    }

    /// Forget a session's lane bookkeeping (called on connect/resnapshot so the
    /// status frame is emitted at least once per connection).
    fn reset_lane_session(&self, kid: &[u8]) {
        self.lane_sessions().remove(kid);
    }

    fn pop_lane_frame(&self, kid: &[u8]) -> Option<SourceFrame> {
        self.lane_sessions().get_mut(kid)?.pending.pop_front()
    }

    fn push_lane_frame(&self, kid: &[u8], frame: SourceFrame) {
        self.with_lane_session(kid, |session| session.pending.push_back(frame));
    }

    fn lane_provenance(&self, kid: &[u8]) -> Option<LaneProvenance> {
        self.lane_sessions().get(kid).and_then(|s| s.provenance)
    }

    fn set_lane_provenance(&self, kid: &[u8], provenance: LaneProvenance) {
        self.with_lane_session(kid, |session| session.provenance = Some(provenance));
    }

    fn lane_trending_generation(&self, kid: &[u8]) -> Option<u64> {
        self.lane_sessions()
            .get(kid)
            .and_then(|s| s.trending_generation)
    }

    fn set_lane_trending_generation(&self, kid: &[u8], generation: u64) {
        self.with_lane_session(kid, |session| {
            session.trending_generation = Some(generation)
        });
    }

    fn lane_price_generation(&self, kid: &[u8]) -> Option<u64> {
        self.lane_sessions()
            .get(kid)
            .and_then(|s| s.price_generation)
    }

    fn set_lane_price_generation(&self, kid: &[u8], generation: u64) {
        self.with_lane_session(kid, |session| session.price_generation = Some(generation));
    }

    /// A target switch invalidates the previously emitted price generation so
    /// the new target's current price is emitted exactly once.
    fn reset_lane_price_generation(&self, kid: &[u8]) {
        self.with_lane_session(kid, |session| session.price_generation = None);
    }

    fn mark_health(&self, healthy: bool) {
        if let Some(flag) = self.health.as_ref() {
            flag.store(healthy, Ordering::SeqCst);
        }
    }

    /// Resolve the session's target: an explicit encrypted binding first, then
    /// the operator seed. `None` is fail-closed (no default token semantics).
    fn resolve(&self, kid: &[u8]) -> Option<RealtimeTarget> {
        self.targets
            .get(kid)
            .or_else(|| self.default_target.clone())
    }

    fn last_target(&self, kid: &[u8]) -> Option<RealtimeTarget> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(kid)
            .cloned()
    }

    fn remember(&self, kid: &[u8], target: &RealtimeTarget) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if sessions.len() >= RealtimeTargetRegistry::MAX_ENTRIES && !sessions.contains_key(kid) {
            if let Some(evict) = sessions.keys().next().cloned() {
                sessions.remove(&evict);
            }
        }
        sessions.insert(kid.to_vec(), target.clone());
    }

    async fn fetch_target(&self, target: &RealtimeTarget) -> Result<Vec<Bar>, FomoMarketError> {
        let resolution =
            fomo_resolution(&target.timeframe).ok_or(FomoMarketError::InvalidRequest)?;
        Ok(normalize_bars(
            self.provider
                .bars(BarsQuery {
                    chain_slug: &target.chain,
                    address: &target.address,
                    resolution,
                    count_back: self.count_back,
                    from_s: None,
                    to_s: None,
                    latest: true,
                })
                .await?,
        ))
    }

    fn snapshot_frame(target: &RealtimeTarget, bars: &[Bar]) -> Option<SourceFrame> {
        let latest = bars.last()?;
        Some(
            SourceFrame::snapshot(
                "ohlcv",
                json!({
                    "timeframe": target.timeframe,
                    "candles": bars.iter().map(bar_json).collect::<Vec<_>>(),
                }),
                None,
            )
            .with_entity_key(target.entity_key())
            .with_priority(1)
            .with_source_age_ms(data_age_ms(latest.time_ms)),
        )
    }

    fn delta_frame(target: &RealtimeTarget, bar: &Bar) -> SourceFrame {
        SourceFrame::delta(
            "ohlcv",
            target.entity_key(),
            json!({ "timeframe": target.timeframe, "candle": bar_json(bar) }),
            None,
        )
        .with_priority(1)
        .with_source_age_ms(data_age_ms(bar.time_ms))
    }
}

#[async_trait]
impl StreamSource for FomoSessionStreamSource {
    /// Session-less callers have no target and fail closed.
    async fn snapshot(&self, _from_seq: Option<u64>) -> Option<SourceFrame> {
        None
    }

    async fn next_delta(&self) -> Option<SourceFrame> {
        None
    }

    async fn snapshot_for(&self, kid: &[u8], _from_seq: Option<u64>) -> Option<SourceFrame> {
        // A (re)connect starts a fresh lane provenance cycle so the client gets
        // the status frame at least once per connection.
        self.reset_lane_session(kid);
        let target = self.resolve(kid)?;
        match self.fetch_target(&target).await {
            Ok(bars) => {
                self.mark_health(true);
                let frame = Self::snapshot_frame(&target, &bars)?;
                self.remember(kid, &target);
                Some(frame)
            }
            Err(_) => {
                self.mark_health(false);
                None
            }
        }
    }

    async fn next_delta_for(&self, kid: &[u8]) -> Option<SourceFrame> {
        let mut failures = 0u32;
        loop {
            // Fail closed: a session with no target emits nothing.
            let target = self.resolve(kid)?;

            // Any lane frame queued for this session is delivered first.
            if let Some(frame) = self.pop_lane_frame(kid) {
                return Some(frame);
            }

            // Lane-first: prefer pushed lane frames when the lane is live.
            if let Some(lane) = self.lane.as_ref() {
                let state = lane.current();
                let live = state.live;
                let provenance = if live {
                    LaneProvenance::Ws
                } else {
                    LaneProvenance::Polling
                };
                // A target switch must resnapshot through the polling path, so
                // the lane data for this generation is skipped: a price frame
                // bound to token A can never be emitted for token B.
                let switched = self.last_target(kid).as_ref() != Some(&target);
                if live && !switched {
                    // Emit each kind exactly once per lane generation: the
                    // trending list persists across price ticks and must not be
                    // rebroadcast on every unrelated event.
                    if let Some(trending) = state.trending.as_ref() {
                        if self.lane_trending_generation(kid) != Some(trending.generation) {
                            self.set_lane_trending_generation(kid, trending.generation);
                            self.push_lane_frame(kid, market_trending_frame(trending));
                        }
                    }
                    if let Some(event) = lane_price_event_for(&target, &state) {
                        if self.lane_price_generation(kid) != Some(event.generation) {
                            self.set_lane_price_generation(kid, event.generation);
                            if let Some(frame) = market_price_frame(&target, event) {
                                self.push_lane_frame(kid, frame);
                            }
                        }
                    }
                } else if live && switched {
                    self.reset_lane_price_generation(kid);
                }
                // Provenance changes are always surfaced, never labelled
                // `fomo-ws` unless the lane gate passed.
                if self.lane_provenance(kid) != Some(provenance) {
                    self.set_lane_provenance(kid, provenance);
                    self.push_lane_frame(kid, market_status_frame(provenance, None));
                }
                if let Some(frame) = self.pop_lane_frame(kid) {
                    return Some(frame);
                }
            }

            // Bounded polling fallback (reconciliation). When a lane is live this
            // is reached only when it has no new state for this session, so the
            // market price lane is never mixed with polling-derived price data.
            tokio::time::sleep(self.interval).await;
            let target = self.resolve(kid)?;
            // A target switch must never surface as a delta: emit a fresh
            // snapshot for the new token so the renderer replaces its series.
            let switched = self.last_target(kid).as_ref() != Some(&target);
            match self.fetch_target(&target).await {
                Ok(bars) => {
                    failures = 0;
                    self.mark_health(true);
                    // Recovered from a poll outage: restore honest provenance.
                    if self.lane.is_some()
                        && self.lane_provenance(kid) == Some(LaneProvenance::Unavailable)
                    {
                        self.set_lane_provenance(kid, LaneProvenance::Polling);
                        self.push_lane_frame(
                            kid,
                            market_status_frame(LaneProvenance::Polling, None),
                        );
                    }
                    if switched {
                        if let Some(frame) = Self::snapshot_frame(&target, &bars) {
                            self.remember(kid, &target);
                            return Some(frame);
                        }
                        continue;
                    }
                    let Some(latest) = bars.last() else {
                        continue;
                    };
                    return Some(Self::delta_frame(&target, latest));
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    if failures >= MAX_STREAM_FAILURES {
                        self.mark_health(false);
                        return None;
                    }
                    // A poll outage is reported honestly as `unavailable`, never
                    // as `fomo-ws` (only relevant when a lane is attached).
                    if self.lane.is_some()
                        && self.lane_provenance(kid) != Some(LaneProvenance::Unavailable)
                    {
                        self.set_lane_provenance(kid, LaneProvenance::Unavailable);
                        self.push_lane_frame(
                            kid,
                            market_status_frame(
                                LaneProvenance::Unavailable,
                                Some("market source unavailable"),
                            ),
                        );
                        if let Some(frame) = self.pop_lane_frame(kid) {
                            return Some(frame);
                        }
                    }
                    continue;
                }
            }
        }
    }

    async fn unavailable(&self) -> Vec<SourceFrame> {
        vec![SourceFrame::error(
            "ohlcv",
            "The selected realtime target is unavailable.",
        )]
    }
}

/// A configured FOMO market wiring: the read dispatcher, an optional realtime
/// source and the session target registry they share.
pub struct FomoMarketWiring {
    pub dispatcher: Arc<dyn CommandDispatcher>,
    pub stream_source: Option<Arc<dyn StreamSource>>,
    pub targets: Arc<RealtimeTargetRegistry>,
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
    build_wiring_with_health(config, provider, inner, None)
}

/// Build the FOMO market wiring, optionally attaching an observational health
/// flag to the realtime source.
///
/// The flag is updated by the source on every bridge read; the composition
/// shares it with `/ready` so a sustained provider outage is observable. It is
/// not a configuration assertion.
pub fn build_wiring_with_health(
    config: &FomoMarketConfig,
    provider: Arc<dyn BarsProvider>,
    inner: Arc<dyn CommandDispatcher>,
    health: Option<Arc<AtomicBool>>,
) -> Result<FomoMarketWiring, FomoMarketError> {
    build_wiring_full(
        config,
        provider,
        inner,
        health,
        None,
        None,
        Arc::new(RealtimeTargetRegistry::new()),
        None,
    )
}

/// Build the FOMO market wiring with independent observational health flags for
/// the realtime `/market/latest` source and the chart `/market/bars` dispatcher.
///
/// `stream_health` is updated by the realtime source on every bounded poll read;
/// `history_health` is updated by the chart dispatcher on every history read.
/// The composition shares each with `/ready` (and with the startup history
/// proof) so a sustained outage of either route is observable rather than
/// masked by a live process. Neither flag is a configuration assertion.
pub fn build_wiring_with_health_flags(
    config: &FomoMarketConfig,
    provider: Arc<dyn BarsProvider>,
    inner: Arc<dyn CommandDispatcher>,
    stream_health: Option<Arc<AtomicBool>>,
    history_health: Option<Arc<AtomicBool>>,
) -> Result<FomoMarketWiring, FomoMarketError> {
    build_wiring_full(
        config,
        provider,
        inner,
        stream_health,
        history_health,
        None,
        Arc::new(RealtimeTargetRegistry::new()),
        None,
    )
}

/// Full FOMO market wiring: independent stream/history/market-read health flags,
/// the shared session realtime target registry and an optional WS-first lane hub.
pub fn build_wiring_full(
    config: &FomoMarketConfig,
    provider: Arc<dyn BarsProvider>,
    inner: Arc<dyn CommandDispatcher>,
    stream_health: Option<Arc<AtomicBool>>,
    history_health: Option<Arc<AtomicBool>>,
    market_health: Option<Arc<AtomicBool>>,
    targets: Arc<RealtimeTargetRegistry>,
    lane: Option<Arc<LaneHub>>,
) -> Result<FomoMarketWiring, FomoMarketError> {
    let dispatcher: Arc<dyn CommandDispatcher> = Arc::new(
        FomoChartDispatcher::new(inner, provider.clone())
            .with_health_flag(history_health)
            .with_market_health_flag(market_health)
            .with_targets(targets.clone()),
    );
    let stream_source: Option<Arc<dyn StreamSource>> = match &config.stream_target {
        None => None,
        Some((chain, address, timeframe)) => {
            let default = RealtimeTarget::validated(chain, address, timeframe)
                .ok_or(FomoMarketError::InvalidRequest)?;
            let source = FomoSessionStreamSource::new(
                provider,
                targets.clone(),
                Some(default),
                config.stream_count_back,
                config.stream_poll,
            )?;
            let source = match stream_health {
                Some(flag) => source.with_health_flag(flag),
                None => source,
            };
            let source = match lane {
                Some(lane) => source.with_lane(lane),
                None => source,
            };
            Some(Arc::new(source))
        }
    };
    Ok(FomoMarketWiring {
        dispatcher,
        stream_source,
        targets,
    })
}

/// One bounded authenticated `/market/trending` read proving the token
/// search/detail/trending read path (provider reachability + bridge session).
///
/// This is the capability proof behind `market`. A reachable-but-empty list is
/// healthy; an auth-rejected/unreachable/malformed response is not, so a
/// configured-but-expired FOMO session can never advertise `market`.
pub async fn probe_market(provider: &dyn BarsProvider) -> bool {
    provider.trending("trending", 1).await.is_ok()
}

/// One bounded `/market/latest` read observing whether the configured realtime
/// source is reachable at startup.
///
/// A reachable-but-empty response is healthy (matching the stream source's own
/// success rule); an unreachable/malformed response is not. Returns `false` when
/// no realtime target is configured.
pub async fn probe_realtime(provider: &dyn BarsProvider, config: &FomoMarketConfig) -> bool {
    let Some((chain, address, timeframe)) = config.stream_target.as_ref() else {
        return false;
    };
    let Some(resolution) = fomo_resolution(timeframe) else {
        return false;
    };
    provider
        .bars(BarsQuery {
            chain_slug: chain,
            address,
            resolution,
            count_back: FomoMarketConfig::clamp_count_back(config.stream_count_back),
            from_s: None,
            to_s: None,
            latest: true,
        })
        .await
        .is_ok()
}

/// One bounded authenticated `/market/bars` read proving the configured FOMO
/// source can actually serve chart history.
///
/// This is the capability proof behind `chart`: unlike the realtime probe, it
/// exercises the *history* route (`latest: false`) the browser chart uses, so a
/// source whose session is expired (HTTP 503 `auth_rejected`) can never be
/// advertised as chart-capable. Returns `false` when no history/realtime target
/// is configured or the bridge refuses the read.
pub async fn probe_history(provider: &dyn BarsProvider, config: &FomoMarketConfig) -> bool {
    let Some((chain, address)) = config.history_probe_pair() else {
        return false;
    };
    let Some(resolution) = fomo_resolution("1m") else {
        return false;
    };
    provider
        .bars(BarsQuery {
            chain_slug: chain,
            address,
            resolution,
            count_back: 1,
            from_s: None,
            to_s: None,
            // History, not the bounded-cadence `/market/latest` read.
            latest: false,
        })
        .await
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::collections::HashMap;
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

    #[tokio::test]
    async fn stream_health_flag_tracks_bridge_reads() {
        // The flag starts false and is only set true by an observed success, so
        // a configured-but-unreachable provider is never reported healthy.
        let health = Arc::new(AtomicBool::new(false));

        let reachable = FomoOhlcvStreamSource::new_for_test(
            fake(vec![bar(1_000, 10.0)]),
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap()
        .with_health_flag(health.clone());
        assert!(!health.load(Ordering::SeqCst));
        assert!(reachable.snapshot(None).await.is_some());
        assert!(health.load(Ordering::SeqCst));

        // An exhausted outage marks the stream unhealthy.
        let down = Arc::new(FakeProvider::new(vec![Err(FomoMarketError::Unavailable)]));
        let source = FomoOhlcvStreamSource::new_for_test(
            down,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(1),
        )
        .unwrap()
        .with_health_flag(health.clone());
        assert!(source.next_delta().await.is_none());
        assert!(!health.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn realtime_probe_requires_a_reachable_target() {
        let no_target = FomoMarketConfig {
            base_url: "http://127.0.0.1:8787".into(),
            api_key_file: PathBuf::from("/tmp/key"),
            request_timeout: Duration::from_millis(100),
            stream_target: None,
            history_target: None,
            stream_poll: Duration::from_secs(5),
            stream_count_back: 10,
        };
        // No configured target: not reachable.
        assert!(!probe_realtime(fake(vec![bar(1_000, 1.0)]).as_ref(), &no_target).await);

        let config = FomoMarketConfig {
            stream_target: Some(("base".into(), "0xabc".into(), "1m".into())),
            ..no_target
        };
        // A reachable provider (even empty) is healthy; a failing one is not.
        assert!(probe_realtime(fake(vec![bar(1_000, 1.0)]).as_ref(), &config).await);
        assert!(
            probe_realtime(fake(Vec::new()).as_ref(), &config).await,
            "a reachable-but-empty response is a success, matching the stream source"
        );
        let down = Arc::new(FakeProvider::new(vec![Err(FomoMarketError::Unavailable)]));
        assert!(!probe_realtime(down.as_ref(), &config).await);
    }

    #[tokio::test]
    async fn history_probe_uses_the_history_route_and_fails_closed() {
        /// Provider whose history and latest routes can fail independently.
        struct RouteAware {
            history: Result<Vec<Bar>, FomoMarketError>,
            latest: Result<Vec<Bar>, FomoMarketError>,
            history_calls: StdMutex<usize>,
        }

        #[async_trait]
        impl BarsProvider for RouteAware {
            async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError> {
                if query.latest {
                    self.latest.clone()
                } else {
                    *self.history_calls.lock().unwrap() += 1;
                    self.history.clone()
                }
            }
        }

        let base = FomoMarketConfig {
            base_url: "http://127.0.0.1:8787".into(),
            api_key_file: PathBuf::from("/tmp/key"),
            request_timeout: Duration::from_millis(100),
            stream_target: None,
            history_target: None,
            stream_poll: Duration::from_secs(5),
            stream_count_back: 10,
        };

        // No target at all: the proof cannot be made, so chart fails closed.
        assert!(!probe_history(fake(vec![bar(1_000, 1.0)]).as_ref(), &base).await);

        // A dedicated history target exercises the non-`latest` history route.
        let provider = Arc::new(RouteAware {
            history: Ok(vec![bar(1_000, 1.0)]),
            latest: Err(FomoMarketError::Unavailable),
            history_calls: StdMutex::new(0),
        });
        let config = FomoMarketConfig {
            history_target: Some(("base".into(), "0xabc".into())),
            ..base.clone()
        };
        assert!(probe_history(provider.as_ref(), &config).await);
        assert_eq!(*provider.history_calls.lock().unwrap(), 1);

        // An auth-rejected `/market/bars` read is not a healthy proof even when
        // the bounded-cadence latest route would answer.
        let expired = Arc::new(RouteAware {
            history: Err(FomoMarketError::Unavailable),
            latest: Ok(vec![bar(1_000, 1.0)]),
            history_calls: StdMutex::new(0),
        });
        assert!(!probe_history(expired.as_ref(), &config).await);

        // The realtime target is reused when no dedicated history target is set.
        let reused = FomoMarketConfig {
            stream_target: Some(("base".into(), "0xabc".into(), "1m".into())),
            ..base
        };
        let provider = Arc::new(RouteAware {
            history: Ok(Vec::new()),
            latest: Err(FomoMarketError::Unavailable),
            history_calls: StdMutex::new(0),
        });
        assert!(probe_history(provider.as_ref(), &reused).await);
        assert_eq!(*provider.history_calls.lock().unwrap(), 1);
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
    async fn chart_dispatcher_health_flag_tracks_history_reads() {
        let health = Arc::new(AtomicBool::new(false));
        let provider = Arc::new(FakeProvider::new(vec![
            Ok(vec![bar(1_000, 10.0)]),
            Err(FomoMarketError::Unavailable),
        ]));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider)
                .with_health_flag(Some(health.clone()));

        // A successful history read proves the source healthy.
        assert!(dispatcher
            .dispatch(&request(
                json!({"chain": "base", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .is_ok());
        assert!(health.load(Ordering::SeqCst));

        // A later provider refusal flips the shared flag false, so `/ready` can
        // report an expired bridge session rather than a stale healthy proof.
        assert!(dispatcher
            .dispatch(&request(
                json!({"chain": "base", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .is_err());
        assert!(!health.load(Ordering::SeqCst));

        // A malformed request never reaches the provider and must not mark the
        // source unhealthy.
        health.store(true, Ordering::SeqCst);
        assert!(dispatcher
            .dispatch(&request(
                json!({"chain": "unknown", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .is_err());
        assert!(health.load(Ordering::SeqCst));

        // A negative range is refused client-side too, so an authenticated
        // caller cannot force the shared readiness flag false.
        assert!(dispatcher
            .dispatch(&request(json!({
                "chain": "base", "address": "0xabc", "window": "m5", "from": -1
            })))
            .await
            .is_err());
        assert!(health.load(Ordering::SeqCst));

        // A provider determinate rejection is likewise not an outage.
        let rejecting = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            Arc::new(FakeProvider::new(vec![Err(
                FomoMarketError::InvalidRequest,
            )])),
        )
        .with_health_flag(Some(health.clone()));
        assert!(rejecting
            .dispatch(&request(
                json!({"chain": "base", "address": "0xabc", "window": "m5"}),
            ))
            .await
            .is_err());
        assert!(health.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn chart_dispatcher_delegates_other_ops_unchanged() {
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), fake(vec![]));
        let err = dispatcher
            .dispatch(&CommandRequest {
                // A market-read op the dispatcher does NOT own is delegated
                // unchanged to the wrapped (fail-closed) dispatcher.
                op: "get_quote".to_string(),
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
    async fn client_maps_a_non_auth_4xx_to_a_determinate_rejection() {
        // A 404 (unknown target) is a per-request client error, not an outage:
        // it must not demote the shared chart readiness flag.
        let missing = spawn_bridge(BridgeState {
            status: axum::http::StatusCode::NOT_FOUND,
            body: json!({"error": "unknown"}).to_string(),
        })
        .await;
        assert_eq!(
            test_client(&missing)
                .bars(bars_query("base", "0xabc", "5", 10, false))
                .await,
            Err(FomoMarketError::InvalidRequest)
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

    // ---- Market reads: chain registry, projections, health, realtime ---- //

    fn market_request(op: &str, payload: Value) -> CommandRequest {
        CommandRequest {
            op: op.to_string(),
            payload,
            request_id: "req".to_string(),
            idempotency_key: None,
        }
    }

    fn bridge_token(address: &str, network_id: i64, symbol: &str) -> BridgeToken {
        BridgeToken {
            address: address.to_string(),
            network_id,
            chain: None,
            symbol: Some(symbol.to_string()),
            name: Some(format!("{symbol} name")),
            price_usd: Some(1.5),
            market_cap_usd: Some(10.0),
            liquidity_usd: None,
            volume24h_usd: None,
            change24h: None,
            holders: Some(5.0),
            rank: None,
        }
    }

    /// Scripted provider: per-address bars plus scripted read results.
    #[derive(Default)]
    struct FakeMarketProvider {
        bars_by_address: StdMutex<HashMap<String, Vec<Bar>>>,
        search: StdMutex<Option<Result<BridgeSearch, FomoMarketError>>>,
        token: StdMutex<Option<Result<BridgeTokenDetail, FomoMarketError>>>,
        trending: StdMutex<Option<Result<BridgeTrending, FomoMarketError>>>,
        /// Every `search` query the dispatcher forwarded, in order.
        search_queries: StdMutex<Vec<String>>,
    }

    impl FakeMarketProvider {
        fn with_bars(address: &str, bars: Vec<Bar>) -> Self {
            let fake = Self::default();
            fake.bars_by_address
                .lock()
                .unwrap()
                .insert(address.to_string(), bars);
            fake
        }

        fn set_search(&self, result: Result<BridgeSearch, FomoMarketError>) {
            *self.search.lock().unwrap() = Some(result);
        }
        fn set_token(&self, result: Result<BridgeTokenDetail, FomoMarketError>) {
            *self.token.lock().unwrap() = Some(result);
        }
        fn set_trending(&self, result: Result<BridgeTrending, FomoMarketError>) {
            *self.trending.lock().unwrap() = Some(result);
        }
        fn search_queries(&self) -> Vec<String> {
            self.search_queries.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl BarsProvider for FakeMarketProvider {
        async fn bars(&self, query: BarsQuery<'_>) -> Result<Vec<Bar>, FomoMarketError> {
            self.bars_by_address
                .lock()
                .unwrap()
                .get(query.address)
                .cloned()
                .ok_or(FomoMarketError::Unavailable)
        }

        async fn search(&self, query: &str) -> Result<BridgeSearch, FomoMarketError> {
            self.search_queries.lock().unwrap().push(query.to_string());
            self.search
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err(FomoMarketError::NotConfigured))
        }

        async fn token(
            &self,
            _chain_slug: &str,
            _address: &str,
        ) -> Result<BridgeTokenDetail, FomoMarketError> {
            self.token
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err(FomoMarketError::NotConfigured))
        }

        async fn trending(
            &self,
            _category: &str,
            _limit: u32,
        ) -> Result<BridgeTrending, FomoMarketError> {
            self.trending
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err(FomoMarketError::NotConfigured))
        }
    }

    #[test]
    fn read_path_chain_registry_covers_the_verified_networks() {
        assert_eq!(fomo_network_id("robinnhood"), None);
        assert_eq!(fomo_network_id("robinhood"), Some(4_663));
        assert_eq!(fomo_network_id("bsc"), Some(56));
        assert_eq!(fomo_network_id("bnb_chain"), Some(56));
        assert_eq!(fomo_chain_slug(4_663), Some("robinhood"));
        assert_eq!(fomo_chain_slug(56), Some("bnb_chain"));
        assert_eq!(fomo_chain_slug(999_999), None);
        let chains = read_path_chains();
        assert_eq!(chains.len(), 5);
        for id in ["solana", "base", "ethereum", "bnb_chain", "robinhood"] {
            let chain = chains
                .iter()
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("missing read identity {id}"));
            assert!(
                !chain.enabled,
                "read-path coverage must not advertise execution readiness for {id}"
            );
        }
        // No native quote asset is guessed.
        assert!(chains.iter().all(|c| c.native_token.is_none()));
    }

    #[tokio::test]
    async fn search_projects_only_verified_network_chains() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_search(Ok(BridgeSearch {
            query: "alpha".to_string(),
            count: 4,
            results: vec![
                bridge_token("0xbase", 8_453, "BASE"),
                bridge_token(
                    "So11111111111111111111111111111111111111112",
                    1_399_811_149,
                    "SOL",
                ),
                bridge_token("0xrobinhood", 4_663, "RH"),
                bridge_token("0xunknown", 999_999, "UNK"),
            ],
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request("search_token", json!({"query": "alpha"})))
            .await
            .unwrap();
        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 3, "unverified network dropped: {result}");
        assert_eq!(results[0]["chain"], "base");
        assert_eq!(results[1]["chain"], "solana");
        assert_eq!(results[2]["chain"], "robinhood");
        // Decimals are never guessed.
        assert!(results.iter().all(|row| row.get("decimals").is_none()));
    }

    #[tokio::test]
    async fn search_forwards_name_and_address_queries_verbatim() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_search(Ok(BridgeSearch {
            query: "echo".to_string(),
            count: 1,
            results: vec![bridge_token("0xbase", 8_453, "BASE")],
        }));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        );
        let address = "0x00000000000000000000000000000000000000a1";
        // Live FOMO matches symbol, name and full address; PEP must forward the
        // operator's query byte-for-byte and never rewrite/normalize it.
        for query in ["Bonk Inu", address] {
            let result = dispatcher
                .dispatch(&market_request("search_token", json!({ "query": query })))
                .await
                .unwrap();
            assert_eq!(result["results"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            provider.search_queries(),
            vec!["Bonk Inu".to_string(), address.to_string()]
        );
    }

    #[tokio::test]
    async fn get_token_projects_stats_and_risk_truthfully() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xbase".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token("0xbase", 8_453, "BASE"),
            detail: Some(BridgeDetailMetrics {
                price: Some(0.5),
                market_cap: Some(48_901_393.8),
                holders: Some(1_200.0),
                ..BridgeDetailMetrics::default()
            }),
            risk: Some(BridgeRisk {
                disable_buying: Some(false),
                disable_selling: Some(true),
                level: Some("hard_risk".to_string()),
                warnings: vec!["honeypot".to_string()],
            }),
            warnings: Vec::new(),
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap();
        assert_eq!(result["token"]["chain"], "base");
        assert_eq!(result["token"]["symbol"], "BASE");
        assert_eq!(result["stats"]["priceUsd"], 0.5);
        assert_eq!(result["stats"]["marketCapUsd"], 48_901_393.8);
        assert!(result["stats"]["liquidityUsd"].is_null());
        assert_eq!(result["risk"]["level"], "hard_risk");
        assert!(result["risk"]["sellRestricted"].is_null());
        let factors = result["risk"]["factors"].as_array().unwrap();
        assert!(factors.iter().any(|f| f["id"] == "fomo_disable_selling"));
        assert!(factors
            .iter()
            .any(|f| f["detail"] == Value::String("honeypot".to_string())));
        assert!(result["evidence"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn search_rows_carry_provider_financials() {
        let provider = Arc::new(FakeMarketProvider::default());
        let mut row = bridge_token("0xbase", 8_453, "BASE");
        row.change24h = Some(-2.5);
        row.liquidity_usd = Some(1_234.0);
        row.volume24h_usd = Some(5_678.0);
        row.rank = Some(3);
        provider.set_search(Ok(BridgeSearch {
            query: "alpha".to_string(),
            count: 1,
            results: vec![row],
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request("search_token", json!({"query": "alpha"})))
            .await
            .unwrap();
        let row = &result["results"][0];
        assert_eq!(row["chain"], "base");
        assert_eq!(row["priceUsd"], 1.5);
        assert_eq!(row["priceChange24h"], -2.5);
        assert_eq!(row["marketCapUsd"], 10.0);
        assert_eq!(row["liquidityUsd"], 1_234.0);
        assert_eq!(row["volume24hUsd"], 5_678.0);
        assert_eq!(row["rank"], 3);
    }

    #[tokio::test]
    async fn trending_rows_carry_provider_financials() {
        let provider = Arc::new(FakeMarketProvider::default());
        let mut row = bridge_token("0xbase", 8_453, "BASE");
        row.change24h = Some(6.5);
        row.liquidity_usd = Some(2_000.0);
        row.volume24h_usd = Some(3_000.0);
        provider.set_trending(Ok(BridgeTrending {
            category: "trending".to_string(),
            tokens: vec![row],
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request("get_trending", json!({})))
            .await
            .unwrap();
        let row = &result["tokens"][0];
        assert_eq!(row["priceUsd"], 1.5);
        assert_eq!(row["priceChange24h"], 6.5);
        assert_eq!(row["liquidityUsd"], 2_000.0);
        assert_eq!(row["volume24hUsd"], 3_000.0);
    }

    #[tokio::test]
    async fn get_token_prefers_complete_detail_metrics_without_enrichment() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xbase".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token("0xbase", 8_453, "BASE"),
            detail: Some(BridgeDetailMetrics {
                price: Some(0.5),
                change24: Some(-1.0),
                market_cap: Some(100.0),
                liquidity: Some(50.0),
                volume24: Some(20.0),
                holders: Some(7.0),
                ..BridgeDetailMetrics::default()
            }),
            risk: None,
            warnings: Vec::new(),
        }));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        );
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap();
        assert_eq!(result["stats"]["priceUsd"], 0.5);
        assert_eq!(result["stats"]["priceChange24h"], -1.0);
        assert_eq!(result["stats"]["liquidityUsd"], 50.0);
        assert_eq!(result["stats"]["volume24hUsd"], 20.0);
        assert_eq!(result["stats"]["holders"], 7.0);
        assert!(
            provider.search_queries().is_empty(),
            "complete metrics need no enrichment lookup"
        );
    }

    #[tokio::test]
    async fn get_token_enriches_from_an_exact_address_search_row() {
        let provider = Arc::new(FakeMarketProvider::default());
        // The embedded token is not the requested address, so the exact-address
        // search is the only permitted enrichment source.
        let mut embedded = bridge_token("0xWRONG", 8_453, "BASE");
        embedded.price_usd = None;
        embedded.market_cap_usd = None;
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xbase".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: embedded,
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let mut row = bridge_token("0xbase", 8_453, "BASE");
        row.price_usd = Some(3.0);
        row.change24h = Some(1.25);
        row.market_cap_usd = Some(999.0);
        row.liquidity_usd = Some(444.0);
        row.volume24h_usd = Some(111.0);
        row.holders = Some(8.0);
        provider.set_search(Ok(BridgeSearch {
            query: "0xbase".to_string(),
            count: 1,
            results: vec![row],
        }));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        );
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap();
        assert_eq!(result["stats"]["priceUsd"], 3.0);
        assert_eq!(result["stats"]["priceChange24h"], 1.25);
        assert_eq!(result["stats"]["marketCapUsd"], 999.0);
        assert_eq!(result["stats"]["liquidityUsd"], 444.0);
        assert_eq!(result["stats"]["volume24hUsd"], 111.0);
        assert_eq!(result["stats"]["holders"], 8.0);
        assert_eq!(provider.search_queries(), vec!["0xbase".to_string()]);
    }

    #[tokio::test]
    async fn get_token_ignores_same_symbol_and_wrong_network_rows() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xbase".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token("0xWRONG", 8_453, "BASE"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        // Same symbol, different address, plus a wrong-network row: neither is an
        // exact identity match, so the fields stay null.
        let mut same_symbol = bridge_token("0xOTHER", 8_453, "BASE");
        same_symbol.price_usd = Some(99.0);
        let mut wrong_network = bridge_token("0xbase", 1, "BASE");
        wrong_network.price_usd = Some(88.0);
        provider.set_search(Ok(BridgeSearch {
            query: "0xbase".to_string(),
            count: 2,
            results: vec![same_symbol, wrong_network],
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap();
        assert!(result["stats"]["priceUsd"].is_null());
        assert!(result["stats"]["marketCapUsd"].is_null());
        assert!(result["stats"]["liquidityUsd"].is_null());
    }

    #[tokio::test]
    async fn get_token_enrichment_respects_the_chain_case_rule() {
        // EVM: a checksum case variant of the requested address IS matched.
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xabcdef0000000000000000000000000000000001".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token("0xWRONG", 8_453, "BASE"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let mut evm_row = bridge_token("0xAbCdEf0000000000000000000000000000000001", 8_453, "BASE");
        evm_row.price_usd = Some(7.0);
        provider.set_search(Ok(BridgeSearch {
            query: "0xabcdef0000000000000000000000000000000001".to_string(),
            count: 1,
            results: vec![evm_row],
        }));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        );
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({
                    "chain": "base",
                    "address": "0xabcdef0000000000000000000000000000000001"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(result["stats"]["priceUsd"], 7.0);

        // Solana: a base58 case variant is a different token and is NOT matched.
        let provider = Arc::new(FakeMarketProvider::default());
        let requested = "So11111111111111111111111111111111111111112";
        let case_variant = "so11111111111111111111111111111111111111112";
        provider.set_token(Ok(BridgeTokenDetail {
            address: requested.to_string(),
            network_id: 1_399_811_149,
            chain: Some("solana".to_string()),
            token: bridge_token("0xWRONG", 1_399_811_149, "SOL"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let mut sol_row = bridge_token(case_variant, 1_399_811_149, "SOL");
        sol_row.price_usd = Some(6.0);
        provider.set_search(Ok(BridgeSearch {
            query: requested.to_string(),
            count: 1,
            results: vec![sol_row],
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "solana", "address": requested}),
            ))
            .await
            .unwrap();
        assert!(result["stats"]["priceUsd"].is_null());
    }

    #[tokio::test]
    async fn get_token_refuses_a_mismatched_bridge_identity() {
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xOTHER".to_string(),
            network_id: 1,
            chain: Some("ethereum".to_string()),
            token: bridge_token("0xOTHER", 1, "OTHER"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let error = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, "server");
    }

    #[test]
    fn returned_identity_case_rule_is_chain_aware() {
        // Only verified EVM chains may ignore ASCII case.
        for chain in ["base", "ethereum", "bnb_chain", "bsc", "bnb"] {
            assert!(identity_is_case_insensitive(chain), "{chain} is EVM");
        }
        // Solana base58 and the unverified Robinhood-associated network must be
        // compared byte-for-byte, so their case variants are distinct tokens.
        for chain in ["solana", "robinhood", "robinhood_chain"] {
            assert!(!identity_is_case_insensitive(chain), "{chain} is strict");
        }
    }

    #[tokio::test]
    async fn get_token_refuses_a_solana_case_variant_identity() {
        // Base58 is case-sensitive: the same network id with an address that
        // differs only by case is a different token and must be refused rather
        // than rendered under the requested identity.
        let requested = "So11111111111111111111111111111111111111112";
        let case_variant = "so11111111111111111111111111111111111111112";
        assert_ne!(requested, case_variant);
        assert!(requested.eq_ignore_ascii_case(case_variant));

        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: case_variant.to_string(),
            network_id: 1_399_811_149,
            chain: Some("solana".to_string()),
            token: bridge_token(case_variant, 1_399_811_149, "SOL"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let health = Arc::new(AtomicBool::new(true));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider)
                .with_market_health_flag(Some(health.clone()));
        let error = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "solana", "address": requested}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, "server");
        assert!(error.retryable);
        assert!(
            !health.load(Ordering::SeqCst),
            "a returned-identity mismatch must demote market readiness"
        );
    }

    #[tokio::test]
    async fn get_token_accepts_an_evm_checksum_case_variant() {
        // Base/Ethereum/BNB addresses are EVM-cased; a checksum variant of the
        // requested address is the same token and is projected under the exact
        // requested identity.
        let requested = "0xabcdef0000000000000000000000000000000001";
        let checksummed = "0xAbCdEf0000000000000000000000000000000001";
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: checksummed.to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token(checksummed, 8_453, "BASE"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let result = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": requested}),
            ))
            .await
            .unwrap();
        assert_eq!(result["token"]["address"], requested);
        assert_eq!(result["token"]["chain"], "base");
    }

    #[tokio::test]
    async fn get_token_refuses_a_robinhood_case_variant_identity() {
        // Robinhood-associated semantics are not verified as EVM, so its
        // identity is compared strictly rather than guessed.
        let requested = "0xAbCdEf0000000000000000000000000000000001";
        let case_variant = "0xabcdef0000000000000000000000000000000001";
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: case_variant.to_string(),
            network_id: 4_663,
            chain: Some("robinhood".to_string()),
            token: bridge_token(case_variant, 4_663, "RH"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider);
        let error = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "robinhood", "address": requested}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, "server");
    }

    #[tokio::test]
    async fn get_token_identity_mismatch_demotes_and_recovers_market_readiness() {
        let health = Arc::new(AtomicBool::new(true));
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xOTHER".to_string(),
            network_id: 1,
            chain: Some("ethereum".to_string()),
            token: bridge_token("0xOTHER", 1, "OTHER"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        )
        .with_market_health_flag(Some(health.clone()));

        let error = dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, "server");
        assert!(
            !health.load(Ordering::SeqCst),
            "an identity mismatch must demote readiness before denying"
        );

        // A later valid identity read restores readiness.
        provider.set_token(Ok(BridgeTokenDetail {
            address: "0xbase".to_string(),
            network_id: 8_453,
            chain: Some("base".to_string()),
            token: bridge_token("0xbase", 8_453, "BASE"),
            detail: None,
            risk: None,
            warnings: Vec::new(),
        }));
        assert!(dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "base", "address": "0xbase"}),
            ))
            .await
            .is_ok());
        assert!(health.load(Ordering::SeqCst), "recovery restores readiness");
    }

    #[tokio::test]
    async fn market_read_failure_degrades_and_recovers_the_health_flag() {
        let health = Arc::new(AtomicBool::new(false));
        let provider = Arc::new(FakeMarketProvider::default());
        provider.set_trending(Err(FomoMarketError::Unavailable));
        let dispatcher = FomoChartDispatcher::new(
            Arc::new(crate::opaque::FailClosedDispatcher),
            provider.clone(),
        )
        .with_market_health_flag(Some(health.clone()));

        let error = dispatcher
            .dispatch(&market_request("get_trending", json!({})))
            .await
            .unwrap_err();
        assert_eq!(error.code, "server");
        assert!(error.retryable);
        assert!(
            !health.load(Ordering::SeqCst),
            "outage must degrade readiness"
        );

        provider.set_trending(Ok(BridgeTrending {
            category: "trending".to_string(),
            tokens: vec![bridge_token("0xbase", 8_453, "BASE")],
        }));
        assert!(dispatcher
            .dispatch(&market_request("get_trending", json!({})))
            .await
            .is_ok());
        assert!(health.load(Ordering::SeqCst), "recovery restores readiness");

        // A determinate client rejection never demotes the dependency.
        health.store(true, Ordering::SeqCst);
        assert!(dispatcher
            .dispatch(&market_request(
                "get_token",
                json!({"chain": "unknown", "address": "0x1"}),
            ))
            .await
            .is_err());
        assert!(health.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn probe_market_requires_a_reachable_read_path() {
        let down = Arc::new(FakeMarketProvider::default());
        down.set_trending(Err(FomoMarketError::Unavailable));
        assert!(!probe_market(down.as_ref()).await);

        let healthy = Arc::new(FakeMarketProvider::default());
        healthy.set_trending(Ok(BridgeTrending {
            category: "trending".to_string(),
            tokens: Vec::new(),
        }));
        assert!(
            probe_market(healthy.as_ref()).await,
            "empty list is healthy"
        );
    }

    #[tokio::test]
    async fn set_realtime_target_binds_the_authenticated_session() {
        let targets = Arc::new(RealtimeTargetRegistry::new());
        let provider = Arc::new(FakeMarketProvider::default());
        let dispatcher =
            FomoChartDispatcher::new(Arc::new(crate::opaque::FailClosedDispatcher), provider)
                .with_targets(targets.clone());
        let kid = [7u8; session_transport::KID_BYTES];

        let result = dispatcher
            .dispatch_for_session(
                &kid,
                &market_request(
                    "set_realtime_target",
                    json!({"chain": "base", "address": "0xabc", "timeframe": "1m"}),
                ),
            )
            .await
            .unwrap();
        assert_eq!(result["accepted"], true);
        assert_eq!(targets.get(&kid).unwrap().address, "0xabc");

        // Unknown chain/window and a session-less call are refused.
        assert!(dispatcher
            .dispatch_for_session(
                &kid,
                &market_request(
                    "set_realtime_target",
                    json!({"chain": "unknown", "address": "0xabc", "timeframe": "1m"}),
                ),
            )
            .await
            .is_err());
        assert!(dispatcher
            .dispatch(&market_request(
                "set_realtime_target",
                json!({"chain": "base", "address": "0xabc", "timeframe": "1m"}),
            ))
            .await
            .is_err());
    }

    #[test]
    fn realtime_target_registry_is_bounded_and_validated() {
        let registry = RealtimeTargetRegistry::new();
        let target = |address: &str| RealtimeTarget {
            chain: "base".to_string(),
            address: address.to_string(),
            timeframe: "1m".to_string(),
        };
        assert!(registry.set(&[1u8; 16], target("0xgood")).is_ok());
        assert_eq!(registry.len(), 1);
        // An invalid target is refused without mutating.
        assert!(registry
            .set(
                &[2u8; 16],
                RealtimeTarget {
                    chain: "unknown".to_string(),
                    address: "0x1".to_string(),
                    timeframe: "1m".to_string(),
                },
            )
            .is_err());
        assert_eq!(registry.len(), 1, "invalid target is not stored");
        registry.clear(&[1u8; 16]);
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn selected_target_switch_emits_a_fresh_snapshot_not_a_stale_delta() {
        let provider = Arc::new(FakeMarketProvider::with_bars(
            "0xAAA",
            vec![bar(1_000, 10.0)],
        ));
        provider
            .bars_by_address
            .lock()
            .unwrap()
            .insert("0xBBB".to_string(), vec![bar(5_000, 99.0)]);
        let targets = Arc::new(RealtimeTargetRegistry::new());
        let source = FomoSessionStreamSource::new_for_test(
            provider,
            targets.clone(),
            None,
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        let kid = [1u8; session_transport::KID_BYTES];
        targets
            .set(
                &kid,
                RealtimeTarget::validated("base", "0xAAA", "1m").unwrap(),
            )
            .unwrap();

        let snapshot = source.snapshot_for(&kid, None).await.expect("snapshot A");
        assert_eq!(snapshot.op, session_transport::StreamOp::Snapshot);
        assert_eq!(snapshot.entity_key.as_deref(), Some("ohlcv:base:0xAAA"));
        assert_eq!(
            snapshot.payload.as_ref().unwrap()["candles"][0]["close"],
            10.0
        );

        let delta = source.next_delta_for(&kid).await.expect("delta A");
        assert_eq!(delta.op, session_transport::StreamOp::Delta);
        assert_eq!(delta.payload.as_ref().unwrap()["candle"]["close"], 10.0);

        // Switch the authenticated session to token B. The next frame must be a
        // full snapshot for B, never a delta A could be applied to.
        targets
            .set(
                &kid,
                RealtimeTarget::validated("base", "0xBBB", "1m").unwrap(),
            )
            .unwrap();
        let switched = source.next_delta_for(&kid).await.expect("switch to B");
        assert_eq!(
            switched.op,
            session_transport::StreamOp::Snapshot,
            "a target switch must resnapshot"
        );
        assert_eq!(switched.entity_key.as_deref(), Some("ohlcv:base:0xBBB"));
        assert_eq!(
            switched.payload.as_ref().unwrap()["candles"][0]["close"],
            99.0
        );
    }

    #[tokio::test]
    async fn session_stream_target_memory_is_bounded_and_eviction_resnapshots() {
        let provider = Arc::new(FakeMarketProvider::with_bars(
            "0xAAA",
            vec![bar(1_000, 10.0)],
        ));
        let targets = Arc::new(RealtimeTargetRegistry::new());
        let source = FomoSessionStreamSource::new_for_test(
            provider,
            targets.clone(),
            None,
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        let target = RealtimeTarget::validated("base", "0xAAA", "1m").unwrap();

        for n in 0..=RealtimeTargetRegistry::MAX_ENTRIES {
            source.remember(&(n as u64).to_le_bytes(), &target);
        }
        assert!(
            source
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
                <= RealtimeTargetRegistry::MAX_ENTRIES
        );

        let kid = [9u8; session_transport::KID_BYTES];
        targets.set(&kid, target.clone()).unwrap();
        source.remember(&kid, &target);
        source
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(kid.as_slice());
        let frame = source.next_delta_for(&kid).await.expect("resnapshot");
        assert_eq!(
            frame.op,
            session_transport::StreamOp::Snapshot,
            "a missing/evicted session target must force a fresh snapshot"
        );
    }

    #[tokio::test]
    async fn session_source_without_a_target_is_fail_closed() {
        let provider = Arc::new(FakeMarketProvider::with_bars(
            "0xAAA",
            vec![bar(1_000, 10.0)],
        ));
        let targets = Arc::new(RealtimeTargetRegistry::new());
        let source = FomoSessionStreamSource::new_for_test(
            provider,
            targets,
            None,
            10,
            Duration::from_millis(1),
        )
        .unwrap();
        // No binding and no operator seed: no snapshot, never a fabricated one.
        assert!(source
            .snapshot_for(&[9u8; session_transport::KID_BYTES], None)
            .await
            .is_none());
    }

    // ---- WS-first realtime lane ---------------------------------------- //

    fn lane_price(
        network_id: i64,
        address: &str,
        price_usd: f64,
        observed_at_ms: i64,
    ) -> LaneEvent {
        LaneEvent {
            kind: LaneEventKind::Price {
                network_id,
                address: address.to_string(),
                price_usd,
                change24h: Some(4.5),
                market_cap_usd: Some(1_000_000.0),
                liquidity_usd: Some(250_000.0),
                volume24h_usd: Some(90_000.0),
            },
            observed_at_ms,
        }
    }

    async fn lane_source_for(
        hub: Arc<LaneHub>,
        address: &str,
    ) -> (FomoSessionStreamSource, [u8; session_transport::KID_BYTES]) {
        let provider = Arc::new(FakeMarketProvider::with_bars(
            address,
            vec![bar(1_000, 10.0)],
        ));
        let targets = Arc::new(RealtimeTargetRegistry::new());
        let source = FomoSessionStreamSource::new_for_test(
            provider,
            targets.clone(),
            None,
            10,
            Duration::from_millis(1),
        )
        .unwrap()
        .with_lane(hub);
        let kid = [3u8; session_transport::KID_BYTES];
        targets
            .set(
                &kid,
                RealtimeTarget::validated("base", address, "1m").unwrap(),
            )
            .unwrap();
        (source, kid)
    }

    #[tokio::test]
    async fn lane_price_event_emits_a_ws_frame_for_the_bound_entity() {
        let hub = Arc::new(LaneHub::new());
        hub.publish(lane_price(8_453, "0xabc", 1.23, 1_730_000_000_000));
        let (source, kid) = lane_source_for(hub, "0xabc").await;

        let mut found = None;
        for _ in 0..6 {
            let frame = source.next_delta_for(&kid).await.expect("frame");
            if frame.entity_key.as_deref() == Some("market:price:base:0xabc") {
                found = Some(frame);
                break;
            }
        }
        let frame = found.expect("market price frame");
        assert_eq!(frame.channel, "market");
        let payload = frame.payload.as_ref().unwrap();
        assert_eq!(payload["kind"], "price");
        assert_eq!(payload["source"], "fomo-ws");
        assert_eq!(payload["chain"], "base");
        assert_eq!(payload["address"], "0xabc");
        assert_eq!(payload["priceUsd"], 1.23);
        assert_eq!(payload["priceChange24h"], 4.5);
        assert_eq!(payload["marketCapUsd"], 1_000_000.0);
        assert_eq!(payload["liquidityUsd"], 250_000.0);
        assert_eq!(payload["volume24hUsd"], 90_000.0);
        assert_eq!(payload["observedAtMs"], 1_730_000_000_000i64);
    }

    #[tokio::test]
    async fn lane_price_event_for_another_entity_is_ignored() {
        let hub = Arc::new(LaneHub::new());
        hub.publish(lane_price(8_453, "0xOTHER", 9.9, 1));
        let (source, kid) = lane_source_for(hub, "0xabc").await;
        for _ in 0..6 {
            let frame = source.next_delta_for(&kid).await.expect("frame");
            assert_ne!(
                frame.entity_key.as_deref(),
                Some("market:price:base:0xabc"),
                "a lane price for another entity must never bind to this kid"
            );
        }
    }

    #[tokio::test]
    async fn lane_trending_event_emits_an_enriched_frame() {
        let hub = Arc::new(LaneHub::new());
        let mut token = bridge_token("0xbase", 8_453, "BASE");
        token.change24h = Some(-3.5);
        token.liquidity_usd = Some(500_000.0);
        token.volume24h_usd = Some(123_456.0);
        hub.publish(LaneEvent {
            kind: LaneEventKind::Trending {
                category: "trending".to_string(),
                tokens: vec![token, bridge_token("0xunknown", 999_999, "UNK")],
            },
            observed_at_ms: 42,
        });
        let (source, kid) = lane_source_for(hub, "0xabc").await;

        let mut found = None;
        for _ in 0..6 {
            let frame = source.next_delta_for(&kid).await.expect("frame");
            if frame.entity_key.as_deref() == Some("market:trending") {
                found = Some(frame);
                break;
            }
        }
        let frame = found.expect("market trending frame");
        let payload = frame.payload.as_ref().unwrap();
        assert_eq!(payload["kind"], "trending");
        assert_eq!(payload["source"], "fomo-ws");
        assert_eq!(payload["category"], "trending");
        assert_eq!(payload["observedAtMs"], 42);
        let tokens = payload["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 1, "unverified network dropped: {payload}");
        assert_eq!(tokens[0]["chain"], "base");
        assert_eq!(tokens[0]["priceUsd"], 1.5);
        assert_eq!(tokens[0]["priceChange24h"], -3.5);
        assert_eq!(tokens[0]["liquidityUsd"], 500_000.0);
        assert_eq!(tokens[0]["volume24hUsd"], 123_456.0);
    }

    #[tokio::test]
    async fn lane_not_live_falls_back_to_polling_and_never_labels_ws() {
        let hub = Arc::new(LaneHub::new());
        let (source, kid) = lane_source_for(hub, "0xabc").await;

        let status = source.next_delta_for(&kid).await.expect("status frame");
        assert_eq!(status.channel, "market");
        assert_eq!(status.payload.as_ref().unwrap()["kind"], "status");
        assert_eq!(
            status.payload.as_ref().unwrap()["realtimeSource"],
            "fomo-polling"
        );

        let ohlcv = source.next_delta_for(&kid).await.expect("ohlcv frame");
        assert_eq!(ohlcv.channel, "ohlcv");

        for frame in [&status, &ohlcv] {
            if let Some(payload) = frame.payload.as_ref() {
                assert_ne!(payload["source"], "fomo-ws");
            }
        }
    }

    #[test]
    fn lane_hub_bounds_the_price_map_and_token_count() {
        let hub = LaneHub::with_limits(Duration::from_secs(1), Duration::from_millis(1), 2, 1);
        for index in 0..5 {
            hub.publish(LaneEvent {
                kind: LaneEventKind::Price {
                    network_id: 1,
                    address: format!("0x{index}"),
                    price_usd: index as f64,
                    change24h: None,
                    market_cap_usd: None,
                    liquidity_usd: None,
                    volume24h_usd: None,
                },
                observed_at_ms: index,
            });
        }
        assert!(hub.current().prices.len() <= 2);
        hub.publish(LaneEvent {
            kind: LaneEventKind::Trending {
                category: "trending".to_string(),
                tokens: vec![bridge_token("0xa", 1, "A"), bridge_token("0xb", 1, "B")],
            },
            observed_at_ms: 1,
        });
        assert_eq!(hub.current().trending.unwrap().tokens.len(), 1);
    }

    /// Fake lane driven by an unbounded channel, for the hub spawn test.
    struct FakeLane {
        tx: tokio::sync::mpsc::UnboundedSender<LaneEvent>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<LaneEvent>>,
    }

    impl FakeLane {
        fn new() -> Self {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            Self {
                tx,
                rx: tokio::sync::Mutex::new(rx),
            }
        }

        fn emit(&self, event: LaneEvent) {
            let _ = self.tx.send(event);
        }
    }

    #[async_trait]
    impl RealtimeLane for FakeLane {
        async fn next_event(&self) -> Option<LaneEvent> {
            self.rx.lock().await.recv().await
        }

        fn is_live(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn lane_hub_spawn_publishes_a_fake_lane_event() {
        let hub = Arc::new(LaneHub::with_limits(
            Duration::from_secs(1),
            Duration::from_millis(1),
            16,
            16,
        ));
        let lane = Arc::new(FakeLane::new());
        hub.spawn(lane.clone());
        lane.emit(lane_price(8_453, "0xabc", 2.0, 5));

        for _ in 0..200 {
            let state = hub.current();
            if state.live && state.prices.contains_key(&(8_453, "0xabc".to_string())) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("hub did not publish the fake lane event");
    }

    async fn spawn_realtime_bridge(body: String) -> String {
        use axum::routing::get;
        let state = BridgeState {
            status: axum::http::StatusCode::OK,
            body,
        };
        let app = axum::Router::new()
            .route("/market/realtime", get(bridge_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{address}")
    }

    fn lane_test_client(base: &str) -> FomoRealtimeLaneClient {
        FomoRealtimeLaneClient::new_for_test(
            base,
            Zeroizing::new("test-key".to_string()),
            Duration::from_secs(2),
            Duration::from_millis(1),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn lane_client_enforces_the_strict_provenance_gate() {
        // A strictly verified WS batch is accepted and parsed.
        let valid = json!({
            "events": [{
                "type": "price", "networkId": 8_453, "address": "0xabc",
                "priceUsd": 1.5, "change24h": 2.0, "observedAtMs": 7
            }],
            "cursor": 9,
            "source": {"provenance": "websocket", "wsPromoted": true}
        })
        .to_string();
        let base = spawn_realtime_bridge(valid).await;
        let lane = lane_test_client(&base);
        let event = tokio::time::timeout(Duration::from_secs(2), lane.next_event())
            .await
            .expect("bounded")
            .expect("event");
        assert!(lane.is_live());
        match event.kind {
            LaneEventKind::Price {
                network_id,
                address,
                price_usd,
                change24h,
                ..
            } => {
                assert_eq!(network_id, 8_453);
                assert_eq!(address, "0xabc");
                assert_eq!(price_usd, 1.5);
                assert_eq!(change24h, Some(2.0));
            }
            other => panic!("expected price event, got {other:?}"),
        }

        // Every non-WS-provenance batch fails closed: `None` and not live.
        for body in [
            json!({"events": [], "cursor": 1, "source": {"provenance": "polling", "wsPromoted": false}})
                .to_string(),
            json!({"events": [], "cursor": 1, "source": {"provenance": "websocket", "wsPromoted": false}})
                .to_string(),
            json!({"events": [], "cursor": 1, "source": {"provenance": "polling", "wsPromoted": true}})
                .to_string(),
            json!({"events": [], "cursor": 1}).to_string(),
        ] {
            let base = spawn_realtime_bridge(body).await;
            let lane = lane_test_client(&base);
            assert!(tokio::time::timeout(Duration::from_secs(2), lane.next_event())
                .await
                .expect("bounded")
                .is_none());
            assert!(!lane.is_live());
        }
    }

    #[tokio::test]
    async fn lane_client_parses_a_trending_batch() {
        let valid = json!({
            "events": [{
                "type": "trending", "category": "trending",
                "tokens": [{
                    "address": "0xbase", "networkId": 8_453, "symbol": "BASE",
                    "priceUsd": 1.5, "liquidityUsd": 10.0
                }],
                "observedAtMs": 11
            }],
            "cursor": 3,
            "source": {"provenance": "websocket", "wsPromoted": true}
        })
        .to_string();
        let base = spawn_realtime_bridge(valid).await;
        let lane = lane_test_client(&base);
        let event = tokio::time::timeout(Duration::from_secs(2), lane.next_event())
            .await
            .expect("bounded")
            .expect("event");
        assert_eq!(event.observed_at_ms, 11);
        match event.kind {
            LaneEventKind::Trending { category, tokens } => {
                assert_eq!(category, "trending");
                assert_eq!(tokens.len(), 1);
                assert_eq!(tokens[0].network_id, 8_453);
                assert_eq!(tokens[0].symbol.as_deref(), Some("BASE"));
                assert_eq!(tokens[0].price_usd, Some(1.5));
                assert_eq!(tokens[0].liquidity_usd, Some(10.0));
            }
            other => panic!("expected trending event, got {other:?}"),
        }
    }

    #[test]
    fn stream_poll_floor_allows_one_second_and_rejects_sub_second() {
        assert_eq!(MIN_STREAM_POLL, Duration::from_secs(1));
        assert_eq!(
            FomoMarketConfig::clamp_poll(Duration::from_millis(500)),
            Duration::from_secs(1)
        );
        let provider = fake(vec![]);
        assert!(FomoOhlcvStreamSource::new(
            provider.clone(),
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_secs(1),
        )
        .is_ok());
        assert!(FomoOhlcvStreamSource::new(
            provider,
            "base".into(),
            "0xabc".into(),
            "1m".into(),
            10,
            Duration::from_millis(999),
        )
        .is_err());
    }

    // ---- HTTP client read routes over a real loopback bridge ----------- //

    async fn spawn_read_bridge(status: axum::http::StatusCode, body: String) -> String {
        use axum::routing::get;
        let state = BridgeState { status, body };
        let app = axum::Router::new()
            .route("/market/bars", get(bridge_handler))
            .route("/market/latest", get(bridge_handler))
            .route("/market/search", get(bridge_handler))
            .route("/market/token", get(bridge_handler))
            .route("/market/trending", get(bridge_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn client_reads_search_token_and_trending_from_the_bridge() {
        let search = json!({
            "query": "alpha",
            "count": 1,
            "results": [{
                "address": "0xbase", "networkId": 8453, "chain": "base",
                "symbol": "BASE", "priceUsd": 1.5, "marketCapUsd": 10.0
            }],
            "source": {"provider": "fomo", "transport": "rest",
                "endpoint": "POST /proxy/filterTokensSearch", "provenance": "rest",
                "wsPromoted": false, "realtimeContract": "x"},
            "fetchedAt": "2026-01-01T00:00:00+00:00",
            "cache": {"hit": false, "ageMs": 0, "minPollIntervalMs": 5000},
            "warnings": []
        })
        .to_string();
        let base = spawn_read_bridge(axum::http::StatusCode::OK, search).await;
        let result = test_client(&base).search("alpha").await.unwrap();
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].chain.as_deref(), Some("base"));

        let token = json!({
            "symbol": "0xbase:8453", "address": "0xbase", "networkId": 8453,
            "chain": "base",
            "token": {"address": "0xbase", "networkId": 8453, "chain": "base", "symbol": "BASE"},
            "detail": {"price": 0.5, "marketCap": 1000.0},
            "risk": {"disableBuying": false, "disableSelling": false, "level": "clear", "warnings": []},
            "source": {"provider": "fomo", "transport": "rest",
                "endpoint": "POST /proxy/tokenDetails", "provenance": "rest",
                "wsPromoted": false, "realtimeContract": "x"},
            "fetchedAt": "2026-01-01T00:00:00+00:00",
            "cache": {"hit": false, "ageMs": 0, "minPollIntervalMs": 5000},
            "warnings": []
        })
        .to_string();
        let base = spawn_read_bridge(axum::http::StatusCode::OK, token).await;
        let result = test_client(&base).token("base", "0xbase").await.unwrap();
        assert_eq!(result.address, "0xbase");
        assert_eq!(result.detail.unwrap().price, Some(0.5));

        let trending = json!({
            "category": "trending", "count": 1,
            "tokens": [{"address": "0xbase", "networkId": 8453, "chain": "base", "symbol": "BASE"}],
            "source": {"provider": "fomo", "transport": "rest",
                "endpoint": "GET /proxy/trendingTokens", "provenance": "rest",
                "wsPromoted": false, "realtimeContract": "x"},
            "fetchedAt": "2026-01-01T00:00:00+00:00",
            "cache": {"hit": false, "ageMs": 0, "minPollIntervalMs": 5000},
            "warnings": []
        })
        .to_string();
        let base = spawn_read_bridge(axum::http::StatusCode::OK, trending).await;
        let result = test_client(&base).trending("trending", 10).await.unwrap();
        assert_eq!(result.tokens[0].chain.as_deref(), Some("base"));
    }

    #[tokio::test]
    async fn client_read_auth_rejection_and_bad_shape_fail_closed() {
        let base = spawn_read_bridge(
            axum::http::StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}).to_string(),
        )
        .await;
        assert_eq!(
            test_client(&base).search("alpha").await,
            Err(FomoMarketError::Unavailable)
        );

        let base = spawn_read_bridge(
            axum::http::StatusCode::NOT_FOUND,
            json!({"error": "unknown"}).to_string(),
        )
        .await;
        assert_eq!(
            test_client(&base).token("base", "0xabc").await,
            Err(FomoMarketError::InvalidRequest)
        );

        // A 200 body that violates the read contract is refused, never repaired.
        let base = spawn_read_bridge(
            axum::http::StatusCode::OK,
            json!({"results": "not-an-array"}).to_string(),
        )
        .await;
        assert_eq!(
            test_client(&base).search("alpha").await,
            Err(FomoMarketError::InvalidResponse)
        );
    }
}
