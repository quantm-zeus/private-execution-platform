//! Read-only FOMO token-intelligence adapter for the private web.
//!
//! This is the PEP-side consumer of the local, read-only `fomo-mcp`
//! token-intelligence bridge. It never talks to FOMO directly and never holds
//! FOMO auth material: `fomo-mcp` owns the FOMO REST session, and PEP only calls
//! the loopback bridge with the bridge's own bearer key.
//!
//! ## Contract consumed
//!
//! ```text
//! GET {base}/market/holders?symbol=<address>:<networkId>
//! GET {base}/market/about?symbol=<address>:<networkId>
//! GET {base}/market/activity?symbol=<address>:<networkId>&limit=<n>[&cursor=<c>]
//! ```
//!
//! `/market/about` is the primary profile read; when the bridge does not serve
//! that route a backwards-compatible extension of `/market/token` is used
//! instead, so either bridge implementation choice is consumable.
//!
//! ## Fail-closed guarantees
//!
//! * The bridge response must echo the exact requested `networkId` + `address`;
//!   a mismatch (including a same-network Solana base58 case variant) is an
//!   invalid provider response and is refused rather than rendered.
//! * Missing/non-finite provider values stay `null`; a value is never
//!   synthesized and a zero is never fabricated.
//! * Only `http://`/`https://` external links survive normalization; a
//!   `javascript:`/`data:`/relative value is dropped.
//! * Pagination is bounded on both the request and the response.
//! * No upstream text, bearer key or provider identifier is carried in a denial
//!   or `Debug` output.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::fomo_market::{
    encode_query_component, fomo_symbol, BridgeRisk, BridgeTokenDetail, FomoBarsClient,
    FomoMarketError,
};

/// Upper bound on holder rows projected from one bridge page.
pub const MAX_HOLDER_ROWS: usize = 200;
/// Upper bound on activity events projected from one bridge page.
pub const MAX_ACTIVITY_ROWS: usize = 100;
/// Upper bound on an activity cursor accepted from the authenticated client.
pub const MAX_CURSOR_LEN: usize = 256;
/// Upper bound on a normalized external URL.
pub const MAX_URL_LEN: usize = 512;
/// Default rows when the client does not ask for a page size.
pub const DEFAULT_HOLDER_LIMIT: u32 = 50;
/// Default events when the client does not ask for a page size.
pub const DEFAULT_ACTIVITY_LIMIT: u32 = 50;
/// Hard cap on a client-requested page size (holders or activity).
pub const MAX_INTEL_LIMIT: u32 = 100;

/// Sanity ceiling for a millisecond timestamp (year 2100), matching the market
/// adapter's bound so both read paths agree on what a real timestamp is.
const MAX_TIMESTAMP_MS: i64 = 4_102_444_800_000;
/// Values below this are treated as seconds-resolution and scaled to ms.
const SECONDS_CUTOFF: i64 = 1_000_000_000_000;

// ------------------------------------------------------------------ //
// Wire shapes
// ------------------------------------------------------------------ //

/// A trader/user identity as returned by the bridge. Every field is optional:
/// an absent value is unknown, never a fabricated default.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeIntelUser {
    #[serde(default, alias = "userHandle", alias = "username")]
    pub handle: Option<String>,
    #[serde(default, alias = "display", alias = "name")]
    pub display_name: Option<String>,
    #[serde(
        default,
        alias = "avatar",
        alias = "image",
        alias = "imageUrl",
        alias = "profileImageUrl"
    )]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub clan: Option<String>,
    #[serde(default)]
    pub followed: Option<bool>,
    #[serde(default, alias = "isDev")]
    pub dev: Option<bool>,
    #[serde(default, alias = "followerCount", alias = "followersCount")]
    pub followers: Option<f64>,
    #[serde(default, alias = "id")]
    pub user_id: Option<String>,
    #[serde(default, alias = "wallet", alias = "walletAddress", alias = "address")]
    pub wallet: Option<String>,
}

/// The optional thesis/comment a holder authored for this token.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeThesis {
    #[serde(default, alias = "comment", alias = "body", alias = "content")]
    pub text: Option<String>,
    #[serde(default, alias = "createdAt", alias = "timestamp", alias = "time")]
    pub created_at_ms: Option<Value>,
    #[serde(default, alias = "likeCount")]
    pub likes: Option<f64>,
    #[serde(default)]
    pub trade_id: Option<String>,
}

/// One holder/trader row. The identity may be nested under `user` or flattened;
/// both are accepted and merged (nested wins).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeHolderRow {
    #[serde(default)]
    pub user: Option<BridgeIntelUser>,
    #[serde(default, alias = "userHandle")]
    pub handle: Option<String>,
    #[serde(default, alias = "display")]
    pub display_name: Option<String>,
    #[serde(default, alias = "avatar", alias = "image")]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub clan: Option<String>,
    #[serde(default)]
    pub followed: Option<bool>,
    #[serde(default)]
    pub dev: Option<bool>,
    #[serde(default, alias = "followerCount")]
    pub followers: Option<f64>,
    #[serde(default, alias = "walletAddress", alias = "address", alias = "owner")]
    pub wallet: Option<String>,
    #[serde(
        default,
        alias = "humanAmount",
        alias = "tokenAmount",
        alias = "quantity"
    )]
    pub amount: Option<f64>,
    #[serde(default, alias = "value")]
    pub value_usd: Option<f64>,
    #[serde(default, alias = "costBasis")]
    pub cost_basis_usd: Option<f64>,
    #[serde(default, alias = "averageEntryPrice", alias = "avgEntryPrice")]
    pub average_entry_price_usd: Option<f64>,
    #[serde(default, alias = "currentPrice")]
    pub current_price_usd: Option<f64>,
    #[serde(default, alias = "realizedPnl")]
    pub realized_pnl_usd: Option<f64>,
    #[serde(default, alias = "unrealizedPnl")]
    pub unrealized_pnl_usd: Option<f64>,
    #[serde(default, alias = "pnl", alias = "totalPnl")]
    pub total_pnl_usd: Option<f64>,
    #[serde(
        default,
        alias = "averageHoldTimeSeconds",
        alias = "avgHoldTimeSeconds",
        alias = "holdTimeSeconds"
    )]
    pub average_hold_time_seconds: Option<f64>,
    #[serde(default, alias = "comment")]
    pub thesis: Option<BridgeThesis>,
}

/// Bounded `/market/holders` response.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeHolders {
    #[serde(default, alias = "tokenAddress")]
    pub address: Option<String>,
    #[serde(default, alias = "network")]
    pub network_id: Option<i64>,
    #[serde(default, alias = "items")]
    pub holders: Vec<BridgeHolderRow>,
    /// Friend/followed holders the bridge returns separately; merged with
    /// `holders` under the bounded cap.
    #[serde(default)]
    pub friends: Vec<BridgeHolderRow>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_age_ms: Option<u64>,
}

/// Social links for the token profile.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSocialLinks {
    #[serde(default, alias = "x", alias = "twitterUrl")]
    pub twitter: Option<String>,
    #[serde(default, alias = "site", alias = "websiteUrl")]
    pub website: Option<String>,
    #[serde(default, alias = "telegramUrl")]
    pub telegram: Option<String>,
    #[serde(default, alias = "discordUrl")]
    pub discord: Option<String>,
}

/// The token profile block of `/market/about`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeAboutToken {
    #[serde(default, alias = "tokenAddress")]
    pub address: Option<String>,
    #[serde(default, alias = "network")]
    pub network_id: Option<i64>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "image", alias = "logo", alias = "imageUrl")]
    pub image_url: Option<String>,
    #[serde(default, alias = "socials", alias = "links")]
    pub social_links: Option<BridgeSocialLinks>,
}

/// Launch/graduation/supply profile block.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeAboutProfile {
    #[serde(default)]
    pub launchpad: Option<String>,
    #[serde(default, alias = "graduation")]
    pub graduation_percent: Option<f64>,
    #[serde(default, alias = "createdAt", alias = "createdAtMs")]
    pub created_at_ms: Option<Value>,
    #[serde(default, alias = "circulating")]
    pub circulating_supply: Option<f64>,
    #[serde(default, alias = "total")]
    pub total_supply: Option<f64>,
}

/// Market-stat block of `/market/about`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeAboutStats {
    #[serde(default, alias = "price")]
    pub price_usd: Option<f64>,
    #[serde(default, alias = "change24", alias = "priceChange24")]
    pub price_change24h: Option<f64>,
    #[serde(default, alias = "marketCap", alias = "mcap")]
    pub market_cap_usd: Option<f64>,
    #[serde(default, alias = "fdv")]
    pub fdv_usd: Option<f64>,
    #[serde(default, alias = "liquidity")]
    pub liquidity_usd: Option<f64>,
    #[serde(default, alias = "volume24", alias = "volume24h")]
    pub volume24h_usd: Option<f64>,
    #[serde(default)]
    pub holders: Option<f64>,
    #[serde(default, alias = "top10Percent", alias = "top10HoldersPct")]
    pub top10_holders_percent: Option<f64>,
}

/// Buy/sell statistics for one timeframe.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeTradingWindow {
    #[serde(default, alias = "buys", alias = "buy")]
    pub buy_count: Option<f64>,
    #[serde(default, alias = "sells", alias = "sell")]
    pub sell_count: Option<f64>,
    #[serde(default, alias = "buyVolume", alias = "buyVolume24")]
    pub buy_volume_usd: Option<f64>,
    #[serde(default, alias = "sellVolume", alias = "sellVolume24")]
    pub sell_volume_usd: Option<f64>,
    #[serde(default)]
    pub unique_buyers: Option<f64>,
    #[serde(default)]
    pub unique_sellers: Option<f64>,
}

/// The four closed buy/sell timeframes.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct BridgeTradingWindows {
    #[serde(default, rename = "5m", alias = "m5", alias = "fiveMinutes")]
    pub m5: Option<BridgeTradingWindow>,
    #[serde(default, rename = "1h", alias = "h1", alias = "oneHour")]
    pub h1: Option<BridgeTradingWindow>,
    #[serde(default, rename = "4h", alias = "h4", alias = "fourHours")]
    pub h4: Option<BridgeTradingWindow>,
    #[serde(default, rename = "24h", alias = "h24", alias = "d1", alias = "oneDay")]
    pub h24: Option<BridgeTradingWindow>,
}

/// Bounded `/market/about` response.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeAbout {
    #[serde(default, alias = "tokenAddress")]
    pub address: Option<String>,
    #[serde(default, alias = "network")]
    pub network_id: Option<i64>,
    #[serde(default, alias = "token")]
    pub profile_token: Option<BridgeAboutToken>,
    #[serde(default, alias = "launch", alias = "details")]
    pub profile: Option<BridgeAboutProfile>,
    #[serde(default)]
    pub stats: Option<BridgeAboutStats>,
    #[serde(default, alias = "tradingStats")]
    pub trading: Option<BridgeTradingWindows>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub risk: Option<BridgeRisk>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_age_ms: Option<u64>,
}

impl BridgeAbout {
    /// Verify every identity echo present in the response against the exact
    /// requested identity.
    ///
    /// A block that states any identity field must state both and match. A
    /// response that echoes two different identities is refused even if one
    /// matches, so the rendered nested profile (symbol/name/image/socials) can
    /// never belong to another token. At least one complete matching echo is
    /// required: a response that proves no identity is refused.
    pub fn identity_echoes_match(
        &self,
        chain: &str,
        expected_network: i64,
        expected_address: &str,
    ) -> bool {
        let nested = self.profile_token.as_ref();
        let echoes = [
            (self.network_id, self.address.as_deref()),
            (
                nested.and_then(|t| t.network_id),
                nested.and_then(|t| t.address.as_deref()),
            ),
        ];
        let mut saw_complete = false;
        for (network, address) in echoes {
            if network.is_none() && address.is_none() {
                continue;
            }
            if !identity_matches(chain, expected_network, expected_address, network, address) {
                return false;
            }
            saw_complete = true;
        }
        saw_complete
    }
}

/// One token-activity event.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeActivityEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub event_id: Option<String>,
    #[serde(
        default,
        rename = "type",
        alias = "action",
        alias = "eventType",
        alias = "kind"
    )]
    pub kind: Option<String>,
    #[serde(default)]
    pub user: Option<BridgeIntelUser>,
    #[serde(default, alias = "userHandle")]
    pub handle: Option<String>,
    #[serde(default, alias = "display")]
    pub display_name: Option<String>,
    #[serde(default, alias = "avatar", alias = "image")]
    pub avatar_url: Option<String>,
    #[serde(default, alias = "usd", alias = "amountUsd", alias = "valueUsd")]
    pub usd_amount: Option<f64>,
    #[serde(default, alias = "price")]
    pub price_usd: Option<f64>,
    #[serde(default, alias = "mcap")]
    pub market_cap_usd: Option<f64>,
    #[serde(default, alias = "fdv")]
    pub fdv_usd: Option<f64>,
    #[serde(default, alias = "createdAt", alias = "timestamp", alias = "time")]
    pub created_at_ms: Option<Value>,
    #[serde(default, alias = "comment", alias = "thesisText")]
    pub thesis: Option<String>,
}

/// Bounded `/market/activity` response.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeActivity {
    #[serde(default, alias = "tokenAddress")]
    pub address: Option<String>,
    #[serde(default, alias = "network")]
    pub network_id: Option<i64>,
    #[serde(default, alias = "items", alias = "activity")]
    pub events: Vec<BridgeActivityEvent>,
    #[serde(default, alias = "cursor", alias = "next_cursor")]
    pub next_cursor: Option<String>,
    #[serde(default, alias = "has_next_page", alias = "hasMore")]
    pub has_next_page: Option<bool>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_age_ms: Option<u64>,
}

// ------------------------------------------------------------------ //
// HTTP client helpers
// ------------------------------------------------------------------ //

/// One authenticated bounded `/market/holders` read for an exact identity.
pub async fn fetch_holders(
    client: &FomoBarsClient,
    chain_slug: &str,
    address: &str,
) -> Result<BridgeHolders, FomoMarketError> {
    let symbol = fomo_symbol(chain_slug, address).ok_or(FomoMarketError::InvalidRequest)?;
    let uri = format!("{}/market/holders?symbol={symbol}", client.base_url());
    let value = client.get_json(uri).await?;
    serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)
}

/// One authenticated bounded token-about read from the bridge's canonical
/// extended `/market/token` route.
///
/// The deployed FOMO bridge intentionally enriches `/market/token` rather than
/// exposing a separate `/market/about` route. Project that stable bridge
/// contract into `BridgeAbout` here so readiness and live reads cannot stall on
/// a route that does not exist.
pub async fn fetch_about(
    client: &FomoBarsClient,
    chain_slug: &str,
    address: &str,
) -> Result<BridgeAbout, FomoMarketError> {
    let symbol = fomo_symbol(chain_slug, address).ok_or(FomoMarketError::InvalidRequest)?;
    let token_uri = format!("{}/market/token?symbol={symbol}", client.base_url());
    let value = client.get_json(token_uri).await?;
    let detail: BridgeTokenDetail =
        serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)?;
    Ok(about_from_detail(&detail))
}

/// One authenticated bounded `/market/activity` read. The cursor is bounded and
/// percent-encoded so it cannot alter the request line.
pub async fn fetch_activity(
    client: &FomoBarsClient,
    chain_slug: &str,
    address: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<BridgeActivity, FomoMarketError> {
    let symbol = fomo_symbol(chain_slug, address).ok_or(FomoMarketError::InvalidRequest)?;
    let limit = limit.clamp(1, MAX_INTEL_LIMIT);
    let mut uri = format!(
        "{}/market/activity?symbol={symbol}&limit={limit}",
        client.base_url()
    );
    if let Some(cursor) = cursor {
        let cursor = cursor.trim();
        if cursor.is_empty() || cursor.len() > MAX_CURSOR_LEN {
            return Err(FomoMarketError::InvalidRequest);
        }
        uri.push_str("&cursor=");
        uri.push_str(&encode_query_component(cursor));
    }
    let value = client.get_json(uri).await?;
    serde_json::from_value(value).map_err(|_| FomoMarketError::InvalidResponse)
}

/// Project the backwards-compatible extended `/market/token` detail into the
/// same `BridgeAbout` shape as the dedicated route, so both bridge choices feed
/// one projection.
pub fn about_from_detail(detail: &BridgeTokenDetail) -> BridgeAbout {
    let token = &detail.token;
    let metrics = detail.detail.as_ref();
    BridgeAbout {
        address: Some(detail.address.clone()),
        network_id: Some(detail.network_id),
        profile_token: Some(BridgeAboutToken {
            address: Some(detail.address.clone()),
            network_id: Some(detail.network_id),
            symbol: token.symbol.clone(),
            name: token.name.clone(),
            image_url: token.image_url.clone(),
            social_links: token.social_links.clone(),
        }),
        profile: Some(BridgeAboutProfile {
            launchpad: token.launchpad.clone(),
            graduation_percent: token.graduation_percent,
            created_at_ms: token.created_at_ms.clone(),
            circulating_supply: token.circulating_supply,
            total_supply: token.total_supply,
        }),
        stats: Some(BridgeAboutStats {
            price_usd: metrics.and_then(|m| m.price).or(token.price_usd),
            price_change24h: metrics.and_then(|m| m.change24).or(token.change24h),
            market_cap_usd: metrics.and_then(|m| m.market_cap).or(token.market_cap_usd),
            fdv_usd: metrics.and_then(|m| m.fdv).or(token.fdv_usd),
            liquidity_usd: metrics.and_then(|m| m.liquidity).or(token.liquidity_usd),
            volume24h_usd: metrics.and_then(|m| m.volume24).or(token.volume24h_usd),
            holders: metrics.and_then(|m| m.holders).or(token.holders),
            top10_holders_percent: metrics.and_then(|m| m.top10_holders_percent),
        }),
        trading: detail.trading.clone(),
        warnings: detail.warnings.clone(),
        risk: detail.risk.clone(),
        // The `/market/token` detail contract carries no provenance, so it stays
        // unknown rather than being labelled by the adapter.
        source: None,
        source_age_ms: None,
    }
}

// ------------------------------------------------------------------ //
// Normalization helpers
// ------------------------------------------------------------------ //

/// A finite, non-negative number, or `null`. Anything else (absent, `NaN`,
/// `Infinity`, negative) is unknown and never rendered as a confident zero.
pub fn finite_nonneg(value: Option<f64>) -> Value {
    match value {
        Some(v) if v.is_finite() && v >= 0.0 => json!(v),
        _ => Value::Null,
    }
}

/// A finite signed number (PnL and 24h change may legitimately be negative).
pub fn finite_signed(value: Option<f64>) -> Value {
    match value {
        Some(v) if v.is_finite() => json!(v),
        _ => Value::Null,
    }
}

/// A provider boolean, or `null` when the provider did not prove it.
pub fn bool_or_null(value: Option<bool>) -> Value {
    match value {
        Some(v) => json!(v),
        None => Value::Null,
    }
}

/// A non-empty, bounded provider string, or `null`.
pub fn string_or_null(value: Option<&str>) -> Value {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if v.len() <= 512 => json!(v),
        _ => Value::Null,
    }
}

/// Normalize an external URL. Only an absolute `http://`/`https://` URL with a
/// host survives; every other scheme, a relative path, whitespace/control
/// characters or an over-long value is dropped (`None`).
pub fn safe_http_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &trimmed[7..]
    } else if lower.starts_with("https://") {
        &trimmed[8..]
    } else {
        return None;
    };
    if rest.is_empty()
        || rest.starts_with('/')
        || rest.starts_with('@')
        || rest.starts_with('?')
        || rest.starts_with('#')
        || rest.starts_with(':')
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// A safe URL as a JSON value, or `null`.
pub fn url_or_null(value: Option<&str>) -> Value {
    match value.and_then(safe_http_url) {
        Some(url) => json!(url),
        None => Value::Null,
    }
}

/// Normalize a provider timestamp to epoch milliseconds, or `null`. A
/// seconds-resolution value is scaled; anything non-finite/out-of-range is
/// unknown.
pub fn timestamp_ms(value: Option<&Value>) -> Value {
    let raw = match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().filter(|f| f.is_finite()).map(|f| f as i64)),
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            trimmed.parse::<i64>().ok().or_else(|| {
                trimmed
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite())
                    .map(|f| f as i64)
            })
        }
        _ => None,
    };
    let Some(raw) = raw else {
        return Value::Null;
    };
    let ms = if raw > 0 && raw < SECONDS_CUTOFF {
        raw.saturating_mul(1000)
    } else {
        raw
    };
    if ms > 0 && ms <= MAX_TIMESTAMP_MS {
        json!(ms)
    } else {
        Value::Null
    }
}

/// Map a provider activity type onto the closed PEP set, preserving the raw
/// provider type separately.
pub fn activity_kind(raw: &str) -> &'static str {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("buy") {
        "buy"
    } else if lower.contains("sell") {
        "sell"
    } else if lower.contains("transfer") {
        "transfer"
    } else if lower.contains("thesis") || lower.contains("comment") {
        "thesis"
    } else {
        "other"
    }
}

/// A transfer direction only when the provider's own type states it.
pub fn activity_direction(raw: &str) -> Value {
    let lower = raw.trim().to_ascii_lowercase();
    if !lower.contains("transfer") {
        return Value::Null;
    }
    // Split on separators and camelCase boundaries so a token that merely ends
    // in "in" (for example "origin") is not mistaken for an inbound direction.
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && !current.is_empty() {
                tokens.push(current.to_ascii_lowercase());
                current.clear();
            }
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(current.to_ascii_lowercase());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current.to_ascii_lowercase());
    }
    let has = |set: &[&str]| tokens.iter().any(|t| set.contains(&t.as_str()));
    if has(&["in", "inbound", "receive", "received", "deposit"]) {
        json!("in")
    } else if has(&["out", "outbound", "send", "sent", "withdraw"]) {
        json!("out")
    } else {
        Value::Null
    }
}

fn merge_user(nested: Option<&BridgeIntelUser>, flat: FlatUser) -> BridgeIntelUser {
    let mut merged = nested.cloned().unwrap_or_default();
    if merged.handle.is_none() {
        merged.handle = flat.handle;
    }
    if merged.display_name.is_none() {
        merged.display_name = flat.display_name;
    }
    if merged.avatar_url.is_none() {
        merged.avatar_url = flat.avatar_url;
    }
    if merged.verified.is_none() {
        merged.verified = flat.verified;
    }
    if merged.clan.is_none() {
        merged.clan = flat.clan;
    }
    if merged.followed.is_none() {
        merged.followed = flat.followed;
    }
    if merged.dev.is_none() {
        merged.dev = flat.dev;
    }
    if merged.followers.is_none() {
        merged.followers = flat.followers;
    }
    merged
}

/// Borrowed flat identity fields used to fill a nested user that omitted them.
struct FlatUser {
    handle: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    verified: Option<bool>,
    clan: Option<String>,
    followed: Option<bool>,
    dev: Option<bool>,
    followers: Option<f64>,
}

fn user_json(user: &BridgeIntelUser) -> Value {
    json!({
        "handle": string_or_null(user.handle.as_deref()),
        "displayName": string_or_null(user.display_name.as_deref()),
        "avatarUrl": url_or_null(user.avatar_url.as_deref()),
        "verified": bool_or_null(user.verified),
        "clan": string_or_null(user.clan.as_deref()),
        "followed": bool_or_null(user.followed),
        "dev": bool_or_null(user.dev),
        "followers": finite_nonneg(user.followers),
    })
}

fn thesis_json(thesis: &BridgeThesis) -> Option<Value> {
    let text = thesis
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let created_at = timestamp_ms(thesis.created_at_ms.as_ref());
    let likes = finite_nonneg(thesis.likes);
    let trade_id = string_or_null(thesis.trade_id.as_deref());
    // A thesis with no text and no usable metadata is absent, not an empty card.
    if text.is_none()
        && created_at == Value::Null
        && likes == Value::Null
        && trade_id == Value::Null
    {
        return None;
    }
    Some(json!({
        "text": text.map(|t| json!(t)).unwrap_or(Value::Null),
        "createdAtMs": created_at,
        "likes": likes,
        "tradeId": trade_id,
    }))
}

/// Project one holder row into the web contract. Nothing is invented.
pub fn holder_row_json(row: &BridgeHolderRow) -> Value {
    let user = merge_user(
        row.user.as_ref(),
        FlatUser {
            handle: row.handle.clone(),
            display_name: row.display_name.clone(),
            avatar_url: row.avatar_url.clone(),
            verified: row.verified,
            clan: row.clan.clone(),
            followed: row.followed,
            dev: row.dev,
            followers: row.followers,
        },
    );
    let wallet = row
        .wallet
        .clone()
        .or_else(|| user.wallet.clone())
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            (!trimmed.is_empty() && trimmed.len() <= 128).then_some(trimmed)
        });
    json!({
        "user": user_json(&user),
        "wallet": wallet.map(|w| json!(w)).unwrap_or(Value::Null),
        "amount": finite_nonneg(row.amount),
        "valueUsd": finite_nonneg(row.value_usd),
        "costBasisUsd": finite_nonneg(row.cost_basis_usd),
        "averageEntryPriceUsd": finite_nonneg(row.average_entry_price_usd),
        "currentPriceUsd": finite_nonneg(row.current_price_usd),
        "realizedPnlUsd": finite_signed(row.realized_pnl_usd),
        "unrealizedPnlUsd": finite_signed(row.unrealized_pnl_usd),
        "totalPnlUsd": finite_signed(row.total_pnl_usd),
        "averageHoldTimeSeconds": finite_nonneg(row.average_hold_time_seconds),
        "thesis": row.thesis.as_ref().and_then(thesis_json).unwrap_or(Value::Null),
    })
}

/// Dedupe key for a holder row: wallet when present, else handle, else none.
/// Only EVM chains fold case: Solana/Robinhood base58 identities are
/// case-sensitive, so two rows differing only in case are distinct holders.
fn holder_dedupe_key(row: &BridgeHolderRow, case_insensitive: bool) -> Option<String> {
    let raw = row
        .wallet
        .as_deref()
        .or_else(|| row.user.as_ref().and_then(|u| u.wallet.as_deref()))
        .or(row.handle.as_deref())
        .or_else(|| row.user.as_ref().and_then(|u| u.handle.as_deref()))
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    Some(if case_insensitive {
        raw.to_ascii_lowercase()
    } else {
        raw.to_string()
    })
}

/// Verify a bridge response echoes the exact requested identity. `None` on
/// either side is a mismatch: a response that cannot prove identity is refused.
fn identity_matches(
    chain_slug: &str,
    expected_network: i64,
    expected_address: &str,
    echoed_network: Option<i64>,
    echoed_address: Option<&str>,
) -> bool {
    crate::fomo_market::identity_matches(
        chain_slug,
        expected_network,
        expected_address,
        echoed_network,
        echoed_address,
    )
}

/// Project a bounded `/market/holders` response. The returned `holders` list is
/// capped at `limit` (and never above [`MAX_HOLDER_ROWS`]).
pub fn holders_json(
    chain: &str,
    expected_network: i64,
    expected_address: &str,
    limit: u32,
    bridge: &BridgeHolders,
) -> Result<Value, FomoMarketError> {
    if !identity_matches(
        chain,
        expected_network,
        expected_address,
        bridge.network_id,
        bridge.address.as_deref(),
    ) {
        return Err(FomoMarketError::InvalidResponse);
    }
    let cap = (limit as usize).clamp(1, MAX_HOLDER_ROWS);
    let fold_case = crate::fomo_market::identity_is_case_insensitive(chain);
    let mut seen: Vec<String> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    for row in bridge.holders.iter().chain(bridge.friends.iter()) {
        if rows.len() >= cap {
            break;
        }
        if let Some(key) = holder_dedupe_key(row, fold_case) {
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
        }
        rows.push(holder_row_json(row));
    }
    Ok(json!({
        "chain": chain,
        "address": expected_address,
        "holders": rows,
        "count": rows.len(),
        "source": string_or_null(bridge.source.as_deref()),
        "sourceAgeMs": bridge.source_age_ms.map(|age| json!(age)).unwrap_or(Value::Null),
    }))
}

fn social_links_json(links: Option<&BridgeSocialLinks>) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(links) = links {
        for (key, value) in [
            ("twitter", links.twitter.as_deref()),
            ("website", links.website.as_deref()),
            ("telegram", links.telegram.as_deref()),
            ("discord", links.discord.as_deref()),
        ] {
            if let Some(url) = value.and_then(safe_http_url) {
                map.insert(key.to_string(), json!(url));
            }
        }
    }
    Value::Object(map)
}

fn trading_window_json(window: Option<&BridgeTradingWindow>) -> Value {
    match window {
        None => Value::Null,
        Some(window) => json!({
            "buyCount": finite_nonneg(window.buy_count),
            "sellCount": finite_nonneg(window.sell_count),
            "buyVolumeUsd": finite_nonneg(window.buy_volume_usd),
            "sellVolumeUsd": finite_nonneg(window.sell_volume_usd),
            "uniqueBuyers": finite_nonneg(window.unique_buyers),
            "uniqueSellers": finite_nonneg(window.unique_sellers),
        }),
    }
}

/// Project a bounded `/market/about` response.
pub fn about_json(
    chain: &str,
    expected_network: i64,
    expected_address: &str,
    bridge: &BridgeAbout,
) -> Result<Value, FomoMarketError> {
    if !bridge.identity_echoes_match(chain, expected_network, expected_address) {
        return Err(FomoMarketError::InvalidResponse);
    }
    let token = bridge.profile_token.as_ref();
    let profile = bridge.profile.as_ref();
    let stats = bridge.stats.as_ref();
    let trading = bridge.trading.as_ref();
    let warnings: Vec<Value> = bridge
        .warnings
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty() && w.len() <= 512)
        .map(|w| json!(w))
        .take(64)
        .collect();
    let risk = bridge.risk.as_ref().map(crate::fomo_market::risk_json);
    Ok(json!({
        "token": {
            "chain": chain,
            "address": expected_address,
            "symbol": string_or_null(token.and_then(|t| t.symbol.as_deref())),
            "name": string_or_null(token.and_then(|t| t.name.as_deref())),
            "imageUrl": url_or_null(token.and_then(|t| t.image_url.as_deref())),
            "socialLinks": social_links_json(token.and_then(|t| t.social_links.as_ref())),
        },
        "profile": {
            "launchpad": string_or_null(profile.and_then(|p| p.launchpad.as_deref())),
            "graduationPercent": finite_nonneg(profile.and_then(|p| p.graduation_percent)),
            "createdAtMs": timestamp_ms(profile.and_then(|p| p.created_at_ms.as_ref())),
            "circulatingSupply": finite_nonneg(profile.and_then(|p| p.circulating_supply)),
            "totalSupply": finite_nonneg(profile.and_then(|p| p.total_supply)),
        },
        "stats": {
            "priceUsd": finite_nonneg(stats.and_then(|s| s.price_usd)),
            "priceChange24h": finite_signed(stats.and_then(|s| s.price_change24h)),
            "marketCapUsd": finite_nonneg(stats.and_then(|s| s.market_cap_usd)),
            "fdvUsd": finite_nonneg(stats.and_then(|s| s.fdv_usd)),
            "liquidityUsd": finite_nonneg(stats.and_then(|s| s.liquidity_usd)),
            "volume24hUsd": finite_nonneg(stats.and_then(|s| s.volume24h_usd)),
            "holders": finite_nonneg(stats.and_then(|s| s.holders)),
            "top10HoldersPercent": finite_nonneg(stats.and_then(|s| s.top10_holders_percent)),
        },
        "trading": {
            "5m": trading_window_json(trading.and_then(|t| t.m5.as_ref())),
            "1h": trading_window_json(trading.and_then(|t| t.h1.as_ref())),
            "4h": trading_window_json(trading.and_then(|t| t.h4.as_ref())),
            "24h": trading_window_json(trading.and_then(|t| t.h24.as_ref())),
        },
        "warnings": warnings,
        "risk": risk.unwrap_or(Value::Null),
        "source": string_or_null(bridge.source.as_deref()),
        "sourceAgeMs": bridge.source_age_ms.map(|age| json!(age)).unwrap_or(Value::Null),
    }))
}

/// Project one activity event. `rawType` preserves the provider's own type.
pub fn activity_event_json(event: &BridgeActivityEvent) -> Value {
    let raw_type = event.kind.as_deref().unwrap_or("").trim();
    let kind = activity_kind(raw_type);
    let user = merge_user(
        event.user.as_ref(),
        FlatUser {
            handle: event.handle.clone(),
            display_name: event.display_name.clone(),
            avatar_url: event.avatar_url.clone(),
            verified: None,
            clan: None,
            followed: None,
            dev: None,
            followers: None,
        },
    );
    let thesis = event
        .thesis
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| json!(t))
        .unwrap_or(Value::Null);
    json!({
        "id": string_or_null(event.event_id.as_deref()),
        "type": kind,
        "rawType": if raw_type.is_empty() { Value::Null } else { json!(raw_type) },
        "direction": activity_direction(raw_type),
        "user": user_json(&user),
        "usdAmount": finite_nonneg(event.usd_amount),
        "priceUsd": finite_nonneg(event.price_usd),
        "marketCapUsd": finite_nonneg(event.market_cap_usd),
        "fdvUsd": finite_nonneg(event.fdv_usd),
        "createdAtMs": timestamp_ms(event.created_at_ms.as_ref()),
        "thesis": thesis,
    })
}

/// Project a bounded `/market/activity` response. The event list is capped at
/// the client-requested `limit` (and never above [`MAX_ACTIVITY_ROWS`]).
pub fn activity_json(
    chain: &str,
    expected_network: i64,
    expected_address: &str,
    limit: u32,
    bridge: &BridgeActivity,
) -> Result<Value, FomoMarketError> {
    if !identity_matches(
        chain,
        expected_network,
        expected_address,
        bridge.network_id,
        bridge.address.as_deref(),
    ) {
        return Err(FomoMarketError::InvalidResponse);
    }
    let cap = (limit as usize).clamp(1, MAX_ACTIVITY_ROWS);
    let events: Vec<Value> = bridge
        .events
        .iter()
        .take(cap)
        .map(activity_event_json)
        .collect();
    let next_cursor = bridge
        .next_cursor
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty() && c.len() <= MAX_CURSOR_LEN)
        .map(|c| json!(c))
        .unwrap_or(Value::Null);
    Ok(json!({
        "chain": chain,
        "address": expected_address,
        "events": events,
        "count": events.len(),
        "nextCursor": next_cursor,
        "hasNextPage": bool_or_null(bridge.has_next_page),
        "source": string_or_null(bridge.source.as_deref()),
        "sourceAgeMs": bridge.source_age_ms.map(|age| json!(age)).unwrap_or(Value::Null),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_allowlist_accepts_only_absolute_http_and_https() {
        assert_eq!(
            safe_http_url("https://x.com/a").as_deref(),
            Some("https://x.com/a")
        );
        assert_eq!(
            safe_http_url("http://example.com").as_deref(),
            Some("http://example.com")
        );
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "/relative",
            "ftp://x",
            "https://",
            "https:// user",
            "http://?x",
            "http://:80",
            "http://#f",
            "",
        ] {
            assert!(safe_http_url(bad).is_none(), "{bad}");
        }
        assert!(safe_http_url(&format!("https://x.com/{}", "a".repeat(600))).is_none());
    }

    #[test]
    fn timestamps_normalize_seconds_and_reject_junk() {
        assert_eq!(
            timestamp_ms(Some(&json!(1_700_000_000_000i64))),
            json!(1_700_000_000_000i64)
        );
        assert_eq!(
            timestamp_ms(Some(&json!(1_700_000_000i64))),
            json!(1_700_000_000_000i64)
        );
        assert_eq!(
            timestamp_ms(Some(&json!("1700000000"))),
            json!(1_700_000_000_000i64)
        );
        assert_eq!(timestamp_ms(Some(&json!("not-a-time"))), Value::Null);
        assert_eq!(timestamp_ms(Some(&json!(-5))), Value::Null);
        assert_eq!(timestamp_ms(None), Value::Null);
    }

    #[test]
    fn activity_kind_preserves_the_closed_semantics() {
        assert_eq!(activity_kind("swap_buy"), "buy");
        assert_eq!(activity_kind("swap_sell"), "sell");
        assert_eq!(activity_kind("transfer"), "transfer");
        assert_eq!(activity_kind("thesis"), "thesis");
        assert_eq!(activity_kind("comment"), "thesis");
        assert_eq!(activity_kind("mystery"), "other");
        assert_eq!(activity_direction("transfer_in"), json!("in"));
        assert_eq!(activity_direction("transfer_out"), json!("out"));
        assert_eq!(activity_direction("tokenTransferIn"), json!("in"));
        // A token that merely ends in "in" is not a stated direction.
        assert_eq!(activity_direction("transfer_origin"), Value::Null);
        assert_eq!(activity_direction("transfer"), Value::Null);
        assert_eq!(activity_direction("swap_buy"), Value::Null);
    }

    #[test]
    fn holders_require_the_exact_echoed_identity() {
        let bridge = BridgeHolders {
            address: Some("0xABC".into()),
            network_id: Some(8_453),
            ..BridgeHolders::default()
        };
        assert!(holders_json("base", 8_453, "0xabc", 50, &bridge).is_ok());
        // Wrong network, wrong address and an absent echo all fail closed.
        assert!(holders_json("base", 1, "0xabc", 50, &bridge).is_err());
        assert!(holders_json("base", 8_453, "0xdef", 50, &bridge).is_err());
        assert!(holders_json("base", 8_453, "0xabc", 50, &BridgeHolders::default()).is_err());
    }

    #[test]
    fn holder_projection_keeps_nulls_and_normalizes_thesis() {
        let row = BridgeHolderRow {
            wallet: Some("0xabc".into()),
            amount: Some(f64::NAN),
            value_usd: Some(10.0),
            realized_pnl_usd: Some(-3.5),
            thesis: Some(BridgeThesis {
                text: Some("  bullish  ".into()),
                created_at_ms: Some(json!(1_700_000_000i64)),
                likes: Some(4.0),
                trade_id: None,
            }),
            ..BridgeHolderRow::default()
        };
        let value = holder_row_json(&row);
        assert_eq!(value["amount"], Value::Null, "NaN is unknown");
        assert_eq!(value["valueUsd"], 10.0);
        assert_eq!(value["realizedPnlUsd"], -3.5);
        assert_eq!(value["thesis"]["text"], "bullish");
        assert_eq!(value["thesis"]["createdAtMs"], 1_700_000_000_000i64);
        assert_eq!(value["thesis"]["likes"], 4.0);
        assert_eq!(value["thesis"]["tradeId"], Value::Null);
    }

    #[test]
    fn holders_merge_friends_and_dedupe_under_the_cap() {
        let bridge = BridgeHolders {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            holders: vec![BridgeHolderRow {
                wallet: Some("0x1".into()),
                ..BridgeHolderRow::default()
            }],
            friends: vec![
                BridgeHolderRow {
                    wallet: Some("0x1".into()),
                    ..BridgeHolderRow::default()
                },
                BridgeHolderRow {
                    wallet: Some("0x2".into()),
                    ..BridgeHolderRow::default()
                },
            ],
            ..BridgeHolders::default()
        };
        let value = holders_json("base", 8_453, "0xabc", 50, &bridge).unwrap();
        assert_eq!(value["count"], 2);
    }

    #[test]
    fn activity_is_bounded_and_preserves_the_cursor() {
        let events = (0..(MAX_ACTIVITY_ROWS + 25))
            .map(|_| BridgeActivityEvent {
                kind: Some("swap_buy".into()),
                ..BridgeActivityEvent::default()
            })
            .collect();
        let bridge = BridgeActivity {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            events,
            next_cursor: Some("c1".into()),
            has_next_page: Some(true),
            ..BridgeActivity::default()
        };
        let value = activity_json("base", 8_453, "0xabc", MAX_INTEL_LIMIT, &bridge).unwrap();
        assert_eq!(value["count"], MAX_ACTIVITY_ROWS);
        assert_eq!(value["nextCursor"], "c1");
        assert_eq!(value["hasNextPage"], true);

        // A client-requested smaller page caps the projection even when a
        // misbehaving bridge returns more than requested.
        let capped = activity_json("base", 8_453, "0xabc", 5, &bridge).unwrap();
        assert_eq!(capped["count"], 5);
    }

    #[test]
    fn about_rejects_a_response_that_echoes_two_identities() {
        // The nested profile is rendered, so a response whose top level matches A
        // but whose nested token block echoes B must be refused rather than
        // rendering B's symbol/name/socials under A.
        let bridge = BridgeAbout {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            profile_token: Some(BridgeAboutToken {
                address: Some("0xdef".into()),
                network_id: Some(8_453),
                symbol: Some("EVIL".into()),
                ..BridgeAboutToken::default()
            }),
            ..BridgeAbout::default()
        };
        assert!(about_json("base", 8_453, "0xabc", &bridge).is_err());

        // A nested-only echo is accepted only when it matches exactly.
        let nested_only = BridgeAbout {
            profile_token: Some(BridgeAboutToken {
                address: Some("0xabc".into()),
                network_id: Some(8_453),
                ..BridgeAboutToken::default()
            }),
            ..BridgeAbout::default()
        };
        assert!(about_json("base", 8_453, "0xabc", &nested_only).is_ok());
        assert!(about_json("base", 8_453, "0xdef", &nested_only).is_err());
        // A response that proves no identity at all is refused.
        assert!(about_json("base", 8_453, "0xabc", &BridgeAbout::default()).is_err());
        // A partial identity block (one field without the other) is unprovable
        // and refused rather than treated as absent.
        let partial = BridgeAbout {
            network_id: Some(8_453),
            ..BridgeAbout::default()
        };
        assert!(about_json("base", 8_453, "0xabc", &partial).is_err());
    }

    #[test]
    fn solana_identity_is_byte_exact_and_wallets_are_not_case_folded() {
        let sol = "TokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let lower = "tokenaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let bridge = BridgeHolders {
            address: Some(sol.into()),
            network_id: Some(1_399_811_149),
            ..BridgeHolders::default()
        };
        assert!(holders_json("solana", 1_399_811_149, sol, 50, &bridge).is_ok());
        // Solana base58 is case-sensitive: a case variant is a different identity.
        assert!(holders_json("solana", 1_399_811_149, lower, 50, &bridge).is_err());

        // Two Solana wallets differing only in case are distinct holders and must
        // not be deduped away.
        let rows = BridgeHolders {
            address: Some(sol.into()),
            network_id: Some(1_399_811_149),
            holders: vec![
                BridgeHolderRow {
                    wallet: Some("Abc".into()),
                    ..BridgeHolderRow::default()
                },
                BridgeHolderRow {
                    wallet: Some("abc".into()),
                    ..BridgeHolderRow::default()
                },
            ],
            ..BridgeHolders::default()
        };
        let value = holders_json("solana", 1_399_811_149, sol, 50, &rows).unwrap();
        assert_eq!(value["count"], 2);

        // EVM identities fold case, so a case variant is the same holder.
        let evm = BridgeHolders {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            holders: vec![
                BridgeHolderRow {
                    wallet: Some("0xABC".into()),
                    ..BridgeHolderRow::default()
                },
                BridgeHolderRow {
                    wallet: Some("0xabc".into()),
                    ..BridgeHolderRow::default()
                },
            ],
            ..BridgeHolders::default()
        };
        let value = holders_json("base", 8_453, "0xabc", 50, &evm).unwrap();
        assert_eq!(value["count"], 1);
    }

    #[test]
    fn projections_leave_absent_provenance_null() {
        let holders = BridgeHolders {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            ..BridgeHolders::default()
        };
        let value = holders_json("base", 8_453, "0xabc", 50, &holders).unwrap();
        assert_eq!(value["source"], Value::Null);
        assert_eq!(value["sourceAgeMs"], Value::Null);

        let with_age = BridgeHolders {
            source: Some("rest".into()),
            source_age_ms: Some(1_234),
            ..holders
        };
        let value = holders_json("base", 8_453, "0xabc", 50, &with_age).unwrap();
        assert_eq!(value["source"], "rest");
        assert_eq!(value["sourceAgeMs"], 1_234);
    }

    #[test]
    fn about_drops_unsafe_social_links_and_keeps_null_stats() {
        let bridge = BridgeAbout {
            address: Some("0xabc".into()),
            network_id: Some(8_453),
            profile_token: Some(BridgeAboutToken {
                social_links: Some(BridgeSocialLinks {
                    twitter: Some("https://x.com/t".into()),
                    website: Some("javascript:alert(1)".into()),
                    telegram: Some("https://t.me/t".into()),
                    discord: None,
                }),
                ..BridgeAboutToken::default()
            }),
            ..BridgeAbout::default()
        };
        let value = about_json("base", 8_453, "0xabc", &bridge).unwrap();
        assert_eq!(value["token"]["socialLinks"]["twitter"], "https://x.com/t");
        assert!(value["token"]["socialLinks"].get("website").is_none());
        assert_eq!(value["token"]["socialLinks"]["telegram"], "https://t.me/t");
        assert!(value["token"]["socialLinks"].get("discord").is_none());
        assert_eq!(value["stats"]["priceUsd"], Value::Null);
        assert_eq!(value["trading"]["5m"], Value::Null);
    }
}
