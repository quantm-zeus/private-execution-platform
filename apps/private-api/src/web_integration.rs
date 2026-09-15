//! Private web intent translation, preview projection and quote-bound execution
//! (BR-10 / BR-11 / BR-12, with the BR-2/BR-3 envelope owned by `session-transport`).
//!
//! The browser speaks a **neutral, human-shaped** contract: it names a chain by
//! its advertised slug, a token by its address, and an amount with an explicit
//! `amount_type` (`usd` / `stablecoin` / `token`). The canonical
//! `agent-commands` vocabulary instead wants chain-qualified `AssetRef`s and
//! lossless atomic [`AmountSpec`]s. This module is the single place that bridges
//! the two, and it **derives nothing on its own**:
//!
//! * Chain identity and token decimals come from an injected, authoritative
//!   [`InstrumentRegistry`]. The default [`FailClosedInstrumentRegistry`]
//!   resolves nothing, so a token amount fails closed rather than trading on a
//!   client-asserted scale factor.
//! * A decimal with more precision than the asset supports is a protocol
//!   rejection, never a silent rounding of a trade size.
//! * `preview_market_order` stores the *translated canonical intent* under a
//!   server-generated, unguessable `quote_id`; `execute_market_order` resolves
//!   that id and executes the exact intent the user reviewed. A quote can only
//!   be executed under the routing source it was quoted with (no silent
//!   re-route), and an unknown/expired quote is a determinate rejection.
//! * The preview response is projected into the web `QuotePreview` view from the
//!   canonical `MarketPreview` (`RouteQuote` + `RouteScore`). Values that the
//!   backend did not supply are `null` ("unknown"), never fabricated.
//!
//! Nothing here is persisted and no key material is handled.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chain_types::ChainId;
use serde_json::{json, Map, Number, Value};
use session_transport::{CommandDenial, CommandRequest, DenialCode};

use crate::opaque::{CommandDispatcher, OpaqueClock};

/// Maximum number of decimal places accepted for an instrument. Bound so a
/// hostile registry entry cannot overflow the scaling arithmetic.
const MAX_DECIMALS: u8 = 36;
/// Default lifetime of a stored preview quote.
pub const DEFAULT_QUOTE_TTL_MS: i64 = 120_000;

/// Authoritative metadata for one chain-qualified instrument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instrument {
    /// Canonical chain the instrument lives on.
    pub chain: ChainId,
    /// Token base-unit decimals. The only accepted scale factor for a
    /// `token` / `stablecoin` amount.
    pub decimals: u8,
}

/// Authoritative instrument lookup (chain slug + token address -> metadata).
///
/// The production implementation is backed by Trading Core / market metadata.
/// There is deliberately no "guess the decimals" fallback.
#[async_trait]
pub trait InstrumentRegistry: Send + Sync {
    async fn resolve(&self, chain_slug: &str, address: &str) -> Result<Instrument, CommandDenial>;

    /// Resolve only the canonical chain identity for a bootstrap chain slug.
    ///
    /// Read paths (`get_token`/`get_intelligence`/`get_chart`) need a chain, not
    /// token decimals, and must work for tokens the reader does not yet know.
    /// Defaults to fail closed.
    async fn resolve_chain(&self, _chain_slug: &str) -> Result<ChainId, CommandDenial> {
        Err(CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Instrument metadata is not configured.",
        ))
    }
}

/// Fail-closed registry: every lookup is a determinate capability denial, so no
/// token-denominated command can reach the canonical parser without an
/// authoritative scale factor.
#[derive(Debug, Default)]
pub struct FailClosedInstrumentRegistry;

#[async_trait]
impl InstrumentRegistry for FailClosedInstrumentRegistry {
    async fn resolve(
        &self,
        _chain_slug: &str,
        _address: &str,
    ) -> Result<Instrument, CommandDenial> {
        Err(CommandDenial::determinate(
            DenialCode::CapabilityMissing,
            "Instrument metadata is not configured.",
        ))
    }
}

/// Static registry used by tests and by deployments with a fixed instrument set.
#[derive(Debug, Default)]
pub struct StaticInstrumentRegistry {
    entries: HashMap<(String, String), Instrument>,
    chains: HashMap<String, ChainId>,
}

impl StaticInstrumentRegistry {
    pub fn new(
        entries: impl IntoIterator<Item = ((String, String), Instrument)>,
    ) -> Result<Self, CommandDenial> {
        let mut map = HashMap::new();
        let mut chains = HashMap::new();
        for ((chain, address), instrument) in entries {
            if chain.trim().is_empty()
                || address.trim().is_empty()
                || instrument.decimals > MAX_DECIMALS
            {
                return Err(CommandDenial::determinate(
                    DenialCode::Protocol,
                    "Instrument registry entry is invalid.",
                ));
            }
            chains.insert(chain.clone(), instrument.chain.clone());
            map.insert((chain, address), instrument);
        }
        Ok(Self {
            entries: map,
            chains,
        })
    }

    /// Convenience constructor keyed by chain slug + token address.
    pub fn from_slug_entries(
        entries: impl IntoIterator<Item = (String, String, ChainId, u8)>,
    ) -> Result<Self, CommandDenial> {
        Self::new(entries.into_iter().map(|(chain, address, id, decimals)| {
            (
                (chain, address),
                Instrument {
                    chain: id,
                    decimals,
                },
            )
        }))
    }
}

#[async_trait]
impl InstrumentRegistry for StaticInstrumentRegistry {
    async fn resolve(&self, chain_slug: &str, address: &str) -> Result<Instrument, CommandDenial> {
        self.entries
            .get(&(chain_slug.to_string(), address.to_string()))
            .cloned()
            .ok_or_else(|| {
                CommandDenial::determinate(
                    DenialCode::CapabilityMissing,
                    "Instrument is not available on this deployment.",
                )
            })
    }

    async fn resolve_chain(&self, chain_slug: &str) -> Result<ChainId, CommandDenial> {
        self.chains.get(chain_slug).cloned().ok_or_else(|| {
            CommandDenial::determinate(
                DenialCode::CapabilityMissing,
                "Chain is not available on this deployment.",
            )
        })
    }
}

/// A stored, fully-translated preview the browser may execute by `quote_id`.
#[derive(Clone)]
struct StoredQuote {
    canonical: Value,
    router: String,
    expires_at_ms: i64,
    sequence: u64,
}

/// Memory-only, session-scoped quote store. Never persisted.
pub struct QuoteStore {
    entries: Mutex<HashMap<(Vec<u8>, String), StoredQuote>>,
    ttl_ms: i64,
    max_entries: usize,
    max_per_kid: usize,
    sequence: AtomicU64,
}

/// Upper bound on live stored quotes, so a session cannot grow the private
/// process without limit by requesting previews.
pub const MAX_QUOTE_ENTRIES: usize = 4096;
/// Per-session bound: a single session evicts its own oldest quote instead of
/// being able to fill the shared store and starve every other session.
pub const MAX_QUOTES_PER_SESSION: usize = 128;

impl QuoteStore {
    pub fn new(ttl_ms: i64) -> Self {
        Self::with_capacity(ttl_ms, MAX_QUOTE_ENTRIES)
    }

    pub fn with_capacity(ttl_ms: i64, max_entries: usize) -> Self {
        Self::with_limits(ttl_ms, max_entries, MAX_QUOTES_PER_SESSION)
    }

    pub fn with_limits(ttl_ms: i64, max_entries: usize, max_per_kid: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl_ms: if ttl_ms > 0 {
                ttl_ms
            } else {
                DEFAULT_QUOTE_TTL_MS
            },
            max_entries: max_entries.max(1),
            max_per_kid: max_per_kid.max(1),
            sequence: AtomicU64::new(0),
        }
    }

    /// The lifetime a stored quote is valid for. Used both for expiry and for
    /// the preview's `expiresAtMs`.
    pub fn ttl_ms(&self) -> i64 {
        self.ttl_ms
    }

    fn insert(
        &self,
        kid: &[u8],
        quote_id: &str,
        canonical: Value,
        router: String,
        now_ms: i64,
    ) -> Result<(), CommandDenial> {
        let mut entries = self.lock();
        prune(&mut entries, now_ms);
        // Per-session quota: evict only this session's oldest quote, so a flood
        // cannot deny the preview surface to other sessions.
        if count_for_kid(&entries, kid) >= self.max_per_kid {
            evict_oldest(&mut entries, Some(kid));
        }
        // Global backstop for total memory.
        if entries.len() >= self.max_entries {
            evict_oldest(&mut entries, None);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        entries.insert(
            (kid.to_vec(), quote_id.to_string()),
            StoredQuote {
                canonical,
                router,
                expires_at_ms: now_ms.saturating_add(self.ttl_ms),
                sequence,
            },
        );
        Ok(())
    }

    fn get(&self, kid: &[u8], quote_id: &str, now_ms: i64) -> Option<(Value, String)> {
        let mut entries = self.lock();
        prune(&mut entries, now_ms);
        entries
            .get(&(kid.to_vec(), quote_id.to_string()))
            .map(|stored| (stored.canonical.clone(), stored.router.clone()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(Vec<u8>, String), StoredQuote>> {
        // A panic while holding this lock must not take the command surface down
        // with a poison error; the map is a plain in-memory cache.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn prune(entries: &mut HashMap<(Vec<u8>, String), StoredQuote>, now_ms: i64) {
    entries.retain(|_, stored| stored.expires_at_ms > now_ms);
}

fn count_for_kid(entries: &HashMap<(Vec<u8>, String), StoredQuote>, kid: &[u8]) -> usize {
    entries
        .keys()
        .filter(|(entry_kid, _)| entry_kid.as_slice() == kid)
        .count()
}

/// Remove the oldest (lowest sequence) entry, optionally restricted to one kid.
fn evict_oldest(entries: &mut HashMap<(Vec<u8>, String), StoredQuote>, kid: Option<&[u8]>) {
    let oldest = entries
        .iter()
        .filter(|((entry_kid, _), _)| kid.is_none_or(|wanted| entry_kid.as_slice() == wanted))
        .min_by_key(|(_, stored)| stored.sequence)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        entries.remove(&key);
    }
}

/// Composes the web intent translation and quote binding around a canonical
/// command dispatcher (the private `WebContractDispatcher`).
pub struct WebIntegrationDispatcher {
    inner: Arc<dyn CommandDispatcher>,
    registry: Arc<dyn InstrumentRegistry>,
    clock: Arc<dyn OpaqueClock>,
    quotes: QuoteStore,
}

impl WebIntegrationDispatcher {
    pub fn new(
        inner: Arc<dyn CommandDispatcher>,
        registry: Arc<dyn InstrumentRegistry>,
        clock: Arc<dyn OpaqueClock>,
    ) -> Self {
        Self::with_quote_ttl(inner, registry, clock, DEFAULT_QUOTE_TTL_MS)
    }

    pub fn with_quote_ttl(
        inner: Arc<dyn CommandDispatcher>,
        registry: Arc<dyn InstrumentRegistry>,
        clock: Arc<dyn OpaqueClock>,
        quote_ttl_ms: i64,
    ) -> Self {
        Self {
            inner,
            registry,
            clock,
            quotes: QuoteStore::new(quote_ttl_ms),
        }
    }

    async fn translate_market(
        &self,
        intent: &Value,
        router: &str,
        with_trade_fields: bool,
    ) -> Result<MarketIntent, CommandDenial> {
        translate_market_intent(intent, router, self.registry.as_ref(), with_trade_fields).await
    }

    async fn preview_market_order(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        let router = required_router(&request.payload)?;
        let intent = request
            .payload
            .get("intent")
            .filter(|value| value.is_object())
            .unwrap_or(&request.payload);
        let market = self.translate_market(intent, &router, true).await?;
        let now = self.clock.now_ms().ok_or_else(clock_denial)?;

        let mut preview_request = request.clone();
        preview_request.payload = market.canonical.clone();
        let result = self.inner.dispatch(&preview_request).await?;

        let quote_id = random_quote_id()?;
        self.quotes.insert(
            kid,
            &quote_id,
            market.canonical.clone(),
            router.clone(),
            now,
        )?;
        let expires_at_ms = now.saturating_add(self.quotes.ttl_ms());
        project_preview(&result, &market, &quote_id, &router, expires_at_ms)
    }

    async fn execute_market_order(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        let router = required_router(&request.payload)?;
        let quote_id = required_string(&request.payload, "quote_id")?;
        let now = self.clock.now_ms().ok_or_else(clock_denial)?;
        let (canonical, quoted_router) = self
            .quotes
            .get(kid, &quote_id, now)
            .ok_or_else(|| protocol("quote is unknown or expired; preview again"))?;
        if quoted_router != router {
            return Err(protocol(
                "router_preference does not match the quoted source; requote explicitly",
            ));
        }
        let mut execute_request = request.clone();
        execute_request.payload = canonical;
        self.inner.dispatch(&execute_request).await
    }

    async fn translate_and_dispatch(
        &self,
        request: &CommandRequest,
        payload: Value,
    ) -> Result<Value, CommandDenial> {
        let mut translated = request.clone();
        translated.payload = payload;
        self.inner.dispatch(&translated).await
    }
}

#[async_trait]
impl CommandDispatcher for WebIntegrationDispatcher {
    async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
        self.dispatch_for_session(&[], request).await
    }

    async fn dispatch_for_session(
        &self,
        kid: &[u8],
        request: &CommandRequest,
    ) -> Result<Value, CommandDenial> {
        match request.op.as_str() {
            "preview_market_order" => self.preview_market_order(kid, request).await,
            "execute_market_order" => self.execute_market_order(kid, request).await,
            "place_limit_order" => {
                let payload =
                    translate_place_limit_order(&request.payload, self.registry.as_ref()).await?;
                self.translate_and_dispatch(request, payload).await
            }
            "get_quote" => {
                let router = required_router(&request.payload)?;
                let intent = request
                    .payload
                    .get("intent")
                    .filter(|value| value.is_object())
                    .unwrap_or(&request.payload);
                // `get_quote` is a read: the canonical parser accepts only the
                // quote fields, so no side or market-order risk caps are built.
                let market = self.translate_market(intent, &router, false).await?;
                self.translate_and_dispatch(request, market.canonical).await
            }
            "get_token" | "get_intelligence" => {
                let payload =
                    translate_token_payload(&request.payload, self.registry.as_ref(), false)
                        .await?;
                self.translate_and_dispatch(request, payload).await
            }
            "get_chart" => {
                let payload =
                    translate_token_payload(&request.payload, self.registry.as_ref(), true).await?;
                self.translate_and_dispatch(request, payload).await
            }
            _ => self.inner.dispatch(request).await,
        }
    }
}

/// The web-shaped market intent plus the canonical command it maps to.
struct MarketIntent {
    canonical: Value,
    chain: String,
    token_in: String,
    token_out: String,
    side: String,
    amount_type: String,
    amount: Value,
    max_slippage_bps: Option<u16>,
    max_price_impact_bps: Option<u16>,
    max_total_cost_usd: Value,
    out_decimals: u8,
}

async fn translate_market_intent(
    intent: &Value,
    router: &str,
    registry: &dyn InstrumentRegistry,
    with_trade_fields: bool,
) -> Result<MarketIntent, CommandDenial> {
    let chain = required_string(intent, "chain")?;
    let token_in = required_string(intent, "token_in")?;
    let token_out = required_string(intent, "token_out")?;
    let side = if with_trade_fields {
        required_side(intent)?
    } else {
        String::new()
    };
    let amount_type = required_string(intent, "amount_type")?;
    let amount = intent
        .get("amount")
        .cloned()
        .ok_or_else(|| protocol("amount is required"))?;

    let in_meta = registry.resolve(&chain, &token_in).await?;
    let out_meta = registry.resolve(&chain, &token_out).await?;
    if in_meta.chain != out_meta.chain {
        return Err(protocol("token_in and token_out must share a chain"));
    }

    let amount_spec = amount_spec_for(&amount, &amount_type, in_meta.decimals)?;
    let mut canonical = Map::new();
    canonical.insert(
        "token_in".to_string(),
        asset_json(&in_meta.chain, &token_in),
    );
    canonical.insert(
        "token_out".to_string(),
        asset_json(&out_meta.chain, &token_out),
    );
    if with_trade_fields {
        canonical.insert("side".to_string(), Value::String(side.clone()));
    }
    canonical.insert("amount".to_string(), amount_spec);
    canonical.insert(
        "router_preference".to_string(),
        Value::String(router.to_string()),
    );

    let max_slippage_bps = if with_trade_fields {
        optional_u16(intent, "max_slippage_bps")?
    } else {
        None
    };
    if let Some(bps) = max_slippage_bps {
        canonical.insert("max_slippage_bps".to_string(), json!(bps));
    }
    let max_price_impact_bps = if with_trade_fields {
        optional_u16(intent, "max_price_impact_bps")?
    } else {
        None
    };
    if let Some(bps) = max_price_impact_bps {
        canonical.insert("max_price_impact_bps".to_string(), json!(bps));
    }
    let max_total_cost_usd = intent
        .get("max_total_cost_usd")
        .cloned()
        .unwrap_or(Value::Null);
    // F1: the canonical command vocabulary has no per-order USD total-cost cap, so
    // a non-null `max_total_cost_usd` cannot be enforced. Echoing it back would
    // present an unenforced safety control as accepted, so it is a determinate
    // refusal (the same policy as an unsupported `usd` amount).
    if with_trade_fields && !max_total_cost_usd.is_null() {
        return Err(protocol(
            "max_total_cost_usd is not enforceable by the canonical command; remove the cap.",
        ));
    }

    Ok(MarketIntent {
        canonical: Value::Object(canonical),
        chain,
        token_in,
        token_out,
        side,
        amount_type,
        amount,
        max_slippage_bps,
        max_price_impact_bps,
        max_total_cost_usd,
        out_decimals: out_meta.decimals,
    })
}

async fn translate_place_limit_order(
    payload: &Value,
    registry: &dyn InstrumentRegistry,
) -> Result<Value, CommandDenial> {
    let chain = required_string(payload, "chain")?;
    let token_in = required_string(payload, "token_in")?;
    let token_out = required_string(payload, "token_out")?;
    let side = required_side(payload)?;
    let amount_type = required_string(payload, "amount_type")?;
    let amount = payload
        .get("amount")
        .cloned()
        .ok_or_else(|| protocol("amount is required"))?;
    let limit_price = payload
        .get("limit_price")
        .cloned()
        .ok_or_else(|| protocol("limit_price is required"))?;
    let allow_partial_fill = payload
        .get("allow_partial_fill")
        .and_then(Value::as_bool)
        .ok_or_else(|| protocol("allow_partial_fill is required"))?;
    let expires_at_ms = payload
        .get("expiry_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| protocol("expiry_ms is required"))?;

    let in_meta = registry.resolve(&chain, &token_in).await?;
    let out_meta = registry.resolve(&chain, &token_out).await?;
    if in_meta.chain != out_meta.chain {
        return Err(protocol("token_in and token_out must share a chain"));
    }

    let amount_spec = amount_spec_for(&amount, &amount_type, in_meta.decimals)?;
    // Canonical orientation (see `agent-backend::trade::place_limit_order`):
    // buy  -> numerator_asset = token_in,  denominator_asset = token_out
    // sell -> numerator_asset = token_out, denominator_asset = token_in
    // so the ratio is always quote-per-base in atomic units.
    let (quote_decimals, base_decimals) = if side == "buy" {
        (in_meta.decimals, out_meta.decimals)
    } else {
        (out_meta.decimals, in_meta.decimals)
    };
    let limit_price = decimal_to_atomic_ratio(&limit_price, quote_decimals, base_decimals)?;

    Ok(json!({
        "token_in": asset_json(&in_meta.chain, &token_in),
        "token_out": asset_json(&out_meta.chain, &token_out),
        "side": side,
        "amount": amount_spec,
        "limit_price": limit_price,
        "allow_partial_fill": allow_partial_fill,
        "expires_at_ms": expires_at_ms,
    }))
}

async fn translate_token_payload(
    payload: &Value,
    registry: &dyn InstrumentRegistry,
    with_window: bool,
) -> Result<Value, CommandDenial> {
    let chain = required_string(payload, "chain")?;
    let address = required_string(payload, "address")?;
    // Reads must work for tokens the reader does not yet know, so only the chain
    // identity is resolved (never a decimal scale factor).
    let chain_id = registry.resolve_chain(&chain).await?;
    let mut translated = Map::new();
    translated.insert("token".to_string(), asset_json(&chain_id, &address));
    if with_window {
        let window = payload
            .get("window")
            .cloned()
            .ok_or_else(|| protocol("window is required"))?;
        translated.insert("window".to_string(), window);
    }
    Ok(Value::Object(translated))
}

/// Translate a browser amount (`amount_type` + human decimal) into the canonical
/// lossless `AmountSpec` using only authoritative decimals.
fn amount_spec_for(
    amount: &Value,
    amount_type: &str,
    token_decimals: u8,
) -> Result<Value, CommandDenial> {
    match amount_type {
        // The canonical trading backend accepts only explicit input-asset atomics
        // and deliberately refuses to convert a USD notional itself (it has no
        // trusted price). Rejecting here is a determinate refusal instead of a
        // downstream "denied"; a USD order needs Trading Core USD-notional support
        // (see `docs/live-integration.md`).
        "usd" => Err(protocol(
            "USD amounts are not supported yet; use a token or stablecoin amount.",
        )),
        "stablecoin" => {
            let atomic = decimal_to_scaled(amount, token_decimals)?;
            ensure_nonzero(atomic)?;
            Ok(json!({ "unit": "stablecoin_atomic", "value": atomic }))
        }
        "token" => {
            let atomic = decimal_to_scaled(amount, token_decimals)?;
            ensure_nonzero(atomic)?;
            Ok(json!({ "unit": "token_atomic", "value": atomic }))
        }
        _ => Err(protocol(
            "amount_type must be one of usd, stablecoin or token",
        )),
    }
}

fn ensure_nonzero(value: u128) -> Result<(), CommandDenial> {
    if value == 0 {
        return Err(protocol("amount must be positive"));
    }
    Ok(())
}

/// Convert a JSON amount/price to decimal text.
///
/// A JSON *float* has already been rounded to the client's f64, so a shortest
/// representation with more than 15 significant digits is refused: the caller
/// must send a decimal string when it needs exact precision. This keeps the
/// "no silent rounding" guarantee honest for `amount` and `limit_price`.
fn numeric_text(raw: &Value, what: &str) -> Result<String, CommandDenial> {
    match raw {
        Value::String(text) => Ok(text.trim().to_string()),
        Value::Number(number) => {
            let text = number.to_string();
            // Count significant digits only (ignore leading zeros).
            let significant = text
                .trim_start_matches('0')
                .chars()
                .filter(|c| c.is_ascii_digit())
                .count();
            if number.is_f64() && significant > 15 {
                return Err(protocol(format!(
                    "{what} must be a decimal string for exact precision"
                )));
            }
            Ok(text)
        }
        _ => Err(protocol(format!(
            "{what} must be a number or decimal string"
        ))),
    }
}

/// Scale a plain non-negative decimal (string or JSON number) to an integer with
/// exactly `decimals` places. Rejects exponent notation and any value that is not
/// representable at the asset's precision (no silent rounding of a trade size).
fn decimal_to_scaled(raw: &Value, decimals: u8) -> Result<u128, CommandDenial> {
    if decimals > MAX_DECIMALS {
        return Err(protocol("asset precision is not supported"));
    }
    let text = numeric_text(raw, "amount")?;
    if text.is_empty() {
        return Err(protocol("amount is required"));
    }
    if !text.chars().all(|c| c.is_ascii_digit() || c == '.') || text.matches('.').count() > 1 {
        return Err(protocol("amount must be a plain non-negative decimal"));
    }
    let (int_part, frac_part) = text.split_once('.').unwrap_or((text.as_str(), ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(protocol("amount must be a plain non-negative decimal"));
    }
    let decimals = decimals as usize;
    if frac_part.len() > decimals {
        return Err(protocol(
            "amount has more precision than the asset supports",
        ));
    }
    let mut digits = String::with_capacity(int_part.len() + decimals + 1);
    digits.push_str(if int_part.is_empty() { "0" } else { int_part });
    digits.push_str(frac_part);
    for _ in 0..(decimals - frac_part.len()) {
        digits.push('0');
    }
    let trimmed = digits.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    trimmed
        .parse::<u128>()
        .map_err(|_| protocol("amount is out of range"))
}

/// Build an exact atomic price ratio from a human quote-per-base decimal.
fn decimal_to_atomic_ratio(
    raw: &Value,
    quote_decimals: u8,
    base_decimals: u8,
) -> Result<Value, CommandDenial> {
    if quote_decimals > MAX_DECIMALS || base_decimals > MAX_DECIMALS {
        return Err(protocol("asset precision is not supported"));
    }
    let text = numeric_text(raw, "limit_price")?;
    if text.is_empty()
        || !text.chars().all(|c| c.is_ascii_digit() || c == '.')
        || text.matches('.').count() > 1
    {
        return Err(protocol("limit_price must be a plain positive decimal"));
    }
    let (int_part, frac_part) = text.split_once('.').unwrap_or((text.as_str(), ""));
    let mut digits = String::with_capacity(int_part.len() + frac_part.len() + 1);
    digits.push_str(if int_part.is_empty() { "0" } else { int_part });
    digits.push_str(frac_part);
    let trimmed = digits.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    let price: u128 = trimmed
        .parse()
        .map_err(|_| protocol("limit_price is out of range"))?;
    if price == 0 {
        return Err(protocol("limit_price must be positive"));
    }
    let fractional_scale = frac_part.len() as u32;
    let numerator = price
        .checked_mul(pow10(quote_decimals as u32)?)
        .ok_or_else(|| protocol("limit_price is out of range"))?;
    let denominator = pow10(
        fractional_scale
            .checked_add(base_decimals as u32)
            .ok_or_else(|| protocol("limit_price is out of range"))?,
    )?;
    Ok(json!({
        "numerator_atomic": numerator,
        "denominator_atomic": denominator,
    }))
}

fn pow10(exponent: u32) -> Result<u128, CommandDenial> {
    10u128
        .checked_pow(exponent)
        .ok_or_else(|| protocol("value is out of range"))
}

/// Project the canonical `MarketPreview` into the web `QuotePreview` view.
///
/// Every value is taken from the authenticated preview; a missing value becomes
/// `null` (unknown) rather than a fabricated default. `routerSource` is passed
/// through exactly as the backend reported it, so a silent source substitution
/// is visible to the client and blocked there.
fn project_preview(
    result: &Value,
    market: &MarketIntent,
    quote_id: &str,
    router: &str,
    expires_at_ms: i64,
) -> Result<Value, CommandDenial> {
    let preview = result
        .get("preview")
        .or_else(|| result.get("quote"))
        .filter(|value| value.is_object())
        .ok_or_else(|| indeterminate("Preview backend returned no preview document."))?;

    let quote = preview.get("quote");
    let net_delta = quote.and_then(|quote| quote.get("net_delta"));

    let gross_output = net_delta
        .and_then(|delta| delta.get("gross_output"))
        .and_then(|amount| amount.get("amount"))
        .and_then(atomic_u128)
        .map(|atomic| atomic_to_number(atomic, market.out_decimals))
        .unwrap_or(Value::Null);
    let net_output_atomic = net_delta
        .and_then(|delta| delta.get("net_output"))
        .and_then(|amount| amount.get("amount"))
        .and_then(atomic_u128);
    let net_output = net_output_atomic
        .map(|atomic| atomic_to_number(atomic, market.out_decimals))
        .unwrap_or(Value::Null);
    // A conservative floor: the worst output still allowed under the user's
    // slippage cap. Without a cap the minimum is genuinely unknown (`null`),
    // never the current net output (which the UI would misread as a floor).
    let min_received = match (net_output_atomic, market.max_slippage_bps) {
        (Some(atomic), Some(bps)) => {
            let slippage = atomic.saturating_mul(u128::from(bps)) / 10_000;
            Value::String(atomic_to_decimal(
                atomic.saturating_sub(slippage),
                market.out_decimals,
            ))
        }
        _ => Value::Null,
    };

    let gross_asset = net_delta
        .and_then(|delta| delta.get("gross_output"))
        .and_then(|amount| amount.get("asset"));
    let gross_atomic = net_delta
        .and_then(|delta| delta.get("gross_output"))
        .and_then(|amount| amount.get("amount"))
        .and_then(atomic_u128);
    let tax_bps = proportional_bps(net_delta, "tax_cost", gross_asset, gross_atomic);
    let fee_bps = combine_bps(
        proportional_bps(net_delta, "dex_fee", gross_asset, gross_atomic),
        None,
    );

    let score = preview.get("score");
    let economics = json!({
        "grossOutput": gross_output,
        "netOutput": net_output,
        "taxBps": tax_bps,
        "dexFeeBps": fee_bps,
        "gasUsd": Value::Null,
        "priceImpactBps": score_field(score, "price_impact"),
        "expectedSlippageBps": score_field(score, "expected_slippage"),
        "mevRiskBps": score_field(score, "mev_risk"),
        "failureProbability": score
            .and_then(|score| score.get("failure_probability"))
            .and_then(Value::as_u64)
            .map(|bps| Number::from_f64(bps as f64 / 10_000.0).map(Value::Number).unwrap_or(Value::Null))
            .unwrap_or(Value::Null),
        "minReceived": min_received,
    });

    let route = quote
        .and_then(|quote| quote.get("hop_quotes"))
        .and_then(Value::as_array)
        .map(|hops| {
            let kind = if hops.len() == 1 { "direct" } else { "bridge" };
            Value::Array(
                hops.iter()
                    .enumerate()
                    .map(|(index, hop)| {
                        json!({
                            "index": index,
                            "venue": hop.get("venue").cloned().unwrap_or(Value::Null),
                            "kind": kind,
                            "tokenIn": asset_address(hop.get("token_in")),
                            "tokenOut": asset_address(hop.get("token_out")),
                            "sharePct": 100,
                        })
                    })
                    .collect(),
            )
        })
        .unwrap_or_else(|| Value::Array(Vec::new()));

    let intent = json!({
        "id": quote_id,
        "chain": market.chain,
        "tokenIn": market.token_in,
        "tokenOut": market.token_out,
        "side": market.side,
        "amountType": market.amount_type,
        "amount": market.amount,
        "orderType": "market",
        "limitPrice": Value::Null,
        "maxBuyTaxBps": Value::Null,
        "maxSellTaxBps": Value::Null,
        "maxPriceImpactBps": market.max_price_impact_bps.map(|bps| json!(bps)).unwrap_or(Value::Null),
        "maxSlippageBps": market.max_slippage_bps.map(|bps| json!(bps)).unwrap_or(Value::Null),
        "maxTotalCostUsd": market.max_total_cost_usd,
        "allowPartialFill": false,
        "expiryMs": Value::Null,
    });

    let mut projected = Map::new();
    projected.insert("quoteId".to_string(), Value::String(quote_id.to_string()));
    projected.insert("intent".to_string(), intent);
    projected.insert("route".to_string(), route);
    projected.insert("economics".to_string(), economics);
    projected.insert(
        "slot".to_string(),
        score
            .and_then(|score| score.get("slot"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    projected.insert(
        "sourceAgeMs".to_string(),
        score
            .and_then(|score| score.get("state_age_ms"))
            .and_then(Value::as_u64)
            .map(|age| json!(age))
            .unwrap_or(Value::Null),
    );
    projected.insert("expiresAtMs".to_string(), json!(expires_at_ms));
    // The server revalidates state at execute; the client does not need to
    // re-preview first, so this is `false` and the ticket stays executable.
    projected.insert("revalidationRequired".to_string(), Value::Bool(false));
    projected.insert(
        "routerPreference".to_string(),
        Value::String(router.to_string()),
    );
    projected.insert(
        "routerSource".to_string(),
        preview.get("router_source").cloned().unwrap_or(Value::Null),
    );
    // Keep the canonical preview available for a future Trading Core projection;
    // it is not a substitute for the fields above.
    projected.insert("preview".to_string(), preview.clone());
    Ok(Value::Object(projected))
}

fn score_field(score: Option<&Value>, field: &str) -> Value {
    score
        .and_then(|score| score.get(field))
        .filter(|value| value.is_number())
        .cloned()
        .unwrap_or(Value::Null)
}

/// Express a cost as bps of the gross output. The cost must be denominated in
/// the same asset as the gross output; a cross-asset ratio would be meaningless,
/// so it yields `None` (unknown) rather than a wrong number.
fn proportional_bps(
    net_delta: Option<&Value>,
    field: &str,
    gross_asset: Option<&Value>,
    gross_atomic: Option<u128>,
) -> Option<u16> {
    let gross = gross_atomic?;
    if gross == 0 {
        return None;
    }
    let cost = net_delta?.get(field)?;
    if cost.get("asset") != gross_asset {
        return None;
    }
    let cost_atomic = cost.get("amount").and_then(atomic_u128)?;
    let scaled = (cost_atomic.saturating_mul(10_000).saturating_add(gross / 2)) / gross;
    u16::try_from(scaled).ok().filter(|bps| *bps <= 10_000)
}

fn combine_bps(first: Option<u16>, second: Option<u16>) -> Value {
    match (first, second) {
        (Some(a), Some(b)) => a
            .checked_add(b)
            .map(|sum| json!(sum))
            .unwrap_or(Value::Null),
        (Some(a), None) | (None, Some(a)) => json!(a),
        (None, None) => Value::Null,
    }
}

fn asset_json(chain: &ChainId, address: &str) -> Value {
    json!({
        "chain": chain,
        "address": address,
    })
}

fn asset_address(asset: Option<&Value>) -> Value {
    asset
        .and_then(|asset| asset.get("address"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn atomic_u128(value: &Value) -> Option<u128> {
    if let Some(unsigned) = value.as_u64() {
        return Some(u128::from(unsigned));
    }
    if let Some(text) = value.as_str() {
        return text.parse().ok();
    }
    if value.is_number() {
        return value.to_string().parse().ok();
    }
    None
}

fn atomic_to_number(atomic: u128, decimals: u8) -> Value {
    let scale = 10f64.powi(decimals as i32);
    Number::from_f64(atomic as f64 / scale)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn atomic_to_decimal(atomic: u128, decimals: u8) -> String {
    let digits = atomic.to_string();
    let decimals = decimals as usize;
    if decimals == 0 {
        return digits;
    }
    if digits.len() <= decimals {
        format!("0.{}{}", "0".repeat(decimals - digits.len()), digits)
    } else {
        let split = digits.len() - decimals;
        format!("{}.{}", &digits[..split], &digits[split..])
    }
}

fn random_quote_id() -> Result<String, CommandDenial> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| clock_denial())?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        id.push_str(&format!("{byte:02x}"));
    }
    Ok(id)
}

fn clamp_optional_u16(value: Option<&Value>) -> Result<Option<u16>, CommandDenial> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| protocol("value must be a non-negative integer"))?;
            u16::try_from(raw)
                .map(Some)
                .map_err(|_| protocol("value is out of range"))
        }
    }
}

fn optional_u16(payload: &Value, field: &str) -> Result<Option<u16>, CommandDenial> {
    clamp_optional_u16(payload.get(field))
}

fn required_string(payload: &Value, field: &str) -> Result<String, CommandDenial> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| protocol(format!("{field} is required")))
}

fn required_side(payload: &Value) -> Result<String, CommandDenial> {
    match payload.get("side").and_then(Value::as_str) {
        Some("buy") => Ok("buy".to_string()),
        Some("sell") => Ok("sell".to_string()),
        _ => Err(protocol("side is required and must be buy or sell")),
    }
}

fn required_router(payload: &Value) -> Result<String, CommandDenial> {
    match payload.get("router_preference").and_then(Value::as_str) {
        Some("okx") => Ok("okx".to_string()),
        Some("local") => Ok("local".to_string()),
        _ => Err(protocol(
            "router_preference is required and must be okx or local",
        )),
    }
}

fn protocol(message: impl Into<String>) -> CommandDenial {
    CommandDenial::determinate(DenialCode::Protocol, message)
}

fn indeterminate(message: impl Into<String>) -> CommandDenial {
    CommandDenial::indeterminate(DenialCode::Unknown, message)
}

fn clock_denial() -> CommandDenial {
    CommandDenial::indeterminate(DenialCode::Server, "Server clock is unavailable.")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(i64);

    impl OpaqueClock for FixedClock {
        fn now_ms(&self) -> Option<i64> {
            Some(self.0)
        }
    }

    struct CapturingDispatcher {
        calls: Mutex<Vec<Value>>,
        response: Value,
        deny: Option<CommandDenial>,
    }

    impl CapturingDispatcher {
        fn new(response: Value) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                response,
                deny: None,
            })
        }

        fn last(&self) -> Value {
            self.calls
                .lock()
                .expect("lock")
                .last()
                .cloned()
                .expect("call")
        }

        fn count(&self) -> usize {
            self.calls.lock().expect("lock").len()
        }
    }

    #[async_trait]
    impl CommandDispatcher for CapturingDispatcher {
        async fn dispatch(&self, request: &CommandRequest) -> Result<Value, CommandDenial> {
            self.calls
                .lock()
                .expect("lock")
                .push(request.payload.clone());
            if let Some(deny) = &self.deny {
                return Err(deny.clone());
            }
            Ok(self.response.clone())
        }
    }

    fn registry() -> Arc<dyn InstrumentRegistry> {
        Arc::new(
            StaticInstrumentRegistry::from_slug_entries(vec![
                ("base".to_string(), "USDC".to_string(), ChainId::Base, 6),
                ("base".to_string(), "TOKEN".to_string(), ChainId::Base, 18),
            ])
            .expect("registry"),
        )
    }

    fn dispatcher(inner: Arc<CapturingDispatcher>) -> WebIntegrationDispatcher {
        WebIntegrationDispatcher::new(inner, registry(), Arc::new(FixedClock(1_000)))
    }

    fn preview_result() -> Value {
        let asset = |address: &str| json!({ "chain": { "kind": "base" }, "address": address });
        json!({
            "preview": {
                "quote": {
                    "net_delta": {
                        "token_in": asset("USDC"),
                        "token_out": asset("TOKEN"),
                        "net_input": { "asset": asset("USDC"), "amount": 25_000_000u64 },
                        "gross_output": { "asset": asset("TOKEN"), "amount": 2_000_000_000_000_000_000u64 },
                        "net_output": { "asset": asset("TOKEN"), "amount": 1_900_000_000_000_000_000u64 },
                        "dex_fee": { "asset": asset("USDC"), "amount": 7_500u64 },
                        "tax_cost": null
                    },
                    "gross_output": { "asset": asset("TOKEN"), "amount": 2_000_000_000_000_000_000u64 },
                    "net_output": { "asset": asset("TOKEN"), "amount": 1_900_000_000_000_000_000u64 },
                    "hop_quotes": [{
                        "venue": "uniswap",
                        "pool_ref": "0xpool",
                        "token_in": asset("USDC"),
                        "token_out": asset("TOKEN"),
                        "amount_in": 25_000_000u64,
                        "amount_out": 2_000_000_000_000_000_000u64,
                        "kind": "cpmm",
                        "impact_bps": 30
                    }]
                },
                "score": {
                    "gross_output": { "asset": asset("TOKEN"), "amount": 2_000_000_000_000_000_000u64 },
                    "simulated_net_output": { "asset": asset("TOKEN"), "amount": 1_900_000_000_000_000_000u64 },
                    "tax_cost": null,
                    "dex_fee": { "asset": asset("USDC"), "amount": 7_500u64 },
                    "provider_fee": null,
                    "gas_cost": null,
                    "price_impact": 30,
                    "expected_slippage": 50,
                    "mev_risk": 10,
                    "failure_probability": 100,
                    "state_age_ms": 250,
                    "provider_reliability": 9_000,
                    "latency_ms": 12
                },
                "truncated": false,
                "router_source": "okx"
            }
        })
    }

    fn request(op: &str, payload: Value) -> CommandRequest {
        CommandRequest {
            op: op.to_string(),
            payload,
            request_id: "req-1".to_string(),
            idempotency_key: Some("key-1".to_string()),
        }
    }

    #[test]
    fn usd_amounts_fail_closed_until_the_core_supports_them() {
        let error = amount_spec_for(&json!("25.5"), "usd", 6).expect_err("usd unsupported");
        assert_eq!(error.code, "protocol");
    }

    #[test]
    fn stablecoin_amount_scales_to_lossless_atomics() {
        let spec = amount_spec_for(&json!("25.5"), "stablecoin", 6).expect("spec");
        assert_eq!(spec["unit"], "stablecoin_atomic");
        assert_eq!(spec["value"], 25_500_000u64);
    }

    #[test]
    fn token_amount_uses_authoritative_decimals() {
        let spec = amount_spec_for(&json!("1.5"), "token", 18).expect("spec");
        assert_eq!(spec["unit"], "token_atomic");
        assert_eq!(spec["value"].as_u64().unwrap(), 1_500_000_000_000_000_000);
    }

    #[test]
    fn extra_precision_fails_closed_instead_of_rounding() {
        let error = amount_spec_for(&json!("1.0000001"), "stablecoin", 6).expect_err("precision");
        assert_eq!(error.code, "protocol");
    }

    #[test]
    fn exponent_notation_is_refused() {
        let error = amount_spec_for(&json!("1e3"), "token", 18).expect_err("exponent");
        assert_eq!(error.code, "protocol");
    }

    #[tokio::test]
    async fn unknown_instrument_fails_closed() {
        let inner = CapturingDispatcher::new(json!({}));
        let dispatcher = WebIntegrationDispatcher::new(
            inner.clone(),
            Arc::new(FailClosedInstrumentRegistry),
            Arc::new(FixedClock(1_000)),
        );
        let error = dispatcher
            .dispatch(&request(
                "preview_market_order",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "side": "buy",
                        "amount_type": "usd",
                        "amount": "25"
                    },
                    "router_preference": "okx"
                }),
            ))
            .await
            .expect_err("fail closed");
        assert_eq!(error.code, "capability_missing");
        assert_eq!(inner.count(), 0, "no command reaches the backend");
    }

    #[tokio::test]
    async fn preview_translates_and_projects_the_canonical_document() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        let result = dispatcher
            .dispatch(&request(
                "preview_market_order",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "side": "buy",
                        "amount_type": "stablecoin",
                        "amount": "25.00",
                        "max_slippage_bps": 100,
                        "max_price_impact_bps": 150,
                        "max_total_cost_usd": null
                    },
                    "router_preference": "okx"
                }),
            ))
            .await
            .expect("preview");

        let sent = inner.last();
        assert_eq!(sent["token_in"]["address"], "USDC");
        assert_eq!(sent["token_in"]["chain"]["kind"], "base");
        assert_eq!(sent["token_out"]["address"], "TOKEN");
        assert_eq!(sent["side"], "buy");
        assert_eq!(sent["amount"]["unit"], "stablecoin_atomic");
        assert_eq!(sent["amount"]["value"], 25_000_000u64);
        assert_eq!(sent["max_slippage_bps"], 100);
        assert_eq!(sent["router_preference"], "okx");
        assert!(sent.get("amount_type").is_none(), "web-only field dropped");

        assert_eq!(result["routerSource"], "okx");
        assert_eq!(result["routerPreference"], "okx");
        assert_eq!(result["revalidationRequired"], false);
        assert_eq!(result["sourceAgeMs"], 250);
        assert_eq!(result["intent"]["amount"], "25.00");
        assert_eq!(result["intent"]["chain"], "base");
        assert_eq!(result["intent"]["tokenIn"], "USDC");
        assert_eq!(result["economics"]["priceImpactBps"], 30);
        assert_eq!(result["economics"]["netOutput"], 1.9);
        // A conservative 1% slippage floor, not the current net output.
        assert_eq!(result["economics"]["minReceived"], "1.881000000000000000");
        assert_eq!(result["expiresAtMs"], 121_000);
        assert_eq!(result["route"][0]["venue"], "uniswap");
        assert!(result["quoteId"].as_str().expect("quote id").len() >= 32);
    }

    /// F1: the canonical command vocabulary has no per-order USD total-cost cap,
    /// so a non-null cap is a determinate refusal rather than a silent drop of a
    /// safety control the user believes is enforced.
    #[tokio::test]
    async fn unenforceable_total_cost_cap_is_refused() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        let error = dispatcher
            .dispatch(&request(
                "preview_market_order",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "side": "buy",
                        "amount_type": "stablecoin",
                        "amount": "25.00",
                        "max_total_cost_usd": 1.0
                    },
                    "router_preference": "okx"
                }),
            ))
            .await
            .expect_err("unenforceable cap");
        assert_eq!(error.code, "protocol");
        assert_eq!(inner.count(), 0, "no command reaches the backend");
    }

    #[tokio::test]
    async fn get_quote_translation_omits_side_and_trade_caps() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        dispatcher
            .dispatch(&request(
                "get_quote",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "amount_type": "stablecoin",
                        "amount": "25",
                        "max_slippage_bps": 100
                    },
                    "router_preference": "local"
                }),
            ))
            .await
            .expect("quote");
        let sent = inner.last();
        assert!(sent.get("side").is_none(), "get_quote has no side");
        assert!(sent.get("max_slippage_bps").is_none(), "read has no caps");
        assert_eq!(sent["amount"]["unit"], "stablecoin_atomic");
        assert_eq!(sent["router_preference"], "local");
    }

    #[tokio::test]
    async fn preview_without_a_side_fails_closed() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        let error = dispatcher
            .dispatch(&request(
                "preview_market_order",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "amount_type": "stablecoin",
                        "amount": "25"
                    },
                    "router_preference": "okx"
                }),
            ))
            .await
            .expect_err("side required");
        assert_eq!(error.code, "protocol");
        assert_eq!(inner.count(), 0);
    }

    #[tokio::test]
    async fn execute_resolves_the_quoted_intent_and_binds_the_source() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        let preview = dispatcher
            .dispatch(&request(
                "preview_market_order",
                json!({
                    "intent": {
                        "chain": "base",
                        "token_in": "USDC",
                        "token_out": "TOKEN",
                        "side": "buy",
                        "amount_type": "stablecoin",
                        "amount": "25"
                    },
                    "router_preference": "okx"
                }),
            ))
            .await
            .expect("preview");
        let quote_id = preview["quoteId"].as_str().expect("quote id").to_string();

        // A different router must not be able to execute the OKX quote.
        let mismatch = dispatcher
            .dispatch(&request(
                "execute_market_order",
                json!({ "quote_id": quote_id, "router_preference": "local" }),
            ))
            .await
            .expect_err("source mismatch");
        assert_eq!(mismatch.code, "protocol");

        let result = dispatcher
            .dispatch(&request(
                "execute_market_order",
                json!({ "quote_id": quote_id, "router_preference": "okx" }),
            ))
            .await
            .expect("execute");
        assert!(result.is_object());
        let sent = inner.last();
        assert_eq!(sent["amount"]["value"], 25_000_000u64);
        assert_eq!(sent["router_preference"], "okx");
        assert!(sent.get("quote_id").is_none());
    }

    #[tokio::test]
    async fn execute_with_an_unknown_quote_fails_closed() {
        let inner = CapturingDispatcher::new(json!({}));
        let dispatcher = dispatcher(inner.clone());
        let error = dispatcher
            .dispatch(&request(
                "execute_market_order",
                json!({ "quote_id": "deadbeef", "router_preference": "okx" }),
            ))
            .await
            .expect_err("unknown quote");
        assert_eq!(error.code, "protocol");
        assert_eq!(inner.count(), 0);
    }

    #[tokio::test]
    async fn place_limit_translates_the_atomic_price_ratio() {
        let inner = CapturingDispatcher::new(json!({ "order_id": "ord-1" }));
        let dispatcher = dispatcher(inner.clone());
        dispatcher
            .dispatch(&request(
                "place_limit_order",
                json!({
                    "chain": "base",
                    "token_in": "USDC",
                    "token_out": "TOKEN",
                    "side": "buy",
                    "order_type": "limit",
                    "amount_type": "stablecoin",
                    "amount": 25,
                    "limit_price": 0.5,
                    "max_slippage_bps": 100,
                    "allow_partial_fill": true,
                    "expiry_ms": 9_999_999_999_999i64
                }),
            ))
            .await
            .expect("limit order");
        let sent = inner.last();
        assert_eq!(sent["amount"]["value"], 25_000_000u64);
        // 0.5 quote (6dp) per base (18dp) => 0.5 * 10^(6-18) = 5e6 / 10^19
        assert_eq!(sent["limit_price"]["numerator_atomic"], 5_000_000u64);
        assert_eq!(
            sent["limit_price"]["denominator_atomic"],
            10_000_000_000_000_000_000u64
        );
        assert_eq!(sent["allow_partial_fill"], true);
        assert_eq!(sent["expires_at_ms"], 9_999_999_999_999i64);
    }

    #[tokio::test]
    async fn place_limit_sell_orients_the_ratio_to_quote_per_base() {
        let inner = CapturingDispatcher::new(json!({ "order_id": "ord-1" }));
        let dispatcher = dispatcher(inner.clone());
        dispatcher
            .dispatch(&request(
                "place_limit_order",
                json!({
                    "chain": "base",
                    "token_in": "TOKEN",
                    "token_out": "USDC",
                    "side": "sell",
                    "order_type": "limit",
                    "amount_type": "token",
                    "amount": 2,
                    "limit_price": 0.5,
                    "allow_partial_fill": true,
                    "expiry_ms": 9_999_999_999_999i64
                }),
            ))
            .await
            .expect("sell limit order");
        let sent = inner.last();
        // Sell amount is the input leg (TOKEN, 18dp).
        assert_eq!(
            sent["amount"]["value"].as_u64().unwrap(),
            2_000_000_000_000_000_000
        );
        // quote = token_out (USDC, 6dp), base = token_in (TOKEN, 18dp).
        assert_eq!(sent["limit_price"]["numerator_atomic"], 5_000_000u64);
        assert_eq!(
            sent["limit_price"]["denominator_atomic"],
            10_000_000_000_000_000_000u64
        );
    }

    #[tokio::test]
    async fn quotes_are_isolated_between_sessions() {
        let inner = CapturingDispatcher::new(preview_result());
        let dispatcher = dispatcher(inner.clone());
        let preview = dispatcher
            .dispatch_for_session(
                b"kid-a",
                &request(
                    "preview_market_order",
                    json!({
                        "intent": {
                            "chain": "base",
                            "token_in": "USDC",
                            "token_out": "TOKEN",
                            "side": "buy",
                            "amount_type": "stablecoin",
                            "amount": "25"
                        },
                        "router_preference": "okx"
                    }),
                ),
            )
            .await
            .expect("preview");
        let quote_id = preview["quoteId"].as_str().expect("quote id").to_string();

        // Session B cannot execute session A's quote.
        let error = dispatcher
            .dispatch_for_session(
                b"kid-b",
                &request(
                    "execute_market_order",
                    json!({ "quote_id": quote_id, "router_preference": "okx" }),
                ),
            )
            .await
            .expect_err("isolated");
        assert_eq!(error.code, "protocol");

        dispatcher
            .dispatch_for_session(
                b"kid-a",
                &request(
                    "execute_market_order",
                    json!({ "quote_id": quote_id, "router_preference": "okx" }),
                ),
            )
            .await
            .expect("owner executes");
    }

    #[tokio::test]
    async fn get_token_translates_the_chain_slug_to_a_canonical_asset() {
        let inner = CapturingDispatcher::new(json!({ "symbol": "USDC" }));
        let dispatcher = dispatcher(inner.clone());
        dispatcher
            .dispatch(&request(
                "get_token",
                json!({ "chain": "base", "address": "USDC" }),
            ))
            .await
            .expect("token");
        let sent = inner.last();
        assert_eq!(sent["token"]["chain"]["kind"], "base");
        assert_eq!(sent["token"]["address"], "USDC");
    }

    #[tokio::test]
    async fn token_reads_work_for_a_token_not_in_the_registry() {
        let inner = CapturingDispatcher::new(json!({ "symbol": "NEW" }));
        let dispatcher = dispatcher(inner.clone());
        // Only the chain must be known; the read is how the reader learns about
        // an arbitrary token, so no decimal metadata is required.
        dispatcher
            .dispatch(&request(
                "get_token",
                json!({ "chain": "base", "address": "NOT_REGISTERED" }),
            ))
            .await
            .expect("token read");
        let sent = inner.last();
        assert_eq!(sent["token"]["chain"]["kind"], "base");
        assert_eq!(sent["token"]["address"], "NOT_REGISTERED");
    }

    #[test]
    fn quote_store_expires_and_is_pruned() {
        let store = QuoteStore::new(1_000);
        store
            .insert(b"kid", "q1", json!({}), "okx".to_string(), 1_000)
            .expect("insert");
        assert!(store.get(b"kid", "q1", 1_500).is_some());
        assert!(store.get(b"kid", "q1", 2_001).is_none());
        assert!(store.get(b"other", "q1", 1_500).is_none());
    }

    #[test]
    fn quote_store_evicts_per_session_instead_of_starving_others() {
        let store = QuoteStore::with_limits(10_000, 10_000, 2);
        store
            .insert(b"a", "a1", json!({}), "okx".to_string(), 1_000)
            .expect("a1");
        store
            .insert(b"a", "a2", json!({}), "okx".to_string(), 1_000)
            .expect("a2");
        store
            .insert(b"b", "b1", json!({}), "okx".to_string(), 1_000)
            .expect("b1");
        // Session A is at its per-session cap: only A's oldest quote is evicted.
        store
            .insert(b"a", "a3", json!({}), "okx".to_string(), 1_000)
            .expect("a3");
        assert!(store.get(b"a", "a1", 1_000).is_none());
        assert!(store.get(b"a", "a2", 1_000).is_some());
        assert!(store.get(b"a", "a3", 1_000).is_some());
        assert!(
            store.get(b"b", "b1", 1_000).is_some(),
            "another session is never starved"
        );
    }

    #[test]
    fn quote_store_global_backstop_evicts_the_oldest() {
        let store = QuoteStore::with_limits(10_000, 2, 10);
        store
            .insert(b"a", "a1", json!({}), "okx".to_string(), 1_000)
            .expect("a1");
        store
            .insert(b"b", "b1", json!({}), "okx".to_string(), 1_000)
            .expect("b1");
        store
            .insert(b"c", "c1", json!({}), "okx".to_string(), 1_000)
            .expect("c1");
        assert_eq!(store.lock().len(), 2);
        assert!(
            store.get(b"a", "a1", 1_000).is_none(),
            "the globally oldest quote is evicted"
        );
        assert!(store.get(b"b", "b1", 1_000).is_some());
        assert!(store.get(b"c", "c1", 1_000).is_some());
    }

    #[test]
    fn oversized_json_float_is_refused_for_exactness() {
        let raw: Value = serde_json::from_str("9007199254740993.1").expect("number");
        let error = amount_spec_for(&raw, "token", 18).expect_err("precision");
        assert_eq!(error.code, "protocol");
    }

    #[test]
    fn proportional_bps_saturates_instead_of_panicking() {
        let asset = json!({ "kind": "base" });
        // The largest value a default `serde_json::Value` can carry is u64::MAX;
        // the conversion must still saturate, not overflow or panic.
        let delta = json!({
            "gross_output": { "asset": asset.clone(), "amount": u64::MAX },
            "tax_cost": { "asset": asset, "amount": u64::MAX },
        });
        let gross_asset = delta
            .get("gross_output")
            .and_then(|entry| entry.get("asset"));
        assert!(proportional_bps(Some(&delta), "tax_cost", gross_asset, Some(2)).is_none());
    }

    #[test]
    fn static_registry_rejects_invalid_entries() {
        let bad = StaticInstrumentRegistry::from_slug_entries(vec![(
            "base".to_string(),
            "TOKEN".to_string(),
            ChainId::Base,
            40,
        )]);
        assert!(bad.is_err());
    }
}
