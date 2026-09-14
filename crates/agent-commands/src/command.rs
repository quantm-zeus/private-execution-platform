//! Structured, channel-agnostic agent command vocabulary.
//!
//! The transport (MCP server or Telegram bot) hands in an already-structured
//! JSON command. There is no natural-language parsing here: ambiguity fails
//! closed and a bare amount without an explicit unit is rejected.
//!
//! ## Lossless decoding note
//!
//! Serde's derive for internally/adjacently tagged enums buffers values through
//! its private `Content` type, which cannot represent `u128`/`i128`. Because
//! [`AmountSpec`] and [`LimitPriceSpec`] carry `u128` atomics, the command
//! enums implement [`Deserialize`] manually over
//! [`serde_json::value::RawValue`] field captures, then decode each field from
//! its exact raw JSON. This keeps atomic amounts lossless.
//!
//! ## Redaction note
//!
//! Every type carrying a semantic payload implements a hand-written,
//! payload-free [`Debug`](fmt::Debug). Public [`Deserialize`] impls first capture
//! the whole input as a [`RawValue`] and then run the strict parser, so a direct
//! `serde_json::from_str` failure cannot echo raw request values. The object
//! decoders also reject duplicate keys, so an ambiguous command fails closed
//! instead of silently keeping the last value.

use std::collections::{btree_map::Entry, BTreeMap};
use std::fmt;

use chain_types::ChainId;
use domain::TradeSide;
use market_types::PriceRatio;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

use crate::AgentCommandError;

/// Maximum accepted asset address length.
///
/// Generous enough for Solana base58 and EVM hex addresses while rejecting
/// pathological payloads before they reach the rest of the system.
pub const MAX_ASSET_ADDRESS_LEN: usize = 128;

/// Raw, lossless capture of a JSON object's fields.
type RawFields = BTreeMap<String, Box<RawValue>>;

/// Lossless JSON object capture that fails closed on duplicate keys.
///
/// Serde's ordinary map decoders silently keep the last value for a repeated
/// key. Ambiguity must fail closed here, so the visitor rejects a repeated key
/// instead of letting the later value win.
struct RawObject(RawFields);

impl RawObject {
    fn into_map(self) -> RawFields {
        self.0
    }
}

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawObjectVisitor;

        impl<'de> Visitor<'de> for RawObjectVisitor {
            type Value = RawObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut fields = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    match fields.entry(key) {
                        Entry::Vacant(entry) => {
                            entry.insert(map.next_value::<Box<RawValue>>()?);
                        }
                        Entry::Occupied(_) => {
                            // The repeated key is never echoed.
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                    }
                }
                Ok(RawObject(fields))
            }
        }

        deserializer.deserialize_map(RawObjectVisitor)
    }
}

/// Channel that submitted a command. Both channels share the same restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentChannel {
    Mcp,
    Telegram,
}

/// Explicit amount unit. A bare number is NOT accepted anywhere.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "unit", content = "value")]
pub enum AmountSpec {
    /// Token base units (atomic).
    TokenAtomic(u128),
    /// Stablecoin base units (atomic).
    StablecoinAtomic(u128),
    /// USD micros.
    UsdMicros(u64),
}

impl fmt::Debug for AmountSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: the atomic/micro value is never rendered.
        match self {
            Self::TokenAtomic(_) => f.write_str("AmountSpec::TokenAtomic(..)"),
            Self::StablecoinAtomic(_) => f.write_str("AmountSpec::StablecoinAtomic(..)"),
            Self::UsdMicros(_) => f.write_str("AmountSpec::UsdMicros(..)"),
        }
    }
}

impl<'de> Deserialize<'de> for AmountSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        amount_from_raw_str(raw.get()).map_err(|_| serde::de::Error::custom("invalid amount"))
    }
}

impl AmountSpec {
    /// True when the explicit amount is zero.
    pub fn is_zero(&self) -> bool {
        match self {
            Self::TokenAtomic(value) | Self::StablecoinAtomic(value) => *value == 0,
            Self::UsdMicros(value) => *value == 0,
        }
    }
}

/// Routing source preference for a market quote/preview/execute.
///
/// The default is [`RouterSource::Okx`]: an omitted `router` field resolves to
/// OKX. A caller that wants the PEP local router must select
/// [`RouterSource::Local`] explicitly, so an OKX outage can never silently fall
/// back to Local.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterSource {
    /// OKX Swap provider route (default).
    #[default]
    Okx,
    /// PEP local router.
    Local,
}

impl RouterSource {
    /// The stable wire label (`"okx"` / `"local"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Okx => "okx",
            Self::Local => "local",
        }
    }
}

/// Closed set of supported chart windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChartWindow {
    M5,
    M15,
    H1,
    H4,
    D1,
}

/// Chain-qualified token reference handed in by a transport.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AssetRef {
    pub chain: ChainId,
    pub address: String,
}

impl fmt::Debug for AssetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: chain and address are never rendered.
        f.write_str("AssetRef { .. }")
    }
}

impl<'de> Deserialize<'de> for AssetRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        asset_from_raw_str(raw.get())
            .map_err(|_| serde::de::Error::custom("invalid asset reference"))
    }
}

impl AssetRef {
    /// Builds a validated asset reference.
    pub fn new(chain: ChainId, address: impl Into<String>) -> Result<Self, AgentCommandError> {
        let asset = Self {
            chain,
            address: address.into(),
        };
        asset.validate()?;
        Ok(asset)
    }

    /// Rejects empty, whitespace-containing, or oversized references.
    pub fn validate(&self) -> Result<(), AgentCommandError> {
        if self.address.trim().is_empty() || self.address.len() > MAX_ASSET_ADDRESS_LEN {
            return Err(AgentCommandError::InvalidAsset);
        }
        if self.address.chars().any(char::is_whitespace) {
            return Err(AgentCommandError::InvalidAsset);
        }
        self.chain
            .validate()
            .map_err(|_| AgentCommandError::InvalidAsset)
    }

    /// Converts to the canonical `chain_types::AssetId`, revalidating first.
    pub fn to_asset_id(&self) -> Result<chain_types::AssetId, AgentCommandError> {
        self.validate()?;
        chain_types::AssetId::new(self.chain.clone(), self.address.clone())
            .map_err(|_| AgentCommandError::InvalidAsset)
    }
}

/// Explicit atomic limit price for a limit order.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LimitPriceSpec {
    pub numerator_atomic: u128,
    pub denominator_atomic: u128,
}

impl fmt::Debug for LimitPriceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: the atomic price sides are never rendered.
        f.write_str("LimitPriceSpec { .. }")
    }
}

impl<'de> Deserialize<'de> for LimitPriceSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        limit_price_from_raw_str(raw.get())
            .map_err(|_| serde::de::Error::custom("invalid limit price"))
    }
}

impl LimitPriceSpec {
    /// Builds a checked limit price; both sides must be non-zero.
    pub fn new(
        numerator_atomic: u128,
        denominator_atomic: u128,
    ) -> Result<Self, AgentCommandError> {
        let spec = Self {
            numerator_atomic,
            denominator_atomic,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Reuses the canonical [`PriceRatio`] construction rules.
    pub fn validate(&self) -> Result<(), AgentCommandError> {
        self.to_price_ratio().map(|_| ())
    }

    /// Converts to the canonical checked [`PriceRatio`].
    pub fn to_price_ratio(&self) -> Result<PriceRatio, AgentCommandError> {
        PriceRatio::new(self.numerator_atomic, self.denominator_atomic)
            .map_err(|_| AgentCommandError::InvalidLimitPrice)
    }
}

/// Read-only commands (allowed while trading is disabled).
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "tool")]
pub enum ReadCommand {
    SearchToken {
        query: String,
    },
    GetToken {
        token: AssetRef,
    },
    GetChart {
        token: AssetRef,
        window: ChartWindow,
    },
    GetIntelligence {
        token: AssetRef,
    },
    GetQuote {
        token_in: AssetRef,
        token_out: AssetRef,
        amount: AmountSpec,
        /// Routing source preference; omitted resolves to [`RouterSource::Okx`].
        router: RouterSource,
    },
    GetOrders {
        status: Option<String>,
    },
    GetPortfolio,
}

impl fmt::Debug for ReadCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: only the variant name and non-semantic shape are shown.
        let name = match self {
            Self::SearchToken { .. } => "ReadCommand::SearchToken { .. }",
            Self::GetToken { .. } => "ReadCommand::GetToken { .. }",
            Self::GetChart { .. } => "ReadCommand::GetChart { .. }",
            Self::GetIntelligence { .. } => "ReadCommand::GetIntelligence { .. }",
            Self::GetQuote { .. } => "ReadCommand::GetQuote { .. }",
            Self::GetOrders { .. } => "ReadCommand::GetOrders { .. }",
            Self::GetPortfolio => "ReadCommand::GetPortfolio",
        };
        f.write_str(name)
    }
}

/// Mutating commands. All require an enabled trading gate and an explicit amount unit.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "tool")]
pub enum TradeCommand {
    PreviewMarketOrder {
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        /// Routing source preference; omitted resolves to [`RouterSource::Okx`].
        router: RouterSource,
    },
    ExecuteMarketOrder {
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
        /// Routing source preference; omitted resolves to [`RouterSource::Okx`].
        router: RouterSource,
    },
    PlaceLimitOrder {
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        limit_price: LimitPriceSpec,
        allow_partial_fill: bool,
        expires_at_ms: i64,
    },
    CancelOrder {
        order_id: String,
    },
}

impl fmt::Debug for TradeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: only the variant name and non-semantic shape are shown.
        let name = match self {
            Self::PreviewMarketOrder { .. } => "TradeCommand::PreviewMarketOrder { .. }",
            Self::ExecuteMarketOrder { .. } => "TradeCommand::ExecuteMarketOrder { .. }",
            Self::PlaceLimitOrder { .. } => "TradeCommand::PlaceLimitOrder { .. }",
            Self::CancelOrder { .. } => "TradeCommand::CancelOrder { .. }",
        };
        f.write_str(name)
    }
}

impl TradeCommand {
    /// A command is mutating iff it can change funds/orders.
    ///
    /// `PreviewMarketOrder` produces a simulation only and moves no funds, so it
    /// is read-only for authorization purposes.
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Self::PreviewMarketOrder { .. })
    }

    pub(crate) fn chains(&self) -> Vec<&ChainId> {
        match self {
            Self::PreviewMarketOrder {
                token_in,
                token_out,
                ..
            }
            | Self::ExecuteMarketOrder {
                token_in,
                token_out,
                ..
            }
            | Self::PlaceLimitOrder {
                token_in,
                token_out,
                ..
            } => vec![&token_in.chain, &token_out.chain],
            Self::CancelOrder { .. } => Vec::new(),
        }
    }
}

/// A structured command from either channel.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum AgentCommand {
    Read(ReadCommand),
    Trade(TradeCommand),
}

impl fmt::Debug for AgentCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: the nested command is never rendered.
        match self {
            Self::Read(_) => f.write_str("AgentCommand::Read(..)"),
            Self::Trade(_) => f.write_str("AgentCommand::Trade(..)"),
        }
    }
}

const READ_TOOL_NAMES: &[&str] = &[
    "search_token",
    "get_token",
    "get_chart",
    "get_intelligence",
    "get_quote",
    "get_orders",
    "get_portfolio",
];

const TRADE_TOOL_NAMES: &[&str] = &[
    "preview_market_order",
    "execute_market_order",
    "place_limit_order",
    "cancel_order",
];

/// Operation names that must never be representable, even by accident.
///
/// The public enum has no matching variant; `parse` turns any of these (and any
/// other unrecognized name) into [`AgentCommandError::ForbiddenOperation`].
const FORBIDDEN_TOOL_NAMES: &[&str] = &[
    "withdraw",
    "withdraw_all",
    "transfer",
    "transfer_token",
    "send",
    "set_owner",
    "set_wallet_owner",
    "change_owner",
    "raise_limit",
    "raise_security_limit",
    "set_limit",
    "sign",
    "sign_raw",
    "sign_transaction",
    "sign_message",
    "export_key",
    "export_private_key",
    "get_private_key",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeclaredKind {
    Read,
    Trade,
}

impl AgentCommand {
    /// A command is mutating iff it can change funds/orders.
    pub fn is_mutating(&self) -> bool {
        match self {
            Self::Read(_) => false,
            Self::Trade(command) => command.is_mutating(),
        }
    }

    /// Strictly decodes a structured command.
    ///
    /// Accepted JSON is tool-tagged, for example:
    ///
    /// ```json
    /// {"tool":"get_portfolio"}
    /// {"tool":"execute_market_order","token_in":{...},"token_out":{...},
    ///  "side":"buy","amount":{"unit":"usd_micros","value":1000000}}
    /// ```
    ///
    /// The optional outer `command` tag emitted by serialization (`"read"` /
    /// `"trade"`) is accepted only when consistent with the tool name. Unknown
    /// fields, a missing amount unit, a bare amount, duplicate keys, and
    /// malformed assets, windows, or limit prices all fail closed. Any tool name
    /// outside the closed read/trade vocabulary returns
    /// [`AgentCommandError::ForbiddenOperation`], never a generic parse error,
    /// so a withdraw/transfer/ownership/limit-raising/signing attempt cannot be
    /// smuggled through.
    pub fn parse(json: &str) -> Result<Self, AgentCommandError> {
        let fields = parse_raw_object(json)?;
        Self::from_fields(fields)
    }

    fn from_fields(fields: RawFields) -> Result<Self, AgentCommandError> {
        let tool = tool_name(&fields)?;
        if is_forbidden_tool(&tool) {
            return Err(AgentCommandError::ForbiddenOperation);
        }

        let declared = declared_kind(&fields)?;
        if READ_TOOL_NAMES.contains(&tool.as_str()) {
            if declared == Some(DeclaredKind::Trade) {
                return Err(AgentCommandError::Malformed);
            }
            Ok(Self::Read(build_read(&tool, &fields)?))
        } else if TRADE_TOOL_NAMES.contains(&tool.as_str()) {
            if declared == Some(DeclaredKind::Read) {
                return Err(AgentCommandError::Malformed);
            }
            Ok(Self::Trade(build_trade(&tool, &fields)?))
        } else {
            // Unknown mutating names are forbidden, not merely unknown.
            Err(AgentCommandError::ForbiddenOperation)
        }
    }
}

/// Strictly decodes a read command from raw JSON.
fn read_from_raw(json: &str) -> Result<ReadCommand, AgentCommandError> {
    let fields = parse_raw_object(json)?;
    let tool = tool_name(&fields)?;
    if !READ_TOOL_NAMES.contains(&tool.as_str()) {
        return Err(AgentCommandError::ForbiddenOperation);
    }
    build_read(&tool, &fields)
}

/// Strictly decodes a trade command from raw JSON.
fn trade_from_raw(json: &str) -> Result<TradeCommand, AgentCommandError> {
    let fields = parse_raw_object(json)?;
    let tool = tool_name(&fields)?;
    if !TRADE_TOOL_NAMES.contains(&tool.as_str()) {
        return Err(AgentCommandError::ForbiddenOperation);
    }
    build_trade(&tool, &fields)
}

impl<'de> Deserialize<'de> for AgentCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Capture the whole input first: `RawValue` accepts any JSON value, so
        // its own errors can never echo a value-bearing type mismatch.
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        Self::parse(raw.get()).map_err(|_| serde::de::Error::custom("invalid agent command"))
    }
}

impl<'de> Deserialize<'de> for ReadCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        read_from_raw(raw.get()).map_err(|_| serde::de::Error::custom("invalid read command"))
    }
}

impl<'de> Deserialize<'de> for TradeCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        trade_from_raw(raw.get()).map_err(|_| serde::de::Error::custom("invalid trade command"))
    }
}

fn parse_raw_object(json: &str) -> Result<RawFields, AgentCommandError> {
    serde_json::from_str::<RawObject>(json)
        .map(RawObject::into_map)
        .map_err(|_| AgentCommandError::Malformed)
}

fn tool_name(fields: &RawFields) -> Result<String, AgentCommandError> {
    let raw = fields.get("tool").ok_or(AgentCommandError::Malformed)?;
    serde_json::from_str::<String>(raw.get()).map_err(|_| AgentCommandError::Malformed)
}

fn declared_kind(fields: &RawFields) -> Result<Option<DeclaredKind>, AgentCommandError> {
    match fields.get("command") {
        None => Ok(None),
        Some(raw) => match serde_json::from_str::<String>(raw.get()).as_deref() {
            Ok("read") => Ok(Some(DeclaredKind::Read)),
            Ok("trade") => Ok(Some(DeclaredKind::Trade)),
            _ => Err(AgentCommandError::Malformed),
        },
    }
}

fn is_forbidden_tool(tool: &str) -> bool {
    FORBIDDEN_TOOL_NAMES.contains(&tool)
}

fn build_read(tool: &str, fields: &RawFields) -> Result<ReadCommand, AgentCommandError> {
    match tool {
        "search_token" => {
            reject_unknown_keys(fields, &["tool", "command", "query"])?;
            Ok(ReadCommand::SearchToken {
                query: field_string(fields, "query")?,
            })
        }
        "get_token" => {
            reject_unknown_keys(fields, &["tool", "command", "token"])?;
            Ok(ReadCommand::GetToken {
                token: field_asset(fields, "token")?,
            })
        }
        "get_chart" => {
            reject_unknown_keys(fields, &["tool", "command", "token", "window"])?;
            Ok(ReadCommand::GetChart {
                token: field_asset(fields, "token")?,
                window: field_window(fields)?,
            })
        }
        "get_intelligence" => {
            reject_unknown_keys(fields, &["tool", "command", "token"])?;
            Ok(ReadCommand::GetIntelligence {
                token: field_asset(fields, "token")?,
            })
        }
        "get_quote" => {
            reject_unknown_keys(
                fields,
                &[
                    "tool",
                    "command",
                    "token_in",
                    "token_out",
                    "amount",
                    "router",
                ],
            )?;
            Ok(ReadCommand::GetQuote {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                amount: field_amount(fields)?,
                router: field_router(fields)?,
            })
        }
        "get_orders" => {
            reject_unknown_keys(fields, &["tool", "command", "status"])?;
            Ok(ReadCommand::GetOrders {
                status: field_optional_string(fields, "status")?,
            })
        }
        "get_portfolio" => {
            reject_unknown_keys(fields, &["tool", "command"])?;
            Ok(ReadCommand::GetPortfolio)
        }
        _ => Err(AgentCommandError::ForbiddenOperation),
    }
}

fn build_trade(tool: &str, fields: &RawFields) -> Result<TradeCommand, AgentCommandError> {
    match tool {
        "preview_market_order" => {
            reject_unknown_keys(
                fields,
                &[
                    "tool",
                    "command",
                    "token_in",
                    "token_out",
                    "side",
                    "amount",
                    "max_slippage_bps",
                    "max_price_impact_bps",
                    "router",
                ],
            )?;
            Ok(TradeCommand::PreviewMarketOrder {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                side: field_side(fields)?,
                amount: field_amount(fields)?,
                max_slippage_bps: field_optional_u16(fields, "max_slippage_bps")?,
                max_price_impact_bps: field_optional_u16(fields, "max_price_impact_bps")?,
                router: field_router(fields)?,
            })
        }
        "execute_market_order" => {
            reject_unknown_keys(
                fields,
                &[
                    "tool",
                    "command",
                    "token_in",
                    "token_out",
                    "side",
                    "amount",
                    "max_slippage_bps",
                    "max_price_impact_bps",
                    "router",
                ],
            )?;
            Ok(TradeCommand::ExecuteMarketOrder {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                side: field_side(fields)?,
                amount: field_amount(fields)?,
                max_slippage_bps: field_optional_u16(fields, "max_slippage_bps")?,
                max_price_impact_bps: field_optional_u16(fields, "max_price_impact_bps")?,
                router: field_router(fields)?,
            })
        }
        "place_limit_order" => {
            reject_unknown_keys(
                fields,
                &[
                    "tool",
                    "command",
                    "token_in",
                    "token_out",
                    "side",
                    "amount",
                    "limit_price",
                    "allow_partial_fill",
                    "expires_at_ms",
                ],
            )?;
            Ok(TradeCommand::PlaceLimitOrder {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                side: field_side(fields)?,
                amount: field_amount(fields)?,
                limit_price: field_limit_price(fields)?,
                allow_partial_fill: field_bool(fields, "allow_partial_fill")?,
                expires_at_ms: field_i64(fields, "expires_at_ms")?,
            })
        }
        "cancel_order" => {
            reject_unknown_keys(fields, &["tool", "command", "order_id"])?;
            Ok(TradeCommand::CancelOrder {
                order_id: field_nonempty_string(fields, "order_id")?,
            })
        }
        _ => Err(AgentCommandError::ForbiddenOperation),
    }
}

fn reject_unknown_keys(fields: &RawFields, allowed: &[&str]) -> Result<(), AgentCommandError> {
    if fields.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        // Unknown fields fail closed; the offending name is never echoed.
        Err(AgentCommandError::Malformed)
    }
}

fn raw_field<'a>(fields: &'a RawFields, name: &str) -> Result<&'a RawValue, AgentCommandError> {
    fields
        .get(name)
        .map(|boxed| boxed.as_ref())
        .ok_or(AgentCommandError::Malformed)
}

fn field_string(fields: &RawFields, name: &str) -> Result<String, AgentCommandError> {
    let raw = raw_field(fields, name)?;
    serde_json::from_str::<String>(raw.get()).map_err(|_| AgentCommandError::Malformed)
}

fn field_nonempty_string(fields: &RawFields, name: &str) -> Result<String, AgentCommandError> {
    let value = field_string(fields, name)?;
    if value.trim().is_empty() {
        return Err(AgentCommandError::Malformed);
    }
    Ok(value)
}

fn field_optional_string(
    fields: &RawFields,
    name: &str,
) -> Result<Option<String>, AgentCommandError> {
    match fields.get(name) {
        None => Ok(None),
        Some(raw) => serde_json::from_str::<Option<String>>(raw.get())
            .map_err(|_| AgentCommandError::Malformed),
    }
}

fn field_optional_u16(fields: &RawFields, name: &str) -> Result<Option<u16>, AgentCommandError> {
    match fields.get(name) {
        None => Ok(None),
        Some(raw) => {
            serde_json::from_str::<Option<u16>>(raw.get()).map_err(|_| AgentCommandError::Malformed)
        }
    }
}

/// Decodes the optional `router` preference; an omitted field defaults to OKX.
///
/// Only the exact `"okx"` and `"local"` spellings are accepted, so an unknown or
/// malformed selector fails closed instead of resolving to a default.
fn field_router(fields: &RawFields) -> Result<RouterSource, AgentCommandError> {
    match fields.get("router") {
        None => Ok(RouterSource::default()),
        Some(raw) => serde_json::from_str::<RouterSource>(raw.get())
            .map_err(|_| AgentCommandError::Malformed),
    }
}

fn field_bool(fields: &RawFields, name: &str) -> Result<bool, AgentCommandError> {
    let raw = raw_field(fields, name)?;
    serde_json::from_str::<bool>(raw.get()).map_err(|_| AgentCommandError::Malformed)
}

fn field_i64(fields: &RawFields, name: &str) -> Result<i64, AgentCommandError> {
    let raw = raw_field(fields, name)?;
    serde_json::from_str::<i64>(raw.get()).map_err(|_| AgentCommandError::Malformed)
}

fn field_asset(fields: &RawFields, name: &str) -> Result<AssetRef, AgentCommandError> {
    let raw = fields.get(name).ok_or(AgentCommandError::InvalidAsset)?;
    asset_from_raw_str(raw.get())
}

fn field_window(fields: &RawFields) -> Result<ChartWindow, AgentCommandError> {
    let raw = fields
        .get("window")
        .ok_or(AgentCommandError::InvalidWindow)?;
    serde_json::from_str::<ChartWindow>(raw.get()).map_err(|_| AgentCommandError::InvalidWindow)
}

fn field_side(fields: &RawFields) -> Result<TradeSide, AgentCommandError> {
    let raw = fields.get("side").ok_or(AgentCommandError::Malformed)?;
    serde_json::from_str::<TradeSide>(raw.get()).map_err(|_| AgentCommandError::Malformed)
}

fn field_amount(fields: &RawFields) -> Result<AmountSpec, AgentCommandError> {
    let raw = fields.get("amount").ok_or(AgentCommandError::Malformed)?;
    // A bare number or non-object amount fails to decode as a field map here.
    amount_from_raw_str(raw.get())
}

/// Decodes an amount from losslessly-captured `unit`/`value` members.
///
/// The capture rejects duplicate keys and any member other than `unit`/`value`.
/// Member order is irrelevant: the `value` is decoded directly from its exact
/// raw JSON using the unit's width, so `u128` atomics stay lossless.
fn amount_from_raw_str(json: &str) -> Result<AmountSpec, AgentCommandError> {
    let fields = parse_raw_object(json)?;
    amount_from_raw_fields(&fields)
}

fn amount_from_raw_fields(
    fields: &BTreeMap<String, Box<RawValue>>,
) -> Result<AmountSpec, AgentCommandError> {
    for key in fields.keys() {
        if key != "unit" && key != "value" {
            return Err(AgentCommandError::Malformed);
        }
    }

    let unit_raw = fields.get("unit").ok_or(AgentCommandError::MissingUnit)?;
    let unit: String =
        serde_json::from_str(unit_raw.get()).map_err(|_| AgentCommandError::InvalidAmount)?;
    let value_raw = fields
        .get("value")
        .ok_or(AgentCommandError::AmbiguousAmount)?;
    let raw = value_raw.get();

    match unit.as_str() {
        "token_atomic" => decode_atomic(raw).map(AmountSpec::TokenAtomic),
        "stablecoin_atomic" => decode_atomic(raw).map(AmountSpec::StablecoinAtomic),
        "usd_micros" => {
            let micros =
                serde_json::from_str::<u64>(raw).map_err(|_| AgentCommandError::InvalidAmount)?;
            if micros == 0 {
                return Err(AgentCommandError::InvalidAmount);
            }
            Ok(AmountSpec::UsdMicros(micros))
        }
        _ => Err(AgentCommandError::InvalidAmount),
    }
}

fn decode_atomic(raw: &str) -> Result<u128, AgentCommandError> {
    let atomic = serde_json::from_str::<u128>(raw).map_err(|_| AgentCommandError::InvalidAmount)?;
    if atomic == 0 {
        return Err(AgentCommandError::InvalidAmount);
    }
    Ok(atomic)
}

fn field_limit_price(fields: &RawFields) -> Result<LimitPriceSpec, AgentCommandError> {
    let raw = fields
        .get("limit_price")
        .ok_or(AgentCommandError::InvalidLimitPrice)?;
    limit_price_from_raw_str(raw.get())
}

/// Decodes a limit price from a losslessly-captured object.
///
/// Only `numerator_atomic`/`denominator_atomic` are accepted, duplicate keys
/// fail closed, and both sides must be non-zero [`u128`] atomics.
fn limit_price_from_raw_str(json: &str) -> Result<LimitPriceSpec, AgentCommandError> {
    let fields = parse_raw_object(json).map_err(|_| AgentCommandError::InvalidLimitPrice)?;
    for key in fields.keys() {
        if key != "numerator_atomic" && key != "denominator_atomic" {
            return Err(AgentCommandError::InvalidLimitPrice);
        }
    }

    let numerator_raw = fields
        .get("numerator_atomic")
        .ok_or(AgentCommandError::InvalidLimitPrice)?;
    let denominator_raw = fields
        .get("denominator_atomic")
        .ok_or(AgentCommandError::InvalidLimitPrice)?;
    let numerator: u128 = serde_json::from_str(numerator_raw.get())
        .map_err(|_| AgentCommandError::InvalidLimitPrice)?;
    let denominator: u128 = serde_json::from_str(denominator_raw.get())
        .map_err(|_| AgentCommandError::InvalidLimitPrice)?;

    LimitPriceSpec::new(numerator, denominator)
}

/// Decodes a validated asset reference from a losslessly-captured object.
///
/// Only `chain`/`address` are accepted and duplicate keys fail closed.
fn asset_from_raw_str(json: &str) -> Result<AssetRef, AgentCommandError> {
    let fields = parse_raw_object(json).map_err(|_| AgentCommandError::InvalidAsset)?;
    for key in fields.keys() {
        if key != "chain" && key != "address" {
            return Err(AgentCommandError::InvalidAsset);
        }
    }

    let chain_raw = fields.get("chain").ok_or(AgentCommandError::InvalidAsset)?;
    let chain: ChainId =
        serde_json::from_str(chain_raw.get()).map_err(|_| AgentCommandError::InvalidAsset)?;
    let address_raw = fields
        .get("address")
        .ok_or(AgentCommandError::InvalidAsset)?;
    let address: String =
        serde_json::from_str(address_raw.get()).map_err(|_| AgentCommandError::InvalidAsset)?;

    let asset = AssetRef { chain, address };
    asset.validate()?;
    Ok(asset)
}
