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

use std::collections::BTreeMap;

use chain_types::ChainId;
use domain::TradeSide;
use market_types::PriceRatio;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;

use crate::AgentCommandError;

/// Maximum accepted asset address length.
///
/// Generous enough for Solana base58 and EVM hex addresses while rejecting
/// pathological payloads before they reach the rest of the system.
pub const MAX_ASSET_ADDRESS_LEN: usize = 128;

/// Raw, lossless capture of a JSON object's fields.
type RawFields = BTreeMap<String, Box<RawValue>>;

/// Channel that submitted a command. Both channels share the same restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentChannel {
    Mcp,
    Telegram,
}

/// Explicit amount unit. A bare number is NOT accepted anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "unit", content = "value")]
pub enum AmountSpec {
    /// Token base units (atomic).
    TokenAtomic(u128),
    /// Stablecoin base units (atomic).
    StablecoinAtomic(u128),
    /// USD micros.
    UsdMicros(u64),
}

impl<'de> Deserialize<'de> for AmountSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Capture both members losslessly and decode order-independently: the
        // derived adjacently-tagged decoder routes `value`-before-`unit` through
        // serde's `Content` buffer, which cannot represent `u128`.
        let fields = BTreeMap::<String, Box<RawValue>>::deserialize(deserializer)?;
        amount_from_raw_fields(&fields).map_err(serde::de::Error::custom)
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAssetRef")]
pub struct AssetRef {
    pub chain: ChainId,
    pub address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAssetRef {
    chain: ChainId,
    address: String,
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

impl TryFrom<RawAssetRef> for AssetRef {
    type Error = AgentCommandError;

    fn try_from(raw: RawAssetRef) -> Result<Self, Self::Error> {
        let asset = Self {
            chain: raw.chain,
            address: raw.address,
        };
        asset.validate()?;
        Ok(asset)
    }
}

/// Explicit atomic limit price for a limit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLimitPriceSpec")]
pub struct LimitPriceSpec {
    pub numerator_atomic: u128,
    pub denominator_atomic: u128,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimitPriceSpec {
    numerator_atomic: u128,
    denominator_atomic: u128,
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

impl TryFrom<RawLimitPriceSpec> for LimitPriceSpec {
    type Error = AgentCommandError;

    fn try_from(raw: RawLimitPriceSpec) -> Result<Self, Self::Error> {
        Self::new(raw.numerator_atomic, raw.denominator_atomic)
    }
}

/// Read-only commands (allowed while trading is disabled).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    },
    GetOrders {
        status: Option<String>,
    },
    GetPortfolio,
}

/// Mutating commands. All require an enabled trading gate and an explicit amount unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "tool")]
pub enum TradeCommand {
    PreviewMarketOrder {
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
    },
    ExecuteMarketOrder {
        token_in: AssetRef,
        token_out: AssetRef,
        side: TradeSide,
        amount: AmountSpec,
        max_slippage_bps: Option<u16>,
        max_price_impact_bps: Option<u16>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum AgentCommand {
    Read(ReadCommand),
    Trade(TradeCommand),
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
    /// fields, a missing amount unit, a bare amount, and malformed assets,
    /// windows, or limit prices all fail closed. Any tool name outside the
    /// closed read/trade vocabulary returns
    /// [`AgentCommandError::ForbiddenOperation`], never a generic parse error,
    /// so a withdraw/transfer/ownership/limit-raising/signing attempt cannot be
    /// smuggled through.
    pub fn parse(json: &str) -> Result<Self, AgentCommandError> {
        let fields = parse_fields(json)?;
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

impl<'de> Deserialize<'de> for AgentCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = RawFields::deserialize(deserializer)?;
        Self::from_fields(fields).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ReadCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = RawFields::deserialize(deserializer)?;
        let tool = tool_name(&fields).map_err(serde::de::Error::custom)?;
        if !READ_TOOL_NAMES.contains(&tool.as_str()) {
            return Err(serde::de::Error::custom(
                AgentCommandError::ForbiddenOperation,
            ));
        }
        build_read(&tool, &fields).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TradeCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = RawFields::deserialize(deserializer)?;
        let tool = tool_name(&fields).map_err(serde::de::Error::custom)?;
        if !TRADE_TOOL_NAMES.contains(&tool.as_str()) {
            return Err(serde::de::Error::custom(
                AgentCommandError::ForbiddenOperation,
            ));
        }
        build_trade(&tool, &fields).map_err(serde::de::Error::custom)
    }
}

fn parse_fields(json: &str) -> Result<RawFields, AgentCommandError> {
    serde_json::from_str::<RawFields>(json).map_err(|_| AgentCommandError::Malformed)
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
                &["tool", "command", "token_in", "token_out", "amount"],
            )?;
            Ok(ReadCommand::GetQuote {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                amount: field_amount(fields)?,
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
                ],
            )?;
            Ok(TradeCommand::PreviewMarketOrder {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                side: field_side(fields)?,
                amount: field_amount(fields)?,
                max_slippage_bps: field_optional_u16(fields, "max_slippage_bps")?,
                max_price_impact_bps: field_optional_u16(fields, "max_price_impact_bps")?,
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
                ],
            )?;
            Ok(TradeCommand::ExecuteMarketOrder {
                token_in: field_asset(fields, "token_in")?,
                token_out: field_asset(fields, "token_out")?,
                side: field_side(fields)?,
                amount: field_amount(fields)?,
                max_slippage_bps: field_optional_u16(fields, "max_slippage_bps")?,
                max_price_impact_bps: field_optional_u16(fields, "max_price_impact_bps")?,
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
    serde_json::from_str::<AssetRef>(raw.get()).map_err(|_| AgentCommandError::InvalidAsset)
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
    let inner: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(raw.get()).map_err(|_| AgentCommandError::Malformed)?;
    amount_from_raw_fields(&inner)
}

/// Decodes an amount from losslessly-captured `unit`/`value` members.
///
/// Member order is irrelevant: the `value` is decoded directly from its exact
/// raw JSON using the unit's width, so `u128` atomics stay lossless.
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
    let value: Value =
        serde_json::from_str(raw.get()).map_err(|_| AgentCommandError::InvalidLimitPrice)?;
    let map = value
        .as_object()
        .ok_or(AgentCommandError::InvalidLimitPrice)?;

    for key in map.keys() {
        if key != "numerator_atomic" && key != "denominator_atomic" {
            return Err(AgentCommandError::InvalidLimitPrice);
        }
    }

    let numerator = map
        .get("numerator_atomic")
        .ok_or(AgentCommandError::InvalidLimitPrice)?;
    let denominator = map
        .get("denominator_atomic")
        .ok_or(AgentCommandError::InvalidLimitPrice)?;
    if !numerator.is_number() || !denominator.is_number() {
        return Err(AgentCommandError::InvalidLimitPrice);
    }
    if is_json_zero(numerator) || is_json_zero(denominator) {
        return Err(AgentCommandError::InvalidLimitPrice);
    }

    serde_json::from_str::<LimitPriceSpec>(raw.get())
        .map_err(|_| AgentCommandError::InvalidLimitPrice)
}

/// True when a JSON numeric value is exactly zero.
///
/// The intermediate [`Value`] is only used for shape and zero checks; actual
/// 128-bit decoding happens from the lossless raw JSON.
fn is_json_zero(value: &Value) -> bool {
    value.as_f64() == Some(0.0)
}
