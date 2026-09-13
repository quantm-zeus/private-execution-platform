//! Hand-written JSON Schemas for the eleven `agent-commands` tools.
//!
//! The schemas mirror the strict `agent-commands` decoders: every tool is an
//! object with `additionalProperties:false` and an explicit `required` list,
//! and every amount is an object requiring an explicit `unit` and `value`
//! (AC-2: a bare amount never passes).

use serde_json::{json, Map, Value};

/// The eleven `agent-commands` tool tags, in canonical order.
pub(crate) const TOOL_NAMES: [&str; 11] = [
    "search_token",
    "get_token",
    "get_chart",
    "get_intelligence",
    "get_quote",
    "get_orders",
    "get_portfolio",
    "preview_market_order",
    "execute_market_order",
    "place_limit_order",
    "cancel_order",
];

/// True when `name` is one of the closed set of served tools.
pub(crate) fn is_known_tool(name: &str) -> bool {
    TOOL_NAMES.contains(&name)
}

/// Every tool, in the canonical `agent-commands` order.
pub(crate) fn tools() -> Vec<Value> {
    vec![
        tool(
            "search_token",
            "Search for tokens by symbol, name, or address.",
            object_schema(vec![("query", string_schema())], &["query"]),
        ),
        tool(
            "get_token",
            "Fetch metadata for one chain-qualified token.",
            object_schema(vec![("token", asset_schema())], &["token"]),
        ),
        tool(
            "get_chart",
            "Fetch a candlestick chart window for one token.",
            object_schema(
                vec![("token", asset_schema()), ("window", window_schema())],
                &["token", "window"],
            ),
        ),
        tool(
            "get_intelligence",
            "Fetch aggregated market intelligence for one token.",
            object_schema(vec![("token", asset_schema())], &["token"]),
        ),
        tool(
            "get_quote",
            "Quote a swap between two tokens for an explicit amount.",
            object_schema(
                vec![
                    ("token_in", asset_schema()),
                    ("token_out", asset_schema()),
                    ("amount", amount_schema()),
                ],
                &["token_in", "token_out", "amount"],
            ),
        ),
        tool(
            "get_orders",
            "List the wallet's orders, optionally filtered by status.",
            object_schema(vec![("status", string_schema())], &[]),
        ),
        tool(
            "get_portfolio",
            "Show the wallet's current portfolio.",
            object_schema(Vec::new(), &[]),
        ),
        tool(
            "preview_market_order",
            "Simulate a market order without moving funds.",
            market_order_schema(),
        ),
        tool(
            "execute_market_order",
            "Execute a market order.",
            market_order_schema(),
        ),
        tool(
            "place_limit_order",
            "Place a limit order at an explicit atomic price.",
            object_schema(
                vec![
                    ("token_in", asset_schema()),
                    ("token_out", asset_schema()),
                    ("side", side_schema()),
                    ("amount", amount_schema()),
                    ("limit_price", limit_price_schema()),
                    ("allow_partial_fill", json!({ "type": "boolean" })),
                    ("expires_at_ms", json!({ "type": "integer" })),
                ],
                &[
                    "token_in",
                    "token_out",
                    "side",
                    "amount",
                    "limit_price",
                    "allow_partial_fill",
                    "expires_at_ms",
                ],
            ),
        ),
        tool(
            "cancel_order",
            "Cancel an existing order by its identifier.",
            object_schema(vec![("order_id", string_schema())], &["order_id"]),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}

fn object_schema(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut map = Map::new();
    for (key, value) in properties {
        map.insert(key.to_string(), value);
    }
    json!({
        "type": "object",
        "properties": Value::Object(map),
        "required": required,
        "additionalProperties": false,
    })
}

fn string_schema() -> Value {
    json!({ "type": "string" })
}

fn side_schema() -> Value {
    json!({ "type": "string", "enum": ["buy", "sell"] })
}

fn window_schema() -> Value {
    json!({ "type": "string", "enum": ["m5", "m15", "h1", "h4", "d1"] })
}

fn asset_schema() -> Value {
    let mut chain_properties = Map::new();
    chain_properties.insert(
        "kind".to_string(),
        json!({
            "type": "string",
            "enum": ["solana", "base", "bnb_chain", "ethereum", "robinhood_associated", "other"],
        }),
    );
    chain_properties.insert("value".to_string(), string_schema());
    let chain = json!({
        "type": "object",
        "properties": Value::Object(chain_properties),
        "required": ["kind"],
        "additionalProperties": false,
    });
    object_schema(
        vec![
            ("chain", chain),
            ("address", json!({ "type": "string", "minLength": 1 })),
        ],
        &["chain", "address"],
    )
}

fn amount_schema() -> Value {
    object_schema(
        vec![
            (
                "unit",
                json!({
                    "type": "string",
                    "enum": ["token_atomic", "stablecoin_atomic", "usd_micros"],
                }),
            ),
            ("value", json!({ "type": "integer", "minimum": 1 })),
        ],
        &["unit", "value"],
    )
}

fn limit_price_schema() -> Value {
    object_schema(
        vec![
            (
                "numerator_atomic",
                json!({ "type": "integer", "minimum": 1 }),
            ),
            (
                "denominator_atomic",
                json!({ "type": "integer", "minimum": 1 }),
            ),
        ],
        &["numerator_atomic", "denominator_atomic"],
    )
}

fn market_order_schema() -> Value {
    object_schema(
        vec![
            ("token_in", asset_schema()),
            ("token_out", asset_schema()),
            ("side", side_schema()),
            ("amount", amount_schema()),
            (
                "max_slippage_bps",
                json!({ "type": "integer", "minimum": 0 }),
            ),
            (
                "max_price_impact_bps",
                json!({ "type": "integer", "minimum": 0 }),
            ),
        ],
        &["token_in", "token_out", "side", "amount"],
    )
}
