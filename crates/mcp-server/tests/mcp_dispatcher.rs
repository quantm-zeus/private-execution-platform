//! P55 acceptance tests for the MCP JSON-RPC dispatcher.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use agent_commands::{AgentCapabilities, AgentChannel, AgentCommand};
use async_trait::async_trait;
use chain_types::ChainId;
use mcp_server::{AgentBackend, BackendOutcome, McpError, McpServer, UnavailableBackend};
use serde_json::{json, Value};

const SOL_ADDR: &str = "So11111111111111111111111111111111111111112";
const USDC_ADDR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

const EXECUTE_JSON: &str = concat!(
    r#"{"tool":"execute_market_order","token_in":"#,
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
    r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    r#""side":"buy","amount":{"unit":"usd_micros","value":1000000},"#,
    r#""max_slippage_bps":100,"max_price_impact_bps":200}"#
);

const PLACE_JSON: &str = concat!(
    r#"{"tool":"place_limit_order","token_in":"#,
    r#"{"chain":{"kind":"solana"},"address":"So11111111111111111111111111111111111111112"},"#,
    r#""token_out":{"chain":{"kind":"solana"},"address":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},"#,
    r#""side":"sell","amount":{"unit":"stablecoin_atomic","value":5000},"#,
    r#""limit_price":{"numerator_atomic":3,"denominator_atomic":2},"#,
    r#""allow_partial_fill":true,"expires_at_ms":1700000000000}"#
);

type Seen = Arc<Mutex<Vec<(AgentChannel, AgentCommand)>>>;

/// Backend double that records every command it is asked to execute.
struct RecordingBackend {
    seen: Seen,
    outcome: BackendOutcome,
    valuation: Option<u64>,
}

impl RecordingBackend {
    fn new(outcome: BackendOutcome, valuation: Option<u64>) -> (Self, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                seen: Arc::clone(&seen),
                outcome,
                valuation,
            },
            seen,
        )
    }

    fn ok() -> (Self, Seen) {
        Self::new(
            BackendOutcome::Value(json!({ "status": "ok" })),
            Some(999_999),
        )
    }
}

#[async_trait]
impl AgentBackend for RecordingBackend {
    async fn execute(&self, channel: AgentChannel, command: AgentCommand) -> BackendOutcome {
        self.seen
            .lock()
            .expect("seen lock")
            .push((channel, command));
        self.outcome.clone()
    }

    async fn valuation_usd_micros(&self, _command: &AgentCommand) -> Option<u64> {
        self.valuation
    }
}

fn caps(trading_enabled: bool) -> AgentCapabilities {
    let mut allowed_chains = HashSet::new();
    allowed_chains.insert(ChainId::Solana);
    AgentCapabilities::new(trading_enabled, allowed_chains, 1_000_000)
}

fn request(id: i64, method: &str, params: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

fn notification(method: &str, params: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
    .to_string()
}

fn parse(response: &str) -> Value {
    serde_json::from_str(response).expect("response is JSON")
}

fn result(response: &Value) -> &Value {
    response.get("result").expect("result present")
}

fn asset(address: &str) -> Value {
    json!({ "chain": { "kind": "solana" }, "address": address })
}

fn market_arguments() -> Value {
    json!({
        "token_in": asset(SOL_ADDR),
        "token_out": asset(USDC_ADDR),
        "side": "buy",
        "amount": { "unit": "usd_micros", "value": 1_000_000 },
        "max_slippage_bps": 100,
        "max_price_impact_bps": 200,
    })
}

fn limit_arguments() -> Value {
    json!({
        "token_in": asset(SOL_ADDR),
        "token_out": asset(USDC_ADDR),
        "side": "sell",
        "amount": { "unit": "stablecoin_atomic", "value": 5000 },
        "limit_price": { "numerator_atomic": 3, "denominator_atomic": 2 },
        "allow_partial_fill": true,
        "expires_at_ms": 1_700_000_000_000i64,
    })
}

fn expected_command(json_str: &str) -> AgentCommand {
    AgentCommand::parse(json_str).expect("expected command parses")
}

// --- initialize / notifications ----------------------------------------------

#[tokio::test]
async fn initialize_returns_the_mcp_contract() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let response = server.handle(&request(1, "initialize", json!({}))).await;
    let value = parse(&response);
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], 1);
    assert_eq!(result(&value)["protocolVersion"], "2024-11-05");
    assert_eq!(result(&value)["capabilities"]["tools"], json!({}));
    assert_eq!(
        result(&value)["serverInfo"]["name"],
        "private-execution-platform"
    );
    assert_eq!(
        result(&value)["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::test]
async fn initialized_notification_yields_no_response() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let frame = notification("notifications/initialized", json!({}));
    assert_eq!(server.handle(&frame).await, "");
}

// --- tools/list ---------------------------------------------------------------

#[tokio::test]
async fn tools_list_returns_exactly_the_agent_command_surface() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let response = server.handle(&request(2, "tools/list", json!({}))).await;
    let value = parse(&response);
    let tools = result(&value)["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec![
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
        ]
    );

    for tool in tools {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["required"].is_array(),
            "required missing for {}",
            tool["name"]
        );
        assert!(
            schema["properties"].is_object(),
            "properties missing for {}",
            tool["name"]
        );
    }

    for amount_tool in [
        "get_quote",
        "preview_market_order",
        "execute_market_order",
        "place_limit_order",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == amount_tool)
            .expect("amount tool present");
        let amount = &tool["inputSchema"]["properties"]["amount"];
        assert_eq!(
            amount["required"],
            json!(["unit", "value"]),
            "amount schema for {amount_tool} must require unit+value"
        );
        assert_eq!(amount["additionalProperties"], false);
    }
}

// --- tools/call: authorize then reach the backend -----------------------------

#[tokio::test]
async fn read_tool_reaches_backend_with_decoded_command_and_mcp_channel() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let params = json!({
        "name": "get_token",
        "arguments": { "token": asset(SOL_ADDR) },
    });
    let response = server.handle(&request(21, "tools/call", params)).await;
    let value = parse(&response);
    assert_eq!(value["id"], 21);
    assert_eq!(result(&value)["isError"], false);
    assert_eq!(result(&value)["content"][0]["type"], "text");

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, AgentChannel::Mcp);
    assert_eq!(
        seen[0].1,
        expected_command(&format!(
            r#"{{"tool":"get_token","token":{{"chain":{{"kind":"solana"}},"address":"{SOL_ADDR}"}}}}"#
        ))
    );
}

#[tokio::test]
async fn trade_tool_reaches_backend_with_decoded_command_and_mcp_channel() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(true));

    let params = json!({
        "name": "execute_market_order",
        "arguments": market_arguments(),
    });
    let response = server.handle(&request(22, "tools/call", params)).await;
    let value = parse(&response);
    assert_eq!(result(&value)["isError"], false);
    assert_eq!(result(&value)["content"][0]["type"], "text");

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, AgentChannel::Mcp);
    assert_eq!(seen[0].1, expected_command(EXECUTE_JSON));
}

#[tokio::test]
async fn limit_tool_reaches_backend_with_decoded_command() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(true));

    let params = json!({
        "name": "place_limit_order",
        "arguments": limit_arguments(),
    });
    let response = server.handle(&request(23, "tools/call", params)).await;
    assert_eq!(result(&parse(&response))["isError"], false);

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, AgentChannel::Mcp);
    assert_eq!(seen[0].1, expected_command(PLACE_JSON));
}

// --- fail-closed paths --------------------------------------------------------

#[tokio::test]
async fn missing_unit_or_bare_amount_fails_closed_without_backend_call() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let missing_unit = json!({
        "name": "get_quote",
        "arguments": {
            "token_in": asset(SOL_ADDR),
            "token_out": asset(USDC_ADDR),
            "amount": { "value": 100 },
        },
    });
    let response = server
        .handle(&request(31, "tools/call", missing_unit))
        .await;
    assert_eq!(result(&parse(&response))["isError"], true);

    let bare_amount = json!({
        "name": "get_quote",
        "arguments": {
            "token_in": asset(SOL_ADDR),
            "token_out": asset(USDC_ADDR),
            "amount": 100,
        },
    });
    let response = server.handle(&request(32, "tools/call", bare_amount)).await;
    assert_eq!(result(&parse(&response))["isError"], true);

    assert!(
        seen.lock().expect("seen lock").is_empty(),
        "ambiguous commands must never reach the backend"
    );
}

#[tokio::test]
async fn forbidden_tool_fails_closed_without_backend_call() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(true));

    let params = json!({
        "name": "withdraw",
        "arguments": { "order_id": "SECRETORDERID" },
    });
    let response = server.handle(&request(33, "tools/call", params)).await;
    let value = parse(&response);
    assert_eq!(result(&value)["isError"], true);
    assert!(seen.lock().expect("seen lock").is_empty());
    assert!(!response.contains("withdraw"));
    assert!(!response.contains("SECRETORDERID"));
}

#[tokio::test]
async fn trading_disabled_denies_mutations_but_allows_preview() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    for (id, name, arguments) in [
        (41, "execute_market_order", market_arguments()),
        (42, "place_limit_order", limit_arguments()),
    ] {
        let params = json!({ "name": name, "arguments": arguments });
        let response = server.handle(&request(id, "tools/call", params)).await;
        let value = parse(&response);
        assert_eq!(
            result(&value)["isError"],
            true,
            "{name} must be denied while trading is disabled"
        );
        assert_eq!(result(&value)["content"][0]["text"], "TradingDisabled");
    }
    assert!(
        seen.lock().expect("seen lock").is_empty(),
        "denied mutations must not reach the backend"
    );

    let preview = json!({
        "name": "preview_market_order",
        "arguments": market_arguments(),
    });
    let response = server.handle(&request(43, "tools/call", preview)).await;
    assert_eq!(result(&parse(&response))["isError"], false);
    assert_eq!(
        seen.lock().expect("seen lock").len(),
        1,
        "read-only preview must reach the backend while trading is disabled"
    );
}

#[tokio::test]
async fn unavailable_backend_reports_tool_error() {
    let server = McpServer::new(UnavailableBackend, caps(false));

    let params = json!({ "name": "get_portfolio", "arguments": {} });
    let response = server.handle(&request(61, "tools/call", params)).await;
    let value = parse(&response);
    assert_eq!(result(&value)["isError"], true);
    assert_eq!(result(&value)["content"][0]["text"], "backend unavailable");
}

// --- JSON-RPC envelope errors -------------------------------------------------

#[tokio::test]
async fn unknown_method_returns_method_not_found() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let response = server
        .handle(&request(51, "resources/list", json!({})))
        .await;
    let value = parse(&response);
    assert_eq!(value["error"]["code"], -32601);
    assert_eq!(value["id"], 51);
}

#[tokio::test]
async fn malformed_json_returns_parse_error() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let response = server.handle("{ this is not json").await;
    let value = parse(&response);
    assert_eq!(value["error"]["code"], -32700);
    assert_eq!(value["id"], Value::Null);
}

#[tokio::test]
async fn non_object_params_return_invalid_params() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let response = server
        .handle(&request(52, "tools/call", json!([1, 2, 3])))
        .await;
    assert_eq!(parse(&response)["error"]["code"], -32602);

    let response = server
        .handle(&request(53, "tools/call", json!({ "arguments": {} })))
        .await;
    assert_eq!(parse(&response)["error"]["code"], -32602);

    // Valid JSON that is not an object is an invalid request, not a parse error.
    let response = server.handle("[]").await;
    assert_eq!(parse(&response)["error"]["code"], -32600);
}

#[tokio::test]
async fn invalid_id_is_nulled_and_never_echoed() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    for frame in [
        r#"{"jsonrpc":"2.0","id":{"secret":"SECRETIDVALUE"},"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":["SECRETIDVALUE"],"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"tools/list"}"#,
    ] {
        let response = server.handle(frame).await;
        let value = parse(&response);
        assert_eq!(value["error"]["code"], -32600);
        assert_eq!(value["id"], Value::Null);
        assert!(!response.contains("SECRETIDVALUE"));
    }
}

// --- notifications ------------------------------------------------------------

#[tokio::test]
async fn notification_yields_empty_response_and_still_executes_read() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let frame = notification(
        "tools/call",
        json!({ "name": "get_portfolio", "arguments": {} }),
    );
    assert_eq!(server.handle(&frame).await, "");
    assert_eq!(
        seen.lock().expect("seen lock").len(),
        1,
        "a notification is processed even though no response is emitted"
    );
}

#[tokio::test]
async fn handle_notification_validates_without_side_effects() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let frame = notification(
        "tools/call",
        json!({ "name": "get_portfolio", "arguments": {} }),
    );
    assert_eq!(server.handle_notification(&frame).await, Ok(()));
    assert!(
        seen.lock().expect("seen lock").is_empty(),
        "notification validation must not execute commands"
    );

    assert_eq!(
        server.handle_notification("{not json").await,
        Err(McpError::ParseError)
    );
    assert_eq!(
        server
            .handle_notification(&request(1, "tools/list", json!({})))
            .await,
        Err(McpError::InvalidRequest)
    );
}

// --- redaction / decoding -----------------------------------------------------

#[tokio::test]
async fn responses_never_echo_request_values() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let secrets = [
        "SECRETQUERY123",
        "SECRETADDRESSSECRETADDRESS",
        "9876543210123456789",
        "SECRETORDERID456",
        "SECRETWINDOW",
        "111222333444555666",
        SOL_ADDR,
        USDC_ADDR,
    ];

    let cases = [
        (
            71,
            json!({ "name": "search_token", "arguments": { "query": "SECRETQUERY123" } }),
        ),
        (
            72,
            json!({ "name": "get_token", "arguments": { "token": asset("SECRETADDRESSSECRETADDRESS") } }),
        ),
        (
            73,
            json!({
                "name": "get_quote",
                "arguments": {
                    "token_in": asset(SOL_ADDR),
                    "token_out": asset(USDC_ADDR),
                    "amount": { "value": 9876543210123456789u64 },
                },
            }),
        ),
        (
            74,
            json!({ "name": "cancel_order", "arguments": { "order_id": "SECRETORDERID456" } }),
        ),
        (
            75,
            json!({
                "name": "get_chart",
                "arguments": { "token": asset(SOL_ADDR), "window": "SECRETWINDOW" },
            }),
        ),
    ];

    for (id, params) in cases {
        let response = server.handle(&request(id, "tools/call", params)).await;
        for secret in secrets {
            assert!(
                !response.contains(secret),
                "response frame leaked {secret}: {response}"
            );
        }
    }

    // A raw frame with a bare amount and a secret address must fail closed
    // without echoing either value.
    let raw = concat!(
        r#"{"jsonrpc":"2.0","id":76,"method":"tools/call","params":{"name":"get_quote","#,
        r#""arguments":{"token_in":{"chain":{"kind":"solana"},"address":"SECRETADDRESSSECRETADDRESS"},"#,
        r#""token_out":{"chain":{"kind":"solana"},"address":"0x0"},"amount":111222333444555666}}}"#
    );
    let response = server.handle(raw).await;
    assert!(!response.contains("SECRETADDRESSSECRETADDRESS"));
    assert!(!response.contains("111222333444555666"));
}

#[tokio::test]
async fn backend_receives_decoded_command_not_raw_json() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(true));

    let params = json!({
        "name": "cancel_order",
        "arguments": { "order_id": "order-123" },
    });
    let response = server.handle(&request(81, "tools/call", params)).await;
    assert_eq!(result(&parse(&response))["isError"], false);

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, AgentChannel::Mcp);
    assert_eq!(
        seen[0].1,
        expected_command(r#"{"tool":"cancel_order","order_id":"order-123"}"#)
    );
}
