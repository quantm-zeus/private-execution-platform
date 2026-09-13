//! P56 acceptance tests for the bounded MCP stdio transport.
//!
//! Every test uses in-memory buffers (`&[u8]` reader / `RecordingWriter`
//! writer); no test touches the process stdin/stdout.

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use agent_commands::{AgentCapabilities, AgentChannel, AgentCommand};
use async_trait::async_trait;
use chain_types::ChainId;
use mcp_server::{
    AgentBackend, BackendOutcome, McpServer, StdioLimits, StdioServer, UnavailableBackend,
};
use serde_json::{json, Value};
use tokio::io::AsyncWrite;

const SOL_ADDR: &str = "So11111111111111111111111111111111111111112";
const USDC_ADDR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

const SECRET_ADDRESS: &str = "SECRETADDRESSSECRETADDRESS";
const SECRET_QUERY: &str = "SECRETQUERY123";
const SECRET_ORDER: &str = "SECRETORDERID456";
const SECRET_AMOUNT: &str = "9876543210123456789";

type Seen = Arc<Mutex<Vec<(AgentChannel, AgentCommand)>>>;

/// Backend double that records every executed command.
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

/// In-memory writer that records bytes and counts flushes.
#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    flushes: usize,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn caps(trading_enabled: bool) -> AgentCapabilities {
    let mut allowed_chains = HashSet::new();
    allowed_chains.insert(ChainId::Solana);
    AgentCapabilities::new(trading_enabled, allowed_chains, 1_000_000)
}

fn limits(max_frame_bytes: usize, max_frames: u64) -> StdioLimits {
    StdioLimits {
        max_frame_bytes,
        max_frames,
    }
}

async fn serve<B: AgentBackend>(
    server: McpServer<B>,
    limits: StdioLimits,
    input: &[u8],
) -> (u64, RecordingWriter) {
    let stdio = StdioServer::new(server, limits);
    let mut writer = RecordingWriter::default();
    let processed = stdio.run(input, &mut writer).await.expect("transport runs");
    (processed, writer)
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

fn asset(address: &str) -> Value {
    json!({ "chain": { "kind": "solana" }, "address": address })
}

fn output_text(writer: &RecordingWriter) -> String {
    String::from_utf8(writer.bytes.clone()).expect("output is UTF-8")
}

fn response_lines(writer: &RecordingWriter) -> Vec<Value> {
    let text = output_text(writer);
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "LF-terminated: {text:?}"
    );
    assert!(
        !text.contains('\r'),
        "output must be LF, not CRLF: {text:?}"
    );
    text.split('\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("response line is JSON"))
        .collect()
}

// --- framing ------------------------------------------------------------------

#[tokio::test]
async fn two_frame_session_returns_two_ordered_responses() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let input = format!(
        "{}\n{}\n",
        request(1, "initialize", json!({})),
        request(2, "tools/list", json!({})),
    );

    let (processed, writer) = serve(server, limits(1 << 20, 0), input.as_bytes()).await;

    assert_eq!(processed, 2);
    assert_eq!(writer.flushes, 2, "one flush per response frame");
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["jsonrpc"], "2.0");
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(lines[1]["jsonrpc"], "2.0");
    assert_eq!(lines[1]["id"], 2);
    assert!(lines[1]["result"]["tools"].is_array());
}

#[tokio::test]
async fn notification_emits_nothing_but_next_request_is_served() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let input = format!(
        "{}\n{}\n",
        notification("notifications/initialized", json!({})),
        request(5, "tools/list", json!({})),
    );

    let (processed, writer) = serve(server, limits(1 << 20, 0), input.as_bytes()).await;

    assert_eq!(processed, 2);
    assert_eq!(writer.flushes, 1, "notifications must not flush a response");
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], 5);
}

#[tokio::test]
async fn blank_and_crlf_lines_are_tolerated_and_output_is_lf() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let input = format!("\n\r\n{}\r\n", request(7, "tools/list", json!({})));

    let (processed, writer) = serve(server, limits(1 << 20, 0), input.as_bytes()).await;

    assert_eq!(processed, 1, "blank lines are skipped and not counted");
    let text = output_text(&writer);
    assert!(text.ends_with('\n'));
    assert!(!text.contains('\r'));
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], 7);
}

#[tokio::test]
async fn crlf_frame_at_exact_byte_bound_is_not_oversized() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    // Pad with JSON whitespace so the frame content is exactly the bound; the
    // CR of the CRLF terminator must not count against it.
    let bound = request(13, "tools/list", json!({})).len() + 16;
    let frame = format!("{}{}", request(13, "tools/list", json!({})), " ".repeat(16));
    assert_eq!(frame.len(), bound);
    let input = format!("{frame}\r\n");

    let (processed, writer) = serve(server, limits(bound, 0), input.as_bytes()).await;

    assert_eq!(processed, 1);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], 13);
    assert!(lines[0]["error"].is_null());
}

// --- bounds and malformed frames ---------------------------------------------

#[tokio::test]
async fn oversized_frame_is_redacted_not_dispatched_and_loop_continues() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let valid = request(
        9,
        "tools/call",
        json!({ "name": "get_portfolio", "arguments": {} }),
    );
    let oversized = format!("{valid}{}", " ".repeat(64));
    let input = format!("{oversized}\n{valid}\n");

    let (processed, writer) = serve(server, limits(valid.len() + 8, 0), input.as_bytes()).await;

    assert_eq!(processed, 2);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 2);
    assert_eq!(
        writer.flushes, 2,
        "one flush per emitted error/response frame"
    );
    assert_eq!(lines[0]["error"]["code"], -32600);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[1]["id"], 9);
    assert_eq!(lines[1]["result"]["isError"], false);
    assert_eq!(
        seen.lock().expect("seen lock").len(),
        1,
        "the oversized frame must never reach the backend"
    );
}

#[tokio::test]
async fn oversized_frame_without_trailing_newline_before_eof_is_one_error() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let frame = "x".repeat(300);

    let (processed, writer) = serve(server, limits(64, 0), frame.as_bytes()).await;

    assert_eq!(processed, 1);
    assert_eq!(writer.flushes, 1);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"]["code"], -32600);
    assert_eq!(lines[0]["id"], Value::Null);
}

#[tokio::test]
async fn garbage_and_non_utf8_frames_are_redacted_and_loop_continues() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(b"{ this is not json\n");
    input.extend_from_slice(&[0xff, 0xfe, b'\n']);
    input.extend_from_slice(request(11, "tools/list", json!({})).as_bytes());
    input.push(b'\n');

    let (processed, writer) = serve(server, limits(1 << 20, 0), &input).await;

    assert_eq!(processed, 3);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 3);
    assert_eq!(
        writer.flushes, 3,
        "one flush per emitted error/response frame"
    );
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert_eq!(lines[1]["id"], Value::Null);
    assert_eq!(lines[2]["id"], 11);

    let text = output_text(&writer);
    assert!(!text.contains("this is not json"));
}

#[tokio::test]
async fn max_frames_stops_after_n_and_returns_n() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let input = format!(
        "{}\n{}\n{}\n",
        request(1, "tools/list", json!({})),
        request(2, "tools/list", json!({})),
        request(3, "tools/list", json!({})),
    );

    let (processed, writer) = serve(server, limits(1 << 20, 2), input.as_bytes()).await;

    assert_eq!(processed, 2);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["id"], 2);
}

#[tokio::test]
async fn max_frames_counts_only_non_blank_frames() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let input = format!(
        "\n{}\n\n{}\n{}\n",
        request(1, "tools/list", json!({})),
        request(2, "tools/list", json!({})),
        request(3, "tools/list", json!({})),
    );

    let (processed, writer) = serve(server, limits(1 << 20, 2), input.as_bytes()).await;

    assert_eq!(
        processed, 2,
        "blank lines must not consume the frame budget"
    );
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["id"], 2);
}

// --- tools/call over stdio ----------------------------------------------------

#[tokio::test]
async fn read_tool_reaches_backend_over_stdio_and_response_is_redacted() {
    let (backend, seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));
    let params = json!({
        "name": "get_token",
        "arguments": { "token": asset(SOL_ADDR) },
    });
    let input = format!("{}\n", request(21, "tools/call", params));

    let (processed, writer) = serve(server, limits(1 << 20, 0), input.as_bytes()).await;

    assert_eq!(processed, 1);
    let lines = response_lines(&writer);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], 21);
    assert_eq!(lines[0]["result"]["isError"], false);
    assert_eq!(lines[0]["result"]["content"][0]["type"], "text");

    let seen = seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, AgentChannel::Mcp);
}

#[tokio::test]
async fn unavailable_backend_is_redacted_over_stdio() {
    let server = McpServer::new(UnavailableBackend, caps(false));
    let params = json!({ "name": "get_portfolio", "arguments": {} });
    let input = format!("{}\n", request(31, "tools/call", params));

    let (_, writer) = serve(server, limits(1 << 20, 0), input.as_bytes()).await;

    let lines = response_lines(&writer);
    assert_eq!(lines[0]["result"]["isError"], true);
    assert_eq!(
        lines[0]["result"]["content"][0]["text"],
        "backend unavailable"
    );
}

// --- redaction ----------------------------------------------------------------

#[tokio::test]
async fn no_output_line_leaks_any_injected_request_value() {
    let (backend, _seen) = RecordingBackend::ok();
    let server = McpServer::new(backend, caps(false));

    let query = request(
        31,
        "tools/call",
        json!({ "name": "search_token", "arguments": { "query": SECRET_QUERY } }),
    );
    let order = request(
        32,
        "tools/call",
        json!({ "name": "cancel_order", "arguments": { "order_id": SECRET_ORDER } }),
    );
    let quote = request(
        33,
        "tools/call",
        json!({
            "name": "get_quote",
            "arguments": {
                "token_in": asset(SECRET_ADDRESS),
                "token_out": asset(USDC_ADDR),
                "amount": { "unit": "usd_micros", "value": 9_876_543_210_123_456_789u64 },
            },
        }),
    );
    // Oversized frame embedding secrets; it is drained and never parsed.
    let oversized = format!(
        "{}{}",
        request(
            34,
            "tools/call",
            json!({ "name": "get_token", "arguments": { "token": asset(SECRET_ADDRESS) } }),
        ),
        " ".repeat(600),
    );

    let mut input: Vec<u8> = Vec::new();
    for frame in [&query, &order, &quote] {
        input.extend_from_slice(frame.as_bytes());
        input.push(b'\n');
    }
    input.extend_from_slice(oversized.as_bytes());
    input.push(b'\n');
    // Non-UTF8 frame that also embeds a secret; the transport must redact it.
    input.extend_from_slice(SECRET_ADDRESS.as_bytes());
    input.extend_from_slice(&[0xff, 0xfe, 0xfd, b'\n']);

    let (processed, writer) = serve(server, limits(512, 0), &input).await;

    assert_eq!(processed, 5);
    assert_eq!(response_lines(&writer).len(), 5);
    let text = output_text(&writer);
    for secret in [SECRET_ADDRESS, SECRET_QUERY, SECRET_ORDER, SECRET_AMOUNT] {
        assert!(
            !text.contains(secret),
            "stdio output leaked {secret}: {text:?}"
        );
    }
}
