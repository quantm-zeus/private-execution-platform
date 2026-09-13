//! The Telegram bot core: same MCP dispatcher and authorization path as MCP.

use mcp_server::{tools_call_frame, AgentBackend, McpServer};
use serde_json::Value;

use crate::error::TelegramError;
use crate::transport::TelegramTransport;
use crate::update::{TelegramUpdate, MAX_UPDATE_TEXT_BYTES};

/// Maximum reply length sent back to a chat. A longer user-facing payload is
/// replaced by a static marker rather than truncated (a truncated JSON document
/// would be misleading); chunking is a follow-up.
pub const MAX_REPLY_BYTES: usize = 4096;

/// Static reply used when the user-facing payload exceeds [`MAX_REPLY_BYTES`].
pub const REPLY_TOO_LARGE: &str = "response too large";

/// What the bot did with one update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// A reply was handed to the transport.
    Sent,
    /// Nothing was sent (the dispatcher produced no response).
    Skipped,
}

/// Telegram bot over the shared [`McpServer`] dispatcher and an injected
/// transport.
///
/// Holding the dispatcher (rather than re-implementing authorization) guarantees
/// Telegram runs the identical rule set as MCP: the same `agent-commands`
/// parsing, capability checks, redaction, and backend port. The bot only maps an
/// inbound chat command onto a `tools/call` frame and relays the rendered reply.
pub struct TelegramBot<B: AgentBackend, T: TelegramTransport> {
    server: McpServer<B>,
    transport: T,
}

impl<B: AgentBackend, T: TelegramTransport> TelegramBot<B, T> {
    /// Wires the bot from the shared dispatcher and an outbound transport.
    pub fn new(server: McpServer<B>, transport: T) -> Self {
        Self { server, transport }
    }

    /// Handles one raw Telegram `Update`.
    pub async fn handle_update(&self, update: &Value) -> Result<Delivery, TelegramError> {
        let parsed = TelegramUpdate::parse(update)?;
        self.handle_text(parsed.chat_id(), parsed.text()).await
    }

    /// Handles one already-extracted command from `chat_id`.
    ///
    /// The text must be a structured command object of the shape
    /// `{"tool": "<name>", ...arguments}`; free-form natural language is rejected
    /// as [`TelegramError::Malformed`] (ambiguity fails closed). The command is
    /// forwarded to the shared dispatcher, so a denied, forbidden, or malformed
    /// command never reaches the backend.
    pub async fn handle_text(&self, chat_id: &str, text: &str) -> Result<Delivery, TelegramError> {
        if chat_id.is_empty() || text.is_empty() || text.len() > MAX_UPDATE_TEXT_BYTES {
            return Err(TelegramError::Malformed);
        }
        let frame = tools_call_frame(text).ok_or(TelegramError::Malformed)?;
        let response = self.server.handle(&frame).await;
        if response.is_empty() {
            return Ok(Delivery::Skipped);
        }
        let reply = extract_reply(&response)?;
        let reply = if reply.len() > MAX_REPLY_BYTES {
            REPLY_TOO_LARGE.to_string()
        } else {
            reply
        };
        self.transport.send_message(chat_id, &reply).await?;
        Ok(Delivery::Sent)
    }
}

impl<B: AgentBackend, T: TelegramTransport> std::fmt::Debug for TelegramBot<B, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the backend, capabilities, or transport configuration.
        formatter
            .debug_struct("TelegramBot")
            .finish_non_exhaustive()
    }
}

/// Extracts the redacted/user-facing text from a JSON-RPC response frame.
fn extract_reply(response: &str) -> Result<String, TelegramError> {
    let value: Value = serde_json::from_str(response).map_err(|_| TelegramError::Malformed)?;
    if let Some(text) = value
        .get("result")
        .and_then(|result| result.get("content"))
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
    {
        return Ok(text.to_string());
    }
    if let Some(message) = value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        // JSON-RPC error messages produced by the dispatcher are static.
        return Ok(message.to_string());
    }
    Err(TelegramError::Malformed)
}
