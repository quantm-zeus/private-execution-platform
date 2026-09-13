//! Inbound Telegram update parsing.

use serde_json::Value;

use crate::error::TelegramError;

/// Maximum accepted command-text length (Telegram caps a message near 4 KiB of
/// UTF-16; 16 KiB of UTF-8 is a safe outer bound and keeps parsing bounded).
pub const MAX_UPDATE_TEXT_BYTES: usize = 16 * 1024;

/// Maximum accepted chat-id length. Telegram ids are small integers; the bound
/// only stops a malicious update from carrying an unbounded destination string.
pub const MAX_CHAT_ID_BYTES: usize = 64;

/// Maximum accepted sender-id length; same rationale as [`MAX_CHAT_ID_BYTES`].
pub const MAX_SENDER_ID_BYTES: usize = 64;

/// A parsed text message: one chat, an optional sender, and the structured
/// command text.
///
/// Fields are private and `Debug` is redacted so a chat id, sender id, or
/// command body can never reach a log through this type.
pub struct TelegramUpdate {
    chat_id: String,
    sender_id: Option<String>,
    text: String,
}

impl TelegramUpdate {
    /// Parses a Telegram `Update` JSON object.
    ///
    /// Only a `message` with a `chat.id` (a JSON integer, or a non-empty string
    /// within [`MAX_CHAT_ID_BYTES`]) and a non-empty `text` within
    /// [`MAX_UPDATE_TEXT_BYTES`] is accepted; anything else (including a
    /// floating-point id) is [`TelegramError::Malformed`] and is never
    /// dispatched. A `message.from.id` is captured when it is a JSON integer or
    /// a bounded non-empty string; a missing or malformed sender is `None`, which
    /// a sender-restricted allowlist denies.
    pub fn parse(update: &Value) -> Result<Self, TelegramError> {
        let message = update.get("message").ok_or(TelegramError::Malformed)?;
        let chat = message.get("chat").ok_or(TelegramError::Malformed)?;
        let chat_id = match chat.get("id") {
            // Telegram sends an integer; reject a float (ambiguous and not a
            // valid chat id) rather than stringifying it.
            Some(Value::Number(number)) if number.is_i64() || number.is_u64() => number.to_string(),
            Some(Value::String(value)) if !value.is_empty() && value.len() <= MAX_CHAT_ID_BYTES => {
                value.clone()
            }
            _ => return Err(TelegramError::Malformed),
        };
        // A missing or malformed sender is not fatal to the update; it simply
        // cannot satisfy a sender-restricted allowlist.
        let sender_id = match message.get("from").and_then(|from| from.get("id")) {
            Some(Value::Number(number)) if number.is_i64() || number.is_u64() => {
                Some(number.to_string())
            }
            Some(Value::String(value))
                if !value.is_empty() && value.len() <= MAX_SENDER_ID_BYTES =>
            {
                Some(value.clone())
            }
            _ => None,
        };
        let text = message
            .get("text")
            .and_then(Value::as_str)
            .ok_or(TelegramError::Malformed)?;
        if text.is_empty() || text.len() > MAX_UPDATE_TEXT_BYTES {
            return Err(TelegramError::Malformed);
        }
        Ok(Self {
            chat_id,
            sender_id,
            text: text.to_string(),
        })
    }

    /// The destination chat id.
    pub fn chat_id(&self) -> &str {
        &self.chat_id
    }

    /// The sender user id, when the update carried a well-formed one.
    pub fn sender_id(&self) -> Option<&str> {
        self.sender_id.as_deref()
    }

    /// The structured command text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Debug for TelegramUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelegramUpdate")
            .finish_non_exhaustive()
    }
}
