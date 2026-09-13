//! Inbound Telegram update parsing.

use serde_json::Value;

use crate::error::TelegramError;

/// Maximum accepted command-text length (Telegram caps a message near 4 KiB of
/// UTF-16; 16 KiB of UTF-8 is a safe outer bound and keeps parsing bounded).
pub const MAX_UPDATE_TEXT_BYTES: usize = 16 * 1024;

/// A parsed text message: one chat and the structured command text.
///
/// Fields are private and `Debug` is redacted so a chat id or command body can
/// never reach a log through this type.
pub struct TelegramUpdate {
    chat_id: String,
    text: String,
}

impl TelegramUpdate {
    /// Parses a Telegram `Update` JSON object.
    ///
    /// Only a `message` with a `chat.id` (integer or string) and a non-empty
    /// `text` within [`MAX_UPDATE_TEXT_BYTES`] is accepted; anything else is
    /// [`TelegramError::Malformed`] and is never dispatched.
    pub fn parse(update: &Value) -> Result<Self, TelegramError> {
        let message = update.get("message").ok_or(TelegramError::Malformed)?;
        let chat = message.get("chat").ok_or(TelegramError::Malformed)?;
        let chat_id = match chat.get("id") {
            Some(Value::Number(number)) => number.to_string(),
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            _ => return Err(TelegramError::Malformed),
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
            text: text.to_string(),
        })
    }

    /// The destination chat id.
    pub fn chat_id(&self) -> &str {
        &self.chat_id
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
