//! Injected Telegram transport and its fail-closed production default.

use async_trait::async_trait;

use crate::error::TelegramError;

/// Outbound Telegram message transport.
///
/// The bot core never performs I/O: it hands a chat id and an already-rendered
/// (redacted/user-facing) reply to this port. A production implementation talks
/// to the Telegram Bot API; this crate ships none.
#[async_trait]
pub trait TelegramTransport: Send + Sync {
    /// Sends `text` to `chat_id`. Implementations must be idempotent per logical
    /// message and must never log the chat id or the body.
    async fn send_message(&self, chat_id: &str, text: &str) -> Result<(), TelegramError>;
}

/// Fail-closed production default: every send is unavailable.
#[derive(Debug, Default)]
pub struct UnavailableTelegramTransport;

impl UnavailableTelegramTransport {
    /// Builds the fail-closed transport.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TelegramTransport for UnavailableTelegramTransport {
    async fn send_message(&self, _chat_id: &str, _text: &str) -> Result<(), TelegramError> {
        Err(TelegramError::Unavailable)
    }
}
