//! Redacted Telegram transport failure classes.

/// A redacted Telegram failure.
///
/// `Debug`/`Display` are payload-free: a failure never renders a chat id, a
/// message body, a tool name, or an amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TelegramError {
    /// The update or command text was malformed or ambiguous.
    #[error("malformed update")]
    Malformed,
    /// No transport is installed (the fail-closed production default).
    #[error("telegram transport unavailable")]
    Unavailable,
    /// The transport itself failed.
    #[error("telegram transport failed")]
    Transport,
}
