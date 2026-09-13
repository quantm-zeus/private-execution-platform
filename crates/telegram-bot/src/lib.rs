//! # Telegram bot transport (Phase 6 S5)
//!
//! The Telegram channel of the unified agent surface, layered on the **same**
//! [`mcp_server::McpServer`] dispatcher and `agent-commands` authorization core
//! as MCP. There is no Telegram-specific privilege and no second rule set: the
//! bot maps an inbound structured command onto a `tools/call` frame, forwards it
//! to the shared dispatcher, and relays the rendered reply through an injected
//! [`TelegramTransport`].
//!
//! ## Boundaries
//! - **Structured input only.** The command text must be a JSON object of the
//!   shape `{"tool": "<name>", ...arguments}`. Free-form natural language fails
//!   closed ([`TelegramError::Malformed`]) rather than being guessed at; the
//!   amount-unit ambiguity rule therefore cannot be bypassed on this channel.
//! - **Same authorization path.** A denied, forbidden, unknown, or malformed
//!   command is handled by the dispatcher exactly as over MCP and never reaches
//!   [`mcp_server::AgentBackend::execute`]. `TRADING_ENABLED=false` denies every
//!   mutation here too. (As over MCP, the dispatcher asks the backend for a
//!   trusted valuation before authorization; the default returns `None`.)
//! - **No I/O and no signing.** The core performs no network I/O; the only
//!   outbound capability is the injected transport, whose production default
//!   ([`UnavailableTelegramTransport`]) fails closed. This crate has no
//!   `privy`/`execution-relay`/`limit-engine` dependency and does not sign.
//! - **Redaction.** Failures are payload-free enums and every type's `Debug` is
//!   redacted, so a chat id, command body, or amount cannot reach a log.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.
//!
//! ## Residuals (transport wiring, before a live inbound poller)
//! - There is no chat/sender allowlist hook: any chat whose update reaches
//!   [`TelegramBot::handle_update`] is authorized with the wallet's
//!   capabilities. Harmless while the transport is unavailable or trading is
//!   disabled, but an allowlist must be installed before enabling trading.
//! - There is no `update_id` deduplication here: a redelivered update is
//!   re-dispatched. The offset-owning poller must own dedup/at-most-once.

#![forbid(unsafe_code)]

mod bot;
mod error;
mod transport;
mod update;

pub use bot::{Delivery, TelegramBot, MAX_REPLY_BYTES, REPLY_TOO_LARGE};
pub use error::TelegramError;
pub use transport::{TelegramTransport, UnavailableTelegramTransport};
pub use update::{TelegramUpdate, MAX_CHAT_ID_BYTES, MAX_UPDATE_TEXT_BYTES};
