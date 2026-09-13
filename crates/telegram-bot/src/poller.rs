//! Inbound Telegram poller: offset ownership, at-most-once dedup, allowlist.
//!
//! The bot core ([`crate::bot`]) handles one update at a time and performs no
//! I/O of its own. This module is the offset-owning driver that a production
//! binary runs: it fetches batches from an injected [`TelegramUpdateSource`],
//! advances the Telegram `getUpdates` offset, deduplicates redelivered
//! `update_id`s, enforces an explicit chat allowlist, and dispatches each
//! accepted update through the shared [`TelegramBot`] (and therefore the same
//! `agent-commands` authorization path as MCP).
//!
//! ## Boundaries
//! - **Offset ownership and dedup.** `next_offset` advances to
//!   `max(update_id) + 1` over every fetched update, including denied and
//!   malformed ones, so an update is acknowledged at most once. A redelivered
//!   `update_id` at or below the last processed id is counted as a duplicate and
//!   never dispatched, so a retrying source cannot double-execute a mutation.
//! - **Allowlist first.** No chat outside [`ChatAllowlist`] is dispatched; an
//!   empty allowlist denies every chat (fail closed). Denied updates are still
//!   acknowledged so they do not repeat.
//! - **No I/O and no timers.** The source and transport are injected; the poller
//!   exposes one deterministic [`TelegramPoller::poll_once`] pass and never
//!   sleeps or retries. A source failure is surfaced as
//!   [`TelegramError::Transport`] without advancing the offset.
//! - **Redaction.** Failures are payload-free, and `Debug` never renders a chat
//!   id, an update body, or the allowlist contents.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

use std::collections::HashSet;

use async_trait::async_trait;
use mcp_server::AgentBackend;
use serde_json::Value;

use crate::bot::{Delivery, TelegramBot};
use crate::error::TelegramError;
use crate::transport::TelegramTransport;
use crate::update::TelegramUpdate;

/// Default `getUpdates` batch size.
pub const DEFAULT_POLL_BATCH: usize = 100;
/// Hard cap on a single `getUpdates` batch.
pub const MAX_POLL_BATCH: usize = 100;

/// One raw batch source for Telegram `getUpdates`.
///
/// Implementations own the transport call and must not retry internally: the
/// poller advances the offset only after a batch is accepted, and a retry of a
/// half-consumed batch is exactly what the dedup window is for.
#[async_trait]
pub trait TelegramUpdateSource: Send + Sync {
    /// Returns updates with `update_id >= offset`, at most `limit`, in ascending
    /// `update_id` order.
    async fn get_updates(&self, offset: i64, limit: usize) -> Result<Vec<Value>, TelegramError>;
}

/// Fail-closed default source: no updates are ever available.
#[derive(Debug, Default)]
pub struct UnavailableUpdateSource;

impl UnavailableUpdateSource {
    /// Builds the fail-closed source.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TelegramUpdateSource for UnavailableUpdateSource {
    async fn get_updates(&self, _offset: i64, _limit: usize) -> Result<Vec<Value>, TelegramError> {
        Err(TelegramError::Unavailable)
    }
}

/// Explicit chat allowlist.
///
/// An empty allowlist denies every chat, so a deployment that forgets to
/// configure one cannot accidentally authorize a random chat.
#[derive(Clone, Default)]
pub struct ChatAllowlist {
    allowed: HashSet<String>,
}

impl ChatAllowlist {
    /// Builds an allowlist from the permitted chat ids.
    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: ids.into_iter().collect(),
        }
    }

    /// An allowlist that denies every chat.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Whether `chat_id` may be dispatched.
    pub fn allows(&self, chat_id: &str) -> bool {
        self.allowed.contains(chat_id)
    }

    /// Number of allowed chats.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether the allowlist is empty (denies everything).
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

impl std::fmt::Debug for ChatAllowlist {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the permitted chat ids.
        formatter
            .debug_struct("ChatAllowlist")
            .field("allowed", &self.allowed.len())
            .finish()
    }
}

/// Bounded `getUpdates` configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollLimits {
    /// Requested batch size; clamped to `1..=MAX_POLL_BATCH` per pass.
    pub batch: usize,
}

impl Default for PollLimits {
    fn default() -> Self {
        Self {
            batch: DEFAULT_POLL_BATCH,
        }
    }
}

/// Counts from one [`TelegramPoller::poll_once`] pass.
///
/// All fields are non-semantic counts, safe for telemetry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollReport {
    /// Updates returned by the source.
    pub fetched: usize,
    /// Updates that passed dedup and the allowlist and were handed to the bot.
    pub dispatched: usize,
    /// Dispatched updates that produced a reply.
    pub sent: usize,
    /// Dispatched updates the dispatcher answered with nothing.
    pub skipped: usize,
    /// Updates dropped because the chat is not allowlisted.
    pub denied: usize,
    /// Updates dropped because they were malformed or had no usable id.
    pub malformed: usize,
    /// Redelivered updates dropped by the dedup window.
    pub duplicates: usize,
    /// Dispatch attempts whose reply could not be delivered.
    pub reply_failures: usize,
}

/// Offset-owning Telegram poller.
pub struct TelegramPoller<B: AgentBackend, T: TelegramTransport, S: TelegramUpdateSource> {
    bot: TelegramBot<B, T>,
    source: S,
    allowlist: ChatAllowlist,
    limits: PollLimits,
    next_offset: i64,
    last_processed: i64,
}

impl<B: AgentBackend, T: TelegramTransport, S: TelegramUpdateSource> TelegramPoller<B, T, S> {
    /// Wires the poller from a bot, an update source, and a chat allowlist.
    ///
    /// `next_offset` starts at `0`; Telegram update ids start at `1`, so the
    /// first request returns everything pending.
    pub fn new(bot: TelegramBot<B, T>, source: S, allowlist: ChatAllowlist) -> Self {
        Self {
            bot,
            source,
            allowlist,
            limits: PollLimits::default(),
            next_offset: 0,
            last_processed: -1,
        }
    }

    /// Overrides the `getUpdates` batch size.
    pub fn with_limits(mut self, limits: PollLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The offset that will be sent on the next fetch.
    pub fn next_offset(&self) -> i64 {
        self.next_offset
    }

    /// Performs one fetch-and-dispatch pass.
    ///
    /// A source failure is returned unchanged (redacted) and leaves the offset
    /// unchanged, so the next pass retries the same batch. Every fetched update
    /// then advances the offset at most once; dedup, allowlist, and malformed
    /// drops are counted rather than fatal, so one bad update cannot wedge the
    /// loop.
    pub async fn poll_once(&mut self) -> Result<PollReport, TelegramError> {
        let batch = self.limits.batch.clamp(1, MAX_POLL_BATCH);
        let updates = self.source.get_updates(self.next_offset, batch).await?;
        let mut report = PollReport {
            fetched: updates.len(),
            ..PollReport::default()
        };

        for update in &updates {
            // Telegram always carries a non-negative integer `update_id`; an
            // update without one cannot be acknowledged, so it is counted and
            // never dispatched.
            let Some(update_id) = parse_update_id(update) else {
                report.malformed = report.malformed.saturating_add(1);
                continue;
            };

            // Acknowledge the id before any content check so a denied or
            // malformed update does not repeat forever.
            let duplicate = update_id <= self.last_processed;
            if update_id > self.last_processed {
                self.last_processed = update_id;
            }
            let next = update_id.saturating_add(1);
            if next > self.next_offset {
                self.next_offset = next;
            }
            if duplicate {
                report.duplicates = report.duplicates.saturating_add(1);
                continue;
            }

            let parsed = match TelegramUpdate::parse(update) {
                Ok(parsed) => parsed,
                Err(_) => {
                    report.malformed = report.malformed.saturating_add(1);
                    continue;
                }
            };
            if !self.allowlist.allows(parsed.chat_id()) {
                report.denied = report.denied.saturating_add(1);
                continue;
            }

            match self.bot.handle_text(parsed.chat_id(), parsed.text()).await {
                Ok(Delivery::Sent) => {
                    report.dispatched = report.dispatched.saturating_add(1);
                    report.sent = report.sent.saturating_add(1);
                }
                Ok(Delivery::Skipped) => {
                    report.dispatched = report.dispatched.saturating_add(1);
                    report.skipped = report.skipped.saturating_add(1);
                }
                // A malformed command never reaches the backend; the update is
                // already acknowledged, so it is not retried.
                Err(TelegramError::Malformed) => {
                    report.dispatched = report.dispatched.saturating_add(1);
                    report.malformed = report.malformed.saturating_add(1);
                }
                // Any other dispatch failure (for example a reply the transport
                // could not deliver) is counted and never re-dispatched, because
                // the command may already have taken effect.
                Err(_) => {
                    report.dispatched = report.dispatched.saturating_add(1);
                    report.reply_failures = report.reply_failures.saturating_add(1);
                }
            }
        }

        Ok(report)
    }
}

impl<B: AgentBackend, T: TelegramTransport, S: TelegramUpdateSource> std::fmt::Debug
    for TelegramPoller<B, T, S>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bot, source, allowlist, or offset state.
        formatter
            .debug_struct("TelegramPoller")
            .finish_non_exhaustive()
    }
}

/// Reads a Telegram `update_id` (a non-negative JSON integer).
fn parse_update_id(update: &Value) -> Option<i64> {
    match update.get("update_id")? {
        Value::Number(number) => number.as_i64().filter(|id| *id >= 0),
        _ => None,
    }
}
