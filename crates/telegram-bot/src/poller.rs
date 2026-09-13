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
//! - **Offset ownership and dedup.** `next_offset` is the acknowledgement
//!   high-water mark: every update with `update_id < next_offset` is already
//!   acknowledged and is never dispatched again. A batch is processed in
//!   ascending `update_id` order, so a source that returns updates out of order
//!   cannot make the high-water mark skip a lower, never-acknowledged update.
//! - **Resumable.** [`TelegramPoller::resume_from`] seeds the offset from a
//!   caller-persisted value, and [`TelegramPoller::next_offset`] exposes it after
//!   each pass. A production binary MUST persist `next_offset` and restore it on
//!   restart; otherwise a crash after a dispatch but before the next `getUpdates`
//!   re-confirms the offset causes that update to be redelivered and dispatched
//!   again. The poller itself performs no I/O, so persistence is the caller's
//!   responsibility.
//! - **Allowlist first.** No chat outside [`ChatAllowlist`] is dispatched; an
//!   empty allowlist denies every chat (fail closed). Denied updates are still
//!   acknowledged so they do not repeat.
//! - **No I/O and no timers.** The source and transport are injected; the poller
//!   exposes one deterministic [`TelegramPoller::poll_once`] pass and never
//!   sleeps or retries. A source failure is returned unchanged (redacted) without
//!   advancing the offset.
//! - **Source contract.** Every returned update MUST carry a non-negative integer
//!   `update_id` (Telegram always does). An update without one cannot be
//!   acknowledged, so it is counted as malformed and the offset is not advanced
//!   for it; a source that repeatedly returns only such updates will fetch them
//!   again, and the caller must treat that as a source fault. A malformed update
//!   *body* with a usable id is acknowledged and skipped.
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
/// Implementations own the transport call and must not retry internally. They
/// MUST return updates in ascending `update_id` order (the poller re-sorts
/// defensively, but the offset semantics assume ascending delivery) and every
/// update MUST carry a non-negative integer `update_id`.
#[async_trait]
pub trait TelegramUpdateSource: Send + Sync {
    /// Returns updates with `update_id >= offset`, at most `limit`, each with an
    /// integer `update_id`.
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
/// All fields are non-semantic counts, safe for telemetry. `dispatched` equals
/// `sent + skipped + invalid_commands + reply_failures` (every update that passed
/// dedup and the allowlist and was handed to the bot).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollReport {
    /// Updates returned by the source.
    pub fetched: usize,
    /// Updates handed to the bot (passed dedup and the allowlist).
    pub dispatched: usize,
    /// Dispatched updates that produced a reply.
    pub sent: usize,
    /// Dispatched updates the dispatcher answered with nothing.
    pub skipped: usize,
    /// Updates dropped because the chat is not allowlisted.
    pub denied: usize,
    /// Updates that could not be acknowledged or parsed (no usable `update_id`,
    /// or a malformed message shape).
    pub malformed: usize,
    /// Dispatched updates whose command text the bot rejected as malformed.
    pub invalid_commands: usize,
    /// Redelivered updates at or below the acknowledgement high-water mark.
    pub duplicates: usize,
    /// Dispatched updates whose reply could not be delivered.
    pub reply_failures: usize,
}

/// Offset-owning Telegram poller.
pub struct TelegramPoller<B: AgentBackend, T: TelegramTransport, S: TelegramUpdateSource> {
    bot: TelegramBot<B, T>,
    source: S,
    allowlist: ChatAllowlist,
    limits: PollLimits,
    next_offset: i64,
}

impl<B: AgentBackend, T: TelegramTransport, S: TelegramUpdateSource> TelegramPoller<B, T, S> {
    /// Wires the poller from a bot, an update source, and a chat allowlist.
    ///
    /// `next_offset` starts at `0`; Telegram update ids start at `1`, so the
    /// first request returns everything pending. Use
    /// [`resume_from`](Self::resume_from) to restore a persisted offset.
    pub fn new(bot: TelegramBot<B, T>, source: S, allowlist: ChatAllowlist) -> Self {
        Self {
            bot,
            source,
            allowlist,
            limits: PollLimits::default(),
            next_offset: 0,
        }
    }

    /// Resumes from a caller-persisted acknowledgement offset.
    ///
    /// Every update with `update_id < next_offset` is treated as already
    /// acknowledged. A negative value is clamped to `0`. A production binary must
    /// persist [`next_offset`](Self::next_offset) after a pass and restore it here
    /// on restart, otherwise the Telegram protocol has not been told the update
    /// was consumed and it may be redelivered.
    pub fn resume_from(mut self, next_offset: i64) -> Self {
        self.next_offset = next_offset.max(0);
        self
    }

    /// Overrides the `getUpdates` batch size.
    pub fn with_limits(mut self, limits: PollLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The acknowledgement offset that will be sent on the next fetch.
    pub fn next_offset(&self) -> i64 {
        self.next_offset
    }

    /// Performs one fetch-and-dispatch pass.
    ///
    /// A source failure is returned unchanged (redacted) and leaves the offset
    /// unchanged, so the next pass retries the same batch. The batch is processed
    /// in ascending `update_id` order and the offset advances monotonically, so
    /// each update is acknowledged and dispatched at most once. Dedup, allowlist,
    /// and malformed drops are counted rather than fatal, so one bad update cannot
    /// block the well-formed updates around it.
    pub async fn poll_once(&mut self) -> Result<PollReport, TelegramError> {
        let batch = self.limits.batch.clamp(1, MAX_POLL_BATCH);
        let mut updates = self.source.get_updates(self.next_offset, batch).await?;
        let mut report = PollReport {
            fetched: updates.len(),
            ..PollReport::default()
        };

        // Ascending order makes the high-water mark sound even if a non-conforming
        // source returns a batch out of order: a lower, never-acknowledged update
        // is processed before a higher one. Updates without a usable id sort to
        // the front and are counted as malformed.
        updates.sort_by_key(|update| parse_update_id(update).unwrap_or(-1));

        for update in &updates {
            let Some(update_id) = parse_update_id(update) else {
                report.malformed = report.malformed.saturating_add(1);
                continue;
            };

            // `next_offset` is the acknowledgement high-water mark: an id below it
            // was consumed in an earlier pass.
            if update_id < self.next_offset {
                report.duplicates = report.duplicates.saturating_add(1);
                continue;
            }
            self.next_offset = update_id.saturating_add(1);

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
                    report.invalid_commands = report.invalid_commands.saturating_add(1);
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
