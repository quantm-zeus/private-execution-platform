//! P66 Telegram poller: offset ownership, at-most-once dedup, allowlist.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use agent_commands::{AgentCapabilities, AgentChannel, AgentCommand};
use async_trait::async_trait;
use mcp_server::{AgentBackend, BackendOutcome};
use serde_json::{json, Value};
use telegram_bot::{
    ChatAllowlist, PollLimits, TelegramBot, TelegramError, TelegramPoller, TelegramTransport,
    TelegramUpdateSource,
};

struct FakeBackend {
    calls: Arc<Mutex<usize>>,
}

#[async_trait]
impl AgentBackend for FakeBackend {
    async fn execute(&self, _channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
        *self.calls.lock().expect("lock") += 1;
        BackendOutcome::Value(json!({ "orders": [] }))
    }
}

#[derive(Clone, Default)]
struct RecordingTransport {
    sent: Arc<Mutex<Vec<(String, String)>>>,
    fail: bool,
}

#[async_trait]
impl TelegramTransport for RecordingTransport {
    async fn send_message(&self, chat_id: &str, text: &str) -> Result<(), TelegramError> {
        if self.fail {
            return Err(TelegramError::Transport);
        }
        self.sent
            .lock()
            .expect("lock")
            .push((chat_id.to_string(), text.to_string()));
        Ok(())
    }
}

#[derive(Default)]
struct ScriptedSource {
    batches: Mutex<VecDeque<Vec<Value>>>,
    calls: Arc<Mutex<Vec<(i64, usize)>>>,
    fail: bool,
}

impl ScriptedSource {
    fn with_batches(batches: Vec<Vec<Value>>) -> Self {
        Self {
            batches: Mutex::new(batches.into()),
            calls: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            batches: Mutex::new(VecDeque::new()),
            calls: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        }
    }

    fn calls_handle(&self) -> Arc<Mutex<Vec<(i64, usize)>>> {
        self.calls.clone()
    }
}

#[async_trait]
impl TelegramUpdateSource for ScriptedSource {
    async fn get_updates(&self, offset: i64, limit: usize) -> Result<Vec<Value>, TelegramError> {
        self.calls.lock().expect("lock").push((offset, limit));
        if self.fail {
            return Err(TelegramError::Transport);
        }
        Ok(self
            .batches
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or_default())
    }
}

type Poller = TelegramPoller<FakeBackend, RecordingTransport, ScriptedSource>;

#[allow(clippy::type_complexity)]
fn poller(
    source: ScriptedSource,
    allowlist: ChatAllowlist,
    transport: RecordingTransport,
) -> (Poller, Arc<Mutex<usize>>, Arc<Mutex<Vec<(String, String)>>>) {
    let calls = Arc::new(Mutex::new(0));
    let sent = transport.sent.clone();
    let bot = TelegramBot::new(
        FakeBackend {
            calls: calls.clone(),
        },
        AgentCapabilities::new(false, HashSet::new(), 0),
        transport,
    );
    (TelegramPoller::new(bot, source, allowlist), calls, sent)
}

fn update(id: i64, chat: &str, text: &str) -> Value {
    json!({
        "update_id": id,
        "message": { "chat": { "id": chat }, "text": text },
    })
}

fn update_from(id: i64, chat: &str, sender: &str, text: &str) -> Value {
    json!({
        "update_id": id,
        "message": {
            "chat": { "id": chat },
            "from": { "id": sender },
            "text": text,
        },
    })
}

fn allowlist(ids: &[&str]) -> ChatAllowlist {
    ChatAllowlist::new(ids.iter().map(|id| id.to_string()))
}

fn sender_allowlist(chats: &[&str], senders: &[&str]) -> ChatAllowlist {
    ChatAllowlist::new(chats.iter().map(|id| id.to_string()))
        .with_senders(senders.iter().map(|id| id.to_string()))
}

const READ: &str = r#"{"tool":"get_orders"}"#;

#[tokio::test]
async fn allowed_updates_are_dispatched_and_acknowledged() {
    let source =
        ScriptedSource::with_batches(vec![vec![update(1, "42", READ), update(2, "42", READ)]]);
    let (mut poller, calls, sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());

    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.fetched, 2);
    assert_eq!(report.dispatched, 2);
    assert_eq!(report.sent, 2);
    assert_eq!(report.denied, 0);
    assert_eq!(*calls.lock().expect("lock"), 2);
    assert_eq!(sent.lock().expect("lock").len(), 2);
    assert_eq!(poller.next_offset(), 3);
}

#[tokio::test]
async fn redelivered_update_id_is_never_dispatched_twice() {
    let source = ScriptedSource::with_batches(vec![
        vec![update(1, "42", READ)],
        // A faulty source replays update 1 and adds update 2.
        vec![update(1, "42", READ), update(2, "42", READ)],
    ]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());

    let first = poller.poll_once().await.expect("poll");
    assert_eq!(first.dispatched, 1);
    assert_eq!(poller.next_offset(), 2);

    let second = poller.poll_once().await.expect("poll");
    assert_eq!(second.fetched, 2);
    assert_eq!(second.duplicates, 1);
    assert_eq!(second.dispatched, 1);
    assert_eq!(poller.next_offset(), 3);
    // Update 1 was never re-dispatched.
    assert_eq!(*calls.lock().expect("lock"), 2);
}

#[tokio::test]
async fn non_allowlisted_chats_are_denied_and_acknowledged() {
    let source =
        ScriptedSource::with_batches(vec![vec![update(1, "42", READ), update(2, "99", READ)]]);
    let (mut poller, calls, sent) =
        poller(source, allowlist(&["99"]), RecordingTransport::default());

    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 1);
    assert_eq!(report.dispatched, 1);
    assert_eq!(*calls.lock().expect("lock"), 1);
    assert_eq!(sent.lock().expect("lock").len(), 1);
    // Both updates were acknowledged, including the denied one.
    assert_eq!(poller.next_offset(), 3);
}

#[tokio::test]
async fn an_empty_allowlist_denies_every_chat() {
    let source = ScriptedSource::with_batches(vec![vec![update(1, "42", READ)]]);
    let (mut poller, calls, sent) = poller(
        source,
        ChatAllowlist::deny_all(),
        RecordingTransport::default(),
    );

    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 1);
    assert_eq!(report.dispatched, 0);
    assert_eq!(*calls.lock().expect("lock"), 0);
    assert!(sent.lock().expect("lock").is_empty());
    assert_eq!(poller.next_offset(), 2);
}

#[tokio::test]
async fn malformed_updates_are_counted_and_acknowledged() {
    let source = ScriptedSource::with_batches(vec![vec![
        json!({ "message": { "chat": { "id": "42" }, "text": READ } }), // no update_id
        json!({ "update_id": 2 }),                                      // no message
        json!({ "update_id": 3, "message": { "chat": { "id": "42" }, "text": "" } }),
    ]]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());

    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.fetched, 3);
    assert_eq!(report.malformed, 3);
    assert_eq!(report.dispatched, 0);
    assert_eq!(*calls.lock().expect("lock"), 0);
    // The id-less update cannot be acknowledged, but ids 2 and 3 can.
    assert_eq!(poller.next_offset(), 4);
}

#[tokio::test]
async fn a_source_failure_leaves_the_offset_unchanged() {
    let source = ScriptedSource::failing();
    let (mut poller, _calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());

    assert_eq!(poller.poll_once().await, Err(TelegramError::Transport));
    assert_eq!(poller.next_offset(), 0);
}

#[tokio::test]
async fn the_batch_size_is_clamped_and_forwarded() {
    for (requested, expected) in [(0usize, 1usize), (7, 7), (usize::MAX, 100)] {
        let source = ScriptedSource::with_batches(vec![Vec::new()]);
        let calls = source.calls_handle();
        let (mut poller, _backend_calls, _sent) =
            poller(source, allowlist(&["42"]), RecordingTransport::default());
        poller = poller.with_limits(PollLimits { batch: requested });
        poller.poll_once().await.expect("poll");
        assert_eq!(
            calls.lock().expect("lock").as_slice(),
            &[(0, expected)],
            "requested batch {requested}"
        );
        assert_eq!(poller.next_offset(), 0);
    }
}

#[tokio::test]
async fn a_reply_failure_is_counted_and_not_retried() {
    let source = ScriptedSource::with_batches(vec![
        vec![update(1, "42", READ)],
        vec![update(1, "42", READ)],
    ]);
    let transport = RecordingTransport {
        sent: Arc::new(Mutex::new(Vec::new())),
        fail: true,
    };
    let (mut poller, calls, _sent) = poller(source, allowlist(&["42"]), transport);

    let first = poller.poll_once().await.expect("poll");
    assert_eq!(first.dispatched, 1);
    assert_eq!(first.reply_failures, 1);
    assert_eq!(first.sent, 0);
    assert_eq!(poller.next_offset(), 2);

    // The redelivered update is deduplicated, so a failed reply is not retried.
    let second = poller.poll_once().await.expect("poll");
    assert_eq!(second.duplicates, 1);
    assert_eq!(second.dispatched, 0);
    assert_eq!(*calls.lock().expect("lock"), 1);
}

#[tokio::test]
async fn an_unavailable_source_fails_closed() {
    let bot = TelegramBot::new(
        FakeBackend {
            calls: Arc::new(Mutex::new(0)),
        },
        AgentCapabilities::new(false, HashSet::new(), 0),
        RecordingTransport::default(),
    );
    let mut poller = TelegramPoller::new(
        bot,
        telegram_bot::UnavailableUpdateSource::new(),
        allowlist(&["42"]),
    );
    assert_eq!(poller.poll_once().await, Err(TelegramError::Unavailable));
    assert_eq!(poller.next_offset(), 0);
}

#[test]
fn debug_output_is_redacted() {
    let (poller, _calls, _sent) = poller(
        ScriptedSource::default(),
        allowlist(&["secret-chat"]),
        RecordingTransport::default(),
    );
    let rendered = format!("{poller:?}");
    assert!(!rendered.contains("secret-chat"));

    let allowlist = allowlist(&["secret-chat"]);
    let rendered = format!("{allowlist:?}");
    assert!(!rendered.contains("secret-chat"));
}

#[test]
fn resume_from_clamps_a_negative_offset() {
    let build = || {
        poller(
            ScriptedSource::default(),
            allowlist(&["42"]),
            RecordingTransport::default(),
        )
        .0
    };
    assert_eq!(build().resume_from(-5).next_offset(), 0);
    assert_eq!(build().resume_from(i64::MIN).next_offset(), 0);
}

#[tokio::test]
async fn an_out_of_order_batch_still_processes_every_never_acknowledged_update() {
    let source =
        ScriptedSource::with_batches(vec![vec![update(7, "42", READ), update(5, "42", READ)]]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.fetched, 2);
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.dispatched, 2);
    assert_eq!(*calls.lock().expect("lock"), 2);
    assert_eq!(poller.next_offset(), 8);
}

#[tokio::test]
async fn resume_from_seeds_the_acknowledgement_offset() {
    let source =
        ScriptedSource::with_batches(vec![vec![update(5, "42", READ), update(6, "42", READ)]]);
    let calls = source.calls_handle();
    let (fresh, backend_calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let mut resumed = fresh.resume_from(5);
    let report = resumed.poll_once().await.expect("poll");
    assert_eq!(report.duplicates, 0);
    assert_eq!(report.dispatched, 2);
    assert_eq!(*backend_calls.lock().expect("lock"), 2);
    assert_eq!(resumed.next_offset(), 7);
    assert_eq!(calls.lock().expect("lock").as_slice(), &[(5, 100)]);

    // An update below the resumed offset is already acknowledged.
    let source =
        ScriptedSource::with_batches(vec![vec![update(3, "42", READ), update(4, "42", READ)]]);
    let (fresh, backend_calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let mut resumed = fresh.resume_from(5);
    let report = resumed.poll_once().await.expect("poll");
    assert_eq!(report.duplicates, 2);
    assert_eq!(report.dispatched, 0);
    assert_eq!(resumed.next_offset(), 5);
    assert_eq!(*backend_calls.lock().expect("lock"), 0);
}

#[tokio::test]
async fn an_id_less_only_batch_cannot_advance_the_offset() {
    let source = ScriptedSource::with_batches(vec![vec![json!({
        "message": { "chat": { "id": "42" }, "text": READ }
    })]]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.malformed, 1);
    assert_eq!(report.dispatched, 0);
    assert_eq!(poller.next_offset(), 0);
    assert_eq!(*calls.lock().expect("lock"), 0);
}

#[tokio::test]
async fn an_invalid_command_is_counted_separately_from_a_malformed_update() {
    let source = ScriptedSource::with_batches(vec![vec![update(1, "42", "not json")]]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.dispatched, 1);
    assert_eq!(report.invalid_commands, 1);
    assert_eq!(report.malformed, 0);
    assert_eq!(report.sent, 0);
    assert_eq!(poller.next_offset(), 2);
    assert_eq!(*calls.lock().expect("lock"), 0);
}

#[tokio::test]
async fn the_running_offset_is_sent_on_each_fetch() {
    let source = ScriptedSource::with_batches(vec![
        vec![update(1, "42", READ)],
        vec![update(2, "42", READ)],
    ]);
    let calls = source.calls_handle();
    let (mut poller, _calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    poller.poll_once().await.expect("first");
    poller.poll_once().await.expect("second");
    assert_eq!(
        calls.lock().expect("lock").as_slice(),
        &[(0, 100), (2, 100)]
    );
    assert_eq!(poller.next_offset(), 3);
}

#[tokio::test]
async fn a_sender_restricted_allowlist_denies_unlisted_or_missing_senders() {
    let source = ScriptedSource::with_batches(vec![vec![
        update_from(1, "42", "7", READ),
        update_from(2, "42", "8", READ),
        update(3, "42", READ), // no `from` at all
    ]]);
    let (mut poller, calls, sent) = poller(
        source,
        sender_allowlist(&["42"], &["7"]),
        RecordingTransport::default(),
    );

    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.fetched, 3);
    assert_eq!(report.denied, 2);
    assert_eq!(report.dispatched, 1);
    assert_eq!(*calls.lock().expect("lock"), 1);
    assert_eq!(sent.lock().expect("lock").len(), 1);
    // Denied updates are still acknowledged.
    assert_eq!(poller.next_offset(), 4);
}

#[tokio::test]
async fn a_chat_level_allowlist_accepts_any_well_formed_sender() {
    let source = ScriptedSource::with_batches(vec![vec![
        update_from(1, "42", "999", READ),
        update(2, "42", READ),
    ]]);
    let (mut poller, calls, _sent) =
        poller(source, allowlist(&["42"]), RecordingTransport::default());
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 0);
    assert_eq!(report.dispatched, 2);
    assert_eq!(*calls.lock().expect("lock"), 2);
}

#[tokio::test]
async fn a_malformed_sender_id_cannot_satisfy_a_sender_allowlist() {
    // A float `from.id` is not a usable sender id, so the update fails closed.
    let source = ScriptedSource::with_batches(vec![vec![json!({
        "update_id": 1,
        "message": {
            "chat": { "id": "42" },
            "from": { "id": 7.5 },
            "text": READ,
        },
    })]]);
    let (mut poller, calls, _sent) = poller(
        source,
        sender_allowlist(&["42"], &["7"]),
        RecordingTransport::default(),
    );
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 1);
    assert_eq!(report.dispatched, 0);
    assert_eq!(*calls.lock().expect("lock"), 0);
}

#[test]
fn the_sender_allowlist_is_redacted_and_counted() {
    let allowlist = sender_allowlist(&["secret-chat"], &["secret-sender"]);
    assert_eq!(allowlist.len(), 1);
    assert_eq!(allowlist.sender_count(), 1);
    assert!(allowlist.allows("secret-chat", Some("secret-sender")));
    assert!(!allowlist.allows("secret-chat", Some("other")));
    assert!(!allowlist.allows("secret-chat", None));
    assert!(!allowlist.allows("other", Some("secret-sender")));
    let rendered = format!("{allowlist:?}");
    assert!(!rendered.contains("secret-chat"));
    assert!(!rendered.contains("secret-sender"));
}

#[tokio::test]
async fn a_numeric_sender_id_is_normalized_and_matched() {
    let source = ScriptedSource::with_batches(vec![vec![json!({
        "update_id": 1,
        "message": { "chat": { "id": "42" }, "from": { "id": 7 }, "text": READ },
    })]]);
    let (mut poller, calls, _sent) = poller(
        source,
        sender_allowlist(&["42"], &["7"]),
        RecordingTransport::default(),
    );
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 0);
    assert_eq!(report.dispatched, 1);
    assert_eq!(*calls.lock().expect("lock"), 1);
}

#[tokio::test]
async fn an_oversized_sender_id_cannot_satisfy_the_allowlist() {
    let oversized = "7".repeat(65);
    let source = ScriptedSource::with_batches(vec![vec![update_from(1, "42", &oversized, READ)]]);
    let (mut poller, calls, _sent) = poller(
        source,
        sender_allowlist(&["42"], &[oversized.as_str()]),
        RecordingTransport::default(),
    );
    let report = poller.poll_once().await.expect("poll");
    assert_eq!(report.denied, 1);
    assert_eq!(report.dispatched, 0);
    assert_eq!(*calls.lock().expect("lock"), 0);
}
