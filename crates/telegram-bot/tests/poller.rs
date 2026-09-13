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

fn allowlist(ids: &[&str]) -> ChatAllowlist {
    ChatAllowlist::new(ids.iter().map(|id| id.to_string()))
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
