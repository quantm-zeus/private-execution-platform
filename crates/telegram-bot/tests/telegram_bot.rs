//! P59 Telegram bot: same dispatcher path, structured-only input, fail-closed.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use agent_commands::{AgentCapabilities, AgentChannel, AgentCommand};
use async_trait::async_trait;
use mcp_server::{AgentBackend, BackendOutcome};
use serde_json::{json, Value};
use telegram_bot::{Delivery, TelegramBot, TelegramError, TelegramTransport, REPLY_TOO_LARGE};

struct FakeBackend {
    outcome: BackendOutcome,
}

#[async_trait]
impl AgentBackend for FakeBackend {
    async fn execute(&self, _channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
        self.outcome.clone()
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

fn capabilities(trading_enabled: bool) -> AgentCapabilities {
    AgentCapabilities::new(trading_enabled, HashSet::new(), 0)
}

fn bot(
    outcome: BackendOutcome,
    trading_enabled: bool,
    transport: RecordingTransport,
) -> TelegramBot<FakeBackend, RecordingTransport> {
    TelegramBot::new(
        FakeBackend { outcome },
        capabilities(trading_enabled),
        transport,
    )
}

/// Records the channel the dispatcher reports for each command.
struct ChannelBackend {
    seen: Arc<Mutex<Vec<AgentChannel>>>,
}

#[async_trait]
impl AgentBackend for ChannelBackend {
    async fn execute(&self, channel: AgentChannel, _command: AgentCommand) -> BackendOutcome {
        self.seen.lock().expect("lock").push(channel);
        BackendOutcome::Value(json!({}))
    }
}

#[tokio::test]
async fn telegram_commands_are_labeled_with_the_telegram_channel() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = TelegramBot::new(
        ChannelBackend { seen: seen.clone() },
        capabilities(false),
        transport,
    );
    bot.handle_text("42", r#"{"tool":"get_orders"}"#)
        .await
        .expect("handled");
    assert_eq!(*seen.lock().expect("lock"), vec![AgentChannel::Telegram]);
}

#[tokio::test]
async fn a_structured_read_command_is_dispatched_and_replied() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = bot(
        BackendOutcome::Value(json!({ "orders": [] })),
        false,
        transport,
    );

    let delivery = bot
        .handle_text("42", r#"{"tool":"get_orders","status":"active"}"#)
        .await
        .expect("handled");
    assert_eq!(delivery, Delivery::Sent);

    let sent = sent.lock().expect("lock");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "42");
    assert_eq!(sent[0].1, r#"{"orders":[]}"#);
}

#[tokio::test]
async fn an_update_is_parsed_and_handled() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = bot(BackendOutcome::Value(json!({"ok": true})), false, transport);

    let update: Value = json!({
        "update_id": 1,
        "message": {
            "message_id": 7,
            "chat": { "id": 99, "type": "private" },
            "text": "{\"tool\":\"get_portfolio\"}"
        }
    });
    assert_eq!(
        bot.handle_update(&update).await.expect("handled"),
        Delivery::Sent
    );
    let sent = sent.lock().expect("lock");
    assert_eq!(sent[0].0, "99");
    assert_eq!(sent[0].1, r#"{"ok":true}"#);
}

#[tokio::test]
async fn natural_language_and_non_text_updates_fail_closed() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = bot(BackendOutcome::Value(json!({})), false, transport);

    // Free-form text is not a structured command.
    assert_eq!(
        bot.handle_text("42", "please buy some token").await,
        Err(TelegramError::Malformed)
    );
    // A non-text update (e.g. a sticker) is malformed, not a command.
    let sticker = json!({ "message": { "chat": { "id": 1 }, "sticker": {} } });
    assert_eq!(
        bot.handle_update(&sticker).await,
        Err(TelegramError::Malformed)
    );
    // A missing chat id is malformed.
    let no_chat = json!({ "message": { "text": "{\"tool\":\"get_orders\"}" } });
    assert_eq!(
        bot.handle_update(&no_chat).await,
        Err(TelegramError::Malformed)
    );
    // A non-integer (float) chat id is malformed.
    let float_chat =
        json!({ "message": { "chat": { "id": 1.5 }, "text": "{\"tool\":\"get_orders\"}" } });
    assert_eq!(
        bot.handle_update(&float_chat).await,
        Err(TelegramError::Malformed)
    );
    assert!(sent.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn duplicate_keys_fail_closed() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = bot(BackendOutcome::Value(json!({})), false, transport);

    assert_eq!(
        bot.handle_text(
            "42",
            r#"{"tool":"get_orders","status":"active","status":"filled"}"#
        )
        .await,
        Err(TelegramError::Malformed)
    );
    assert!(sent.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn forbidden_and_disabled_mutations_never_reach_the_backend() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    // The backend would happily return a value, so any reply other than the
    // denial proves the dispatcher short-circuited.
    let bot = bot(
        BackendOutcome::Value(json!({"hacked": true})),
        false,
        transport,
    );

    let delivery = bot
        .handle_text("42", r#"{"tool":"withdraw","amount":"1"}"#)
        .await
        .expect("handled");
    assert_eq!(delivery, Delivery::Sent);
    let sent_text = sent.lock().expect("lock")[0].1.clone();
    assert_eq!(sent_text, "tool not found");

    let delivery = bot
        .handle_text("42", r#"{"tool":"cancel_order","order_id":"o1"}"#)
        .await
        .expect("handled");
    assert_eq!(delivery, Delivery::Sent);
    let sent_text = sent.lock().expect("lock")[1].1.clone();
    assert_eq!(sent_text, "TradingDisabled");
}

#[tokio::test]
async fn a_large_reply_is_replaced_by_a_static_marker() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let huge = "x".repeat(5000);
    let bot = bot(
        BackendOutcome::Value(json!({ "blob": huge })),
        false,
        transport,
    );

    assert_eq!(
        bot.handle_text("42", r#"{"tool":"get_portfolio"}"#)
            .await
            .expect("handled"),
        Delivery::Sent
    );
    let sent = sent.lock().expect("lock");
    assert_eq!(sent[0].1, REPLY_TOO_LARGE);
}

#[tokio::test]
async fn a_transport_failure_is_reported_without_leaking() {
    let transport = RecordingTransport {
        sent: Arc::new(Mutex::new(Vec::new())),
        fail: true,
    };
    let bot = bot(BackendOutcome::Value(json!({})), false, transport);
    assert_eq!(
        bot.handle_text("42", r#"{"tool":"get_orders"}"#).await,
        Err(TelegramError::Transport)
    );
}

#[tokio::test]
async fn malformed_chat_ids_are_rejected_on_both_entry_points() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        sent: sent.clone(),
        fail: false,
    };
    let bot = bot(BackendOutcome::Value(json!({})), false, transport);
    let command = r#"{"tool":"get_orders"}"#;

    // Direct text entry: empty or oversized chat ids fail closed.
    assert_eq!(
        bot.handle_text("", command).await,
        Err(TelegramError::Malformed)
    );
    let oversized = "c".repeat(65);
    assert_eq!(
        bot.handle_text(&oversized, command).await,
        Err(TelegramError::Malformed)
    );

    // Update entry: non-integer / collection / empty chat ids fail closed.
    for id in [
        json!(true),
        json!(null),
        json!({}),
        json!([]),
        json!(""),
        json!("x".repeat(65)),
    ] {
        let update = json!({ "message": { "chat": { "id": id }, "text": command } });
        assert_eq!(
            bot.handle_update(&update).await,
            Err(TelegramError::Malformed)
        );
    }

    assert!(sent.lock().expect("lock").is_empty());
}
