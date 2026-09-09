//! Integration tests for the NATS EventBus implementation (P0-15).
//!
//! These tests run against a REAL NATS 2.11 server via `NATS_TEST_URL`
//! (compose exposes `nats://127.0.0.1:4222`). They prove the EventBus
//! contract end-to-end: publish of a validated envelope reaches a
//! subscriber with the same subject and payload bytes, per-subject
//! ordering is preserved, invalid envelopes are rejected before any
//! network contact, and health reflects connection state (including the
//! unavailable path via a dead URL). Default package/workspace tests
//! need no broker; this target is feature-gated by `nats-integration`.

use std::time::Duration;

use futures_util::StreamExt;
use storage::nats::NatsEventBus;
use storage::{EventBus, EventSubject, InternalEventEnvelope, StorageError};

const NATS_ADVISORY_NOTE: &str = "NATS_TEST_URL must point at the compose/test NATS server";

fn test_url() -> String {
    std::env::var("NATS_TEST_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .expect(NATS_ADVISORY_NOTE)
}

fn envelope(event_id: &str, subject: EventSubject) -> InternalEventEnvelope {
    InternalEventEnvelope {
        event_id: event_id.to_string(),
        subject,
        schema_version: 1,
        occurred_at_ms: 1_000,
        payload: vec![0xE7; 32],
    }
}

#[tokio::test]
async fn publish_reaches_subscriber_with_subject_and_payload() {
    let url = test_url();
    let bus = NatsEventBus::connect(&url)
        .await
        .expect("connect to test NATS");

    let mut subscriber = bus
        .client
        .subscribe("order.created".to_string())
        .await
        .expect("subscribe");

    bus.publish(envelope("evt-1", EventSubject::OrderCreated))
        .await
        .expect("publish");

    let message = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
        .await
        .expect("timed out waiting for published message")
        .expect("subscription ended unexpectedly");

    assert_eq!(message.subject.as_str(), "order.created");
    let decoded: InternalEventEnvelope = serde_json::from_slice(&message.payload)
        .expect("published payload must decode to the envelope");
    assert_eq!(decoded.event_id, "evt-1");
    assert_eq!(decoded.subject, EventSubject::OrderCreated);
    assert_eq!(decoded.payload, vec![0xE7; 32]);
}

#[tokio::test]
async fn per_subject_publish_order_is_preserved() {
    let url = test_url();
    let bus = NatsEventBus::connect(&url)
        .await
        .expect("connect to test NATS");

    let mut subscriber = bus
        .client
        .subscribe("order.filled".to_string())
        .await
        .expect("subscribe");

    for index in 0..10 {
        bus.publish(envelope(
            &format!("evt-fill-{index}"),
            EventSubject::OrderFilled,
        ))
        .await
        .expect("publish in order");
    }

    for index in 0..10 {
        let message = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
            .await
            .expect("timed out waiting for ordered message")
            .expect("subscription ended unexpectedly");
        let decoded: InternalEventEnvelope =
            serde_json::from_slice(&message.payload).expect("payload must decode");
        assert_eq!(
            decoded.event_id,
            format!("evt-fill-{index}"),
            "per-subject order must match publish order"
        );
    }
}

#[tokio::test]
async fn invalid_envelopes_are_rejected_before_network_contact() {
    let url = test_url();
    let bus = NatsEventBus::connect(&url)
        .await
        .expect("connect to test NATS");

    let mut empty_id = envelope("", EventSubject::OrderTriggered);
    empty_id.event_id = "  ".to_string();
    assert!(matches!(
        bus.publish(empty_id).await,
        Err(StorageError::Invalid(_))
    ));

    let mut zero_schema = envelope("evt-bad", EventSubject::OrderTriggered);
    zero_schema.schema_version = 0;
    assert!(matches!(
        bus.publish(zero_schema).await,
        Err(StorageError::Invalid(_))
    ));

    let mut empty_payload = envelope("evt-bad", EventSubject::OrderTriggered);
    empty_payload.payload.clear();
    assert!(matches!(
        bus.publish(empty_payload).await,
        Err(StorageError::Invalid(_))
    ));
}

#[tokio::test]
async fn health_reports_healthy_and_unavailable() {
    let url = test_url();
    let bus = NatsEventBus::connect(&url)
        .await
        .expect("connect to test NATS");
    assert_eq!(bus.health().await.status, storage::ComponentHealth::Healthy);

    // Dead URL: connect fails closed with the opaque unavailable error;
    // the URL text is never forwarded.
    let err = NatsEventBus::connect("nats://127.0.0.1:1")
        .await
        .expect_err("dead url must fail");
    assert_eq!(err, StorageError::Unavailable);

    // Empty URL is rejected client-side.
    assert!(matches!(
        NatsEventBus::connect("   ").await,
        Err(StorageError::Unavailable)
    ));
}
