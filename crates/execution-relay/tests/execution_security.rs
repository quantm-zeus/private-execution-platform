//! P75 — adversarial execution-security suite over the relay sign/bind path.
//!
//! Test-only. Every case reuses the deterministic `support` fakes; no network,
//! wall clock, key material, or real chain is involved. The suite exercises:
//! genuinely concurrent duplicate execution, the full tamper matrix over the
//! sign/bind path, reservation-store faults, an exhaustive redaction sweep over
//! the error/outcome surface, and kill-switch precedence.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chain_types::ChainId;
use domain::OrderStatus;
use execution_relay::{
    ChainHealth, ChainHealthBreaker, ObservedFill, RelayError, RelayOutcome, SignedPayload,
    SubmissionState, SubmitRequest, MAX_SIGNED_PAYLOAD_BYTES,
};
use support::{
    approved, engine, intent_with_idempotency, other_payload, other_signing_request, payload,
    policy_context, prepared, preview, route, signed_ref_for, signing_request, MockAdapter,
    MockSigning, MockSource, MockStore, RelayHarness, NOW_MS,
};

/// An async barrier that guarantees simultaneous entry into a race.
///
/// `tokio::sync::Barrier` is unavailable to this crate's test build — the
/// workspace `tokio` does not enable the `sync` feature and this slice is
/// forbidden from touching `Cargo.toml` — so this yield-based barrier provides
/// the same guarantee with no new dependency. It never blocks a worker thread:
/// early arrivals yield, allowing the remaining tasks to be scheduled.
struct SpinBarrier {
    arrived: AtomicUsize,
    total: usize,
}

impl SpinBarrier {
    fn new(total: usize) -> Self {
        Self {
            arrived: AtomicUsize::new(0),
            total,
        }
    }

    async fn wait(&self) {
        let prior = self.arrived.fetch_add(1, Ordering::SeqCst);
        if prior + 1 == self.total {
            return;
        }
        while self.arrived.load(Ordering::SeqCst) < self.total {
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_duplicate_execute_signs_and_submits_once() {
    const TASKS: usize = 8;

    let harness = Arc::new(RelayHarness::standard());
    let barrier = Arc::new(SpinBarrier::new(TASKS));

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let harness = Arc::clone(&harness);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            harness.relay.execute(harness.input(NOW_MS)).await
        }));
    }

    let mut outcomes = Vec::with_capacity(TASKS);
    for handle in handles {
        outcomes.push(handle.await.expect("join"));
    }

    assert_eq!(
        harness.signing.calls.load(Ordering::SeqCst),
        1,
        "concurrent duplicates must sign exactly once"
    );
    assert_eq!(
        harness.adapter.submits.load(Ordering::SeqCst),
        1,
        "concurrent duplicates must submit exactly once"
    );
    assert!(
        harness.store.reserve_calls.load(Ordering::SeqCst) <= TASKS,
        "no reservation call may be duplicated beyond one per task"
    );

    // Every task must return the same *canonical* result. The process-local
    // reservation store may hand a duplicate that arrives after `reserve` but
    // before the winner records its terminal outcome the transient `Reserved` or
    // `Signed` journal state; all three states are coalesced duplicates that map
    // to the same `OrderStatus::Executing`, and none of them signs or submits.
    let mut terminal = 0usize;
    for outcome in &outcomes {
        let outcome = outcome.as_ref().expect("no task may error");
        assert!(
            matches!(
                outcome,
                RelayOutcome::Reserved | RelayOutcome::Signed | RelayOutcome::Submitted { .. }
            ),
            "unexpected duplicate outcome: {outcome:?}"
        );
        assert_eq!(outcome.order_status(), OrderStatus::Executing);
        if matches!(outcome, RelayOutcome::Submitted { .. }) {
            terminal += 1;
        }
    }
    assert!(
        terminal >= 1,
        "the winning task must return the terminal submission outcome"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_keys_each_submit_once() {
    const TASKS: usize = 8;

    let harness = Arc::new(RelayHarness::standard());
    let barrier = Arc::new(SpinBarrier::new(TASKS));

    let mut handles = Vec::with_capacity(TASKS);
    for index in 0..TASKS {
        let harness = Arc::clone(&harness);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let intent = intent_with_idempotency(&format!("idem-{index}"), index as u64 + 1);
            let context = policy_context();
            let creator = engine(true);
            let approved = approved(&creator, &intent);
            let prepared = prepared(&intent);
            let route = route();
            let preview = preview(&intent, &route);
            barrier.wait().await;
            let input = execution_relay::RelayExecutionInput {
                intent: &intent,
                policy_context: &context,
                prepared: &prepared,
                approved: &approved,
                route: &route,
                preview: &preview,
                now_ms: NOW_MS,
            };
            harness.relay.execute(input).await
        }));
    }

    let mut outcomes = Vec::with_capacity(TASKS);
    for handle in handles {
        outcomes.push(handle.await.expect("join"));
    }

    assert_eq!(
        harness.signing.calls.load(Ordering::SeqCst),
        TASKS,
        "distinct keys must never be falsely coalesced"
    );
    assert_eq!(
        harness.adapter.submits.load(Ordering::SeqCst),
        TASKS,
        "each distinct key must submit exactly once"
    );
    for outcome in &outcomes {
        assert!(matches!(
            outcome.as_ref().expect("no task may error"),
            RelayOutcome::Submitted { .. }
        ));
    }
}

#[tokio::test]
async fn reservation_conflict_never_signs() {
    let harness = RelayHarness::build(
        engine(true),
        ChainHealthBreaker::new(2, 5_000),
        MockStore::conflicting(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let result = harness.relay.execute(harness.input(NOW_MS)).await;

    assert_eq!(result, Err(RelayError::IdempotencyConflict));
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.signing.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn record_signed_failure_fails_before_submit() {
    let harness = RelayHarness::build(
        engine(true),
        ChainHealthBreaker::new(2, 5_000),
        MockStore::failing_record_signed(),
        MockAdapter::accepting(),
        MockSource::standard(),
        MockSigning::ok(),
    );

    let outcome = harness
        .relay
        .execute(harness.input(NOW_MS))
        .await
        .expect("execute");

    assert_eq!(outcome, RelayOutcome::FailedBeforeSubmit);
    assert_eq!(
        harness.store.record_signed_calls.load(Ordering::SeqCst),
        1,
        "the durable record must be attempted exactly once"
    );
    assert_eq!(
        harness.signing.calls.load(Ordering::SeqCst),
        1,
        "the sign may have happened before the durable record failed"
    );
    assert_eq!(
        harness.adapter.submits.load(Ordering::SeqCst),
        0,
        "a record-signed failure must never submit"
    );
}

/// Every step of the sign/bind path must fail closed, with zero submissions.
#[tokio::test]
async fn tamper_matrix_never_submits() {
    // (a) the payload source cannot produce the pre-signing payload.
    {
        let source = MockSource::standard();
        source.set_fail_pre(true);
        let harness = RelayHarness::build(
            engine(true),
            ChainHealthBreaker::new(2, 5_000),
            MockStore::new(),
            MockAdapter::accepting(),
            source,
            MockSigning::ok(),
        );
        assert_eq!(
            harness.relay.execute(harness.input(NOW_MS)).await,
            Err(RelayError::MissingSignedPayload)
        );
        assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    }

    // (b) the post-signing payload digest differs from the committed digest.
    {
        let source = MockSource::standard();
        source.set_post_override(other_payload());
        let harness = RelayHarness::build(
            engine(true),
            ChainHealthBreaker::new(2, 5_000),
            MockStore::new(),
            MockAdapter::accepting(),
            source,
            MockSigning::ok(),
        );
        assert_eq!(
            harness.relay.execute(harness.input(NOW_MS)).await,
            Err(RelayError::SignedPayloadDigestMismatch)
        );
        assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    }

    // (c) the signed reference does not attest to the signing request.
    {
        let harness = RelayHarness::standard();
        let other = other_signing_request();
        harness.signing.set_override_digest(*other.request_digest());
        assert_eq!(
            harness.relay.execute(harness.input(NOW_MS)).await,
            Err(RelayError::SigningRequestMismatch)
        );
        assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
    }

    // (d) a chain differing from the signed request chain is rejected at bind
    //     time. `execute` always binds the intent chain, so the guard is
    //     exercised directly on the fully bound request.
    {
        let signing = signing_request();
        let signed = signed_ref_for(&signing, "signed-ref");
        let error = SubmitRequest::bind(&signing, &signed, &payload(), &ChainId::Ethereum)
            .expect_err("a different chain must be rejected");
        assert_eq!(error, RelayError::ChainMismatch);
    }

    // (e) an empty signed payload is rejected when the payload is constructed.
    {
        let error = SignedPayload::new(Vec::new()).expect_err("an empty payload must be rejected");
        assert_eq!(error, RelayError::SignedPayloadEmpty);
    }

    // (f) an oversized signed payload is rejected when it is constructed.
    {
        let error = SignedPayload::new(vec![0u8; MAX_SIGNED_PAYLOAD_BYTES + 1])
            .expect_err("an oversized payload must be rejected");
        assert_eq!(error, RelayError::SignedPayloadTooLarge);
    }

    // (g) the adapter reports the chain unavailable.
    {
        let adapter = MockAdapter::accepting();
        adapter.set_health(ChainHealth::Unavailable);
        let harness = RelayHarness::build(
            engine(true),
            ChainHealthBreaker::new(2, 5_000),
            MockStore::new(),
            adapter,
            MockSource::standard(),
            MockSigning::ok(),
        );
        assert_eq!(
            harness.relay.execute(harness.input(NOW_MS)).await,
            Err(RelayError::ChainHealthUnavailable)
        );
        assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
        assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 0);
    }
}

/// Hostile payload values that must never reach a rendered surface.
const HOSTILE: &str = "0xwallet-intent-idem-asset-pool-http://deadbeef-1234567890";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// A `Debug` rendering, checked for every sensitive token.
    Debug,
    /// A static `Display` message. The `IdempotencyConflict` message
    /// legitimately contains the word "idempotency" (and therefore the
    /// substring "idem"); that is the error's own name, not a key value, so the
    /// generic `idem` token is checked on `Debug` only.
    Display,
}

/// Names every [`RelayError`] variant exactly once and expands to both the swept
/// array and a wildcard-free `match` over the same list.
///
/// Because the generated `match` is exhaustive and has no wildcard arm, adding a
/// `RelayError` variant makes this macro invocation fail to compile until the
/// variant is listed here — and the array is built from that same single list, so
/// the sweep can never silently omit a variant.
macro_rules! relay_error_sweep {
    ($($variant:ident),+ $(,)?) => {{
        let _: fn(&RelayError) = |error| match error {
            $(RelayError::$variant => {}),+
        };
        [$(RelayError::$variant),+]
    }};
}

#[test]
fn every_relay_error_variant_is_redacted() {
    let errors = relay_error_sweep![
        TradingDisabled,
        ChainHealthUnavailable,
        SigningFailed,
        SigningRequestMismatch,
        ChainMismatch,
        MissingSignedPayload,
        SignedPayloadEmpty,
        SignedPayloadTooLarge,
        SignedPayloadDigestMismatch,
        ReservationUnavailable,
        IdempotencyConflict,
        AdapterUnavailable,
        AdapterRejected,
        AdapterTimeout,
        UnknownSubmissionState,
        InvalidTransition,
        StoreUnavailable,
    ];

    for error in &errors {
        assert_redacted(&format!("{error:?}"), Surface::Debug);
        assert_redacted(&format!("{error}"), Surface::Display);
    }
}

/// Lists every [`RelayOutcome`] variant exactly once with its hostile carrier
/// and redaction label, then expands to both the carrier array and a
/// wildcard-free `match` over that same list.
///
/// The match has no wildcard arm, so a new `RelayOutcome` variant — or a
/// duplicated/omitted entry — fails to compile here until the list is fixed.
/// Because the carriers and the match arms are generated from this one list, a
/// variant cannot silently escape the sweep while the carrier count stays the
/// same.
macro_rules! relay_outcome_sweep {
    ($($pattern:pat => ($label:expr, $carrier:expr $(,)?)),+ $(,)?) => {{
        let carriers = [$($carrier),+];
        for carrier in &carriers {
            let _: &'static str = match carrier {
                $($pattern => $label),+
            };
        }
        carriers
    }};
}

#[test]
fn every_relay_outcome_variant_is_redacted() {
    let outcomes = relay_outcome_sweep![
        RelayOutcome::Prepared => ("Prepared", RelayOutcome::Prepared),
        RelayOutcome::Reserved => ("Reserved", RelayOutcome::Reserved),
        RelayOutcome::Signed => ("Signed", RelayOutcome::Signed),
        RelayOutcome::Submitted { .. } => (
            "Submitted",
            RelayOutcome::Submitted {
                reference: HOSTILE.to_string(),
                state: SubmissionState::Unknown,
            },
        ),
        RelayOutcome::Unknown => ("Unknown", RelayOutcome::Unknown),
        RelayOutcome::Confirmed { .. } => (
            "Confirmed",
            RelayOutcome::Confirmed {
                reference: HOSTILE.to_string(),
                fill: Some(ObservedFill {
                    net_input: 987_654_321,
                    net_output: 123_456_789,
                }),
            },
        ),
        RelayOutcome::Rejected { .. } => (
            "Rejected",
            RelayOutcome::Rejected {
                final_reason: HOSTILE.to_string(),
            },
        ),
        RelayOutcome::FailedBeforeSubmit => ("FailedBeforeSubmit", RelayOutcome::FailedBeforeSubmit),
    ];
    // Keep this count in lockstep with the exhaustive match generated by
    // `relay_outcome_sweep!`, so an accidentally dropped carrier is caught.
    assert_eq!(
        outcomes.len(),
        8,
        "the hostile carriers must cover every variant handled by the exhaustive match"
    );

    for outcome in &outcomes {
        assert_redacted(&format!("{outcome:?}"), Surface::Debug);
    }
}

/// Asserts a rendered surface carries no digits, endpoint markers, or
/// asset/identifier tokens.
fn assert_redacted(surface: &str, kind: Surface) {
    assert!(
        !surface.chars().any(|c| c.is_ascii_digit()),
        "ASCII digit leaked in `{surface}`"
    );
    assert!(
        !has_hex_run(surface, 8),
        "hex run of length >= 8 leaked in `{surface}`"
    );
    for marker in ["0x", "http", "://", "wallet", "intent", "asset", "pool"] {
        assert!(
            !surface.contains(marker),
            "`{marker}` leaked in `{surface}`"
        );
    }
    if kind == Surface::Debug {
        assert!(!surface.contains("idem"), "`idem` leaked in `{surface}`");
    }
    // Concrete fixture values / secrets that must never be rendered.
    for value in ["idem-1", "wallet-1", "intent-1", "USDC", "TOKEN", "pool-1"] {
        assert!(!surface.contains(value), "`{value}` leaked in `{surface}`");
    }
}

/// Detects a run of at least `min_len` ASCII hex digits (leaked digest bytes).
///
/// The digit guard above only rejects `0x..` payloads that happen to carry a
/// numeric digit; this catches a pure-hex-letter run such as `deadbeef`.
fn has_hex_run(value: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// A runtime kill switch disables the *same* engine the relay consults and must
/// deny before any reservation, signing, or submission.
#[tokio::test]
async fn kill_switch_denies_before_reservation_and_signer() {
    let harness = RelayHarness::standard();
    harness.relay.policy().disable_trading();
    assert!(!harness.relay.policy().is_trading_enabled());

    let result = harness.relay.execute(harness.input(NOW_MS)).await;

    assert_eq!(result, Err(RelayError::TradingDisabled));
    assert_eq!(harness.store.reserve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.signing.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.adapter.submits.load(Ordering::SeqCst), 0);
}
