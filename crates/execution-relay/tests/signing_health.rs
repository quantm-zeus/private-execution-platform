//! Signing-failure circuit breaker: state machine, relay integration, and
//! cancellation safety. All deterministic; no wall clock, signer, or network.
//!
//! The relay still checks the kill switch and chain health first, so these tests
//! also pin that an open signing breaker can only halt execution, never bypass
//! those gates.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use domain::{RoutePlan, TradeIntent, ValidatedExecutionPreview};
use execution_relay::{
    ChainHealth, ExecutionRelay, RelayError, RelayExecutionInput, RelayOutcome, SignedExecutionRef,
    SigningBoundary, SigningFailureBreaker, SigningHealth,
};
use policy::{ApprovedExecution, PolicyContext};
use privy::{PreparedExecutionRef, SigningRequest};
use support::{MockAdapter, MockSigning, MockSource, MockStore};

// ---------------------------------------------------------------------------
// Breaker state machine
// ---------------------------------------------------------------------------

#[test]
fn default_policy_trips_at_three_failures_and_blocks_cooldown() {
    let breaker = SigningFailureBreaker::default_policy();
    assert_eq!(breaker.state(0), SigningHealth::Healthy);
    assert!(breaker.check_allowed(0));

    breaker.record_failure(100);
    assert_eq!(breaker.state(100), SigningHealth::Degraded);
    assert!(breaker.check_allowed(100), "below threshold still admits");

    breaker.record_failure(200);
    assert_eq!(breaker.state(200), SigningHealth::Degraded);

    breaker.record_failure(300);
    assert_eq!(breaker.state(300), SigningHealth::Unavailable);
    assert!(!breaker.check_allowed(300), "open breaker blocks");
    assert!(!breaker.check_allowed(30_299), "still cooling down");
    assert!(
        breaker.admit_probe(300).is_none(),
        "no probe while cooling down"
    );
}

#[test]
fn after_cooldown_exactly_one_half_open_probe_and_success_closes() {
    let breaker = SigningFailureBreaker::new(2, 5_000);
    breaker.record_failure(100);
    breaker.record_failure(200);
    assert_eq!(breaker.state(200), SigningHealth::Unavailable);

    // The read-only gate admits once the cooldown elapsed and never consumes.
    assert!(breaker.check_allowed(5_300));
    assert!(breaker.check_allowed(5_300));

    let probe = breaker.admit_probe(5_300).expect("probe admitted");
    assert!(
        breaker.admit_probe(5_300).is_none(),
        "only one in-flight probe is permitted"
    );
    assert!(
        !breaker.check_allowed(5_300),
        "an admitted probe blocks a second concurrent admission"
    );
    assert_eq!(
        breaker.state(5_300),
        SigningHealth::Degraded,
        "an admitted probe leaves the breaker half-open"
    );

    probe.success();
    assert_eq!(breaker.state(5_301), SigningHealth::Healthy);
    assert!(breaker.check_allowed(5_301));
    assert!(breaker.admit_probe(5_301).is_some());
}

#[test]
fn probe_failure_reopens_with_a_fresh_cooldown() {
    let breaker = SigningFailureBreaker::new(2, 4_000);
    breaker.record_failure(100);
    breaker.record_failure(200);
    assert!(!breaker.check_allowed(4_100));

    let probe = breaker.admit_probe(4_300).expect("probe admitted");
    probe.failure(4_350);

    assert_eq!(breaker.state(4_350), SigningHealth::Unavailable);
    assert!(!breaker.check_allowed(8_349), "the cooldown restarted");
    assert!(breaker.check_allowed(8_350), "and expires from the failure");
}

#[test]
fn healthy_admissions_need_no_probe_and_check_allowed_is_read_only() {
    let breaker = SigningFailureBreaker::new(3, 1_000);

    for _ in 0..3 {
        assert!(breaker.check_allowed(0), "read-only gate never mutates");
    }

    // A healthy breaker admits without consuming a probe, so several concurrent
    // admissions are allowed and dropping them records nothing.
    let first = breaker.admit_probe(0).expect("healthy admission");
    let second = breaker.admit_probe(0).expect("healthy admission");
    assert_eq!(breaker.state(0), SigningHealth::Healthy);
    drop(first);
    drop(second);
    assert_eq!(breaker.state(0), SigningHealth::Healthy);
    assert!(breaker.check_allowed(0));
}

#[test]
fn record_success_resets_the_consecutive_failure_counter() {
    let breaker = SigningFailureBreaker::new(3, 10_000);
    breaker.record_failure(0);
    breaker.record_failure(0);
    assert_eq!(breaker.state(0), SigningHealth::Degraded);

    breaker.record_success();
    assert_eq!(breaker.state(0), SigningHealth::Healthy);

    // Two failures after the reset must not trip the threshold.
    breaker.record_failure(1);
    breaker.record_failure(2);
    assert_eq!(breaker.state(2), SigningHealth::Degraded);

    breaker.record_failure(3);
    assert_eq!(breaker.state(3), SigningHealth::Unavailable);
}

#[test]
fn dropped_probe_guard_releases_half_open_probe_with_fresh_cooldown() {
    let breaker = SigningFailureBreaker::new(2, 5_000);
    breaker.record_failure(100);
    breaker.record_failure(200);

    let probe = breaker.admit_probe(5_300).expect("probe admitted");
    drop(probe);

    assert_eq!(breaker.state(5_300), SigningHealth::Unavailable);
    assert!(!breaker.check_allowed(10_299), "the cooldown restarted");
    assert!(breaker.check_allowed(10_300));
}

#[test]
fn new_clamps_zero_threshold_and_negative_cooldown() {
    let threshold = SigningFailureBreaker::new(0, 5_000);
    threshold.record_failure(100);
    assert_eq!(threshold.state(100), SigningHealth::Unavailable);
    assert!(!threshold.check_allowed(100));

    let cooldown = SigningFailureBreaker::new(1, -5);
    cooldown.record_failure(100);
    assert!(
        cooldown.check_allowed(100),
        "a negative cooldown clamps to zero and admits immediately"
    );
}

// ---------------------------------------------------------------------------
// Relay integration through `ExecutionRelay::execute`
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum SignerMode {
    Fail,
    Succeed,
    Hang,
}

/// A signing boundary whose behavior can be flipped between attempts.
struct ScriptedSigner {
    calls: AtomicUsize,
    mode: Mutex<SignerMode>,
    reference: String,
}

impl ScriptedSigner {
    fn new(mode: SignerMode) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(mode),
            reference: "scripted-ref".to_string(),
        })
    }

    fn set_mode(&self, mode: SignerMode) {
        *self.mode.lock().expect("signer mode lock") = mode;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SigningBoundary for ScriptedSigner {
    async fn sign(&self, request: &SigningRequest) -> Result<SignedExecutionRef, RelayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Copy the mode out so no mutex guard is held across the `Hang` await.
        let mode = *self.mode.lock().expect("signer mode lock");
        match mode {
            SignerMode::Fail => Err(RelayError::SigningFailed),
            SignerMode::Succeed => SignedExecutionRef::new(
                self.reference.clone(),
                *request.request_digest(),
                request.intent_id().clone(),
                request.idempotency_key().clone(),
            ),
            SignerMode::Hang => {
                std::future::pending::<Result<SignedExecutionRef, RelayError>>().await
            }
        }
    }
}

type SigningRelay =
    ExecutionRelay<Arc<MockStore>, Arc<MockAdapter>, Arc<MockSource>, Arc<ScriptedSigner>>;

fn relay_with(signer: Arc<ScriptedSigner>, breaker: SigningFailureBreaker) -> SigningRelay {
    ExecutionRelay::new_with_seams(
        support::engine(true),
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        signer,
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    )
    .with_signing_breaker(breaker)
}

/// One fully owned attempt fixture whose `input` borrows the bound approvals.
struct AttemptFixture {
    intent: TradeIntent,
    context: PolicyContext,
    prepared: PreparedExecutionRef,
    approved: ApprovedExecution,
    route: RoutePlan,
    preview: ValidatedExecutionPreview,
}

impl AttemptFixture {
    fn new(key: &str, nonce: u64) -> Self {
        let intent = support::intent_with_idempotency(key, nonce);
        let engine = support::engine(true);
        let context = support::policy_context();
        let approved = support::approved(&engine, &intent);
        let prepared = support::prepared(&intent);
        let route = support::route();
        let preview = support::preview(&intent, &route);
        Self {
            intent,
            context,
            prepared,
            approved,
            route,
            preview,
        }
    }

    fn input(&self, now_ms: i64) -> RelayExecutionInput<'_> {
        RelayExecutionInput {
            intent: &self.intent,
            policy_context: &self.context,
            prepared: &self.prepared,
            approved: &self.approved,
            route: &self.route,
            preview: &self.preview,
            now_ms,
        }
    }
}

#[tokio::test]
async fn failing_signer_trips_breaker_and_blocks_attempt_four() {
    let signer = ScriptedSigner::new(SignerMode::Fail);
    // The fixture intent expires at 10_000 ms, so keep the cooldown inside it.
    let relay = relay_with(Arc::clone(&signer), SigningFailureBreaker::new(3, 5_000));

    // Attempts 1..=3 each reach the signer and fail.
    for (index, (key, nonce)) in [("p90-a", 11u64), ("p90-b", 12), ("p90-c", 13)]
        .into_iter()
        .enumerate()
    {
        let fixture = AttemptFixture::new(key, nonce);
        assert_eq!(
            relay.execute(fixture.input(1_000)).await,
            Err(RelayError::SigningFailed),
            "attempt {}",
            index + 1
        );
        assert_eq!(signer.calls(), index + 1);
    }
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Unavailable
    );

    // Attempt 4 inside the cooldown is blocked before signing.
    let blocked = AttemptFixture::new("p90-d", 14);
    assert_eq!(
        relay.execute(blocked.input(1_000)).await,
        Err(RelayError::SigningUnavailable)
    );
    assert_eq!(signer.calls(), 3, "the signer must not be called");
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Unavailable
    );

    // The blocked attempt recorded a definitive pre-send failure on its reserved
    // key, so a duplicate of that exact key returns it without signing.
    let duplicate = AttemptFixture::new("p90-d", 14);
    assert_eq!(
        relay.execute(duplicate.input(1_000)).await,
        Ok(RelayOutcome::FailedBeforeSubmit)
    );
    assert_eq!(signer.calls(), 3, "the duplicate must not sign");

    // After the cooldown the half-open probe succeeds and closes the breaker.
    signer.set_mode(SignerMode::Succeed);
    let probe = AttemptFixture::new("p90-e", 15);
    let outcome = relay
        .execute(probe.input(6_000))
        .await
        .expect("half-open probe signs");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(signer.calls(), 4);
    assert_eq!(relay.signing_breaker().state(6_000), SigningHealth::Healthy);

    // A later attempt signs normally.
    let later = AttemptFixture::new("p90-f", 16);
    let outcome = relay.execute(later.input(6_100)).await.expect("later sign");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(signer.calls(), 5);
}

#[tokio::test]
async fn successful_sign_resets_consecutive_failure_counter() {
    let signer = ScriptedSigner::new(SignerMode::Fail);
    let relay = relay_with(Arc::clone(&signer), SigningFailureBreaker::new(3, 10_000));

    for (key, nonce) in [("reset-a", 21u64), ("reset-b", 22)] {
        let fixture = AttemptFixture::new(key, nonce);
        assert_eq!(
            relay.execute(fixture.input(1_000)).await,
            Err(RelayError::SigningFailed)
        );
    }
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Degraded
    );

    signer.set_mode(SignerMode::Succeed);
    let success = AttemptFixture::new("reset-c", 23);
    let outcome = relay.execute(success.input(1_000)).await.expect("sign");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(relay.signing_breaker().state(1_000), SigningHealth::Healthy);

    // Two more failures after the reset must stay below the threshold.
    signer.set_mode(SignerMode::Fail);
    for (key, nonce) in [("reset-d", 24u64), ("reset-e", 25)] {
        let fixture = AttemptFixture::new(key, nonce);
        assert_eq!(
            relay.execute(fixture.input(1_000)).await,
            Err(RelayError::SigningFailed)
        );
    }
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Degraded,
        "the earlier success reset the consecutive-failure counter"
    );
}

#[tokio::test]
async fn mismatched_signed_reference_resolves_the_probe_as_a_failure() {
    let signing = MockSigning::ok();
    // The signer returns a reference bound to a different request digest, so the
    // relay rejects it as `SigningRequestMismatch`.
    signing.set_override_digest(*support::other_signing_request().request_digest());
    let relay = ExecutionRelay::new_with_seams(
        support::engine(true),
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        Arc::clone(&signing),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    )
    .with_signing_breaker(SigningFailureBreaker::new(3, 10_000));

    for (key, nonce) in [
        ("mismatch-a", 61u64),
        ("mismatch-b", 62),
        ("mismatch-c", 63),
    ] {
        let fixture = AttemptFixture::new(key, nonce);
        assert_eq!(
            relay.execute(fixture.input(1_000)).await,
            Err(RelayError::SigningRequestMismatch)
        );
    }
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Unavailable,
        "each mismatched reference must resolve its half-open probe as a failure"
    );
}

#[tokio::test]
async fn kill_switch_off_wins_over_an_open_signing_breaker() {
    let signer = ScriptedSigner::new(SignerMode::Succeed);
    let relay = ExecutionRelay::new_with_seams(
        support::engine(false),
        MockStore::new(),
        MockAdapter::accepting(),
        MockSource::standard(),
        Arc::clone(&signer),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    )
    .with_signing_breaker(SigningFailureBreaker::new(1, 60_000));
    relay.signing_breaker().record_failure(0);

    let fixture = AttemptFixture::new("kill-a", 31);
    assert_eq!(
        relay.execute(fixture.input(100)).await,
        Err(RelayError::TradingDisabled),
        "the kill switch must remain first"
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(
        relay.signing_breaker().state(100),
        SigningHealth::Unavailable,
        "the blocked attempt must not alter the breaker"
    );
}

#[tokio::test]
async fn chain_health_gate_precedes_an_open_signing_breaker() {
    let signer = ScriptedSigner::new(SignerMode::Succeed);
    let adapter = MockAdapter::accepting();
    adapter.set_health(ChainHealth::Unavailable);
    let relay = ExecutionRelay::new_with_seams(
        support::engine(true),
        MockStore::new(),
        adapter,
        MockSource::standard(),
        Arc::clone(&signer),
        execution_relay::ChainHealthBreaker::new(2, 5_000),
    )
    .with_signing_breaker(SigningFailureBreaker::new(1, 60_000));
    relay.signing_breaker().record_failure(0);

    let fixture = AttemptFixture::new("chain-first", 71);
    assert_eq!(
        relay.execute(fixture.input(100)).await,
        Err(RelayError::ChainHealthUnavailable),
        "the chain-health gate must remain ahead of the signing breaker"
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(
        relay.signing_breaker().state(100),
        SigningHealth::Unavailable,
        "the chain-health rejection must not alter the signing breaker"
    );
}

#[tokio::test]
async fn reconcile_never_touches_the_signing_breaker() {
    let signer = ScriptedSigner::new(SignerMode::Succeed);
    let relay = relay_with(Arc::clone(&signer), SigningFailureBreaker::new(3, 10_000));

    let fixture = AttemptFixture::new("recon-a", 41);
    let outcome = relay.execute(fixture.input(1_000)).await.expect("execute");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));

    // Force the signing breaker open at 0, so the cooldown runs to 10_000.
    for _ in 0..3 {
        relay.signing_breaker().record_failure(0);
    }
    assert_eq!(relay.signing_breaker().state(0), SigningHealth::Unavailable);

    // Reconcile well inside the cooldown. A spurious `record_failure(5_000)`
    // would push the cooldown to 15_000, and a spurious `record_success` would
    // close the breaker, so the exact boundary assertions below are decisive.
    let reconciled = relay
        .reconcile(&fixture.intent.idempotency_key, 5_000)
        .await
        .expect("reconcile");
    assert!(matches!(reconciled, RelayOutcome::Confirmed { .. }));

    assert_eq!(
        relay.signing_breaker().state(5_000),
        SigningHealth::Unavailable,
        "reconcile must not close the breaker"
    );
    assert!(
        !relay.signing_breaker().check_allowed(9_999),
        "reconcile must not shorten or restart the cooldown"
    );
    assert!(
        relay.signing_breaker().check_allowed(10_000),
        "the original cooldown still expires at 10_000"
    );

    // Reconcile again after the cooldown: a spurious `admit_probe` in reconcile
    // would consume the single half-open probe, so this is decisive for that
    // branch too.
    let again = relay
        .reconcile(&fixture.intent.idempotency_key, 11_000)
        .await
        .expect("reconcile");
    assert!(matches!(again, RelayOutcome::Confirmed { .. }));
    assert_eq!(
        relay.signing_breaker().state(11_000),
        SigningHealth::Degraded,
        "the reclaimable half-open probe is untouched"
    );
    assert!(relay.signing_breaker().check_allowed(11_000));
    assert!(
        relay.signing_breaker().admit_probe(11_000).is_some(),
        "reconcile must not consume the half-open probe"
    );
}

#[tokio::test]
async fn cancelled_sign_releases_half_open_probe() {
    use std::time::Duration;

    let signer = ScriptedSigner::new(SignerMode::Hang);
    let relay = relay_with(Arc::clone(&signer), SigningFailureBreaker::new(1, 1_000));
    // Open the breaker so the next admission consumes the single half-open probe.
    relay.signing_breaker().record_failure(0);
    assert_eq!(
        relay.signing_breaker().state(500),
        SigningHealth::Unavailable
    );

    let fixture = AttemptFixture::new("cancel-a", 51);
    let cancelled = tokio::time::timeout(
        Duration::from_millis(10),
        relay.execute(fixture.input(1_000)),
    )
    .await;
    assert!(cancelled.is_err(), "the hung sign must be cancelled");
    assert_eq!(signer.calls(), 1);

    // The guard resolved the dropped probe as a failure with a fresh cooldown.
    assert_eq!(
        relay.signing_breaker().state(1_000),
        SigningHealth::Unavailable
    );
    assert!(!relay.signing_breaker().check_allowed(1_999));
    assert!(relay.signing_breaker().check_allowed(2_000));

    signer.set_mode(SignerMode::Succeed);
    let recovered = AttemptFixture::new("cancel-b", 52);
    let outcome = relay
        .execute(recovered.input(2_000))
        .await
        .expect("recovered execute");
    assert!(matches!(outcome, RelayOutcome::Submitted { .. }));
    assert_eq!(relay.signing_breaker().state(2_001), SigningHealth::Healthy);
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

#[test]
fn signing_unavailable_error_is_payload_free() {
    let error = RelayError::SigningUnavailable;
    assert_eq!(error.to_string(), "signing unavailable");
    assert_eq!(format!("{error:?}"), "SigningUnavailable");
}

#[test]
fn signing_breaker_debug_is_payload_free() {
    let breaker = SigningFailureBreaker::default_policy();
    breaker.record_failure(1);
    breaker.record_failure(2);

    let rendered = format!("{breaker:?}");
    assert!(rendered.contains("SigningFailureBreaker"));
    assert!(rendered.contains("failure_threshold"));
    assert!(rendered.contains("cooldown_ms"));
    assert!(
        !rendered.contains("consecutive_failures"),
        "the breaker Debug must not render internal failure state: {rendered}"
    );
    assert!(!rendered.contains("signing unavailable"));
}
