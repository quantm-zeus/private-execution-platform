//! P75 — adversarial execution-security suite over the relay-backed
//! `RelayMarketExecutionPort`.
//!
//! Test-only. Reuses the crate's shared `support` fakes; no network, wall clock,
//! key material, or real chain is involved. The suite exercises genuinely
//! concurrent duplicate execution through the port, trust-state tampering,
//! verbatim observed-fill reporting, and a redaction sweep over the port's
//! error/outcome surface.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort};
use chain_types::ChainId;
use domain::WalletRef;
use execution_relay::{ObservedFill, RelayOutcome};
use market_execution::MarketExecutionTrust;
use market_types::{AtomicAmount, Sequence};
use support::{harness, request, scripted_port, token, trust, Behavior, NOW_MS};

/// An async barrier that guarantees simultaneous entry into a race.
///
/// A yield-based barrier is used instead of `tokio::sync::Barrier` so the test
/// depends only on the crate's declared `tokio` features; it never blocks a
/// worker thread.
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

    let fixture = Arc::new(harness(true, Behavior::Accept, trust(), false));
    let barrier = Arc::new(SpinBarrier::new(TASKS));

    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            fixture.port.execute(request()).await
        }));
    }

    let mut outcomes = Vec::with_capacity(TASKS);
    for handle in handles {
        outcomes.push(handle.await.expect("join"));
    }

    assert_eq!(
        fixture.signer.calls.load(Ordering::SeqCst),
        1,
        "concurrent duplicates must sign exactly once"
    );
    assert_eq!(
        fixture.adapter.submits.load(Ordering::SeqCst),
        1,
        "concurrent duplicates must submit exactly once"
    );

    // Transient relay reservation states (`Reserved`/`Signed`) and the terminal
    // `Submitted` all map to `MarketExecutionOutcome::Submitted`, so every
    // duplicate observes the same port outcome.
    for outcome in &outcomes {
        assert_eq!(
            outcome.as_ref().expect("no task may error"),
            &MarketExecutionOutcome::Submitted
        );
    }
}

/// Runs one tampered trust snapshot through the port and asserts it denies
/// before any sign or submit.
async fn assert_trust_denied(trust_value: MarketExecutionTrust) {
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        0,
        "a tampered trust snapshot must deny before signing"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.prepared_calls.load(Ordering::SeqCst),
        0,
        "denial must precede the prepared-reference source"
    );
}

#[tokio::test]
async fn tamper_trust_state_denies_before_sign() {
    // Wallet identity mismatch.
    let mut wallet_mismatch = trust();
    wallet_mismatch.wallet_balance.wallet_ref = WalletRef::new("wallet-2").expect("wallet ref");
    assert_trust_denied(wallet_mismatch).await;

    // Chain mismatch between the balance snapshot and the intent.
    let mut chain_mismatch = trust();
    chain_mismatch.wallet_balance.chain = ChainId::Ethereum;
    assert_trust_denied(chain_mismatch).await;

    // Balance asset mismatch: the snapshot covers a different asset.
    let mut asset_mismatch = trust();
    asset_mismatch.wallet_balance.asset = token();
    assert_trust_denied(asset_mismatch).await;

    // Insufficient balance for the full wallet debit.
    let mut insufficient = trust();
    insufficient.wallet_balance.available = AtomicAmount::new(999);
    assert_trust_denied(insufficient).await;

    // Stale tax observation.
    let mut stale_tax = trust();
    stale_tax.tax_observation.observed_at_ms = NOW_MS - 60_000;
    assert_trust_denied(stale_tax).await;

    // Zero-sequence wallet freshness (must force a resync, not a trade).
    let mut zero_sequence = trust();
    zero_sequence.wallet_balance.freshness.sequence = Sequence(0);
    assert_trust_denied(zero_sequence).await;
}

#[tokio::test]
async fn observed_fill_is_reported_verbatim() {
    // The observed amounts are deliberately unrelated to the request's quoted
    // 1_000-in / 240-out economics: the port is observational and must report
    // exactly what the reservation store/relay observed, with no derivation or
    // validation of the realized amounts.
    let (port, adapter, signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 999_999,
                net_output: 7,
            }),
        },
        trust(),
    );

    let outcome = port.execute(request()).await;

    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 999_999,
            net_output: 7,
        })
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
}

/// Names every [`MarketExecutionError`] variant exactly once and expands to both
/// the swept array and a wildcard-free `match` over the same list.
///
/// A new variant makes the generated exhaustive `match` (which has no wildcard
/// arm) fail to compile until it is listed here, and the array is built from the
/// same list, so no variant can silently escape the sweep.
macro_rules! market_execution_error_sweep {
    ($($variant:ident),+ $(,)?) => {{
        let _: fn(&MarketExecutionError) = |error| match error {
            $(MarketExecutionError::$variant => {}),+
        };
        [$(MarketExecutionError::$variant),+]
    }};
}

/// Lists every [`MarketExecutionOutcome`] variant exactly once with its carrier
/// and redaction label, then expands to both the carrier array and a
/// wildcard-free `match` over that same list.
///
/// The match has no wildcard arm, so a new `MarketExecutionOutcome` variant — or
/// a duplicated/omitted entry — fails to compile here until the list is fixed,
/// and a variant cannot silently escape the sweep.
macro_rules! market_execution_outcome_sweep {
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
fn market_execution_error_and_outcome_debug_is_redacted() {
    let errors = market_execution_error_sweep![Unavailable, Denied];
    for error in &errors {
        assert_redacted(&format!("{error:?}"));
        assert_redacted(&format!("{error}"));
    }

    let outcomes = market_execution_outcome_sweep![
        MarketExecutionOutcome::Submitted => ("Submitted", MarketExecutionOutcome::Submitted),
        MarketExecutionOutcome::Filled { .. } => (
            "Filled",
            MarketExecutionOutcome::Filled {
                net_input: 987_654_321,
                net_output: 123_456_789,
            },
        ),
        MarketExecutionOutcome::Unknown => ("Unknown", MarketExecutionOutcome::Unknown),
        MarketExecutionOutcome::Failed => ("Failed", MarketExecutionOutcome::Failed),
    ];
    // Keep this count in lockstep with the exhaustive match generated by
    // `market_execution_outcome_sweep!`, so a dropped carrier is caught.
    assert_eq!(
        outcomes.len(),
        4,
        "the carriers must cover every variant handled by the exhaustive match"
    );

    for outcome in &outcomes {
        assert_redacted(&format!("{outcome:?}"));
    }
}

/// Asserts a rendered surface carries no digits, endpoint markers, or
/// asset/identifier tokens.
fn assert_redacted(surface: &str) {
    assert!(
        !surface.chars().any(|c| c.is_ascii_digit()),
        "ASCII digit leaked in `{surface}`"
    );
    assert!(
        !has_hex_run(surface, 8),
        "hex run of length >= 8 leaked in `{surface}`"
    );
    for marker in [
        "0x", "http", "://", "wallet", "intent", "idem", "asset", "pool",
    ] {
        assert!(
            !surface.contains(marker),
            "`{marker}` leaked in `{surface}`"
        );
    }
    for value in [
        "USDC",
        "TOKEN",
        "pool-1",
        "wallet-1",
        "intent-1",
        "idem-1",
        "prepared-1",
    ] {
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
