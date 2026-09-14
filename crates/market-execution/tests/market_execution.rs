//! P72 — concrete relay-backed `agent_backend::MarketExecutionPort`.
//!
//! Every test wires the port over the `#[doc(hidden)] ExecutionRelay::new_with_seams`
//! test seam with deterministic fakes (a counting signer, a scripted chain
//! adapter, a constant in-memory payload source, `InMemoryReservationStore`) and
//! an explicit `now_ms`. No live signer, chain, RPC, database, or key material is
//! involved.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_backend::{MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort};
use execution_relay::{
    ChainHealthBreaker, ChainObservation, InMemoryReservationStore, ObservedFill,
    PrivySigningBoundaryAdapter, RelayOutcome, UnavailableChainAdapter,
};
use market_execution::RelayMarketExecutionPort;
use market_types::AtomicAmount;
use policy::{PolicyContext, TurnoverSnapshot, UsdMicros};
use support::{
    harness, policy, reconcile_harness, request, request_with, scripted_port, trust, Behavior,
    CountingSource, FakePreparedRefs, FakeTrust, TestSource, NOW_MS,
};

// ---------------------------------------------------------------------------
// Required cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trading_disabled_denies_before_signer_or_adapter() {
    let h = harness(false, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        0,
        "the kill switch must block before signing"
    );
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.source.pre_calls.load(Ordering::SeqCst),
        0,
        "the kill switch must block before the payload is fetched"
    );
    assert_eq!(
        h.prepared_calls.load(Ordering::SeqCst),
        0,
        "denial must precede the prepared-reference source"
    );
}

#[tokio::test]
async fn policy_trade_size_exceeded_denies() {
    let mut trust_value = trust();
    trust_value.policy_context = PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(2_000_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("policy context");
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_tax_observation_denies_before_sign() {
    let mut trust_value = trust();
    trust_value.tax_observation.observed_at_ms = NOW_MS - 60_000;
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn insufficient_balance_denies_before_sign() {
    let mut trust_value = trust();
    trust_value.wallet_balance.available = AtomicAmount::new(999);
    let h = harness(true, Behavior::Accept, trust_value, false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn confirmed_with_observed_amounts_maps_to_filled() {
    let (port, adapter, signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 1_000,
                net_output: 240,
            }),
        },
        trust(),
    );

    let outcome = port.execute(request()).await;

    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1_000,
            net_output: 240,
        })
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn confirmed_without_amounts_maps_to_unknown() {
    let (port, _adapter, _signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        },
        trust(),
    );

    let outcome = port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Unknown));
}

#[tokio::test]
async fn submitted_maps_to_submitted() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ambiguous_adapter_timeout_maps_to_unknown() {
    let h = harness(true, Behavior::Timeout, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Unknown));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_adapter_maps_to_failed() {
    let h = harness(true, Behavior::Reject, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Failed));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn definitive_signing_failure_maps_to_failed() {
    let h = harness(true, Behavior::Accept, trust(), true);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Failed));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        0,
        "a definitive pre-send failure must never reach the adapter"
    );
}

#[tokio::test]
async fn duplicate_execute_signs_and_submits_once() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let first = h.port.execute(request()).await;
    let second = h.port.execute(request()).await;

    assert_eq!(first, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(second, Ok(MarketExecutionOutcome::Submitted));
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        1,
        "a duplicate must not reach the signing boundary again"
    );
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        1,
        "a duplicate must not re-submit"
    );
}

#[tokio::test]
async fn production_wiring_fails_closed_before_signer_or_adapter() {
    let source = Arc::new(CountingSource::new());
    let port = RelayMarketExecutionPort::<
        InMemoryReservationStore,
        UnavailableChainAdapter,
        TestSource,
        PrivySigningBoundaryAdapter,
        FakeTrust,
        FakePreparedRefs,
    >::production(
        policy(true),
        InMemoryReservationStore::new(),
        Arc::clone(&source),
        ChainHealthBreaker::new(2, 5_000),
        FakeTrust {
            trust: trust(),
            calls: Arc::new(AtomicUsize::new(0)),
        },
        FakePreparedRefs {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    );

    let outcome = port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Unavailable));
    assert_eq!(
        source.pre_calls.load(Ordering::SeqCst),
        0,
        "the unavailable adapter must block before any payload/sign step"
    );
}

#[tokio::test]
async fn debug_is_redacted() {
    let trust_value = trust();
    let trust_debug = format!("{trust_value:?}");
    let h = harness(true, Behavior::Accept, trust_value, false);
    let outcome = h.port.execute(request()).await.expect("submitted");
    let port_debug = format!("{:?}", h.port);
    let outcome_debug = format!("{outcome:?}");

    assert!(
        trust_debug.contains("..") && port_debug.contains(".."),
        "trust and port must use a non-exhaustive Debug"
    );

    for surface in [&trust_debug, &port_debug, &outcome_debug] {
        for needle in [
            "USDC",
            "TOKEN",
            "wallet-1",
            "intent-1",
            "idem-1",
            "uniswap",
            "pool-1",
            "1000",
            "240",
            "prepared-1",
            "signed-ref",
            "receipt-ref",
            "http",
            "://",
            "0x",
        ] {
            assert!(
                !surface.contains(needle),
                "redaction leak: `{surface}` contains `{needle}`"
            );
        }
        assert!(
            !has_hex_run(surface, 8),
            "redaction leak: `{surface}` contains a hex run of length >= 8"
        );
    }
}

/// Detects a run of at least `min_len` ASCII hex digits (leaked digest bytes).
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

#[tokio::test]
async fn market_min_out_denies_a_delta_below_the_slippage_floor() {
    // The exact floor arithmetic is pinned by the `market_min_out` unit tests in
    // `src/lib.rs`; this integration case proves the end-to-end gate denies (and
    // performs no sign/submit) when the delta net output sits below the floor
    // implied by the route expectation and the slippage cap.
    //
    // With a zero slippage cap the floor is exactly `route.expected_net_output`,
    // and a quote whose net output equals it passes revalidation and, when the
    // relay observes a fill of exactly that amount, maps to `Filled`.
    let (port, _adapter, _signer) = scripted_port(
        RelayOutcome::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 1_000,
                net_output: 240,
            }),
        },
        trust(),
    );
    let outcome = port.execute(request_with(240, 240, 0)).await;
    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1_000,
            net_output: 240,
        })
    );

    // A route expectation whose slippage floor sits above the delta net output
    // is denied (`MinOutNotMet`) before any sign/submit.
    let h = harness(true, Behavior::Accept, trust(), false);
    let outcome = h.port.execute(request_with(240, 237, 100)).await;
    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn trust_is_fetched_once_per_execute() {
    let h = harness(true, Behavior::Accept, trust(), false);

    let _ = h.port.execute(request()).await;

    assert_eq!(h.trust_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn trading_disabled_after_preview_denies() {
    // Defense in depth: with a disabled engine the authority check denies at
    // `authorize_trade` before any trust-derived basis, prepared reference, or
    // signer/adapter call. (The relay's own kill-switch gate is a redundant
    // second check on the same engine.)
    let h = harness(false, Behavior::Accept, trust(), false);

    let outcome = h.port.execute(request()).await;

    assert_eq!(outcome, Err(MarketExecutionError::Denied));
    assert_eq!(h.trust_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.prepared_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// P76 — read-only reconcile / observation seam
// ---------------------------------------------------------------------------

/// Populates the relay's process-local journal with exactly one ordinary
/// `execute`, then zeroes the signer/submit counters so the following read-only
/// `reconcile` can be held to zero signer and zero adapter submits.
async fn journal_one_attempt(h: &support::ReconcileHarness) {
    let executed = h.port.execute(request()).await;
    assert_eq!(executed, Ok(MarketExecutionOutcome::Submitted));
    h.signer.calls.store(0, Ordering::SeqCst);
    h.adapter.submits.store(0, Ordering::SeqCst);
}

#[tokio::test]
async fn reconcile_maps_an_observed_fill_to_filled() {
    let h = reconcile_harness(ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: Some(ObservedFill {
            net_input: 1_000,
            net_output: 240,
        }),
    });
    journal_one_attempt(&h).await;

    let outcome = h
        .port
        .reconcile(&request().intent.idempotency_key, NOW_MS)
        .await;

    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Filled {
            net_input: 1_000,
            net_output: 240,
        })
    );
    assert_eq!(
        h.signer.calls.load(Ordering::SeqCst),
        0,
        "reconcile must never sign"
    );
    assert_eq!(
        h.adapter.submits.load(Ordering::SeqCst),
        0,
        "reconcile must never submit"
    );
}

#[tokio::test]
async fn reconcile_without_amounts_is_unknown() {
    let h = reconcile_harness(ChainObservation::Confirmed {
        reference: "confirmed-ref".to_string(),
        fill: None,
    });
    journal_one_attempt(&h).await;

    let outcome = h
        .port
        .reconcile(&request().intent.idempotency_key, NOW_MS)
        .await;

    assert_eq!(
        outcome,
        Ok(MarketExecutionOutcome::Unknown),
        "a confirmation without exact amounts is never a fabricated fill"
    );
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_with_an_unknown_journal_key_is_unknown() {
    // No execute: the key is absent from the process-local journal, so the relay
    // reports `InvalidTransition`. That is observational ambiguity, never a
    // definitive failure.
    let h = reconcile_harness(ChainObservation::Unknown);

    let outcome = h
        .port
        .reconcile(&request().intent.idempotency_key, NOW_MS)
        .await;

    assert_eq!(outcome, Ok(MarketExecutionOutcome::Unknown));
    assert_eq!(h.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.adapter.submits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_never_signs_or_submits() {
    let observations = [
        ChainObservation::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: Some(ObservedFill {
                net_input: 1_000,
                net_output: 240,
            }),
        },
        ChainObservation::Confirmed {
            reference: "confirmed-ref".to_string(),
            fill: None,
        },
        ChainObservation::Pending,
        ChainObservation::Rejected {
            final_reason: "reverted".to_string(),
        },
        ChainObservation::Unknown,
    ];
    for observation in observations {
        let h = reconcile_harness(observation);
        journal_one_attempt(&h).await;
        let _ = h
            .port
            .reconcile(&request().intent.idempotency_key, NOW_MS)
            .await;
        assert_eq!(
            h.signer.calls.load(Ordering::SeqCst),
            0,
            "reconcile must never sign"
        );
        assert_eq!(
            h.adapter.submits.load(Ordering::SeqCst),
            0,
            "reconcile must never submit"
        );
        assert_eq!(h.trust_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.prepared_calls.load(Ordering::SeqCst),
            1,
            "reconcile must not run the prepared-reference/execute composition"
        );
    }
}
