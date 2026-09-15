//! P89 — integration tests for the pure dynamic slippage recommendation core.
//!
//! These tests pin the arithmetic (including ceiling rounding), the hard-max
//! clamp, saturation, determinism, redaction, and the crate's offline,
//! fail-closed shape. Production code in `src/` never uses a fallible
//! shortcut; `unwrap_or_else` is used here only to turn a literal typo in a
//! test into a clear failure.

use market_types::Bps;
use risk_engine::{
    recommend_slippage, RiskError, SlippagePolicy, SlippageSignals, TRADING_ENABLED,
};

fn bps(value: u16) -> Bps {
    Bps::new(value).unwrap_or_else(|error| panic!("invalid bps literal {value}: {error:?}"))
}

fn signals(
    volatility_bps: u16,
    route_uncertainty_bps: u16,
    state_latency_ms: u64,
    confirmation_latency_ms: u64,
) -> SlippageSignals {
    SlippageSignals {
        volatility_bps: bps(volatility_bps),
        route_uncertainty_bps: bps(route_uncertainty_bps),
        state_latency_ms,
        confirmation_latency_ms,
    }
}

fn policy(base_bps: u16, drift_bps_per_sec: u16) -> SlippagePolicy {
    SlippagePolicy {
        base_bps: bps(base_bps),
        drift_bps_per_sec: bps(drift_bps_per_sec),
    }
}

fn recommend(signals: &SlippageSignals, policy: &SlippagePolicy, hard_max: u16) -> Bps {
    recommend_slippage(signals, policy, bps(hard_max))
        .unwrap_or_else(|error| panic!("recommendation failed: {error:?}"))
}

#[test]
fn pinned_latency_rounding_vectors() {
    // 1 ms at 1 bps/s is 0.001 bps, which rounds up to 1 bps.
    let one_ms = recommend(&signals(0, 0, 1, 0), &policy(0, 1), Bps::MAX);
    assert_eq!(one_ms.get(), 1);

    // 1000 ms at 5 bps/s is exactly 5 bps.
    let one_second = recommend(&signals(0, 0, 1000, 0), &policy(0, 5), Bps::MAX);
    assert_eq!(one_second.get(), 5);

    // 1001 ms at 1 bps/s rounds up from 1.001 to 2 bps.
    let partial = recommend(&signals(0, 0, 1001, 0), &policy(0, 1), Bps::MAX);
    assert_eq!(partial.get(), 2);

    // 30 ms at 100 bps/s is 3 bps exactly.
    let exact = recommend(&signals(0, 0, 30, 0), &policy(0, 100), Bps::MAX);
    assert_eq!(exact.get(), 3);
}

#[test]
fn pinned_full_recommendation_vector() {
    // state 1000 ms + confirmation 500 ms = 1500 ms.
    // 1500 ms at 2 bps/s = 3 bps (exact).
    // raw = base 30 + volatility 20 + route 10 + latency 3 = 63.
    let signals = signals(20, 10, 1000, 500);
    let policy = policy(30, 2);
    assert_eq!(recommend(&signals, &policy, Bps::MAX).get(), 63);
}

#[test]
fn zero_policy_and_zero_signals_recommend_zero() {
    let signals = signals(0, 0, 0, 0);
    let policy = policy(0, 0);
    assert_eq!(recommend(&signals, &policy, Bps::MAX).get(), 0);
}

#[test]
fn zero_drift_ignores_latency() {
    let signals = signals(0, 0, u64::MAX, u64::MAX);
    let policy = policy(0, 0);
    assert_eq!(recommend(&signals, &policy, Bps::MAX).get(), 0);
}

#[test]
fn monotone_non_decreasing_in_each_signal() {
    let policy = policy(5, 3);
    let baseline = recommend(&signals(10, 20, 100, 200), &policy, Bps::MAX).get();

    let higher_variants = [
        (11, 20, 100, 200),
        (10, 21, 100, 200),
        (10, 20, 101, 200),
        (10, 20, 100, 201),
    ];

    for (volatility, route, state, confirmation) in higher_variants {
        let raised = recommend(
            &signals(volatility, route, state, confirmation),
            &policy,
            Bps::MAX,
        )
        .get();
        assert!(
            raised >= baseline,
            "raising a signal must not lower the recommendation: {raised} < {baseline}"
        );
    }
}

#[test]
fn monotone_non_decreasing_in_policy_values() {
    let signals = signals(10, 20, 100, 200);
    let low = recommend(&signals, &policy(5, 3), Bps::MAX).get();
    let higher_base = recommend(&signals, &policy(6, 3), Bps::MAX).get();
    let higher_drift = recommend(&signals, &policy(5, 4), Bps::MAX).get();

    assert!(higher_base >= low, "{higher_base} < {low}");
    assert!(higher_drift >= low, "{higher_drift} < {low}");
}

#[test]
fn result_never_exceeds_hard_max_and_caps_exactly() {
    // A raw recommendation far above every plausible hard maximum.
    let signals = signals(Bps::MAX, Bps::MAX, 1_000_000, 1_000_000);
    let policy = policy(500, 100);

    for hard_max in [0u16, 1, 50, 999, Bps::MAX] {
        let output = recommend(&signals, &policy, hard_max).get();
        assert!(
            output <= hard_max,
            "output {output} exceeds hard max {hard_max}"
        );
        assert_eq!(
            output, hard_max,
            "an over-budget raw sum must clamp exactly"
        );
    }
}

#[test]
fn zero_hard_max_always_recommends_zero() {
    let signals = signals(Bps::MAX, Bps::MAX, u64::MAX, u64::MAX);
    let policy = policy(Bps::MAX, Bps::MAX);
    assert_eq!(recommend(&signals, &policy, 0).get(), 0);
}

#[test]
fn bps_max_hard_max_is_respected() {
    let signals = signals(Bps::MAX, Bps::MAX, u64::MAX, u64::MAX);
    let policy = policy(Bps::MAX, Bps::MAX);
    let output = recommend(&signals, &policy, Bps::MAX).get();
    assert_eq!(output, Bps::MAX);
}

#[test]
fn latency_saturation_does_not_wrap() {
    // The clamp makes the observable result equal whether the add saturates or
    // wraps, so the wrap property itself is pinned by the `src` unit test
    // `latency_sum_saturates_instead_of_wrapping`; this integration test only
    // proves the extreme input still terminates at the hard maximum.
    let signals = signals(0, 0, u64::MAX, u64::MAX);
    let policy = policy(0, 1);
    let output = recommend(&signals, &policy, Bps::MAX).get();
    assert_eq!(output, Bps::MAX);
}

#[test]
fn extreme_inputs_never_hit_the_overflow_error() {
    // With the current field widths the checked operations cannot fail:
    // u64::MAX * 10_000 fits in u128. This test pins that the extreme, fully
    // saturated input set still succeeds rather than failing closed.
    let signals = signals(Bps::MAX, Bps::MAX, u64::MAX, u64::MAX);
    let policy = policy(Bps::MAX, Bps::MAX);
    let result = recommend_slippage(&signals, &policy, bps(Bps::MAX));
    assert_eq!(result, Ok(bps(Bps::MAX)));
}

#[test]
fn risk_error_is_redacted_and_fieldless() {
    let error = RiskError::ArithmeticOverflow;

    assert_eq!(
        format!("{error}"),
        "slippage recommendation arithmetic overflowed"
    );
    assert_eq!(format!("{error:?}"), "ArithmeticOverflow");

    for rendered in [format!("{error}"), format!("{error:?}")] {
        for sensitive in ["bps", "latency", "volatility", "route", "token", "amount"] {
            assert!(
                !rendered.to_lowercase().contains(sensitive),
                "RiskError rendering leaked `{sensitive}`: {rendered}"
            );
        }
    }
}

#[test]
fn recommendation_is_deterministic() {
    let signals = signals(37, 41, 1234, 5678);
    let policy = policy(9, 7);
    let first = recommend(&signals, &policy, Bps::MAX).get();

    for _ in 0..128 {
        assert_eq!(recommend(&signals, &policy, Bps::MAX).get(), first);
    }
    assert_eq!(
        recommend_slippage(&signals, &policy, bps(Bps::MAX)),
        recommend_slippage(&signals, &policy, bps(Bps::MAX))
    );
}

#[test]
fn debug_output_is_redacted() {
    let signals = SlippageSignals {
        volatility_bps: bps(4321),
        route_uncertainty_bps: bps(1234),
        state_latency_ms: 987_654_321,
        confirmation_latency_ms: 1_122_334_455,
    };
    let policy = SlippagePolicy {
        base_bps: bps(777),
        drift_bps_per_sec: bps(13),
    };

    let signals_debug = format!("{signals:?}");
    let policy_debug = format!("{policy:?}");

    assert!(signals_debug.contains("SlippageSignals"));
    assert!(policy_debug.contains("SlippagePolicy"));

    for leak in ["4321", "1234", "987654321", "1122334455"] {
        assert!(
            !signals_debug.contains(leak),
            "signal debug leaked `{leak}`: {signals_debug}"
        );
    }
    for leak in ["777", "13"] {
        assert!(
            !policy_debug.contains(leak),
            "policy debug leaked `{leak}`: {policy_debug}"
        );
    }
}

#[test]
fn source_has_no_forbidden_constructs() {
    let sources = [
        ("src/lib.rs", include_str!("../src/lib.rs")),
        ("src/slippage.rs", include_str!("../src/slippage.rs")),
    ];
    // The scan strips all whitespace first, so `.unwrap (` / `panic !` /
    // `unsafe {` (and other spacing variants) cannot evade it. `f32`/`f64` are
    // forbidden because the core must stay integer-only.
    let forbidden = [
        ".unwrap(",
        ".expect(",
        "panic!",
        "unreachable!",
        "todo!",
        "unimplemented!",
        "unsafe{",
        "unsafefn",
        "unsafeimpl",
        "f32",
        "f64",
    ];

    for (name, source) in sources {
        let compact: String = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for token in forbidden {
            assert!(
                !compact.contains(token),
                "{name} must not contain `{token}`"
            );
        }
    }
    assert!(include_str!("../src/lib.rs").contains("#![forbid(unsafe_code)]"));
}

#[test]
fn trading_is_disabled() {
    const { assert!(!TRADING_ENABLED) };
}

#[test]
fn no_network_serde_or_runtime_dependencies() {
    let cargo_toml = include_str!("../Cargo.toml");
    let prohibited = [
        "serde",
        "tokio",
        "async-trait",
        "reqwest",
        "hyper",
        "tonic",
        "axum",
        "rand",
        "tracing",
    ];

    for dependency in prohibited {
        assert!(
            !cargo_toml.contains(dependency),
            "risk-engine must stay pure and offline; found `{dependency}`"
        );
    }
}
