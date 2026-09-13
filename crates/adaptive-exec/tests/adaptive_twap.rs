//! P61: adaptive TWAP chunking, conservation, halts, and fallback behavior.

use adaptive_exec::{
    AdaptiveTwap, ChunkReason, HaltReason, MarketObservation, TwapDecision, TwapPlan, TwapPolicy,
    TwapState,
};
use market_types::AtomicAmount;

fn amount(value: u128) -> AtomicAmount {
    AtomicAmount::new(value)
}

fn plan(total: u128, slices: u32, max_slippage_bps: u16) -> TwapPlan {
    TwapPlan::new(
        amount(total),
        slices,
        amount(1),
        amount(total),
        4_000,
        1_000,
        max_slippage_bps,
    )
}

fn fresh(now_ms: i64) -> MarketObservation {
    MarketObservation {
        observed_at_ms: now_ms,
        last_slippage_bps: Some(10),
        liquidity_recovery_bps: Some(0),
        volatility_bps: Some(10),
    }
}

fn engine() -> AdaptiveTwap {
    AdaptiveTwap::new(TwapPolicy::default_policy())
}

#[test]
fn a_plain_schedule_conserves_the_total_and_completes() {
    let plan = plan(1_000, 4, 100);
    let mut state = TwapState::new(amount(1_000));
    let mut now = 0;
    let mut total = 0u128;
    let mut steps = 0;

    loop {
        let decision = engine().next(&plan, &state, &fresh(now), now);
        match decision {
            TwapDecision::Execute {
                chunk,
                remaining_after,
                next_at_ms,
                ..
            } => {
                total += chunk.get();
                assert_eq!(
                    state.remaining_input.get() - chunk.get(),
                    remaining_after.get()
                );
                state = state.record(chunk, now);
                assert_eq!(state.remaining_input, remaining_after);
                now = next_at_ms;
                steps += 1;
                assert!(steps <= 16, "schedule must terminate");
            }
            TwapDecision::Complete => break,
            TwapDecision::Halt { .. } => panic!("unexpected halt"),
        }
    }

    assert_eq!(total, 1_000);
    assert_eq!(state.remaining_input.get(), 0);
}

#[test]
fn realized_slippage_over_the_hard_cap_halts() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));
    let observation = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(101),
        liquidity_recovery_bps: Some(0),
        volatility_bps: Some(0),
    };
    assert_eq!(
        engine().next(&plan, &state, &observation, 0),
        TwapDecision::Halt {
            reason: HaltReason::SlippageExceeded
        }
    );
}

#[test]
fn slippage_near_the_cap_slows_the_schedule() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));
    let observation = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(60),
        liquidity_recovery_bps: Some(0),
        volatility_bps: Some(10),
    };
    match engine().next(&plan, &state, &observation, 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert_eq!(reason, ChunkReason::Slowed);
            assert_eq!(chunk.get(), 125);
        }
        other => panic!("expected slowed execute, got {other:?}"),
    }
}

#[test]
fn liquidity_recovery_accelerates_the_schedule() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));
    let observation = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(10),
        liquidity_recovery_bps: Some(600),
        volatility_bps: Some(10),
    };
    match engine().next(&plan, &state, &observation, 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert_eq!(reason, ChunkReason::Accelerated);
            assert_eq!(chunk.get(), 500);
        }
        other => panic!("expected accelerated execute, got {other:?}"),
    }
}

#[test]
fn high_volatility_slows_the_schedule() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));
    let observation = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(10),
        liquidity_recovery_bps: Some(0),
        volatility_bps: Some(300),
    };
    match engine().next(&plan, &state, &observation, 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert_eq!(reason, ChunkReason::Slowed);
            assert_eq!(chunk.get(), 125);
        }
        other => panic!("expected slowed execute, got {other:?}"),
    }
}

#[test]
fn stale_or_missing_observations_fall_back_to_cron() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));

    // Missing observation.
    match engine().next(&plan, &state, &MarketObservation::default(), 5_000) {
        TwapDecision::Execute {
            chunk,
            reason,
            next_at_ms,
            ..
        } => {
            assert_eq!(reason, ChunkReason::FallbackCron);
            assert_eq!(chunk.get(), 250);
            assert_eq!(next_at_ms, 6_000);
        }
        other => panic!("expected fallback, got {other:?}"),
    }

    // Stale observation (older than the policy window) even though it carries signals.
    let stale = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(10),
        liquidity_recovery_bps: Some(600),
        volatility_bps: Some(10),
    };
    match engine().next(&plan, &state, &stale, 1_000_000) {
        TwapDecision::Execute { reason, .. } => assert_eq!(reason, ChunkReason::FallbackCron),
        other => panic!("expected fallback, got {other:?}"),
    }
}

#[test]
fn a_small_remainder_becomes_a_final_slice() {
    // Remaining is below the minimum non-final chunk, so the whole remainder is
    // emitted as a final slice.
    let plan = TwapPlan::new(amount(1_000), 10, amount(100), amount(500), 1_000, 100, 100);
    let state = TwapState {
        remaining_input: amount(50),
        slices_done: 3,
        last_chunk_at_ms: Some(0),
        last_chunk: Some(amount(50)),
    };
    match engine().next(&plan, &state, &fresh(0), 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert_eq!(reason, ChunkReason::Final);
            assert_eq!(chunk.get(), 50);
        }
        other => panic!("expected final execute, got {other:?}"),
    }
}

#[test]
fn zero_remaining_completes() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState {
        remaining_input: amount(0),
        slices_done: 4,
        last_chunk_at_ms: Some(0),
        last_chunk: Some(amount(250)),
    };
    assert_eq!(
        engine().next(&plan, &state, &fresh(0), 0),
        TwapDecision::Complete
    );
}

#[test]
fn an_inverted_plan_does_not_panic() {
    let mut plan = plan(1_000, 4, 100);
    plan.min_chunk = amount(500);
    plan.max_chunk = amount(10);
    let state = TwapState::new(amount(1_000));
    match engine().next(&plan, &state, &fresh(0), 0) {
        TwapDecision::Execute { chunk, .. } => {
            assert!(chunk.get() >= 1);
            assert!(chunk.get() <= 1_000);
        }
        other => panic!("expected execute, got {other:?}"),
    }
}

#[test]
fn a_zero_slice_plan_does_not_panic() {
    // `slices` is a public field; a directly-mutated zero must not divide by zero.
    let mut plan = plan(1_000, 4, 100);
    plan.slices = 0;
    let state = TwapState::new(amount(1_000));
    match engine().next(&plan, &state, &fresh(0), 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert!(chunk.get() >= 1);
            // The nominal schedule is exhausted, so the remainder is a final slice.
            assert_eq!(chunk.get(), 1_000);
            assert_eq!(reason, ChunkReason::Final);
        }
        other => panic!("expected execute, got {other:?}"),
    }
}

#[test]
fn exactly_at_the_slippage_cap_does_not_halt() {
    let plan = plan(1_000, 4, 100);
    let state = TwapState::new(amount(1_000));
    let observation = MarketObservation {
        observed_at_ms: 0,
        last_slippage_bps: Some(100),
        liquidity_recovery_bps: Some(0),
        volatility_bps: Some(0),
    };
    assert!(matches!(
        engine().next(&plan, &state, &observation, 0),
        TwapDecision::Execute { .. }
    ));
}

#[test]
fn an_explicit_min_max_clamp_is_honored() {
    // base = 1000/4 = 250; the max of 200 must win.
    let plan = TwapPlan::new(
        amount(1_000),
        4,
        amount(100),
        amount(200),
        4_000,
        1_000,
        100,
    );
    let state = TwapState::new(amount(1_000));
    match engine().next(&plan, &state, &fresh(0), 0) {
        TwapDecision::Execute { chunk, reason, .. } => {
            assert_eq!(chunk.get(), 200);
            assert_eq!(reason, ChunkReason::Schedule);
        }
        other => panic!("expected execute, got {other:?}"),
    }
}

#[test]
fn zero_or_negative_durations_do_not_panic() {
    for duration in [0i64, -5] {
        let plan = TwapPlan::new(
            amount(1_000),
            4,
            amount(1),
            amount(1_000),
            duration,
            1_000,
            100,
        );
        let state = TwapState::new(amount(1_000));
        match engine().next(&plan, &state, &fresh(0), 0) {
            TwapDecision::Execute { next_at_ms, .. } => assert!(next_at_ms >= 0),
            other => panic!("expected execute, got {other:?}"),
        }
    }
}

#[test]
fn varying_observations_still_conserve_the_total() {
    let plan = plan(10_000, 8, 200);
    let mut state = TwapState::new(amount(10_000));
    let mut now = 0;
    let mut total = 0u128;

    let observations = [
        MarketObservation {
            observed_at_ms: 0,
            last_slippage_bps: Some(10),
            liquidity_recovery_bps: Some(800),
            volatility_bps: Some(10),
        },
        MarketObservation {
            observed_at_ms: 0,
            last_slippage_bps: Some(150),
            liquidity_recovery_bps: Some(-800),
            volatility_bps: Some(500),
        },
        MarketObservation {
            observed_at_ms: 0,
            last_slippage_bps: Some(10),
            liquidity_recovery_bps: Some(0),
            volatility_bps: Some(10),
        },
    ];

    let mut index = 0;
    loop {
        let mut observation = observations[index % observations.len()];
        observation.observed_at_ms = now;
        index += 1;
        match engine().next(&plan, &state, &observation, now) {
            TwapDecision::Execute {
                chunk,
                remaining_after,
                next_at_ms,
                ..
            } => {
                assert!(chunk.get() >= 1);
                total += chunk.get();
                state = state.record(chunk, now);
                assert_eq!(state.remaining_input, remaining_after);
                now = next_at_ms.max(now + 1);
                assert!(index <= 32, "must terminate");
            }
            TwapDecision::Complete => break,
            TwapDecision::Halt { reason } => panic!("unexpected halt {reason:?}"),
        }
    }

    assert_eq!(total, 10_000);
    assert_eq!(state.remaining_input.get(), 0);
}
