//! Deterministic chain-health breaker tests with explicit `now_ms`.

use chain_types::ChainId;
use execution_relay::{ChainHealth, ChainHealthBreaker};

#[test]
fn breaker_opens_after_threshold_and_half_open_recovers() {
    let breaker = ChainHealthBreaker::new(2, 5_000);
    let chain = ChainId::Base;

    assert_eq!(breaker.health(&chain, 0), ChainHealth::Healthy);
    assert!(breaker.check_allowed(&chain, 0));

    breaker.record_failure(&chain, 100);
    assert_eq!(breaker.health(&chain, 100), ChainHealth::Degraded);
    assert!(
        breaker.check_allowed(&chain, 100),
        "below the threshold the breaker still admits requests"
    );

    breaker.record_failure(&chain, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);
    assert!(
        !breaker.check_allowed(&chain, 1_000),
        "an open breaker blocks during cooldown"
    );
    assert!(!breaker.check_allowed(&chain, 5_199));

    // Cooldown elapses at 5,200: exactly one half-open probe is admitted.
    assert!(breaker.check_allowed(&chain, 5_300));
    assert!(
        !breaker.check_allowed(&chain, 5_300),
        "a second concurrent probe must be blocked"
    );

    breaker.record_success(&chain);
    assert_eq!(breaker.health(&chain, 5_301), ChainHealth::Healthy);
    assert!(breaker.check_allowed(&chain, 5_301));
}

#[test]
fn probe_failure_reopens_the_breaker() {
    let breaker = ChainHealthBreaker::new(2, 4_000);
    let chain = ChainId::Base;

    breaker.record_failure(&chain, 100);
    breaker.record_failure(&chain, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);
    assert!(!breaker.check_allowed(&chain, 4_100));

    assert!(breaker.check_allowed(&chain, 4_300), "probe admitted");
    breaker.record_failure(&chain, 4_350);
    assert_eq!(breaker.health(&chain, 4_350), ChainHealth::Unavailable);
    assert!(!breaker.check_allowed(&chain, 5_000));
}

#[test]
fn adapter_health_readings_feed_the_breaker_but_healthy_does_not_reset() {
    let breaker = ChainHealthBreaker::new(2, 5_000);
    let chain = ChainId::Base;

    breaker.observe(&chain, ChainHealth::Degraded, 100);
    breaker.observe(&chain, ChainHealth::Unavailable, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);

    // A healthy reading does not mask the recorded failures.
    breaker.observe(&chain, ChainHealth::Healthy, 300);
    assert_eq!(breaker.health(&chain, 300), ChainHealth::Unavailable);
    assert!(!breaker.check_allowed(&chain, 1_000));
}
