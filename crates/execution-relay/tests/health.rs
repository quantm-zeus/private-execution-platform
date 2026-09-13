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
    assert!(
        breaker.check_allowed(&chain, 5_300),
        "the read-only gate admits once the cooldown has elapsed"
    );
    assert!(breaker.check_allowed(&chain, 5_300));
    let probe = breaker.admit_probe(&chain, 5_300);
    assert!(probe.is_some(), "probe admitted");
    assert!(
        !breaker.check_allowed(&chain, 5_300),
        "a second concurrent probe must be blocked"
    );
    assert!(
        breaker.admit_probe(&chain, 5_300).is_none(),
        "only one in-flight probe is permitted"
    );

    // Explicit success closes the breaker.
    probe.expect("admitted probe").success();
    assert_eq!(breaker.health(&chain, 5_301), ChainHealth::Healthy);
    assert!(breaker.check_allowed(&chain, 5_301));
    assert!(breaker.admit_probe(&chain, 5_301).is_some());
}

#[test]
fn check_allowed_is_read_only_and_admit_probe_consumes() {
    let breaker = ChainHealthBreaker::new(2, 5_000);
    let chain = ChainId::Base;

    breaker.record_failure(&chain, 100);
    breaker.record_failure(&chain, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);

    // Repeated read-only gates do not burn the half-open probe.
    assert!(breaker.check_allowed(&chain, 5_300));
    assert!(breaker.check_allowed(&chain, 5_300));
    assert!(breaker.check_allowed(&chain, 5_300));

    // Only an explicit admission consumes it.
    let probe = breaker.admit_probe(&chain, 5_300).expect("probe admitted");
    assert!(breaker.admit_probe(&chain, 5_300).is_none());
    assert!(!breaker.check_allowed(&chain, 5_300));
    assert_eq!(
        breaker.health(&chain, 5_300),
        ChainHealth::Degraded,
        "an admitted probe leaves the breaker half-open"
    );

    // Explicit failure re-opens the breaker.
    probe.failure(5_300);
    assert_eq!(breaker.health(&chain, 5_300), ChainHealth::Unavailable);
}

#[test]
fn probe_failure_reopens_the_breaker() {
    let breaker = ChainHealthBreaker::new(2, 4_000);
    let chain = ChainId::Base;

    breaker.record_failure(&chain, 100);
    breaker.record_failure(&chain, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);
    assert!(!breaker.check_allowed(&chain, 4_100));

    assert!(breaker.check_allowed(&chain, 4_300), "probe gate admits");
    let probe = breaker.admit_probe(&chain, 4_300).expect("probe admitted");
    probe.failure(4_350);
    assert_eq!(breaker.health(&chain, 4_350), ChainHealth::Unavailable);
    assert!(!breaker.check_allowed(&chain, 5_000));
}

#[test]
fn dropped_probe_guard_releases_half_open_probe() {
    let breaker = ChainHealthBreaker::new(2, 5_000);
    let chain = ChainId::Base;

    breaker.record_failure(&chain, 100);
    breaker.record_failure(&chain, 200);
    assert_eq!(breaker.health(&chain, 200), ChainHealth::Unavailable);

    // Simulate a cancelled `execute`: admit the half-open probe and drop the
    // guard without ever resolving it.
    let probe = breaker.admit_probe(&chain, 5_300).expect("probe admitted");
    drop(probe);

    // The stranded probe would have blocked the chain forever; instead the
    // guard released it as a failure with a fresh cooldown.
    assert_eq!(breaker.health(&chain, 5_300), ChainHealth::Unavailable);
    assert!(
        !breaker.check_allowed(&chain, 10_299),
        "the release restarts the cooldown"
    );
    assert!(
        breaker.check_allowed(&chain, 10_300),
        "the breaker recovers after the released probe's cooldown"
    );

    // A later admission still works and is no longer stuck.
    let probe = breaker
        .admit_probe(&chain, 10_300)
        .expect("re-probe admitted");
    probe.success();
    assert_eq!(breaker.health(&chain, 10_301), ChainHealth::Healthy);
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
