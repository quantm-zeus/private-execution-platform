//! P63: deterministic padding-ladder and artifact-rotation policies.

use privacy::{PaddedFrame, PaddingPolicy, PrivacyError, RotationConfig, RotationPolicy};

const LADDER: [usize; 4] = [64, 256, 1_024, 4_096];

fn policy() -> PaddingPolicy {
    PaddingPolicy::new(LADDER.to_vec()).expect("valid ladder")
}

#[test]
fn frames_pad_up_to_the_next_bucket() {
    let policy = policy();
    for (real, expected) in [
        (1usize, 64usize),
        (64, 64),
        (65, 256),
        (200, 256),
        (256, 256),
        (257, 1_024),
        (4_096, 4_096),
    ] {
        let padded = policy.pad(real);
        assert_eq!(
            padded,
            PaddedFrame {
                padded_len: expected,
                padding_len: expected - real,
                padded: true,
            },
            "real={real}"
        );
        assert!(padded.padded_len >= real);
    }
}

#[test]
fn a_frame_above_the_largest_bucket_is_not_truncated() {
    let policy = policy();
    let padded = policy.pad(5_000);
    assert_eq!(
        padded,
        PaddedFrame {
            padded_len: 5_000,
            padding_len: 0,
            padded: false,
        }
    );
    // Zero-length frames still pad to the first bucket.
    assert_eq!(policy.pad(0).padded_len, 64);
}

#[test]
fn invalid_ladders_are_rejected() {
    assert_eq!(PaddingPolicy::new(vec![]), Err(PrivacyError::EmptyLadder));
    assert_eq!(
        PaddingPolicy::new(vec![64, 0, 256]),
        Err(PrivacyError::ZeroBucket)
    );
    assert_eq!(
        PaddingPolicy::new(vec![64, 64, 256]),
        Err(PrivacyError::NotAscending)
    );
    assert_eq!(
        PaddingPolicy::new(vec![256, 64]),
        Err(PrivacyError::NotAscending)
    );
}

#[test]
fn rotation_honors_inclusive_age_and_use_bounds() {
    let policy = RotationPolicy::new(RotationConfig {
        max_age_ms: 1_000,
        max_uses: 10,
        window_ms: 500,
    })
    .expect("valid policy");

    assert!(!policy.should_rotate(999, 9));
    assert!(policy.should_rotate(1_000, 0));
    assert!(policy.should_rotate(0, 10));
    // A negative age is treated as zero rather than rotating.
    assert!(!policy.should_rotate(-5, 0));
    assert_eq!(policy.next_rotation_at_ms(5_000), 5_500);
    assert_eq!(policy.next_rotation_at_ms(i64::MAX), i64::MAX);
}

#[test]
fn invalid_rotation_bounds_are_rejected() {
    for config in [
        RotationConfig {
            max_age_ms: 0,
            max_uses: 1,
            window_ms: 1,
        },
        RotationConfig {
            max_age_ms: 1,
            max_uses: 0,
            window_ms: 1,
        },
        RotationConfig {
            max_age_ms: 1,
            max_uses: 1,
            window_ms: -1,
        },
    ] {
        assert_eq!(
            RotationPolicy::new(config),
            Err(PrivacyError::InvalidRotationBounds)
        );
    }
}

#[test]
fn the_default_rotation_config_is_valid() {
    let policy = RotationPolicy::new(RotationConfig::default()).expect("default is valid");
    assert!(!policy.should_rotate(0, 0));
    assert!(policy.should_rotate(86_400_000, 0));
}
