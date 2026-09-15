//! P91: bounded, deterministic artifact-rotation scheduling.

use privacy::{
    plan_rotations, ArtifactRotation, PrivacyError, RotationConfig, RotationPlan, RotationPolicy,
};

const NOW: i64 = 10_000;

fn policy() -> RotationPolicy {
    RotationPolicy::new(RotationConfig {
        max_age_ms: 1_000,
        max_uses: 10,
        window_ms: 500,
    })
    .expect("valid policy")
}

fn artifact(artifact_id: u64, created_at_ms: i64, uses: u64) -> ArtifactRotation {
    ArtifactRotation {
        artifact_id,
        created_at_ms,
        uses,
        // Distinctive so the redaction test can prove it never leaks.
        key_id: 0x00FF_00FF,
    }
}

#[test]
fn empty_set_is_an_empty_plan() {
    let plan = plan_rotations(&[], &policy(), NOW, 4).expect("valid bounds");
    assert_eq!(
        plan,
        RotationPlan {
            rotate: Vec::new(),
            deferred: false,
            next_deadline_ms: None,
        }
    );
}

#[test]
fn nothing_due_reports_the_earliest_age_bound() {
    // Neither is due; the earliest `created_at + max_age_ms` is the min over all.
    let artifacts = [
        artifact(1, NOW, 0),       // next = NOW + 1000 = 11_000
        artifact(2, NOW - 500, 0), // next = NOW + 500 = 10_500
        artifact(3, NOW - 100, 3), // next = NOW + 900 = 10_900
    ];
    let plan = plan_rotations(&artifacts, &policy(), NOW, 4).expect("valid bounds");
    assert!(plan.rotate.is_empty());
    assert!(!plan.deferred);
    assert_eq!(plan.next_deadline_ms, Some(NOW + 500));
}

#[test]
fn some_due_rotates_exactly_them_ascending_and_excludes_them_from_the_deadline() {
    let artifacts = [
        artifact(7, NOW - 2_000, 0), // due by age
        artifact(3, NOW - 200, 0),   // not due; next = NOW + 300 = 10_300
        artifact(5, NOW - 1_500, 0), // due by age
        artifact(1, NOW, 10),        // due by uses
        artifact(9, NOW - 100, 0),   // not due; next = NOW + 400 = 10_400
    ];
    let plan = plan_rotations(&artifacts, &policy(), NOW, 4).expect("valid bounds");
    assert_eq!(plan.rotate, vec![1, 5, 7]);
    assert!(!plan.deferred);
    // Scheduled artifacts are excluded; only 3 and 9 remain, min = NOW + 800.
    assert_eq!(plan.next_deadline_ms, Some(NOW + 800));
}

#[test]
fn duplicate_ids_exclude_only_the_scheduled_entry_from_the_deadline() {
    // Two entries share id 1: the first is due, the second is not. Only the
    // scheduled element must be excluded; the untouched duplicate still drives
    // the deadline (regression: exclusion by id dropped both).
    let artifacts = [
        artifact(1, NOW - 2_000, 0), // due by age
        artifact(1, NOW, 0),         // not due; age bound = NOW + 1000
    ];
    let plan = plan_rotations(&artifacts, &policy(), NOW, 1).expect("valid bounds");
    assert_eq!(plan.rotate, vec![1]);
    assert!(!plan.deferred);
    assert_eq!(plan.next_deadline_ms, Some(NOW + 1_000));
}

#[test]
fn deadline_is_the_age_bound_not_a_late_nominal_window() {
    // `window_ms` far exceeds `max_age_ms`: the deadline must be the age bound,
    // not `created + window_ms`, or a caller would sleep past the artifact's
    // actual due time.
    let p = RotationPolicy::new(RotationConfig {
        max_age_ms: 1_000,
        max_uses: 10,
        window_ms: 100_000,
    })
    .expect("valid policy");
    let artifacts = [artifact(1, NOW, 0)];
    let plan = plan_rotations(&artifacts, &p, NOW, 1).expect("valid bounds");
    assert!(plan.rotate.is_empty());
    assert_eq!(plan.next_deadline_ms, Some(NOW + 1_000));
}

#[test]
fn more_due_than_the_bound_defers_and_runs_again_now() {
    let artifacts = [
        artifact(9, NOW - 2_000, 0),
        artifact(2, NOW - 2_000, 0),
        artifact(5, NOW - 2_000, 0),
    ];
    let plan = plan_rotations(&artifacts, &policy(), NOW, 2).expect("valid bounds");
    assert_eq!(plan.rotate, vec![2, 5]);
    assert!(plan.deferred);
    assert_eq!(plan.next_deadline_ms, Some(NOW));
}

#[test]
fn due_selection_is_deterministic_under_input_reordering() {
    let forward = [
        artifact(4, NOW - 2_000, 0),
        artifact(2, NOW - 3_000, 0),
        artifact(8, NOW, 0),
        artifact(1, NOW, 10),
        artifact(6, NOW - 1_000, 0),
    ];
    let mut reversed = forward;
    reversed.reverse();

    let a = plan_rotations(&forward, &policy(), NOW, 3).expect("valid bounds");
    let b = plan_rotations(&reversed, &policy(), NOW, 3).expect("valid bounds");
    assert_eq!(a, b);
    assert_eq!(a.rotate, vec![1, 2, 4]);
    assert!(a.deferred);
    assert_eq!(a.next_deadline_ms, Some(NOW));
}

#[test]
fn age_boundary_is_inclusive() {
    let p = policy();
    let at_bound = [artifact(1, NOW - 1_000, 0)];
    let one_below = [artifact(1, NOW - 999, 0)];

    let due = plan_rotations(&at_bound, &p, NOW, 1).expect("valid bounds");
    assert_eq!(due.rotate, vec![1]);

    let not_due = plan_rotations(&one_below, &p, NOW, 1).expect("valid bounds");
    assert!(not_due.rotate.is_empty());
    // The deadline is the exact age bound, so it is strictly after `now_ms`.
    assert_eq!(not_due.next_deadline_ms, Some(NOW + 1));
}

#[test]
fn uses_boundary_is_inclusive() {
    let p = policy();
    let at_bound = [artifact(1, NOW, 10)];
    let one_below = [artifact(1, NOW, 9)];

    let due = plan_rotations(&at_bound, &p, NOW, 1).expect("valid bounds");
    assert_eq!(due.rotate, vec![1]);

    let not_due = plan_rotations(&one_below, &p, NOW, 1).expect("valid bounds");
    assert!(not_due.rotate.is_empty());
    assert_eq!(not_due.next_deadline_ms, Some(NOW + 1_000));
}

#[test]
fn zero_max_per_pass_fails_closed() {
    assert_eq!(
        plan_rotations(&[artifact(1, NOW - 2_000, 0)], &policy(), NOW, 0),
        Err(PrivacyError::InvalidRotationBounds)
    );
    // Even an empty set fails closed: the bound itself is invalid.
    assert_eq!(
        plan_rotations(&[], &policy(), NOW, 0),
        Err(PrivacyError::InvalidRotationBounds)
    );
}

#[test]
fn saturating_clock_extremes_do_not_panic_or_wrap() {
    let p = policy();

    // created_at far in the past: age saturates at i64::MAX, so the age bound
    // fires; the epochal next rotation saturates instead of wrapping.
    let future_created = [artifact(1, i64::MIN, 0)];
    let plan = plan_rotations(&future_created, &p, i64::MAX, 1).expect("valid bounds");
    assert_eq!(plan.rotate, vec![1]);
    assert!(!plan.deferred);
    assert_eq!(plan.next_deadline_ms, None);

    let far_future = [artifact(2, i64::MAX, 0)];
    let plan = plan_rotations(&far_future, &p, i64::MIN, 1).expect("valid bounds");
    assert!(plan.rotate.is_empty());
    assert_eq!(plan.next_deadline_ms, Some(i64::MAX));

    // Saturated subtraction: i64::MIN - i64::MAX clamps to i64::MIN, clamped
    // again to zero by the policy; the huge use count makes it due.
    let extremes = [
        artifact(3, i64::MAX, u64::MAX),
        artifact(4, i64::MIN, u64::MAX),
    ];
    let plan = plan_rotations(&extremes, &p, i64::MIN, 1).expect("valid bounds");
    assert_eq!(plan.rotate, vec![3]);
    assert!(plan.deferred);
    assert_eq!(plan.next_deadline_ms, Some(i64::MIN));
}

#[test]
fn debug_renders_no_id_key_time_or_count() {
    let artifact = ArtifactRotation {
        artifact_id: 987_654_321,
        created_at_ms: 123_456_789,
        uses: 1_234_567,
        key_id: 0x00FF_00FF,
    };
    let artifact_debug = format!("{artifact:?}");
    for leaked in ["987654321", "123456789", "1234567", "16711935"] {
        assert!(
            !artifact_debug.contains(leaked),
            "artifact Debug leaked {leaked}: {artifact_debug}"
        );
    }

    let plan = RotationPlan {
        rotate: vec![987_654_321],
        deferred: true,
        next_deadline_ms: Some(123_456_789),
    };
    let plan_debug = format!("{plan:?}");
    for leaked in [
        "987654321",
        "123456789",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
    ] {
        assert!(
            !plan_debug.contains(leaked),
            "plan Debug leaked {leaked}: {plan_debug}"
        );
    }
}
