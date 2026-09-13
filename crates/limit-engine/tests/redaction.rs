//! Redaction roster: no error variant may expose a payload.

use limit_engine::{AttemptResolution, LimitEngineError, RealizedFill, TickOutcome};
use market_types::AtomicAmount;

#[test]
fn error_roster_is_complete() {
    assert_eq!(LimitEngineError::ALL.len(), 27);
    let mut names: Vec<String> = LimitEngineError::ALL
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 27, "error roster contains duplicates");
}

#[test]
fn every_error_variant_is_payload_free() {
    for error in LimitEngineError::ALL {
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(!display.is_empty(), "empty display for {debug}");
        assert!(
            !display.chars().any(|c| c.is_ascii_digit()),
            "display for {debug} leaked a number: {display}"
        );
        assert!(
            !debug.chars().any(|c| c.is_ascii_digit()),
            "debug leaked a number: {debug}"
        );
        assert!(
            !display.contains("0x") && !debug.contains("0x"),
            "error leaked a hex reference: {debug}"
        );
        assert!(
            !display.contains('(') && !debug.contains('('),
            "error debug carries a payload: {debug}"
        );
        assert!(
            !display.contains('{') && !debug.contains('{'),
            "error debug carries a payload: {debug}"
        );
    }
}

#[test]
fn orchestrator_debug_is_payload_free() {
    let fill = RealizedFill {
        net_input: AtomicAmount::new(12_345),
        net_output: AtomicAmount::new(67_890),
    };
    let rendered = [
        format!("{fill:?}"),
        format!("{:?}", AttemptResolution::Filled(fill.clone())),
        format!(
            "{:?}",
            TickOutcome::Filled {
                attempt_seq: 3,
                realized: fill.clone(),
            }
        ),
        format!(
            "{:?}",
            TickOutcome::PartiallyFilled {
                attempt_seq: 3,
                realized: fill.clone(),
                remaining: AtomicAmount::new(1),
            }
        ),
        format!(
            "{:?}",
            TickOutcome::Terminal {
                status: domain::OrderStatus::Expired,
            }
        ),
    ];
    for text in rendered {
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "orchestrator Debug leaked a number: {text}"
        );
        assert!(
            !text.contains("USDC") && !text.contains("TOKEN") && !text.contains("0x"),
            "orchestrator Debug leaked an asset or reference: {text}"
        );
    }
}
